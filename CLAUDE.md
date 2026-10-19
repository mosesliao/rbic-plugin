# CLAUDE.md — Role-Gated LLM Chatbot (Casbin RBAC+ABAC over Text-to-SQL)

## Project Overview

An enterprise LLM chatbot plugin that answers workers' questions from a company
database while revealing only what their role permits:

- **Master user** manages policy (Casbin model + policy files)
- **Worker user** asks natural-language questions; the LLM translates them to SQL
- A **SQL gate** (`sql_gate.py`) enforces access *before* any data reaches the LLM
- Denied requests get the fixed, code-generated response:
  _"You have no access to this information, please approach your manager."_

**Access model:** RBAC + ABAC.
- **RBAC** — which `table.column` a role may `read` (Casbin `p` rules, role
  hierarchy via `g`)
- **ABAC** — which *rows* within those tables, via WHERE predicates bound from
  the worker's attributes (Casbin `p2` rules, e.g. `dept = '{dept}'`)

**Core security stance:** the LLM is untrusted. Enforcement happens in code at
the query layer — never via system-prompt instructions (see Legacy note).

---

## Architecture

```
worker question (natural language)
        ↓
LLM (text-to-SQL)                      Anthropic API
        ↓  candidate SQL
sql_gate.SQLGate.authorize(username, sql)
        ├─ 1. parse       sqlglot AST; single SELECT only (no UNION/DML/DDL)
        ├─ 2. qualify     resolve columns vs db_schema.json; expand SELECT *
        ├─ 3. constructs  allowlist of expression types: anything the column
        │                 capture doesn't model (whole-row refs, CTEs, ...) denies
        ├─ 4. RBAC        per table reference: some scope (p grants, or a
        │                 scoped-grant column list) of the role level or the
        │                 user level must cover every column used; p3 denies
        ├─ 5. ABAC        ((role scopes AND NOT role p4) OR user scopes)
        │                 AND NOT user p4, ANDed into each SELECT
        └─ 6. audit log   ALLOW/DENY via logging ("rbic.audit")
        ↓  rewritten safe SQL
database (least-privilege DB role)
        ↓  rows the worker may see
LLM summarizes results → answer to worker
```

On `AccessDenied`, the chatbot prints `sql_gate.DENY_MESSAGE` directly — the
LLM never generates (and can never be talked out of) the deny message.

---

## Project Structure

```
project/
├── .env                    # ANTHROPIC_API_KEY — never commit
├── CLAUDE.md               # this file
├── casbin/
│   ├── model.conf          # RBAC model + p2 (ABAC filter) definition
│   └── policy.csv          # p (grants), g (hierarchy), p2 (row filters)
├── db_schema.json          # table → columns; the qualify/deny reference
├── worker_attributes.json  # username → {role, dept/site…}; IdP/HRIS stand-in
├── sql_gate.py             # the PEP: parse → RBAC → ABAC → safe SQL
├── chatbot.py              # worker CLI: NL → text-to-SQL → gate → answer
├── master_bot.py           # master CLI: NL → proposed policy change → human yes/no
├── policy_admin.py         # validated, atomic, audited policy/attribute editor
├── policy_changes.jsonl    # runtime audit log of applied changes (gitignored)
├── seed_db.py              # creates + seeds company.db (demo data)
├── company.db              # seeded SQLite demo DB (regenerate anytime)
├── test_salary_policy_evolution.py  # pytest: policy stages 0→1→2
├── test_master_policy.py   # pytest: master bot, hot reload, validation, undo
├── test_scoped_grants.py   # pytest: 4-field p2 scoped grants
├── test_user_overrides.py  # pytest: per-user rules, deny rules, precedence
├── test_gate_review_fixes.py  # pytest: security-review regressions (both dialects)
└── requirements.txt        # anthropic, python-dotenv, casbin, sqlglot, pytest
```

Run:
```bash
python sql_gate.py        # gate demo cases (no API key needed)
python seed_db.py         # (re)create the demo database
pytest -q                 # policy-evolution + invariant tests
python chatbot.py alice   # chat as a worker (needs ANTHROPIC_API_KEY)
python chatbot.py bob     # hr_staff — try asking for salaries
python master_bot.py master  # master user: change policy by chatting
```

### chatbot.py flow
- The model gets a `run_sql` tool and a system prompt listing **only the
  tables/columns its role may read** (`allowed_schema()`), plus its scoped
  grants' column lists (`scoped_schema()`, flagged "row-limited", filter
  text not shown) — pure UX so it doesn't write doomed queries; the gate
  enforces regardless.
- Every `run_sql` call goes through `gate.authorize()`; results are returned
  to the model as JSON (capped at `MAX_ROWS_TO_MODEL`).
- The SQLite connection is opened **read-only** (`mode=ro`) — invariant #3.
- On `AccessDenied`, the partial tool-use turn is rolled back from history and
  `DENY_MESSAGE` is printed from code (invariant #4).
- Each turn calls `refresh_session()` → `gate.refresh()`: the role is re-read
  from `gate.attributes` and the system prompt rebuilt. If `policy_version`
  changed, history is cleared and "(Access policy was updated — conversation
  reset.)" is printed, so rows fetched under the old policy never linger.

### Hot reload (sql_gate.py)
- `authorize()` starts with `_maybe_reload()`: stat (mtime_ns, size, inode)
  of policy.csv, model.conf, worker_attributes.json; on change, build a
  complete new immutable `PolicySnapshot` (enforcer, attributes, compiled
  row filters, version, broken reason) and swap it in under a
  `threading.Lock`, then log `POLICY_RELOAD`.
- `authorize()` grabs the snapshot **once**; parse → RBAC → ABAC all use
  that snapshot (passed explicitly), so a reload mid-request can never mix
  old grants with new row filters. The gate is safe to share across
  threads. `policy_version`, `enforcer`, `attributes`, `broken` are
  read-only properties of the current snapshot.
- A failed reload (or files changing mid-load, or a p2 template the gate
  refuses to compile) marks the snapshot broken and denies every request
  ("policy reload failed: …") until a later reload succeeds. The worker
  chatbot clears its history while the gate is broken.
- Any unexpected exception inside `authorize()` (e.g. a sqlglot
  `TokenError`) is converted to a DENY — every `SqlglotError` is caught.

### master_bot.py flow
- `python master_bot.py master` refuses to start unless the user's role is
  `master`. `master` is not a Casbin role and has no data grants or data tools.
- Tools: list_roles, list_tables, describe_role, describe_user, show_history,
  propose_grant, propose_revoke, propose_deny, propose_remove_deny,
  propose_row_scope, propose_remove_row_scope (optional `columns` → a
  scoped grant), propose_deny_rows, propose_remove_deny_rows (optional
  `columns` → hides rows only from queries reading them), propose_inherit,
  propose_remove_inherit, propose_assign_role, propose_add_user_role,
  propose_remove_user_role (`g, user:x, role`), propose_set_attribute,
  propose_undo. **There is no apply tool.** Every grant/revoke/deny/row
  tool takes *either* `role` (a group) *or* `username` (a personal rule,
  subject `user:<name>`); the system prompt tells the model: a named person
  → personal rule, a group/job → role rule, never widen a role because one
  person was named, and "Carol is on leave, let Alice cover" → extra role
  for user:alice or specific personal rules.
- `propose_*` → `PolicyAdmin` validates and returns a `Change` (exact
  before/after text + computed effect summary) without writing. It is held
  as pending; validation errors go back to the model as `is_error` results.
- After the model's turn, code prints each pending change (description +
  unified diff) and asks `Apply change <id>? [yes/no]`. Only `yes`/`y`
  (any case) calls `PolicyAdmin.apply()`; `no`/`n` declines; anything else
  re-asks; EOF declines. Confirmations and declines are logged on
  `rbic.audit`. The outcome is fed back to the model as a `[Code note]`.
  Pending changes never outlive that step.
- Every `Change` records the sha256 of **all** inputs (policy.csv,
  worker_attributes.json, db_schema.json, model.conf) at proposal time.
  `apply()` runs under an inter-process lock file (`casbin/.policy.lock`,
  `O_CREAT|O_EXCL`, retried with a timeout, always removed), re-checks the
  actor is a master and that every input hash still matches — otherwise
  "Policy changed since this was proposed — please ask again" — and (for
  policy.csv) that the new file loads in a fresh `casbin.Enforcer`.
- Audit ordering: the full changelog record is appended with status
  `applying` **before** the atomic `os.replace`, then a full record with
  status `applied` (or a `failed: <reason>` record). A live change can
  never lack an audit entry; history and undo only use `applied` records.
  `POLICY_CHANGE` is logged on `rbic.audit`.
- Every policy.csv change (and every undo) re-binds every non-master
  user's row filters with their real attribute values against the
  after-state and is rejected on failure; attribute changes and attribute
  undos get the same value/scope checks and the same computed effect
  summary.
- policy.csv edits are line-based (comments preserved); additions go under
  `# ---- Changes via master chatbot ----`. Casbin's CSV has no quoting:
  commas split fields unless inside ()/[], so a rule that doesn't
  round-trip through Casbin's own tokenizer is rejected. Lines are split on
  LF only (as Casbin's file adapter does), never `str.splitlines()`.
- Diffs and descriptions shown to the human escape control/invisible
  characters (ANSI escapes, form feeds, U+2028, bidi overrides).
- **Operational note — removing a user.** A `user:<name>` subject must name
  an existing non-master worker, so deleting a worker who still holds
  `user:` rules (p/p2/p3/p4/g) breaks the policy load and the gate denies
  *everyone* until fixed (fail closed, by design). Remove the user's rules
  first (`propose_revoke` / `propose_remove_*` / `propose_remove_user_role`),
  then the user.

---

## Policy Files — Semantics

### `casbin/model.conf`
- Objects are `table.column` strings; `keyMatch` makes `inventory.*` grants
  match `inventory.qty`; bare `employees.name` is an exact match.
- `g` gives role inheritance (`g, hr_manager, hr_staff` → hr_manager gets all
  hr_staff grants, its p2 row filters *and* its denies). `g, user:alice,
  hr_manager` gives one user an extra role (its rules apply at role level).
  Nothing may inherit *from* a `user:` subject (`g, x, user:y` fails the
  load).
- **Subjects** are roles or `user:<username>` (namespaced so a username can
  never collide with a role). A `user:` subject must name an existing
  non-master worker in worker_attributes.json, else the load fails closed.
- Four ptypes, all read by `sql_gate.py` (`enforce()` is not used for
  decisions; the gate applies `keyMatch` itself, which is equivalent to
  the matcher for the role level): `p` allow column, `p2` allow rows,
  `p3 = sub, obj, act` deny column, `p4 = sub, table, filter, columns` deny
  rows. Deny rules are separate ptypes rather than an effect column so
  every pre-existing row keeps its meaning byte-for-byte, rows round-trip
  through Casbin's comma tokenizer unchanged, and precedence can be
  user-over-role (Casbin's own effect expression would let a role deny
  beat a user allow, because `g` links the two). The trailing `columns`
  field of p2/p4 is optional: pycasbin's file adapter keeps whatever fields
  a line has regardless of this definition, so 3-field and 4-field rows
  coexist; the gate is the only arity check (3 or 4, else the policy load
  fails closed). A model.conf without p3/p4, a policy line with an
  unknown ptype, a p/p3 action that is not exactly `read` (Casbin has no
  inline comments: `read # temp` is the action), a p3 naming an unknown
  table.column, a `g` row with extra fields, or a lone CR in policy.csv
  (an editor shows a line break, Casbin doesn't) all fail the load —
  each would otherwise silently drop a rule. A deny filter whose unquoted
  placeholder binds a non-number denies the query (a string there would
  compare FALSE and hide nothing).

### `casbin/policy.csv`
- `p` rows: RBAC grants. Column-level control works by granting named columns
  (e.g. hr_staff gets `employees.name` but not `employees.salary`).
- `p2` rows: ABAC filter templates. `{placeholders}` are bound from the
  worker's attributes at query time; a missing attribute denies the query.
  `'{name}'` always binds a string literal; bare `{name}` binds a number if
  the value is an int or all digits (else a string), and inside `IN (...)`
  a comma-separated value expands to one literal per item.
- **Template rules** (`sql_gate.compile_row_filter`). Always, also enforced
  by the gate on every load: a boolean condition; no subqueries, table
  references, stars, bind parameters or non-allowlisted functions; only
  unqualified columns of the filtered table; each placeholder stands alone
  as a value. Additionally for templates proposed via the master bot
  (`strict=True`): printable ASCII only (0x20–0x7E); no SQL comments
  (`--`, `/*`, `*/`, `#`); predicate-only — AND/OR/NOT/parentheses over
  leaves that compare a column with a value (=, <>, <, >, IN, IS, LIKE,
  BETWEEN), so bare columns/literals (`TRUE`, `1`, `employee_id`), CASE,
  identical sides (`employee_id = employee_id`) and column-vs-column
  comparisons are rejected, in every OR branch. Static filters (no
  placeholder) are allowed but flagged "WARNING: this filter is the same
  for every user".
- **Scope-union semantics**: multiple p2 rows for the *same* table are
  OR-combined (each row is a sufficient scope; a worker with several roles
  sees the union — e.g. hr_manager sees own payslip OR team payslips).
  Scopes on different tables stay independent (each ANDed into its own
  table's WHERE).
- **Scoped grants** (4-field p2 rows): `p2, warehouse_worker, employees,
  id = 2, id|name|salary` grants those columns *for those rows* in one
  rule — no `p` grant needed. Columns are `|`-separated (Casbin's CSV
  splits on commas); each must exist in db_schema.json, no duplicates,
  no whitespace, no `*`, and `master` can't hold one (else the load fails
  closed). The gate decides **per table reference** (each alias in each
  SELECT, so self-joins and subqueries are checked separately): with C =
  the columns of that reference used anywhere in the query, the *base
  scope* (columns = p grants; rows = OR of the role's 3-field filters, or
  all rows) and each scoped grant (columns = exactly its list; rows = its
  filter) *cover* the reference iff C ⊆ their columns. No covering scope →
  deny; otherwise the OR of the covering scopes' filters is ANDed in (an
  unfiltered covering base scope → nothing injected, and it alone decides).
  Scoped grants are purely additive — they can only add OR branches, never
  narrow what the base scope already allowed. **Every covering scope must
  bind**: a row filter *or* scoped grant that covers the reference but
  needs an attribute the worker lacks denies the query (same as the
  classic missing-attribute deny); a scoped grant that does not cover the
  reference is ignored, so it never narrows another scope. A **column-less
  reference** (`SELECT COUNT(*) FROM t`, `SELECT 1 FROM t`) is covered by
  every scope through which at least one column of `t` is readable, so it
  still needs a grant on the table (dave/master get denied) and gets the
  OR of those scopes' filters; a whole-table column deny (`p3 … t.*` or a
  p3 on every column) denies it. The ALLOW audit line records which
  scope(s) authorized each reference (`scopes=employees:base`,
  `a:scoped[warehouse_worker:id|name|salary]`). Templates follow the same
  rules as row filters. Propose via `propose_row_scope(..., columns=...)`.
- **Per-user rules and denies — precedence.** A request has a *user level*
  (subject `user:<name>`) and a *role level* (the worker's role from
  attributes + inherited roles + extra roles via `g, user:<name>, role` +
  theirs). Highest first:

  | level | effect | rule | result |
  | --- | --- | --- | --- |
  | user | deny | `p3, user:x, t.c, read` touching a used column | query denied outright |
  | user | deny | `p4, user:x, t, filter[, cols]` | `AND NOT (filter)` on the final predicate |
  | user | allow | `p, user:x, …` / `p2, user:x, …` | a user scope covering the reference adds rows even where role rules deny |
  | role | deny | `p3, role, t.c, read` touching a used column | no role scope covers (only a user allow can authorize) |
  | role | deny | `p4, role, t, filter[, cols]` | `AND NOT (filter)` on the role predicate |
  | role | allow | `p` / `p2` as before | base scope + scoped grants |

  Per table reference: `visible = ((role_allow AND NOT role_deny_rows) OR
  user_allow) AND NOT user_deny_rows`; no covering scope at either level →
  deny. Coverage is per level: a personal grant is its own scope, and a
  query mixing user-only and role-only columns is denied (the reason says
  which columns the user's rules cover). **Rows of a personal grant**: the
  user-level base scope (personal `p` grants, including one that overrides
  a role p3) keeps the rows the user's roles see — its filters are the
  user's own 3-field `p2, user:x, t, …` filter(s) if any, else the OR of
  the role level's 3-field filters on `t`, else every row (so a master can
  still widen rows deliberately with a personal p2). Personal scoped
  grants (4-field) keep their own filter. Audit label
  `user_allow[user:x](role rows)` marks borrowed filters;
  `describe_user.personal_grant_rows` and the grant/row-scope effect
  summaries say which rows apply. Column denies apply to every scope at
  their level and below (a user p3 also removes the column from role
  scopes). A p4 with columns only bites queries reading one of them;
  without columns, every query on the table. `NOT (NULL)` is NULL in SQL,
  so a row where a deny filter is NULL is hidden (fail closed). A deny
  filter that can't bind (missing attribute) denies the query. Audit
  labels name level/subject/effect: `employees:base-role_deny[hr_staff]
  +user_allow[user:alice:id|name|salary]-user_deny[user:alice]`,
  `deny:user[user:alice] employees.salary`, `deny:role[hr_staff] …`.
  Example: `p2, user:alice, employees, id = 2, id|name|salary` (alice
  alone reads Carol's salary; other warehouse workers don't).
- **Parity / regression note.** With no p3/p4/`user:` rules present,
  decisions and rewritten SQL are those of the original gate **except**,
  deliberately: (a) a column-less reference (`COUNT(*)`, `SELECT 1`) on a
  table the role has no grant on is denied, and one on a table with a row
  filter gets that filter (previously: all rows, no grant needed); (b) a
  covering scoped grant that can't bind denies instead of being skipped;
  (c) SQL outside the construct allowlist (whole-row references, CTEs,
  set operations in subqueries, LATERAL/UNNEST, `INTO`, `FOR UPDATE`,
  `TABLESAMPLE`, schema-qualified names) is denied. Golden-string parity
  tests cover the remaining byte-for-byte cases
  (`test_rewritten_sql_matches_pre_user_rule_gate`).
- **Sensitive columns get their own table/view** (see `payroll`): p2 filters
  are table-scoped, so a self-only filter on `employees` would clamp every
  employees query to one row. Segregating salary into `payroll` lets
  "own payslip" coexist with "browse department directory".

### `db_schema.json`
Single source of truth for what tables/columns exist. Dual purpose:
1. lets `sqlglot.optimizer.qualify` resolve unqualified columns and expand
   `SELECT *` into explicit columns → star queries get real column-level RBAC;
2. any table/column not listed here is an automatic deny.
Keep it in sync with the real database (generate it from information_schema
in production).

### `worker_attributes.json`
Demo stand-in for the IdP/HRIS. In production these attributes must come from
the authenticated session, never from user input.

---

## Security Invariants (do not weaken these)

1. **Fail closed.** Unparseable SQL, multi-statement input, non-SELECT
   statements, unknown tables/columns, unresolved stars, missing worker
   attributes — all deny.
2. **SQL-parsing completeness is the security boundary.** Every construct the
   parser can't fully account for must be rejected, not passed through. v1 is
   deliberately narrow (single SELECT); widen it only with tests proving the
   new construct is gated. Concretely, after `qualify` every node of the
   tree must be in `sql_gate.SUPPORTED_NODES` and none in
   `UNSUPPORTED_NODES` (`_check_constructs`): sqlglot's `TableColumn`
   (Postgres whole-row refs `e`, `(e).salary`, `to_jsonb(e)`,
   `row_to_json(e)`, `ORDER BY (e).salary` — a bare alias used as a value,
   which `_column_refs` never saw), `Dot`, UDTFs, set operations, CTEs,
   `INTO`, locks, `TABLESAMPLE`, bind parameters, schema-qualified tables or
   columns, bare identifiers outside name positions, and `*` anywhere but
   `COUNT(*)` all deny. Adding a node type to the allowlist requires a test
   showing its columns are captured under both dialects.
3. **Defense in depth.** The app's DB connection must use a least-privilege DB
   role (SELECT-only, sanctioned tables/views only) so a parser gap cannot
   reach data the DB itself won't serve. Casbin is policy; DB grants are the
   floor.
4. **The deny message is code, not model output.** Catch `AccessDenied`, print
   `DENY_MESSAGE`. Never ask the LLM to refuse.
5. **Audit everything.** Every ALLOW (with the rewritten SQL) and every DENY
   (with the reason) goes through the `rbic.audit` logger.
6. **Attribute values are bound as literal AST nodes, never spliced as
   text.** Each p2 template is parsed once per load with placeholders as
   sentinel string literals; at query time each sentinel is replaced by
   `exp.Literal` node(s) built from the attribute value, so a value can
   never become an identifier, operator or subquery. (Move to real query
   parameters when wiring a production DB driver.)
7. **Policy changes are proposed by the LLM but validated and applied only by
   code after explicit human confirmation.** No apply tool exists; only
   `yes`/`y` (any case) applies, `no`/`n` declines, anything else re-asks,
   EOF declines; confirmations and declines are logged on `rbic.audit`. A
   stale proposal (file changed since) is refused.
8. **No privilege escalation via chat — or by hand.** The `master` role
   can't be assigned, master users' records can't be edited through the
   bot, and `user:master` (or any `user:` subject that is not an existing
   non-master worker) is refused by the bot and fails the gate load.
   `compile_snapshot` (the gate's own loader, also run by PolicyAdmin on
   every proposal) refuses `master` as the subject, parent, table or
   object of any p/p2/p3/p4/g row, so a hand-edited `g, user:bob, master`
   plus `p, master, employees.salary, read` breaks the snapshot (deny all)
   instead of granting anything; a worker whose role is `master` is denied
   data access outright. A role name equal to a username is refused by the
   bot (it would be a silent, empty role); a worker whose `role` attribute
   is a `user:` subject is denied. Nothing inherits from a `user:` subject.
9. **Row-filter templates may not contain subqueries or other-table
   references** (nor unsafe functions): filters are injected after the RBAC
   column check, so a subquery would read ungranted data. Templates written
   via the bot must be printable ASCII, comment-free, predicate-only and
   non-tautological (see Template rules). Attribute values bound into
   unquoted placeholders must be numbers / number lists. The same rules
   apply to scoped grants and to deny filters (p4), for roles and users
   alike (one `compile_row_filter`, one literal-AST binder); column lists
   are validated against db_schema.json on every load, and columns are
   resolved per table reference (an alias reused in a subquery never stands
   in for an outer table). Precedence is evaluated in the gate, per table
   reference, never via Casbin's effect expression.
10. **Hot reload is fail-closed, atomic and thread-safe, and worker
    sessions reset history on policy change.** One immutable snapshot per
    request (allow and deny rules, user subjects, attributes compiled
    together); a failed reload — including a malformed deny row or an
    unknown user subject — denies everything (and clears worker history)
    until fixed. Policy writes are serialized by a file lock, verify all
    input hashes, and are audited before the file changes.

---

## Legacy v0 (deprecated)

The original design put a role→allowed-topics list (`master_config.json`) into
the LLM **system prompt** and asked the model to self-censor. That is a UX
nicety, not a security control — prompt injection or jailbreaks can bypass it,
and the model sees the restricted data regardless. Superseded by the SQL gate
above: restricted rows/columns now never enter the model's context. Do not
reintroduce prompt-level enforcement as the primary control.

---

## Environment

`.env` (never commit; `.gitignore` must include it):
```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

Install: `pip install -r requirements.txt`

LLM model for text-to-SQL / summarization: `claude-sonnet-4-6`.

---

## Next Steps

- **Audit persistence**: ship `rbic.audit` records to a table/file with
  worker, role, original SQL, rewritten SQL, decision, reason
- **IdP integration**: replace `worker_attributes.json` with session-derived
  attributes
- **Postgres migration**: swap SQLite for Postgres; generate `db_schema.json`
  from `information_schema`; add a SELECT-only DB role scoped to sanctioned
  views (strengthens invariant #3 beyond SQLite's `mode=ro`)
- **Master web UI**: a web front end for `master_bot.py` (same
  propose → human-confirm → apply flow; never expose an apply tool to the LLM)
- **Gate test suite**: `test_salary_policy_evolution.py` is the start — fold
  in the `sql_gate.py` demo cases and mock-client chatbot tests, and grow the
  suite with every new SQL construct admitted past the parser (invariant #2)
