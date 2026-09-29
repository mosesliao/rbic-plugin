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
        ├─ 3. RBAC        enforce(role, "table.column", "read") per column
        ├─ 4. ABAC        AND p2 row filters into every SELECT scope
        └─ 5. audit log   ALLOW/DENY via logging ("rbic.audit")
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
  tables/columns its role may read** (`allowed_schema()`) — pure UX so it
  doesn't write doomed queries; the gate enforces regardless.
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
  propose_grant, propose_revoke, propose_row_scope, propose_remove_row_scope,
  propose_inherit, propose_remove_inherit, propose_assign_role,
  propose_set_attribute, propose_undo. **There is no apply tool.**
- `propose_*` → `PolicyAdmin` validates and returns a `Change` (exact
  before/after text + computed effect summary) without writing. It is held
  as pending; validation errors go back to the model as `is_error` results.
- After the model's turn, code prints each pending change (description +
  unified diff) and asks `Apply change <id>? [yes/no]`. Only literal `yes`
  calls `PolicyAdmin.apply()`; the outcome is fed back to the model as a
  `[Code note]`. Pending changes never outlive that step.
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

---

## Policy Files — Semantics

### `casbin/model.conf`
- Objects are `table.column` strings; `keyMatch` makes `inventory.*` grants
  match `inventory.qty`; bare `employees.name` is an exact match.
- `g` gives role inheritance (`g, hr_manager, hr_staff` → hr_manager gets all
  hr_staff grants *and* its p2 row filters).
- `p2 = sub, table, filter` rows are **never** evaluated by `enforce()` —
  `sql_gate.py` reads them with `get_named_policy("p2")` and rewrites queries.

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
   new construct is gated.
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
   code after literal human confirmation.** No apply tool exists; a stale
   proposal (file changed since) is refused.
8. **No privilege escalation via chat.** The `master` role can't appear in
   policy.csv or be assigned, and master users' records can't be edited
   through the bot.
9. **Row-filter templates may not contain subqueries or other-table
   references** (nor unsafe functions): filters are injected after the RBAC
   column check, so a subquery would read ungranted data. Templates written
   via the bot must be printable ASCII, comment-free, predicate-only and
   non-tautological (see Template rules). Attribute values bound into
   unquoted placeholders must be numbers / number lists.
10. **Hot reload is fail-closed, atomic and thread-safe, and worker
    sessions reset history on policy change.** One immutable snapshot per
    request; a failed reload denies everything (and clears worker history)
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
