# CLAUDE.md — Role-Gated LLM Chatbot (Casbin RBAC+ABAC over Text-to-SQL)

## Project Overview

An enterprise LLM chatbot plugin that answers workers' questions from a company
database while revealing only what their role permits:

- **Master user** manages policy (Casbin model + policy files)
- **Worker user** asks natural-language questions; the LLM translates them to SQL
- A **SQL gate** (`rbic.gate`) enforces access *before* any data reaches the LLM
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
host (rbic-chat CLI, Open WebUI Pipe, ...): authenticated Identity + chat history
        ↓
RBICEngine.ask(identity, messages, conversation_id=, audience=)
        ├─ audience      only Audience.PRIVATE              (else fixed deny)
        ├─ snapshot      one gate snapshot for the whole request
        ├─ identity      AttributeProvider → worker; unmapped/master → DENY_MESSAGE
        ├─ history       sanitize_history: plain-text user/assistant turns only
        ├─ guard         (worker, conversation_id) → fingerprint; drop stale turns
        └─ system prompt built server-side from the worker's grants
        ↓
LLM (text-to-SQL, run_sql tool)        Anthropic API
        ↓  candidate SQL
rbic.gate.SQLGate.authorize(username, sql)
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
LLM summarizes results → AskResult(text, denied, reason, ...) → host
```

On `AccessDenied`, `ask()` returns `rbic.gate.DENY_MESSAGE` directly — the
LLM never generates (and can never be talked out of) the deny message.

---

## Project Structure

```
project/
├── .env                    # ANTHROPIC_API_KEY — never commit (read by rbic.cli only)
├── CLAUDE.md               # this file
├── README.md
├── pyproject.toml          # rbic-plugin: deps, [test] extra, entry points (hatchling, src layout)
├── docs/RELEASING.md       # owner checklist: Trusted Publishing, environments, tagging
├── .github/workflows/
│   ├── tests.yml           # pytest (3.10/3.11/3.12) + wheel smoke; adapters (anthropic 0.86.0, pydantic 2.13.4, Pipe tests)
│   ├── openwebui-image.yml # non-required: build the Open WebUI image + smoke (path-filtered, no push)
│   └── release.yml         # v*.*.* tag on main → build/test → TestPyPI → PyPI (OIDC, SHA-pinned actions)
├── src/rbic/               # the library: no print/input/exit/basicConfig/dotenv here
│   ├── __init__.py         # public API: RBICEngine, Identity, Audience, AskResult, SQLGate, ...
│   ├── audit.py            # "rbic.audit" logger: NullHandler + configure(path) JSON lines
│   ├── config.py           # EngineConfig / resolve_config: args > RBIC_* env > defaults
│   ├── gate.py             # the PEP: parse → RBAC → ABAC → safe SQL; load_snapshot (THE loader)
│   ├── engine.py           # RBICEngine.ask(): identity → history → guard → gated tool loop
│   ├── identity.py         # Identity, AttributeProvider, JsonAttributeProvider, LocalProvider
│   ├── history.py          # sanitize_history: untrusted host history → text-only turns
│   ├── master.py           # master tools, dispatch, email redaction, confirm flow (injected I/O)
│   ├── admin.py            # validated, atomic, audited policy/attribute editor
│   ├── demo/seed.py        # demo company.db schema + rows (seed())
│   └── cli/                # the only terminal I/O: argparse, print/input, .env, logging setup
│       ├── chat.py         # rbic-chat: run_chatbot on RBICEngine.ask() (LocalProvider)
│       ├── master.py       # rbic-master: interactive master session
│       ├── gate_demo.py    # rbic-gate-demo: 15 fixed queries (6 ALLOW, 9 DENY on the demo)
│       └── seed.py         # rbic-seed
├── examples/demo/          # demo config dir (not in the wheel)
│   ├── casbin/
│   │   ├── model.conf      # RBAC model + p2 (ABAC filter) definition
│   │   └── policy.csv      # p (grants), g (hierarchy), p2 (row filters)
│   ├── db_schema.json      # table → columns; the qualify/deny reference
│   ├── worker_attributes.json  # username → {role, email, dept/site…}; IdP/HRIS stand-in
│   ├── company.db          # seeded SQLite demo DB (generated, gitignored)
│   └── policy_changes.jsonl  # runtime changelog of applied changes (gitignored)
├── tests/
│   ├── conftest.py         # copies examples/demo + seeded DB into tmp_path
│   ├── test_config.py      # pytest: config precedence, refusals, cwd independence
│   ├── test_engine.py      # pytest: RBICEngine.ask() decision order, guard, errors
│   ├── test_history.py     # pytest: host history sanitizing
│   ├── test_identity.py    # pytest: identity providers, email index, fingerprint, no-email logs/LLM
│   ├── test_phase1_review_fixes.py  # pytest: Phase 1 review regressions (emails, schema reload, URI, ...)
│   ├── test_cli.py         # pytest: rbic.cli entry points with injected I/O / fake clients
│   ├── test_library_hygiene.py  # pytest: AST scan, import side effects, audit.configure
│   ├── test_wheel_contents.py   # pytest: wheel = rbic/** + dist-info only
│   ├── test_admin_loader.py     # pytest: PolicyAdmin validates with gate.load_snapshot
│   ├── test_salary_policy_evolution.py  # pytest: policy stages 0→1→2
│   ├── test_master_policy.py   # pytest: master bot, hot reload, validation, undo
│   ├── test_master_confirm.py  # pytest: master yes/no confirmation flow
│   ├── test_scoped_grants.py   # pytest: 4-field p2 scoped grants
│   ├── test_user_overrides.py  # pytest: per-user rules, deny rules, precedence
│   ├── test_gate_review_fixes.py  # pytest: security-review regressions (both dialects)
│   └── test_openwebui_pipe.py     # pytest: the Open WebUI Pipe (importlib-loaded, fake client)
├── integrations/openwebui/ # Open WebUI plugin (sdist only, not in the wheel)
│   ├── rbic_pipe.py        # the Pipe function admins import (needs only pydantic + rbic)
│   ├── Dockerfile          # Open WebUI v0.12.4 (digest-pinned) + rbic wheel built from src/
│   ├── requirements-*.txt  # hash-pinned casbin/simpleeval/sqlglot + wheel build tooling
│   ├── docker-compose.yml  # test deployment: Open WebUI + Keycloak OIDC, hardening env
│   ├── keycloak/realm-rbic.json  # test realm: open-webui client, owui-admin/bob/carol/dave/mallory
│   └── README.md           # quickstart, Valves, SSO recipes, hardening checklist, e2e script
└── scripts/demo/           # drive.py + record.ps1: re-record docs/master-bot-demo.gif
```

The config directory has a fixed layout (`casbin/model.conf`,
`casbin/policy.csv`, `db_schema.json`, `worker_attributes.json`; db
defaults to `<config_dir>/company.db`). There is no default config dir and
no cwd fallback: pass `--config-dir` or set `RBIC_CONFIG_DIR`
(`RBIC_DB_PATH`, `RBIC_MODEL`, `RBIC_DIALECT` likewise). `SQLGate` and
`PolicyAdmin` take explicit paths (or `.from_config(cfg)`); the gate's
`dialect` is a required keyword argument.

Run:
```bash
pip install -e ".[test]"
rbic-gate-demo --config-dir examples/demo   # gate demo cases (no API key needed)
rbic-seed --config-dir examples/demo        # (re)create the demo database
python -m pytest -q                         # all tests (work on tmp copies)
rbic-chat --config-dir examples/demo alice  # chat as a worker (needs ANTHROPIC_API_KEY)
rbic-chat --config-dir examples/demo bob    # hr_staff — try asking for salaries
rbic-master --config-dir examples/demo master  # master user: change policy by chatting
python -m rbic.cli.gate_demo --config-dir examples/demo  # any CLI also runs as a module
cd integrations/openwebui && docker compose up --build  # Open WebUI + Keycloak test deployment (its README)
```
Every CLI takes `--help`; `rbic-chat`, `rbic-master` and `rbic-gate-demo`
also take `--audit-log PATH` (JSON lines, see Audit logging).

### RBICEngine.ask() flow (engine.py)
`ask(identity, messages, *, conversation_id=None, audience=PRIVATE) ->
AskResult(text, denied, reason, worker, role, reset)` is the single entry
point for every chat host (`aask` = `asyncio.to_thread(ask)`; `reload()`
returns the policy fingerprint). In order — every refusal is code text and
happens before the LLM is called:
1. **Audience**: anything but `Audience.PRIVATE` (including strings) →
   `AUDIENCE_DENY_MESSAGE`, audit `AUDIENCE_DENY`.
2. **One snapshot**: `gate.refreshed_snapshot()` is taken once for
   identity, system prompt and fingerprint. Broken → `DENY_MESSAGE`,
   reason `policy unavailable`, history ignored.
3. **Identity**: the host's `Identity` is first copied to a fresh
   `Identity` of plain `str` fields (anything that isn't an `Identity`, or
   whose fields can't be read → "not an Identity"). The attribute provider
   (default `JsonAttributeProvider`: email → the worker whose record has
   that `email`, compared with `gate.normalize_email` — ASCII whitespace
   stripped, plain ASCII address required, ASCII-lowercased; **never
   casefolded**, which maps lookalikes such as `ſ`/U+212A/`ß`/`ﬁ` onto
   ASCII) resolves against that snapshot's **read-only** attributes
   (`MappingProxyType` / tuples all the way down: a provider can't change
   what later requests see). Unmapped, role-less, `master`, or a
   `user:` role → `DENY_MESSAGE`, audit `IDENTITY_DENY` (provider and
   subject — the host's user id — only: never the email, nor a hash of it).
4. **History**: `sanitize_history()` keeps only plain-text user/assistant
   turns (merged, truncated, ending with the user); empty → a fixed
   "Please type a question." (not a deny). The iterable is materialized
   once (one that fails part-way → empty); dicts are read via `dict.get`
   itself, other Mappings in a try; roles/contents (and the
   conversation id) are copied to exact `str`, so str/dict subclass
   overrides never run.
5. **Conversation guard** (in memory, bounded LRU of 10,000
   `(worker, conversation_id)` entries → policy fingerprint + digests of
   the replies `ask()` returned under it): no id / unknown conversation →
   only the last user turn is sent; fingerprint changed → only the last
   user turn, `reset=True`, reply prefixed with `POLICY_RESET_NOTICE`;
   same fingerprint → the turns after the last assistant turn that is not
   one of our own replies under this fingerprint (normally all of them),
   so pre-change turns the host still holds are never resent.
   The guard lives in **per-process memory**: after a restart, and in a
   multi-worker host (several processes / replicas) whenever a request
   lands on a process that hasn't seen the conversation, the conversation
   is unknown and is treated as new (fail closed: only the last user turn
   is sent). The fingerprint covers **every** worker's attributes, so any
   edit to worker_attributes.json (an HR change for one person) resets
   every conversation once.
6. **System prompt** built here from the worker's role (`allowed_schema`,
   `scoped_schema`) — never from the host.
7. **Tool loop** on a private copy; every `run_sql` → `gate.authorize()`;
   `AccessDenied` (or an unknown tool / malformed call) → `DENY_MESSAGE`,
   reason = the gate's reason. Tool blocks never leave `ask()`.
8. **Mid-turn change**: the snapshot is re-taken after the turn; a new
   version/fingerprint (or a broken gate) discards the answer →
   `POLICY_CHANGED_MESSAGE`, `reset=True`, guard entry dropped.
9. **Errors**: any Anthropic error → `LLM_UNAVAILABLE_MESSAGE`, audit
   `LLM_ERROR` (exception class only); anything else in the tool loop →
   same text, `ENGINE_ERROR`. Gated SQL that fails to execute gives the
   model only `"The query could not be executed. (<ExceptionClass>)"`
   (`SQL_ERROR_TOOL_MESSAGE`; SQLite messages can quote values), audit
   `SQL_ERROR` (class only).
10. **Never raises**: `ask()` wraps the whole pipeline; any `Exception`
   (a hostile host object, a bug) → `DENY_MESSAGE`, `denied=True`, reason
   `engine error`, audit `ENGINE_ERROR stage=ask` (class only).

`AskResult.reason` is for host logs only — hosts must never display it.
The engine executes on SQLite read-only (`engine.readonly_uri`:
`Path(db).resolve().as_uri() + "?mode=ro"`, never the raw path — a `#` or
`?` in it would drop `mode=ro`, a `%` would be decoded) and refuses to
build if the dialect isn't `sqlite` or the database is missing; the Anthropic client is
created lazily on the first LLM call. Library code (everything outside
`rbic.cli`) never calls `print`/`input`/`exit`/`sys.exit`/
`logging.basicConfig` or imports `dotenv` (`test_library_hygiene.py`
scans the AST); only the `rbic.cli.*` `main()`s load `.env` and set up
logging.

### Audit logging (rbic.audit)
- Every module logs on the `"rbic.audit"` logger (`rbic.audit.logger`):
  `ALLOW`/`DENY` (gate), `IDENTITY_DENY`, `AUDIENCE_DENY`,
  `POLICY_UNAVAILABLE_DENY`, `POLICY_RESET`, `POLICY_CHANGED_DURING_TURN`,
  `SQL_ERROR`, `LLM_ERROR`/`ENGINE_ERROR` (engine), `POLICY_RELOAD[_FAILED]`,
  `POLICY_CONFIRM`, `POLICY_CHANGE[_LOG_FAILED]` (master/admin),
  `PIPE_TASK_STUB`, `PIPE_AUDIENCE`, `PIPE_CONFIG_ERROR`, `PIPE_ERROR`
  (Open WebUI Pipe; it also writes `IDENTITY_DENY … reason=not an SSO
  user`). The line formats are stable.
- **Decision: library convention.** Importing `rbic` attaches only a
  `NullHandler` to `rbic.audit` and never touches the root logger. The
  trade-off is deliberate: with no handler anywhere, Python's last-resort
  handler stays silent and audit records (DENY warnings included) are
  discarded. So hosts are **required** to call
  `rbic.audit.configure(path, level=logging.INFO)` once at startup (the
  Open WebUI Pipe will) or attach their own handler to `rbic.audit`/root.
  `RBICEngine()` emits one `AuditNotConfiguredWarning` per process when
  neither happened (`audit.is_configured()`).
- `configure()` attaches one idempotent JSON-lines `FileHandler` (same
  path → same handler; a new path replaces it; host handlers are left
  alone; `unconfigure()` removes it) and lowers the logger level to
  `level` if needed. Each line: `{"ts": UTC ISO 8601, "level", "event":
  first word of the message, "message": the full audit line}`.
- The CLIs log `LEVEL message` to stderr (`logging.basicConfig`, casbin at
  WARNING) and add the JSON file with `--audit-log PATH`.
- Audit lines never contain a worker's email or a hash of one.
  `policy_changes.jsonl` (the master changelog used for history/undo) does
  hold full before/after file text, emails included — protect it like the
  config directory.

### rbic.cli.chat flow (rbic-chat)
- `run_chatbot` calls `engine.ask(Identity("local", username), history,
  conversation_id=<per-session uuid>)` with `LocalProvider` (CLI only —
  hosts serving web users must never use it), keeps a text-only history,
  and prints `result.text`. Deny handling lives only in `ask()`.
- The model gets a `run_sql` tool and a system prompt listing **only the
  tables/columns its role may read** (`allowed_schema()`), plus its scoped
  grants' column lists (`scoped_schema()`, flagged "row-limited", filter
  text not shown) — pure UX so it doesn't write doomed queries; the gate
  enforces regardless.
- Every `run_sql` call goes through `gate.authorize()`; results are returned
  to the model as JSON (capped at `MAX_ROWS_TO_MODEL`).
- The SQLite connection is opened **read-only** (`mode=ro`) — invariant #3.
- On `AccessDenied`, the private tool-use turns are discarded and
  `DENY_MESSAGE` is returned from code (invariant #4).
- Each turn re-reads the policy (one snapshot) and rebuilds the system
  prompt from the worker's current role. When the policy fingerprint
  changed, earlier turns are dropped and the reply starts with "(Access
  policy was updated — conversation reset.)", so rows fetched under the
  old policy never linger; the CLI then trims its own history too.

### Hot reload (rbic.gate)
- `authorize()` starts with `_maybe_reload()`: stat (mtime_ns, size, inode)
  of policy.csv, model.conf, worker_attributes.json **and db_schema.json**;
  on change, build a complete new immutable `PolicySnapshot` (enforcer,
  attributes, schema, compiled row filters, version, broken reason) with
  `load_snapshot()` and swap it in under a `threading.Lock`, then log
  `POLICY_RELOAD`.
- `load_snapshot(model_bytes, policy_bytes, attributes_bytes,
  schema_bytes, *, dialect)` is **the** loader: `check_policy_bytes` (lone
  CR, unknown ptype), the bytes-based Casbin load (`load_enforcer`), JSON
  attributes and schema, `compile_snapshot` (schema shape, arity, user
  subjects, master, unsafe filters, email shape/uniqueness) and the
  fingerprint. PolicyAdmin validates with the same function over the same
  files (db_schema.json included), so it can never write a policy the gate
  would refuse.
- The schema is part of the snapshot (`snapshot.schema`, read-only;
  `gate.schema` is the current snapshot's): qualify, column resolution,
  row-filter compilation and the engine's system prompt all use the
  request's snapshot schema, never a copy taken at start-up. Editing
  db_schema.json takes effect on the next request (no restart), and a
  malformed one fails the reload (deny all) like any other policy file.
- Snapshot attributes and schema are deeply read-only (`gate.freeze`:
  `MappingProxyType` over fresh dicts, tuples for lists). Code that needs
  different attributes writes worker_attributes.json (or goes through
  PolicyAdmin); nothing mutates a snapshot.
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

### rbic.master / rbic.cli.master flow (rbic-master)
- `rbic.master` holds the tools, dispatch (`run_tool`), system prompt and
  the confirm flow (`confirm_pending`, `ask_yes_no`) with injected
  `input_fn`/`output`; `rbic.cli.master.run_master_bot` is the terminal
  loop. `require_master` raises `NotMasterError`; the CLI exits with it.
- `rbic-master --config-dir <dir> master` refuses to start (and re-checks
  before every turn) unless the user's role is `master`. `master` is not a
  Casbin role and has no data grants or data tools.
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
  Every proposal's resulting files (policy.csv + worker_attributes.json)
  must load through `gate.load_snapshot` in both dialects, else it is
  refused ("would not load in the SQL gate: …").
- **No worker emails reach the LLM.** `run_tool` output is what the model
  sees: `describe_user` shows `email: <set>` / `<not set>`, and any worker
  address left in any tool result (or `[Code note]` error) is replaced by
  `<email>`. The human-facing description/diff printed at the
  confirmation prompt is unchanged.
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
  "Policy changed since this was proposed — please ask again" — and that
  the resulting files load through `gate.load_snapshot` (before the
  changelog record is written).
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
- Four ptypes, all read by `rbic.gate` (`enforce()` is not used for
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
- **Template rules** (`rbic.gate.compile_row_filter`). Always, also enforced
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
Single source of truth for what tables/columns exist
(`{table: {column: type}}`). Dual purpose:
1. lets `sqlglot.optimizer.qualify` resolve unqualified columns and expand
   `SELECT *` into explicit columns → star queries get real column-level RBAC;
2. any table/column not listed here is an automatic deny.
Keep it in sync with the real database (generate it from information_schema
in production). It is hot-reloaded and fingerprinted with the policy files
(see Hot reload): a schema change applies on the next request and resets
worker conversations once.

### `worker_attributes.json`
Demo stand-in for the IdP/HRIS. In production these attributes must come from
the authenticated session, never from user input. `email` (optional per
worker) is the identity key `JsonAttributeProvider` maps sign-ins by: it
must be a plain ASCII address and unique after ASCII lowercasing
(`gate.normalize_email`, the same normalization identity emails get), or
the load fails closed (everyone denied). The master bot can never change an email
(`propose_set_attribute` refuses it, and no other path, undo included,
may alter one) — it is owned by HR / the IdP.

**Policy fingerprint**: `gate.fingerprint` / `PolicySnapshot.fingerprint`
is a sha256 over the exact bytes of model.conf, policy.csv,
worker_attributes.json and db_schema.json that the snapshot was built from
(each file is read once per load; the bytes parsed are the bytes hashed). Unlike
`policy_version` it is stable across restarts and processes.
`compile_row_filter` and `compile_snapshot` take `dialect` as a required
keyword.

---

## Security Invariants (do not weaken these)

1. **Fail closed.** Unparseable SQL, multi-statement input, non-SELECT
   statements, unknown tables/columns, unresolved stars, missing worker
   attributes — all deny.
2. **SQL-parsing completeness is the security boundary.** Every construct the
   parser can't fully account for must be rejected, not passed through. v1 is
   deliberately narrow (single SELECT); widen it only with tests proving the
   new construct is gated. Concretely, after `qualify` every node of the
   tree must be in `rbic.gate.SUPPORTED_NODES` and none in
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
11. **Identity comes only from the host's authenticated session.**
    `ask()` resolves `Identity` (provider, subject, verified email) through
    an `AttributeProvider` against the request's one snapshot; unmapped,
    role-less, `master` and `user:`-role workers are denied with
    `DENY_MESSAGE` before the LLM is called (audit `IDENTITY_DENY`).
    Worker emails are validated and unique (else the load fails closed) and
    can't be changed through the master bot. `LocalProvider` (subject =
    worker key) is for the CLI and tests only.
12. **Host history is untrusted text.** Only plain-text user/assistant
    turns survive `sanitize_history`; the system prompt is always built
    server-side; tool_use/tool_result blocks stay inside `ask()`; the
    caller's message list is never mutated. Earlier turns are only sent
    for a known conversation whose fingerprint is unchanged, and only after
    the last assistant turn that isn't one of the engine's own replies
    under that fingerprint.
13. **Non-private audiences are denied.** Only `Audience.PRIVATE` is
    answered; shared/unknown channels get `AUDIENCE_DENY_MESSAGE` from code
    and the LLM is never called.

### Open WebUI Pipe flow (integrations/openwebui/rbic_pipe.py)
Phase 2 host, written against Open WebUI **v0.12.4** source (facts and
file references in `integrations/openwebui/README.md`, "Verified
against"). One model (`pipes()` → `<function id>.rbic`, "Company Data
(RBIC)"); `async pipe(body, __user__, __metadata__, __task__,
__event_emitter__)` returns a `str` (no streaming). In order, every
refusal is fixed code text:
1. **Tasks**: `__task__` (or `__metadata__["task"]`) set → a fixed,
   data-free stub in the format Open WebUI parses (`{"title": "Company
   data chat"}`, `{"tags": []}`, `{"follow_ups": []}`, `{"queries": []}`,
   `{"text": ""}`, `{"operations": []}`, a fixed compaction note, else
   `""`), audit `PIPE_TASK_STUB`; the engine is never called (Host
   requirements below).
2. **Config**: Valve `AUDIT_LOG_PATH` required (`rbic.audit.configure`,
   else "not configured" text); `EXPECTED_RBIC_VERSION`, when set, must
   equal `rbic.__version__` (`PIPE_CONFIG_ERROR`).
3. **Identity**: `Identity("openwebui", __user__["id"],
   __user__["email"])`. `IDENTITY_SOURCE="oauth"` (default) requires
   Open WebUI's SSO marker `__user__["oauth"] = {provider: {"sub": …}}`
   (written on every OAuth/OIDC sign-in; admin-created/local users have
   `null`), else `DENY_MESSAGE` + `IDENTITY_DENY` with no engine call.
   `"admin_created"` (tests only) accepts any user; the engine's
   `JsonAttributeProvider` maps the email either way.
4. **Audience**: `PRIVATE` only for a saved chat the user owns that is
   not shared (share_id / shared-chat row), not in a shared or foreign
   folder, not internal (`metadata.internal`, sub-agents/notes), not
   `channel:` and not `temporary:`/`local:`; looked up in Open WebUI's
   own tables in-process (`_chat_audience`, fails closed: lookup error or
   no Open WebUI → `UNKNOWN`). Empty `chat_id` (direct API call) →
   `UNKNOWN` unless Valve `ALLOW_API_REQUESTS` (e2e only). Non-private →
   the engine returns `AUDIENCE_DENY_MESSAGE`; the Pipe logs
   `PIPE_AUDIENCE` with the reason.
5. **Answer**: `engine.aask(identity, body["messages"],
   conversation_id=chat_id, audience=…)` → `result.text` only (never
   `reason`, never exception text; anything unexpected → fixed text,
   `PIPE_ERROR` class only). One "Checking access…" status event (done
   at the end); emitter errors/timeouts are ignored.
- One `RBICEngine` per Valves tuple (`CONFIG_DIR`, `DB_PATH`, `MODEL`),
  built off the event loop under a lock and rebuilt when they change;
  empty `CONFIG_DIR`/`DB_PATH` fall back to `RBIC_CONFIG_DIR`/
  `RBIC_DB_PATH`. The Anthropic key comes only from the container env
  (Valves are plaintext in Open WebUI's DB). `_TEST_CLIENT_FACTORY` is a
  test-only seam; production never sets it.
- **Plan corrections (docs/plugin-plan.md §5)**: pinned v0.12.4, not
  v0.12.3 (security fixes); `ENABLE_LOGIN_FORM=false` only hides the
  form — `ENABLE_PASSWORD_AUTH=false` is what closes password sign-in;
  a non-empty `chat_id` is not proof of a private chat (0.12 shared
  chats in "continue" mode and shared folders let other users write into
  the owner's chat; channels use `channel:` ids), hence the ownership
  lookup; `EXPECTED_RBIC_VERSION` refuses requests instead of failing
  the import; more tasks than title/tags/follow-ups reach the Pipe
  (query, autocomplete, emoji, image prompt, memory review, context
  compaction, function calling), and a separate task model or context
  compaction model would receive transcripts without the Pipe ever
  seeing them (disable them; see the hardening checklist); Open WebUI
  does not check `email_verified`, so the IdP must own emails;
  `ENABLE_PERSISTENT_CONFIG=false` keeps the hardening env authoritative.

### Host requirements (Phase 2 design note)

- **Never paste transcripts into a user turn.** The conversation guard
  (invariant #12) only filters *assistant* turns: earlier replies that a
  host re-sends inside a USER turn are indistinguishable from the user's
  own text, so they bypass the policy-change reset and rows fetched under
  an old policy reach the model again. Open WebUI's background tasks
  (chat title, tags, follow-up suggestions) do exactly this. Hosts must
  route such background/task requests **away from `ask()`** (or answer
  them without data, e.g. a fixed title) and only ever call `ask()` with
  the real chat history, one message per turn. The Open WebUI Pipe does
  this (stubs for every `__task__`); Open WebUI must also not route
  tasks or context compaction to a *different* model (see
  `integrations/openwebui/README.md`).

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

Install: `pip install -e ".[test]"` (development) or, once released,
`pip install rbic-plugin`. Releases: tag `vX.Y.Z` → `.github/workflows/release.yml`
(TestPyPI, then PyPI after approval); see `docs/RELEASING.md`.
`__version__` lives only in `src/rbic/__init__.py` (currently `0.1.0.dev0`).

LLM model for text-to-SQL / summarization: `claude-sonnet-4-6`.

---

## Next Steps

- **Audit persistence**: `rbic.audit.configure(path)` writes JSON lines
  today; next, structured fields (worker, role, original SQL, rewritten
  SQL, decision, reason) and shipping to a table / SIEM
- **IdP integration**: replace `worker_attributes.json` with session-derived
  attributes
- **Postgres migration**: swap SQLite for Postgres; generate `db_schema.json`
  from `information_schema`; add a SELECT-only DB role scoped to sanctioned
  views (strengthens invariant #3 beyond SQLite's `mode=ro`)
- **Master web UI**: a web front end for `rbic.master` (same
  propose → human-confirm → apply flow; never expose an apply tool to the LLM)
- **Gate test suite**: keep growing it with every new SQL construct
  admitted past the parser (invariant #2); the demo cases run in
  `test_cli.py` and the mock-client chatbot tests in `test_engine.py`
- **Plugin roadmap**: see `docs/plugin-plan.md` (core package → Open WebUI
  plugin with SSO → onboarding toolkit; Chainlit and master web UI deferred).
  Phase 2 (Open WebUI Pipe, image, Keycloak test deployment) lives in
  `integrations/openwebui/`; its manual end-to-end run against a live
  deployment is still to do.
