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
├── seed_db.py              # creates + seeds company.db (demo data)
├── company.db              # seeded SQLite demo DB (regenerate anytime)
├── test_salary_policy_evolution.py  # pytest: policy stages 0→1→2
└── requirements.txt        # anthropic, python-dotenv, casbin, sqlglot, pytest
```

Run:
```bash
python sql_gate.py        # gate demo cases (no API key needed)
python seed_db.py         # (re)create the demo database
pytest -q                 # policy-evolution + invariant tests
python chatbot.py alice   # chat as a worker (needs ANTHROPIC_API_KEY)
python chatbot.py bob     # hr_staff — try asking for salaries
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
6. **Attribute values are escaped** before substitution into filters; move to
   real query parameters when wiring a production DB driver.

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
- **master_ui.py**: CLI/web for the master user to edit `policy.csv` safely
- **Gate test suite**: `test_salary_policy_evolution.py` is the start — fold
  in the `sql_gate.py` demo cases and mock-client chatbot tests, and grow the
  suite with every new SQL construct admitted past the parser (invariant #2)
- **Policy hot-reload**: `enforcer.load_policy()` on file change (or from
  master_ui.py) so policy edits apply to running sessions, with an audit
  entry per reload
