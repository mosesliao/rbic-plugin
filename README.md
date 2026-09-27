# RBIC Plugin — Role-Gated LLM Chatbot (Casbin RBAC+ABAC over Text-to-SQL)

An enterprise LLM chatbot that answers workers' questions from a company
database while revealing **only what their role permits**.

The LLM translates natural-language questions into SQL, but it is treated as
untrusted: every statement it generates passes through a SQL gate that

1. **parses** it to an AST (`sqlglot`) — single `SELECT` only,
2. **RBAC-checks** every referenced `table.column` against a Casbin policy,
3. **rewrites** it with ABAC row filters bound from the worker's attributes
   (e.g. `WHERE dept = 'engineering'`),

before it ever touches the database. Restricted data never enters the model's
context. Denied requests always get the fixed, code-generated response:

> *"You have no access to this information, please approach your manager."*

```
worker question ──► LLM (text-to-SQL) ──► sql_gate.authorize()
                                              │  parse → RBAC → ABAC → audit
                                              ▼
                                    SQLite (read-only) ──► rows ──► LLM ──► answer
```

---

## Prerequisites

- Python 3.10+
- An Anthropic API key (only needed for the chat loop — the gate demo runs
  without one)

## Installation

```bash
# 1. Clone / copy the project, then from the project root:
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root (never commit it):

```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

## Running

### 1. Seed the demo database

```bash
python seed_db.py
```

Creates `company.db` (SQLite) with 9 tables and demo rows spanning two
warehouses (`SG-01`, `SG-02`) and two departments (`engineering`,
`logistics`), so you can see the row filtering work.

### 2. Smoke-test the SQL gate (no API key needed)

```bash
python sql_gate.py
```

Runs ~10 allow/deny cases and prints each decision, e.g. `SELECT * FROM
employees` as hr_staff is denied because the star expands to the forbidden
`salary` column.

### 3. Chat as a worker

```bash
python chatbot.py alice     # warehouse_worker, site SG-01
python chatbot.py bob       # hr_staff, dept engineering
python chatbot.py carol     # hr_manager (inherits hr_staff + salary access)
python chatbot.py dave      # finance_analyst, dept logistics
```

Type `exit` to quit.

### Demo users

| User  | Role             | Sees                                                    |
|-------|------------------|---------------------------------------------------------|
| alice | warehouse_worker | inventory / shipments / incidents — **SG-01 rows only** |
| bob   | hr_staff         | employees (no salary), leave, trainings — **engineering only** |
| carol | hr_manager       | everything bob sees **plus salaries**                   |
| dave  | finance_analyst  | budgets, invoices, expenses — **logistics expenses only** |

### Things to try

```
python chatbot.py bob
You: who is on leave this month?          → answers from engineering rows only
You: what is everyone's salary?           → "You have no access to this information, ..."
You: what is my salary?                   → answered from bob's own payroll row only

python chatbot.py carol
You: show me my team's salaries           → self + subordinates (Bob, Erin) only

python chatbot.py alice
You: which SKUs are running low?          → SG-01 stock only; SG-02 is invisible
You: show me the expense reports          → denied (not a warehouse topic)
```

### Policy as code

Access rules evolve by editing `casbin/policy.csv` — no code changes. The
shipped policy encodes a three-stage salary rollout (deny-all → workers see
their own payslip → managers also see subordinates'), and
`test_salary_policy_evolution.py` replays all three stages against the same
codebase:

```bash
pytest -q
```

---

## Managing access (master user)

All policy lives in two files — no code changes needed:

- **`casbin/policy.csv`**
  - `p, <role>, <table.column|table.*>, read` — RBAC grants
  - `g, <role>, <parent_role>` — role inheritance
  - `p2, <role>, <table>, <filter template>` — ABAC row filters;
    `{placeholders}` are bound from the worker's attributes at query time
- **`worker_attributes.json`** — `username → {role, dept/site, …}`
  (stand-in for your IdP/HRIS)

Example — give a new `auditor` role read access to all invoices in their
region only:

```csv
p, auditor, invoices.*, read
p2, auditor, invoices, region = '{region}'
```

then add the worker: `"eve": { "role": "auditor", "region": "APAC" }`.

If you add tables/columns to the database, mirror them in `db_schema.json` —
anything not listed there is denied automatically.

---

## Project layout

```
casbin/model.conf        Casbin model (RBAC matcher + p2 ABAC definition)
casbin/policy.csv        grants, role hierarchy, row-filter templates
db_schema.json           table → columns; unknown tables/columns are denied
worker_attributes.json   demo users and their attributes
sql_gate.py              the enforcement gate (parse → RBAC → ABAC → audit)
chatbot.py               worker CLI (text-to-SQL loop, read-only DB access)
seed_db.py               creates + seeds company.db
CLAUDE.md                architecture notes and security invariants
```

## Security model (short version)

- **Fail closed** — unparseable SQL, non-SELECT statements, unknown
  tables/columns, or missing worker attributes all deny.
- **Enforcement is code, not prompts** — the allowed-schema shown to the LLM
  is a convenience; the gate re-checks every query regardless.
- **Defense in depth** — the chatbot opens SQLite read-only (`mode=ro`).
- **Deny message is code** — the model never generates (and can't be talked
  out of) the refusal.
- **Audit** — every ALLOW (with rewritten SQL) and DENY (with reason) is
  logged via the `rbic.audit` logger.

See [CLAUDE.md](CLAUDE.md) for the full invariants and design rationale.
