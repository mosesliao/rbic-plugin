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
host (CLI / chat platform) ──► RBICEngine.ask(identity, messages)
                                  │  audience → identity → history → policy guard
                                  ▼
                        LLM (text-to-SQL) ──► SQLGate.authorize()
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

From PyPI, once the first release is out (the distribution is `rbic-plugin`,
the import package is `rbic`):

```bash
pip install rbic-plugin
```

The wheel contains only the `rbic` package. The demo configuration
(`examples/demo/`) lives in this repository (and the sdist), so for the
quickstart below clone the repository.

For development (editable, with test dependencies):

```bash
# from the project root
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e ".[test]"
```

Every command below takes `--config-dir` (or reads `RBIC_CONFIG_DIR`); there
is no default configuration directory. The demo configuration lives in
`examples/demo/`.

## Configuration

Create a `.env` file in the project root (never commit it):

```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

Only the command-line tools read `.env`. The library never does: a host
application passes `api_key=` (or sets `ANTHROPIC_API_KEY` itself).
`RBIC_CONFIG_DIR`, `RBIC_DB_PATH`, `RBIC_MODEL` (default
`claude-sonnet-4-6`) and `RBIC_DIALECT` (default `sqlite`) are read from the
environment when no argument is given.

## Running

### 1. Seed the demo database

```bash
rbic-seed --config-dir examples/demo
```

Creates `examples/demo/company.db` (SQLite; `--db PATH` writes elsewhere) with 10 tables and demo rows spanning two
warehouses (`SG-01`, `SG-02`) and two departments (`engineering`,
`logistics`), so you can see the row filtering work.

### 2. Smoke-test the SQL gate (no API key needed)

```bash
rbic-gate-demo --config-dir examples/demo
```

Runs 15 fixed queries through the gate and prints each decision (6 ALLOW,
9 DENY on the demo policy), e.g. `SELECT * FROM employees` as hr_staff is
denied because the star expands to the forbidden `salary` column.

### 3. Chat as a worker

```bash
rbic-chat --config-dir examples/demo alice   # warehouse_worker, site SG-01
rbic-chat --config-dir examples/demo bob     # hr_staff, dept engineering
rbic-chat --config-dir examples/demo carol   # hr_manager (inherits hr_staff + salary access)
rbic-chat --config-dir examples/demo dave    # finance_analyst, dept logistics
```

Type `exit` to quit. Every command takes `--help`; `rbic-chat`,
`rbic-master` and `rbic-gate-demo` also take `--audit-log PATH` to append
the audit records as JSON lines. Each command also runs as a module, e.g.
`python -m rbic.cli.chat --config-dir examples/demo alice`.

| Command | Module | What it does |
|---------|--------|--------------|
| `rbic-chat USER` | `rbic.cli.chat` | chat with company data as a worker |
| `rbic-master USER` | `rbic.cli.master` | change access policy by chatting (master users only) |
| `rbic-gate-demo` | `rbic.cli.gate_demo` | gate decisions for fixed queries, no API key |
| `rbic-seed` | `rbic.cli.seed` | (re)create the demo SQLite database |

### Demo users

| User  | Role             | Sees                                                    |
|-------|------------------|---------------------------------------------------------|
| alice | warehouse_worker | inventory / shipments / incidents — **SG-01 rows only** |
| bob   | hr_staff         | employees (no salary), leave, trainings — **engineering only** |
| carol | hr_manager       | everything bob sees **plus salaries**                   |
| dave  | finance_analyst  | budgets, invoices, expenses — **logistics expenses only** |
| master | master          | **no data** — manages policy via `rbic-master`          |

### Things to try

```
rbic-chat --config-dir examples/demo bob
You: who is on leave this month?          → answers from engineering rows only
You: what is everyone's salary?           → "You have no access to this information, ..."
You: what is my salary?                   → answered from bob's own payroll row only

rbic-chat --config-dir examples/demo carol
You: show me my team's salaries           → self + subordinates (Bob, Erin) only

rbic-chat --config-dir examples/demo alice
You: which SKUs are running low?          → SG-01 stock only; SG-02 is invisible
You: show me the expense reports          → denied (not a warehouse topic)
```

### Policy as code

Access rules evolve by editing `examples/demo/casbin/policy.csv` — no code changes. The
shipped policy encodes a three-stage salary rollout (deny-all → workers see
their own payslip → managers also see subordinates'), and
`tests/test_salary_policy_evolution.py` replays all three stages against the same
codebase:

```bash
pytest -q
```

---

## Using it from Python

`RBICEngine.ask()` is the single entry point a chat host calls. The host
supplies who is asking (from its own authenticated session, never from
what the user typed) and the chat history (treated as untrusted text);
every refusal is fixed text from code.

```python
import logging

from rbic import Audience, Identity, RBICEngine, audit

# Required for hosts: keep the audit trail (ALLOW / DENY / POLICY_* lines).
audit.configure("/var/log/rbic/audit.jsonl", level=logging.INFO)

engine = RBICEngine.from_config_dir(
    "examples/demo",                 # or RBIC_CONFIG_DIR
    api_key="sk-ant-...",            # or ANTHROPIC_API_KEY in the environment
)

# The host's signed-in user. JsonAttributeProvider (the default) maps the
# verified email to the worker whose record in worker_attributes.json has it.
who = Identity(provider="openwebui", subject="user-123", email="bob@example.test")

result = engine.ask(
    who,
    [{"role": "user", "content": "What is everyone's salary?"}],
    conversation_id="chat-42",       # lets follow-up turns keep their context
    audience=Audience.PRIVATE,       # shared channels are refused
)
print(result.text)     # safe to show: the answer, or the fixed deny message
print(result.denied)   # True when the gate refused the SQL (hr_staff can't read salaries)
# result.reason is for host logs only; never show it to users.
```

- `await engine.aask(...)` is the asyncio version; `engine.reload()` picks
  up policy changes now and returns the policy fingerprint.
- An unmapped identity, a `master` user, or a non-private audience is
  refused before the LLM is called.
- When the policy changes, earlier turns of a conversation are dropped and
  the reply starts with `(Access policy was updated — conversation
  reset.)` (`result.reset` is `True`). The conversation guard is in-process
  memory: after a restart, or in another worker process, a conversation is
  treated as new.
- **Audit logging.** Importing `rbic` only adds a `NullHandler` to the
  `rbic.audit` logger, so a host that configures nothing would silently
  lose the audit trail. Call `rbic.audit.configure(path)` (one JSON object
  per line: `ts`, `level`, `event`, `message`) or attach your own handler;
  `RBICEngine` warns once (`AuditNotConfiguredWarning`) if neither was done.

---

## Managing access (master user)

All policy lives in two files — no code changes needed:

- **`casbin/policy.csv`**
  - `p, <role>, <table.column|table.*>, read` — RBAC grants
  - `g, <role>, <parent_role>` — role inheritance
  - `p2, <role>, <table>, <filter template>` — ABAC row filters;
    `{placeholders}` are bound from the worker's attributes at query time
- **`worker_attributes.json`** — `username → {role, email, dept/site, …}`
  (stand-in for your IdP/HRIS). `email` is the identity key hosts sign
  users in by: it must be a plain address and unique, or the policy fails
  to load and everyone is denied

Example — give a new `auditor` role read access to all invoices in their
region only:

```csv
p, auditor, invoices.*, read
p2, auditor, invoices, region = '{region}'
```

then add the worker: `"eve": { "role": "auditor", "email": "eve@example.com", "region": "APAC" }`.

If you add tables/columns to the database, mirror them in `db_schema.json` —
anything not listed there is denied automatically.

---

## Master chatbot (change access policy by chatting)

The master user can inspect and change access policy in plain English:

```bash
rbic-master --config-dir examples/demo master
```

Only users whose record in `worker_attributes.json` has `"role": "master"`
can start it (`rbic-master --config-dir examples/demo bob` exits with an error). The master
bot has no data tools: it can't query the business database, and worker
email addresses are never sent to the model (`describe_user` shows
`email: <set>` or `<not set>`).

Example requests:

```
You: what can bob see?                   → describes bob's role, columns and row filters
You: let hr_staff see salaries           → proposes  p, hr_staff, employees.salary, read
You: dave should only see unpaid invoices→ proposes  p2, finance_analyst, invoices, status = 'unpaid'
You: move dave to hr_staff               → proposes a role change in worker_attributes.json
You: undo that                           → proposes reverting the last applied change
```

**The model only proposes; you confirm.** After each reply, the code (not
the model) prints every proposed change: a plain-English effect summary
(including WARNINGs, e.g. "row filter removed: ALL rows visible") and a
unified diff of the real file. Then it asks `Apply change <id>? [yes/no]`.
Only `yes` or `y` (any case) writes the file; `no` or `n` declines; anything
else asks again; end of input (Ctrl-D / Ctrl-Z) declines. Every decision is
logged on `rbic.audit`. There is no "apply" tool for the model to call.

**Changes are live.** The SQL gate checks the policy files' timestamps on
every query and hot-reloads them, so workers pick up changes on their next
question. A worker session whose policy changed clears its conversation
history (`(Access policy was updated — conversation reset.)`) so rows fetched
under the old policy don't linger in the model's context. If a reload fails
(e.g. a hand-edited policy.csv is malformed or has an unsafe row filter),
every query is denied and worker conversation history is cleared until the
file is fixed.

**Guard rails** (enforced in `rbic.admin`, not by the model):
- tables/columns must exist in `db_schema.json`; role names are validated;
  duplicate rules and inheritance cycles are rejected
- the `master` role can't be granted, inherited, or assigned, and master
  users' records can't be edited through the bot
- row filters may only reference their own table's columns: no subqueries,
  table references or unsafe functions (a subquery would bypass the
  column check). Commas are allowed only inside parentheses (Casbin's CSV
  format has no quoting)
- row filters must be plain printable ASCII with no SQL comments, and be
  made only of comparisons of a column with a value (`=`, `<>`, `<`, `>`,
  `IN`, `IS`, `LIKE`, `BETWEEN`) joined by AND/OR/NOT. Always-true or
  non-restrictive filters (`TRUE`, `1`, `employee_id = employee_id`,
  `... OR 1 = 1`) are rejected. A filter with no `{placeholder}` is allowed
  but flagged: "WARNING: this filter is the same for every user (it does
  not depend on who is asking)."
- the SQL gate binds attribute values as literal values, never as SQL
  text, so a value can't become a column name, operator or subquery. On
  top of that, attribute values can't contain quotes, parentheses or
  operators, and a value used in an unquoted placeholder (e.g.
  `IN ({ids})`) must be a number or a comma-separated list of numbers
- a change is refused if **any** policy input (policy.csv,
  worker_attributes.json, db_schema.json, model.conf) changed after it was
  proposed: "Policy changed since this was proposed — please ask again".
  If you confirm several proposals from one reply, the later ones are
  refused once an earlier one is applied, so ask again to get a fresh
  proposal. Writes are atomic, and the files a change would produce must
  load with the SQL gate's own loader (`rbic.gate.load_snapshot`), both
  when it is proposed and again just before it replaces the live file, so
  the bot can never write a policy the gate would refuse
- only one change is applied at a time, even across processes (lock file
  `casbin/.policy.lock`; if a crash ever leaves it behind, the error
  message tells you which file to delete)
- every change is appended to `policy_changes.jsonl` (who, when, what,
  before/after text + hashes) *before* the file is replaced, followed by
  an `applied` or `failed: …` record, and logged as `POLICY_CHANGE` on the
  `rbic.audit` logger. History and undo only use applied changes.
  Comments in `policy.csv` are preserved: new rules go under
  `# ---- Changes via master chatbot ----`. Diffs and summaries show
  control characters escaped (e.g. `\x0c`) so nothing can hide in them

### Demo: changing policy live

![Master bot (top) grants and revokes alice's access to Carol's salary while alice's worker chatbot (bottom) picks up each change](docs/master-bot-demo.gif)

Top pane: `rbic-master --config-dir examples/demo master`. Bottom pane:
`rbic-chat --config-dir examples/demo alice`
(warehouse_worker). Everything shown is live output from the real bots, the
SQL gate and the API. Dimmed `[gate audit]` lines are a condensed copy of
the `rbic.audit` log.

1. alice asks for Carol's salary. Her own-payslip row filter is ANDed into
   the query (`AND payroll.employee_id = '6'`), so no rows come back.
2. The master asks: "Let Alice alone see Carol's salary". The bot proposes
   `p2, user:alice, employees, id = 2, id|name|salary` and shows the diff.
   The human types `yes`.
3. alice asks again. Her chatbot prints `(Access policy was updated —
   conversation reset.)` and answers with the salary.
4. The master asks: "Remove that grant again". It shows the diff, gets `yes`,
   and alice's next question finds nothing again.

Try it yourself in a Windows Terminal window split horizontally (or split
an open tab with Alt+Shift+-):

```powershell
wt -d . rbic-master --config-dir examples/demo master `; split-pane -H -d . rbic-chat --config-dir examples/demo alice
```

(The backtick escapes `;` for PowerShell. In cmd.exe, use a plain `;`.)

To re-record the GIF, run
`powershell -ExecutionPolicy Bypass -File scripts\demo\record.ps1` (needs
`wt` and `ffmpeg`, and makes real API calls). It backs up `policy.csv`,
`worker_attributes.json` and `policy_changes.jsonl` and starts from the
committed `policy.csv`. It drives both bots with `scripts/demo/drive.py`
and records the window with ffmpeg. When it finishes, or if it fails, it
restores the backed-up files and checks their hashes.

---

## Tests

```bash
pip install -e ".[test]"
python -m pytest -q                      # the whole suite (works on tmp copies of examples/demo)
python -m pytest -q tests/test_engine.py # one file
rbic-gate-demo --config-dir examples/demo
```

No test calls the Anthropic API (the client is a scripted fake). The suite
includes an AST scan that keeps terminal I/O out of the library
(`tests/test_library_hygiene.py`) and a wheel-contents check
(`tests/test_wheel_contents.py`, builds a wheel with `build`). CI runs it on
Python 3.10–3.12, smoke-tests the built wheel in a fresh virtualenv, and
runs the engine tests against `anthropic==0.86.0`, the lowest supported
version. Releases: see [docs/RELEASING.md](docs/RELEASING.md).

## Project layout

```
pyproject.toml                package metadata, dependencies, entry points
src/rbic/__init__.py          public API (RBICEngine, Identity, Audience, AskResult, SQLGate, ...)
src/rbic/engine.py            RBICEngine.ask(): identity, history, guard, text-to-SQL loop (read-only DB)
src/rbic/gate.py              the enforcement gate (parse → RBAC → ABAC → audit) and policy loader
src/rbic/identity.py          Identity and attribute providers (email → worker)
src/rbic/history.py           untrusted host history → text-only turns
src/rbic/audit.py             the rbic.audit logger; configure(path) for JSON-lines files
src/rbic/config.py            configuration resolution (args > RBIC_* env > defaults)
src/rbic/master.py            master chatbot: tools, propose, human confirms (no terminal I/O)
src/rbic/admin.py             validated, atomic, audited policy/attribute editor
src/rbic/demo/seed.py         demo database schema and rows
src/rbic/cli/                 rbic-chat, rbic-master, rbic-gate-demo, rbic-seed (all terminal I/O)
examples/demo/casbin/model.conf   Casbin model (RBAC matcher + p2 ABAC definition)
examples/demo/casbin/policy.csv   grants, role hierarchy, row-filter templates
examples/demo/db_schema.json      table → columns; unknown tables/columns are denied
examples/demo/worker_attributes.json  demo users and their attributes
examples/demo/company.db      seeded demo database (generated, gitignored)
examples/demo/policy_changes.jsonl  changelog of applied policy changes (gitignored)
tests/                        pytest suite (conftest.py copies examples/demo to tmp)
.github/workflows/            tests.yml (CI), release.yml (tag → TestPyPI → PyPI)
docs/RELEASING.md             how a release is cut and published
CLAUDE.md                     architecture notes and security invariants
docs/master-bot-demo.gif      recording of a live policy change (master + worker)
scripts/demo/                 drive.py (scripted bot driver), record.ps1 (re-record the GIF)
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
  logged via the `rbic.audit` logger (hosts: call `rbic.audit.configure`).
  Audit lines never contain a user's email.
- **Identity from the host** — who is asking comes from the host's
  authenticated session; unmapped users are denied before the LLM runs,
  host chat history is treated as untrusted text, and shared channels are
  refused.

See [CLAUDE.md](CLAUDE.md) for the full invariants and design rationale.
