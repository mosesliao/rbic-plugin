# RBIC plugin plan: core package, Open WebUI plugin, onboarding toolkit

- **Date:** 2026-10-21
- **Status:** approved plan. Phase 1 is merged. Phase 2 (Open WebUI plugin) is implemented on branch
  `feat/openwebui-pipe` (`integrations/openwebui/`); see `CLAUDE.md` for where it differs from section 5.

This document records the agreed plan for turning the RBIC gate and chatbot
into a reusable plugin. It is written for the project owner and for future
contributors. Names of current files, classes and functions (`sql_gate.py`,
`SQLGate`, `PolicySnapshot`, `compile_snapshot`, `run_chatbot`,
`PolicyAdmin`, `propose_set_attribute`) refer to the code on `main` at the
time of writing; see `CLAUDE.md` for how they work today.

---

## 1. Goal

Turn this repository into an installable Python package named `rbic`
(published on PyPI as `rbic-plugin`) with one host-neutral entry point. Ship
an Open WebUI plugin first. Then build an onboarding toolkit so that each
organization can generate its own policy instead of hand-writing it.

Throughout all phases, the gate's decisions and the 10 security invariants
in `CLAUDE.md` must not weaken.

---

## 2. Decisions (2026-10-20/21)

| Topic | Decision |
| --- | --- |
| Chainlit plugin | Deferred. Chainlit's GitHub repository was archived on 2026-10-15; the last release is 2.12.0. |
| Identity | SSO via standard OpenID Connect, provider-agnostic (works with Entra ID, Google Workspace, Okta, Keycloak). The reference and test environment uses Keycloak. |
| Master bot web UI | Deferred. The CLI stays the policy tool. |
| Open WebUI admins | Accepted as fully trusted. They can edit in-process function code and can read the configuration, the database and the API key. |
| Distribution | Publish to PyPI. |
| Database | Stay on the SQLite demo. A least-privilege Postgres executor is out of scope (about 2–3 days if added later). |

---

## 3. Phases and effort

Estimates are in engineer-days.

| Phase | Scope | Effort |
| --- | --- | --- |
| 1 | Core refactor | 6–9 |
| 2 | Open WebUI plugin | 4–6 |
| 3 | Onboarding toolkit | 8–12 (a rougher estimate than the others) |
| | **In-scope total** | **18–27** |
| Deferred | Chainlit plugin | 3–5 |
| Deferred | Master bot web UI | 5–8 |

The order is: core package first, then an Open WebUI pilot using the demo
policy, then the onboarding toolkit before a second organization is
onboarded. Optionally, a minimal `rbic init` (schema introspection, compile,
access report) can be folded into Phase 1.

The first PyPI release (0.1.0) happens at the end of Phase 1.

---

## 4. Phase 1 — core package

### 4.1 Layout

Start from a freshly fetched `main`. The code moves into a `src/` layout:

| Path | Contents | Comes from |
| --- | --- | --- |
| `src/rbic/gate.py` | The SQL gate | `sql_gate.py` |
| `src/rbic/admin.py` | Policy administration | `policy_admin.py` |
| `src/rbic/master.py` | Master tools, dispatch, and the confirm flow with injected I/O | `master_bot.py` |
| `src/rbic/engine.py` | System prompt, allowed/scoped schema, tool loop, SQLite executor | `chatbot.py` |
| `src/rbic/config.py` | Configuration resolution | new |
| `src/rbic/identity.py` | Identity types and attribute providers | new |
| `src/rbic/history.py` | Host history sanitizing | new |
| `src/rbic/audit.py` | Audit logger setup | new |
| `src/rbic/cli/` | `rbic-chat`, `rbic-master`, `rbic-gate-demo`, `rbic-seed` | the current `__main__` blocks |
| `examples/demo/` | Demo configuration (excluded from the wheel) | repository root |
| `tests/` | All tests | repository root |

### 4.2 Public API

```python
class Audience(Enum): PRIVATE; SHARED; UNKNOWN

@dataclass(frozen=True)
class Identity:
    provider: str
    subject: str
    email: str | None

@dataclass(frozen=True)
class AskResult:
    text: str
    denied: bool
    reason: str | None
    worker: str | None
    role: str | None
    reset: bool = False

class AttributeProvider(Protocol):
    def resolve(self, identity: Identity, attributes: Mapping[str, dict]) -> str | None

class RBICEngine:
    @classmethod
    def from_config_dir(cls, config_dir=None, *, db_path=None, model=None,
                        dialect=None, api_key=None, client=None,
                        attribute_provider=None) -> "RBICEngine"
    def ask(self, identity, messages, *, conversation_id: str | None = None,
            audience: Audience = Audience.PRIVATE) -> AskResult
    async def aask(...) -> AskResult   # asyncio.to_thread(self.ask, ...)
    def reload(self) -> str            # returns the policy fingerprint
```

### 4.3 What `ask()` does

`ask()` runs these steps in order:

1. **Refuse non-private audiences.** Any audience other than `PRIVATE` is
   denied.
2. **Resolve the identity.** If the identity is unmapped, has no role, or
   maps to a master user, the result is `DENY_MESSAGE`, an `IDENTITY_DENY`
   audit line is written, and the LLM is never called.
3. **Sanitize the host's history.** Only user and assistant turns whose
   content is a plain string are kept; system, tool and multimodal content is
   dropped. Adjacent turns are merged, the history is truncated, and the last
   turn must be a user turn.
4. **Apply the conversation guard** (see 4.5, fix 2).
5. **Build the system prompt on the server.** It is never taken from the
   host.
6. **Run the tool loop on a private copy of the history.** On
   `AccessDenied`, the result is `DENY_MESSAGE` from code. Tool blocks never
   leave `ask()`. Anthropic API errors are turned into a fixed message from
   code.

`AskResult.reason` is for host logs only and is never shown to users.

### 4.4 Configuration

Precedence, highest first:

1. Explicit arguments to `from_config_dir()`.
2. Environment variables `RBIC_CONFIG_DIR`, `RBIC_DB_PATH`, `RBIC_MODEL`,
   `RBIC_DIALECT`.
3. Defaults.

There is no default configuration directory or database path, and no
fallback to the current working directory. The model defaults to
`claude-sonnet-4-6` and the dialect defaults to `sqlite`. The engine refuses
to start if the gate's dialect differs from the executor's dialect.

### 4.5 Fixes found during planning

1. **Dialect mismatch.** `SQLGate`'s `dialect` default is `postgres`, while
   the chatbot runs on SQLite (today `run_chatbot` passes
   `SQLGate(dialect="sqlite")` explicitly). In the package, the dialect
   becomes required.
2. **Policy changes across restarts and workers.** The per-process
   `policy_version` counter cannot detect policy changes across restarts or
   across worker processes. The package adds a *policy fingerprint* (sha256
   of `model.conf`, `policy.csv` and `worker_attributes.json`) and an
   in-memory conversation guard that maps `(worker, conversation_id)` to a
   fingerprint:
   - If the fingerprint has changed, earlier turns are dropped and the answer
     is prefixed with `POLICY_RESET_NOTICE` (`reset=True`).
   - If the conversation is unknown or has no id, earlier turns are dropped
     silently (fail closed).
   - If the gate is broken, history is dropped.
3. **Identity takeover.** Once email is the identity key,
   `propose_set_attribute` must refuse `email` (as it already refuses
   `role`), and duplicate or invalid emails must fail the policy load.

### 4.6 Identity

`JsonAttributeProvider` reads an `email` field per worker in
`worker_attributes.json` and keeps a casefolded, unique index of emails. A
`local` provider, whose subject is the worker key, exists for the CLI only.

### 4.7 Library hygiene

- No `print`, `input`, `sys.exit`, `logging.basicConfig` or `load_dotenv`
  outside `cli/`.
- The `rbic.audit` logger gets a `NullHandler`.
- `audit.configure(path)` adds an idempotent JSONL handler.

### 4.8 What must not change

- Gate decisions and rewritten SQL. The golden parity tests must pass with
  import changes only.
- `DENY_MESSAGE` stays a code constant.
- One policy snapshot per request.
- `PolicyAdmin`'s flow: propose → hash check → lock → audit before replace.
- There is no apply tool.
- The `ALLOW`, `DENY` and `POLICY_*` audit line formats.

### 4.9 New invariants

These are added to the list in `CLAUDE.md`:

11. Identity comes only from the host's authenticated session, and unmapped
    users are denied before the LLM is called.
12. Host history is untrusted text, the system prompt is built by the
    server, and tool blocks stay inside `ask()`.
13. Non-private audiences are denied.

### 4.10 New tests

| Test | Covers |
| --- | --- |
| `test_engine.py` | `RBICEngine.ask()` behaviour |
| `test_history.py` | History sanitizing |
| `test_identity.py` | Identity resolution and the email index |
| `test_config.py` | Configuration precedence and refusals |
| `test_library_hygiene.py` | AST scan for forbidden calls; no root handlers on import |
| Wheel-contents test | No demo data, `company.db` or `.env` in the wheel |

---

## 5. Phase 2 — Open WebUI plugin

### 5.1 Files

All files live under `integrations/openwebui/`:

- `rbic_pipe.py` — the Pipe function.
- `Dockerfile` — the derived Open WebUI image.
- `docker-compose.yml` — a test deployment including Keycloak.
- `README.md` — deployment and hardening guide.

### 5.2 The Pipe

```python
async def pipe(self, body, __user__, __metadata__, __task__=None, __event_emitter__=None)
```

- The Pipe exposes one model, "Company Data (RBIC)".
- When `__task__` is set (title, tag or follow-up generation), the Pipe
  returns a fixed stub and never calls the engine.
- The identity is `Identity("openwebui", __user__["id"], __user__["email"])`.
- The Valve `IDENTITY_SOURCE` defaults to `oauth`, which requires a non-empty
  `__user__["oauth"]`, so only SSO users are served. An `admin_created` mode
  exists only for tests.
- The audience is `PRIVATE` only when `__metadata__["chat_id"]` is non-empty;
  otherwise the request is denied. The Valve `ALLOW_API_REQUESTS` exists for
  end-to-end tests only.
- `conversation_id` is the `chat_id`.
- Valves: `CONFIG_DIR`, `DB_PATH`, `MODEL`, `IDENTITY_SOURCE`,
  `AUDIT_LOG_PATH`, `EXPECTED_RBIC_VERSION` (the import fails if the
  installed `rbic` version does not match).
- The Anthropic API key comes from the container environment and is never a
  Valve, because Valves are stored in plaintext.
- No streaming. The Pipe emits one "Checking access…" status event.

### 5.3 Deployment

- Build a derived image `FROM ghcr.io/open-webui/open-webui:v0.12.3` that
  runs `pip install rbic-plugin==X.Y.Z` with `--require-hashes`.
- Do not use the `requirements:` frontmatter, and set
  `ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS=false`.
- Mount the configuration directory and the database read-only.
- The CLI `rbic-master` edits the same host directory, and hot reload picks
  up the changes.

### 5.4 SSO setup (provider-agnostic OIDC)

In every deployment:

- Enable OAuth sign-up.
- Hide the password login form.
- Disable local sign-up.
- Disable account merging by email (`OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false`).
- Restrict sign-in to the company email domain.

Provider recipes:

| Provider | Recipe |
| --- | --- |
| Microsoft Entra ID | Open WebUI's built-in Microsoft login. This is the same identity a future Teams bot would use. |
| Google Workspace | Open WebUI's built-in Google login, restricted to the company domain. |
| Okta, Keycloak or other | The generic OIDC provider URL. |

The exact Open WebUI environment-variable names must be verified against the
pinned version at implementation time.

### 5.5 Hardening checklist

- SSO only.
- Raw OpenAI/Ollama connections off, or hidden by access control;
  `BYPASS_MODEL_ACCESS_CONTROL=false`; `ENABLE_DIRECT_CONNECTIONS=false`.
- Chat sharing and community sharing off.
- Title, tag, follow-up and autocomplete generation off.
- File upload and tools off for this model.
- Treat Open WebUI admins as fully trusted.
- Be aware that answers are stored at rest in Open WebUI's database.

### 5.6 Verification

Run the `docker-compose.yml` deployment with Keycloak test users and check:

| Scenario | Expected result |
| --- | --- |
| bob asks for salaries | `DENY_MESSAGE` and a `DENY` audit line |
| carol asks for team payslips | Only `employee_id` 1, 2 and 3, and an `ALLOW` line with scopes |
| An unmapped user asks anything | `DENY_MESSAGE` and `IDENTITY_DENY`; no Anthropic call |
| A grant is revoked via `rbic-master` mid-chat | The next answer starts with the reset notice |
| Title generation | No `ALLOW`/`DENY` line |
| A request without `chat_id` | Denied |

Pipe unit tests use fake `__user__` and `__metadata__` values and need only
pydantic.

### 5.7 Risk

Open WebUI pins `anthropic==0.86.0`, while development uses 1.9.0. A
separate, non-required CI job tests the adapters against that pin.

---

## 6. Phase 3 — onboarding toolkit (`rbic init`)

### 6.1 Why

Every organization has different users, roles and tables, so `policy.csv` is
generated per organization. `model.conf`, which defines the policy language,
is the same for everyone.

| Ships in the package | Generated per organization |
| --- | --- |
| Gate, engine, Pipe, master bot | `policy.csv` |
| `model.conf` | `db_schema.json` |
| Validation, audit, hot reload, confirmation flow | Worker attributes, from the IdP / HR system |
| Onboarding tools | Column labels and the role matrix |

### 6.2 Steps

1. **Introspect the schema** to produce `db_schema.json`.
2. **Import existing roles** from IdP groups, and attributes (department,
   site, manager) from the HR system. Do not invent roles.
3. **Suggest a data category per column** from name and value patterns, run
   locally. An LLM may see column names but never data values. Columns that
   have not been approved stay hidden from everyone.
4. **Fill a roles × categories grid.** Starter packs help here.
5. **Choose the row-ownership column per table**, which becomes the row
   filters.
6. **Compile to `policy.csv`**, load it with the gate's own loader
   (`compile_snapshot`), and produce a plain-language access report for
   sign-off.
7. **Maintain.** Changes go through the master bot. A nightly drift check
   flags new columns, which stay hidden until they are labelled.

### 6.3 Starter packs

Starter packs cover HR, finance, sales, warehouse, people managers and staff
self-service, plus common tables (directory, payroll, leave). The default is
no access.

### 6.4 Effort

| Component | Engineer-days |
| --- | --- |
| Schema introspection | ~1 |
| Category store and compiler | 2–3 |
| Category suggestions | 1–2 |
| Access report | ~1 |
| IdP group import | 2–4 per provider |
| Drift check | ~1 |

### 6.5 Risks

- Onboarding is the main product cost: days to weeks of customer time.
- Mislabelled columns leak data, but the fail-closed default makes
  over-restriction the common failure.
- Messy schemas may need views created by a DBA.
- Each organization needs a data owner (the "master").
- Larger organizations may need the policy stored in a database (a Casbin
  adapter) instead of a CSV file.

---

## 7. Distribution and release

- The PyPI name is `rbic-plugin`. Both `rbic-plugin` and `rbic` were free on
  PyPI and TestPyPI on 2026-10-20; the name is claimed by the first release.
- Publish via PyPI Trusted Publishing from a GitHub Actions release workflow
  triggered by `vX.Y.Z` tags, so no API tokens are stored. Do a TestPyPI dry
  run first.
- Protect release tags.
- Keep a single `__version__`.
- The wheel excludes demo data.
- Dependency ranges:

  ```
  sqlglot>=30.20,<31
  casbin>=1.43,<2
  anthropic>=0.86,<2
  ```

  The parser version matters for invariant 2, which is why `sqlglot` is
  pinned to one major version.
- Extras: `test`.

---

## 8. CI

- Keep the job id `pytest` and the Python matrix, so the required checks
  `pytest (3.10)`, `pytest (3.11)` and `pytest (3.12)` keep their names. If
  the names change, the branch ruleset must be updated, or PRs will wait
  forever for checks that never report.
- The steps become:

  ```bash
  pip install -e ".[test]"
  pytest
  rbic-gate-demo
  python -m build   # followed by an install-from-wheel smoke test
  ```
- Add a separate, initially non-required `adapters` job.
- Update the paths in `CODEOWNERS` if needed.

---

## 9. Deferred and out of scope

- **Chainlit.** If the project is revived: OAuth only, no data layer in v1,
  and `on_chat_resume` must clear history and start fresh.
- **Master bot web UI.** It needs a two-phase propose/decide API; a
  confirmation channel the LLM can't drive (an Open WebUI confirmation event
  or Chainlit action buttons, where errors and timeouts must count as
  decline); a writable policy volume; and its own security review.
- **MCP / OpenAPI tool-server route — rejected.** Rows would enter the host
  model's context, and the refusal would come from the LLM, breaking
  invariant 4.
- **Postgres executor.**

---

## 10. Risks and open items

- Each deployment must choose and configure its own SSO provider.
- Onboarding effort per organization.
- Open WebUI admins are trusted (accepted).
- Chat content is stored at rest in Open WebUI.

---

## Sources

- https://docs.openwebui.com/features/extensibility/plugin/functions/pipe/
- https://docs.openwebui.com/features/extensibility/plugin/development/reserved-args/
- https://docs.openwebui.com/features/extensibility/plugin/development/events/
- https://docs.openwebui.com/reference/env-configuration/
- https://docs.openwebui.com/features/extensibility/mcp/
- https://github.com/open-webui/open-webui/releases/latest
- https://github.com/Chainlit/chainlit
- https://github.com/Chainlit/chainlit/issues/3079
- https://docs.chainlit.io/authentication/oauth
- https://docs.chainlit.io/api-reference/lifecycle-hooks/on-chat-resume
