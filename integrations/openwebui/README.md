# RBIC in Open WebUI

This directory ships the Open WebUI integration of rbic:

| File | What it is |
| --- | --- |
| `rbic_pipe.py` | The Pipe function. Admins import it. It exposes one model, **Company Data (RBIC)**, and answers through `RBICEngine.aask()`. |
| `Dockerfile` | Open WebUI v0.12.4 (pinned by digest) with `rbic-plugin` preinstalled from a wheel built from this repository. |
| `requirements-rbic.txt`, `requirements-build.txt` | Hash-pinned dependencies for the image. |
| `docker-compose.yml` | Local test deployment: Open WebUI plus Keycloak as the OIDC provider, with the hardening settings applied. |
| `keycloak/realm-rbic.json` | Test realm with the `open-webui` client and the users owui-admin, bob, carol, dave and mallory. |

Open WebUI handles sign-in (SSO) and the chat UI. rbic decides what each
worker may see. The Pipe connects the two:

1. Open WebUI's authenticated user becomes an `Identity`.
2. The Pipe refuses anything that isn't a private one-to-one chat.
3. Open WebUI's background tasks (titles, tags, follow-ups and so on)
   never reach rbic.

Every SQL statement the LLM writes still goes through the SQL gate. Every
refusal is fixed text from code (see the root `CLAUDE.md`).

> **Status:** test deployment. Everything in `docker-compose.yml` and the
> realm (client secret, passwords, `WEBUI_SECRET_KEY`, plain HTTP) is a
> clearly fake demo value. Production needs real secrets, HTTPS and your
> own IdP. See the hardening checklist below.

---

## Quickstart (local, Keycloak)

Prerequisites: Docker with Compose v2, an Anthropic API key, and this
repository installed in a virtualenv (`pip install -e ".[test]"`) for
`rbic-seed` and `rbic-master`.

```bash
# 1. From the repository root: seed the demo database once.
#    It is mounted read-only into the container.
rbic-seed --config-dir examples/demo

# 2. Build and start Open WebUI and Keycloak.
export ANTHROPIC_API_KEY=sk-ant-...        # only ever from your shell / a secret store
cd integrations/openwebui
docker compose up --build
```

3. Open <http://localhost:3000> and click **Continue with Keycloak (demo)**.
   **Sign in as `owui-admin` first** (password `demo-owui-admin-pw`). Open
   WebUI makes its first account the admin.
4. Import the Pipe. Go to Admin Panel → Functions → **Import**, choose
   `integrations/openwebui/rbic_pipe.py` (the image also holds a copy at
   `/app/rbic/rbic_pipe.py`), save it and switch it on.
5. Set the Valves (gear icon on the function):
   - `AUDIT_LOG_PATH` = `/app/rbic/audit/audit.jsonl` (**required**; the
     Pipe refuses every request until it is set)
   - `EXPECTED_RBIC_VERSION` = the version the image printed during the
     build (`0.1.0.dev0` today)
   - Leave `CONFIG_DIR` empty. The container's `RBIC_CONFIG_DIR` is
     `/app/rbic/config`, the read-only mount of `examples/demo`.
6. Make it the only model workers see. Under Admin Panel → Settings →
   Models, set **Company Data (RBIC)** as the default model. The compose
   file already turns off OpenAI/Ollama connections, so no other models
   exist.
7. Sign out. Then sign in as `bob`, `carol` or `mallory` (password
   `demo-<name>-pw`) and run the end-to-end script below.

Watch the audit log:

```bash
docker compose exec open-webui tail -f /app/rbic/audit/audit.jsonl
```

Change policy live from the host. `rbic-master` edits `examples/demo`, and
the gate hot-reloads on the next request:

```bash
rbic-master --config-dir examples/demo master
```

---

## Valves

Valves are stored in plaintext in Open WebUI's database and every admin
can see them. That is why the Anthropic key is **not** a Valve: the
anthropic SDK reads `ANTHROPIC_API_KEY` from the container environment.

| Valve | Default | Meaning |
| --- | --- | --- |
| `CONFIG_DIR` | `""` | rbic config directory (`casbin/model.conf`, `casbin/policy.csv`, `db_schema.json`, `worker_attributes.json`). Empty means the container's `RBIC_CONFIG_DIR`. |
| `DB_PATH` | `""` | SQLite database. Empty means `RBIC_DB_PATH`, else `<CONFIG_DIR>/company.db`. Opened read-only. |
| `MODEL` | `claude-sonnet-4-6` | Anthropic model for text-to-SQL. |
| `IDENTITY_SOURCE` | `oauth` | `oauth`: only users who signed in through SSO are served. `admin_created`: any Open WebUI user, mapped by email. **Tests only**, because anyone who can create or rename Open WebUI accounts can then pick an identity. |
| `AUDIT_LOG_PATH` | `""` | **Required.** JSON-lines audit file on a writable volume (`rbic.audit.configure`). If empty or unwritable, every request gets a fixed "not configured" reply. |
| `EXPECTED_RBIC_VERSION` | `""` | When set, it must equal the installed `rbic.__version__`, or every request is refused (catches an image/Pipe mismatch after an upgrade). |
| `ALLOW_API_REQUESTS` | `false` | Answer requests that have no `chat_id` (direct API calls). **End-to-end testing only.** It never opens temporary, channel or shared chats, and it never skips the SSO check. |

Changing any of `CONFIG_DIR`, `DB_PATH` or `MODEL` makes the Pipe build a
new engine on the next request. The engine is cached per Valves tuple and
shared by all requests.

---

## What the Pipe does with each request

The steps run in this order. Every refusal is fixed text from code.

1. **Background tasks.** When `__task__` (or `__metadata__["task"]`) is
   set, the Pipe returns a fixed, data-free stub and never calls the
   engine:

   | Task | Stub |
   | --- | --- |
   | `title_generation` | `{"title": "Company data chat"}` |
   | `tags_generation` | `{"tags": []}` |
   | `follow_up_generation` | `{"follow_ups": []}` |
   | `query_generation` | `{"queries": []}` |
   | `autocomplete_generation` | `{"text": ""}` |
   | `memory_review` | `{"operations": []}` |
   | `context_compaction` | a fixed one-line note |
   | anything else | `""` |

   Open WebUI pastes the whole transcript into a *user* turn for these
   tasks. The engine's conversation guard can't tell that apart from the
   user's own words. The audit log gets a `PIPE_TASK_STUB` line and no
   ALLOW or DENY line.
2. **Configuration.** `AUDIT_LOG_PATH` must be set and writable, and
   `EXPECTED_RBIC_VERSION` must match when set. Otherwise the reply is
   *"The company data assistant is not configured correctly…"* and a
   `PIPE_CONFIG_ERROR` line is logged.
3. **Identity.** The Pipe builds `Identity("openwebui", __user__["id"],
   __user__["email"])`. In `oauth` mode the user must carry Open WebUI's
   SSO marker, a non-empty `__user__["oauth"]` of the form
   `{"<provider>": {"sub": "<subject>"}}`. Open WebUI writes it on every
   OAuth/OIDC sign-in. Admin-created and locally signed-up users have
   `oauth = null`. A user without the marker gets `DENY_MESSAGE` and an
   `IDENTITY_DENY … reason=not an SSO user` line, and the engine is not
   called. Otherwise the engine maps the email to a worker in
   `worker_attributes.json`. An unmapped email (mallory) gets
   `DENY_MESSAGE` and `IDENTITY_DENY`, with no Anthropic call.
4. **Audience.** `Audience.PRIVATE` applies only to a saved chat that the
   asking user owns and nobody else can read or continue. The Pipe reads
   Open WebUI's own tables in-process to check this. Anything else is sent
   to the engine as `UNKNOWN` or `SHARED`, so the engine replies with
   `AUDIENCE_DENY_MESSAGE`, and the Pipe logs `PIPE_AUDIENCE` with the
   reason. Refused cases:
   - an empty `chat_id`: a direct API call, unless `ALLOW_API_REQUESTS`
   - `temporary:` or `local:` chats (not saved, so ownership can't be checked)
   - `channel:` chats
   - a chat owned by another user (Open WebUI 0.12's shared chats in
     "continue" mode let other users write into the owner's chat)
   - a chat with a share link
   - a chat in a folder that is shared or owned by someone else
   - internal requests (sub-agents, notes)
   - a `metadata.user_id` that differs from `__user__["id"]`
   - any lookup error
5. **Answer.** The Pipe calls `engine.aask(identity, body["messages"],
   conversation_id=chat_id, audience=…)`. The messages are passed
   unchanged; the engine sanitizes them. The Pipe returns `result.text`
   only, never `result.reason` and never an exception message. One status
   event, "Checking access…", is shown while it works; a broken emitter is
   ignored. No streaming.

---

## SSO recipes

Every recipe uses Open WebUI's own OAuth support. Set these in every
deployment:

```env
ENABLE_OAUTH_SIGNUP=true
ENABLE_LOGIN_FORM=false
ENABLE_PASSWORD_AUTH=false        # ENABLE_LOGIN_FORM only hides the form
ENABLE_SIGNUP=false
OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false
OAUTH_ALLOWED_DOMAINS=company.com
WEBUI_URL=https://chat.company.com
```

> **The email is the identity key.** Open WebUI doesn't check the
> `email_verified` claim (`utils/oauth.py`, v0.12.4), and rbic maps workers
> by email. Use an IdP where **only administrators** can set a user's email,
> and never accept guest or consumer accounts.

### Microsoft Entra ID

Use Open WebUI's built-in Microsoft login:

1. Register an app in Entra ID. Choose **single tenant** (accounts in this
   organizational directory only).
2. Add the web redirect URI
   `https://chat.company.com/oauth/microsoft/login/callback`.
3. Create a client secret.

```env
MICROSOFT_CLIENT_ID=<application id>
MICROSOFT_CLIENT_SECRET=<secret>          # from a secret store
MICROSOFT_CLIENT_TENANT_ID=<your tenant id>   # never "common"/"organizations"
MICROSOFT_REDIRECT_URI=https://chat.company.com/oauth/microsoft/login/callback
```

Block guest users from the app (Enterprise app → *Assignment required* plus
a group of members), and keep `OAUTH_ALLOWED_DOMAINS` to your verified
domains. The `email` claim of a member account comes from its `mail`
attribute, which only admins set.

### Google Workspace (domain-restricted)

Use Open WebUI's built-in Google login:

1. Create an OAuth client in the Workspace's Google Cloud project.
2. Set the consent screen **User type: Internal**. This lets only
   accounts of your Workspace sign in.
3. Add the redirect URI `https://chat.company.com/oauth/google/login/callback`.

```env
GOOGLE_CLIENT_ID=<client id>
GOOGLE_CLIENT_SECRET=<secret>
GOOGLE_REDIRECT_URI=https://chat.company.com/oauth/google/login/callback
OAUTH_ALLOWED_DOMAINS=company.com
```

### Generic OIDC (Okta, Keycloak, Auth0, …)

```env
OAUTH_CLIENT_ID=<client id>
OAUTH_CLIENT_SECRET=<secret>
OPENID_PROVIDER_URL=https://<idp>/.well-known/openid-configuration
#  Okta:     https://<org>.okta.com/oauth2/default/.well-known/openid-configuration
#  Keycloak: https://<host>/realms/<realm>/.well-known/openid-configuration
OPENID_REDIRECT_URI=https://chat.company.com/oauth/oidc/login/callback
OAUTH_PROVIDER_NAME=Company SSO
OAUTH_SCOPES=openid email profile
```

Configure the IdP so users can't edit their own email. In Keycloak, set
Realm settings → User profile → `email` → *Who can edit* to admin only, as
`keycloak/realm-rbic.json` does, and turn off self-registration. In Okta,
make the email attribute read-only for users.

---

## Admin hardening checklist

`docker-compose.yml` applies everything that has an environment variable.
Check the rest in the admin UI.

**Identity**
- [ ] SSO only: `ENABLE_LOGIN_FORM=false`, `ENABLE_PASSWORD_AUTH=false`,
      `ENABLE_SIGNUP=false`, `ENABLE_OAUTH_SIGNUP=true`,
      `OAUTH_MERGE_ACCOUNTS_BY_EMAIL=false`, `OAUTH_ALLOWED_DOMAINS` set.
- [ ] The Pipe's `IDENTITY_SOURCE` is `oauth`.
- [ ] `WEBUI_AUTH_TRUSTED_EMAIL_HEADER` is unset (trusted-header auth
      would let any proxy client choose an email).
- [ ] The IdP owns emails: users can't change them, there are no guest or
      consumer accounts, and email addresses are never reused.
- [ ] `DEFAULT_USER_ROLE=pending` (an admin approves new users) or OAuth
      role management. The demo uses `user`.
- [ ] Sign in with the intended admin account first, because the first
      account becomes admin.
- [ ] `WEBUI_SECRET_KEY` is a long random secret, and HTTPS is used
      everywhere. Never set `AUTHLIB_INSECURE_TRANSPORT` outside the demo.

**Only the RBIC model**
- [ ] Make the RBIC model the only model workers can see:
      `ENABLE_OPENAI_API=false`, `ENABLE_OLLAMA_API=false`,
      `ENABLE_DIRECT_CONNECTIONS=false`, `BYPASS_MODEL_ACCESS_CONTROL=false`,
      no arena models. If other models must exist, hide them from workers
      with model access control and set
      `USER_PERMISSIONS_CHAT_MULTIPLE_MODELS=false`. Switching a chat to
      another model would send the whole history, rows included, to that
      model.
- [ ] Don't attach tools, knowledge or files to the RBIC model. Keep file
      and web upload off (`USER_PERMISSIONS_CHAT_FILE_UPLOAD=false`,
      `USER_PERMISSIONS_CHAT_WEB_UPLOAD=false`).
- [ ] `ENABLE_API_KEYS=false` unless needed. The Pipe refuses requests
      without a `chat_id` anyway.

**Nothing re-sends transcripts**
- [ ] Turn off title, tag, follow-up and autocomplete generation, plus
      search/retrieval query generation, image prompt generation, context
      compaction and memories (`ENABLE_TITLE_GENERATION`,
      `ENABLE_TAGS_GENERATION`, `ENABLE_FOLLOW_UP_GENERATION`,
      `ENABLE_AUTOCOMPLETE_GENERATION`, `ENABLE_SEARCH_QUERY_GENERATION`,
      `ENABLE_RETRIEVAL_QUERY_GENERATION`, `ENABLE_IMAGE_PROMPT_GENERATION`,
      `ENABLE_CONTEXT_COMPACTION`, `ENABLE_MEMORIES`,
      `ENABLE_MEMORY_BACKGROUND_REVIEW` = `false`).
- [ ] Leave `TASK_MODEL_EXTERNAL` and `TASK_MODEL` unset (or point them at
      the RBIC model). A separate task model would receive the transcripts
      that the Pipe's stubs keep away from rbic.

**No sharing**
- [ ] Turn off chat sharing: `USER_PERMISSIONS_CHAT_SHARE=false`,
      `ENABLE_COMMUNITY_SHARING=false`,
      `USER_PERMISSIONS_CHAT_ALLOW_PUBLIC_SHARING=false`,
      `USER_PERMISSIONS_CHAT_ALLOW_OPEN_SHARING=false`,
      `USER_PERMISSIONS_FOLDERS_ALLOW_SHARING=false`. The Pipe refuses to
      answer in a shared chat, but it can't un-share answers that were
      given before a chat was shared.
- [ ] Channels, notes and automations off (`ENABLE_CHANNELS`,
      `ENABLE_NOTES`, `ENABLE_AUTOMATIONS` = `false`). Temporary chats off
      (`USER_PERMISSIONS_CHAT_TEMPORARY=false`); the Pipe refuses them.

**Platform**
- [ ] `ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS=false` (the image sets it).
- [ ] `ENABLE_PERSISTENT_CONFIG=false`, so the environment stays
      authoritative and an admin-UI change can't quietly re-enable a
      setting. The trade-off: admin-UI settings don't survive a restart.
- [ ] Mount the config directory and database **read-only**; only the
      audit log volume is writable.
- [ ] Treat Open WebUI admins as fully trusted. They can edit function
      code, read Valves, the environment (including the API key), the
      config directory, `policy_changes.jsonl` (worker emails) and every
      stored chat. Keep the admin set minimal. `ENABLE_ADMIN_CHAT_ACCESS=false`
      reduces casual exposure but is not a boundary.
- [ ] Answers are stored at rest in Open WebUI's database
      (`/app/backend/data`), including any rows the model summarized.
      Protect and back up that volume like the company database, and set a
      retention policy.

---

## Manual end-to-end test

Run it against the compose deployment after the Quickstart. Watch the
audit log while you go (`docker compose exec open-webui tail -f
/app/rbic/audit/audit.jsonl`).

| # | As | Do | Expect in the chat | Expect in the audit log |
| --- | --- | --- | --- | --- |
| 1 | bob | Start a new chat with Company Data (RBIC): "What are everyone's salaries?" | *"You have no access to this information, please approach your manager."* | `DENY user=bob reason=…salary…` |
| 2 | carol | "Show my team's payslips." | Payslips of employee_id 1, 2 and 3 only | `ALLOW user=carol … IN (1, 2, 3) … scopes=payroll:…` |
| 3 | mallory | Ask anything | The deny message | `IDENTITY_DENY provider='openwebui' subject='<id>' reason=unmapped identity`, and no Anthropic call (no `ALLOW`/`DENY`/`LLM_ERROR` line) |
| 4 | carol | Ask about payslips. Then on the host run `rbic-master --config-dir examples/demo master` and ask it to remove `payroll_manager`'s row scope on `payroll` (the `employee_id IN ({self_and_subordinate_ids})` rule; answer `yes`). Ask again in the **same chat**. | The next answer starts with *"(Access policy was updated — conversation reset.)"* and shows only her own payslip (employee_id 2) | Container: `POLICY_RELOAD`, `POLICY_RESET user=carol …`, then `ALLOW … WHERE payroll.employee_id = '2'`. Host (`rbic-master`'s stderr): `POLICY_CHANGE …` |
| 5 | any | Temporarily set `ENABLE_TITLE_GENERATION=true` and restart, then chat | The chat title is "Company data chat" | `PIPE_TASK_STUB task='title_generation'`, with no `ALLOW`/`DENY` for it |
| 6 | carol | Call the API without a `chat_id` (see below) | `AUDIENCE_DENY_MESSAGE` (*"This assistant only answers in private one-to-one chats."*) | `PIPE_AUDIENCE … reason=no chat_id`, `AUDIENCE_DENY …` |

Undo step 4 afterwards with `rbic-master` (`propose_undo`) or by
re-checking out `examples/demo/casbin/policy.csv`.

**Step 6 (API).** Take carol's session token from the browser (developer
tools → Local Storage → `token`) and run:

```bash
curl -s http://localhost:3000/api/chat/completions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"model": "<function id>.rbic", "stream": false,
       "messages": [{"role": "user", "content": "Show my team payslips"}]}'
```

`<function id>` is the id you gave the function at import; Admin Panel →
Functions shows it. Setting `ALLOW_API_REQUESTS=true` makes the same call
answer (e2e testing only). Turn it off again afterwards.

**Scripted smoke without a browser (test only).** Password sign-in is off
in the compose file. For an API-only smoke test, use a throwaway
deployment:

1. Start it with `ENABLE_PASSWORD_AUTH=true`, `ENABLE_LOGIN_FORM=true` and
   `WEBUI_ADMIN_EMAIL` / `WEBUI_ADMIN_PASSWORD` set to throwaway values.
2. Have the admin create a local test user whose email is a demo worker's
   (Admin Panel → Users → Add user).
3. Set the Valves `IDENTITY_SOURCE=admin_created` and
   `ALLOW_API_REQUESTS=true`.
4. Sign in through `POST /api/v1/auths/signin`.
5. Call `/api/chat/completions` as above.

Never do this with real credentials or on a shared host.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Every answer is *"…not configured correctly…"* | `AUDIT_LOG_PATH` is empty or not writable. Set it to a file on the `rbic-audit` volume. If `EXPECTED_RBIC_VERSION` is set, it must equal the version printed during the image build. A `PIPE_CONFIG_ERROR` line says which. A bad `CONFIG_DIR`/`DB_PATH` gives the same text (`reason=engine build failed`). Is `company.db` seeded? |
| Every answer is the deny message, audit `IDENTITY_DENY … not an SSO user` | The account was created by an admin or by local signup, not through SSO. Sign in with SSO. An account that existed before SSO keeps `oauth = null`, because merging by email is off on purpose. Delete it and sign in again with SSO. |
| `IDENTITY_DENY … unmapped identity` for a real worker | The SSO email doesn't match the worker's `email` in `worker_attributes.json` (compared ASCII-lowercased). Fix the HR record, not the IdP. |
| Every answer is *"This assistant only answers in private one-to-one chats."* | A temporary chat, channel or shared chat, or an API call without `chat_id`. `PIPE_AUDIENCE … reason=…` names the case. Start a normal new chat. |
| Login loops or "OAuth login failed" | The browser and the container must reach Keycloak under the same URL (`http://keycloak.localhost:8080`). If your browser doesn't resolve `*.localhost`, add `127.0.0.1 keycloak.localhost` to your hosts file. Check `WEBUI_URL` and that the redirect URI matches the Keycloak client (`/oauth/oidc/login/callback`). |
| New users can't chat ("pending") | `DEFAULT_USER_ROLE` is `pending`; approve them under Admin Panel → Users. |
| Function import fails with `No module named 'rbic'` | The container isn't the derived image. Rebuild with `docker compose up --build`. |
| Status "Checking access…" never clears | Harmless. The answer is still delivered; emitter errors are ignored. |
| `LLM_ERROR` lines, *"temporarily unavailable"* | `ANTHROPIC_API_KEY` is missing or wrong in the container environment, or the API is unreachable. |

---

## Verified against Open WebUI v0.12.4

These facts were checked in the Open WebUI source at tag `v0.12.4`
(`ghcr.io/open-webui/open-webui:v0.12.4@sha256:a5b9e403…`) and in the docs.
Re-check them when bumping the image.

- **Pipe calling convention:** `backend/open_webui/functions.py`.
  - The Pipe gets `body` plus only the reserved arguments its signature
    names (`__user__ = user.model_dump()`, `__metadata__`, `__task__`,
    `__event_emitter__`, …).
  - `pipes()` returns `{"id", "name"}` entries, which become model ids
    `<function id>.<id>`.
  - Valves are rebuilt from the database on every request.
  - A returned `str` becomes one chat-completion message (a single chunk
    when streaming).
  - An exception's text is sent to the client, which is why the Pipe never
    raises.
- **SSO marker:** `backend/open_webui/models/users.py` (`oauth: dict |
  None`, `update_user_oauth_by_id`) and `backend/open_webui/utils/oauth.py`.
  - The marker has the shape `{provider: {"sub": sub}}`.
  - It is written on OAuth sign-up and sign-in.
  - Email merging only happens if `OAUTH_MERGE_ACCOUNTS_BY_EMAIL`.
  - `email_verified` is not checked.
  - The first account becomes admin.
- **Chat ids:** `backend/open_webui/utils/chat_id.py` (`temporary:`,
  legacy `local:`, `channel:`) and `backend/open_webui/main.py`
  (`chat_completion`).
  - For a new chat the server creates and saves the chat before the Pipe
    runs.
  - `metadata.internal` marks server-made requests.
  - `Chats.get_accessible_chat_by_id` (`models/chats.py`) lets other users
    write into chats shared in "continue" mode, and into chats in shared
    folders.
- **Tasks:** `backend/open_webui/constants.py` `TASKS`, plus the parsing in
  `utils/middleware.py`, `utils/task.py` (`parse_follow_ups`),
  `utils/memory.py` and `utils/context_compaction.py`.
- **Status event:** `{"type": "status", "data": {"description", "done",
  "hidden"}}`.
- **Environment variables** (names and defaults):
  `backend/open_webui/config.py` and `backend/open_webui/env.py`.
  - `ENABLE_PASSWORD_AUTH` gates `/api/v1/auths/signin`.
  - `ENABLE_LOGIN_FORM` only hides the form.
  - `ENABLE_PERSISTENT_CONFIG` makes database values win over the
    environment.
- **Docs:**
  - <https://docs.openwebui.com/features/extensibility/plugin/functions/pipe/>
  - <https://docs.openwebui.com/features/extensibility/plugin/development/reserved-args/>
    (also: "Direct API calls get an empty `chat_id`")
  - <https://docs.openwebui.com/features/extensibility/plugin/development/events/>
  - <https://docs.openwebui.com/reference/env-configuration/>

**Dependency pins:** Open WebUI v0.12.4 pins `anthropic==0.86.0` and
`pydantic==2.13.4`, and ships `python-dotenv`. These satisfy rbic's
`anthropic>=0.86,<2` and `python-dotenv>=1`. `casbin`, `simpleeval` and
`sqlglot` are not in the image and are installed from
`requirements-rbic.txt`. The Dockerfile fails the build if `pip check`
reports any unmet requirement of `rbic-plugin`.
