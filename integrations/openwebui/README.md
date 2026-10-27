# RBIC in Open WebUI

This directory ships the Open WebUI integration of rbic:

| File | What it is |
| --- | --- |
| `rbic_pipe.py` | The Pipe function. Admins import it. It exposes one model, **Company Data (RBIC)**, and answers through `RBICEngine.aask()`. |
| `Dockerfile` | Open WebUI v0.12.4 (pinned by digest) with `rbic-plugin` preinstalled from a wheel built from this repository. |
| `requirements-rbic.txt`, `requirements-build.txt` | Hash-pinned dependencies for the image. |
| `docker-compose.yml` | Local test deployment: Open WebUI plus Keycloak as the OIDC provider, with the hardening settings applied. |
| `keycloak/realm-rbic.json` | Test realm with the `open-webui` client (client roles `owui-admin`/`owui-user`, sent in the `roles` claim) and the users owui-admin (`owui-admin`), bob, carol, dave and mallory (`owui-user`). |

Open WebUI handles sign-in (SSO) and the chat UI. rbic decides what each
worker may see. The Pipe connects the two:

1. Open WebUI's authenticated user becomes an `Identity`.
2. The Pipe refuses anything that isn't a private one-to-one chat.
3. Open WebUI's background tasks (titles, tags, follow-ups and so on)
   never reach rbic.
4. Attachments, knowledge, chat references and any other retrieved
   context are refused, because Open WebUI would paste them into the
   user's message.

Every SQL statement the LLM writes still goes through the SQL gate. Every
refusal is fixed text from code (see the root `CLAUDE.md`).

> **Status:** test deployment. The secrets that ship in
> `docker-compose.yml` and `keycloak/realm-rbic.json` (Keycloak admin
> password, the `open-webui` client secret, every user password) are
> **demo-only** values that anyone can read in this repository, and the
> demo runs on plain HTTP. `WEBUI_SECRET_KEY` and the bootstrap admin
> password have no default: you generate them. Production needs real
> secrets, HTTPS and your own IdP. See the hardening checklist below.

---

## Quickstart (local, Keycloak)

Prerequisites: Docker with Compose v2, an Anthropic API key, and this
repository installed in a virtualenv (`pip install -e ".[test]"`) for
`rbic-seed` and `rbic-master`.

```bash
# 1. From the repository root: seed the demo database once.
#    It is mounted read-only into the container.
rbic-seed --config-dir examples/demo

# 2. Generate the two secrets compose requires. Keep them (a password
#    manager, or an untracked integrations/openwebui/.env file): a new
#    WEBUI_SECRET_KEY signs everyone out.
export WEBUI_SECRET_KEY="$(python -c "import secrets;print(secrets.token_urlsafe(48))")"
export WEBUI_BOOTSTRAP_ADMIN_PASSWORD="$(python -c "import secrets;print(secrets.token_urlsafe(48))")"

# 3. Build and start Open WebUI and Keycloak.
export ANTHROPIC_API_KEY=sk-ant-...        # only ever from your shell / a secret store
cd integrations/openwebui
docker compose up --build
```

3. Open <http://localhost:3000> and click **Continue with Keycloak (demo)**.
   Sign in as `owui-admin` (password `demo-owui-admin-pw`). Who is an Open
   WebUI admin comes from the IdP, not from who signs in first: Keycloak
   sends the `open-webui` client roles in the `roles` claim, and Open WebUI
   maps `owui-admin` to admin and `owui-user` to user on every sign-in
   (`ENABLE_OAUTH_ROLE_MANAGEMENT`). Open WebUI also makes its very first
   account admin no matter what; compose therefore creates a placeholder
   local admin (`bootstrap-admin@rbic-demo.invalid`) at first start, which
   can't sign in because password sign-in is off.
   **Before importing the Pipe, check Admin Panel → Users:** the only admins
   are `owui-admin` and the placeholder; bob, carol, dave and mallory are
   `user`. If anyone else is admin, stop, remove the `open-webui-data`
   volume (`docker compose down -v`) and start again.
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
7. Strip the model's extras. Edit **Company Data (RBIC)** (Admin Panel →
   Settings → Models): under *Capabilities* turn off **File Upload**,
   **File Context**, **Web Search**, **Vision**, **Image Generation**,
   **Code Interpreter** and **Builtin Tools**; attach no *Knowledge*,
   *Tools*, *Filters*, *Actions* or *Skills*; save. The Pipe refuses any
   request that still carries attachments, but nothing should be
   retrieved for it in the first place.
8. Sign out. Then sign in as `bob`, `carol` or `mallory` (password
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
   `PIPE_CONFIG_ERROR` line is logged. If another RBIC Pipe function in
   the same Open WebUI process already configured a different audit file,
   that file is kept (records of both go there) and one
   `PIPE_CONFIG_WARNING … requested=… in_use=…` line is logged: run one
   RBIC Pipe per Open WebUI process, or give them the same
   `AUDIT_LOG_PATH`.
3. **Attachments.** Open WebUI runs its retrieval step for Pipes too.
   Files, knowledge collections, web search results and **chat
   references** (a whole earlier chat, rebuilt as `#### User` /
   `#### Assistant` text) are turned into text and, unless
   `RAG_SYSTEM_CONTEXT=true`, pasted into the last *user* message. That
   would bring rows fetched under an old policy back to the model inside
   the user's own words. So when `__files__`, `__metadata__["files"]`,
   `["sources"]`, `["folder_knowledge"]`, `["user_message"]["files"]`,
   `body["files"]` or any message's `files`/`sources` is non-empty, or the
   user turn carries Open WebUI's RAG wrapper (`<source id="`,
   `<context>…</context>`, `<chat_history>…</chat_history>`, the default
   RAG template's first line), the reply is *"Attachments, documents and
   chat references can't be used with this assistant. Please ask your
   question directly."*, the engine is not called, and
   `PIPE_ATTACHMENT_REFUSED subject=… source=<where>` is logged (never
   file names, ids or content).
4. **Identity.** The Pipe builds `Identity("openwebui", __user__["id"],
   __user__["email"])`. In `oauth` mode the user must carry Open WebUI's
   SSO marker, a non-empty `__user__["oauth"]` of the form
   `{"<provider>": {"sub": "<subject>"}}`. Open WebUI writes it on every
   OAuth/OIDC sign-in. Admin-created and locally signed-up users have
   `oauth = null`. A user without the marker gets `DENY_MESSAGE` and an
   `IDENTITY_DENY … reason=not an SSO user` line, and the engine is not
   called. Otherwise the engine maps the email to a worker in
   `worker_attributes.json`. An unmapped email (mallory) gets
   `DENY_MESSAGE` and `IDENTITY_DENY`, with no Anthropic call.
5. **Audience.** `Audience.PRIVATE` applies only to a saved chat that the
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
6. **Answer.** The Pipe calls `engine.aask(identity, body["messages"],
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
OAUTH_UPDATE_EMAIL_ON_LOGIN=true  # stored email follows the IdP on every sign-in
ENABLE_OAUTH_TOKEN_EXCHANGE=false # (default) no IdP-token -> session exchange endpoint
WEBUI_URL=https://chat.company.com
# Open WebUI admin/user roles from the IdP (claim name and values: your IdP)
ENABLE_OAUTH_ROLE_MANAGEMENT=true
OAUTH_ROLES_CLAIM=roles
OAUTH_ALLOWED_ROLES=owui-user
OAUTH_ADMIN_ROLES=owui-admin
DEFAULT_USER_ROLE=pending         # users whose token has no roles claim wait for approval
# Open WebUI makes its first account admin whatever the IdP says: create a
# placeholder admin at first start so that is never an SSO user.
WEBUI_ADMIN_EMAIL=bootstrap-admin@<unused domain>
WEBUI_ADMIN_PASSWORD=<long random value from a secret store>
```

> **The email is the identity key.** rbic maps the email Open WebUI has
> **stored** for the user to a worker. Open WebUI doesn't check the
> `email_verified` claim (`utils/oauth.py`, v0.12.4). By default it also
> keeps the email it saw at the first sign-in (`OAUTH_UPDATE_EMAIL_ON_LOGIN`
> is off), and any Open WebUI admin can edit a user's email (Admin Panel →
> Users), which re-maps that SSO user to another worker. That is part of
> "Open WebUI admins are fully trusted" (checklist). With
> `OAUTH_UPDATE_EMAIL_ON_LOGIN=true` the stored email is reset to the IdP's
> on the user's next sign-in, so Open WebUI stays in sync with the IdP; it
> does not undo an admin edit for an already-open session. Use an IdP
> where **only administrators** can set a user's email, and never accept
> guest or consumer accounts.

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

For role management, the IdP must put the Open WebUI role into a claim of
the ID token or userinfo. The test realm does it with client roles
`owui-admin` / `owui-user` on the `open-webui` client and a *User Client
Role* mapper that writes them to `roles` (ID token, access token and
userinfo). In Entra ID use app roles (claim `roles`); in Okta a groups or
custom claim.

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
- [ ] Emails come from the IdP: users can't change them there, there are
      no guest or consumer accounts, and addresses are never reused.
      `OAUTH_UPDATE_EMAIL_ON_LOGIN=true`, so Open WebUI's stored copy (the
      email rbic maps) is reset to the IdP's on every sign-in. Open WebUI
      admins can still edit any user's email and so re-map an SSO user to
      another worker until that user signs in again: one more reason they
      are fully trusted (Platform, below).
- [ ] Admin rights come from the IdP: `ENABLE_OAUTH_ROLE_MANAGEMENT=true`
      with `OAUTH_ROLES_CLAIM`, `OAUTH_ALLOWED_ROLES` and
      `OAUTH_ADMIN_ROLES` matching your IdP's claim, and only the intended
      admins hold the admin role. Re-checked on every sign-in.
- [ ] The first-account race is closed: `WEBUI_ADMIN_EMAIL` /
      `WEBUI_ADMIN_PASSWORD` create a placeholder admin at first start
      (Open WebUI makes its first account admin regardless of role
      management), with an email no IdP user has and a long random
      password; it can't sign in with password sign-in off. Before
      importing the Pipe, check Admin Panel → Users: no unexpected admin.
- [ ] `DEFAULT_USER_ROLE=pending` (an admin approves users whose token has
      no roles claim). The demo uses `user`.
- [ ] `ENABLE_OAUTH_TOKEN_EXCHANGE=false` (the default): no endpoint that
      turns an IdP token from elsewhere into an Open WebUI session.
- [ ] `WEBUI_SECRET_KEY` is a long random secret (compose refuses to start
      without one), and HTTPS is used everywhere. Never set
      `AUTHLIB_INSECURE_TRANSPORT` outside the demo. Replace every demo
      secret of `docker-compose.yml` and `keycloak/realm-rbic.json`.

**Only the RBIC model**
- [ ] Make the RBIC model the only model workers can see:
      `ENABLE_OPENAI_API=false`, `ENABLE_OLLAMA_API=false`,
      `ENABLE_DIRECT_CONNECTIONS=false`, `BYPASS_MODEL_ACCESS_CONTROL=false`,
      no arena models. If other models must exist, hide them from workers
      with model access control and set
      `USER_PERMISSIONS_CHAT_MULTIPLE_MODELS=false`. Switching a chat to
      another model would send the whole history, rows included, to that
      model.
- [ ] Nothing is retrieved for the RBIC model. On the model (Admin Panel →
      Settings → Models → Company Data (RBIC)) turn off the *File Upload*,
      *File Context*, *Web Search*, *Vision*, *Image Generation*, *Code
      Interpreter* and *Builtin Tools* capabilities, and attach no
      knowledge bases, tools, filters, actions or skills; put RBIC chats in
      no folder that has knowledge files. Keep file and web upload off
      (`USER_PERMISSIONS_CHAT_FILE_UPLOAD=false`,
      `USER_PERMISSIONS_CHAT_WEB_UPLOAD=false`) and web search off
      (`ENABLE_WEB_SEARCH=false`).
- [ ] `RAG_SYSTEM_CONTEXT=true`, so any context Open WebUI still retrieves
      (files, knowledge, chat references, web search) goes into the system
      message, which rbic drops, never into the user's turn. The Pipe
      refuses requests carrying attachments either way.
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
- [ ] Run one RBIC Pipe function per Open WebUI process (or give every
      copy the same `AUDIT_LOG_PATH`). rbic has one audit file per
      process: a second copy with a different path writes into the first
      one's file and logs `PIPE_CONFIG_WARNING`.
- [ ] Treat Open WebUI admins as fully trusted. They can edit function
      code, read Valves, the environment (including the API key), the
      config directory, `policy_changes.jsonl` (worker emails) and every
      stored chat, and they can change any user's email (which re-maps
      that user to another worker). Keep the admin set minimal.
      `ENABLE_ADMIN_CHAT_ACCESS=false` reduces casual exposure but is not
      a boundary.
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
| 7 | carol | With `ALLOW_API_REQUESTS=true`, repeat step 6 with a chat reference: add `"files": [{"type": "chat", "id": "<id of carol's chat from step 2>"}]` to the JSON (the id is the last part of the chat's URL) | *"Attachments, documents and chat references can't be used with this assistant. Please ask your question directly."* | `PIPE_ATTACHMENT_REFUSED subject='<id>' source=metadata.files`, and no `ALLOW`/`DENY` line |
| 8 | owui-admin | Admin Panel → Users | owui-admin and the bootstrap placeholder are `admin`; bob, carol, dave, mallory are `user`, whatever order they signed in | — |

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
   (Password sign-in also opens the bootstrap placeholder admin, which is
   why it stays off in every real deployment.)
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
| New users can't chat ("pending") | `DEFAULT_USER_ROLE` is `pending` and their token carries no roles claim; give them the IdP role (`owui-user`) or approve them under Admin Panel → Users. |
| Sign-in fails with "access prohibited" | OAuth role management: the token's `roles` claim has neither an `OAUTH_ALLOWED_ROLES` nor an `OAUTH_ADMIN_ROLES` value. Assign the user `owui-user` (or `owui-admin`) on the `open-webui` client in Keycloak. |
| `docker compose up` stops with "Set WEBUI_SECRET_KEY …" | Export `WEBUI_SECRET_KEY` and `WEBUI_BOOTSTRAP_ADMIN_PASSWORD` first (Quickstart step 2). |
| *"Attachments, documents and chat references can't be used…"* | The request carried a file, knowledge, a chat reference, web search results or retrieved context (`PIPE_ATTACHMENT_REFUSED … source=…` names where). Ask without attachments; turn off the model's File Upload / File Context / Web Search capabilities and detach its knowledge. |
| `PIPE_CONFIG_WARNING … audit log already configured by another RBIC Pipe` | Two RBIC Pipe functions with different `AUDIT_LOG_PATH`s in one process. Records go to the `in_use` file. Keep one RBIC Pipe, or give both the same path. |
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
    names (`__user__ = user.model_dump()`, `__metadata__`, `__task__`, `__files__`,
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
  - The first account becomes admin even with role management on: the
    first SSO sign-up is promoted after insert when it is the only user
    (`utils/oauth.py` 2194-2198), and the only user is kept admin on
    every sign-in (`get_user_role`, ~1602-1605). `WEBUI_ADMIN_EMAIL` +
    `WEBUI_ADMIN_PASSWORD` create an admin at start-up when there are no
    users (`env.py` 806-808, `main.py` 400-403, `utils/auth.py`
    `create_admin_user` 631-656).
  - Role management (`config.py` 2673, 2688-2700; `utils/oauth.py`
    `get_user_role` 1614-1671): the `OAUTH_ROLES_CLAIM` (dotted paths
    allowed, `_get_claim` 227) is read from the ID-token/userinfo claims;
    an `OAUTH_ADMIN_ROLES` value → admin, an `OAUTH_ALLOWED_ROLES` value →
    user, roles present but neither → sign-in refused (403), no claim → the
    current role / `DEFAULT_USER_ROLE`.
  - `OAUTH_UPDATE_EMAIL_ON_LOGIN` (`config.py` 2708, default off) resets
    the stored email to the IdP's claim on sign-in (`utils/oauth.py`
    2112-2124; skipped if another account has that email). Admins can edit
    any user's email (`routers/users.py` ~993-995).
  - `ENABLE_OAUTH_TOKEN_EXCHANGE` (`env.py` 901, default off) gates the
    token-exchange endpoint (`routers/auths.py` ~1613-1615).
- **Retrieval for Pipes** (why attachments are refused):
  - The request's `files` become `metadata["files"]` (`main.py` 1335;
    `utils/middleware.py` `process_chat_payload` 2641-2651) and the Pipe's
    `__files__` (`functions.py` 228, 256).
  - The files handler runs for every model whose *File Context*
    capability is on (default) (`utils/middleware.py` 2944-2949) and
    records the retrieved context in `metadata["sources"]` (2970).
  - A `type: "chat"` reference is rebuilt as `#### User` / `#### Assistant`
    text (`retrieval/utils.py` 1469-1500).
  - The context is wrapped in `<source id=…>` tags (`get_source_context`,
    `utils/middleware.py` 613-640) and the RAG template
    (`DEFAULT_RAG_TEMPLATE`, `config.py` 1077-1101: `### Task:` …
    `<context>…</context>`), and goes into the **last user message** unless
    `RAG_SYSTEM_CONTEXT=true` (`env.py` 372, default off;
    `apply_source_context_to_messages`, `utils/middleware.py` 669-680).
  - Model capability names: `src/lib/components/workspace/Models/Capabilities.svelte`
    (`file_upload`, `file_context`, `web_search`, `builtin_tools`, …).
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
