# Changelog

All notable changes to `rbic-plugin` (import name `rbic`). Versions follow
[semantic versioning](https://semver.org/); `__version__` lives only in
`src/rbic/__init__.py`. Release steps: `docs/RELEASING.md`.

## 0.1.0 — first release

First public release on PyPI. Python 3.10–3.12.

### SQL gate (`rbic.gate.SQLGate`)
- Casbin RBAC + ABAC enforced over LLM-generated SQL, before any data reaches
  the model: sqlglot parse (a single `SELECT` only), qualification against
  `db_schema.json` (`SELECT *` expanded to real columns), a construct
  allowlist (whole-row references, CTEs, set operations, `INTO`, locks,
  schema-qualified names and other unmodelled constructs deny), per-column
  RBAC, and row filters bound from the worker's attributes as literal AST
  nodes and ANDed into each `SELECT`.
- Policy ptypes: `p` column grants (`keyMatch`, e.g. `inventory.*`), `g` role
  hierarchy, `p2` row filters and 4-field scoped grants (columns for chosen
  rows), `p3` column denies and `p4` row denies; personal `user:<name>`
  rules with user-over-role precedence.
- Fail closed throughout: unknown tables/columns, missing attributes, unsafe
  filter templates, malformed policy files and duplicate emails or
  employee_ids deny. The deny reply is fixed code text, never model output.
- Hot reload of all four policy files into one immutable, thread-safe
  snapshot per request, with a stable policy fingerprint.
- `rbic.audit`: every ALLOW (with the rewritten SQL) and DENY is logged;
  `rbic.audit.configure(path)` writes JSON lines. Audit lines never contain
  a worker's email.

### Engine (`rbic.RBICEngine.ask()`)
- One entry point for chat hosts: audience check (private chats only),
  identity resolution through an `AttributeProvider` (default: verified
  email → `worker_attributes.json`), untrusted-history sanitizing, a
  conversation guard that drops earlier turns when the policy changes, a
  server-built system prompt listing only the role's readable schema, and a
  gated `run_sql` tool loop over a read-only SQLite connection. `ask()` never
  raises; `aask()` is the async variant.

### Master policy bot (`rbic-master`)
- A master user changes the policy by chatting. The LLM can only propose;
  code validates every change through the gate's own loader, shows the
  description and diff, and applies it only after an explicit `yes`.
  Writes are locked, hash-checked against the proposal, logged to a
  changelog before the file changes, and can be undone. Worker emails never
  reach the model.

### Onboarding toolkit (`rbic-init`)
- Generates a new organization's policy: `schema` (introspect the database
  into `db_schema.json`), `suggest` (rule-based column categories; no LLM,
  values only counted), `approve` / `reject` (human review, with recorded
  sensitivity downgrades), `roles` (starter packs `hr`, `finance`,
  `warehouse`, `staff_self_service`, `people_manager`), `compile` (a
  generated block in `policy.csv`, refused when high-sensitivity columns
  would be readable on all rows without an acknowledgement), `report`
  (Markdown access report), `import-users` (HR/IdP CSV export, the only
  channel that sets emails) and `drift` (exit 0/1/2 for CI).

### Command-line tools
- `rbic-chat`, `rbic-master`, `rbic-gate-demo`, `rbic-seed`, `rbic-init`;
  each takes `--config-dir` (or `RBIC_CONFIG_DIR`); there is no default
  config directory.

### Open WebUI integration (`integrations/openwebui/`, sdist only)
- A Pipe function for Open WebUI v0.12.4: SSO-only identity, private chats
  only, data-free stubs for background tasks, refusal of attachments and
  retrieved context, fixed reply texts.
- A digest-pinned Docker image with rbic preinstalled and a Docker Compose
  test deployment with Keycloak OIDC and a hardening checklist.

### Release tooling
- `.github/workflows/release.yml`: a `vX.Y.Z` tag on `main` (matching
  `__version__`) builds, tests and publishes to TestPyPI, then to PyPI
  after approval of the `pypi` environment, via Trusted Publishing (OIDC,
  no tokens). Actions are SHA-pinned and the build tooling is
  version-pinned.
