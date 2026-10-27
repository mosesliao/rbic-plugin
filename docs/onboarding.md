# Onboarding an organization with `rbic-init`

This guide takes a new organization from an empty config directory to a
signed-off access policy, and keeps it correct afterwards. The toolkit
**proposes**; the organization's policy owner (a *master* user) **approves**
every write with a typed `yes`. Nothing grants access until a master
approves it, and anything not approved stays hidden from everyone.

## 1. Prerequisites

- `pip install rbic-plugin` (or `pip install -e ".[test]"` from a checkout).
- A SQLite database the chatbot will answer from (Postgres is on the
  roadmap). `rbic-init` only reads its catalog (table and column names)
  and, for `suggest`, a sample of text values that it counts but never
  prints or stores.
- One person who owns the policy (HR / security / data owner). They are
  the master user: a record with `"role": "master"` in
  `worker_attributes.json`, and the `--actor` of every write. A master has
  no data access.
- An export of your workers from the IdP or HR system (CSV, see step 6).
- Run `rbic-init` on the machine that holds the config directory, as an
  operating-system user who may change the policy. Nobody else needs it.

## 2. The config directory

```
<config_dir>/
├── casbin/model.conf          # the policy language (ships with rbic; copy it from examples/demo)
├── casbin/policy.csv          # rules: the rbic-init block + hand-written / master-bot rules
├── db_schema.json             # table -> {column: type}; written by rbic-init schema
├── worker_attributes.json     # workers; written by rbic-init import-users
├── company.db                 # the database (or pass --db / RBIC_DB_PATH)
├── policy_changes.jsonl       # changelog of every applied change (holds full file text)
└── onboarding/
    ├── catalog.json           # column -> data category, with approvals
    ├── roles.json             # roles x categories, inheritance, row scopes
    ├── group_map.json         # IdP group -> role, for import-users
    └── access-report.md       # the report you sign off (sensitive, see 11)
```

Start from `examples/demo`'s `casbin/model.conf`, an empty
`casbin/policy.csv`, an empty `db_schema.json` (`{}`) and a
`worker_attributes.json` holding only your master user:

```json
{"master": {"role": "master"}}
```

Every command takes `--config-dir DIR` (or `RBIC_CONFIG_DIR`) and
`--audit-log PATH` (JSON lines). Every write prints what it will do and
asks `Apply? [yes/no]`: only `yes`/`y` (any case) applies, `no`/`n`
declines, anything else re-asks, end of input declines. Decisions are
audited.

## 3. Schema: `rbic-init schema`

```bash
rbic-init schema --config-dir $D                             # dry run: diff vs db_schema.json
rbic-init schema --config-dir $D --write --actor master      # write it (yes/no)
```

Tables and columns whose names are not lowercase identifiers are skipped
(the gate could not address them). Anything not in `db_schema.json` is
denied to everyone.

## 4. Categories: `suggest`, `status`, `approve`, `reject`

```bash
rbic-init suggest --config-dir $D            # or --no-values: names only, no rows read
rbic-init status  --config-dir $D
rbic-init approve --config-dir $D --actor master --all-suggested
rbic-init approve --config-dir $D --actor master payroll.salary pay   # one column, your category
rbic-init reject  --config-dir $D --actor master notes.body           # stays hidden, for good
```

`suggest` labels each column with a category (`directory`, `contact`,
`pay`, `personal_identifier`, `leave`, `training`, `inventory`,
`logistics`, `finance`, `safety`, `other`) from local name and value rules.
No LLM is involved and no value is shown: evidence reads like
"value-rule:email matched 37/40 sampled values". Each category has a
sensitivity (`low`, `medium`, `high`); `pay` and `personal_identifier` are
high. Review every suggestion: only **approved** columns are ever compiled.

## 5. Roles: `roles add-pack / set / scope / all-rows`

```bash
rbic-init roles packs --config-dir $D                                   # what ships
rbic-init roles add-pack staff_self_service --config-dir $D --actor master
rbic-init roles add-pack hr       --config-dir $D --actor master        # also finance, warehouse, people_manager
rbic-init roles set hr_staff --inherits employee --config-dir $D --actor master
rbic-init roles scope hr_staff trainings "dept = '{dept}'" --config-dir $D --actor master
rbic-init roles show --config-dir $D
```

A role reads every approved column of its categories. Row scopes become
row filters bound from each worker's attributes (`dept = '{dept}'`). Packs
place them by column name and list every table they had to skip. A role a
human edited is never overwritten by a pack.

**High-sensitivity data on all rows is refused.** If a role would read a
column of a high-sensitivity category on a table that no row scope of its
role level limits, `compile` refuses. Either add a row scope, or record
why that role needs every row:

```bash
rbic-init roles all-rows auditor payroll --reason "auditors reconcile every payslip" \
          --config-dir $D --actor master
```

The reason (printable ASCII, at most 200 characters) is written into the
generated block as `# all_rows auditor payroll: …`, shown next to
**ALL rows** in the access report, and listed in the compile's effect
summary. `--remove` takes it back. Medium-sensitivity data on all rows is
a warning only. A role that only inherits such columns needs no
acknowledgement of its own, because the ancestor that grants them had to
give one.

## 6. Workers: `rbic-init import-users`

This is the HR / IdP channel. It is the only path that may create workers
or set their emails; the master chatbot never can.

```bash
rbic-init import-users --config-dir $D --csv hr_export.csv --actor master \
          [--group-map onboarding/group_map.json] [--team-depth direct|all] [--remove-missing]
rbic-init import-users --config-dir $D --undo --actor master    # undo the last import
```

**CSV rules**

- UTF-8 (a BOM is fine) with one header row. The delimiter is `,` or `;`,
  detected from the header; a header with both, or neither, is refused.
- Header names are trimmed and lowercased. Required: `username`, `email`.
  Optional: `groups`, `employee_id`, `manager`. Every other column becomes
  a worker attribute; its name must be lowercase letters, digits and
  underscores. A `role` column is refused, because roles come from groups.
- `groups` are separated by `;` when the delimiter is `,`, and by `|`
  when it is `;`. Group names cannot contain `;` or `|`.
- Cells are trimmed. An empty cell means "no value", and removes that
  attribute from an existing worker. Attributes the file has no column for
  are kept.
- `email` must be a plain ASCII address. Non-ASCII and lookalike
  characters are refused. Emails are stored lowercased and must be unique,
  including against workers the import keeps. `employee_id` is digits
  only and unique. `manager` is the username of another row.
- Values may only contain letters, digits, spaces and `. , @ : / _ -`
  (at most 200 characters). Spreadsheet formulas such as `=…` or `+…` are
  refused. `-5` or `@team` are stored as plain text. Nothing is ever
  evaluated.
- One invalid row rejects the whole import. Errors give the row number
  and the username, never a value.

**group_map.json**

```json
{"version": 1, "map": [
  {"group": "HR Managers",  "role": "hr_manager"},
  {"group": "HR Staff",     "role": "hr_staff"},
  {"group": "Finance",      "role": "finance_analyst"},
  {"group": "Warehouse SG", "role": "warehouse_worker"}
]}
```

Entries are in priority order: a worker's role is the role of the first
entry whose group they are in (one role per worker for now), and other
mapped groups are reported. Roles must exist in `roles.json` or the
policy, and can never be `master`. **A worker in no mapped group is
imported without a role and denied everything.** Existing workers missing
from the file are kept and listed, unless you pass `--remove-missing`.
Removing a worker who still holds personal (`user:`) rules is refused,
with the rules to remove first. Master users are never created, changed or
removed. A row naming one is refused.

With a `manager` column, every worker with an `employee_id` gets
`self_and_subordinate_ids`: their own id plus their direct reports'
(`--team-depth direct`, the default) or all their reports' (`all`) ids,
for example `"1, 2, 3"`. A manager cycle is refused. The value must fit in
200 characters.

The summary names users, roles and attribute names only. Emails appear as
`<email set>` / `<email changed>` / `<email removed>`. The file diff is not
shown. The import is applied like every policy change: it must load in the
gate, every user's row filters are re-bound, it is locked, written to the
changelog before the file is replaced, and audited as
`POLICY_CONFIRM` / `POLICY_CHANGE kind=user_import`. The master chatbot
can undo an import only when no email changed. Otherwise use
`import-users --undo`.

`examples/demo/onboarding-sample/` holds a fake export and group map for
the demo database (`@example.test` addresses).

## 7. Compile: `rbic-init compile`

```bash
rbic-init compile --config-dir $D --actor master [--report PATH]
```

Compile writes one `p, role, table.column, read` line per approved column
(never `table.*`, so a new column stays hidden until approved), plus `g`
and `p2` lines, between these markers in `policy.csv`:

```
# ---- BEGIN rbic init (generated; edit onboarding/*.json and re-run rbic-init compile) ----
# sources: catalog.json, roles.json, db_schema.json sha256=<fingerprint> rbic=<version>
...
# ---- END rbic init ----
```

It prints warnings, the access report of the proposed policy (also written
to `onboarding/access-report.md`), the diff and the effect per role and
user, then asks yes/no.

**How the block and the master chatbot coexist.** Recompiling replaces
only the block. Every line outside it is kept byte for byte: your
hand-written rules and the master chatbot's section
(`# ---- Changes via master chatbot ----`). The chatbot refuses to edit or
remove a generated line. Change `catalog.json` / `roles.json` and
recompile instead. Its own additions, such as personal rules and denies,
go below the block and take effect alongside it. A deny always wins.
Undoing a compile restores the previous `policy.csv` but **not** the
onboarding sources. The undo says so, and `status` / `drift` report the
block as undone until you edit the sources or compile again.

## 8. Before you sign the access report

`rbic-init report --config-dir $D [--out PATH]` describes the live policy
as the gate enforces it (generated and manual rules together). Check:

- every role's readable columns, especially high-sensitivity ones;
- every **ALL rows** entry: is it intended? A high-sensitivity one must
  carry an acknowledgement and its reason;
- the users of each role, and users listed with no usable role or missing
  attributes (they are denied the queries those rules cover);
- personal rules and denies;
- the hidden columns: these are what no one can read. Is anything missing
  that people need?
- the warnings, in particular "readable but not approved", which points at
  a hand-written `table.*` rule that bypasses the catalog.

## 9. Fail-closed rules (summary)

- Unapproved, rejected or unlabelled columns are hidden from everyone.
- A new database column is hidden until it is in `db_schema.json` and
  approved.
- High-sensitivity data on all rows is refused unless acknowledged with a
  reason.
- Unmapped workers have no role and are denied everything.
- A policy, schema or worker file the gate would not load is never written.
  A stale proposal, where any input changed since it was shown, is
  refused.
- Malformed block markers stop both `compile` and the master chatbot until
  a human fixes them.

## 10. Keep it correct: `rbic-init drift`

```bash
rbic-init drift --config-dir $D [--db PATH] [--json]
```

| Check | Reports |
| --- | --- |
| `schema` | database vs `db_schema.json` (new/removed tables and columns, type changes) |
| `catalog` | columns not approved (unlabelled or suggested: hidden from everyone); entries for columns that no longer exist. Rejected columns are listed as info |
| `generated_block` | block out of date (sources changed), edited by hand, undone, missing or malformed |
| `roles` | roles.json naming missing categories, tables, columns, parent roles; scopes that no longer compile |
| `workers` | workers with no role or an unknown role; roles nobody holds; a policy that does not load (CRITICAL) |

Exit codes: `0` clean, `1` drift found, `2` the check could not run (for
example, the database is missing). Output names tables, columns, roles and
users only, never a value or an email. Run it nightly from cron or CI and
alert on a non-zero exit:

```cron
15 2 * * *  rbic-init drift --config-dir /srv/rbic/config --json > /var/log/rbic-drift.json || mail -s "rbic drift" owner@example.com < /var/log/rbic-drift.json
```

`rbic-init status` shows catalog progress and the block state.

## 11. Security notes

- **Who runs it:** the policy owner, on the host that holds the config
  directory. `--actor` must be a master user, and `PolicyAdmin` re-checks
  that under its lock. Anyone who can write the config directory can
  change the policy, so restrict it like any secret.
- **Protect `onboarding/` and the reports.** The access report contains
  usernames and the full policy structure. `policy_changes.jsonl` holds
  the full before/after text of every changed file, emails included. HR
  exports hold emails. Keep all of them out of version control:
  `.gitignore` covers `**/onboarding/access-report.md`,
  `**/onboarding/.onboarding.lock`, `**/onboarding/*.csv` and
  `policy_changes.jsonl` in any config directory. Store exports outside
  the config directory and delete them after the import.
- **Emails belong to HR / the IdP.** Only `import-users` sets them. The
  master chatbot cannot change an email, and cannot undo an import that
  changed one.
- **No data values** are printed, logged, stored in the catalog or sent to
  an LLM by any `rbic-init` command.
