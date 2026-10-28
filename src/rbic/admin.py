"""Pure-Python policy editor behind the master chatbot.

Every change is a two-step affair: a propose_* method validates the
request and returns a Change (the exact before/after file text) without
touching disk; apply() writes it only if the file is still exactly what
the proposal was computed against. The LLM never calls apply() — the
human confirms each Change in code (see rbic.master).

Rules are held by a ROLE (a group) or by one USER (subject "user:<name>",
which overrides the role: user deny > user allow > role deny > role
allow, see rbic.gate). Allow rules: p (columns), p2 (rows / scoped
grants); deny rules: p3 (columns), p4 (rows). "g, user:<name>, <role>"
gives a user an extra role on top of their own.

Fail-closed rules:
- unknown tables/columns/roles/users, malformed names      -> reject
- a role named like a user, or a user subject for an
  unknown or master user                                    -> reject
- anything touching the "master" role or a master user      -> reject
- row-filter templates with subqueries, table references,
  functions outside a small allowlist, or foreign columns   -> reject
- row-filter templates with non-printable/non-ASCII text,
  SQL comments, or a non-predicate / always-true shape      -> reject
- ANY input file (policy, attributes, schema, model)
  changed since the proposal                                -> reject
- the resulting files (policy.csv + worker_attributes.json)
  don't load with the SQL gate's own loader (gate.load_snapshot:
  bytes-based Casbin load, lone CR / unknown ptype refusal,
  compile_snapshot, email and user-subject checks), checked for
  every proposal and again under the lock in apply()          -> reject

worker_attributes.json changes come from the master bot (roles and
non-identity attributes only) or from the HR / IdP channel
(propose_user_import, `rbic-init import-users`), the one path that may set
emails. Imported workers whose IdP groups map to no role have no `role`
key: the engine denies them everything (fail closed).

apply() is serialized across processes with a lock file next to
policy.csv, and the changelog record ("applying") is written BEFORE the
file is replaced, followed by an "applied"/"failed: ..." record — a live
change can never lack an audit entry. History and undo only consider
"applied" records.
"""

import contextlib
import difflib
import functools
import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import casbin
from casbin.persist.adapter import load_policy_line

from .audit import logger
from .config import EngineConfig
from .gate import (
    PTYPE_ALLOW_COLUMNS, PTYPE_ALLOW_ROWS, PTYPE_DENY_COLUMNS, PTYPE_DENY_ROWS,
    SCOPE_COLUMN_SEP, STATIC_FILTER_WARNING, USER_PREFIX, FilterError,
    MissingAttribute, PolicySnapshot, bind_row_filter, check_schema,
    compile_row_filter, compile_snapshot, is_user_subject, load_enforcer,
    load_snapshot, parse_scope_columns, subjects_for, user_subject,
)
from .onboarding import CATALOG_FILE, ONBOARDING_DIR, ROLES_FILE
from .onboarding.block import (GENERATED_DUPLICATE_MESSAGE,
                               GENERATED_RULE_MESSAGE, BlockError,
                               block_line_indexes)
from .onboarding.schema import diff_schema


MASTER_ROLE = "master"
CHANGES_HEADER = "# ---- Changes via master chatbot ----"
READ = "read"

# Patterns end in \Z (not $, which also matches before a trailing "\n")
# and are used with fullmatch().
ROLE_RE = re.compile(r"[a-z][a-z0-9_]{1,40}\Z", re.ASCII)
ATTR_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,40}\Z", re.ASCII)
USER_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}\Z", re.ASCII)
# Attribute values are bound into row filters as literal AST nodes by the
# gate (never spliced as text); this allowlist is defense in depth.
ATTR_VALUE_RE = re.compile(r"[\w .,@:/-]{0,200}\Z", re.ASCII)
# A value bound into an UNQUOTED placeholder (e.g. IN ({ids})) must be a
# number, or a comma-separated list of numbers inside an IN list.
INT_RE = re.compile(r"[0-9]{1,18}\Z", re.ASCII)
INT_LIST_RE = re.compile(r"[0-9]{1,18}(\s*,\s*[0-9]{1,18})*\Z", re.ASCII)

STALE_MESSAGE = "Policy changed since this was proposed — please ask again"
SOURCES_NOT_REVERTED = (
    "NOTE: the onboarding sources (onboarding/catalog.json, roles.json) were "
    "NOT reverted: rbic-init status / drift report the generated block as "
    "out of date, and the next rbic-init compile applies them again unless "
    "you change them first.")
# Attributes that identify WHO a worker is (hosts map a signed-in user to a
# worker by them). Owned by HR / the identity provider: no admin path may
# change them, or a master could take over another worker's identity.
IDENTITY_ATTRIBUTES = ("email",)
IDENTITY_ATTRIBUTE_MESSAGE = (
    "The {key} attribute is identity-critical (it decides which signed-in "
    "person is this worker) and is owned by HR / the identity provider; it "
    "cannot be changed through the chatbot.")
_ABSENT = object()
LOCK_NAME = ".policy.lock"
CHANGELOG_FILE = "policy_changes.jsonl"
LOCK_TIMEOUT_S = 10.0
FILTER_DIALECTS = ("postgres", "sqlite")
COLUMN_PTYPES = (PTYPE_ALLOW_COLUMNS, PTYPE_DENY_COLUMNS)
ROW_PTYPES = (PTYPE_ALLOW_ROWS, PTYPE_DENY_ROWS)
PERSONAL_GRANT_WARNING = (
    "NOTE: a personal grant is its own scope - it keeps the rows the user's "
    "role sees (or the user's own personal row filter, if one exists), and a "
    "query mixing it with role columns must be covered entirely by personal "
    "rules (or entirely by the role).")


@dataclass
class Change:
    id: str
    kind: str
    actor: Optional[str]
    description: str
    target: str
    before_text: str
    after_text: str
    undoes: Optional[str] = None
    # sha256 of every input file at proposal time; apply() re-verifies all.
    input_hashes: dict = field(default_factory=dict)
    # Inputs beyond the four policy files ({name: path}; e.g. the
    # onboarding sources of a generated_policy change), hashed alongside.
    extra_inputs: dict = field(default_factory=dict)

    def diff(self) -> str:
        text = "".join(difflib.unified_diff(
            _lines(self.before_text), _lines(self.after_text),
            fromfile=self.target,
            tofile=f"{self.target} (proposed)",
        ))
        return _visible(text)


def _visible(text: str) -> str:
    """Escape control/invisible characters (ANSI escapes, form feeds, lone
    CRs, line/paragraph separators, bidi overrides...) so text shown to the
    human can't hide or rewrite what it says. CRLF is shown as a line end."""
    text = text.replace("\r\n", "\n")
    return "".join(c if c in "\n\t" or c.isprintable()
                   else c.encode("unicode_escape").decode("ascii")
                   for c in text)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path: str) -> str:
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _lines(text: str) -> list:
    """Split on LF only, keeping line ends: exactly the lines Casbin's
    file adapter sees (str.splitlines() would also split on form feed,
    U+2028 and other separators, hiding text from our line edits)."""
    parts = text.split("\n")
    out = [p + "\n" for p in parts[:-1]]
    if parts[-1]:
        out.append(parts[-1])
    return out


@contextlib.contextmanager
def exclusive_lock(path, timeout: Optional[float] = None, *,
                   what: str = "policy change"):
    """Inter-process lock: an O_CREAT|O_EXCL lock file at `path`, retried
    until `timeout` (default LOCK_TIMEOUT_S), always removed on exit."""
    path = os.fspath(path)
    deadline = time.monotonic() + (LOCK_TIMEOUT_S if timeout is None
                                   else timeout)
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ValueError(
                    f"Another {what} is being applied; nothing was "
                    f"written. Try again (if no {what} is in progress, "
                    f"delete the stale lock file {path}).")
            time.sleep(0.05)
    try:
        try:
            os.write(fd, f"{os.getpid()}\n".encode())
        finally:
            os.close(fd)
        yield
    finally:
        os.remove(path)


def _proposal(method):
    """Record input-file hashes around a propose_* call.

    If any input changed while the proposal was being computed, its
    analysis may be inconsistent, so it is refused outright.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        before = self._input_hashes()
        change = method(self, *args, **kwargs)
        # Whatever the method checked, the files it would produce must
        # load in the gate exactly as the gate loads them.
        self._check_gate_loads(change)
        # A method with extra inputs records their hashes as it read them.
        final = self._input_hashes(change.extra_inputs)
        if final != {**before, **change.input_hashes}:
            raise ValueError(STALE_MESSAGE + ".")
        change.input_hashes = final
        return change
    return wrapper


class _Ast:
    def __init__(self):
        self.policy = []


class _ShimModel:
    def __init__(self):
        self.model = {"p": {pt: _Ast() for pt in (*COLUMN_PTYPES, *ROW_PTYPES)},
                      "g": {"g": _Ast()}}


def _casbin_tokens(line: str) -> Optional[list]:
    """Tokenize one policy line exactly as Casbin's file adapter does.

    Casbin's CSV has no quoting: commas split fields unless inside ()/[].
    Returns [ptype, *fields], or None for comments/blank/unparseable lines.
    """
    shim = _ShimModel()
    try:
        load_policy_line(line.strip(), shim)
    except (IndexError, KeyError):
        return None
    for sec in shim.model.values():
        for ptype, ast in sec.items():
            if ast.policy:
                return [ptype, *ast.policy[0]]
    return None


def _cols(text) -> list:
    return text.split(SCOPE_COLUMN_SEP) if text else []


class PolicyAdmin:
    def __init__(
        self,
        policy_path,
        attributes_path,
        schema_path,
        model_path,
        changelog_path,
        onboarding_dir=None,
    ):
        # No default paths: nothing depends on the current directory.
        self.policy_path = os.fspath(policy_path)
        self.attributes_path = os.fspath(attributes_path)
        self.schema_path = os.fspath(schema_path)
        self.model_path = os.fspath(model_path)
        self.changelog_path = os.fspath(changelog_path)
        # <config_dir>/onboarding (the rbic-init sources); None: no
        # generated-policy proposals.
        self.onboarding_dir = (None if onboarding_dir is None
                               else os.fspath(onboarding_dir))

    @classmethod
    def from_config(cls, cfg: EngineConfig,
                    changelog_path=None) -> "PolicyAdmin":
        """Admin over an EngineConfig's files; the changelog defaults to
        <config_dir>/policy_changes.jsonl."""
        if changelog_path is None:
            changelog_path = cfg.config_dir / CHANGELOG_FILE
        return cls(cfg.policy_path, cfg.attributes_path, cfg.schema_path,
                   cfg.model_path, changelog_path,
                   onboarding_dir=cfg.config_dir / ONBOARDING_DIR)

    # ------------------------------------------------------------------
    # state loading
    # ------------------------------------------------------------------

    def schema(self) -> dict:
        with open(self.schema_path, encoding="utf-8") as f:
            return json.load(f)

    def attributes(self) -> dict:
        return json.loads(_read(self.attributes_path))

    def _input_hashes(self, extra: Optional[dict] = None) -> dict:
        """sha256 of every file a proposal's analysis depends on (plus
        `extra` {name: path}; a missing extra file hashes as None)."""
        out = {}
        for name, path in (("policy", self.policy_path),
                           ("attributes", self.attributes_path),
                           ("schema", self.schema_path),
                           ("model", self.model_path)):
            with open(path, "rb") as f:
                out[name] = hashlib.sha256(f.read()).hexdigest()
        for name, path in (extra or {}).items():
            out[f"extra:{name}"] = (hashlib.sha256(_read_bytes(path)).hexdigest()
                                    if os.path.exists(path) else None)
        return out

    def _lock_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(self.policy_path)),
                            LOCK_NAME)

    def _apply_lock(self, timeout: Optional[float] = None):
        """Inter-process lock (exclusive_lock on casbin/.policy.lock)."""
        return exclusive_lock(self._lock_path(), timeout)

    def _enforcer(self, policy_text: Optional[str] = None) -> casbin.Enforcer:
        """Casbin enforcer over policy.csv (or `policy_text`), loaded from
        bytes exactly as the gate loads it."""
        policy = (_read_bytes(self.policy_path) if policy_text is None
                  else policy_text.encode("utf-8"))
        return load_enforcer(_read_bytes(self.model_path), policy)

    def _after_state(self, change: "Change") -> tuple:
        """(policy, attributes, schema) bytes once `change` is applied; the
        files it doesn't touch are read from disk."""
        target = self._managed_path(change.target)
        return tuple(change.after_text.encode("utf-8") if path == target
                     else _read_bytes(path)
                     for path in (self.policy_path, self.attributes_path,
                                  self.schema_path))

    def _check_gate_loads(self, change: "Change") -> None:
        """Refuse a change whose resulting files the SQL gate would refuse
        to load (the gate would then deny everyone): the same
        gate.load_snapshot the gate runs on every reload, in every
        supported dialect."""
        policy, attributes, schema = self._after_state(change)
        model = _read_bytes(self.model_path)
        try:
            for dialect in FILTER_DIALECTS:
                load_snapshot(model, policy, attributes, schema,
                              dialect=dialect)
        except Exception as err:  # noqa: BLE001 - anything the gate refuses
            raise ValueError(f"The resulting policy would not load in the SQL "
                             f"gate: {type(err).__name__}: {err}") from None

    def _snapshot(self, e: casbin.Enforcer, attrs=None, schema=None,
                  what="The current policy.csv") -> PolicySnapshot:
        """Compile a policy exactly as the SQL gate would (every rule the
        gate refuses makes the gate fail closed, so it is refused here)."""
        attrs = self.attributes() if attrs is None else attrs
        schema = self.schema() if schema is None else schema
        try:
            for dialect in FILTER_DIALECTS:
                snap = compile_snapshot(0, e, attrs, schema, dialect=dialect)
        except ValueError as err:
            raise ValueError(f"{what} would not load in the SQL gate: "
                             f"{err}") from None
        return snap

    @staticmethod
    def _roles(e: casbin.Enforcer) -> set:
        subs = set()
        for ptype in (*COLUMN_PTYPES, *ROW_PTYPES):
            subs |= {r[0] for r in e.get_named_policy(ptype)}
        for child, parent, *_ in e.get_grouping_policy():
            subs |= {child, parent}
        return {s for s in subs if not is_user_subject(s)}

    @staticmethod
    def _all_roles_of(e: casbin.Enforcer, role: str) -> set:
        return {role, *e.get_implicit_roles_for_user(role)}

    @staticmethod
    def _filter_rows(e: casbin.Enforcer, ptype=PTYPE_ALLOW_ROWS) -> list:
        """[(sub, table, template, columns_text|None)] for every p2 (or p4)
        row. 3 fields: row filter; 4 fields: column-scoped (the gate
        refuses any other arity, so do we)."""
        rows = []
        for rule in e.get_named_policy(ptype):
            if len(rule) not in (3, 4):
                raise ValueError(f"Malformed row filter rule {rule!r}.")
            rows.append((*rule[:3], rule[3] if len(rule) == 4 else None))
        return rows

    def _scopes(self, e: casbin.Enforcer, role: str) -> dict:
        """table -> [templates] (legacy filters), mirroring the gate's
        role-level base scope."""
        roles = self._all_roles_of(e, role)
        out: dict = {}
        for sub, table, template, columns in self._filter_rows(e):
            if sub in roles and columns is None:
                out.setdefault(table, []).append(template)
        return out

    def _scoped_grants(self, e: casbin.Enforcer, role: str) -> dict:
        """table -> [(template, columns_text)] scoped grants, incl. inherited."""
        roles = self._all_roles_of(e, role)
        out: dict = {}
        for sub, table, template, columns in self._filter_rows(e):
            if sub in roles and columns is not None:
                out.setdefault(table, []).append((template, columns))
        return out

    def _hidden_rows(self, e: casbin.Enforcer, role: str) -> dict:
        """table -> [(template, columns_text|None)] row denies (p4) held by
        the role or an inherited role."""
        roles = self._all_roles_of(e, role)
        out: dict = {}
        for sub, table, template, columns in self._filter_rows(e, PTYPE_DENY_ROWS):
            if sub in roles:
                out.setdefault(table, []).append((template, columns))
        return out

    @staticmethod
    def _normalize_columns(columns) -> Optional[str]:
        """Accept a list of names or a '|'/','-separated string; return the
        policy-file form ("id|name") or None when no columns were given."""
        if columns is None:
            return None
        if isinstance(columns, str):
            columns = re.split(r"[|,]", columns)
        if not isinstance(columns, (list, tuple)) or not all(
                isinstance(c, str) for c in columns):
            raise ValueError("columns must be a list of column names.")
        items = [c.strip() for c in columns if c.strip()]
        if not items:
            return None
        return SCOPE_COLUMN_SEP.join(items)

    def _readable(self, s: PolicySnapshot, role: str, schema: dict) -> dict:
        """Role-level effective columns: grants minus column denies."""
        return s.columns_for(self._all_roles_of(s.enforcer, role), schema)

    @staticmethod
    def _personal_rows(s: PolicySnapshot, username: str, table: str) -> str:
        """Which rows of `table` the user's personal (p) grants see, exactly
        as the gate decides it: their own 3-field p2 filter(s) if any, else
        the row filters of their roles, else every row."""
        subj = s.subjects_for(username)
        filters, borrowed = s.user_base_filters(subj, table) if subj else ([], False)
        text = " OR ".join(f"({rf.template})" for rf in filters)
        if not filters:
            return f"ALL rows of {table} - no row filter at role or personal level"
        if borrowed:
            return f"rows their role sees: {text}"
        return f"only rows matching their personal row filter: {text}"

    # ------------------------------------------------------------------
    # read-only API
    # ------------------------------------------------------------------

    def list_roles(self) -> list:
        e = self._enforcer()
        attrs = self.attributes()
        return [
            {
                "role": r,
                "inherits": sorted(e.get_roles_for_user(r)),
                "users": sorted(u for u, a in attrs.items() if a.get("role") == r),
                "extra_for_users": sorted(
                    u for u, a in attrs.items() if a.get("role") != MASTER_ROLE
                    and r in e.get_roles_for_user(user_subject(u))),
            }
            for r in sorted(self._roles(e))
        ]

    def list_tables(self) -> dict:
        return {t: list(cols) for t, cols in self.schema().items()}

    def describe_role(self, role: str) -> dict:
        e = self._enforcer()
        if role not in self._roles(e):
            raise ValueError(f"Unknown role {role!r}. Known roles: "
                             f"{', '.join(sorted(self._roles(e)))}")
        s = self._snapshot(e)
        attrs = self.attributes()
        inherited = sorted(e.get_implicit_roles_for_user(role))
        roles = self._all_roles_of(e, role)
        info = {
            "role": role,
            "direct_grants": sorted(p[1] for p in e.get_policy() if p[0] == role),
            "inherits_directly": sorted(e.get_roles_for_user(role)),
            "inherited_roles": inherited,
            "inherited_grants": {
                r: sorted(p[1] for p in e.get_policy() if p[0] == r)
                for r in inherited
            },
            "column_denies": sorted(
                ({"column": p[1], "from_role": p[0]}
                 for p in e.get_named_policy(PTYPE_DENY_COLUMNS) if p[0] in roles),
                key=lambda d: (d["column"], d["from_role"])),
            "effective_read": self._readable(s, role, self.schema()),
            "row_scopes": [
                {"table": t, "filter": f, "from_role": sub}
                for sub, t, f, c in self._filter_rows(e) if sub in roles and c is None
            ],
            "scoped_grants": [
                {"table": t, "columns": _cols(c), "filter": f, "from_role": sub}
                for sub, t, f, c in self._filter_rows(e)
                if sub in roles and c is not None
            ],
            "hidden_rows": [
                {"table": t, "filter": f, "from_role": sub,
                 **({"columns": _cols(c)} if c else {})}
                for sub, t, f, c in self._filter_rows(e, PTYPE_DENY_ROWS)
                if sub in roles
            ],
            "users": sorted(u for u, a in attrs.items() if a.get("role") == role),
            "extra_for_users": sorted(
                u for u, a in attrs.items() if a.get("role") != MASTER_ROLE
                and role in e.get_roles_for_user(user_subject(u))),
        }
        personal = sorted(u for u in info["users"] if any(
            self._personal(s, u).values()))
        if personal:
            info["users_with_personal_rules"] = personal
        return info

    def describe_user(self, username: str) -> dict:
        attrs = self.attributes()
        if username not in attrs:
            raise ValueError(f"Unknown user {username!r}. Known users: "
                             f"{', '.join(sorted(attrs))}")
        record = attrs[username]
        role = record.get("role")
        info = {
            "username": username,
            "role": role,
            "attributes": {k: v for k, v in record.items() if k != "role"},
        }
        if role == MASTER_ROLE:
            info["note"] = ("master user: manages access policy only; has no "
                            "data access and cannot be edited via the chatbot")
            return info
        e = self._enforcer()
        s = self._snapshot(e, attrs)
        schema = self.schema()
        subj = s.subjects_for(username)
        scopes = {}
        hidden = {}
        if subj is not None:
            for sub, table, template, columns in self._filter_rows(e):
                if sub in subj.roles and columns is None:
                    scopes.setdefault(table, []).append(template)
            for sub, table, template, columns in self._filter_rows(e, PTYPE_DENY_ROWS):
                if sub in subj.roles:
                    hidden.setdefault(table, []).append(
                        template + (f" [columns {columns}]" if columns else ""))
            info["extra_roles"] = sorted(e.get_roles_for_user(subj.user))
        info["effective_read"] = s.effective_columns(username, schema)
        denied = s.denied_columns(username, schema)
        if denied:
            info["denied_columns"] = denied
        info["row_scopes"] = {t: " OR ".join(f"({x})" for x in fs)
                              for t, fs in scopes.items()}
        if hidden:
            info["hidden_rows"] = hidden
        scoped = {}
        if subj is not None:  # role-level scoped grants (personal: see below)
            for sub, rf in s.row_filters:
                if rf.scoped and sub in subj.roles:
                    cols = [c for c in rf.columns
                            if c not in denied.get(rf.table, [])]
                    if cols:
                        scoped.setdefault(rf.table, []).append(
                            {"columns": cols, "rows_where": rf.template})
        if scoped:
            info["scoped_grants"] = scoped
        personal = self._personal(s, username)
        if any(personal.values()):
            info["personal_rules"] = personal
            tables = sorted({g.split(".")[0] for g in personal["grants"]})
            if tables:  # the rows each personal grant sees, as the gate decides
                info["personal_grant_rows"] = {
                    t: self._personal_rows(s, username, t) for t in tables}
        missing = self._missing_for_user(s, username)
        if missing:
            info["denied_tables_missing_attributes"] = missing
        return info

    def history(self, limit: int = 10) -> list:
        keep = ("id", "ts", "actor", "kind", "description", "file", "undoes")
        return [{k: e[k] for k in keep if k in e}
                for e in self._applied()[-max(1, int(limit)):]]

    def _changelog(self) -> list:
        if not os.path.exists(self.changelog_path):
            return []
        with open(self.changelog_path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def _applied(self) -> list:
        """Changelog records of changes that actually went live.

        apply() writes a full record with status "applying" before replacing
        the file and a full "applied" record after; only the latter counts
        (records without a status predate this scheme and were applied).
        """
        return [e for e in self._changelog()
                if e.get("status", "applied") == "applied"]

    def _append_log(self, entry: dict) -> None:
        with open(self.changelog_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # ------------------------------------------------------------------
    # validation helpers
    # ------------------------------------------------------------------

    def _check_role_name(self, role, what="role"):
        if isinstance(role, str) and role.startswith(USER_PREFIX):
            raise ValueError(f"{role!r} is a user subject, not a {what}: pass "
                             f"username={role[len(USER_PREFIX):]!r} for a "
                             "personal rule.")
        if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
            raise ValueError(f"Invalid {what} name {role!r}: use lowercase "
                             "letters, digits and underscores (2-41 chars).")
        if role == MASTER_ROLE:
            raise ValueError("The 'master' role cannot be used in access "
                             "policy - it manages policy and has no data access.")
        if role in self.attributes():
            raise ValueError(f"{role!r} is a username, not a {what}. For a "
                             f"rule about that person use username={role!r}; "
                             "roles are groups (e.g. hr_staff).")

    def _check_username(self, username) -> dict:
        """The record of an existing non-master user (fail otherwise)."""
        attrs = self.attributes()
        if not isinstance(username, str) or not USER_RE.fullmatch(username) \
                or username not in attrs:
            raise ValueError(f"Unknown user {username!r}. Known users: "
                             f"{', '.join(sorted(attrs))}")
        if attrs[username].get("role") == MASTER_ROLE:
            raise ValueError(f"{username} is a master user; master users have "
                             "no data access and cannot be changed through "
                             "the chatbot.")
        return attrs[username]

    def _subject(self, role, username) -> tuple:
        """(policy subject, display name) for a rule held by a role (group)
        or by one user (personal rule, subject "user:<name>")."""
        if username is not None and role is not None:
            raise ValueError("Give either a role (for a group) or a username "
                             "(for one person), not both.")
        if username is not None:
            record = self._check_username(username)
            return (user_subject(username),
                    f"User {username} (role {record.get('role')})")
        if role is None:
            raise ValueError("Give a role (for a group) or a username (for "
                             "one person).")
        self._check_role_name(role)
        return role, f"Role {role}"

    def _check_table(self, table, schema):
        if table not in schema:
            raise ValueError(f"Unknown table {table!r}. Tables: "
                             f"{', '.join(sorted(schema))}")

    def _check_column(self, table, column, schema):
        if column != "*" and column not in schema[table]:
            raise ValueError(f"Unknown column {column!r} on {table}. Columns: "
                             f"{', '.join(schema[table])} (or '*' for all).")

    def _check_filter(self, table: str, template, schema: dict) -> tuple:
        """Validate a proposed template with the strict authoring rules.

        Uses the gate's own compiler (so anything accepted here also loads
        in the gate), once per supported dialect. Strict rules: printable
        ASCII only, no SQL comments, a boolean combination of
        column-vs-value predicates, no tautologies (see rbic.gate).
        """
        if not isinstance(template, str) or not template.strip():
            raise ValueError("Filter template must be a non-empty string.")
        template = template.strip()
        for dialect in FILTER_DIALECTS:
            compiled = compile_row_filter(table, template, schema,
                                          dialect=dialect, strict=True)
        return template, compiled

    @staticmethod
    def _missing_for_user(s: PolicySnapshot, username: str) -> dict:
        """table -> [attributes] the user lacks for a row filter, scoped
        grant or row deny that applies to them (the gate denies every
        query such a rule covers)."""
        subj = s.subjects_for(username)
        record = s.attributes.get(username, {})
        missing: dict = {}
        if subj is None:
            return missing
        for sub, rf in (*s.row_filters, *s.deny_filters):
            if sub != subj.user and sub not in subj.roles:
                continue
            need = [p for p in rf.placeholders if p not in record]
            if need:
                missing.setdefault(rf.table, set()).update(need)
        return {t: sorted(v) for t, v in missing.items()}

    @staticmethod
    def _check_attr_value(username, key, value):
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError(f"{username}.{key}: attribute value must be a "
                             "string or integer.")
        if isinstance(value, str) and not ATTR_VALUE_RE.fullmatch(value):
            raise ValueError(f"{username}.{key} = {value!r}: attribute values "
                             "may only contain letters, digits, spaces and "
                             ". , @ : / _ - (max 200).")

    def _check_rendered_scopes(self, e, role, record, schema, username="user"):
        """Bind every row filter and row deny that applies to the user
        (role level and personal) with their real attribute values.

        The gate binds values as literal AST nodes, so a value can never
        change a filter's structure; this is defense in depth that also
        keeps bindings meaningful. Every bound value must pass
        ATTR_VALUE_RE, and a value bound into an UNQUOTED placeholder must
        be a number (inside IN (...): a comma-separated list of numbers),
        so e.g. "1, employee_id" is refused rather than silently matching
        a string.
        """
        subj = subjects_for(e, username, role)
        templates = []
        for ptype in ROW_PTYPES:
            for sub, table, template, _ in self._filter_rows(e, ptype):
                if sub == subj.user or sub in subj.roles:
                    templates.append((table, template))
        for table, t in templates:
            for dialect in FILTER_DIALECTS:
                try:
                    rf = compile_row_filter(table, t, schema,
                                            dialect=dialect)
                    bind_row_filter(rf, record, table)
                except MissingAttribute:
                    break  # the gate denies these queries outright
                except FilterError as err:
                    raise ValueError(
                        f"Row filter on {table} ({t}) cannot be applied "
                        f"to {username}: {err}") from None
            else:
                for name, quoted, in_list in rf.uses():
                    value = record[name]
                    self._check_attr_value(username, name, value)
                    if quoted or isinstance(value, int):
                        continue
                    if not (INT_LIST_RE if in_list else INT_RE).fullmatch(value):
                        raise ValueError(
                            f"{username}.{name} = {value!r} can't be used "
                            f"in the row filter on {table} ({t}): an "
                            "unquoted placeholder needs a number"
                            + (" or a comma-separated list of numbers."
                               if in_list else "."))

    def _check_all_users(self, e, attrs: dict, schema: dict, users=None):
        """_check_rendered_scopes for every (or the given) non-master user."""
        for user, record in sorted(attrs.items()):
            if users is not None and user not in users:
                continue
            if not isinstance(record, dict):
                raise ValueError(f"Record for {user!r} must be an object.")
            role = record.get("role")
            if role == MASTER_ROLE or role is None:
                continue  # master: no data access; no role: denied outright
            if not isinstance(role, str):
                raise ValueError(f"User {user!r} has an invalid role.")
            self._check_rendered_scopes(e, role, record, schema, user)

    def _check_master_intact(self, before: dict, after: dict):
        masters_before = {u: r for u, r in before.items()
                          if r.get("role") == MASTER_ROLE}
        masters_after = {u: r for u, r in after.items()
                         if r.get("role") == MASTER_ROLE}
        if masters_before != masters_after:
            raise ValueError("Master users cannot be created, edited or "
                             "demoted through the chatbot.")

    @staticmethod
    def _check_no_master_in_policy(e: casbin.Enforcer):
        if MASTER_ROLE in PolicyAdmin._roles(e):
            raise ValueError("The 'master' role may not appear in policy.csv.")

    # ------------------------------------------------------------------
    # policy.csv line editing (line-based: comments are preserved)
    # ------------------------------------------------------------------

    def _add_line(self, text: str, fields: list) -> str:
        self._block(text)  # malformed rbic-init markers: refuse
        line = ", ".join(fields)
        if _casbin_tokens(line) != fields:
            # Casbin's CSV has no quoting; a comma outside ()/[] or an
            # unbalanced bracket would silently split/merge fields.
            raise ValueError(
                "Rule would not round-trip through Casbin's policy parser: "
                "commas are only allowed inside parentheses, and brackets "
                "must be balanced.")
        nl = _newline(text)
        if text and not text.endswith(("\n", "\r")):
            text += nl
        if CHANGES_HEADER not in [l.rstrip("\r\n") for l in _lines(text)]:
            text += nl + CHANGES_HEADER + nl
        return text + line + nl

    @staticmethod
    def _block(text: str) -> set:
        """Line indexes of policy.csv's rbic-init block (empty if none);
        malformed markers refuse every edit (fail closed)."""
        try:
            return block_line_indexes(text)
        except BlockError as err:
            raise ValueError(f"policy.csv: {err}. Fix the rbic-init markers "
                             "by hand before changing rules.") from None

    @classmethod
    def _remove_line(cls, text: str, fields: list) -> str:
        lines = _lines(text)
        hits = {i for i, l in enumerate(lines) if _casbin_tokens(l) == fields}
        if not hits:
            raise ValueError("No such rule in policy.csv.")
        inside = hits & cls._block(text)
        if inside == hits:
            # The onboarding sources own the block: an edit here would be
            # silently reverted by the next compile.
            raise ValueError(f"Refused: {GENERATED_RULE_MESSAGE}.")
        if inside:
            # A hand-written copy outside the block of a generated rule:
            # removing it would change nothing (the block's copy stays in
            # force), so refuse rather than suggest access changed.
            raise ValueError(f"Refused: {GENERATED_DUPLICATE_MESSAGE}.")
        return "".join(l for i, l in enumerate(lines) if i not in hits)

    @classmethod
    def _check_undo_keeps_generated(cls, current: str, restored: str) -> None:
        """An undo of a non-compile change may not remove a line outside
        the block that duplicates a generated rule (_remove_line's rule)."""
        def split(text):
            block = cls._block(text)
            inside, outside = set(), []
            for i, line in enumerate(_lines(text)):
                tokens = _casbin_tokens(line)
                if tokens:
                    if i in block:
                        inside.add(tuple(tokens))
                    else:
                        outside.append(tuple(tokens))
            return inside, outside

        generated, now_outside = split(current)
        _, then_outside = split(restored)
        for rule in now_outside:
            if rule in generated and now_outside.count(rule) > \
                    then_outside.count(rule):
                raise ValueError(f"Refused: the undo would remove "
                                 f"'{', '.join(rule)}': "
                                 f"{GENERATED_DUPLICATE_MESSAGE}.")

    def _rules(self, text: str) -> list:
        return [t for t in map(_casbin_tokens, _lines(text)) if t]

    # ------------------------------------------------------------------
    # effect summaries (what actually changes, computed not guessed)
    # ------------------------------------------------------------------

    @staticmethod
    def _personal(s: PolicySnapshot, username: str) -> dict:
        """Every rule held by the user subject, plus their extra roles."""
        u = user_subject(username)
        return {
            "grants": sorted(obj for sub, obj in s.allow_grants if sub == u),
            "denies": sorted(obj for sub, obj in s.deny_grants if sub == u),
            "row_scopes": [{"table": rf.table, "filter": rf.template}
                           for sub, rf in s.row_filters
                           if sub == u and not rf.scoped],
            "scoped_grants": [{"table": rf.table, "columns": list(rf.columns),
                               "filter": rf.template}
                              for sub, rf in s.row_filters
                              if sub == u and rf.scoped],
            "hidden_rows": [{"table": rf.table, "filter": rf.template,
                             **({"columns": list(rf.columns)} if rf.scoped else {})}
                            for sub, rf in s.deny_filters if sub == u],
            "extra_roles": sorted(s.enforcer.get_roles_for_user(u)),
        }

    @staticmethod
    def _column_diff(before: dict, after: dict) -> list:
        """[(table, gained, lost)] for tables whose column lists differ."""
        out = []
        for table in sorted(set(before) | set(after)):
            gained = [c for c in after.get(table, []) if c not in before.get(table, [])]
            lost = [c for c in before.get(table, []) if c not in after.get(table, [])]
            if gained or lost:
                out.append((table, gained, lost))
        return out

    def _role_effects(self, before_s, after_s, schema) -> list:
        attrs = self.attributes()
        before_e, after_e = before_s.enforcer, after_s.enforcer
        notes = []
        for role in sorted(self._roles(before_e) | self._roles(after_e)):
            rb = self._readable(before_s, role, schema)
            ra = self._readable(after_s, role, schema)
            sb = self._scopes(before_e, role)
            sa = self._scopes(after_e, role)
            bits = []
            for table, gained, lost in self._column_diff(rb, ra):
                if gained:
                    bits.append(f"gains read on {table}.({', '.join(gained)})")
                if lost:
                    bits.append(f"loses read on {table}.({', '.join(lost)})")
            for table in sorted(set(sb) | set(sa)):
                before_t, after_t = sb.get(table, []), sa.get(table, [])
                if sorted(before_t) == sorted(after_t):
                    continue
                if not after_t and table in ra:
                    bits.append(f"WARNING: row filter on {table} removed - "
                                f"ALL rows of {table} become visible")
                elif after_t:
                    # same-table scopes OR together: more scopes = more rows
                    widened = bool(before_t) and set(before_t) < set(after_t)
                    label = "WIDENED to" if widened else "limited to"
                    bits.append(f"rows of {table} {label}: "
                                + " OR ".join(f"({t})" for t in after_t))
            for table in sorted(ra):
                if table not in sa and table not in rb:
                    bits.append(f"no row filter on {table} - all rows visible")
            gb = self._scoped_grants(before_e, role)
            ga = self._scoped_grants(after_e, role)
            for table in sorted(set(gb) | set(ga)):
                for template, cols in ga.get(table, []):
                    if (template, cols) not in gb.get(table, []):
                        bits.append(self._scoped_note("gains", table, cols,
                                                      template))
                for template, cols in gb.get(table, []):
                    if (template, cols) not in ga.get(table, []):
                        bits.append(self._scoped_note("loses", table, cols,
                                                      template))
            hb = self._hidden_rows(before_e, role)
            ha = self._hidden_rows(after_e, role)
            for table in sorted(set(hb) | set(ha)):
                for template, cols in ha.get(table, []):
                    if (template, cols) not in hb.get(table, []):
                        bits.append(self._hidden_note("hidden", table, cols,
                                                      template))
                for template, cols in hb.get(table, []):
                    if (template, cols) not in ha.get(table, []):
                        bits.append(self._hidden_note("no longer hidden", table,
                                                      cols, template))
            if bits:
                users = sorted(u for u, a in attrs.items() if a.get("role") == role)
                who = f" [users: {', '.join(users)}]" if users else ""
                notes.append(f"{role}{who}: " + "; ".join(bits))
        return notes

    def _user_effects(self, before_s, after_s, schema) -> list:
        """Per-user notes: users whose personal rules / extra roles changed
        get a full effective-access diff ("overriding role ..."); users
        whose personal rules mask a role-level change get told so."""
        notes = []
        for user, record in sorted(after_s.attributes.items()):
            role = record.get("role")
            if role == MASTER_ROLE or not isinstance(role, str):
                continue
            pb, pa = self._personal(before_s, user), self._personal(after_s, user)
            eff_diff = self._column_diff(before_s.effective_columns(user, schema),
                                         after_s.effective_columns(user, schema))
            subj_b, subj_a = before_s.subjects_for(user), after_s.subjects_for(user)
            role_cols_a = after_s.columns_for(subj_a.roles, schema) if subj_a else {}
            bits = []
            if pb != pa:
                for table, gained, lost in eff_diff:
                    if gained:
                        over = [c for c in gained if c not in role_cols_a.get(table, [])]
                        bits.append(f"gains read on {table}.({', '.join(gained)})"
                                    + (f" by personal rule, overriding role {role}"
                                       if over else ""))
                    if lost:
                        over = [c for c in lost if c in role_cols_a.get(table, [])]
                        bits.append(f"loses read on {table}.({', '.join(lost)})"
                                    + (f" by personal deny, overriding role {role}"
                                       if over else ""))
                bits += self._personal_diff(pb, pa, after_s, user, role, schema)
            else:
                # personal rules unchanged: a role-level change may be masked
                role_diff = self._column_diff(
                    before_s.columns_for(subj_b.roles, schema) if subj_b else {},
                    role_cols_a)
                eff = {t: (g, l) for t, g, l in eff_diff}
                for table, gained, lost in role_diff:
                    eg, el = eff.get(table, ([], []))
                    masked = [c for c in gained if c not in eg]
                    kept = [c for c in lost if c not in el]
                    if masked:
                        bits.append(f"{table}.({', '.join(masked)}) stays denied "
                                    "by a personal deny")
                    if kept:
                        bits.append(f"{table}.({', '.join(kept)}) stays readable "
                                    "by a personal grant")
            if bits:
                notes.append(f"{user} (role {role}): " + "; ".join(bits))
        return notes

    def _personal_diff(self, pb, pa, after_s, user, role, schema) -> list:
        bits = []
        added = [r for r in pa["extra_roles"] if r not in pb["extra_roles"]]
        removed = [r for r in pb["extra_roles"] if r not in pa["extra_roles"]]
        if added:
            bits.append(f"additionally holds role(s) {', '.join(added)} (their "
                        "grants, row filters and denies apply at role level)")
        if removed:
            bits.append(f"no longer holds extra role(s) {', '.join(removed)}")
        new_grant_tables = {g.split(".")[0] for g in pa["grants"]
                            if g not in pb["grants"]}
        changed_scope_tables = {r["table"] for r in pa["row_scopes"]
                                if r not in pb["row_scopes"]} | {
            r["table"] for r in pb["row_scopes"] if r not in pa["row_scopes"]}
        for table in sorted(new_grant_tables | changed_scope_tables):
            rows = self._personal_rows(after_s, user, table)
            if table in changed_scope_tables and table not in new_grant_tables \
                    and not any(g.startswith(table + ".") for g in pa["grants"]):
                continue  # no personal grant uses this scope (yet)
            bits.append(f"personal grants on {table} see "
                        + ("WARNING: " if rows.startswith("ALL rows") else "")
                        + rows)
        for r in pb["row_scopes"]:
            if r not in pa["row_scopes"]:
                bits.append(f"WARNING: personal row filter on {r['table']} "
                            f"({r['filter']}) removed")
        for r in pa["scoped_grants"]:
            if r not in pb["scoped_grants"]:
                bits.append(self._scoped_note(
                    "gains", r["table"], SCOPE_COLUMN_SEP.join(r["columns"]),
                    r["filter"]) + " (personal)")
        for r in pb["scoped_grants"]:
            if r not in pa["scoped_grants"]:
                bits.append(self._scoped_note(
                    "loses", r["table"], SCOPE_COLUMN_SEP.join(r["columns"]),
                    r["filter"]) + " (personal)")
        for r in pa["hidden_rows"]:
            if r not in pb["hidden_rows"]:
                bits.append(self._hidden_note(
                    "hidden", r["table"],
                    SCOPE_COLUMN_SEP.join(r.get("columns", [])) or None,
                    r["filter"]) + " (personal deny - overrides every allow)")
        for r in pb["hidden_rows"]:
            if r not in pa["hidden_rows"]:
                bits.append(self._hidden_note(
                    "no longer hidden", r["table"],
                    SCOPE_COLUMN_SEP.join(r.get("columns", [])) or None,
                    r["filter"]))
        for table, keys in self._missing_for_user(after_s, user).items():
            bits.append(f"WARNING: lacks attribute(s) {', '.join(keys)}, so "
                        f"their queries on {table} that the rule needing it "
                        "covers will be denied")
        return bits

    @staticmethod
    def _scoped_note(verb: str, table: str, cols: str, template: str) -> str:
        names = ", ".join(cols.split(SCOPE_COLUMN_SEP))
        note = (f"{verb} scoped read on {table}.({names}) for rows where "
                f"{template} (only for queries that use no other {table} column")
        if verb == "gains":
            note += "; adds to, never narrows, existing access"
        return note + ")"

    @staticmethod
    def _hidden_note(state: str, table: str, cols, template: str) -> str:
        note = f"rows of {table} where {template} {state}"
        if cols:
            note += f" when reading columns ({', '.join(_cols(cols))})"
        return note

    def _missing_attr_warnings(self, s: PolicySnapshot, roles) -> list:
        warnings = []
        for user, record in sorted(s.attributes.items()):
            if record.get("role") not in roles:
                continue
            for table, keys in self._missing_for_user(s, user).items():
                warnings.append(
                    f"WARNING: {user} lacks attribute(s) {', '.join(keys)}, so "
                    f"their queries on {table} that the rule needing it covers "
                    "will be denied.")
        return warnings

    def _policy_change(self, kind, actor, headline, before, after,
                       extra_notes=()) -> Change:
        schema = self.schema()
        attrs = self.attributes()
        after_e = self._enforcer(after)
        self._check_no_master_in_policy(after_e)
        # Compiling the result exactly as the gate does refuses every rule
        # that would make the gate fail closed (bad filters, unknown user
        # subjects, inheriting from a user, deny rules the model lacks...).
        after_s = self._snapshot(after_e, attrs, schema, "Resulting policy")
        before_s = self._snapshot(self._enforcer(before), attrs, schema)
        # Defense in depth: every user's filters must bind cleanly with
        # their real attribute values under the NEW policy.
        self._check_all_users(after_e, attrs, schema)
        effects = self._role_effects(before_s, after_s, schema)
        changed_roles = {n.split(" ", 1)[0].rstrip(":") for n in effects}
        notes = [*extra_notes, *effects,
                 *self._user_effects(before_s, after_s, schema),
                 *self._missing_attr_warnings(after_s, changed_roles)]
        return self._make(kind, actor, headline, notes, self.policy_path,
                          before, after)

    @staticmethod
    def _make(kind, actor, headline, notes, target, before, after,
              undoes=None) -> Change:
        description = headline
        if notes:
            description += "\nEffects:\n" + "\n".join(f"- {n}" for n in notes)
        elif before != after:
            description += "\nEffects: no change to any role's effective access."
        description = _visible(description)
        return Change(
            id=uuid.uuid4().hex[:8], kind=kind, actor=actor,
            description=description, target=target,
            before_text=before, after_text=after, undoes=undoes,
        )

    # ------------------------------------------------------------------
    # proposals (validate + compute; never write)
    # ------------------------------------------------------------------

    def _column_rule(self, ptype, add, kind, role, table, column, actor,
                     username) -> Change:
        """Shared by grant/revoke (p) and deny/remove_deny (p3)."""
        schema = self.schema()
        subject, who = self._subject(role, username)
        self._check_table(table, schema)
        self._check_column(table, column, schema)
        obj = f"{table}.{column}"
        what = f"every column of {table}" if column == "*" else obj
        before = _read(self.policy_path)
        fields = [ptype, subject, obj, READ]
        present = fields in self._rules(before)
        deny = ptype == PTYPE_DENY_COLUMNS
        if add and present:
            raise ValueError(f"{'Deny' if deny else 'Grant'} already present: "
                             + ", ".join(fields))
        if not add and not present:
            if deny:
                raise ValueError(f"There is no rule '{', '.join(fields)}' to "
                                 "remove.")
            raise ValueError(self._explain_missing_grant(subject, obj))
        after = self._add_line(before, fields) if add else \
            self._remove_line(before, fields)
        e = self._enforcer()
        s = self._snapshot(e)
        if add and not deny:
            if username is None:
                new = "" if subject in self._roles(e) else " (new role)"
                scopes = self._scopes(e, subject).get(table)
                rows = (f"only rows matching its row filter on {table}: "
                        + " OR ".join(f"({t})" for t in scopes)) if scopes \
                    else f"ALL rows of {table} - no row filter applies"
                headline = f"{who}{new} will be able to read {what} ({rows})."
            else:
                rows = self._personal_rows(s, username, table)
                headline = (f"{who} will be able to read {what} by a personal "
                            f"rule, overriding any role deny ({rows}).")
            extra = [PERSONAL_GRANT_WARNING] if username is not None else []
        elif add:
            if username is None:
                headline = (f"{who} (and every role inheriting it) will be "
                            f"denied read on {what}; only a personal (user) "
                            "allow can override this.")
            else:
                headline = (f"{who} will be denied read on {what}; this "
                            "overrides every role and personal allow.")
            extra = []
        elif not deny:
            headline = (f"{who} will lose its direct grant on {obj}."
                        if username is None else
                        f"{who} will lose their personal grant on {obj}.")
            extra = []
        else:
            headline = f"{who} will no longer be denied read on {obj}."
            extra = []
        return self._policy_change(kind, actor, headline, before, after, extra)

    @_proposal
    def propose_grant(self, role=None, table=None, column=None, actor=None,
                      username=None) -> Change:
        """Allow a role (or, with username, one user) to read table.column."""
        return self._column_rule(PTYPE_ALLOW_COLUMNS, True, "grant", role,
                                 table, column, actor, username)

    @_proposal
    def propose_revoke(self, role=None, table=None, column=None, actor=None,
                       username=None) -> Change:
        return self._column_rule(PTYPE_ALLOW_COLUMNS, False, "revoke", role,
                                 table, column, actor, username)

    @_proposal
    def propose_deny(self, role=None, table=None, column=None, actor=None,
                     username=None) -> Change:
        """Deny a role (or one user) read on table.column (p3)."""
        return self._column_rule(PTYPE_DENY_COLUMNS, True, "deny", role,
                                 table, column, actor, username)

    @_proposal
    def propose_remove_deny(self, role=None, table=None, column=None,
                            actor=None, username=None) -> Change:
        return self._column_rule(PTYPE_DENY_COLUMNS, False, "remove_deny",
                                 role, table, column, actor, username)

    def _explain_missing_grant(self, subject, obj) -> str:
        e = self._enforcer()
        msg = f"There is no rule 'p, {subject}, {obj}, read' to remove."
        if is_user_subject(subject):
            return msg + " (Personal grants must be removed with the exact " \
                         "column name they were given.)"
        role = subject
        if role not in self._roles(e):
            return msg + f" Role {role!r} does not exist."
        if obj.endswith(".*"):
            return msg + " (Use the exact column names granted to this role.)"
        if not e.enforce(role, obj, READ):
            return msg + f" Role {role} cannot read {obj} at all."
        sources = []
        for r in sorted(self._all_roles_of(e, role)):
            for sub, pobj, act in e.get_policy():
                if sub == r and act == READ and casbin.util.key_match(obj, pobj):
                    sources.append(f"'p, {sub}, {pobj}, read'"
                                   + ("" if r == role else
                                      f" (inherited from role {r})"))
        return (msg + f" {role} can read {obj} via " + ", ".join(sources)
                + ". To remove it, revoke that rule (affects every role that "
                  "has it) or remove the inheritance.")

    @_proposal
    def propose_row_scope(self, role=None, table=None, filter_template=None,
                          columns=None, actor=None, username=None) -> Change:
        """Add a row filter (columns=None) or a scoped grant (columns given)
        for a role or, with username, for one user.

        A scoped grant lets the subject read exactly `columns` of `table`
        for the rows matching the filter, with no p grant needed, and only
        for queries that use no other column of that table. It never
        narrows what the subject could already see.
        """
        schema = self.schema()
        subject, who = self._subject(role, username)
        self._check_table(table, schema)
        template, compiled = self._check_filter(table, filter_template, schema)
        cols = self._normalize_columns(columns)
        if cols is not None:
            try:
                names = parse_scope_columns(table, cols, schema)
            except FilterError as err:
                raise ValueError(str(err)) from None
        before = _read(self.policy_path)
        fields = [PTYPE_ALLOW_ROWS, subject, table, template] + ([cols] if cols else [])
        if fields in self._rules(before):
            raise ValueError("Row filter already present: " + ", ".join(fields))
        after = self._add_line(before, fields)
        before_e, after_e = self._enforcer(before), self._enforcer(after)
        before_s = self._snapshot(before_e)
        personal = " personal" if username is not None else ""
        override = (" This personal rule applies even where role rules deny "
                    "these rows.") if username is not None else ""
        if cols is not None:
            readable = (before_s.effective_columns(username, schema)
                        if username is not None
                        else self._readable(before_s, subject, schema)).get(table, [])
            already = [c for c in names if c in readable]
            headline = (f"{who} gets a{personal} scoped grant on {table}: "
                        f"it can read columns ({', '.join(names)}) for rows "
                        f"where {template}, without any other grant on "
                        f"{table}. Applies only to queries that use no other "
                        f"column of {table}; it adds to (never narrows) what "
                        f"is already visible.{override}")
            if already:
                headline += (f" Note: {table}.({', '.join(already)}) is already "
                             "readable via regular grants.")
            extra = [STATIC_FILTER_WARNING] if compiled.static else []
            return self._policy_change("row_scope", actor, headline, before,
                                       after, extra)
        if username is not None:
            existing = [rf.template for sub, rf in before_s.row_filters
                        if sub == subject and rf.table == table and not rf.scoped]
            if existing:
                headline = (f"{who} gets an additional personal row scope on "
                            f"{table}: {template}. Same-table scopes are "
                            "OR-combined, so this WIDENS their personal grants "
                            "(existing: " + " OR ".join(f"({t})" for t in existing)
                            + ").")
            else:
                was = self._personal_rows(before_s, username, table)
                headline = (f"{who}'s personal grants on {table} will only "
                            f"see rows where {template}, replacing the rows "
                            f"they saw before ({was}). This can WIDEN or "
                            "narrow them. (Their role's grants keep the "
                            "role's own row filters.)")
            extra = [STATIC_FILTER_WARNING] if compiled.static else []
            return self._policy_change("row_scope", actor, headline, before,
                                       after, extra)
        existing = self._scopes(before_e, subject).get(table)
        if existing:
            headline = (f"{who} gets an additional row scope on {table}: "
                        f"{template}. Same-table scopes are OR-combined, so "
                        "this WIDENS what it sees (existing: "
                        + " OR ".join(f"({t})" for t in existing) + ").")
        else:
            headline = (f"{who} will only see rows of {table} where "
                        f"{template}.")
        # Roles inheriting `role`: the same before/after scope diff the
        # effect notes use decides whether each is narrowed or widened.
        heirs = sorted(r for r in self._roles(after_e)
                       if r != subject and subject in self._all_roles_of(after_e, r))
        narrowed = [r for r in heirs if not self._scopes(before_e, r).get(table)]
        widened = [r for r in heirs if self._scopes(before_e, r).get(table)]
        if narrowed and not existing:
            headline += (f" Roles inheriting it ({', '.join(narrowed)}) will "
                         "also only see those rows.")
        if widened:
            headline += (f" WARNING: roles inheriting it that already had a "
                         f"row filter on {table} ({', '.join(widened)}) will "
                         "see MORE rows, because same-table scopes are "
                         "OR-combined.")
        extra = [STATIC_FILTER_WARNING] if compiled.static else []
        return self._policy_change("row_scope", actor, headline, before, after,
                                   extra)

    @_proposal
    def propose_remove_row_scope(self, role=None, table=None,
                                 filter_template=None, columns=None,
                                 actor=None, username=None) -> Change:
        """Remove a row filter, or (with columns) a scoped grant."""
        return self._remove_row_rule(PTYPE_ALLOW_ROWS, "remove_row_scope", role,
                                     table, filter_template, columns, actor,
                                     username)

    def _remove_row_rule(self, ptype, kind, role, table, filter_template,
                         columns, actor, username) -> Change:
        schema = self.schema()
        subject, who = self._subject(role, username)
        self._check_table(table, schema)
        if not isinstance(filter_template, str):
            raise ValueError("Filter template must be a string.")
        template = filter_template.strip()
        cols = self._normalize_columns(columns)
        before = _read(self.policy_path)
        fields = [ptype, subject, table, template] + ([cols] if cols else [])
        if fields not in self._rules(before):
            current = [", ".join(r[3:]) for r in self._rules(before)
                       if r[:3] == [ptype, subject, table] and len(r) in (4, 5)]
            noun = "row denies" if ptype == PTYPE_DENY_ROWS else \
                "filters/scoped grants"
            raise ValueError(
                f"No rule '{', '.join(fields)}'. Current {noun} for {subject} "
                f"on {table}: {current or 'none'} (inherited ones must be "
                "removed from their own role; a column-scoped rule needs its "
                "exact column list).")
        after = self._remove_line(before, fields)
        deny = ptype == PTYPE_DENY_ROWS
        if deny:
            headline = (f"{who} will again see rows of {table} where {template}"
                        + (f" (for columns {cols})" if cols else "") + ".")
        elif cols:
            headline = (f"{who} will lose its scoped grant on {table} "
                        f"(columns {cols} for rows where {template}).")
        else:
            headline = (f"{who} will lose the row filter on {table}: "
                        f"{template}.")
        return self._policy_change(kind, actor, headline, before, after)

    @_proposal
    def propose_deny_rows(self, role=None, table=None, filter_template=None,
                          columns=None, actor=None, username=None) -> Change:
        """Hide the rows of `table` matching the filter from a role (or one
        user) - for every query on the table, or (with columns) only for
        queries reading one of those columns. A role deny is overridden by a
        personal allow; a personal deny overrides everything."""
        schema = self.schema()
        subject, who = self._subject(role, username)
        self._check_table(table, schema)
        template, compiled = self._check_filter(table, filter_template, schema)
        cols = self._normalize_columns(columns)
        if cols is not None:
            try:
                names = parse_scope_columns(table, cols, schema)
            except FilterError as err:
                raise ValueError(str(err)) from None
        before = _read(self.policy_path)
        fields = [PTYPE_DENY_ROWS, subject, table, template] + ([cols] if cols else [])
        if fields in self._rules(before):
            raise ValueError("Row deny already present: " + ", ".join(fields))
        after = self._add_line(before, fields)
        when = (f" when reading columns ({', '.join(names)})" if cols is not None
                else "")
        if username is None:
            headline = (f"{who} (and every role inheriting it) will not see "
                        f"rows of {table} where {template}{when}. A personal "
                        "(user) allow still shows them.")
        else:
            headline = (f"{who} will not see rows of {table} where {template}"
                        f"{when}, whatever their roles or personal grants say.")
        headline += (" Rows where the filter is NULL are hidden too "
                     "(fail closed).")
        extra = [STATIC_FILTER_WARNING] if compiled.static else []
        return self._policy_change("deny_rows", actor, headline, before, after,
                                   extra)

    @_proposal
    def propose_remove_deny_rows(self, role=None, table=None,
                                 filter_template=None, columns=None,
                                 actor=None, username=None) -> Change:
        return self._remove_row_rule(PTYPE_DENY_ROWS, "remove_deny_rows", role,
                                     table, filter_template, columns, actor,
                                     username)

    @_proposal
    def propose_inherit(self, role, parent_role, actor=None) -> Change:
        self._check_role_name(role)
        self._check_role_name(parent_role, "parent role")
        e = self._enforcer()
        if parent_role not in self._roles(e):
            raise ValueError(f"Parent role {parent_role!r} does not exist.")
        if role == parent_role or role in self._all_roles_of(e, parent_role):
            raise ValueError(f"Inheritance cycle: {parent_role} already "
                             f"inherits from {role}.")
        before = _read(self.policy_path)
        fields = ["g", role, parent_role]
        if fields in self._rules(before):
            raise ValueError(f"Inheritance already present: g, {role}, "
                             f"{parent_role}")
        after = self._add_line(before, fields)
        headline = (f"Role {role} will inherit all grants, row filters AND "
                    f"denies of {parent_role}.")
        return self._policy_change("inherit", actor, headline, before, after)

    @_proposal
    def propose_remove_inherit(self, role, parent_role, actor=None) -> Change:
        self._check_role_name(role)
        self._check_role_name(parent_role, "parent role")
        before = _read(self.policy_path)
        fields = ["g", role, parent_role]
        if fields not in self._rules(before):
            raise ValueError(f"No rule 'g, {role}, {parent_role}' - {role} "
                             f"does not directly inherit {parent_role}.")
        after = self._remove_line(before, fields)
        headline = (f"Role {role} will no longer inherit grants, row "
                    f"filters or denies from {parent_role}.")
        return self._policy_change("remove_inherit", actor, headline,
                                   before, after)

    @_proposal
    def propose_add_user_role(self, username, role, actor=None) -> Change:
        """Give a user an EXTRA role (g, user:<name>, role) on top of their
        own - e.g. to cover for a colleague on leave. The extra role's
        grants, row filters and denies apply at role level; the user's
        own role is unchanged (use assign_role to change it)."""
        record = self._check_username(username)
        self._check_role_name(role)
        e = self._enforcer()
        if role not in self._roles(e):
            raise ValueError(f"Unknown role {role!r}. Known roles: "
                             f"{', '.join(sorted(self._roles(e)))}")
        main = record.get("role")
        if role == main or role in e.get_implicit_roles_for_user(main):
            raise ValueError(f"{username} already has role {role} through "
                             f"their own role {main}.")
        subject = user_subject(username)
        before = _read(self.policy_path)
        fields = ["g", subject, role]
        if fields in self._rules(before):
            raise ValueError(f"{username} already holds extra role {role}.")
        after = self._add_line(before, fields)
        inherited = sorted(e.get_implicit_roles_for_user(role))
        headline = (f"User {username} (role {main}) will additionally hold "
                    f"role {role}"
                    + (f" (which inherits {', '.join(inherited)})" if inherited
                       else "")
                    + ": all of its grants, row filters and denies apply to "
                      f"{username} as role-level rules, alongside {main}'s.")
        return self._policy_change("add_user_role", actor, headline, before,
                                   after)

    @_proposal
    def propose_remove_user_role(self, username, role, actor=None) -> Change:
        record = self._check_username(username)
        self._check_role_name(role)
        subject = user_subject(username)
        before = _read(self.policy_path)
        fields = ["g", subject, role]
        if fields not in self._rules(before):
            held = sorted(self._enforcer().get_roles_for_user(subject))
            raise ValueError(f"{username} does not hold extra role {role!r} "
                             f"(extra roles: {', '.join(held) or 'none'}; "
                             f"their own role is {record.get('role')}).")
        after = self._remove_line(before, fields)
        headline = (f"User {username} will no longer hold extra role {role}; "
                    f"their own role {record.get('role')} is unchanged.")
        return self._policy_change("remove_user_role", actor, headline,
                                   before, after)

    def _user_record(self, username) -> tuple:
        before = _read(self.attributes_path)
        attrs = json.loads(before)
        if not isinstance(username, str) or not USER_RE.fullmatch(username) \
                or username not in attrs:
            raise ValueError(f"Unknown user {username!r}. Known users: "
                             f"{', '.join(sorted(attrs))}")
        if attrs[username].get("role") == MASTER_ROLE:
            raise ValueError(f"{username} is a master user; master records "
                             "cannot be changed through the chatbot.")
        return before, attrs

    def _user_notes(self, before_s, after_s, schema, user, old, new) -> list:
        """Effect of one user's record changing from `old` to `new`."""
        e = after_s.enforcer
        old_role, new_role = old.get("role"), new.get("role")
        rb = before_s.effective_columns(user, schema) if user in before_s.attributes \
            else {}
        ra = after_s.effective_columns(user, schema)
        sa = self._scopes(e, new_role) if isinstance(new_role, str) else {}
        notes = []
        for table, gained, lost in self._column_diff(rb, ra):
            if gained:
                notes.append(f"gains read on {table}.({', '.join(gained)})")
            if lost:
                notes.append(f"loses read on {table}.({', '.join(lost)})")
        for table, fs in sa.items():
            names = set()
            for sub, rf in after_s.row_filters:
                if rf.table == table and not rf.scoped and rf.template in fs:
                    names.update(rf.placeholders)
            changed = sorted(n for n in names if old.get(n) != new.get(n))
            if changed or old_role != new_role:
                note = (f"rows of {table} limited to: "
                        + " OR ".join(f"({t})" for t in fs))
                if changed:
                    note += " with " + ", ".join(
                        f"{n}={new.get(n)!r} (was {old.get(n)!r})"
                        for n in changed)
                notes.append(note)
        for table in sorted(ra):
            if table not in sa and old_role != new_role:
                notes.append(f"no row filter on {table} - all rows visible")
        if old_role != new_role:
            gb = self._scoped_grants(e, old_role) if isinstance(old_role, str) else {}
            ga = self._scoped_grants(e, new_role) if isinstance(new_role, str) else {}
            for table in sorted(set(gb) | set(ga)):
                for template, cols in ga.get(table, []):
                    if (template, cols) not in gb.get(table, []):
                        notes.append(self._scoped_note("gains", table, cols,
                                                       template))
                for template, cols in gb.get(table, []):
                    if (template, cols) not in ga.get(table, []):
                        notes.append(self._scoped_note("loses", table, cols,
                                                       template))
            personal = self._personal(after_s, user)
            if any(personal.values()):
                notes.append("personal rules and extra roles are unchanged "
                             "and still apply")
        for table, keys in self._missing_for_user(after_s, user).items():
            notes.append(f"WARNING: lacks attribute(s) {', '.join(keys)}, so "
                         f"their queries on {table} that the rule needing it "
                         "covers will be denied")
        return notes

    def _attrs_change_notes(self, e, schema, before: dict, after: dict) -> list:
        """Validate and describe every user record that differs.

        Shared by set_attribute/assign_role proposals and attribute undo,
        so an undo gets the same value checks, scope checks and effect
        summary as a forward change.
        """
        changed = sorted(u for u in set(before) | set(after)
                         if before.get(u) != after.get(u))
        for user in changed:
            old_record = before.get(user)
            record = after.get(user)
            # Identity attributes never change here, in either direction
            # (forward change or undo of an older changelog entry).
            for key in IDENTITY_ATTRIBUTES:
                old_value = (old_record.get(key, _ABSENT)
                             if isinstance(old_record, dict) else _ABSENT)
                new_value = (record.get(key, _ABSENT)
                             if isinstance(record, dict) else _ABSENT)
                if old_value != new_value:
                    raise ValueError(f"{user}: "
                                     + IDENTITY_ATTRIBUTE_MESSAGE.format(key=key))
            if record is None:
                continue
            if not USER_RE.fullmatch(user) or not isinstance(record, dict):
                raise ValueError(f"Invalid user record {user!r}.")
            for key, value in record.items():
                # role is checked by assign_role; identity attributes are
                # unchanged (above) and validated by the gate's loader.
                if key == "role" or key in IDENTITY_ATTRIBUTES:
                    continue
                if not ATTR_KEY_RE.fullmatch(key):
                    raise ValueError(f"Invalid attribute name {user}.{key!r}.")
                self._check_attr_value(user, key, value)
        self._check_all_users(e, after, schema, users=set(changed))
        # The policy must still load against the new attributes (a user
        # subject must keep referring to a known non-master worker).
        after_s = self._snapshot(e, after, schema, "The policy")
        before_s = self._snapshot(e, before, schema)
        notes = []
        for user in changed:
            old = before.get(user) or {"role": None}
            new = after.get(user) or {"role": None}
            notes += [f"{user}: {n}" for n in self._user_notes(
                before_s, after_s, schema, user, old, new)]
        return notes

    def _user_change(self, kind, actor, username, headline, before, attrs,
                     new_record) -> Change:
        schema = self.schema()
        e = self._enforcer()
        after_attrs = dict(attrs, **{username: new_record})
        self._check_master_intact(attrs, after_attrs)
        notes = self._attrs_change_notes(e, schema, attrs, after_attrs)
        nl = _newline(before)
        after = json.dumps(after_attrs, indent=2).replace("\n", nl) + nl
        return self._make(kind, actor, headline, notes, self.attributes_path,
                          before, after)

    @_proposal
    def propose_assign_role(self, username, role, actor=None) -> Change:
        before, attrs = self._user_record(username)
        if role == MASTER_ROLE:
            raise ValueError("The master role cannot be assigned through "
                             "the chatbot.")
        self._check_role_name(role)
        e = self._enforcer()
        if role not in self._roles(e):
            raise ValueError(f"Unknown role {role!r}. Known roles: "
                             f"{', '.join(sorted(self._roles(e)))}")
        old_role = attrs[username].get("role")
        if old_role == role:
            raise ValueError(f"{username} already has role {role}.")
        headline = f"User {username}'s role will change from {old_role} to {role}."
        return self._user_change("assign_role", actor, username, headline,
                                 before, attrs, dict(attrs[username], role=role))

    @_proposal
    def propose_set_attribute(self, username, key, value, actor=None) -> Change:
        before, attrs = self._user_record(username)
        if not isinstance(key, str) or not ATTR_KEY_RE.fullmatch(key):
            raise ValueError(f"Invalid attribute name {key!r}: lowercase "
                             "letters, digits, underscores.")
        if key == "role":
            raise ValueError("Use assign_role to change a user's role.")
        if key in IDENTITY_ATTRIBUTES:
            raise ValueError(IDENTITY_ATTRIBUTE_MESSAGE.format(key=key))
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("Attribute value must be a string or integer.")
        if isinstance(value, str) and not ATTR_VALUE_RE.fullmatch(value):
            raise ValueError("Attribute value may only contain letters, "
                             "digits, spaces and . , @ : / _ - (max 200).")
        old = attrs[username].get(key)
        if old == value:
            raise ValueError(f"{username}.{key} is already {value!r}.")
        record = dict(attrs[username])
        record[key] = value
        headline = (f"User {username}'s attribute {key} will change from "
                    f"{old!r} to {value!r}.")
        return self._user_change("set_attribute", actor, username, headline,
                                 before, attrs, record)

    @_proposal
    def propose_undo(self, actor=None, *, identity_channel=False) -> Change:
        """Revert the most recently applied change that is not undone yet.

        `identity_channel=True` is the HR / IdP channel (rbic-init
        import-users --undo): it only undoes a user_import, and may restore
        emails. The master bot never passes it, so it can undo an import
        only when no email differs."""
        entries = self._applied()
        undone = {e.get("undoes") for e in entries}
        candidates = [e for e in entries
                      if e.get("kind") != "undo" and e["id"] not in undone]
        if not candidates:
            raise ValueError("Nothing to undo.")
        last = candidates[-1]
        target = self._managed_path(last.get("file"))
        current = _read(target)
        if _sha(current) != last["after_sha256"]:
            raise ValueError(
                f"{target} changed since change {last['id']} was applied; "
                "undo manually.")
        restored = last["before_text"]
        if _sha(restored) != last["before_sha256"]:
            raise ValueError("Changelog entry is inconsistent; undo manually.")
        headline = (f"Undo change {last['id']} ({last['kind']}), restoring "
                    f"{target} to its previous content. Undone change was: "
                    + last["description"].splitlines()[0])
        if identity_channel and last.get("kind") != "user_import":
            raise ValueError(f"The last change ({last['id']}, {last['kind']}) "
                             "is not a user import; undo it with rbic-master.")
        if target == self.policy_path:
            if last.get("kind") != "generated_policy":
                self._check_undo_keeps_generated(current, restored)
            notes = ([SOURCES_NOT_REVERTED]
                     if last.get("kind") == "generated_policy" else [])
            change = self._policy_change("undo", actor, headline, current,
                                         restored, notes)
        elif target == self.schema_path:
            change = self._schema_change("undo", actor, headline, current,
                                         restored)
        elif last.get("kind") == "user_import":
            before_attrs, after_attrs = json.loads(current), json.loads(restored)
            if not identity_channel and self._identity_differs(before_attrs,
                                                               after_attrs):
                raise ValueError(
                    f"Change {last['id']} imported workers from the HR / IdP "
                    "export; undoing it would change emails, which only that "
                    "channel may do: run rbic-init import-users --undo (or "
                    "import a corrected export).")
            change = self._make("undo", actor, headline,
                                self._import_notes(before_attrs, after_attrs),
                                target, current, restored)
        else:
            before_attrs, after_attrs = json.loads(current), json.loads(restored)
            self._check_master_intact(before_attrs, after_attrs)
            notes = self._attrs_change_notes(self._enforcer(), self.schema(),
                                             before_attrs, after_attrs)
            change = self._make("undo", actor, headline, notes, target,
                                current, restored)
        change.undoes = last["id"]
        return change

    # ------------------------------------------------------------------
    # worker_attributes.json from the HR / IdP export (rbic-init import-users)
    # ------------------------------------------------------------------

    @staticmethod
    def _identity_differs(before: dict, after: dict) -> bool:
        for user in set(before) | set(after):
            for key in IDENTITY_ATTRIBUTES:
                b, a = before.get(user), after.get(user)
                if (b.get(key, _ABSENT) if isinstance(b, dict) else _ABSENT) != \
                        (a.get(key, _ABSENT) if isinstance(a, dict) else _ABSENT):
                    return True
        return False

    def _import_notes(self, before: dict, after: dict) -> list:
        """Validate a whole new worker_attributes.json from the HR / IdP
        channel and describe it per user - usernames, role names, column
        names and attribute NAMES only: never an email or attribute value
        (emails show as <email set> / <email changed> / <email removed>).

        Masters must be untouched; every non-master record must have valid
        keys and values; every user's row filters must bind with their
        real values; the result must load in the gate (email shape and
        uniqueness, user subjects naming existing workers)."""
        if not isinstance(after, dict) or not all(
                isinstance(r, dict) for r in after.values()):
            raise ValueError("Worker attributes must map username -> object.")
        self._check_master_intact(before, after)
        schema = self.schema()
        e = self._enforcer()
        for user, record in after.items():
            if record.get("role") == MASTER_ROLE:
                continue
            if not isinstance(user, str) or not USER_RE.fullmatch(user):
                raise ValueError("Invalid username in the import (letters, "
                                 "digits and _ . @ - only, at most 64).")
            for key, value in record.items():
                if key in IDENTITY_ATTRIBUTES:
                    continue  # shape + uniqueness: the gate's loader below
                if key == "role":
                    if not isinstance(value, str) or not ROLE_RE.fullmatch(value) \
                            or value == MASTER_ROLE:
                        raise ValueError(f"{user}: invalid role (never "
                                         "master; lowercase letters, digits, "
                                         "underscores).")
                    if value in after:
                        raise ValueError(f"{user}: role {value} is also a "
                                         "username; roles are groups.")
                    continue
                if not isinstance(key, str) or not ATTR_KEY_RE.fullmatch(key):
                    raise ValueError(f"{user}: invalid attribute name.")
                try:
                    self._check_attr_value(user, key, value)
                except ValueError:
                    raise ValueError(f"{user}.{key}: invalid attribute value "
                                     "(letters, digits, spaces and . , @ : / "
                                     "_ - only, at most 200; value not "
                                     "shown).") from None
        for user in sorted(after):
            try:
                self._check_all_users(e, after, schema, users={user})
            except ValueError:
                raise ValueError(
                    f"{user}: an attribute value cannot be used in a row "
                    "filter that applies to them (an unquoted placeholder "
                    "such as IN ({...}) needs a number or a comma-separated "
                    "list of numbers; values not shown).") from None
        after_s = self._snapshot(e, after, schema,
                                 "The policy with the imported workers")
        before_s = self._snapshot(e, before, schema)
        notes = []
        for user in sorted(set(before) | set(after)):
            old, new = before.get(user), after.get(user)
            if old == new:
                continue
            if new is None:
                notes.append(f"{user}: removed (loses all access)")
                continue
            bits = []
            role = new.get("role")
            if old is None:
                bits.append(f"new worker, role {role}" if role else
                            "new worker with NO role (unmapped: every "
                            "request is denied)")
            elif old.get("role") != role:
                bits.append(f"role {old.get('role') or 'none'} -> "
                            f"{role or 'NONE (unmapped: every request is denied)'}")
            had = old is not None and "email" in old
            if "email" in new and not had:
                bits.append("<email set>")
            elif "email" in new and old.get("email") != new["email"]:
                bits.append("<email changed>")
            elif had and "email" not in new:
                bits.append("<email removed>")
            keys_old = {k for k in (old or {}) if k not in ("role", "email")}
            keys_new = {k for k in new if k not in ("role", "email")}
            added = sorted(keys_new - keys_old)
            changed = sorted(k for k in keys_new & keys_old if old[k] != new[k])
            removed = sorted(keys_old - keys_new)
            for label, keys in (("attributes set", added),
                                ("attributes changed", changed),
                                ("attributes removed", removed)):
                if keys:
                    bits.append(f"{label}: {', '.join(keys)}")
            if old is not None:
                diff = self._column_diff(
                    before_s.effective_columns(user, schema),
                    after_s.effective_columns(user, schema))
                for table, gained, lost in diff:
                    if gained:
                        bits.append(f"gains read on {table}.({', '.join(gained)})")
                    if lost:
                        bits.append(f"loses read on {table}.({', '.join(lost)})")
            for table, keys in self._missing_for_user(after_s, user).items():
                bits.append(f"WARNING: lacks attribute(s) {', '.join(keys)}, so "
                            f"their queries on {table} that the rule needing "
                            "it covers will be denied")
            notes.append(f"{user}: " + "; ".join(bits))
        return notes

    @_proposal
    def propose_user_import(self, attributes: dict, actor=None, *,
                            headline: Optional[str] = None,
                            extra_notes=()) -> Change:
        """Replace worker_attributes.json with `attributes` (the result of
        rbic.onboarding.users.plan_import: the HR / IdP export applied to
        the current file). The only proposal that may set or change emails;
        masters must be untouched. Validated like every change (gate loader
        in both dialects, every user's filters bound, input hashes, lock,
        changelog before replace, undo). The description never holds an
        email or attribute value."""
        before = _read(self.attributes_path)
        current = json.loads(before)
        notes = self._import_notes(current, attributes)
        nl = _newline(before)
        after = json.dumps(attributes, indent=2).replace("\n", nl) + nl
        if after == before:
            raise ValueError("worker_attributes.json already matches this "
                             "import; nothing to change.")
        if headline is None:
            headline = (f"Import {len(attributes)} worker record(s) from the "
                        "HR / IdP export into worker_attributes.json.")
        return self._make("user_import", actor, headline,
                          [*extra_notes, *notes], self.attributes_path,
                          before, after)

    # ------------------------------------------------------------------
    # the rbic-init block (rbic-init compile)
    # ------------------------------------------------------------------

    @_proposal
    def propose_generated_policy(self, generated, actor=None) -> Change:
        """Replace policy.csv's rbic-init block with `generated` (an
        rbic.onboarding.compile.GeneratedPolicy from compile_from_files).

        Lines outside the block are kept byte for byte. Refused when any
        source the compile read (catalog.json, roles.json, db_schema.json,
        worker_attributes.json) changed since - and, through the Change's
        input hashes, again at apply time - when the block markers are
        malformed, and (like every proposal) when the result would not
        load in the gate or a user's row filters would not bind.
        """
        # Imported here: rbic.onboarding.compile imports this module.
        from .onboarding.compile import build_policy_text, sources_current
        if self.onboarding_dir is None:
            raise ValueError("This PolicyAdmin has no onboarding directory.")
        extra = {"catalog": os.path.join(self.onboarding_dir,
                                         CATALOG_FILE.name),
                 "roles": os.path.join(self.onboarding_dir, ROLES_FILE.name)}
        hashes = self._input_hashes(extra)
        if not sources_current(generated, {**extra,
                                           "schema": self.schema_path,
                                           "attributes": self.attributes_path}):
            raise ValueError("The onboarding sources (catalog.json, roles.json, "
                             "db_schema.json or worker_attributes.json) "
                             "changed since this policy was compiled; run "
                             "rbic-init compile again.")
        before = _read(self.policy_path)
        try:
            after, notes = build_policy_text(before, generated)
        except BlockError as err:
            raise ValueError(f"policy.csv: {err}. Fix the rbic-init markers by "
                             "hand, then compile again.") from None
        if after == before:
            raise ValueError("policy.csv already holds exactly this compiled "
                             "policy; nothing to change.")
        n = sum(1 for line in generated.body if not line.startswith("#"))
        headline = (f"Replace the rbic-init block of policy.csv with {n} "
                    f"rule(s) for {len(generated.roles)} role(s) compiled from "
                    "onboarding/catalog.json and roles.json; lines outside "
                    "the block are unchanged.")
        change = self._policy_change(
            "generated_policy", actor, headline, before, after,
            [*(f"compile: {a}" for a in generated.acknowledged),
             *(f"compile: {w}" for w in (*notes, *generated.warnings))])
        change.extra_inputs = extra
        change.input_hashes = {k: v for k, v in hashes.items()
                               if k.startswith("extra:")}
        return change

    # ------------------------------------------------------------------
    # db_schema.json (rbic-init schema; validated like every other change)
    # ------------------------------------------------------------------

    @_proposal
    def propose_schema_update(self, schema, actor=None) -> Change:
        """Replace db_schema.json with `schema` ({table: {column: type}},
        written in the given order).

        Refused when the gate would refuse the result (a row filter or
        column deny naming a removed column, a malformed schema...) and
        when any p/p3/p2/p4 rule names a table or table.column the new
        schema removes: a grant left pointing at a vanished column would
        silently come back to life if a column of that name reappeared.
        """
        try:
            schema = check_schema(schema)
        except ValueError as err:
            raise ValueError(f"Invalid schema: {err}") from None
        before = _read(self.schema_path)
        nl = _newline(before)
        after = json.dumps(schema, indent=2).replace("\n", nl) + nl
        if after == before:
            raise ValueError("db_schema.json already matches; nothing to "
                             "change.")
        headline = (f"db_schema.json will describe {len(schema)} table(s) "
                    "as shown in the diff.")
        return self._schema_change("schema_update", actor, headline, before,
                                   after)

    @staticmethod
    def _schema_refs(e: casbin.Enforcer) -> list:
        """[(rule, table, column|None)] for every table.column a p/p3 rule
        names and every table a p2/p4 rule filters (column None)."""
        refs = []
        for ptype in COLUMN_PTYPES:
            for rule in e.get_named_policy(ptype):
                table, _, column = rule[1].partition(".")
                refs.append(([ptype, *rule], table, column))
        for ptype in ROW_PTYPES:
            for rule in e.get_named_policy(ptype):
                refs.append(([ptype, *rule], rule[1], None))
        return refs

    @classmethod
    def _check_schema_refs(cls, e: casbin.Enforcer, old: dict, new: dict,
                           notes: Optional[list] = None) -> None:
        """Refuse a schema that removes a table/column a rule names (while
        the old schema had it); note rules that name something only the
        new schema has (they take effect with this change)."""
        def has(schema, table, column):
            if table not in schema:
                return False
            return column in (None, "*") or column in schema[table]

        broken = []
        for rule, table, column in cls._schema_refs(e):
            if "*" in table:  # a glob over table names: nothing to resolve
                continue
            name = table if column in (None, "*") else f"{table}.{column}"
            line = ", ".join(rule)
            if has(old, table, column) and not has(new, table, column):
                broken.append(f"{name} (rule: {line})")
            elif notes is not None and not has(old, table, column) \
                    and has(new, table, column):
                notes.append(f"WARNING: the existing rule '{line}' names "
                             f"{name}, which did not exist before; it takes "
                             "effect with this change")
        if broken:
            raise ValueError(
                "The new schema removes table(s)/column(s) that policy rules "
                "still reference: " + "; ".join(broken) + ". Remove or "
                "revoke those rules first (rbic-master; for rules in the "
                "rbic-init block: update onboarding/*.json and run rbic-init "
                "compile), then update the schema.")

    def _schema_change(self, kind, actor, headline, before, after) -> Change:
        try:
            old = check_schema(json.loads(before))
            new = check_schema(json.loads(after))
        except ValueError as err:  # json.JSONDecodeError is a ValueError
            raise ValueError(f"Invalid schema: {err}") from None
        e = self._enforcer()
        attrs = self.attributes()
        notes = diff_schema(old, new).lines(new)
        self._check_schema_refs(e, old, new, notes)
        before_s = self._snapshot(e, attrs, old)
        after_s = self._snapshot(e, attrs, new,
                                 "The policy with the new db_schema.json")
        self._check_all_users(e, attrs, new)
        for role in sorted(self._roles(e)):
            diff = self._column_diff(self._readable(before_s, role, old),
                                     self._readable(after_s, role, new))
            users = sorted(u for u, a in attrs.items() if a.get("role") == role)
            who = f" [users: {', '.join(users)}]" if users else ""
            for table, gained, lost in diff:
                if gained:
                    notes.append(
                        f"WARNING: {role}{who} can read {table}."
                        f"({', '.join(gained)}) immediately through an "
                        "existing grant (e.g. a table.* wildcard)")
                if lost:
                    notes.append(f"{role}{who}: loses read on {table}."
                                 f"({', '.join(lost)}) (removed)")
        for user in sorted(attrs):
            if attrs[user].get("role") == MASTER_ROLE or not any(
                    self._personal(after_s, user).values()):
                continue
            diff = self._column_diff(before_s.effective_columns(user, old),
                                     after_s.effective_columns(user, new))
            for table, gained, lost in diff:
                if gained:
                    notes.append(f"WARNING: {user} (has personal rules) can "
                                 f"read {table}.({', '.join(gained)}) "
                                 "immediately")
                if lost:
                    notes.append(f"{user}: loses read on {table}."
                                 f"({', '.join(lost)}) (removed)")
        if not notes:
            notes.append("no table, column or access change (formatting "
                         "only)")
        return self._make(kind, actor, headline, notes, self.schema_path,
                          before, after)

    def _managed_path(self, path) -> str:
        for p in (self.policy_path, self.attributes_path, self.schema_path):
            if path and os.path.abspath(path) == os.path.abspath(p):
                return p
        raise ValueError(f"Changelog refers to unmanaged file {path!r}.")

    # ------------------------------------------------------------------
    # apply (the only method that writes)
    # ------------------------------------------------------------------

    def apply(self, change: Change, actor: str) -> None:
        with self._apply_lock():
            self._apply_locked(change, actor)
        logger.info(
            "POLICY_CHANGE id=%s actor=%s kind=%s file=%s after_sha256=%s desc=%r",
            change.id, actor, change.kind, change.target,
            _sha(change.after_text), change.description.splitlines()[0],
        )

    def _apply_locked(self, change: Change, actor: str) -> None:
        attrs = self.attributes()
        if attrs.get(actor, {}).get("role") != MASTER_ROLE:
            raise ValueError(f"{actor!r} is not a master user.")
        target = self._managed_path(change.target)
        # The proposal's analysis (effects, scope checks, description) was
        # computed from ALL of these files; any change invalidates it.
        if not change.input_hashes or \
                self._input_hashes(change.extra_inputs) != change.input_hashes:
            raise ValueError(STALE_MESSAGE + "; nothing was written.")
        current = _read(target)
        if _sha(current) != _sha(change.before_text):
            raise ValueError(STALE_MESSAGE + "; nothing was written.")
        directory = os.path.dirname(os.path.abspath(target))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_",
                                   suffix=os.path.splitext(target)[1])
        entry = {
            "id": change.id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "kind": change.kind,
            "description": change.description,
            "file": target,
            "before_sha256": _sha(change.before_text),
            "after_sha256": _sha(change.after_text),
            "before_text": change.before_text,
            "after_text": change.after_text,
            "status": "applying",
        }
        if change.undoes:
            entry["undoes"] = change.undoes
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(change.after_text)
                f.flush()
                os.fsync(f.fileno())
            # Same loader as the gate, over the exact bytes about to go
            # live (the input-hash check above pinned every other file).
            self._check_gate_loads(change)
            if target == self.policy_path:
                self._check_no_master_in_policy(
                    load_enforcer(_read_bytes(self.model_path),
                                  change.after_text.encode("utf-8")))
            elif target == self.schema_path:
                self._check_schema_refs(self._enforcer(),
                                        json.loads(change.before_text),
                                        json.loads(change.after_text))
            else:
                self._check_master_intact(attrs, json.loads(change.after_text))
            # The audit record goes down BEFORE the file changes, so a live
            # change can never lack an audit entry.
            self._append_log(entry)
            try:
                os.replace(tmp, target)
            except Exception as err:
                self._append_log({
                    "id": change.id,
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "actor": actor, "kind": change.kind, "file": target,
                    "status": f"failed: {type(err).__name__}: {err}",
                })
                raise
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        change.actor = actor
        try:
            self._append_log(dict(entry, status="applied",
                                  ts=datetime.now(timezone.utc).isoformat()))
        except OSError as err:
            # The change IS live and its "applying" record exists; don't
            # report it as not applied.
            logger.error("POLICY_CHANGE_LOG_FAILED id=%s status=applied err=%s",
                         change.id, err)
