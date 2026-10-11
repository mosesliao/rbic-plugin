"""Pure-Python policy editor behind the master chatbot.

Every change is a two-step affair: a propose_* method validates the
request and returns a Change (the exact before/after file text) without
touching disk; apply() writes it only if the file is still exactly what
the proposal was computed against. The LLM never calls apply() — the
human confirms each Change in code (see master_bot.py).

Fail-closed rules:
- unknown tables/columns/roles/users, malformed names      -> reject
- anything touching the "master" role or a master user      -> reject
- row-filter templates with subqueries, table references,
  functions outside a small allowlist, or foreign columns   -> reject
- row-filter templates with non-printable/non-ASCII text,
  SQL comments, or a non-predicate / always-true shape      -> reject
- ANY input file (policy, attributes, schema, model)
  changed since the proposal                                -> reject
- resulting policy.csv doesn't load in a fresh Enforcer     -> reject

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
import logging
import os
import re
import string
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import casbin
import sqlglot
from casbin.persist.adapter import load_policy_line

from sql_gate import (
    STATIC_FILTER_WARNING, FilterError, MissingAttribute, bind_row_filter,
    compile_row_filter,
)

logger = logging.getLogger("rbic.audit")

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
LOCK_NAME = ".policy.lock"
LOCK_TIMEOUT_S = 10.0
FILTER_DIALECTS = ("postgres", "sqlite")


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


def _proposal(method):
    """Record input-file hashes around a propose_* call.

    If any input changed while the proposal was being computed, its
    analysis may be inconsistent, so it is refused outright.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        before = self._input_hashes()
        change = method(self, *args, **kwargs)
        if self._input_hashes() != before:
            raise ValueError(STALE_MESSAGE + ".")
        change.input_hashes = before
        return change
    return wrapper


class _Ast:
    def __init__(self):
        self.policy = []


class _ShimModel:
    def __init__(self):
        self.model = {"p": {"p": _Ast(), "p2": _Ast()}, "g": {"g": _Ast()}}


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


class PolicyAdmin:
    def __init__(
        self,
        policy_path: str = "casbin/policy.csv",
        attributes_path: str = "worker_attributes.json",
        schema_path: str = "db_schema.json",
        model_path: str = "casbin/model.conf",
        changelog_path: str = "policy_changes.jsonl",
    ):
        self.policy_path = policy_path
        self.attributes_path = attributes_path
        self.schema_path = schema_path
        self.model_path = model_path
        self.changelog_path = changelog_path

    # ------------------------------------------------------------------
    # state loading
    # ------------------------------------------------------------------

    def schema(self) -> dict:
        with open(self.schema_path, encoding="utf-8") as f:
            return json.load(f)

    def attributes(self) -> dict:
        return json.loads(_read(self.attributes_path))

    def _input_hashes(self) -> dict:
        """sha256 of every file a proposal's analysis depends on."""
        out = {}
        for name, path in (("policy", self.policy_path),
                           ("attributes", self.attributes_path),
                           ("schema", self.schema_path),
                           ("model", self.model_path)):
            with open(path, "rb") as f:
                out[name] = hashlib.sha256(f.read()).hexdigest()
        return out

    def _lock_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(self.policy_path)),
                            LOCK_NAME)

    @contextlib.contextmanager
    def _apply_lock(self, timeout: Optional[float] = None):
        """Inter-process lock: O_CREAT|O_EXCL lock file, always removed."""
        path = self._lock_path()
        deadline = time.monotonic() + (LOCK_TIMEOUT_S if timeout is None
                                       else timeout)
        while True:
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise ValueError(
                        "Another policy change is being applied; nothing was "
                        "written. Try again (if no change is in progress, "
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

    def _enforcer(self, policy_text: Optional[str] = None) -> casbin.Enforcer:
        if policy_text is None:
            return casbin.Enforcer(self.model_path, self.policy_path)
        fd, tmp = tempfile.mkstemp(suffix=".csv")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write(policy_text)
            return casbin.Enforcer(self.model_path, tmp)
        finally:
            os.remove(tmp)

    @staticmethod
    def _roles(e: casbin.Enforcer) -> set:
        roles = {r[0] for r in e.get_policy()}
        roles |= {r[0] for r in e.get_named_policy("p2")}
        for child, parent, *_ in e.get_grouping_policy():
            roles |= {child, parent}
        return roles

    @staticmethod
    def _all_roles_of(e: casbin.Enforcer, role: str) -> set:
        return {role, *e.get_implicit_roles_for_user(role)}

    def _scopes(self, e: casbin.Enforcer, role: str) -> dict:
        """table -> [templates], mirroring SQLGate._filters_for_role."""
        roles = self._all_roles_of(e, role)
        out: dict = {}
        for sub, table, template in e.get_named_policy("p2"):
            if sub in roles:
                out.setdefault(table, []).append(template)
        return out

    def _readable(self, e: casbin.Enforcer, role: str, schema: dict) -> dict:
        out = {}
        for table, cols in schema.items():
            allowed = [c for c in cols if e.enforce(role, f"{table}.{c}", READ)]
            if allowed:
                out[table] = allowed
        return out

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
        inherited = sorted(e.get_implicit_roles_for_user(role))
        roles = self._all_roles_of(e, role)
        return {
            "role": role,
            "direct_grants": sorted(p[1] for p in e.get_policy() if p[0] == role),
            "inherits_directly": sorted(e.get_roles_for_user(role)),
            "inherited_roles": inherited,
            "inherited_grants": {
                r: sorted(p[1] for p in e.get_policy() if p[0] == r)
                for r in inherited
            },
            "effective_read": self._readable(e, role, self.schema()),
            "row_scopes": [
                {"table": t, "filter": f, "from_role": s}
                for s, t, f in e.get_named_policy("p2") if s in roles
            ],
            "users": sorted(u for u, a in self.attributes().items()
                            if a.get("role") == role),
        }

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
        scopes = self._scopes(e, role)
        info["effective_read"] = self._readable(e, role, self.schema())
        info["row_scopes"] = {t: " OR ".join(f"({x})" for x in fs)
                              for t, fs in scopes.items()}
        missing = self._missing_placeholders(scopes, record)
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
        if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
            raise ValueError(f"Invalid {what} name {role!r}: use lowercase "
                             "letters, digits and underscores (2-41 chars).")
        if role == MASTER_ROLE:
            raise ValueError("The 'master' role cannot be used in access "
                             "policy - it manages policy and has no data access.")

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
        column-vs-value predicates, no tautologies (see sql_gate).
        """
        if not isinstance(template, str) or not template.strip():
            raise ValueError("Filter template must be a non-empty string.")
        template = template.strip()
        for dialect in FILTER_DIALECTS:
            compiled = compile_row_filter(table, template, schema, dialect,
                                          strict=True)
        return template, compiled

    @staticmethod
    def _missing_placeholders(scopes: dict, record: dict) -> dict:
        missing = {}
        for table, templates in scopes.items():
            need = set()
            for t in templates:
                need |= {f for _, f, _, _ in string.Formatter().parse(t)
                         if f and f not in record}
            if need:
                missing[table] = sorted(need)
        return missing

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
        """Bind the user's row filters with their real attribute values.

        The gate binds values as literal AST nodes, so a value can never
        change a filter's structure; this is defense in depth that also
        keeps bindings meaningful. Every bound value must pass
        ATTR_VALUE_RE, and a value bound into an UNQUOTED placeholder must
        be a number (inside IN (...): a comma-separated list of numbers),
        so e.g. "1, employee_id" is refused rather than silently matching
        a string.
        """
        for table, templates in self._scopes(e, role).items():
            for t in templates:
                for dialect in FILTER_DIALECTS:
                    try:
                        rf = compile_row_filter(table, t, schema, dialect)
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
            if role == MASTER_ROLE:
                continue
            if not isinstance(role, str):
                raise ValueError(f"User {user!r} has no role.")
            self._check_rendered_scopes(e, role, record, schema, user)

    def _check_gate_loads(self, e, schema: dict):
        """Every p2 rule must compile in the gate, or the gate fails closed."""
        for rule in e.get_named_policy("p2"):
            if len(rule) != 3:
                raise ValueError(f"Malformed row filter rule {rule!r}.")
            sub, table, template = rule
            for dialect in FILTER_DIALECTS:
                try:
                    compile_row_filter(table, template, schema, dialect)
                except FilterError as err:
                    raise ValueError(
                        f"Resulting policy has a row filter the SQL gate "
                        f"would refuse to load (p2, {sub}, {table}, "
                        f"{template}): {err}") from None

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
    def _remove_line(text: str, fields: list) -> str:
        lines = _lines(text)
        kept = [l for l in lines if _casbin_tokens(l) != fields]
        if len(kept) == len(lines):
            raise ValueError("No such rule in policy.csv.")
        return "".join(kept)

    def _rules(self, text: str) -> list:
        return [t for t in map(_casbin_tokens, _lines(text)) if t]

    # ------------------------------------------------------------------
    # effect summaries (what actually changes, computed not guessed)
    # ------------------------------------------------------------------

    def _policy_effects(self, before_e, after_e, schema) -> list:
        attrs = self.attributes()
        notes = []
        for role in sorted(self._roles(before_e) | self._roles(after_e)):
            rb = self._readable(before_e, role, schema)
            ra = self._readable(after_e, role, schema)
            sb = self._scopes(before_e, role)
            sa = self._scopes(after_e, role)
            bits = []
            for table in sorted(set(rb) | set(ra)):
                gained = [c for c in ra.get(table, []) if c not in rb.get(table, [])]
                lost = [c for c in rb.get(table, []) if c not in ra.get(table, [])]
                if gained:
                    bits.append(f"gains read on {table}.({', '.join(gained)})")
                if lost:
                    bits.append(f"loses read on {table}.({', '.join(lost)})")
            for table in sorted(set(sb) | set(sa)):
                before_s, after_s = sb.get(table, []), sa.get(table, [])
                if sorted(before_s) == sorted(after_s):
                    continue
                if not after_s and table in ra:
                    bits.append(f"WARNING: row filter on {table} removed - "
                                f"ALL rows of {table} become visible")
                elif after_s:
                    # same-table scopes OR together: more scopes = more rows
                    widened = bool(before_s) and set(before_s) < set(after_s)
                    label = "WIDENED to" if widened else "limited to"
                    bits.append(f"rows of {table} {label}: "
                                + " OR ".join(f"({s})" for s in after_s))
            for table in sorted(ra):
                if table not in sa and table not in rb:
                    bits.append(f"no row filter on {table} - all rows visible")
            if bits:
                users = sorted(u for u, a in attrs.items() if a.get("role") == role)
                who = f" [users: {', '.join(users)}]" if users else ""
                notes.append(f"{role}{who}: " + "; ".join(bits))
        return notes

    def _missing_attr_warnings(self, e, roles) -> list:
        warnings = []
        for user, record in sorted(self.attributes().items()):
            if record.get("role") not in roles:
                continue
            for table, keys in self._missing_placeholders(
                    self._scopes(e, record["role"]), record).items():
                warnings.append(
                    f"WARNING: {user} lacks attribute(s) {', '.join(keys)}, so "
                    f"all of their queries on {table} will be denied.")
        return warnings

    def _policy_change(self, kind, actor, headline, before, after,
                       extra_notes=()) -> Change:
        schema = self.schema()
        before_e = self._enforcer(before)
        after_e = self._enforcer(after)
        self._check_no_master_in_policy(after_e)
        self._check_gate_loads(after_e, schema)
        # Defense in depth: every user's filters must bind cleanly with
        # their real attribute values under the NEW policy.
        self._check_all_users(after_e, self.attributes(), schema)
        effects = self._policy_effects(before_e, after_e, schema)
        changed_roles = {n.split(" ", 1)[0].rstrip(":") for n in effects}
        notes = [*extra_notes, *effects,
                 *self._missing_attr_warnings(after_e, changed_roles)]
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

    @_proposal
    def propose_grant(self, role, table, column, actor=None) -> Change:
        schema = self.schema()
        self._check_role_name(role)
        self._check_table(table, schema)
        self._check_column(table, column, schema)
        obj = f"{table}.{column}"
        before = _read(self.policy_path)
        fields = ["p", role, obj, READ]
        if fields in self._rules(before):
            raise ValueError(f"Grant already present: p, {role}, {obj}, read")
        after = self._add_line(before, fields)
        e = self._enforcer()
        new = "" if role in self._roles(e) else " (new role)"
        scopes = self._scopes(e, role).get(table)
        rows = (f"only rows matching its row filter on {table}: "
                + " OR ".join(f"({s})" for s in scopes)) if scopes \
            else f"ALL rows of {table} - no row filter applies"
        what = f"every column of {table}" if column == "*" else obj
        headline = f"Role {role}{new} will be able to read {what} ({rows})."
        return self._policy_change("grant", actor, headline, before, after)

    @_proposal
    def propose_revoke(self, role, table, column, actor=None) -> Change:
        schema = self.schema()
        self._check_role_name(role)
        self._check_table(table, schema)
        self._check_column(table, column, schema)
        obj = f"{table}.{column}"
        before = _read(self.policy_path)
        fields = ["p", role, obj, READ]
        if fields not in self._rules(before):
            raise ValueError(self._explain_missing_grant(role, obj))
        after = self._remove_line(before, fields)
        headline = f"Role {role} will lose its direct grant on {obj}."
        return self._policy_change("revoke", actor, headline, before, after)

    def _explain_missing_grant(self, role, obj) -> str:
        e = self._enforcer()
        msg = f"There is no rule 'p, {role}, {obj}, read' to remove."
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
    def propose_row_scope(self, role, table, filter_template, actor=None) -> Change:
        schema = self.schema()
        self._check_role_name(role)
        self._check_table(table, schema)
        template, compiled = self._check_filter(table, filter_template, schema)
        before = _read(self.policy_path)
        fields = ["p2", role, table, template]
        if fields in self._rules(before):
            raise ValueError(f"Row filter already present: p2, {role}, "
                             f"{table}, {template}")
        after = self._add_line(before, fields)
        before_e, after_e = self._enforcer(before), self._enforcer(after)
        existing = self._scopes(before_e, role).get(table)
        if existing:
            headline = (f"Role {role} gets an additional row scope on {table}: "
                        f"{template}. Same-table scopes are OR-combined, so "
                        "this WIDENS what it sees (existing: "
                        + " OR ".join(f"({s})" for s in existing) + ").")
        else:
            headline = (f"Role {role} will only see rows of {table} where "
                        f"{template}.")
        # Roles inheriting `role`: the same before/after scope diff the
        # effect notes use decides whether each is narrowed or widened.
        heirs = sorted(r for r in self._roles(after_e)
                       if r != role and role in self._all_roles_of(after_e, r))
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
    def propose_remove_row_scope(self, role, table, filter_template,
                                 actor=None) -> Change:
        schema = self.schema()
        self._check_role_name(role)
        self._check_table(table, schema)
        if not isinstance(filter_template, str):
            raise ValueError("Filter template must be a string.")
        template = filter_template.strip()
        before = _read(self.policy_path)
        fields = ["p2", role, table, template]
        if fields not in self._rules(before):
            current = [r[3] for r in self._rules(before)
                       if r[:3] == ["p2", role, table] and len(r) == 4]
            raise ValueError(
                f"No row filter 'p2, {role}, {table}, {template}'. Current "
                f"filters for {role} on {table}: {current or 'none'}"
                " (inherited filters must be removed from their own role).")
        after = self._remove_line(before, fields)
        headline = f"Role {role} will lose the row filter on {table}: {template}."
        return self._policy_change("remove_row_scope", actor, headline,
                                   before, after)

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
        headline = (f"Role {role} will inherit all grants AND row filters of "
                    f"{parent_role}.")
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
        headline = (f"Role {role} will no longer inherit grants or row "
                    f"filters from {parent_role}.")
        return self._policy_change("remove_inherit", actor, headline,
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

    def _user_notes(self, e, schema, old: dict, new: dict) -> list:
        """Effect of one user's record changing from `old` to `new`."""
        old_role, new_role = old.get("role"), new.get("role")
        rb = self._readable(e, old_role, schema) if isinstance(old_role, str) else {}
        ra = self._readable(e, new_role, schema) if isinstance(new_role, str) else {}
        sa = self._scopes(e, new_role) if isinstance(new_role, str) else {}
        notes = []
        for table in sorted(set(rb) | set(ra)):
            gained = [c for c in ra.get(table, []) if c not in rb.get(table, [])]
            lost = [c for c in rb.get(table, []) if c not in ra.get(table, [])]
            if gained:
                notes.append(f"gains read on {table}.({', '.join(gained)})")
            if lost:
                notes.append(f"loses read on {table}.({', '.join(lost)})")
        for table, fs in sa.items():
            names = {f for t in fs for _, f, _, _ in string.Formatter().parse(t) if f}
            changed = sorted(n for n in names if old.get(n) != new.get(n))
            if changed or old_role != new_role:
                note = (f"rows of {table} limited to: "
                        + " OR ".join(f"({s})" for s in fs))
                if changed:
                    note += " with " + ", ".join(
                        f"{n}={new.get(n)!r} (was {old.get(n)!r})"
                        for n in changed)
                notes.append(note)
        for table in sorted(ra):
            if table not in sa and old_role != new_role:
                notes.append(f"no row filter on {table} - all rows visible")
        for table, keys in self._missing_placeholders(sa, new).items():
            notes.append(f"WARNING: lacks attribute(s) {', '.join(keys)}, so "
                         f"all of their queries on {table} will be denied")
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
            record = after.get(user)
            if record is None:
                continue
            if not USER_RE.fullmatch(user) or not isinstance(record, dict):
                raise ValueError(f"Invalid user record {user!r}.")
            for key, value in record.items():
                if key == "role":
                    continue
                if not ATTR_KEY_RE.fullmatch(key):
                    raise ValueError(f"Invalid attribute name {user}.{key!r}.")
                self._check_attr_value(user, key, value)
        self._check_all_users(e, after, schema, users=set(changed))
        notes = []
        for user in changed:
            old = before.get(user) or {"role": None}
            new = after.get(user) or {"role": None}
            notes += [f"{user}: {n}" for n in self._user_notes(e, schema, old, new)]
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
    def propose_undo(self, actor=None) -> Change:
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
        if target == self.policy_path:
            change = self._policy_change("undo", actor, headline, current,
                                         restored)
        else:
            before_attrs, after_attrs = json.loads(current), json.loads(restored)
            self._check_master_intact(before_attrs, after_attrs)
            notes = self._attrs_change_notes(self._enforcer(), self.schema(),
                                             before_attrs, after_attrs)
            change = self._make("undo", actor, headline, notes, target,
                                current, restored)
        change.undoes = last["id"]
        return change

    def _managed_path(self, path) -> str:
        for p in (self.policy_path, self.attributes_path):
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
        if not change.input_hashes or self._input_hashes() != change.input_hashes:
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
            if target == self.policy_path:
                self._check_no_master_in_policy(
                    casbin.Enforcer(self.model_path, tmp))
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
