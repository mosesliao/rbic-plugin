"""Master chatbot: natural-language access-policy management.

The LLM is untrusted here too. It can inspect policy and PROPOSE changes
through tools, but no tool applies anything. After each turn the code
prints every proposed change (plain-English effect + unified diff of the
real file) and applies it only if the human answers yes/y (case-insensitive;
no/n declines, anything else re-asks, EOF/Ctrl-C declines).
Validation, master protections and the atomic write all live in
rbic.admin.PolicyAdmin. This bot has no path to business data.

This module is I/O-free: the confirm flow takes input/output callables
and the interactive loop lives in rbic.cli.master. Tool output sent to the
LLM never contains a worker's email address (see redact_emails).
"""

import json
import re

from .admin import MASTER_ROLE, PolicyAdmin
from .audit import logger as audit
from .config import DEFAULT_MODEL

MODEL = DEFAULT_MODEL
MAX_TOOL_TURNS = 8
AWAITING = "Awaiting the human's confirmation; do not claim it is applied."
YES = frozenset({"yes", "y"})
NO = frozenset({"no", "n"})
REASK = "Please type yes or no."
CONFIRM_RULE = (
    "- After your reply, code (not you) asks the human to type yes or no for\n"
    "  each proposed change. Never claim a change was applied before a\n"
    "  [Code note] says it was APPLIED. If the human asks you to \"apply\" in\n"
    "  chat, explain that you cannot apply changes yourself and offer to\n"
    "  re-propose it so they can answer yes at the prompt.")

EMAIL_SET, EMAIL_NOT_SET, EMAIL_REDACTED = "<set>", "<not set>", "<email>"


def _tool(name, description, optional=(), **props):
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": {
                k: {"type": t, "description": d} for k, (t, d) in props.items()
            },
            "required": [p for p in props if p not in optional],
        },
    }


ROLE = ("string", "Casbin role name, e.g. hr_staff.")
TABLE = ("string", "Table name exactly as listed.")
COLUMN = ("string", "Column name exactly as listed, or '*' for every column.")
FILTER = ("string", "SQL condition on that table's own columns; "
                    "{attribute} placeholders bind worker attributes, "
                    "e.g. dept = '{dept}'. Only comparisons of a column with "
                    "a value (=, <>, <, >, IN, IS, LIKE, BETWEEN) combined "
                    "with AND/OR/NOT; plain ASCII, no SQL comments.")
USER = ("string", "Username, e.g. bob.")
COLUMNS = ("string", "Optional. Comma-separated column names of that table, "
                     "e.g. 'id, name, salary'. If given, the rule is a SCOPED "
                     "GRANT: the subject may read exactly these columns for "
                     "the rows matching the filter, with no separate grant "
                     "needed, but only in queries that use no other column of "
                     "the table. It never narrows existing access. Without "
                     "columns, the rule is a plain row filter that limits "
                     "every query the subject makes on the table.")
DENY_COLUMNS = ("string", "Optional. Comma-separated column names. If given, "
                          "the rows are hidden only from queries that read one "
                          "of these columns; without it, from every query on "
                          "the table.")
SUBJECT_ROLE = ("string", "The role (a group of workers), e.g. hr_staff. Give "
                          "EITHER role OR username, never both.")
SUBJECT_USER = ("string", "The username (one person), e.g. alice, for a "
                          "PERSONAL rule that overrides their role's rules. "
                          "Give EITHER role OR username, never both.")
EITHER = ("role", "username")

TOOLS = [
    _tool("list_roles", "List every role with what it inherits and its users."),
    _tool("list_tables", "List every table and its columns."),
    _tool("describe_role", "Show a role's direct and inherited grants, column "
                           "denies, effective readable columns, row filters "
                           "and hidden rows.", role=ROLE),
    _tool("describe_user", "Show a user's role, extra roles, attributes, "
                           "personal rules and effective access after "
                           "precedence.", username=USER),
    _tool("show_history", "Show recently applied policy changes.",
          optional=("limit",), limit=("integer", "How many entries (default 10).")),
    _tool("propose_grant", "Propose letting a role (or, with username, one "
                           "person) read table.column.",
          optional=EITHER, role=SUBJECT_ROLE, username=SUBJECT_USER,
          table=TABLE, column=COLUMN),
    _tool("propose_revoke", "Propose removing a role's (or a person's) direct "
                            "grant on table.column.",
          optional=EITHER, role=SUBJECT_ROLE, username=SUBJECT_USER,
          table=TABLE, column=COLUMN),
    _tool("propose_deny", "Propose DENYING a role (or one person) read on "
                          "table.column. A role deny is overridden only by a "
                          "personal allow; a personal deny beats everything.",
          optional=EITHER, role=SUBJECT_ROLE, username=SUBJECT_USER,
          table=TABLE, column=COLUMN),
    _tool("propose_remove_deny", "Propose removing a column deny.",
          optional=EITHER, role=SUBJECT_ROLE, username=SUBJECT_USER,
          table=TABLE, column=COLUMN),
    _tool("propose_row_scope", "Propose a row filter limiting which rows of a "
                               "table a role (or one person) sees, or (with "
                               "columns) a scoped grant: specific columns for "
                               "specific rows in one rule.",
          optional=(*EITHER, "columns"), role=SUBJECT_ROLE,
          username=SUBJECT_USER, table=TABLE, filter_template=FILTER,
          columns=COLUMNS),
    _tool("propose_remove_row_scope", "Propose removing a row filter or scoped "
                                      "grant (use the exact filter text, and "
                                      "the exact columns for a scoped grant).",
          optional=(*EITHER, "columns"), role=SUBJECT_ROLE,
          username=SUBJECT_USER, table=TABLE, filter_template=FILTER,
          columns=COLUMNS),
    _tool("propose_deny_rows", "Propose HIDING the rows of a table matching "
                               "the filter from a role (or one person), "
                               "whatever other rules allow.",
          optional=(*EITHER, "columns"), role=SUBJECT_ROLE,
          username=SUBJECT_USER, table=TABLE, filter_template=FILTER,
          columns=DENY_COLUMNS),
    _tool("propose_remove_deny_rows", "Propose removing a row deny (exact "
                                      "filter text and columns).",
          optional=(*EITHER, "columns"), role=SUBJECT_ROLE,
          username=SUBJECT_USER, table=TABLE, filter_template=FILTER,
          columns=DENY_COLUMNS),
    _tool("propose_inherit", "Propose that role inherits all grants, row "
                             "filters and denies of parent_role.",
          role=ROLE, parent_role=("string", "Existing role to inherit from.")),
    _tool("propose_remove_inherit", "Propose removing a direct inheritance.",
          role=ROLE, parent_role=("string", "Role currently inherited.")),
    _tool("propose_assign_role", "Propose changing a user's own (main) role.",
          username=USER, role=ROLE),
    _tool("propose_add_user_role", "Propose giving one person an EXTRA role on "
                                   "top of their own, e.g. to cover for a "
                                   "colleague on leave. Their own role is "
                                   "unchanged.",
          username=USER, role=("string", "Existing role to add.")),
    _tool("propose_remove_user_role", "Propose taking an extra role away from "
                                      "a person (their own role is unchanged).",
          username=USER, role=("string", "Extra role currently held.")),
    _tool("propose_set_attribute", "Propose setting a user attribute used by "
                                   "row filters (e.g. dept, site).",
          username=USER,
          key=("string", "Attribute name (not 'role' or 'email'; email is "
                         "identity-critical and owned by HR/IdP)."),
          value=("string", "New value.")),
    _tool("propose_undo", "Propose reverting the most recently applied change."),
]
REQUIRED = {t["name"]: set(t["input_schema"]["required"]) for t in TOOLS}

# tool name -> (PolicyAdmin method, argument names)
_SUBJECT_COLUMN = ("role", "username", "table", "column")
_SUBJECT_ROWS = ("role", "username", "table", "filter_template", "columns")
DISPATCH = {
    "list_roles": ("list_roles", ()),
    "list_tables": ("list_tables", ()),
    "describe_role": ("describe_role", ("role",)),
    "describe_user": ("describe_user", ("username",)),
    "show_history": ("history", ()),
    "propose_grant": ("propose_grant", _SUBJECT_COLUMN),
    "propose_revoke": ("propose_revoke", _SUBJECT_COLUMN),
    "propose_deny": ("propose_deny", _SUBJECT_COLUMN),
    "propose_remove_deny": ("propose_remove_deny", _SUBJECT_COLUMN),
    "propose_row_scope": ("propose_row_scope", _SUBJECT_ROWS),
    "propose_remove_row_scope": ("propose_remove_row_scope", _SUBJECT_ROWS),
    "propose_deny_rows": ("propose_deny_rows", _SUBJECT_ROWS),
    "propose_remove_deny_rows": ("propose_remove_deny_rows", _SUBJECT_ROWS),
    "propose_inherit": ("propose_inherit", ("role", "parent_role")),
    "propose_remove_inherit": ("propose_remove_inherit", ("role", "parent_role")),
    "propose_assign_role": ("propose_assign_role", ("username", "role")),
    "propose_add_user_role": ("propose_add_user_role", ("username", "role")),
    "propose_remove_user_role": ("propose_remove_user_role", ("username", "role")),
    "propose_set_attribute": ("propose_set_attribute", ("username", "key", "value")),
    "propose_undo": ("propose_undo", ()),
}


def build_system_prompt(admin: PolicyAdmin) -> str:
    tables = "\n".join(f"- {t}({', '.join(c)})"
                       for t, c in admin.list_tables().items())
    roles = "\n".join(
        f"- {r['role']}"
        + (f" (inherits {', '.join(r['inherits'])})" if r["inherits"] else "")
        + (f" users: {', '.join(r['users'])}" if r["users"] else "")
        for r in admin.list_roles()
    )
    return f"""You are Master, the access-policy assistant for the company's data chatbot.

You help the master user inspect and change who can see what. Workers ask the
data chatbot questions; what they can read is decided by grants (table.column),
role inheritance, row filters bound to worker attributes, scoped grants
(specific columns for specific rows in one rule, e.g. "let warehouse workers
see the name and salary of employee 2" = propose_row_scope with columns
"id, name, salary" and filter "id = 2"; no separate grant needed), and denies.

Rules belong to a ROLE (a group / job title: pass role=...) or to ONE PERSON
(pass username=...; a personal rule). Precedence, highest first:
personal deny > personal allow > role deny > role allow. A personal rule never
changes what anyone else sees. A personal grant is its own scope: it keeps
the rows the person's role sees (a personal row scope, propose_row_scope
username=..., replaces that and can widen or narrow it), and a query mixing
personal-only columns with role-only columns is denied.

Choosing the subject:
- The master names a person ("Alice", "bob") -> a PERSONAL rule (username=).
  Never widen or narrow a whole role because one person was named.
- The master names a group or job ("HR", "warehouse workers") -> a role rule.
- Cover for someone: "Carol is on leave, let Alice take over" -> either give
  alice Carol's role on top of her own (propose_add_user_role username=alice,
  role=<carol's role>; check with describe_user that alice has the attributes
  that role's row filters need, e.g. dept), or give alice the specific personal
  rules she needs (e.g. propose_row_scope username=alice ...). Ask which, if
  unclear. Later, propose_remove_user_role restores the old access.
- "X must never see Y" -> a deny (propose_deny / propose_deny_rows), which
  also hides rows a role inherits; a personal deny beats everything.

Tables and columns:
{tables}

Roles:
{roles}

Rules:
- Always use the tools to look things up; never guess current policy.
- You can only PROPOSE changes.
{CONFIRM_RULE}
- Be precise: use exact table.column names from the list above.
- If a request is ambiguous (which role or person? all columns or some? which
  rows?), ask a clarifying question instead of proposing.
- After proposing, summarize each change in plain language, including any
  WARNING lines from the tool result.
- The master role and master users cannot be changed through you.
"""


def _worker_emails(admin) -> list:
    try:
        attrs = admin.attributes()
    except Exception:  # noqa: BLE001 - unreadable attributes: nothing to list
        return []
    if not isinstance(attrs, dict):
        return []
    return sorted({r["email"].strip() for r in attrs.values()
                   if isinstance(r, dict) and isinstance(r.get("email"), str)
                   and r["email"].strip()}, key=len, reverse=True)


def redact_emails(text: str, emails) -> str:
    """Replace every occurrence of any of `emails` (case-insensitive)."""
    for email in emails:
        text = re.sub(re.escape(email), EMAIL_REDACTED, text, flags=re.IGNORECASE)
    return text


def _redact_user_info(info):
    """describe_user output for the LLM: email -> <set> / <not set>."""
    if isinstance(info, dict) and isinstance(info.get("attributes"), dict):
        attributes = dict(info["attributes"])
        attributes["email"] = EMAIL_SET if attributes.get("email") else EMAIL_NOT_SET
        info = dict(info, attributes=attributes)
    return info


def run_tool(admin, username, name, args, pending):
    """Execute one tool call. Returns (text, is_error).

    The text goes to the LLM, so worker email addresses are taken out of
    it (describe_user shows email: <set> / <not set>; any other address
    is replaced by <email>). The human-facing diff shown by
    confirm_pending is unaffected.
    """
    text, is_error = _run_tool(admin, username, name, args, pending)
    return redact_emails(text, _worker_emails(admin)), is_error


def _run_tool(admin, username, name, args, pending):
    if name not in DISPATCH:
        return f"Unknown tool {name!r}.", True
    method, params = DISPATCH[name]
    args = args if isinstance(args, dict) else {}
    try:
        missing = [p for p in params if p not in args and p in REQUIRED[name]]
        if missing:
            raise ValueError(f"Missing argument(s): {', '.join(missing)}")
        values = {p: args[p] for p in params if p in args}
        if name == "show_history":
            values = {"limit": args.get("limit", 10)}
        if name.startswith("propose_"):
            change = getattr(admin, method)(**values, actor=username)
            pending[change.id] = change
            return (f"Proposed change {change.id}:\n{change.description}\n"
                    f"{AWAITING}"), False
        result = getattr(admin, method)(**values)
        if name == "describe_user":
            result = _redact_user_info(result)
        return json.dumps(result, default=str), False
    except Exception as err:  # noqa: BLE001 - report to the model, never crash
        return str(err) or type(err).__name__, True


def complete_turn(client, admin, username, system_prompt, history, pending,
                  model: str = MODEL) -> str:
    """Drive one master turn to completion, including tool round-trips."""
    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            tools=TOOLS,
            messages=history,
        )
        history.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            return "".join(b.text for b in response.content if b.type == "text")

        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            text, is_error = run_tool(admin, username, block.name, block.input,
                                      pending)
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": text,
                "is_error": is_error,
            })
        history.append({"role": "user", "content": results})

    return "Sorry, I couldn't complete that request — please rephrase."


def add_user_text(history, text):
    """Append user text, merging into a trailing user message if present."""
    if history and history[-1]["role"] == "user":
        content = history[-1]["content"]
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        history[-1]["content"] = [*content, {"type": "text", "text": text}]
    else:
        history.append({"role": "user", "content": text})


def ask_yes_no(input_fn, output, prompt) -> bool:
    """Ask until the human types yes/y or no/n (case-insensitive).

    Anything else, including an empty line, re-asks. EOF or Ctrl-C at the
    prompt counts as "no" (fail closed).
    """
    while True:
        try:
            answer = input_fn(prompt)
        except (EOFError, KeyboardInterrupt):
            return False
        answer = (answer or "").strip().lower()
        if answer in YES:
            return True
        if answer in NO:
            return False
        output(REASK)


def confirm_pending(admin, username, pending, history, input_fn, output):
    """Show each proposed change and apply it only if the human says yes.

    Runs in code after the model's turn; pending changes never outlive it.
    """
    try:
        for change_id, change in list(pending.items()):
            output(f"\n--- Proposed change {change_id} ({change.kind}) ---")
            output(change.description)
            output(change.diff() or "(no textual difference)")
            confirmed = ask_yes_no(input_fn, output,
                                   f"Apply change {change_id}? [yes/no]: ")
            audit.info("POLICY_CONFIRM change=%s actor=%s decision=%s",
                       change_id, username,
                       "confirmed" if confirmed else "declined")
            if confirmed:
                try:
                    admin.apply(change, actor=username)  # re-checks actor is master
                except (ValueError, OSError) as err:
                    output(f"Change {change_id} was NOT applied: {err}")
                    reason = redact_emails(str(err), _worker_emails(admin))
                    add_user_text(history, f"[Code note] Change {change_id} "
                                           f"could NOT be applied: {reason}")
                    continue
                output(f"Change {change_id} APPLIED. Workers see it on their "
                       "next question.")
                add_user_text(history, f"[Code note] Change {change_id} was "
                                       "APPLIED by the human.")
            else:
                output(f"Change {change_id} declined by you; nothing was "
                       "written.")
                add_user_text(history, f"[Code note] Change {change_id} was "
                                       "DECLINED by the human; nothing was "
                                       "written.")
    finally:
        pending.clear()


class NotMasterError(PermissionError):
    """The user may not use the master chatbot (not a master user)."""


def require_master(admin: PolicyAdmin, username: str) -> None:
    """Raise NotMasterError unless `username` is a master user. Checked
    before the session starts and again before every turn."""
    record = admin.attributes().get(username)
    if not isinstance(record, dict) or record.get("role") != MASTER_ROLE:
        raise NotMasterError(
            f"{username!r} is not a master user; the master chatbot is "
            "restricted to users with role 'master'.")
