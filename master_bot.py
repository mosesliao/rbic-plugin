"""Master chatbot: natural-language access-policy management.

The LLM is untrusted here too. It can inspect policy and PROPOSE changes
through tools, but no tool applies anything. After each turn the code
prints every proposed change (plain-English effect + unified diff of the
real file) and applies it only if the human types the literal "yes".
Validation, master protections and the atomic write all live in
policy_admin.PolicyAdmin. This bot has no path to business data.
"""

import json
import logging
import sys

import anthropic
from dotenv import load_dotenv

from policy_admin import MASTER_ROLE, PolicyAdmin

MODEL = "claude-sonnet-4-6"
MAX_TOOL_TURNS = 8
AWAITING = "Awaiting the human's confirmation; do not claim it is applied."


def _tool(name, description, **props):
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": {
                k: {"type": t, "description": d} for k, (t, d) in props.items()
            },
            "required": list(props),
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

TOOLS = [
    _tool("list_roles", "List every role with what it inherits and its users."),
    _tool("list_tables", "List every table and its columns."),
    _tool("describe_role", "Show a role's direct and inherited grants, "
                           "effective readable columns and row filters.", role=ROLE),
    _tool("describe_user", "Show a user's role, attributes and effective "
                           "access.", username=USER),
    _tool("show_history", "Show recently applied policy changes.",
          limit=("integer", "How many entries (default 10).")),
    _tool("propose_grant", "Propose letting a role read table.column.",
          role=ROLE, table=TABLE, column=COLUMN),
    _tool("propose_revoke", "Propose removing a role's direct grant on "
                            "table.column.", role=ROLE, table=TABLE, column=COLUMN),
    _tool("propose_row_scope", "Propose a row filter limiting which rows of a "
                               "table a role sees.",
          role=ROLE, table=TABLE, filter_template=FILTER),
    _tool("propose_remove_row_scope", "Propose removing a role's row filter "
                                      "(use the exact filter text).",
          role=ROLE, table=TABLE, filter_template=FILTER),
    _tool("propose_inherit", "Propose that role inherits all grants and row "
                             "filters of parent_role.",
          role=ROLE, parent_role=("string", "Existing role to inherit from.")),
    _tool("propose_remove_inherit", "Propose removing a direct inheritance.",
          role=ROLE, parent_role=("string", "Role currently inherited.")),
    _tool("propose_assign_role", "Propose changing a user's role.",
          username=USER, role=ROLE),
    _tool("propose_set_attribute", "Propose setting a user attribute used by "
                                   "row filters (e.g. dept, site).",
          username=USER,
          key=("string", "Attribute name (not 'role')."),
          value=("string", "New value.")),
    _tool("propose_undo", "Propose reverting the most recently applied change."),
]

# tool name -> (PolicyAdmin method, argument names)
DISPATCH = {
    "list_roles": ("list_roles", ()),
    "list_tables": ("list_tables", ()),
    "describe_role": ("describe_role", ("role",)),
    "describe_user": ("describe_user", ("username",)),
    "show_history": ("history", ()),
    "propose_grant": ("propose_grant", ("role", "table", "column")),
    "propose_revoke": ("propose_revoke", ("role", "table", "column")),
    "propose_row_scope": ("propose_row_scope", ("role", "table", "filter_template")),
    "propose_remove_row_scope": ("propose_remove_row_scope",
                                 ("role", "table", "filter_template")),
    "propose_inherit": ("propose_inherit", ("role", "parent_role")),
    "propose_remove_inherit": ("propose_remove_inherit", ("role", "parent_role")),
    "propose_assign_role": ("propose_assign_role", ("username", "role")),
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
data chatbot questions; what they can read is decided by role grants
(table.column), role inheritance, and row filters bound to worker attributes.

Tables and columns:
{tables}

Roles:
{roles}

Rules:
- Always use the tools to look things up; never guess current policy.
- You can only PROPOSE changes. The human confirms each one after your reply;
  never say a change is applied unless a [Code note] says it was APPLIED.
- Be precise: use exact table.column names from the list above.
- If a request is ambiguous (which role? all columns or some? which rows?),
  ask a clarifying question instead of proposing.
- After proposing, summarize each change in plain language, including any
  WARNING lines from the tool result.
- The master role and master users cannot be changed through you.
"""


def run_tool(admin, username, name, args, pending):
    """Execute one tool call. Returns (text, is_error)."""
    if name not in DISPATCH:
        return f"Unknown tool {name!r}.", True
    method, params = DISPATCH[name]
    args = args if isinstance(args, dict) else {}
    try:
        missing = [p for p in params if p not in args]
        if missing:
            raise ValueError(f"Missing argument(s): {', '.join(missing)}")
        values = [args[p] for p in params]
        if name == "show_history":
            values = [args.get("limit", 10)]
        if name.startswith("propose_"):
            change = getattr(admin, method)(*values, actor=username)
            pending[change.id] = change
            return (f"Proposed change {change.id}:\n{change.description}\n"
                    f"{AWAITING}"), False
        return json.dumps(getattr(admin, method)(*values), default=str), False
    except Exception as err:  # noqa: BLE001 - report to the model, never crash
        return str(err) or type(err).__name__, True


def complete_turn(client, admin, username, system_prompt, history, pending) -> str:
    """Drive one master turn to completion, including tool round-trips."""
    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=MODEL,
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


def confirm_pending(admin, username, pending, history, input_fn, output):
    """Show each proposed change and apply it only on a literal "yes".

    Runs in code after the model's turn; pending changes never outlive it.
    """
    try:
        for change_id, change in list(pending.items()):
            output(f"\n--- Proposed change {change_id} ({change.kind}) ---")
            output(change.description)
            output(change.diff() or "(no textual difference)")
            try:
                answer = input_fn(f"Apply change {change_id}? [yes/no] ")
            except EOFError:
                answer = ""
            if answer.strip() == "yes":
                try:
                    admin.apply(change, actor=username)  # re-checks actor is master
                except (ValueError, OSError) as err:
                    output(f"Change {change_id} was NOT applied: {err}")
                    add_user_text(history, f"[Code note] Change {change_id} "
                                           f"could NOT be applied: {err}")
                    continue
                output(f"Change {change_id} APPLIED. Workers see it on their "
                       "next question.")
                add_user_text(history, f"[Code note] Change {change_id} was "
                                       "APPLIED by the human.")
            else:
                output(f"Change {change_id} declined; nothing was written.")
                add_user_text(history, f"[Code note] Change {change_id} was "
                                       "DECLINED by the human.")
    finally:
        pending.clear()


def require_master(admin: PolicyAdmin, username: str) -> None:
    record = admin.attributes().get(username)
    if record is None or record.get("role") != MASTER_ROLE:
        sys.exit(f"{username!r} is not a master user; the master chatbot "
                 "is restricted to users with role 'master'.")


def run_master_bot(username, client=None, input_fn=input, output=print,
                   admin=None):
    admin = admin or PolicyAdmin()
    require_master(admin, username)
    client = client or anthropic.Anthropic()
    history, pending = [], {}

    output(f"\n=== Master Chatbot | user: {username} ===")
    output("Ask about or change access policy. Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input_fn("You: ").strip()
        except EOFError:
            break
        if user_input.lower() == "exit":
            break
        if not user_input:
            continue
        require_master(admin, username)

        add_user_text(history, user_input)
        reply = complete_turn(client, admin, username, build_system_prompt(admin),
                              history, pending)
        output(f"\nMaster: {reply}\n")
        confirm_pending(admin, username, pending, history, input_fn, output)


if __name__ == "__main__":
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("casbin").setLevel(logging.WARNING)  # every proposal loads policy
    if len(sys.argv) != 2:
        sys.exit("usage: python master_bot.py <master-username>")
    run_master_bot(sys.argv[1])
