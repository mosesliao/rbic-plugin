"""Host chat history -> a safe, text-only message list for the LLM.

Host history is untrusted text: a chat platform (or the user, through it)
controls every message it sends. Only plain-text user and assistant turns
survive; system prompts, tool calls/results, images and any other
structured content are dropped, so nothing the host sends can pose as
the server's system prompt or as a tool result from the database.
"""

ROLES = ("user", "assistant")
DEFAULT_MAX_MESSAGES = 20
DEFAULT_MAX_CHARS = 8000
TURN_SEPARATOR = "\n\n"


def normalize_turn(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """The form one turn's text takes after sanitizing: stripped and cut
    to at most max_chars characters (the beginning is kept)."""
    return text.strip()[:max_chars].strip()


def sanitize_history(messages, *, max_messages: int = DEFAULT_MAX_MESSAGES,
                     max_chars: int = DEFAULT_MAX_CHARS) -> list:
    """Return a new list of {"role", "content": str} turns, oldest first.

    - keep only dicts whose role is "user" or "assistant" and whose content
      is a str (system/tool roles and list/multimodal content are dropped);
    - strip each turn and drop empty ones;
    - drop leading assistant turns (a conversation starts with the user);
    - merge consecutive turns of the same role;
    - cut each turn to max_chars and keep the most recent max_messages;
    - return [] unless the last turn is from the user.

    The input is never mutated; anything that isn't a list of dicts yields
    [] or is skipped item by item.
    """
    if isinstance(messages, (str, bytes, dict)) or messages is None:
        return []
    try:
        items = list(messages)
    except TypeError:
        return []
    turns: list = []
    for item in items:
        if not isinstance(item, dict):
            continue
        role, content = item.get("role"), item.get("content")
        if not isinstance(role, str) or role not in ROLES \
                or not isinstance(content, str):
            continue
        text = content.strip()
        if not text:
            continue
        if not turns and role != "user":
            continue  # leading assistant turn
        if turns and turns[-1][0] == role:
            turns[-1] = (role, turns[-1][1] + TURN_SEPARATOR + text)
        else:
            turns.append((role, text))
    out = [{"role": role, "content": normalize_turn(text, max_chars)}
           for role, text in turns]
    out = [t for t in out if t["content"]]
    if max_messages is not None and max_messages >= 0:
        out = out[-max_messages:] if max_messages else []
    while out and out[0]["role"] != "user":
        out.pop(0)  # the cut may have left an assistant turn first
    if not out or out[-1]["role"] != "user":
        return []
    return out

