"""Host chat history -> a safe, text-only message list for the LLM.

Host history is untrusted text: a chat platform (or the user, through it)
controls every message it sends. Only plain-text user and assistant turns
survive; system prompts, tool calls/results, images and any other
structured content are dropped, so nothing the host sends can pose as
the server's system prompt or as a tool result from the database.
"""

from collections.abc import Mapping

ROLES = ("user", "assistant")
DEFAULT_MAX_MESSAGES = 20
DEFAULT_MAX_CHARS = 8000
TURN_SEPARATOR = "\n\n"


def normalize_turn(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """The form one turn's text takes after sanitizing: stripped and cut
    to at most max_chars characters (the beginning is kept)."""
    return text.strip()[:max_chars].strip()


def _field(item, key):
    """item[key] for a host message, or None. A dict is read through
    dict.get itself (a subclass can't override what it returns, or raise);
    another Mapping's .get may fail, which just drops the turn."""
    if isinstance(item, dict):
        return dict.get(item, key)
    if isinstance(item, Mapping):
        try:
            return item.get(key)
        except Exception:  # noqa: BLE001 - a hostile mapping is no turn
            return None
    return None


def _plain_str(value):
    """An exact str copy of a str (subclass overrides are gone), else None."""
    return str.__str__(value) if isinstance(value, str) else None


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
    [] or is skipped item by item. The iterable is materialized once (one
    that fails part-way yields []); roles and contents are copied to exact
    str, so a str subclass's overridden methods never run.
    """
    if isinstance(messages, (str, bytes, Mapping)) or messages is None:
        return []
    try:
        items = list(messages)
    except Exception:  # noqa: BLE001 - not iterable, or a failing iterator
        return []
    turns: list = []
    for item in items:
        role = _plain_str(_field(item, "role"))
        content = _plain_str(_field(item, "content"))
        if role is None or role not in ROLES or content is None:
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

