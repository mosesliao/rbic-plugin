"""Worker-facing engine: NL question -> LLM text-to-SQL -> SQL gate -> SQLite -> answer.

RBICEngine.ask() is the single entry point every chat host calls. The LLM
is untrusted: every SQL statement it emits goes through
SQLGate.authorize() (parse -> RBAC -> ABAC rewrite) before touching the
database, and the database connection itself is opened read-only as
defense in depth. Every refusal (audience, identity, policy, gate) is a
fixed message from code - the model never generates it.

The host is only partly trusted: its authenticated session decides who is
asking (Identity), but the chat history it sends is untrusted text (see
rbic.history), and the system prompt is always built here.
"""

import asyncio
import hashlib
import json
import os
import sqlite3
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import anthropic

from . import audit
from .audit import logger
from .config import DEFAULT_MODEL, ConfigError, EngineConfig, resolve_config
from .gate import (
    DENY_MESSAGE, MASTER_ROLE, AccessDenied, PolicySnapshot, SQLGate,
    is_user_subject, normalize_email,
)
from .history import (DEFAULT_MAX_CHARS, DEFAULT_MAX_MESSAGES, normalize_turn,
                      sanitize_history)
from .identity import Identity, JsonAttributeProvider

MODEL = DEFAULT_MODEL
EXECUTOR_DIALECT = "sqlite"
MAX_TOOL_TURNS = 5
MAX_ROWS_TO_MODEL = 50
MAX_TOKENS = 1024

# Fixed replies, all from code.
POLICY_RESET_NOTICE = "(Access policy was updated — conversation reset.)"
AUDIENCE_DENY_MESSAGE = "This assistant only answers in private one-to-one chats."
EMPTY_QUESTION_MESSAGE = "Please type a question."
LLM_UNAVAILABLE_MESSAGE = ("The assistant is temporarily unavailable. "
                           "Please try again later.")
POLICY_CHANGED_MESSAGE = (POLICY_RESET_NOTICE + " The access policy changed "
                          "while your question was being answered. Please "
                          "ask it again.")
INCOMPLETE_MESSAGE = "Sorry, I couldn't complete that request — please rephrase."

# Conversation guard bounds (memory only; see _ConversationGuard).
GUARD_MAX_CONVERSATIONS = 10_000
GUARD_MAX_REPLIES = 200
MAX_CONVERSATION_ID_LEN = 256

RUN_SQL_TOOL = {
    "name": "run_sql",
    "description": (
        "Run a single read-only SQL SELECT against the company database and "
        "get the matching rows back as JSON. Use it whenever the worker's "
        "question needs data."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "sql": {
                "type": "string",
                "description": "Exactly one SQLite SELECT statement.",
            }
        },
        "required": ["sql"],
    },
}


# ---------------------------------------------------------------------------
# system prompt (UX only: the gate enforces regardless of what it says)
# ---------------------------------------------------------------------------

def allowed_schema(gate: SQLGate, username: str, snapshot=None) -> dict:
    """Subset of the schema this worker may read through plain grants,
    after precedence (user deny > user allow > role deny > role allow),
    so a denied column is never advertised.

    Shown to the LLM so it doesn't write doomed queries — purely UX.
    The gate still enforces every query regardless of what the model saw.
    """
    snapshot = snapshot or gate.snapshot
    return snapshot.effective_columns(username, gate.schema)


def scoped_schema(gate: SQLGate, username: str, snapshot=None) -> dict:
    """table -> [[columns], ...] of the worker's scoped grants (4-field p2
    rows, role- or user-level): columns readable only for certain rows and
    only together, minus any column a deny takes away.

    UX only, like allowed_schema; the filter itself is not shown.
    """
    snapshot = snapshot or gate.snapshot
    out = {}
    for table, grants in snapshot.scoped_columns(username).items():
        if table not in gate.schema:
            continue
        out[table] = [list(cols) for _, cols in grants]
    return out


def build_system_prompt(role: str, schema: dict, scoped: dict = None) -> str:
    tables = "\n".join(f"- {t}({', '.join(cols)})" for t, cols in schema.items())
    scoped_lines = "\n".join(
        f"- {t}({', '.join(cols)})"
        for t, grants in (scoped or {}).items() for cols in grants)
    if scoped_lines:
        scoped_lines = f"""
Row-limited scopes. Each line below lists columns of a table you may read
only for a limited set of rows (the limit is applied automatically). A query
that uses any column of such a table beyond its regular list above must use
ONLY the columns of one of these lines, nothing else from that table:
{scoped_lines}
"""
    return f"""You are a company data assistant for a {role}.

Answer the worker's questions using the run_sql tool against these tables:
{tables}
{scoped_lines}
Rules:
- Emit a single SQLite SELECT per tool call. No other statement types.
- Only reference the tables and columns listed above.
- After getting rows back, answer concisely in plain language.
- If a question needs no company data, answer directly without the tool.
"""


def system_prompt_for(gate: SQLGate, username: str,
                      snapshot: Optional[PolicySnapshot] = None) -> tuple:
    """(role, system prompt) for a worker, from one snapshot (by default
    the gate's freshly reloaded one). role is None (and the prompt lists no
    tables) if the worker is unknown or has no usable role."""
    snap = snapshot or gate.refreshed_snapshot()
    subj = snap.subjects_for(username)
    if subj is None:
        return None, build_system_prompt(None, {}, {})
    return subj.role, build_system_prompt(
        subj.role, allowed_schema(gate, username, snap),
        scoped_schema(gate, username, snap))


# ---------------------------------------------------------------------------
# executor + tool loop
# ---------------------------------------------------------------------------

def execute(sql: str, db_path) -> list:
    """Run gated SQL against a read-only connection (defense in depth)."""
    conn = sqlite3.connect(f"file:{os.fspath(db_path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def _tool_denied(username: str, reason: str, detail) -> AccessDenied:
    """A malformed tool call is denied like an ungated query."""
    logger.warning("DENY user=%s reason=%s sql=%r", username, reason,
                   str(detail)[:500])
    return AccessDenied(reason)


def complete_turn(client, gate, username, system_prompt, history, *,
                  db_path, model: str = MODEL) -> str:
    """Drive one user turn to completion, including tool round-trips.

    `history` is appended to (assistant tool_use turns, tool results), so
    pass a private copy. Raises AccessDenied the moment any generated SQL
    fails the gate, or the model calls anything but run_sql with a string.
    """
    for _ in range(MAX_TOOL_TURNS):
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            tools=[RUN_SQL_TOOL],
            messages=history,
        )
        history.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            text = "".join(b.text for b in response.content
                           if getattr(b, "type", None) == "text")
            return text.strip() or INCOMPLETE_MESSAGE

        results = []
        for block in response.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            if block.name != RUN_SQL_TOOL["name"]:
                raise _tool_denied(username, f"unknown tool {block.name!r}",
                                   block.input)
            sql = block.input.get("sql") if isinstance(block.input, dict) else None
            if not isinstance(sql, str):
                raise _tool_denied(username, "run_sql called without a SQL "
                                             "string", block.input)
            safe_sql = gate.authorize(username, sql)  # may raise AccessDenied
            try:
                rows = execute(safe_sql, db_path)
            except sqlite3.Error as err:
                results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "is_error": True,
                    "content": f"SQL error: {type(err).__name__}: "
                               f"{str(err)[:200]}",
                })
                continue
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(rows[:MAX_ROWS_TO_MODEL], default=str),
            })
        history.append({"role": "user", "content": results})

    return INCOMPLETE_MESSAGE


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

class Audience(Enum):
    """Who can see the reply. Only PRIVATE (one-to-one with the asking
    worker) is served: in a shared channel other people would read rows
    that only the asker may see."""

    PRIVATE = "private"
    SHARED = "shared"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AskResult:
    """The reply to show the user, plus metadata for the host.

    text:   always safe to display (every refusal is fixed code text).
    denied: True when access was refused (audience, identity, policy, gate).
    reason: for host LOGS only - never display it (it can name tables,
            columns and policy details the user may not see).
    worker / role: who the identity resolved to (None if it didn't).
    reset:  True when earlier turns were dropped because the policy changed.
    """

    text: str
    denied: bool
    reason: Optional[str]
    worker: Optional[str]
    role: Optional[str]
    reset: bool = False


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _GuardEntry:
    __slots__ = ("fingerprint", "replies")

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint
        self.replies = deque(maxlen=GUARD_MAX_REPLIES)  # digests of our replies


class _ConversationGuard:
    """(worker, conversation_id) -> the policy fingerprint the conversation
    was answered under, plus digests of the replies ask() returned under it.

    Thread-safe, bounded LRU, in memory: after a restart every conversation
    is unknown, which fails closed (earlier turns are dropped).
    """

    def __init__(self, max_entries: int = GUARD_MAX_CONVERSATIONS):
        self._entries: OrderedDict = OrderedDict()
        self._max = max_entries
        self._lock = threading.Lock()

    def get(self, key) -> Optional[tuple]:
        """(fingerprint, frozenset of reply digests) or None."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry.fingerprint, frozenset(entry.replies)

    def record(self, key, fingerprint: str, reply_digest: str) -> None:
        """Remember a reply returned under `fingerprint`; an entry for
        another fingerprint is replaced (its replies are stale)."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.fingerprint != fingerprint:
                entry = _GuardEntry(fingerprint)
                self._entries[key] = entry
            entry.replies.append(reply_digest)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)

    def drop(self, key) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def _safe_repr(value, limit: int = 200) -> str:
    return repr(value if isinstance(value, str) else type(value).__name__)[:limit]


class RBICEngine:
    """Role-gated question answering over the company database.

    Build it with from_config_dir() (or RBICEngine(config)); share one
    instance across threads. Building it, reload() and identity/audience
    denials never need an API key: the Anthropic client is created on the
    first LLM call (unless `client` is injected).

    Hosts must keep the audit trail: call rbic.audit.configure(path) (or
    attach a handler to "rbic.audit") before building the engine, or it
    warns once (AuditNotConfiguredWarning) and audit records are lost.
    """

    def __init__(self, config: EngineConfig, *, gate: Optional[SQLGate] = None,
                 client=None, api_key: Optional[str] = None,
                 attribute_provider=None,
                 max_messages: int = DEFAULT_MAX_MESSAGES,
                 max_chars: int = DEFAULT_MAX_CHARS):
        if config.dialect != EXECUTOR_DIALECT:
            raise ConfigError(f"The engine executes on SQLite; the gate's "
                              f"dialect must be {EXECUTOR_DIALECT!r}, not "
                              f"{config.dialect!r}.")
        if gate is not None and gate.dialect != EXECUTOR_DIALECT:
            raise ConfigError(f"The gate's dialect {gate.dialect!r} differs "
                              f"from the executor's ({EXECUTOR_DIALECT!r}).")
        if not config.db_path.is_file():
            raise ConfigError(f"Database {str(config.db_path)!r} does not exist.")
        self.config = config
        self.gate = gate or SQLGate.from_config(config)
        self.attribute_provider = attribute_provider or JsonAttributeProvider()
        self.max_messages = max_messages
        self.max_chars = max_chars
        self._client = client
        self._api_key = api_key
        self._client_lock = threading.Lock()
        self._guard = _ConversationGuard()
        audit.warn_if_unconfigured()

    @classmethod
    def from_config_dir(cls, config_dir=None, *, db_path=None, model=None,
                        dialect=None, api_key=None, client=None,
                        attribute_provider=None) -> "RBICEngine":
        """Engine over a configuration directory (see rbic.config for the
        precedence: arguments > RBIC_* environment > defaults)."""
        cfg = resolve_config(config_dir, db_path=db_path, model=model,
                             dialect=dialect)
        return cls(cfg, client=client, api_key=api_key,
                   attribute_provider=attribute_provider)

    # -- public API ---------------------------------------------------------

    @property
    def fingerprint(self) -> str:
        return self.gate.fingerprint

    @property
    def broken(self) -> Optional[str]:
        """Why the policy failed to load (every request is denied), or None."""
        return self.gate.broken

    def reload(self) -> str:
        """Pick up policy/attribute file changes now; return the policy
        fingerprint (of the last good load if the policy is broken - check
        `broken`)."""
        return self.gate.refreshed_snapshot().fingerprint

    async def aask(self, identity: Identity, messages, *,
                   conversation_id: Optional[str] = None,
                   audience: Audience = Audience.PRIVATE) -> AskResult:
        return await asyncio.to_thread(self.ask, identity, messages,
                                       conversation_id=conversation_id,
                                       audience=audience)

    def ask(self, identity: Identity, messages, *,
            conversation_id: Optional[str] = None,
            audience: Audience = Audience.PRIVATE) -> AskResult:
        """Answer the last user turn of `messages` for `identity`.

        `identity` must come from the host's authenticated session.
        `messages` is the host's chat history ({"role", "content"} dicts);
        it is treated as untrusted text and never mutated. Every step that
        refuses does so before the LLM is called.
        """
        provider = _safe_repr(getattr(identity, "provider", None))
        subject = _safe_repr(getattr(identity, "subject", None))

        # a. only private one-to-one chats
        if audience is not Audience.PRIVATE:
            logger.warning("AUDIENCE_DENY provider=%s subject=%s audience=%s",
                           provider, subject, _safe_repr(
                               getattr(audience, "value", audience)))
            return AskResult(AUDIENCE_DENY_MESSAGE, True, "audience", None, None)

        # b. one snapshot for identity, prompt and fingerprint
        snap = self.gate.refreshed_snapshot()
        if snap.broken or not snap.fingerprint:
            logger.warning("POLICY_UNAVAILABLE_DENY provider=%s subject=%s",
                           provider, subject)
            return AskResult(DENY_MESSAGE, True, "policy unavailable", None, None)

        # c. who is asking
        worker, role, why = self._resolve(identity, snap)
        if worker is None:
            email = normalize_email(getattr(identity, "email", None))
            logger.warning(
                "IDENTITY_DENY provider=%s subject=%s email_sha256=%s reason=%s",
                provider, subject, _digest(email)[:16] if email else "-", why)
            return AskResult(DENY_MESSAGE, True, f"identity: {why}", None, None)

        # d. untrusted host history -> text-only turns ending with the user
        history = sanitize_history(messages, max_messages=self.max_messages,
                                   max_chars=self.max_chars)
        if not history:
            return AskResult(EMPTY_QUESTION_MESSAGE, False, "no question",
                             worker, role)

        # e. conversation guard
        key = None
        if isinstance(conversation_id, str) and \
                0 < len(conversation_id) <= MAX_CONVERSATION_ID_LEN:
            key = (worker, conversation_id)
        known = self._guard.get(key) if key is not None else None
        reset = False
        if known is None:
            history = history[-1:]
        elif known[0] != snap.fingerprint:
            history = history[-1:]
            reset = True
            logger.info("POLICY_RESET user=%s conversation=%s", worker,
                        _safe_repr(conversation_id))
        else:
            history = self._trusted_suffix(history, known[1])

        # f. system prompt, server-side, from the same snapshot
        _, system_prompt = system_prompt_for(self.gate, worker, snap)

        # g. tool loop on a private copy
        private = [dict(turn) for turn in history]
        denied, reason = False, None
        try:
            text = complete_turn(self._get_client(), self.gate, worker,
                                 system_prompt, private,
                                 db_path=self.config.db_path,
                                 model=self.config.model)
        except AccessDenied as err:
            text, denied, reason = DENY_MESSAGE, True, str(err)
        except anthropic.AnthropicError as err:
            logger.error("LLM_ERROR user=%s error=%s", worker,
                         type(err).__name__)
            text, reason = LLM_UNAVAILABLE_MESSAGE, "llm error"
        except Exception as err:  # noqa: BLE001 - never leak, never crash the host
            logger.error("ENGINE_ERROR user=%s error=%s", worker,
                         type(err).__name__)
            text, reason = LLM_UNAVAILABLE_MESSAGE, "internal error"
        del private

        # h. a policy change during the turn invalidates the answer
        after = self.gate.refreshed_snapshot()
        if (after.version != snap.version or after.fingerprint != snap.fingerprint
                or after.broken):
            if key is not None:
                self._guard.drop(key)
            logger.warning("POLICY_CHANGED_DURING_TURN user=%s", worker)
            return AskResult(POLICY_CHANGED_MESSAGE, denied,
                             "policy changed during turn", worker, role,
                             reset=True)

        if reset:
            text = f"{POLICY_RESET_NOTICE}\n\n{text}"
        if key is not None:
            self._guard.record(key, snap.fingerprint,
                               _digest(normalize_turn(text, self.max_chars)))
        return AskResult(text, denied, reason, worker, role, reset=reset)

    # -- internals ----------------------------------------------------------

    def _resolve(self, identity, snap: PolicySnapshot) -> tuple:
        """(worker, role, None) or (None, None, why)."""
        if not isinstance(identity, Identity):
            return None, None, "not an Identity"
        try:
            worker = self.attribute_provider.resolve(identity, snap.attributes)
        except Exception as err:  # noqa: BLE001 - a failing provider denies
            return None, None, f"attribute provider error {type(err).__name__}"
        if worker is None:
            return None, None, "unmapped identity"
        record = snap.attributes.get(worker) if isinstance(worker, str) else None
        if not isinstance(record, dict):
            return None, None, "unknown worker"
        role = record.get("role")
        if not isinstance(role, str) or not role:
            return None, None, "worker has no role"
        if role == MASTER_ROLE:
            return None, None, "master users have no data access"
        if is_user_subject(role):
            return None, None, "worker role is a user subject"
        if snap.subjects_for(worker) is None:
            return None, None, "worker has no usable role"
        return worker, role, None

    def _trusted_suffix(self, history: list, replies: frozenset) -> list:
        """The turns after the last assistant turn this engine did not
        return under the current policy (all of them, normally). Anything
        the host altered, inserted or kept from before a policy change
        cuts the history there."""
        cut = 0
        for i, turn in enumerate(history):
            if turn["role"] == "assistant" and _digest(turn["content"]) not in replies:
                cut = i + 1
        return history[cut:]

    def _get_client(self):
        with self._client_lock:
            if self._client is None:
                self._client = (anthropic.Anthropic(api_key=self._api_key)
                                if self._api_key else anthropic.Anthropic())
            return self._client
