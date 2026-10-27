"""
title: Company Data (RBIC)
author: mosesliao
author_url: https://github.com/mosesliao/rbic-plugin
version: 0.1.0
license: see https://github.com/mosesliao/rbic-plugin
description: Answers questions from the company database; every SQL query is checked by the rbic Casbin RBAC+ABAC gate in code. SSO users, private chats only.
"""

# Open WebUI Pipe function for rbic (written against Open WebUI v0.12.4).
#
# Admins import this file under Admin Panel -> Functions. It has no
# `requirements` frontmatter on purpose: rbic-plugin is preinstalled in the
# derived image (integrations/openwebui/Dockerfile) and frontmatter pip
# installs must stay disabled (ENABLE_PIP_INSTALL_FRONTMATTER_REQUIREMENTS=false).
# Keep any "word: text" line out of the docstring above: Open WebUI parses
# every such line as frontmatter.
#
# What this file does, in order (every refusal is fixed text from code):
#   1. Background tasks (title/tags/follow-ups/autocomplete/query generation,
#      memory review, context compaction, ...) get a fixed, data-free stub.
#      The engine is never called for them: Open WebUI pastes the chat
#      transcript into a USER turn for tasks (CLAUDE.md "Host requirements").
#   2. Configuration checks: AUDIT_LOG_PATH set (audit.configure), the
#      installed rbic version (EXPECTED_RBIC_VERSION), IDENTITY_SOURCE.
#   2b. Attachments: files, knowledge, chat references, web search results
#      or anything else Open WebUI would retrieve and paste into the last
#      USER turn (RAG) get a fixed refusal; the engine is never called.
#   3. Identity: Identity("openwebui", user id, email) from __user__. With
#      IDENTITY_SOURCE="oauth" the user must carry Open WebUI's SSO marker
#      (__user__["oauth"] = {provider: {"sub": ...}}), else IDENTITY_DENY.
#   4. Audience: PRIVATE only for a saved chat the user owns that isn't
#      shared, in a shared folder, internal (subagent/note) or a channel.
#      Temporary chats and requests without a chat_id are not answered
#      (unless ALLOW_API_REQUESTS, for end-to-end tests).
#   5. RBICEngine.aask(identity, body["messages"], conversation_id=chat_id,
#      audience=...) -> result.text. Never result.reason, never exceptions.
#
# The Anthropic API key is read by the anthropic SDK from the container
# environment (ANTHROPIC_API_KEY). It is never a Valve: Valves are stored in
# plaintext in Open WebUI's database and shown to every admin.

import asyncio
import logging
import os
import re
import threading
from typing import Literal, Optional

from pydantic import BaseModel, Field

import rbic
from rbic import (AUDIENCE_DENY_MESSAGE, DENY_MESSAGE, Audience, ConfigError,
                  Identity, JsonAttributeProvider, RBICEngine, audit)
from rbic.audit import logger as audit_log
from rbic.engine import LLM_UNAVAILABLE_MESSAGE
from rbic.history import sanitize_history

PROVIDER = "openwebui"
MODEL_ID = "rbic"
MODEL_NAME = "Company Data (RBIC)"
IDENTITY_SOURCES = ("oauth", "admin_created")

NOT_CONFIGURED_MESSAGE = ("The company data assistant is not configured "
                          "correctly. Please contact your administrator.")
UNAVAILABLE_MESSAGE = LLM_UNAVAILABLE_MESSAGE
ATTACHMENT_REFUSED_MESSAGE = ("Attachments, documents and chat references "
                              "can't be used with this assistant. Please ask "
                              "your question directly.")
STATUS_TEXT = "Checking access…"
EMITTER_TIMEOUT_S = 5.0
MAX_FOLDER_DEPTH = 64

# Open WebUI chat_id prefixes (open_webui/utils/chat_id.py, v0.12.4).
TEMPORARY_CHAT_PREFIXES = ("temporary:", "local:")
CHANNEL_CHAT_PREFIX = "channel:"

# Data-free answers for Open WebUI's internal task calls, in the format each
# caller parses (open_webui/utils/middleware.py, utils/task.py,
# utils/memory.py, utils/context_compaction.py at v0.12.4). Anything not
# listed (emoji, image prompt, MoA, function calling, future tasks) gets "".
TASK_STUBS = {
    "title_generation": '{"title": "Company data chat"}',
    "tags_generation": '{"tags": []}',
    "follow_up_generation": '{"follow_ups": []}',
    "query_generation": '{"queries": []}',
    "autocomplete_generation": '{"text": ""}',
    "memory_review": '{"operations": []}',
    # Non-empty, or Open WebUI builds its own summary from the messages.
    "context_compaction": "(Earlier messages are not summarized.)",
}
DEFAULT_TASK_STUB = ""

# Where Open WebUI v0.12.4 puts retrieval inputs a Pipe can see. Any
# non-empty one is refused: the files handler (utils/middleware.py
# chat_completion_files_handler, run for Pipes too unless the model's
# "File Context" capability is off) turns them into text and, unless
# RAG_SYSTEM_CONTEXT=true, pastes it into the last USER turn
# (apply_source_context_to_messages). A `type: "chat"` reference is a whole
# earlier chat rebuilt as "#### User / #### Assistant" text
# (retrieval/utils.py), i.e. old rows the conversation guard can't see.
#   metadata.files          the request's files, knowledge, web search, chat
#                           references (main.py chat_completion,
#                           middleware.py process_chat_payload); __files__ is
#                           the same list (functions.py)
#   metadata.sources        retrieved context already built for this turn
#   metadata.folder_knowledge   knowledge attached to the chat's folder
#   metadata.user_message.files the stored user message's attachments
#   body.files, messages[*].files / .sources   (defensive; normally popped)
ATTACHMENT_METADATA_KEYS = ("files", "sources", "folder_knowledge")
ATTACHMENT_MESSAGE_KEYS = ("files", "sources")

# Defense in depth: text Open WebUI's RAG/context wrappers put into a user
# turn. `<source id="` is written by get_source_context (utils/middleware.py)
# whatever RAG template is configured; the rest is DEFAULT_RAG_TEMPLATE and
# the task templates' transcript wrapper (config.py).
RAG_MARKERS = ('<source id="',
               "Respond to the user query using the provided context")
RAG_MARKER_PAIRS = (("<context>", "</context>"),
                    ("<chat_history>", "</chat_history>"))

# Test seam: tests set this to a zero-argument callable returning a fake
# Anthropic client. Production never sets it (the engine then creates the
# real client lazily from the container environment).
_TEST_CLIENT_FACTORY = None

log = logging.getLogger("rbic.openwebui")  # operational errors, class names only

_engine_lock = threading.Lock()
_engine_entry = None  # (key, RBICEngine): one engine per Valves tuple

# rbic.audit has one configure() file per process. The owner id lets this
# function move its own file when its Valve changes, but never swap the file
# of another RBIC function in the same process. Open WebUI names the module
# "function_<id>_<32 hex>" (utils/plugin.py load_function_module_by_id) and
# re-execs it when the code changes, so the hex suffix is dropped.
AUDIT_OWNER = re.sub(r"_[0-9a-f]{32}$", "", __name__)
_audit_warned = set()  # (requested path, path in use) already reported


def _plain_str(value) -> Optional[str]:
    """An exact str copy of a str (subclass overrides are gone), else None."""
    return str.__str__(value) if isinstance(value, str) else None


def _class_name(obj) -> str:
    try:
        name = type.__dict__["__name__"].__get__(type(obj))
    except Exception:  # noqa: BLE001
        return "?"
    return name if type(name) is str else "?"


def _get(mapping, key):
    """mapping[key] for a plain dict, else None (dict.get itself, so a dict
    subclass can't override what it returns)."""
    return dict.get(mapping, key) if isinstance(mapping, dict) else None


def _present(value) -> bool:
    """True unless value is None/False or an empty str/list/tuple/dict/set
    (anything unusual counts as present: fail closed)."""
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, tuple, dict, set, frozenset)):
        try:
            return len(value) > 0
        except Exception:  # noqa: BLE001
            return True
    return True


def _attachment_source(body, metadata, files) -> Optional[str]:
    """The name of the first place an attachment or retrieved context shows
    up in this request, or None. Names only: never file names, ids or text."""
    if _present(files):
        return "__files__"
    for key in ATTACHMENT_METADATA_KEYS:
        if _present(_get(metadata, key)):
            return f"metadata.{key}"
    if _present(_get(_get(metadata, "user_message"), "files")):
        return "metadata.user_message.files"
    if _present(_get(body, "files")):
        return "body.files"
    messages = _get(body, "messages")
    if isinstance(messages, list):
        for message in list(messages):
            for key in ATTACHMENT_MESSAGE_KEYS:
                if _present(_get(message, key)):
                    return f"message.{key}"
    # the user turn the engine would send (sanitized exactly as it will be)
    last = sanitize_history(messages)[-1:]
    text = last[0]["content"] if last else ""
    if any(marker in text for marker in RAG_MARKERS) or any(
            start in text and end in text for start, end in RAG_MARKER_PAIRS):
        return "rag markers in user turn"
    return None


def _configure_audit(audit_path: str) -> None:
    """audit.configure for this function. Another RBIC function's file in
    this process is kept, with one PIPE_CONFIG_WARNING per path pair."""
    handler = audit.configure(audit_path, owner=AUDIT_OWNER)
    requested = os.path.abspath(audit_path)
    in_use = getattr(handler, "baseFilename", None)
    if in_use != requested and (requested, in_use) not in _audit_warned:
        _audit_warned.add((requested, in_use))
        audit_log.warning(
            "PIPE_CONFIG_WARNING reason=audit log already configured by "
            "another RBIC Pipe in this process, records go to the file in "
            "use requested=%r in_use=%r", requested, in_use)


def _engine_key(valves) -> tuple:
    return (valves.CONFIG_DIR.strip(), valves.DB_PATH.strip(),
            valves.MODEL.strip())


def _engine_for(key: tuple) -> RBICEngine:
    """The cached engine for these Valves, built on first use and rebuilt
    whenever the Valves change. Thread-safe; a failed build is not cached."""
    global _engine_entry
    with _engine_lock:
        if _engine_entry is not None and _engine_entry[0] == key:
            return _engine_entry[1]
        config_dir, db_path, model = key
        client = _TEST_CLIENT_FACTORY() if _TEST_CLIENT_FACTORY is not None else None
        engine = RBICEngine.from_config_dir(
            config_dir or None, db_path=db_path or None, model=model or None,
            dialect="sqlite", client=client,
            attribute_provider=JsonAttributeProvider())
        _engine_entry = (key, engine)
        return engine


def _has_sso_marker(user: dict) -> bool:
    """Open WebUI records each OAuth/OIDC sign-in in user.oauth as
    {provider: {"sub": "<subject>"}} (models/users.py
    update_user_oauth_by_id, utils/oauth.py). Users created by an admin or
    through local signup have oauth = None."""
    oauth = _get(user, "oauth")
    if not isinstance(oauth, dict):
        return False
    for provider, entry in dict.items(oauth):
        if not isinstance(provider, str) or not provider:
            continue
        sub = _get(entry, "sub")
        if isinstance(sub, bool):
            continue
        if (isinstance(sub, str) and sub.strip()) or isinstance(sub, int):
            return True
    return False


async def _openwebui_chat_audience(chat_id: str, user_id: str) -> tuple:
    """(Audience, reason) for a saved chat, read from Open WebUI's own
    database in-process. PRIVATE only if the asking user owns the chat and
    nobody else can read or continue it. Fails closed."""
    try:
        from open_webui.models.access_grants import AccessGrants
        from open_webui.models.chats import Chats
        from open_webui.models.folders import Folders
        from open_webui.models.shared_chats import SharedChats
    except Exception:  # noqa: BLE001 - not running inside Open WebUI
        return Audience.UNKNOWN, "open webui unavailable"
    chat = await Chats.get_chat_by_id(chat_id)
    if chat is None:
        return Audience.UNKNOWN, "chat not found"
    if chat.user_id != user_id:
        # e.g. a shared chat in "continue" mode answered for another user
        return Audience.SHARED, "chat owned by another user"
    meta = chat.meta if isinstance(chat.meta, dict) else {}
    if meta.get("internal") is True:
        return Audience.UNKNOWN, "internal chat"
    if chat.share_id or await SharedChats.get_by_chat_id(chat_id) is not None:
        return Audience.SHARED, "chat is shared"
    folder_id, seen = chat.folder_id, set()
    while folder_id:
        if folder_id in seen or len(seen) >= MAX_FOLDER_DEPTH:
            return Audience.UNKNOWN, "folder chain too deep"
        seen.add(folder_id)
        folder = await Folders.get_folder_by_id(folder_id)
        if folder is None:
            return Audience.UNKNOWN, "folder not found"
        if folder.user_id != user_id:
            return Audience.SHARED, "folder owned by another user"
        if await AccessGrants.get_grants_by_resource("folder", folder.id):
            return Audience.SHARED, "folder is shared"
        folder_id = folder.parent_id
    return Audience.PRIVATE, None


# Production resolver; tests replace it (no Open WebUI install in tests).
_chat_audience = _openwebui_chat_audience


async def _resolve_audience(metadata: dict, user_id: str, allow_api: bool) -> tuple:
    """(Audience, conversation_id, reason)."""
    if _get(metadata, "internal") is True:
        return Audience.UNKNOWN, None, "internal request"
    meta_user = _get(metadata, "user_id")
    if meta_user is not None and _plain_str(meta_user) != user_id:
        return Audience.UNKNOWN, None, "metadata user mismatch"
    raw_chat_id = _get(metadata, "chat_id")
    chat_id = _plain_str(raw_chat_id)
    if raw_chat_id is not None and chat_id is None:
        return Audience.UNKNOWN, None, "chat_id is not a string"
    if not chat_id:
        if allow_api:
            return Audience.PRIVATE, None, None
        return Audience.UNKNOWN, None, "no chat_id"
    if chat_id.startswith(CHANNEL_CHAT_PREFIX):
        return Audience.SHARED, None, "channel"
    if chat_id.startswith(TEMPORARY_CHAT_PREFIXES):
        return Audience.UNKNOWN, None, "temporary chat"
    try:
        audience, reason = await _chat_audience(chat_id, user_id)
    except Exception as err:  # noqa: BLE001 - fail closed
        return Audience.UNKNOWN, None, f"chat lookup error {_class_name(err)}"
    if audience is not Audience.PRIVATE:
        return audience, None, reason or "not private"
    return Audience.PRIVATE, chat_id, None


async def _emit(emitter, done: bool) -> None:
    """One status event; a failing or slow emitter never breaks the answer."""
    if emitter is None:
        return
    try:
        await asyncio.wait_for(emitter({
            "type": "status",
            "data": {"description": STATUS_TEXT, "done": done, "hidden": done},
        }), EMITTER_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        pass


class Pipe:
    class Valves(BaseModel):
        CONFIG_DIR: str = Field(
            default="",
            description="rbic config directory (casbin/, db_schema.json, "
                        "worker_attributes.json). Empty = the container's "
                        "RBIC_CONFIG_DIR.")
        DB_PATH: str = Field(
            default="",
            description="SQLite database. Empty = RBIC_DB_PATH, else "
                        "<CONFIG_DIR>/company.db.")
        MODEL: str = Field(default="claude-sonnet-4-6",
                           description="Anthropic model for text-to-SQL.")
        IDENTITY_SOURCE: Literal["oauth", "admin_created"] = Field(
            default="oauth",
            description="oauth: only SSO (OAuth/OIDC) users are served. "
                        "admin_created: any Open WebUI user, mapped by email "
                        "- TESTS ONLY.")
        AUDIT_LOG_PATH: str = Field(
            default="",
            description="Required. JSON-lines audit log file (writable "
                        "volume). Empty = every request is refused.")
        EXPECTED_RBIC_VERSION: str = Field(
            default="",
            description="If set, must equal the installed rbic.__version__, "
                        "else every request is refused.")
        ALLOW_API_REQUESTS: bool = Field(
            default=False,
            description="Answer requests without a chat_id (direct API "
                        "calls). End-to-end testing only.")

    def __init__(self):
        self.valves = self.Valves()

    def pipes(self) -> list:
        return [{"id": MODEL_ID, "name": MODEL_NAME}]

    async def pipe(self, body: dict, __user__: Optional[dict] = None,
                   __metadata__: Optional[dict] = None,
                   __task__: Optional[str] = None,
                   __files__: Optional[list] = None,
                   __event_emitter__=None) -> str:
        try:
            return await self._pipe(body, __user__, __metadata__, __task__,
                                    __files__, __event_emitter__)
        except Exception as err:  # noqa: BLE001 - never leak, never crash
            try:
                audit_log.error("PIPE_ERROR error=%s", _class_name(err))
            except Exception:  # noqa: BLE001
                pass
            return UNAVAILABLE_MESSAGE

    async def _pipe(self, body, user, metadata, task, files, emitter) -> str:
        valves = self.valves  # one snapshot: Open WebUI swaps it per request
        metadata = metadata if isinstance(metadata, dict) else {}
        user = user if isinstance(user, dict) else {}
        user_id = _plain_str(_get(user, "id")) or None

        audit_path = valves.AUDIT_LOG_PATH.strip()
        audit_ok = False
        if audit_path:
            try:
                _configure_audit(audit_path)
                audit_ok = True
            except Exception as err:  # noqa: BLE001
                log.error("rbic pipe: audit log %r unusable (%s)", audit_path,
                          _class_name(err))

        # 1. background tasks: fixed stubs, the engine is never called
        task_name = task if task else _get(metadata, "task")
        if task_name:
            name = _plain_str(task_name) or ""
            audit_log.info("PIPE_TASK_STUB task=%r subject=%r", name[:64],
                           user_id)
            return TASK_STUBS.get(name, DEFAULT_TASK_STUB)

        # 2. configuration
        if not audit_ok:
            log.error("rbic pipe: AUDIT_LOG_PATH is not set or not writable; "
                      "refusing requests")
            return NOT_CONFIGURED_MESSAGE
        expected = valves.EXPECTED_RBIC_VERSION.strip()
        if expected and expected != rbic.__version__:
            audit_log.error("PIPE_CONFIG_ERROR reason=rbic version mismatch "
                            "expected=%r installed=%r", expected,
                            rbic.__version__)
            return NOT_CONFIGURED_MESSAGE
        source = valves.IDENTITY_SOURCE
        if source not in IDENTITY_SOURCES:
            audit_log.error("PIPE_CONFIG_ERROR reason=unknown IDENTITY_SOURCE")
            return NOT_CONFIGURED_MESSAGE

        # 2b. attachments / retrieved context: never reach the engine
        where = _attachment_source(body, metadata, files)
        if where is not None:
            audit_log.warning("PIPE_ATTACHMENT_REFUSED subject=%r source=%s",
                              user_id, where)
            return ATTACHMENT_REFUSED_MESSAGE

        await _emit(emitter, done=False)
        try:
            return await self._answer(valves, body, user, user_id, metadata,
                                      source)
        finally:
            await _emit(emitter, done=True)

    async def _answer(self, valves, body, user, user_id, metadata,
                      source) -> str:
        # 3. identity from the authenticated Open WebUI session
        if not user_id:
            audit_log.warning("IDENTITY_DENY provider=%r subject=None "
                              "reason=no Open WebUI user", PROVIDER)
            return DENY_MESSAGE
        if source == "oauth" and not _has_sso_marker(user):
            audit_log.warning("IDENTITY_DENY provider=%r subject=%r "
                              "reason=not an SSO user", PROVIDER, user_id)
            return DENY_MESSAGE
        identity = Identity(PROVIDER, user_id,
                            _plain_str(_get(user, "email")))

        # 4. audience: only private one-to-one chats
        audience, conversation_id, why = await _resolve_audience(
            metadata, user_id, bool(valves.ALLOW_API_REQUESTS))
        if audience is not Audience.PRIVATE:
            audit_log.warning("PIPE_AUDIENCE subject=%r audience=%s reason=%s",
                              user_id, audience.value, why)

        # 5. the engine (built off the event loop; cached per Valves tuple)
        try:
            engine = await asyncio.to_thread(_engine_for, _engine_key(valves))
        except ConfigError as err:
            audit_log.error("PIPE_CONFIG_ERROR reason=engine build failed "
                            "error=%s", _class_name(err))
            return NOT_CONFIGURED_MESSAGE
        messages = _get(body, "messages")
        result = await engine.aask(identity, messages,
                                   conversation_id=conversation_id,
                                   audience=audience)
        text = getattr(result, "text", None)
        if not isinstance(text, str):
            return DENY_MESSAGE
        if audience is not Audience.PRIVATE and text != AUDIENCE_DENY_MESSAGE:
            return AUDIENCE_DENY_MESSAGE  # belt and braces: never answer
        return text
