"""The rbic.audit logger: every ALLOW, DENY and POLICY_* decision.

Library convention: importing rbic attaches only a NullHandler to the
"rbic.audit" logger and never touches the root logger, so the host keeps
full control of logging.

The catch: with a NullHandler and no handler anywhere else, Python's
"last resort" stderr handler stays silent, so audit records (including
DENY warnings) are discarded. Invariant #5 says audit everything, so a
host MUST either call configure(path) once at startup (the supported way;
the Open WebUI Pipe does) or attach its own handler to "rbic.audit" (or
the root logger). RBICEngine emits an AuditNotConfiguredWarning once per
process when neither has happened.

configure() writes one JSON object per line:

    {"ts": "2026-10-24T09:15:02.123456+00:00", "level": "WARNING",
     "event": "DENY", "message": "DENY user=bob reason=... sql='...'"}

`event` is the first word of the message (ALLOW, DENY, IDENTITY_DENY,
POLICY_RELOAD, POLICY_CHANGE, ...); `message` is the full audit line in
the documented ALLOW/DENY/POLICY_* formats.
"""

import json
import logging
import os
import threading
import warnings
from datetime import datetime, timezone

LOGGER_NAME = "rbic.audit"
logger = logging.getLogger(LOGGER_NAME)
logger.addHandler(logging.NullHandler())

_lock = threading.Lock()
_handler = None  # the one handler configure() manages
_owner = None    # the owner= of the configure() call that attached it
_warned = False


class AuditNotConfiguredWarning(RuntimeWarning):
    """Audit records are being discarded: call rbic.audit.configure()."""


class JsonLinesFormatter(logging.Formatter):
    """One JSON object per record: ts (UTC ISO 8601), level, event, message."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        return json.dumps({
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "event": message.split(" ", 1)[0] if message else "",
            "message": message,
        }, ensure_ascii=False)


def configure(path, *, level=logging.INFO, owner=None) -> logging.Handler:
    """Send rbic.audit records at `level` and above to a JSON-lines file.

    Idempotent: calling it again with the same path returns the same
    handler (with `level` updated); with a different path the previous
    configure() handler is closed and replaced, so there is always at most
    one. Handlers the host attached itself are left alone. The logger's
    level is lowered to `level` if needed (records still propagate to the
    host's own handlers as usual). The file is opened in append mode,
    UTF-8.

    `owner` (optional, any hashable id, e.g. one plugin instance): when it
    is given and the current configure() handler writes to a different
    file for a different owner (or for a call without one), that handler
    is kept and returned unchanged. Callers detect this by comparing the
    returned handler's `baseFilename` with the path they asked for. Without
    `owner` the previous handler is always replaced.
    """
    global _handler, _owner
    target = os.path.abspath(os.fspath(path))
    with _lock:
        if _handler is not None and _handler.baseFilename == target:
            _handler.setLevel(level)
        elif _handler is not None and owner is not None and owner != _owner:
            return _handler  # another owner's file: keep it as it is
        else:
            if _handler is not None:
                logger.removeHandler(_handler)
                _handler.close()
            handler = logging.FileHandler(target, mode="a", encoding="utf-8")
            handler.setFormatter(JsonLinesFormatter())
            handler.setLevel(level)
            logger.addHandler(handler)
            _handler, _owner = handler, owner
        if logger.level == logging.NOTSET or logger.level > level:
            logger.setLevel(level)
        return _handler


def unconfigure() -> None:
    """Detach and close the handler configure() attached (if any)."""
    global _handler, _owner
    with _lock:
        if _handler is not None:
            logger.removeHandler(_handler)
            _handler.close()
            _handler, _owner = None, None


def is_configured() -> bool:
    """True if any non-Null handler would receive rbic.audit records
    (configure()'s, one the host attached to rbic.audit, or one on an
    ancestor logger such as root)."""
    current = logger
    while current is not None:
        if any(not isinstance(h, logging.NullHandler) for h in current.handlers):
            return True
        if not current.propagate:
            return False
        current = current.parent
    return False


def warn_if_unconfigured(stacklevel: int = 3) -> None:
    """Warn (once per process) that audit records are being discarded."""
    global _warned
    if _warned or is_configured():
        return
    _warned = True
    warnings.warn(
        "The rbic.audit logger has no handler, so ALLOW/DENY audit records are "
        "discarded. Call rbic.audit.configure(path) at startup (or attach a "
        "logging handler to 'rbic.audit').",
        AuditNotConfiguredWarning, stacklevel=stacklevel)
