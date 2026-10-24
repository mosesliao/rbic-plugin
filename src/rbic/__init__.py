"""Role-gated LLM chatbot: Casbin RBAC+ABAC enforced over text-to-SQL."""

__version__ = "0.1.0.dev0"

from . import audit  # attaches the NullHandler to "rbic.audit" first
from .admin import PolicyAdmin
from .config import ConfigError
from .engine import (AUDIENCE_DENY_MESSAGE, POLICY_RESET_NOTICE, AskResult,
                     Audience, RBICEngine)
from .gate import DENY_MESSAGE, AccessDenied, SQLGate
from .history import sanitize_history
from .identity import (AttributeProvider, Identity, JsonAttributeProvider,
                       LocalProvider)

__all__ = [
    "AUDIENCE_DENY_MESSAGE", "DENY_MESSAGE", "POLICY_RESET_NOTICE",
    "AccessDenied", "AskResult", "AttributeProvider", "Audience",
    "ConfigError", "Identity", "JsonAttributeProvider", "LocalProvider",
    "PolicyAdmin", "RBICEngine", "SQLGate", "sanitize_history", "__version__",
]
