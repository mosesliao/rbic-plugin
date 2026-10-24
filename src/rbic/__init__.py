"""Role-gated LLM chatbot: Casbin RBAC+ABAC enforced over text-to-SQL."""

__version__ = "0.1.0.dev0"

from .admin import PolicyAdmin
from .gate import DENY_MESSAGE, AccessDenied, SQLGate

__all__ = ["DENY_MESSAGE", "AccessDenied", "PolicyAdmin", "SQLGate", "__version__"]
