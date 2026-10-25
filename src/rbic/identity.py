"""Who is asking: identity types and attribute providers.

An Identity comes from the HOST's authenticated session (the chat
platform's sign-in), never from anything the user typed. An
AttributeProvider maps it to a worker key in worker_attributes.json,
looking only at the attributes of the gate snapshot the request uses, so
identity and policy always come from the same load.

Providers return None for anything they cannot map; RBICEngine.ask()
denies such requests before the LLM is called.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from .gate import normalize_email


@dataclass(frozen=True)
class Identity:
    """An authenticated principal as the host knows it.

    provider: which host/identity system vouched for it (e.g. "openwebui").
    subject:  that system's stable user id.
    email:    the verified email the host has for the user, if any.
    """

    provider: str
    subject: str
    email: Optional[str] = None


@runtime_checkable
class AttributeProvider(Protocol):
    def resolve(self, identity: Identity,
                attributes: Mapping) -> Optional[str]:
        """The worker key in `attributes` this identity is, or None.

        `attributes` is the request snapshot's read-only username ->
        record mapping (MappingProxyType all the way down): providers
        can't change it. RBICEngine.ask() passes a plain Identity whose
        fields are plain str (or None)."""


class JsonAttributeProvider:
    """Maps an identity to a worker by email.

    The identity's email and each worker record's `email` field are
    compared through gate.normalize_email: ASCII whitespace stripped, a
    plain ASCII address required (anything non-ASCII - a U+017F long s, a
    Kelvin sign, a fullwidth @, a zero-width or Unicode space - matches no
    one), then ASCII-lowercased; never casefolded, which would map such
    lookalikes onto a real worker's address. The gate's loader guarantees
    worker emails are well-formed and unique (a duplicate fails the load,
    which denies everyone), and refuses to serve a broken snapshot;
    uniqueness is re-checked here anyway, so an ambiguous match resolves
    to no one. No email, an invalid email, or no match -> None.
    """

    def resolve(self, identity: Identity,
                attributes: Mapping) -> Optional[str]:
        wanted = normalize_email(getattr(identity, "email", None))
        if not wanted:
            return None
        matches = [username for username, record in attributes.items()
                   if isinstance(record, Mapping)
                   and normalize_email(record.get("email")) == wanted]
        return matches[0] if len(matches) == 1 else None


class LocalProvider:
    """The subject IS the worker key.

    For the local CLI and tests only: whoever can set the subject can be
    any worker. Hosts serving web users must never use it - map
    authenticated sessions with JsonAttributeProvider (or a provider backed
    by the real IdP) instead.
    """

    def resolve(self, identity: Identity,
                attributes: Mapping) -> Optional[str]:
        subject = getattr(identity, "subject", None)
        if not isinstance(subject, str) or not subject:
            return None
        return subject if subject in attributes else None
