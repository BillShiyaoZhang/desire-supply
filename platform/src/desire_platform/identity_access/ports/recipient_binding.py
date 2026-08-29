"""Recipient canonicalization boundary shared by invitations and OIDC."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class RecipientBindingTuple:
    contact_type: str
    binding_digest: str = field(repr=False)
    digest_key_id: str


class RecipientBindingPort(Protocol):
    def bind_verified(
        self,
        *,
        contact_type: str,
        verified_locator: str,
    ) -> RecipientBindingTuple:
        """Canonicalize one verified provider locator without exposing it."""
