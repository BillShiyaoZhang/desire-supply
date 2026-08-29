"""Verification boundary for a versioned AccessInvitation capability."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class VerifiedAccessInvitationCapability:
    invitation_id: str
    invitation_nonce: str = field(repr=False)
    expires_at: datetime
    token_key_id: str
    token_format_version: str


class AccessInvitationCapabilityPort(Protocol):
    def verify(
        self,
        *,
        access_invitation_token: str,
        now: datetime,
    ) -> VerifiedAccessInvitationCapability:
        """Authenticate a token; business invitation facts remain database-owned."""
