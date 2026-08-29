"""Closed application values for editing a public organization profile field.

The public name is deliberately the only editable field in this command.  The
organization identity, status, type, jurisdiction, actor authority, and
authentication strength remain server-owned facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
import unicodedata
from typing import Any, Mapping, Optional, Tuple


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$")


class OrganizationPublicNameReasonCode(str, Enum):
    PUBLIC_NAME_CORRECTION = "PUBLIC_NAME_CORRECTION"


@dataclass(frozen=True)
class OrganizationPublicNameActorContext:
    actor_user_id: str
    current_session_id: str
    original_actor_id: Optional[str]
    correlation_id: str
    causation_id: str
    trace_id: str
    auth_time: datetime
    acr_code: str
    amr_codes: Tuple[str, ...]

    def __post_init__(self) -> None:
        required = (
            self.actor_user_id,
            self.current_session_id,
            self.correlation_id,
            self.causation_id,
            self.trace_id,
            self.acr_code,
        )
        if any(not isinstance(value, str) or not value for value in required):
            raise ValueError("organization public-name actor is invalid")
        if self.original_actor_id is not None and (
            not isinstance(self.original_actor_id, str)
            or not self.original_actor_id
            or self.original_actor_id == self.actor_user_id
        ):
            raise ValueError("organization public-name original actor is invalid")
        if (
            not isinstance(self.auth_time, datetime)
            or self.auth_time.tzinfo is None
            or self.auth_time.utcoffset() != timedelta(0)
            or not isinstance(self.amr_codes, tuple)
            or not self.amr_codes
            or len(set(self.amr_codes)) != len(self.amr_codes)
            or any(not isinstance(code, str) or not code for code in self.amr_codes)
        ):
            raise ValueError("organization public-name authentication is invalid")


@dataclass(frozen=True, repr=False)
class UpdateOrganizationPublicNameCommand:
    organization_id: str
    expected_version: int
    public_name: str
    reason_code: OrganizationPublicNameReasonCode
    idempotency_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.organization_id, str) or not self.organization_id:
            raise ValueError("organization public-name target is invalid")
        if (
            not isinstance(self.expected_version, int)
            or isinstance(self.expected_version, bool)
            or self.expected_version < 1
        ):
            raise ValueError("organization public-name If-Match is invalid")
        if (
            not isinstance(self.public_name, str)
            or not 1 <= len(self.public_name) <= 160
            or self.public_name != self.public_name.strip()
            or unicodedata.normalize("NFC", self.public_name) != self.public_name
            or any(
                unicodedata.category(character) in {"Cc", "Cf"}
                for character in self.public_name
            )
        ):
            raise ValueError("organization public name is invalid")
        if self.reason_code is not OrganizationPublicNameReasonCode.PUBLIC_NAME_CORRECTION:
            raise ValueError("organization public-name reason is invalid")
        if (
            not isinstance(self.idempotency_key, str)
            or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
        ):
            raise ValueError("organization public-name idempotency key is invalid")


@dataclass(frozen=True, repr=False)
class UpdateOrganizationPublicNameResult:
    replayed: bool
    organization: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.replayed, bool) or not isinstance(
            self.organization, Mapping
        ):
            raise ValueError("organization public-name result is invalid")


__all__ = [
    "OrganizationPublicNameActorContext",
    "OrganizationPublicNameReasonCode",
    "UpdateOrganizationPublicNameCommand",
    "UpdateOrganizationPublicNameResult",
]
