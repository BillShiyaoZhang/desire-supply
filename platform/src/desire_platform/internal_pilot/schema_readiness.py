"""Exact online-role checks for reviewed PostgreSQL schema contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Tuple


_STATEMENTS = {
    "iam": (
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "combined_contract_sha256 FROM infra.iam_schema_compatibility"
    ),
    "profile": (
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "migration_manifest_sha256 FROM profile.schema_compatibility"
    ),
    "demand": (
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version,migration_manifest_sha256,"
        "policy.active_idempotency_key_id,policy.active_payload_key_id,"
        "policy.retained_idempotency_key_ids,policy.retained_payload_key_ids "
        "FROM demand.schema_compatibility CROSS JOIN "
        "demand.receipt_key_policy AS policy WHERE policy.singleton_key"
    ),
    "trust": (
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version,required_demand_schema_version,"
        "required_iam_contract_sha256,required_demand_contract_sha256,"
        "combined_contract_sha256,migration_manifest_sha256 "
        "FROM trust.schema_compatibility"
    ),
    "matching": (
        "SELECT component,current_schema_version,schema_head_version,"
        "min_app_compatible_version,max_app_compatible_version,"
        "required_iam_schema_version,migration_manifest_sha256 "
        "FROM matching.schema_compatibility"
    ),
}


class SchemaCompatibilityError(RuntimeError):
    def __init__(self) -> None:
        self.code = "SCHEMA_NOT_READY"
        super().__init__(self.code)


@dataclass(frozen=True)
class SchemaCompatibilityRequirement:
    component: str
    expected_schema_head: int
    expected_contract_sha256: bytes = field(repr=False)
    required_iam_schema_version: Optional[int]
    expected_idempotency_key_id: Optional[str] = field(default=None, repr=False)
    expected_payload_key_id: Optional[str] = field(default=None, repr=False)
    expected_retained_idempotency_key_ids: Optional[Tuple[str, ...]] = field(
        default=None, repr=False
    )
    expected_retained_payload_key_ids: Optional[Tuple[str, ...]] = field(
        default=None, repr=False
    )
    required_demand_schema_version: Optional[int] = None
    expected_iam_contract_sha256: Optional[bytes] = field(
        default=None, repr=False
    )
    expected_demand_contract_sha256: Optional[bytes] = field(
        default=None, repr=False
    )
    expected_combined_contract_sha256: Optional[bytes] = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        if self.component not in _STATEMENTS:
            raise ValueError("schema component is not closed")
        if type(self.expected_schema_head) is not int or self.expected_schema_head < 1:
            raise ValueError("schema head is invalid")
        if (
            not isinstance(self.expected_contract_sha256, bytes)
            or len(self.expected_contract_sha256) != 32
        ):
            raise ValueError("schema contract digest is invalid")
        if self.component == "demand":
            if (
                type(self.required_iam_schema_version) is not int
                or self.required_iam_schema_version < 1
                or not _closed_key_id(self.expected_idempotency_key_id)
                or not _closed_key_id(self.expected_payload_key_id)
                or self.expected_idempotency_key_id
                == self.expected_payload_key_id
                or not _closed_retained_key_ids(
                    self.expected_retained_idempotency_key_ids,
                    self.expected_idempotency_key_id,
                )
                or not _closed_retained_key_ids(
                    self.expected_retained_payload_key_ids,
                    self.expected_payload_key_id,
                )
                or set(self.expected_retained_idempotency_key_ids).intersection(
                    self.expected_retained_payload_key_ids
                )
                or self.required_demand_schema_version is not None
                or self.expected_iam_contract_sha256 is not None
                or self.expected_demand_contract_sha256 is not None
                or self.expected_combined_contract_sha256 is not None
            ):
                raise ValueError("Demand IAM schema dependency is invalid")
        elif self.component == "trust":
            if (
                type(self.required_iam_schema_version) is not int
                or self.required_iam_schema_version < 1
                or type(self.required_demand_schema_version) is not int
                or self.required_demand_schema_version < 1
                or not _digest(self.expected_iam_contract_sha256)
                or not _digest(self.expected_demand_contract_sha256)
                or not _digest(self.expected_combined_contract_sha256)
                or self.expected_idempotency_key_id is not None
                or self.expected_payload_key_id is not None
                or self.expected_retained_idempotency_key_ids is not None
                or self.expected_retained_payload_key_ids is not None
            ):
                raise ValueError("Trust schema dependencies are invalid")
        elif self.component == "matching":
            if (
                type(self.required_iam_schema_version) is not int
                or self.required_iam_schema_version < 1
                or self.required_demand_schema_version is not None
                or self.expected_idempotency_key_id is not None
                or self.expected_payload_key_id is not None
                or self.expected_retained_idempotency_key_ids is not None
                or self.expected_retained_payload_key_ids is not None
                or self.expected_iam_contract_sha256 is not None
                or self.expected_demand_contract_sha256 is not None
                or self.expected_combined_contract_sha256 is not None
            ):
                raise ValueError("Matching IAM schema dependency is invalid")
        elif (
            self.required_iam_schema_version is not None
            or self.required_demand_schema_version is not None
            or self.expected_idempotency_key_id is not None
            or self.expected_payload_key_id is not None
            or self.expected_retained_idempotency_key_ids is not None
            or self.expected_retained_payload_key_ids is not None
            or self.expected_iam_contract_sha256 is not None
            or self.expected_demand_contract_sha256 is not None
            or self.expected_combined_contract_sha256 is not None
        ):
            raise ValueError("schema dependency is not valid for this component")


class PostgresSchemaCompatibilityReadiness:
    def __init__(self, *, pool: Any, requirement: SchemaCompatibilityRequirement) -> None:
        if not all(
            callable(getattr(pool, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("schema readiness pool is unavailable")
        if not isinstance(requirement, SchemaCompatibilityRequirement):
            raise TypeError("schema compatibility requirement is unavailable")
        self._pool = pool
        self._requirement = requirement
        self._closed = False

    @staticmethod
    def statement_for(component: str) -> str:
        try:
            return _STATEMENTS[component]
        except KeyError:
            raise ValueError("schema component is not closed") from None

    def check_readiness(self, *, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise ValueError("schema readiness timeout is outside bounds")
        if self._closed:
            raise SchemaCompatibilityError()
        connection = None
        transaction = False
        try:
            connection = self._pool.checkout()
            connection.execute("BEGIN TRANSACTION READ ONLY")
            transaction = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'" % timeout_ms
            )
            row = connection.execute(
                _STATEMENTS[self._requirement.component]
            ).fetchone()
            if not self._matches(row):
                raise RuntimeError("schema compatibility facts drifted")
            connection.execute("COMMIT")
            transaction = False
            self._pool.release(connection)
            connection = None
            return None
        except BaseException:
            if connection is not None:
                try:
                    if transaction:
                        connection.execute("ROLLBACK")
                except BaseException:
                    pass
                self._pool.discard(connection)
            raise SchemaCompatibilityError() from None

    def _matches(self, row: Any) -> bool:
        required = self._requirement
        if required.component == "demand":
            if not isinstance(row, tuple) or len(row) != 11:
                return False
            (
                component,
                current,
                head,
                minimum,
                maximum,
                iam_head,
                digest,
                active_idempotency_key_id,
                active_payload_key_id,
                retained_idempotency_key_ids,
                retained_payload_key_ids,
            ) = row
            dependency_matches = (
                iam_head == required.required_iam_schema_version
                and active_idempotency_key_id
                == required.expected_idempotency_key_id
                and active_payload_key_id == required.expected_payload_key_id
                and _exact_retained_key_ids(
                    retained_idempotency_key_ids,
                    required.expected_retained_idempotency_key_ids,
                )
                and _exact_retained_key_ids(
                    retained_payload_key_ids,
                    required.expected_retained_payload_key_ids,
                )
            )
        elif required.component == "trust":
            if not isinstance(row, tuple) or len(row) != 11:
                return False
            (
                component,
                current,
                head,
                minimum,
                maximum,
                iam_head,
                demand_head,
                iam_contract,
                demand_contract,
                combined_contract,
                digest,
            ) = row
            dependency_matches = (
                iam_head == required.required_iam_schema_version
                and demand_head == required.required_demand_schema_version
                and iam_contract == required.expected_iam_contract_sha256
                and demand_contract == required.expected_demand_contract_sha256
                and combined_contract == required.expected_combined_contract_sha256
            )
        elif required.component == "matching":
            if not isinstance(row, tuple) or len(row) != 7:
                return False
            (
                component,
                current,
                head,
                minimum,
                maximum,
                iam_head,
                digest,
            ) = row
            dependency_matches = (
                iam_head == required.required_iam_schema_version
            )
        else:
            if not isinstance(row, tuple) or len(row) != 6:
                return False
            component, current, head, minimum, maximum, digest = row
            dependency_matches = True
        return (
            component == required.component
            and current == required.expected_schema_head
            and head == required.expected_schema_head
            and minimum <= required.expected_schema_head <= maximum
            and dependency_matches
            and isinstance(digest, bytes)
            and digest == required.expected_contract_sha256
        )

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return (
            "PostgresSchemaCompatibilityReadiness("
            f"component={self._requirement.component!r}, closed={self._closed}, "
            "contract=<redacted>)"
        )


def _closed_key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value == value.strip()
        and value.isascii()
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _digest(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 32


def _closed_retained_key_ids(values: Any, active: Optional[str]) -> bool:
    return (
        type(values) is tuple
        and 1 <= len(values) <= 4
        and values[0] == active
        and len(values) == len(set(values))
        and all(_closed_key_id(value) for value in values)
    )


def _exact_retained_key_ids(
    values: Any, expected: Optional[Tuple[str, ...]]
) -> bool:
    return (
        isinstance(values, (list, tuple))
        and expected is not None
        and tuple(values) == expected
        and all(_closed_key_id(value) for value in values)
    )


__all__ = [
    "PostgresSchemaCompatibilityReadiness",
    "SchemaCompatibilityError",
    "SchemaCompatibilityRequirement",
]
