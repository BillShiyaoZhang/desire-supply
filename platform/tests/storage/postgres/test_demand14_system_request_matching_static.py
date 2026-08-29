"""Static closure checks for system-owned RequestMatching."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)
from tests.support.demand_postgres_builders import postgres_command


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
)
MIGRATION = MIGRATION_ROOT / "0014_expand__system_request_matching.sql"


def test_demand14_remains_registered_byte_exact_below_the_reviewed_head() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[13]

    assert DEMAND_SCHEMA_HEAD_VERSION == 15
    assert DEMAND_MIGRATION_LAYOUT[13] == (
        14,
        DemandMigrationPhase.EXPAND,
        "system_request_matching",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert catalog.manifest_sha256 == DEMAND_REVIEWED_MANIFEST_SHA256


def test_system_program_uses_system_identity_without_review_assignment() -> None:
    command = postgres_command(DemandPostgresOperation.REQUEST_MATCHING_SYSTEM)

    assert command.scope.actor_kind == "SYSTEM"
    assert command.scope.session_id is None
    assert command.assignment_id is None
    assert command.receipt is not None
    assert command.receipt.principal_kind == "SYSTEM"
    assert command.receipt.principal_id == command.scope.actor_id
    assert command.receipt.command_name == "RequestMatching"

    with pytest.raises(ValueError, match="cannot carry an assignment"):
        command.__class__(
            **{
                **command.__dict__,
                "assignment_id": command.scope.command_id,
            }
        )


def test_system_grants_and_rls_are_operation_scoped() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "principal_kind IN ('USER', 'SYSTEM')",
        "GRANT SELECT ON demand.demand_funding_markers TO demand_system",
        "GRANT SELECT, INSERT ON demand.matching_requests TO demand_system",
        "GRANT SELECT, INSERT, UPDATE ON demand.command_receipts TO demand_system",
        "CREATE POLICY rls_demand_funding_system_matching",
        "CREATE POLICY rls_demand_matching_system_read",
        "CREATE POLICY rls_demand_matching_system_insert",
        "CREATE POLICY rls_demand_receipt_system_matching",
        "= 'DEMAND_SYSTEM'",
        "= 'REQUEST_MATCHING'",
    ):
        assert marker in sql
    assert "GRANT DELETE" not in sql
