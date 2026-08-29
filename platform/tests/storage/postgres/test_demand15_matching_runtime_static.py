"""Static closure checks for the reviewed Demand15 Matching programs."""

from __future__ import annotations

import hashlib
from pathlib import Path

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_MIGRATION_LAYOUT,
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_REVIEWED_MANIFEST_SHA256,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandMigrationCatalog,
    DemandMigrationPhase,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = PLATFORM_ROOT / "src/desire_platform/demand/adapters/postgres/migrations"
MIGRATION = MIGRATION_ROOT / "0015_expand__matching_completion_and_delivery.sql"


def test_demand15_is_the_registered_reviewed_head() -> None:
    catalog = DemandMigrationCatalog.load(MIGRATION_ROOT)
    artifact = catalog.artifacts[-1]

    assert DEMAND_SCHEMA_HEAD_VERSION == 15
    assert DEMAND_REQUIRED_IAM_SCHEMA_VERSION == 45
    assert DEMAND_MIGRATION_LAYOUT[-1] == (
        15,
        DemandMigrationPhase.EXPAND,
        "matching_completion_and_delivery",
        MIGRATION.name,
    )
    assert artifact.descriptor.checksum_sha256 == hashlib.sha256(
        MIGRATION.read_bytes()
    ).digest()
    assert artifact.descriptor.checksum_sha256.hex() == (
        "d095b37927b0e3b10dfe42b032044736276df830986493b03d1580f3d3a2fa34"
    )
    assert catalog.manifest_sha256 == DEMAND_REVIEWED_MANIFEST_SHA256
    assert catalog.manifest_sha256.hex() == (
        "32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73"
    )


def test_demand15_programs_are_fixed_role_bound_and_trace_uuid_exact() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    for marker in (
        "CREATE FUNCTION demand_api.claim_matching_requested_delivery_v1(",
        "CREATE FUNCTION demand_api.complete_matching_requested_delivery_v1(",
        "CREATE FUNCTION demand_api.fail_matching_requested_delivery_v1(",
        "CREATE FUNCTION demand_api.execute_complete_selection_system_v1(",
        "CREATE FUNCTION demand_api.execute_close_matching_without_selection_system_v1(",
        "exact_trace_id uuid",
        "session_user IS DISTINCT FROM 'matching_coordinator'",
        "FOR UPDATE SKIP LOCKED",
        "DemandMatchingClosedWithoutSelection",
        "DemandMatched",
        "original_actor_user_id uuid",
        "event.actor_kind = 'USER'",
        "event.actor_kind = 'SYSTEM'",
        "REVOKE ALL ON FUNCTION demand_api.execute_complete_selection_system_v1(",
        "REVOKE ALL ON FUNCTION demand_api.execute_close_matching_without_selection_system_v1(",
    ):
        assert marker in sql
    assert "exact_trace_id varchar" not in sql
    assert "GRANT SELECT ON demand." not in sql
