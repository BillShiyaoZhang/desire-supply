"""Static RED contracts for upgrade-safe editor target discovery catalogs."""

from __future__ import annotations

from pathlib import Path

from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileMigrationCatalog,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DemandMigrationCatalog,
)


ROOT = Path(__file__).resolve().parents[3]
PROFILE_ROOT = (
    ROOT / "src/desire_platform/creator_profile/adapters/postgres/migrations"
)
DEMAND_ROOT = ROOT / "src/desire_platform/demand/adapters/postgres/migrations"


def test_profile_v2_is_narrow_self_discovery_and_online_compatibility() -> None:
    sql = (PROFILE_ROOT / "0002_expand__editor_target_discovery.sql").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "profile_api.list_owned_profile_targets_v1",
        "SECURITY DEFINER",
        "session_user IS DISTINCT FROM 'profile_app'",
        "iam_api.verify_editor_principal_marker_v1",
        "owner_user_id = exact_actor_user_id",
        "GRANT SELECT ON profile.schema_compatibility TO profile_app",
        "GRANT EXECUTE ON FUNCTION profile_api.list_owned_profile_targets_v1",
    ):
        assert fragment in sql
    lowered = sql.lower()
    for forbidden in (
        "grant select on iam.",
        "bypassrls",
        "execute format",
        "demand.",
    ):
        assert forbidden not in lowered


def test_demand_v2_owner_and_independent_reviewer_discovery_are_separate() -> None:
    sql = (DEMAND_ROOT / "0002_expand__editor_target_discovery.sql").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "demand_api.list_owned_demand_targets_v1",
        "demand_api.list_reviewer_demand_targets_v1",
        "session_user IS DISTINCT FROM 'demand_self'",
        "session_user IS DISTINCT FROM 'demand_review'",
        "creator_user_id = exact_actor_user_id",
        "reviewer_user_id = exact_actor_user_id",
        "assignment.status = 'ACTIVE'",
        "transaction_timestamp() < assignment.expires_at",
        "iam_api.verify_editor_principal_marker_v1",
    ):
        assert fragment in sql
    lowered = sql.lower()
    for forbidden in (
        "grant select on iam.",
        "bypassrls",
        "execute format",
        "profile.",
    ):
        assert forbidden not in lowered


def test_catalog_runners_are_upgrade_safe_and_require_exact_iam_minimums() -> None:
    profile_runner = (PROFILE_ROOT / "runner.py").read_text(encoding="utf-8")
    demand_runner = (DEMAND_ROOT / "runner.py").read_text(encoding="utf-8")
    # Profile5 requires IAM0046 versioned Creator match eligibility evidence;
    # current Demand additionally requires IAM0043 release authority.
    assert "PROFILE_REQUIRED_IAM_SCHEMA_VERSION = 46" in profile_runner
    assert "DEMAND_REQUIRED_IAM_SCHEMA_VERSION = 43" in demand_runner
    for runner in (profile_runner, demand_runner):
        assert "artifact.descriptor.checksum_sha256" in runner
        assert "ON CONFLICT (singleton_key) DO UPDATE" in runner
        assert "catalog.manifest_sha256" in runner
        assert "descriptor.prefix_manifest_sha256" in runner


def test_historical_ledger_hash_is_exact_reviewed_catalog_prefix() -> None:
    cases = (
        (
            ProfileMigrationCatalog.load(PROFILE_ROOT),
            "15eeba951b2b41bcb81ef4df07664ac28701c3ca13a7e070e3745365d55da65f",
        ),
        (
            DemandMigrationCatalog.load(DEMAND_ROOT),
            "568db4604acbad7c96d7460227311683f5acb108b5c77f597d263374e8fadaf0",
        ),
    )
    for catalog, reviewed_v1_manifest in cases:
        assert len(catalog.artifacts) >= 2
        assert (
            catalog.artifacts[0].descriptor.prefix_manifest_sha256.hex()
            == reviewed_v1_manifest
        )
        assert (
            catalog.artifacts[-1].descriptor.prefix_manifest_sha256
            == catalog.manifest_sha256
        )
