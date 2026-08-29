"""Install the exact reviewed Profile/Demand/Trust heads Matching v3 reads."""

from __future__ import annotations

from pathlib import Path

import psycopg

from desire_platform.creator_profile.adapters.postgres.migrations import (
    ProfileContractSources,
    ProfileMigrationCatalog,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    PsycopgTrustMigrationDriver,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationRunner,
    TrustMigrationSettings,
)


def install_matching_runtime_dependencies(
    *, postgres, database: str, platform_root: Path
) -> None:
    """Install Profile5, Demand15, and Trust22 after the caller installs IAM46."""

    source_root = platform_root / "src/desire_platform"
    contracts = platform_root / "contracts"
    PsycopgCreatorProfileMigrationRunner(
        conninfo=postgres.conninfo(
            database=database, user="profile_migration_runner"
        ),
        dbapi=psycopg,
        runner_version="matching-dependencies-profile/1",
    ).run(
        catalog=ProfileMigrationCatalog.load(
            source_root / "creator_profile/adapters/postgres/migrations"
        ),
        contract_sources=ProfileContractSources(
            api_contract_bytes=(contracts / "api/profile-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(
                contracts / "events/profile-v1.schema.json"
            ).read_bytes(),
            domain_contract_bytes=(
                contracts / "domain/profile-version-v1.schema.json"
            ).read_bytes(),
        ),
    )
    DemandMigrationRunner(
        driver=PsycopgDemandMigrationDriver(
            settings=DemandMigrationSettings(
                conninfo=postgres.conninfo(
                    database=database, user="demand_migration_runner"
                ),
                application_name="matching-dependencies-demand",
            ),
            dbapi=psycopg,
        ),
        runner_version="matching-dependencies-demand/1",
    ).run(
        catalog=DemandMigrationCatalog.load(
            source_root / "demand/adapters/postgres/migrations"
        ),
        contract_sources=DemandContractSources(
            api_contract_bytes=(contracts / "api/demand-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(
                contracts / "events/demand-v1.schema.json"
            ).read_bytes(),
            content_contract_bytes=(
                contracts / "domain/demand-content-v1.schema.json"
            ).read_bytes(),
        ),
    )
    TrustMigrationRunner(
        driver=PsycopgTrustMigrationDriver(
            settings=TrustMigrationSettings(
                conninfo=postgres.conninfo(
                    database=database, user="trust_migration_runner"
                ),
                application_name="matching-dependencies-trust",
            ),
            dbapi=psycopg,
        ),
        runner_version="matching-dependencies-trust/1",
    ).run(
        catalog=TrustMigrationCatalog.load(
            source_root / "trust_safety/adapters/postgres/migrations"
        ),
        contract_sources=TrustContractSources(
            api_contract_bytes=(contracts / "api/trust-v1.openapi.yaml").read_bytes(),
            event_contract_bytes=(
                contracts / "events/trust-v1.schema.json"
            ).read_bytes(),
            report_contract_bytes=(
                contracts / "domain/trust-report-v1.schema.json"
            ).read_bytes(),
            triage_contract_bytes=(
                contracts / "domain/trust-triage-v1.schema.json"
            ).read_bytes(),
            appeal_api_contract_bytes=(
                contracts / "api/appeal-v1.openapi.yaml"
            ).read_bytes(),
            appeal_event_contract_bytes=(
                contracts / "events/appeal-v1.schema.json"
            ).read_bytes(),
            appeal_application_contract_bytes=(
                contracts / "domain/appeal-application-v1.schema.json"
            ).read_bytes(),
            appeal_review_contract_bytes=(
                contracts / "domain/appeal-review-v1.schema.json"
            ).read_bytes(),
        ),
    )


__all__ = ("install_matching_runtime_dependencies",)
