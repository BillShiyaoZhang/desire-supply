"""RED/GREEN contract for the independent Trust migration runner."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REVIEWED_MANIFEST_SHA256,
)
from desire_platform.trust_safety.adapters.postgres.migrations.catalog import (
    TrustMigrationCatalog,
)
from desire_platform.trust_safety.adapters.postgres.migrations.runner import (
    _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    PsycopgTrustMigrationDriver,
    TRUST_APPEAL_API_CONTRACT_SHA256,
    TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
    TRUST_APPEAL_EVENT_CONTRACT_SHA256,
    TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
    TRUST_API_CONTRACT_SHA256,
    TRUST_EVENT_CONTRACT_SHA256,
    TRUST_REPORT_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
    TRUST_SCHEMA_HEAD_VERSION,
    TRUST_TRIAGE_CONTRACT_SHA256,
    TrustContractSources,
    TrustMigrationRunner,
    TrustMigrationRunnerError,
    TrustMigrationSettings,
    combined_contract_sha256,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
TRUST_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/trust_safety/adapters/postgres/migrations"
)


def _actual_sources() -> TrustContractSources:
    contract_root = PLATFORM_ROOT / "contracts"
    return TrustContractSources(
        api_contract_bytes=(contract_root / "api/trust-v1.openapi.yaml").read_bytes(),
        event_contract_bytes=(
            contract_root / "events/trust-v1.schema.json"
        ).read_bytes(),
        report_contract_bytes=(
            contract_root / "domain/trust-report-v1.schema.json"
        ).read_bytes(),
        triage_contract_bytes=(
            contract_root / "domain/trust-triage-v1.schema.json"
        ).read_bytes(),
        appeal_api_contract_bytes=(
            contract_root / "api/appeal-v1.openapi.yaml"
        ).read_bytes(),
        appeal_event_contract_bytes=(
            contract_root / "events/appeal-v1.schema.json"
        ).read_bytes(),
        appeal_application_contract_bytes=(
            contract_root / "domain/appeal-application-v1.schema.json"
        ).read_bytes(),
        appeal_review_contract_bytes=(
            contract_root / "domain/appeal-review-v1.schema.json"
        ).read_bytes(),
    )


def test_runner_pins_exact_direct_iam46_and_demand15_dependency_contracts() -> None:
    assert TRUST_SCHEMA_HEAD_VERSION == 22
    assert TRUST_REQUIRED_IAM_SCHEMA_VERSION == 46
    assert TRUST_REQUIRED_DEMAND_SCHEMA_VERSION == 15
    assert _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION == 45
    assert TRUST_REQUIRED_IAM_CONTRACT_SHA256.hex() == (
        "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
    )
    assert TRUST_REQUIRED_DEMAND_CONTRACT_SHA256.hex() == (
        "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf"
    )
    assert TRUST_API_CONTRACT_SHA256.hex() == (
        "6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2"
    )
    assert TRUST_EVENT_CONTRACT_SHA256.hex() == (
        "a26c410ca62c6d996fd13148863935729f480ca1a1fd9a44378a96ab13eae582"
    )
    assert TRUST_REPORT_CONTRACT_SHA256.hex() == (
        "29b0c97a576edf654b5517847c73ce7a059141158182b16008f2cce3ef996278"
    )
    assert TRUST_TRIAGE_CONTRACT_SHA256.hex() == (
        "de45a368bc75f7523e9135b83f61ab8753581a1e775cffe943c7a70cbe6f3084"
    )
    assert TRUST_APPEAL_API_CONTRACT_SHA256.hex() == (
        "ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46"
    )
    assert TRUST_APPEAL_EVENT_CONTRACT_SHA256.hex() == (
        "7d3916ab89ace8c677da6ba6b6b5a65cfae28b8d91cf0c71fc0b0d9a88a064ba"
    )
    assert TRUST_APPEAL_APPLICATION_CONTRACT_SHA256.hex() == (
        "3549b053c911da3b5bf5b526c8abfc9e1ef9cdafd1f81e177d43cb412cab8223"
    )
    assert TRUST_APPEAL_REVIEW_CONTRACT_SHA256.hex() == (
        "08982687c6654d606040c52faedc15a14b7b50e1c5c80db560587bbf3e16f72b"
    )
    assert TRUST_REVIEWED_COMBINED_CONTRACT_SHA256.hex() == (
        "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
    )


def test_contract_digest_is_domain_separated_and_manifest_bound() -> None:
    sources = TrustContractSources(
        api_contract_bytes=b"api",
        event_contract_bytes=b"event",
        report_contract_bytes=b"report",
        triage_contract_bytes=b"triage",
        appeal_api_contract_bytes=b"appeal-api",
        appeal_event_contract_bytes=b"appeal-event",
        appeal_application_contract_bytes=b"appeal-application",
        appeal_review_contract_bytes=b"appeal-review",
    )
    first = combined_contract_sha256(
        sources=sources,
        migration_manifest_sha256=hashlib.sha256(b"manifest-one").digest(),
    )
    second = combined_contract_sha256(
        sources=sources,
        migration_manifest_sha256=hashlib.sha256(b"manifest-two").digest(),
    )
    assert len(first) == 32
    assert first != second


def test_runner_settings_fail_closed() -> None:
    with pytest.raises(TrustMigrationRunnerError) as error:
        TrustMigrationSettings(conninfo="")
    assert error.value.code == "TRUST_MIGRATION_CONFIGURATION_INVALID"


class _Cursor:
    def __init__(self, *, row=None, rows=()) -> None:
        self._row = row
        self._rows = rows

    def fetchone(self):
        return self._row

    def fetchall(self):
        return self._rows


class _DatabaseState:
    def __init__(self) -> None:
        self.schema_exists = False
        self.ledger_exists = False
        self.ledger_rows = []
        self.schema_contract_parameters = None
        self.capability_query = ""
        self.iam_schema_version = TRUST_REQUIRED_IAM_SCHEMA_VERSION
        self.iam_contract_sha256 = TRUST_REQUIRED_IAM_CONTRACT_SHA256
        self.demand_schema_version = TRUST_REQUIRED_DEMAND_SCHEMA_VERSION
        self.demand_required_iam_schema_version = (
            _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION
        )
        self.demand_contract_sha256 = TRUST_REQUIRED_DEMAND_CONTRACT_SHA256


class _Connection:
    def __init__(self, state: _DatabaseState) -> None:
        self.state = state

    def execute(self, query, parameters=None):
        if query.startswith("SELECT session_user"):
            return _Cursor(
                row=("trust_migration_runner", "trust_migration_runner", 18)
            )
        if "FROM infra.iam_schema_compatibility" in query:
            return _Cursor(
                row=(
                    self.state.iam_schema_version,
                    self.state.iam_schema_version,
                    self.state.iam_schema_version,
                    self.state.iam_schema_version,
                    self.state.iam_contract_sha256,
                )
            )
        if "FROM demand.trust_schema_dependency_v1" in query:
            return _Cursor(
                row=(
                    "demand",
                    self.state.demand_schema_version,
                    self.state.demand_schema_version,
                    self.state.demand_schema_version,
                    self.state.demand_schema_version,
                    self.state.demand_required_iam_schema_version,
                    bytes.fromhex(
                        "046561ae51d147e8df3b8fcf0b61f1dd922efe452175e63f128a937e8f11c4ff"
                    ),
                    bytes.fromhex(
                        "46631be37cb70aea771d2103e1fe39dc39f3f4303239ae1dc6e55fa946d1059c"
                    ),
                    bytes.fromhex(
                        "4a3316ca66f58e92d23b946226b235578ad77e247f92f72863aa8f76c5b5c631"
                    ),
                    DEMAND_REVIEWED_MANIFEST_SHA256,
                    self.state.demand_contract_sha256,
                )
            )
        if query.startswith("SELECT pg_catalog.to_regprocedure"):
            self.state.capability_query = query
            return _Cursor(row=(True, True, True, True, True, True))
        if query.startswith("SELECT pg_catalog.to_regnamespace"):
            return _Cursor(
                row=(self.state.schema_exists, self.state.ledger_exists)
            )
        if "FROM trust_meta.schema_migrations" in query:
            return _Cursor(rows=tuple(self.state.ledger_rows))
        if query.startswith("INSERT INTO trust_meta.schema_migrations"):
            self.state.schema_exists = True
            self.state.ledger_exists = True
            self.state.ledger_rows.append(tuple(parameters[:5]))
            return _Cursor()
        if query.startswith("INSERT INTO trust_meta.schema_contracts"):
            self.state.schema_contract_parameters = tuple(parameters)
            return _Cursor()
        if "FROM trust.schema_compatibility" in query:
            return _Cursor(
                row=(
                    "trust",
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_SCHEMA_HEAD_VERSION,
                    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
                    TRUST_REQUIRED_IAM_CONTRACT_SHA256,
                    TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
                    TRUST_REVIEWED_COMBINED_CONTRACT_SHA256,
                    TrustMigrationCatalog.load(TRUST_ROOT).manifest_sha256,
                )
            )
        return _Cursor()

    def close(self) -> None:
        pass


class _DbApi:
    def __init__(self, state: _DatabaseState) -> None:
        self.state = state

    def connect(self, *_args, **_kwargs):
        return _Connection(self.state)


def _runner(state: _DatabaseState) -> TrustMigrationRunner:
    return TrustMigrationRunner(
        driver=PsycopgTrustMigrationDriver(
            settings=TrustMigrationSettings(conninfo="postgresql://reviewed"),
            dbapi=_DbApi(state),
        ),
        runner_version="trust-runner-unit/2",
    )


def test_runner_official_first_apply_and_second_skip_shape() -> None:
    catalog = TrustMigrationCatalog.load(TRUST_ROOT)
    sources = _actual_sources()
    state = _DatabaseState()

    first = _runner(state).run(catalog=catalog, contract_sources=sources)
    replay = _runner(state).run(catalog=catalog, contract_sources=sources)

    assert first.applied_versions == tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1))
    assert first.skipped_versions == ()
    assert replay.applied_versions == ()
    assert replay.skipped_versions == tuple(range(1, TRUST_SCHEMA_HEAD_VERSION + 1))
    assert tuple(row[4] for row in state.ledger_rows) == tuple(
        artifact.descriptor.prefix_manifest_sha256
        for artifact in catalog.artifacts
    )
    assert state.schema_contract_parameters is not None
    assert len(state.schema_contract_parameters) == 17
    assert state.schema_contract_parameters[3:7] == (
        TRUST_REQUIRED_IAM_SCHEMA_VERSION,
        TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
        TRUST_REQUIRED_IAM_CONTRACT_SHA256,
        TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
    )
    assert state.schema_contract_parameters[11:15] == (
        TRUST_APPEAL_API_CONTRACT_SHA256,
        TRUST_APPEAL_EVENT_CONTRACT_SHA256,
        TRUST_APPEAL_APPLICATION_CONTRACT_SHA256,
        TRUST_APPEAL_REVIEW_CONTRACT_SHA256,
    )
    assert "resolve_appeal_reviewer_authority_v1" in state.capability_query
    assert "resolve_appeal_applicant_party_v1" in state.capability_query


def test_runner_upgrades_an_exact_trust0001_prefix_forward_only() -> None:
    catalog = TrustMigrationCatalog.load(TRUST_ROOT)
    first = catalog.artifacts[0].descriptor
    state = _DatabaseState()
    state.schema_exists = True
    state.ledger_exists = True
    state.ledger_rows.append(
        (
            first.version,
            first.phase.value,
            first.name,
            first.checksum_sha256,
            first.prefix_manifest_sha256,
        )
    )

    report = _runner(state).run(
        catalog=catalog,
        contract_sources=_actual_sources(),
    )

    assert report.applied_versions == tuple(range(2, TRUST_SCHEMA_HEAD_VERSION + 1))
    assert report.skipped_versions == (1,)


def test_runner_upgrades_an_exact_trust0002_prefix_through_current_head() -> None:
    catalog = TrustMigrationCatalog.load(TRUST_ROOT)
    state = _DatabaseState()
    state.schema_exists = True
    state.ledger_exists = True
    state.ledger_rows.extend(
        (
            artifact.descriptor.version,
            artifact.descriptor.phase.value,
            artifact.descriptor.name,
            artifact.descriptor.checksum_sha256,
            artifact.descriptor.prefix_manifest_sha256,
        )
        for artifact in catalog.artifacts[:2]
    )

    report = _runner(state).run(
        catalog=catalog,
        contract_sources=_actual_sources(),
    )

    assert report.applied_versions == tuple(range(3, TRUST_SCHEMA_HEAD_VERSION + 1))
    assert report.skipped_versions == (1, 2)


def test_runner_upgrades_an_exact_trust0004_prefix_through_current_head() -> None:
    catalog = TrustMigrationCatalog.load(TRUST_ROOT)
    state = _DatabaseState()
    state.schema_exists = True
    state.ledger_exists = True
    state.ledger_rows.extend(
        (
            artifact.descriptor.version,
            artifact.descriptor.phase.value,
            artifact.descriptor.name,
            artifact.descriptor.checksum_sha256,
            artifact.descriptor.prefix_manifest_sha256,
        )
        for artifact in catalog.artifacts[:4]
    )

    report = _runner(state).run(
        catalog=catalog,
        contract_sources=_actual_sources(),
    )

    assert report.applied_versions == tuple(range(5, TRUST_SCHEMA_HEAD_VERSION + 1))
    assert report.skipped_versions == (1, 2, 3, 4)


@pytest.mark.parametrize(
    "iam_schema_version,iam_contract_sha256",
    (
        (TRUST_REQUIRED_IAM_SCHEMA_VERSION - 1, TRUST_REQUIRED_IAM_CONTRACT_SHA256),
        (TRUST_REQUIRED_IAM_SCHEMA_VERSION, b"i" * 32),
    ),
)
def test_runner_rejects_direct_previous_iam_or_contract_drift(
    iam_schema_version: int,
    iam_contract_sha256: bytes,
) -> None:
    state = _DatabaseState()
    state.iam_schema_version = iam_schema_version
    state.iam_contract_sha256 = iam_contract_sha256

    with pytest.raises(TrustMigrationRunnerError) as error:
        _runner(state).run(
            catalog=TrustMigrationCatalog.load(TRUST_ROOT),
            contract_sources=_actual_sources(),
        )

    assert error.value.code == "TRUST_MIGRATION_IAM_DEPENDENCY_UNAVAILABLE"
    assert state.ledger_rows == []


@pytest.mark.parametrize(
    "demand_schema_version,demand_required_iam_schema_version,demand_contract_sha256",
    (
        (
            TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
            _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION - 1,
            TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
        ),
        (
            9,
            _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
            TRUST_REQUIRED_DEMAND_CONTRACT_SHA256,
        ),
        (
            TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
            _EXPECTED_DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
            b"d" * 32,
        ),
    ),
)
def test_runner_rejects_demand_head_hash_or_transitive_iam_drift(
    demand_schema_version: int,
    demand_required_iam_schema_version: int,
    demand_contract_sha256: bytes,
) -> None:
    state = _DatabaseState()
    state.demand_schema_version = demand_schema_version
    state.demand_required_iam_schema_version = demand_required_iam_schema_version
    state.demand_contract_sha256 = demand_contract_sha256

    with pytest.raises(TrustMigrationRunnerError) as error:
        _runner(state).run(
            catalog=TrustMigrationCatalog.load(TRUST_ROOT),
            contract_sources=_actual_sources(),
        )

    assert error.value.code == "TRUST_MIGRATION_DEMAND_DEPENDENCY_UNAVAILABLE"
    assert state.ledger_rows == []
