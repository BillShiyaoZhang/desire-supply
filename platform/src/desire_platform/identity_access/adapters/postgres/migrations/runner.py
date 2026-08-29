"""Closed transactional protocol for applying reviewed IAM migrations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sys
from typing import Optional, Protocol, Tuple

from .catalog import (
    IAM_MIGRATION_LAYOUT,
    IAM_REVIEWED_MANIFEST_SHA256,
    MigrationArtifact,
    MigrationCatalog,
    MigrationCatalogError,
    MigrationDescriptor,
    MigrationPhase,
    _validate_sql_bytes,
)


IAM_MIGRATION_LOCK: Tuple[int, int] = (1229016369, 1)
IAM_MIGRATION_SESSION_ROLE = "iam_migration_runner"
IAM_MIGRATION_SCHEMA_ROLE = "schema_owner"
IAM_POSTGRES_MAJOR = 18
IAM_SCHEMA_HEAD_VERSION = IAM_MIGRATION_LAYOUT[-1][0]
IAM_MIN_APP_COMPATIBLE_VERSION = IAM_SCHEMA_HEAD_VERSION
IAM_MAX_APP_COMPATIBLE_VERSION = IAM_SCHEMA_HEAD_VERSION


class MigrationRunnerError(RuntimeError):
    """Stable, non-reflective runner rejection safe for deployment logs."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MigrationConnectionLost(ConnectionError):
    """The migration session is unusable and its session lock is server-released."""


class MigrationCommitOutcomeUnknown(MigrationConnectionLost):
    """COMMIT was sent, but its durable outcome was not acknowledged."""


@dataclass(frozen=True)
class MigrationLedgerRecord:
    component: str
    version: int
    phase: MigrationPhase
    name: str
    checksum_sha256: bytes

    @classmethod
    def from_descriptor(cls, descriptor: MigrationDescriptor) -> "MigrationLedgerRecord":
        return cls(
            component=descriptor.component,
            version=descriptor.version,
            phase=descriptor.phase,
            name=descriptor.name,
            checksum_sha256=descriptor.checksum_sha256,
        )


@dataclass(frozen=True)
class MigrationDatabaseState:
    ledger_exists: bool
    has_unledgered_iam_objects: bool
    applied_migrations: Tuple[MigrationLedgerRecord, ...]


@dataclass(frozen=True)
class IamContractSources:
    api_contract_bytes: bytes
    event_contract_bytes: bytes


@dataclass(frozen=True)
class IamContractParameters:
    component: str
    schema_head_version: int
    min_app_compatible_version: int
    max_app_compatible_version: int
    api_contract_sha256: bytes
    event_contract_sha256: bytes
    migration_manifest_sha256: bytes
    combined_contract_sha256: bytes


@dataclass(frozen=True)
class MigrationRunReport:
    applied_versions: Tuple[int, ...]
    recovered_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


class MigrationSession(Protocol):
    """Small transactional surface implemented by a deployment-only adapter."""

    def acquire_advisory_lock(self, key1: int, key2: int) -> None:
        ...

    def prepare_runner(self, *, schema_role: str, postgres_major: int) -> None:
        ...

    def inspect_database(self) -> MigrationDatabaseState:
        ...

    def begin_migration(self, descriptor: MigrationDescriptor) -> None:
        ...

    def set_local_timeouts(self) -> None:
        ...

    def execute_artifact(self, artifact: MigrationArtifact) -> None:
        ...

    def assert_artifact(self, descriptor: MigrationDescriptor) -> None:
        ...

    def insert_contract_row(self, parameters: IamContractParameters) -> None:
        """Insert with bind parameters; implementations must not interpolate SQL."""

        ...

    def read_contract_parameters(self) -> Optional[IamContractParameters]:
        """Read back the 0007 row inside its still-open transaction."""

        ...

    def insert_ledger_row(
        self,
        record: MigrationLedgerRecord,
        *,
        runner_version: str,
    ) -> None:
        ...

    def commit_migration(self) -> None:
        ...

    def rollback_migration(self) -> None:
        ...

    def read_ledger_record(
        self,
        *,
        component: str,
        version: int,
    ) -> Optional[MigrationLedgerRecord]:
        ...

    def release_advisory_lock(self, key1: int, key2: int) -> None:
        ...

    def close(self, *, discard: bool) -> None:
        ...


class MigrationDriver(Protocol):
    def connect(self, *, session_role: str) -> MigrationSession:
        ...


class IamMigrationRunner:
    """Apply the one reviewed IAM sequence under one deployment-only lock."""

    def __init__(self, *, driver: MigrationDriver, runner_version: str) -> None:
        if not _valid_runner_version(runner_version):
            raise MigrationRunnerError("MIGRATION_RUNNER_CONFIGURATION_INVALID")
        self._driver = driver
        self._runner_version = runner_version

    def run(
        self,
        *,
        catalog: MigrationCatalog,
        contract_sources: IamContractSources,
    ) -> MigrationRunReport:
        _require_reviewed_catalog(catalog)
        contract_parameters = _contract_parameters(catalog, contract_sources)

        applied_versions = []
        recovered_versions = []
        skipped_versions = []
        next_version: Optional[int] = None
        pending_recovery: Optional[int] = None

        while True:
            session = self._driver.connect(
                session_role=IAM_MIGRATION_SESSION_ROLE
            )
            locked = False
            transaction_active = False
            discard = False
            reconnect = False
            try:
                session.acquire_advisory_lock(*IAM_MIGRATION_LOCK)
                locked = True
                session.prepare_runner(
                    schema_role=IAM_MIGRATION_SCHEMA_ROLE,
                    postgres_major=IAM_POSTGRES_MAJOR,
                )
                prefix_length = _require_exact_database_state(
                    session.inspect_database(),
                    catalog=catalog,
                )

                if next_version is None:
                    skipped_versions.extend(range(prefix_length))
                    next_version = prefix_length
                elif pending_recovery is not None:
                    if prefix_length < pending_recovery:
                        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
                    if prefix_length > pending_recovery:
                        _append_unique(recovered_versions, pending_recovery)
                        for version in range(
                            pending_recovery + 1,
                            prefix_length,
                        ):
                            _append_unique(skipped_versions, version)
                    next_version = prefix_length
                    pending_recovery = None
                elif prefix_length != next_version:
                    raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")

                while next_version < len(catalog.artifacts):
                    artifact = catalog.artifacts[next_version]
                    descriptor = artifact.descriptor
                    try:
                        session.begin_migration(descriptor)
                        transaction_active = True
                        session.set_local_timeouts()
                        session.execute_artifact(artifact)
                        session.assert_artifact(descriptor)
                        if descriptor.version == IAM_SCHEMA_HEAD_VERSION:
                            session.insert_contract_row(contract_parameters)
                        expected_record = MigrationLedgerRecord.from_descriptor(
                            descriptor
                        )
                        session.insert_ledger_row(
                            expected_record,
                            runner_version=self._runner_version,
                        )
                        if descriptor.version == IAM_SCHEMA_HEAD_VERSION:
                            # The compatibility view derives its current
                            # version from the ledger.  Read it only after the
                            # schema-head row is visible in this same transaction so the
                            # final startup contract, DDL and receipt are
                            # verified atomically before COMMIT.
                            if (
                                session.read_contract_parameters()
                                != contract_parameters
                            ):
                                raise MigrationRunnerError(
                                    "MIGRATION_CONTRACT_DRIFT"
                                )
                        session.commit_migration()
                        transaction_active = False
                    except MigrationCommitOutcomeUnknown:
                        # The server releases the session lock with the lost
                        # connection.  This connection is permanently tainted;
                        # only an exact ledger row observed after reconnect may
                        # prove the file committed.
                        transaction_active = False
                        pending_recovery = descriptor.version
                        discard = True
                        locked = False
                        reconnect = True
                        break
                    except MigrationConnectionLost:
                        transaction_active = False
                        discard = True
                        locked = False
                        raise
                    except BaseException as primary_error:
                        if transaction_active:
                            try:
                                session.rollback_migration()
                            except BaseException:
                                discard = True
                                locked = False
                            transaction_active = False
                        raise primary_error

                    try:
                        committed_record = session.read_ledger_record(
                            component=descriptor.component,
                            version=descriptor.version,
                        )
                    except MigrationConnectionLost:
                        pending_recovery = descriptor.version
                        discard = True
                        locked = False
                        reconnect = True
                        break
                    if committed_record != expected_record:
                        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
                    applied_versions.append(descriptor.version)
                    next_version += 1

                if reconnect:
                    continue
                return MigrationRunReport(
                    applied_versions=tuple(applied_versions),
                    recovered_versions=tuple(recovered_versions),
                    skipped_versions=tuple(skipped_versions),
                )
            except MigrationConnectionLost:
                discard = True
                locked = False
                raise
            finally:
                primary_error_active = sys.exc_info()[0] is not None
                cleanup_error = None
                cleanup_connection_lost = False
                try:
                    if transaction_active and not discard:
                        session.rollback_migration()
                        transaction_active = False
                    if locked and not discard:
                        session.release_advisory_lock(*IAM_MIGRATION_LOCK)
                except MigrationConnectionLost as error:
                    discard = True
                    locked = False
                    transaction_active = False
                    cleanup_error = error
                    cleanup_connection_lost = True
                except BaseException as error:
                    discard = True
                    locked = False
                    transaction_active = False
                    cleanup_error = error
                try:
                    session.close(discard=discard)
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
                        cleanup_connection_lost = isinstance(
                            error,
                            MigrationConnectionLost,
                        )
                if cleanup_error is not None and not primary_error_active:
                    if cleanup_connection_lost:
                        raise cleanup_error
                    raise MigrationRunnerError(
                        "MIGRATION_SESSION_CLEANUP_FAILED"
                    ) from cleanup_error


def _require_reviewed_catalog(catalog: MigrationCatalog) -> None:
    if (
        not isinstance(catalog, MigrationCatalog)
        or len(catalog.artifacts) != len(IAM_MIGRATION_LAYOUT)
        or not isinstance(catalog.manifest_bytes, bytes)
        or not isinstance(catalog.manifest_sha256, bytes)
        or len(catalog.manifest_sha256) != 32
        or not hmac.compare_digest(
            catalog.manifest_sha256,
            IAM_REVIEWED_MANIFEST_SHA256,
        )
        or not hmac.compare_digest(
            hashlib.sha256(catalog.manifest_bytes).digest(),
            catalog.manifest_sha256,
        )
    ):
        raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")
    expected_entries = []
    for artifact, expected_layout in zip(
        catalog.artifacts,
        IAM_MIGRATION_LAYOUT,
    ):
        version, phase, name, relative_path = expected_layout
        descriptor = artifact.descriptor
        if (
            descriptor.component != "iam"
            or descriptor.version != version
            or descriptor.phase != phase
            or descriptor.name != name
            or descriptor.relative_path != relative_path
            or not isinstance(descriptor.checksum_sha256, bytes)
            or len(descriptor.checksum_sha256) != 32
            or not isinstance(artifact.sql_bytes, bytes)
            or not hmac.compare_digest(
                hashlib.sha256(artifact.sql_bytes).digest(),
                descriptor.checksum_sha256,
            )
        ):
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")
        try:
            _validate_sql_bytes(artifact.sql_bytes)
        except MigrationCatalogError as error:
            raise MigrationRunnerError("MIGRATION_CATALOG_INVALID") from error
        expected_entries.append(
            {
                "component": "iam",
                "version": version,
                "phase": phase.value,
                "name": name,
                "path": relative_path,
                "sha256": descriptor.checksum_sha256.hex(),
            }
        )
    expected_manifest = (
        json.dumps(
            expected_entries,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    if not hmac.compare_digest(catalog.manifest_bytes, expected_manifest):
        raise MigrationRunnerError("MIGRATION_CATALOG_INVALID")


def _contract_parameters(
    catalog: MigrationCatalog,
    sources: IamContractSources,
) -> IamContractParameters:
    if (
        not isinstance(sources, IamContractSources)
        or not isinstance(sources.api_contract_bytes, bytes)
        or not sources.api_contract_bytes
        or not isinstance(sources.event_contract_bytes, bytes)
        or not sources.event_contract_bytes
    ):
        raise MigrationRunnerError("MIGRATION_CONTRACT_SOURCE_INVALID")
    api_hash = hashlib.sha256(sources.api_contract_bytes).digest()
    event_hash = hashlib.sha256(sources.event_contract_bytes).digest()
    combined_hash = hashlib.sha256(
        b"iam-v1-contract"
        + b"\x00"
        + api_hash
        + event_hash
        + catalog.manifest_sha256
    ).digest()
    return IamContractParameters(
        component="iam",
        schema_head_version=IAM_SCHEMA_HEAD_VERSION,
        min_app_compatible_version=IAM_MIN_APP_COMPATIBLE_VERSION,
        max_app_compatible_version=IAM_MAX_APP_COMPATIBLE_VERSION,
        api_contract_sha256=api_hash,
        event_contract_sha256=event_hash,
        migration_manifest_sha256=catalog.manifest_sha256,
        combined_contract_sha256=combined_hash,
    )


def _require_exact_database_state(
    state: MigrationDatabaseState,
    *,
    catalog: MigrationCatalog,
) -> int:
    if not isinstance(state, MigrationDatabaseState):
        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
    records = tuple(state.applied_migrations)
    if not state.ledger_exists and state.has_unledgered_iam_objects:
        raise MigrationRunnerError("MIGRATION_UNLEDGERED_DATABASE")
    known_versions = set(range(len(catalog.artifacts)))
    for record in records:
        if (
            not isinstance(record, MigrationLedgerRecord)
            or record.component != "iam"
        ):
            raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
        if record.version not in known_versions:
            raise MigrationRunnerError("MIGRATION_LEDGER_UNKNOWN_VERSION")
    versions = [record.version for record in records]
    if (
        (not state.ledger_exists and records)
        or (state.ledger_exists and not records)
        or len(versions) != len(set(versions))
        or sorted(versions) != list(range(len(records)))
    ):
        raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
    records_by_version = {record.version: record for record in records}
    for version in range(len(records)):
        expected = MigrationLedgerRecord.from_descriptor(
            catalog.artifacts[version].descriptor
        )
        if records_by_version[version] != expected:
            raise MigrationRunnerError("MIGRATION_LEDGER_DRIFT")
    return len(records)


def _valid_runner_version(value: str) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(0x21 <= byte <= 0x7E for byte in encoded)


def _append_unique(items: list[int], value: int) -> None:
    if value not in items:
        items.append(value)
