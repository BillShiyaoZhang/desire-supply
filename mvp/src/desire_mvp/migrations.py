import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

from .migration_support import (
    CURRENT_DATABASE_VERSION,
    CURRENT_PAYLOAD_SCHEMA_VERSION,
    MIGRATION_APP_VERSION,
    MIGRATION_DESCRIPTORS,
    MIGRATION_HISTORY_TRIGGER_DEFINITIONS,
    MigrationError,
    frozen_legacy_variant,
)
from .schema import (
    SchemaContractError,
    SchemaVersionError,
    is_controlled_reference,
    validate_payload_contract,
    validate_schema_version,
)


PLAN_FORMAT_VERSION = 1
_PLAN_ROOT_FIELDS = {
    "plan_format_version",
    "plan_id",
    "source_database_version",
    "target_database_version",
    "target_payload_schema_version",
    "source_fingerprint",
    "resolution_sha256",
    "migrations",
    "counts",
    "blockers",
    "recommendation_history_sha256",
    "target_payload_sha256",
}
_PLAN_COUNT_FIELDS = {
    "entities",
    "outcomes",
    "v0_records",
    "v1_records",
    "recommendations",
}
_BUSINESS_TABLES = ("entities", "recommendations", "decisions", "outcomes")
_EXPECTED_LEGACY_INDEXES = {
    "idx_entities_pilot",
    "idx_recommendations_pilot",
    "idx_decisions_pilot",
    "idx_outcomes_pilot",
}
_EXPECTED_LEGACY_INDEX_DEFINITIONS = {
    "idx_entities_pilot": ("entities", ("pilot_id", "kind")),
    "idx_recommendations_pilot": ("recommendations", ("pilot_id", "demand_id")),
    "idx_decisions_pilot": ("decisions", ("pilot_id", "demand_id")),
    "idx_outcomes_pilot": ("outcomes", ("pilot_id", "demand_id")),
}
_VALID_RESOLUTION_TARGETS = {"agreed", "cancelled"}
_VALID_RESOLUTION_REASONS = {
    "PROJECT_ESTABLISHED",
    "NO_PROJECT_ESTABLISHED",
    "OPERATOR_CORRECTION",
}


@dataclass(frozen=True)
class RecordMigrationResult:
    record: Dict[str, Any]
    changed: bool
    change_codes: Tuple[str, ...]
    resolution_code: Optional[str] = None
    resolution_ref: Optional[str] = None


@dataclass(frozen=True)
class MigrationBlocker:
    code: str
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "count": self.count}


@dataclass(frozen=True)
class MigrationPlan:
    plan_id: str
    source_database_version: int
    target_database_version: int
    target_payload_schema_version: int
    source_fingerprint: str
    resolution_sha256: Optional[str]
    migrations: Tuple[Dict[str, Any], ...]
    counts: Dict[str, int]
    blockers: Tuple[MigrationBlocker, ...]
    recommendation_history_sha256: str
    target_payload_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_format_version": PLAN_FORMAT_VERSION,
            "plan_id": self.plan_id,
            "source_database_version": self.source_database_version,
            "target_database_version": self.target_database_version,
            "target_payload_schema_version": self.target_payload_schema_version,
            "source_fingerprint": self.source_fingerprint,
            "resolution_sha256": self.resolution_sha256,
            "migrations": [dict(item) for item in self.migrations],
            "counts": dict(self.counts),
            "blockers": [item.to_dict() for item in self.blockers],
            "recommendation_history_sha256": self.recommendation_history_sha256,
            "target_payload_sha256": self.target_payload_sha256,
        }

    def digest_payload(self) -> Dict[str, Any]:
        value = self.to_dict()
        value.pop("plan_id")
        return value

    def validate_integrity(self) -> None:
        if self.plan_id != _plan_payload(self.digest_payload()):
            raise MigrationError("INVALID_MIGRATION_PLAN")

    @classmethod
    def from_dict(cls, value: Any) -> "MigrationPlan":
        if (
            type(value) is not dict
            or set(value) != _PLAN_ROOT_FIELDS
            or type(value.get("plan_format_version")) is not int
            or value["plan_format_version"] != PLAN_FORMAT_VERSION
        ):
            raise MigrationError("INVALID_MIGRATION_PLAN")

        def is_digest(candidate: Any) -> bool:
            return (
                isinstance(candidate, str)
                and len(candidate) == 64
                and all(character in "0123456789abcdef" for character in candidate)
            )

        if (
            type(value["source_database_version"]) is not int
            or value["source_database_version"] not in (0, CURRENT_DATABASE_VERSION)
            or type(value["target_database_version"]) is not int
            or value["target_database_version"] != CURRENT_DATABASE_VERSION
            or type(value["target_payload_schema_version"]) is not int
            or value["target_payload_schema_version"]
            != CURRENT_PAYLOAD_SCHEMA_VERSION
            or not is_digest(value["plan_id"])
            or not is_digest(value["source_fingerprint"])
            or not is_digest(value["recommendation_history_sha256"])
            or not is_digest(value["target_payload_sha256"])
            or (
                value["resolution_sha256"] is not None
                and not is_digest(value["resolution_sha256"])
            )
        ):
            raise MigrationError("INVALID_MIGRATION_PLAN")

        raw_migrations = value["migrations"]
        if type(raw_migrations) is not list or any(
            type(item) is not dict
            or set(item) != {"version", "name", "checksum_sha256"}
            or type(item["version"]) is not int
            or not isinstance(item["name"], str)
            or not is_digest(item["checksum_sha256"])
            for item in raw_migrations
        ):
            raise MigrationError("INVALID_MIGRATION_PLAN")
        migrations = tuple(dict(item) for item in raw_migrations)
        if migrations != _migration_dicts():
            raise MigrationError("INVALID_MIGRATION_PLAN")

        raw_counts = value["counts"]
        if (
            type(raw_counts) is not dict
            or set(raw_counts) != _PLAN_COUNT_FIELDS
            or any(type(count) is not int or count < 0 for count in raw_counts.values())
        ):
            raise MigrationError("INVALID_MIGRATION_PLAN")

        raw_blockers = value["blockers"]
        if type(raw_blockers) is not list or any(
            type(item) is not dict
            or set(item) != {"code", "count"}
            or not isinstance(item["code"], str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]*", item["code"]) is None
            or type(item["count"]) is not int
            or item["count"] <= 0
            for item in raw_blockers
        ):
            raise MigrationError("INVALID_MIGRATION_PLAN")
        blocker_codes = [item["code"] for item in raw_blockers]
        if blocker_codes != sorted(set(blocker_codes)):
            raise MigrationError("INVALID_MIGRATION_PLAN")
        blockers = tuple(
            MigrationBlocker(item["code"], item["count"]) for item in raw_blockers
        )

        plan = cls(
            plan_id=value["plan_id"],
            source_database_version=value["source_database_version"],
            target_database_version=value["target_database_version"],
            target_payload_schema_version=value["target_payload_schema_version"],
            source_fingerprint=value["source_fingerprint"],
            resolution_sha256=value["resolution_sha256"],
            migrations=migrations,
            counts=dict(raw_counts),
            blockers=blockers,
            recommendation_history_sha256=value["recommendation_history_sha256"],
            target_payload_sha256=value["target_payload_sha256"],
        )
        try:
            plan.validate_integrity()
        except (TypeError, ValueError) as exc:
            raise MigrationError("INVALID_MIGRATION_PLAN") from exc
        return plan

    @classmethod
    def read(cls, path: Path) -> "MigrationPlan":
        try:
            with Path(path).open("r", encoding="utf-8") as handle:
                return cls.from_dict(json.load(handle))
        except (OSError, json.JSONDecodeError) as exc:
            raise MigrationError("INVALID_MIGRATION_PLAN") from exc

    def write(self, path: Path) -> None:
        self.validate_integrity()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise MigrationError("PLAN_WRITE_FAILED") from exc
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self.to_dict(), handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
            os.chmod(str(destination), 0o600)
        except BaseException:
            try:
                destination.unlink()
            except OSError:
                pass
            raise


@dataclass(frozen=True)
class MigrationStatus:
    state: str
    database_version: int
    plan_id: Optional[str] = None


@dataclass(frozen=True)
class MigrationResult:
    status: str
    plan_id: str
    backup_path: Optional[str]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _sha256_descriptor(descriptor: int, chunk_size: int = 1024 * 1024) -> str:
    position = os.lseek(descriptor, 0, os.SEEK_CUR)
    hasher = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    finally:
        os.lseek(descriptor, position, os.SEEK_SET)
    return hasher.hexdigest()


def _descriptor_identity(descriptor: int) -> Tuple[int, int]:
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino


def _path_has_identity(path: Path, identity: Optional[Tuple[int, int]]) -> bool:
    if identity is None:
        return False
    try:
        current = Path(path).lstat()
    except OSError:
        return False
    return stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity


def _unlink_if_owned(path: Path, identity: Optional[Tuple[int, int]]) -> None:
    if not _path_has_identity(path, identity):
        return
    try:
        Path(path).unlink()
    except OSError:
        pass


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(Path(path)), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inside_repository(path: Path) -> bool:
    resolved = Path(path).resolve()
    return any((candidate / ".git").exists() for candidate in (resolved, *resolved.parents))


def _resolution_digest(resolutions: Optional[Sequence[Dict[str, Any]]]) -> Optional[str]:
    if not resolutions:
        return None
    return _sha256_text(_canonical_json(list(resolutions)))


def _validate_resolution_shape(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    required = {"demand_id", "from", "to", "reason_code", "evidence_ref"}
    if set(value) != required or any(
        not isinstance(value.get(field), str) for field in required
    ):
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    if value.get("from") != "closed":
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    target = value.get("to")
    reason = value.get("reason_code")
    evidence = value.get("evidence_ref")
    if target not in _VALID_RESOLUTION_TARGETS or reason not in _VALID_RESOLUTION_REASONS:
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    if reason == "PROJECT_ESTABLISHED" and target != "agreed":
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    if reason == "NO_PROJECT_ESTABLISHED" and target != "cancelled":
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    if not is_controlled_reference(evidence):
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    return value


def _validate_resolution(value: Any, demand_id: str) -> Dict[str, Any]:
    resolution = _validate_resolution_shape(value)
    if resolution["demand_id"] != demand_id:
        raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
    return resolution


def migrate_record_v0_to_v1(
    record_type: str,
    record: Dict[str, Any],
    *,
    resolutions: Sequence[Dict[str, Any]],
) -> RecordMigrationResult:
    """Pure, deterministic conversion for the three legacy record roots."""

    if record_type not in {"demand", "creator", "outcome"} or not isinstance(record, dict):
        raise MigrationError("INVALID_LEGACY_PAYLOAD")
    for resolution in resolutions:
        _validate_resolution_shape(resolution)
    if "schema_version" in record:
        try:
            validate_schema_version(record)
            validate_payload_contract(record_type, record)
        except SchemaVersionError as exc:
            raise MigrationError(exc.code) from exc
        except SchemaContractError as exc:
            raise MigrationError("INVALID_LEGACY_PAYLOAD") from exc
        if resolutions:
            raise MigrationError("UNUSED_DEMAND_STATUS_RESOLUTION")
        return RecordMigrationResult(record, False, ())

    migrated = copy.deepcopy(record)
    change_codes: List[str] = ["SCHEMA_VERSION_ADDED"]
    resolution_code: Optional[str] = None
    resolution_ref: Optional[str] = None

    if record_type == "demand" and record.get("status") == "closed":
        matching = [
            value
            for value in resolutions
            if isinstance(value, dict) and value.get("demand_id") == record.get("id")
        ]
        if not matching:
            raise MigrationError("MISSING_DEMAND_STATUS_RESOLUTION")
        if len(matching) != 1 or len(resolutions) != 1:
            raise MigrationError("INVALID_DEMAND_STATUS_RESOLUTION")
        selected = _validate_resolution(matching[0], str(record.get("id", "")))
        migrated["status"] = selected["to"]
        resolution_code = selected["reason_code"]
        resolution_ref = selected["evidence_ref"]
        change_codes.append("CLOSED_STATUS_RESOLVED")
    elif resolutions:
        raise MigrationError("UNUSED_DEMAND_STATUS_RESOLUTION")

    if record_type == "creator" and record.get("status") == "withdrawn":
        migrated["status"] = "inactive"
        change_codes.append("WITHDRAWN_TO_INACTIVE")

    migrated["schema_version"] = CURRENT_PAYLOAD_SCHEMA_VERSION
    try:
        validate_payload_contract(record_type, migrated)
    except (SchemaVersionError, SchemaContractError) as exc:
        raise MigrationError("INVALID_LEGACY_PAYLOAD") from exc
    return RecordMigrationResult(
        migrated,
        True,
        tuple(change_codes),
        resolution_code,
        resolution_ref,
    )


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = "file:{}?mode=ro".format(quote(str(Path(path).resolve())))
    connection = sqlite3.connect(uri, uri=True, timeout=0.1)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _table_columns(connection: sqlite3.Connection, table: str) -> Tuple[str, ...]:
    return tuple(row["name"] for row in connection.execute("PRAGMA table_info({})".format(table)))


def _entity_row_matches_payload(
    kind: Any, entity_id: Any, pilot_id: Any, record: Dict[str, Any]
) -> bool:
    if kind not in ("creator", "demand") or record.get("id") != entity_id:
        return False
    if kind == "demand":
        return record.get("pilot_id") == pilot_id
    return pilot_id is None


def _outcome_row_matches_payload(row: sqlite3.Row, record: Dict[str, Any]) -> bool:
    try:
        creator_ids = json.loads(row["creator_ids_json"])
    except (TypeError, json.JSONDecodeError):
        return False
    return (
        record.get("project_id") == row["project_id"]
        and record.get("pilot_id") == row["pilot_id"]
        and record.get("demand_id") == row["demand_id"]
        and isinstance(creator_ids, list)
        and record.get("creator_ids") == creator_ids
    )


def _legacy_variant(connection: sqlite3.Connection) -> str:
    variant = frozen_legacy_variant(connection)
    if variant is None:
        raise MigrationError("UNRECOGNIZED_LEGACY_SCHEMA")
    return variant


def _database_state_connection(connection: sqlite3.Connection) -> Tuple[str, int]:
    has_registry = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if has_registry:
        return "current", _validate_migration_history(connection)
    _legacy_variant(connection)
    return "legacy", 0


def _database_state(path: Path) -> Tuple[str, int]:
    try:
        if not Path(path).exists() or Path(path).stat().st_size == 0:
            return "empty", 0
        with _readonly_connection(path) as connection:
            return _database_state_connection(connection)
    except MigrationError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise MigrationError("MIGRATION_HISTORY_INVALID") from exc


def _validate_migration_history(connection: sqlite3.Connection) -> int:
    try:
        rows = connection.execute(
            "SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version"
        ).fetchall()
    except sqlite3.Error as exc:
        raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
    expected = [
        (item.version, item.name, item.checksum_sha256) for item in MIGRATION_DESCRIPTORS
    ]
    actual = [(row[0], row[1], row[2]) for row in rows]
    if actual != expected:
        raise MigrationError("MIGRATION_HISTORY_INVALID")
    return CURRENT_DATABASE_VERSION


def _feed_value(hasher: "hashlib._Hash", value: Any) -> None:
    if value is None:
        encoded = b"null"
    elif isinstance(value, bytes):
        encoded = b"bytes:" + value
    else:
        encoded = (type(value).__name__ + ":" + str(value)).encode("utf-8")
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)


def logical_fingerprint(path: Path) -> str:
    with _readonly_connection(path) as connection:
        hasher = hashlib.sha256()
        objects = connection.execute(
            """
            SELECT type, name, tbl_name, coalesce(sql, '') AS sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        for row in objects:
            for value in row:
                _feed_value(hasher, value)
        for table in _BUSINESS_TABLES:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()
            if not exists:
                continue
            hasher.update(table.encode("ascii"))
            rows = connection.execute(
                'SELECT * FROM "{}" ORDER BY rowid'.format(table)
            ).fetchall()
            for row in rows:
                for value in row:
                    _feed_value(hasher, value)
        return hasher.hexdigest()


def _recommendation_digest(connection: sqlite3.Connection) -> str:
    hasher = hashlib.sha256()
    rows = connection.execute(
        """
        SELECT id, input_snapshot_json, result_json, budget_json
        FROM recommendations ORDER BY id
        """
    ).fetchall()
    for row in rows:
        for value in row:
            _feed_value(hasher, value)
    return hasher.hexdigest()


def _migration_dicts() -> Tuple[Dict[str, Any], ...]:
    return tuple(
        {
            "version": item.version,
            "name": item.name,
            "checksum_sha256": item.checksum_sha256,
        }
        for item in MIGRATION_DESCRIPTORS
    )


def _plan_payload(plan_values: Dict[str, Any]) -> str:
    return _sha256_text(_canonical_json(plan_values))


class _MigrationLock:
    def __init__(self, path: Path, timeout_seconds: float):
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+")
        os.chmod(str(self.path), 0o600)
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self.handle.close()
                    self.handle = None
                    raise MigrationError("MIGRATION_BUSY")
                time.sleep(0.01)

    def __exit__(self, exc_type, exc, traceback):
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


class SqliteBackupService:
    def create(
        self,
        source_path: Path,
        backup_dir: Path,
        *,
        plan_id: str,
        source_fingerprint: str,
    ) -> Tuple[Path, Path, str]:
        backup_root = Path(backup_dir)
        if not backup_root.exists() or not backup_root.is_dir():
            raise MigrationError("BACKUP_FAILED")
        source_root = Path(source_path).resolve().parent
        backup_root_resolved = backup_root.resolve()
        try:
            backup_root_resolved.relative_to(source_root)
        except ValueError:
            pass
        else:
            raise MigrationError("BACKUP_FAILED")
        if _inside_repository(backup_root_resolved):
            raise MigrationError("BACKUP_FAILED")
        backup_path = backup_root / "mvp-before-{}.sqlite3".format(plan_id[:16])
        manifest_path = Path(str(backup_path) + ".manifest.json")
        if backup_path.exists() or manifest_path.exists():
            raise MigrationError("BACKUP_FAILED")
        descriptor: Optional[int] = None
        manifest_descriptor: Optional[int] = None
        backup_identity: Optional[Tuple[int, int]] = None
        manifest_identity: Optional[Tuple[int, int]] = None
        staging_root: Optional[Path] = None
        try:
            descriptor = os.open(
                str(backup_path), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600
            )
            backup_identity = _descriptor_identity(descriptor)
            os.fchmod(descriptor, 0o600)

            staging_root = Path(tempfile.mkdtemp(prefix="desire-migration-backup-"))
            os.chmod(str(staging_root), 0o700)
            staging_path = staging_root / "backup.sqlite3"
            source = _readonly_connection(source_path)
            destination = sqlite3.connect(str(staging_path))
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()
            os.chmod(str(staging_path), 0o600)
            with sqlite3.connect(str(staging_path)) as check:
                if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise MigrationError("BACKUP_FAILED")
            if logical_fingerprint(staging_path) != source_fingerprint:
                raise MigrationError("BACKUP_FAILED")
            digest = _sha256_file(staging_path)

            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            with staging_path.open("rb") as staged, os.fdopen(
                os.dup(descriptor), "wb"
            ) as reserved:
                shutil.copyfileobj(staged, reserved)
                reserved.flush()
            os.fsync(descriptor)
            if (
                not _path_has_identity(backup_path, backup_identity)
                or _sha256_descriptor(descriptor) != digest
            ):
                raise MigrationError("BACKUP_FAILED")
            with _readonly_connection(backup_path) as check:
                if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise MigrationError("BACKUP_FAILED")
            if (
                not _path_has_identity(backup_path, backup_identity)
                or logical_fingerprint(backup_path) != source_fingerprint
                or not _path_has_identity(backup_path, backup_identity)
            ):
                raise MigrationError("BACKUP_FAILED")

            manifest = {
                "plan_id": plan_id,
                "source_fingerprint": source_fingerprint,
                "database_sha256": digest,
                "app_version": MIGRATION_APP_VERSION,
            }
            manifest_descriptor = os.open(
                str(manifest_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            manifest_identity = _descriptor_identity(manifest_descriptor)
            with os.fdopen(
                os.dup(manifest_descriptor), "w", encoding="utf-8"
            ) as handle:
                json.dump(manifest, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
            os.fsync(manifest_descriptor)
            os.fchmod(manifest_descriptor, 0o600)
            if not _path_has_identity(manifest_path, manifest_identity):
                raise MigrationError("BACKUP_FAILED")
            _fsync_directory(backup_root)
            os.close(manifest_descriptor)
            manifest_descriptor = None
            os.close(descriptor)
            descriptor = None
            return backup_path, manifest_path, digest
        except BaseException as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if manifest_descriptor is not None:
                try:
                    os.close(manifest_descriptor)
                except OSError:
                    pass
            _unlink_if_owned(manifest_path, manifest_identity)
            _unlink_if_owned(backup_path, backup_identity)
            if isinstance(exc, MigrationError):
                raise
            raise MigrationError("BACKUP_FAILED") from exc
        finally:
            if staging_root is not None:
                for name in ("backup.sqlite3", "backup.sqlite3-journal", "backup.sqlite3-wal", "backup.sqlite3-shm"):
                    try:
                        (staging_root / name).unlink()
                    except OSError:
                        pass
                try:
                    staging_root.rmdir()
                except OSError:
                    pass

    def restore(
        self,
        *,
        backup_path: Path,
        manifest_path: Path,
        destination_dir: Path,
    ) -> Path:
        backup = Path(backup_path)
        manifest_file = Path(manifest_path)
        destination_root = Path(destination_dir)
        destination = destination_root / "mvp.sqlite3"
        root_created = False
        destination_identity: Optional[Tuple[int, int]] = None
        descriptor: Optional[int] = None
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            digest_fields = (
                manifest.get("plan_id") if isinstance(manifest, dict) else None,
                manifest.get("source_fingerprint") if isinstance(manifest, dict) else None,
                manifest.get("database_sha256") if isinstance(manifest, dict) else None,
            )
            if (
                type(manifest) is not dict
                or set(manifest)
                != {"plan_id", "source_fingerprint", "database_sha256", "app_version"}
                or any(
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(
                        character not in "0123456789abcdef" for character in value
                    )
                    for value in digest_fields
                )
                or not isinstance(manifest.get("app_version"), str)
                or not manifest["app_version"]
            ):
                raise ValueError
            if _sha256_file(backup) != manifest.get("database_sha256"):
                raise ValueError
            with sqlite3.connect(str(backup)) as connection:
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError
            if logical_fingerprint(backup) != manifest.get("source_fingerprint"):
                raise ValueError
            if destination.exists():
                raise ValueError
            destination_root.mkdir(mode=0o700, parents=False, exist_ok=False)
            root_created = True
            descriptor = os.open(
                str(destination), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600
            )
            destination_identity = _descriptor_identity(descriptor)
            with backup.open("rb") as source, os.fdopen(
                os.dup(descriptor), "wb"
            ) as target:
                shutil.copyfileobj(source, target)
                target.flush()
            os.fsync(descriptor)
            if (
                not _path_has_identity(destination, destination_identity)
                or _sha256_descriptor(descriptor) != manifest.get("database_sha256")
            ):
                raise ValueError
            with _readonly_connection(destination) as restored:
                if restored.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError
            if (
                not _path_has_identity(destination, destination_identity)
                or logical_fingerprint(destination) != manifest.get("source_fingerprint")
                or not _path_has_identity(destination, destination_identity)
            ):
                raise ValueError
            _fsync_directory(destination_root)
            os.close(descriptor)
            descriptor = None
            return destination
        except BaseException as exc:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            _unlink_if_owned(destination, destination_identity)
            if root_created:
                try:
                    destination_root.rmdir()
                except OSError:
                    pass
            raise MigrationError("BACKUP_INTEGRITY_ERROR") from exc


class MigrationRunner:
    def __init__(self, repository: Any, lock_timeout_seconds: float = 1.0):
        self.repository = repository
        self.lock_timeout_seconds = lock_timeout_seconds

    @property
    def path(self) -> Path:
        return Path(self.repository.path)

    def status(self, plan_id: Optional[str] = None) -> MigrationStatus:
        try:
            if not self.path.exists() or self.path.stat().st_size == 0:
                return MigrationStatus("empty", 0, None)
        except OSError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        try:
            with _readonly_connection(self.path) as connection:
                connection.execute("BEGIN")
                state, version = _database_state_connection(connection)
                if state == "legacy":
                    return MigrationStatus("migration_required", 0, None)
                self.repository._require_current_connection(connection)
                if plan_id:
                    row = connection.execute(
                        """
                        SELECT plan_id, source_database_version, target_database_version,
                               source_fingerprint, target_fingerprint, backup_sha256
                        FROM migration_runs WHERE plan_id=?
                        """,
                        (plan_id,),
                    ).fetchone()
                    if row is not None:
                        registry_plan_ids = {
                            item["plan_id"]
                            for item in connection.execute(
                                "SELECT plan_id FROM schema_migrations"
                            ).fetchall()
                        }
                        hashes = (
                            row["source_fingerprint"],
                            row["target_fingerprint"],
                            row["backup_sha256"],
                        )
                        if (
                            registry_plan_ids != {plan_id}
                            or row["source_database_version"] != 0
                            or row["target_database_version"] != CURRENT_DATABASE_VERSION
                            or any(
                                not isinstance(value, str)
                                or len(value) != 64
                                or any(
                                    character not in "0123456789abcdef"
                                    for character in value
                                )
                                for value in hashes
                            )
                        ):
                            raise MigrationError("MIGRATION_HISTORY_INVALID")
                        return MigrationStatus("applied", version, plan_id)
                return MigrationStatus("current", version, None)
        except MigrationError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc

    def plan(
        self,
        target_version: int = CURRENT_PAYLOAD_SCHEMA_VERSION,
        resolutions: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> MigrationPlan:
        if target_version != CURRENT_PAYLOAD_SCHEMA_VERSION:
            raise MigrationError("UNSUPPORTED_SCHEMA_VERSION")
        resolution_values = list(resolutions or [])
        for resolution in resolution_values:
            _validate_resolution_shape(resolution)
        try:
            if not self.path.exists() or self.path.stat().st_size == 0:
                raise MigrationError("MIGRATION_NOT_REQUIRED")
        except OSError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        blockers: List[MigrationBlocker] = []
        counts = {
            "entities": 0,
            "outcomes": 0,
            "v0_records": 0,
            "v1_records": 0,
            "recommendations": 0,
        }
        target_hasher = hashlib.sha256()
        recommendation_digest = _sha256_text("")

        with _readonly_connection(self.path) as connection:
            connection.execute("BEGIN")
            state, source_version = _database_state_connection(connection)
            if state == "current":
                self.repository._require_current_connection(connection)
            source_fingerprint = self._logical_fingerprint_connection(connection)
            recommendation_digest = _recommendation_digest(connection)
            counts["recommendations"] = connection.execute(
                "SELECT count(*) FROM recommendations"
            ).fetchone()[0]
            if state == "current":
                payload_rows = [
                    ("entity", row["payload_json"])
                    for row in connection.execute(
                        "SELECT payload_json FROM entities ORDER BY kind, entity_id"
                    ).fetchall()
                ] + [
                    ("outcome", row["payload_json"])
                    for row in connection.execute(
                        "SELECT payload_json FROM outcomes ORDER BY project_id"
                    ).fetchall()
                ]
                for _, payload_text in payload_rows:
                    target_hasher.update(payload_text.encode("utf-8"))
                    counts["v1_records"] += 1
            else:
                used_resolution_ids = set()
                entity_rows = connection.execute(
                    """
                    SELECT kind, entity_id, pilot_id, payload_json
                    FROM entities ORDER BY kind, entity_id
                    """
                ).fetchall()
                outcome_rows = connection.execute(
                    """
                    SELECT project_id, pilot_id, demand_id, creator_ids_json, payload_json
                    FROM outcomes ORDER BY project_id
                    """
                ).fetchall()
                counts["entities"] = len(entity_rows)
                counts["outcomes"] = len(outcome_rows)
                work = [
                    (row["kind"], row["entity_id"], row["payload_json"], row)
                    for row in entity_rows
                ] + [
                    ("outcome", row["project_id"], row["payload_json"], row)
                    for row in outcome_rows
                ]
                for record_type, record_key, payload_text, storage_row in work:
                    try:
                        record = json.loads(payload_text)
                        if not isinstance(record, dict):
                            raise ValueError
                    except (json.JSONDecodeError, TypeError, ValueError):
                        blockers.append(MigrationBlocker("INVALID_LEGACY_PAYLOAD"))
                        continue
                    matching_resolutions: List[Dict[str, Any]] = []
                    if record_type == "demand" and record.get("status") == "closed":
                        matching_resolutions = [
                            item
                            for item in resolution_values
                            if isinstance(item, dict) and item.get("demand_id") == record_key
                        ]
                        used_resolution_ids.update(
                            item.get("demand_id") for item in matching_resolutions
                        )
                    try:
                        result = migrate_record_v0_to_v1(
                            record_type,
                            record,
                            resolutions=matching_resolutions,
                        )
                    except MigrationError as exc:
                        blockers.append(MigrationBlocker(exc.code))
                        continue
                    identity_matches = (
                        _outcome_row_matches_payload(storage_row, record)
                        if record_type == "outcome"
                        else _entity_row_matches_payload(
                            record_type,
                            storage_row["entity_id"],
                            storage_row["pilot_id"],
                            record,
                        )
                    )
                    if not identity_matches:
                        blockers.append(
                            MigrationBlocker("LEGACY_ROW_METADATA_MISMATCH")
                        )
                        continue
                    if result.changed:
                        counts["v0_records"] += 1
                        target_text = _canonical_json(result.record)
                    else:
                        counts["v1_records"] += 1
                        target_text = payload_text
                    _feed_value(target_hasher, record_type)
                    _feed_value(target_hasher, record_key)
                    _feed_value(target_hasher, target_text)
                unused = [
                    item
                    for item in resolution_values
                    if not isinstance(item, dict) or item.get("demand_id") not in used_resolution_ids
                ]
                if unused:
                    blockers.append(MigrationBlocker("UNUSED_DEMAND_STATUS_RESOLUTION", len(unused)))
            connection.execute("ROLLBACK")

        blocker_counts: Dict[str, int] = {}
        for blocker in blockers:
            blocker_counts[blocker.code] = blocker_counts.get(blocker.code, 0) + blocker.count
        compact_blockers = tuple(
            MigrationBlocker(code, blocker_counts[code]) for code in sorted(blocker_counts)
        )
        base = {
            "plan_format_version": PLAN_FORMAT_VERSION,
            "source_database_version": source_version,
            "target_database_version": CURRENT_DATABASE_VERSION,
            "target_payload_schema_version": CURRENT_PAYLOAD_SCHEMA_VERSION,
            "source_fingerprint": source_fingerprint,
            "resolution_sha256": _resolution_digest(resolution_values),
            "migrations": list(_migration_dicts()),
            "counts": counts,
            "blockers": [item.to_dict() for item in compact_blockers],
            "recommendation_history_sha256": recommendation_digest,
            "target_payload_sha256": target_hasher.hexdigest(),
        }
        plan_id = _plan_payload(base)
        return MigrationPlan(
            plan_id=plan_id,
            source_database_version=source_version,
            target_database_version=CURRENT_DATABASE_VERSION,
            target_payload_schema_version=CURRENT_PAYLOAD_SCHEMA_VERSION,
            source_fingerprint=source_fingerprint,
            resolution_sha256=base["resolution_sha256"],
            migrations=_migration_dicts(),
            counts=counts,
            blockers=compact_blockers,
            recommendation_history_sha256=recommendation_digest,
            target_payload_sha256=target_hasher.hexdigest(),
        )

    def apply(
        self,
        plan: MigrationPlan,
        *,
        backup_dir: Path,
        resolutions: Optional[Sequence[Dict[str, Any]]] = None,
        fault_injector: Optional[Callable[[str], None]] = None,
    ) -> MigrationResult:
        def fault(stage: str) -> None:
            if fault_injector is not None:
                fault_injector(stage)

        plan.validate_integrity()
        status = self.status(plan_id=plan.plan_id)
        if status.state == "applied":
            return MigrationResult("already_applied", plan.plan_id, None)
        if status.state == "current":
            recalculated = self.plan(
                target_version=plan.target_payload_schema_version,
                resolutions=resolutions,
            )
            if recalculated.plan_id != plan.plan_id:
                raise MigrationError("STALE_MIGRATION_PLAN")
            return MigrationResult("no_changes", plan.plan_id, None)
        if plan.blockers:
            raise MigrationError("MIGRATION_BLOCKED")
        if plan.resolution_sha256 is not None and not resolutions:
            raise MigrationError("MISSING_MIGRATION_RESOLUTIONS")
        if plan.resolution_sha256 is None and resolutions:
            raise MigrationError("STALE_MIGRATION_PLAN")
        backup_root = Path(backup_dir)
        if not backup_root.exists() or not backup_root.is_dir():
            raise MigrationError("BACKUP_FAILED")
        try:
            backup_root.resolve().relative_to(self.path.parent.resolve())
        except ValueError:
            pass
        else:
            raise MigrationError("BACKUP_FAILED")
        if _inside_repository(backup_root):
            raise MigrationError("BACKUP_FAILED")

        lock_path = self.path.parent / ".migration.lock"
        with _MigrationLock(lock_path, self.lock_timeout_seconds):
            fault("after_lock_acquired")
            current_status = self.status(plan_id=plan.plan_id)
            if current_status.state == "applied":
                return MigrationResult("already_applied", plan.plan_id, None)
            recalculated = self.plan(
                target_version=plan.target_payload_schema_version,
                resolutions=resolutions,
            )
            if (
                recalculated.plan_id != plan.plan_id
                or recalculated.source_fingerprint != plan.source_fingerprint
                or recalculated.resolution_sha256 != plan.resolution_sha256
            ):
                raise MigrationError("STALE_MIGRATION_PLAN")
            if recalculated.blockers:
                raise MigrationError("MIGRATION_BLOCKED")

            backup_path: Optional[Path] = None
            target_fingerprint: Optional[str] = None
            connection = sqlite3.connect(str(self.path), timeout=1.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            commit_attempted = False
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("BEGIN IMMEDIATE")
                if self._logical_fingerprint_connection(connection) != plan.source_fingerprint:
                    raise MigrationError("STALE_MIGRATION_PLAN")
                backup_path, _, backup_sha256 = SqliteBackupService().create(
                    self.path,
                    backup_root,
                    plan_id=plan.plan_id,
                    source_fingerprint=plan.source_fingerprint,
                )
                fault("after_backup")
                self._apply_0001(connection)
                fault("after_0001_bootstrap_and_expand")
                audits, before_recommendations = self._apply_0002(
                    connection, plan.plan_id, list(resolutions or [])
                )
                fault("after_0002_backfill_payload_v1")
                self._apply_0003(connection)
                fault("after_0003_contract_v1_and_history")

                after_recommendations = connection.execute(
                    """
                    SELECT id, input_snapshot_json, result_json, budget_json
                    FROM recommendations ORDER BY id
                    """
                ).fetchall()
                if [tuple(row) for row in after_recommendations] != before_recommendations:
                    raise MigrationError("HISTORY_INTEGRITY_ERROR")

                target_fingerprint = self._logical_fingerprint_connection(connection)
                now = self._utc_now()
                connection.execute(
                    """
                    INSERT INTO migration_runs(
                        plan_id, source_database_version, target_database_version,
                        source_fingerprint, target_fingerprint, resolution_sha256,
                        backup_path, backup_sha256, summary_json, applied_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan.plan_id,
                        plan.source_database_version,
                        plan.target_database_version,
                        plan.source_fingerprint,
                        target_fingerprint,
                        plan.resolution_sha256,
                        str(backup_path),
                        backup_sha256,
                        _canonical_json(plan.counts),
                        now,
                    ),
                )
                for audit in audits:
                    connection.execute(
                        """
                        INSERT INTO payload_migration_audit(
                            plan_id, record_type, record_key, from_version, to_version,
                            before_sha256, after_sha256, change_codes_json,
                            resolution_code, resolution_ref
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (plan.plan_id,) + audit,
                    )
                for descriptor in MIGRATION_DESCRIPTORS:
                    connection.execute(
                        """
                        INSERT INTO schema_migrations(
                            version, name, checksum_sha256, app_version, plan_id, applied_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            descriptor.version,
                            descriptor.name,
                            descriptor.checksum_sha256,
                            MIGRATION_APP_VERSION,
                            plan.plan_id,
                            now,
                        ),
                    )
                manifest_count = connection.execute(
                    "SELECT count(*) FROM recommendation_snapshot_manifests"
                ).fetchone()[0]
                recommendation_count = connection.execute(
                    "SELECT count(*) FROM recommendations"
                ).fetchone()[0]
                if manifest_count != recommendation_count:
                    raise MigrationError("HISTORY_INTEGRITY_ERROR")
                manifest_rows = connection.execute(
                    """
                    SELECT r.input_snapshot_json, r.result_json, r.budget_json,
                           m.input_sha256, m.result_sha256, m.budget_sha256
                    FROM recommendations r
                    JOIN recommendation_snapshot_manifests m
                      ON m.recommendation_id = r.id
                    ORDER BY r.id
                    """
                ).fetchall()
                if any(
                    (_sha256_text(row[0]), _sha256_text(row[1]), _sha256_text(row[2]))
                    != (row[3], row[4], row[5])
                    for row in manifest_rows
                ):
                    raise MigrationError("HISTORY_INTEGRITY_ERROR")
                if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise MigrationError("MIGRATION_ROLLED_BACK")
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise MigrationError("MIGRATION_ROLLED_BACK")
                fault("before_commit")
                commit_attempted = True
                connection.execute("COMMIT")
            except BaseException as exc:
                try:
                    in_transaction = connection.in_transaction
                except BaseException as state_exc:
                    raise MigrationError("MIGRATION_RECOVERY_REQUIRED") from state_exc
                if in_transaction:
                    try:
                        connection.execute("ROLLBACK")
                    except BaseException as rollback_exc:
                        raise MigrationError("MIGRATION_RECOVERY_REQUIRED") from rollback_exc
                elif commit_attempted:
                    raise MigrationError("MIGRATION_RECOVERY_REQUIRED") from exc
                if isinstance(exc, MigrationError):
                    raise
                raise MigrationError("MIGRATION_ROLLED_BACK") from exc
            finally:
                connection.close()

            try:
                fault("after_commit")
                self.repository.ensure_readable()
                with _readonly_connection(self.path) as verification:
                    receipt = verification.execute(
                        """
                        SELECT source_fingerprint, target_fingerprint
                        FROM migration_runs WHERE plan_id=?
                        """,
                        (plan.plan_id,),
                    ).fetchone()
                    if (
                        receipt is None
                        or receipt["source_fingerprint"] != plan.source_fingerprint
                        or receipt["target_fingerprint"] != target_fingerprint
                        or self._logical_fingerprint_connection(verification)
                        != target_fingerprint
                    ):
                        raise MigrationError("MIGRATION_RECOVERY_REQUIRED")
            except BaseException as exc:
                if isinstance(exc, MigrationError) and exc.code == "MIGRATION_RECOVERY_REQUIRED":
                    raise
                raise MigrationError("MIGRATION_RECOVERY_REQUIRED") from exc
            return MigrationResult("applied", plan.plan_id, str(backup_path))

    @staticmethod
    def _utc_now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def _apply_0001(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
              version INTEGER PRIMARY KEY CHECK (version > 0),
              name TEXT NOT NULL UNIQUE,
              checksum_sha256 TEXT NOT NULL CHECK (length(checksum_sha256) = 64),
              app_version TEXT NOT NULL,
              plan_id TEXT NOT NULL,
              applied_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE migration_runs (
              plan_id TEXT PRIMARY KEY,
              source_database_version INTEGER NOT NULL,
              target_database_version INTEGER NOT NULL,
              source_fingerprint TEXT NOT NULL,
              target_fingerprint TEXT NOT NULL,
              resolution_sha256 TEXT,
              backup_path TEXT NOT NULL,
              backup_sha256 TEXT NOT NULL,
              summary_json TEXT NOT NULL,
              applied_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE payload_migration_audit (
              plan_id TEXT NOT NULL,
              record_type TEXT NOT NULL,
              record_key TEXT NOT NULL,
              from_version INTEGER NOT NULL,
              to_version INTEGER NOT NULL,
              before_sha256 TEXT NOT NULL,
              after_sha256 TEXT NOT NULL,
              change_codes_json TEXT NOT NULL,
              resolution_code TEXT,
              resolution_ref TEXT,
              PRIMARY KEY (plan_id, record_type, record_key),
              FOREIGN KEY (plan_id) REFERENCES migration_runs(plan_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recommendation_snapshot_manifests (
              recommendation_id INTEGER PRIMARY KEY,
              snapshot_schema_version INTEGER NOT NULL
                CHECK (snapshot_schema_version IN (0, 1)),
              input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
              result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
              budget_sha256 TEXT NOT NULL CHECK(length(budget_sha256) = 64),
              recorded_at TEXT NOT NULL,
              FOREIGN KEY (recommendation_id) REFERENCES recommendations(id)
            )
            """
        )
        columns = _table_columns(connection, "decisions")
        if "participant_responses_json" not in columns:
            connection.execute(
                "ALTER TABLE decisions ADD COLUMN participant_responses_json TEXT NOT NULL DEFAULT '[]'"
            )

    def _apply_0002(
        self,
        connection: sqlite3.Connection,
        plan_id: str,
        resolutions: Sequence[Dict[str, Any]],
    ) -> Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]:
        before_recommendations = [
            tuple(row)
            for row in connection.execute(
                """
                SELECT id, input_snapshot_json, result_json, budget_json
                FROM recommendations ORDER BY id
                """
            ).fetchall()
        ]
        now = self._utc_now()
        for row in before_recommendations:
            connection.execute(
                """
                INSERT INTO recommendation_snapshot_manifests(
                    recommendation_id, snapshot_schema_version,
                    input_sha256, result_sha256, budget_sha256, recorded_at
                ) VALUES (?, 0, ?, ?, ?, ?)
                """,
                (
                    row[0],
                    _sha256_text(row[1]),
                    _sha256_text(row[2]),
                    _sha256_text(row[3]),
                    now,
                ),
            )

        audits: List[Tuple[Any, ...]] = []
        entity_rows = connection.execute(
            "SELECT kind, entity_id, pilot_id, payload_json, updated_at FROM entities ORDER BY kind, entity_id"
        ).fetchall()
        migrated_entities: List[Tuple[Any, ...]] = []
        used_resolution_ids = set()
        for row in entity_rows:
            try:
                record = json.loads(row["payload_json"])
            except json.JSONDecodeError as exc:
                raise MigrationError("MIGRATION_BLOCKED") from exc
            if not isinstance(record, dict) or not _entity_row_matches_payload(
                row["kind"], row["entity_id"], row["pilot_id"], record
            ):
                raise MigrationError("MIGRATION_BLOCKED")
            matching_resolutions: List[Dict[str, Any]] = []
            if row["kind"] == "demand" and record.get("status") == "closed":
                matching_resolutions = [
                    item
                    for item in resolutions
                    if isinstance(item, dict) and item.get("demand_id") == row["entity_id"]
                ]
                used_resolution_ids.update(item.get("demand_id") for item in matching_resolutions)
            result = migrate_record_v0_to_v1(
                row["kind"], record, resolutions=matching_resolutions
            )
            after_text = _canonical_json(result.record) if result.changed else row["payload_json"]
            migrated_entities.append(
                (
                    row["kind"],
                    row["entity_id"],
                    row["pilot_id"],
                    CURRENT_PAYLOAD_SCHEMA_VERSION,
                    after_text,
                    row["updated_at"],
                )
            )
            if result.changed:
                audits.append(
                    (
                        row["kind"],
                        row["entity_id"],
                        0,
                        1,
                        _sha256_text(row["payload_json"]),
                        _sha256_text(after_text),
                        _canonical_json(list(result.change_codes)),
                        result.resolution_code,
                        result.resolution_ref,
                    )
                )

        if any(
            not isinstance(item, dict) or item.get("demand_id") not in used_resolution_ids
            for item in resolutions
        ):
            raise MigrationError("MIGRATION_BLOCKED")

        outcome_rows = connection.execute(
            """
            SELECT project_id, pilot_id, demand_id, creator_ids_json,
                   payload_json, recorded_at
            FROM outcomes ORDER BY project_id
            """
        ).fetchall()
        migrated_outcomes: List[Tuple[Any, ...]] = []
        for row in outcome_rows:
            try:
                record = json.loads(row["payload_json"])
            except json.JSONDecodeError as exc:
                raise MigrationError("MIGRATION_BLOCKED") from exc
            if not isinstance(record, dict) or not _outcome_row_matches_payload(row, record):
                raise MigrationError("MIGRATION_BLOCKED")
            result = migrate_record_v0_to_v1("outcome", record, resolutions=[])
            after_text = _canonical_json(result.record) if result.changed else row["payload_json"]
            migrated_outcomes.append(
                (
                    row["project_id"],
                    row["pilot_id"],
                    row["demand_id"],
                    row["creator_ids_json"],
                    CURRENT_PAYLOAD_SCHEMA_VERSION,
                    after_text,
                    row["recorded_at"],
                )
            )
            if result.changed:
                audits.append(
                    (
                        "outcome",
                        row["project_id"],
                        0,
                        1,
                        _sha256_text(row["payload_json"]),
                        _sha256_text(after_text),
                        _canonical_json(list(result.change_codes)),
                        result.resolution_code,
                        result.resolution_ref,
                    )
                )

        connection.execute(
            """
            CREATE TABLE entities_v1 (
                kind TEXT NOT NULL CHECK(kind IN ('creator', 'demand')),
                entity_id TEXT NOT NULL,
                pilot_id TEXT,
                payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version = 1),
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (kind, entity_id)
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO entities_v1(
                kind, entity_id, pilot_id, payload_schema_version, payload_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            migrated_entities,
        )
        connection.execute("DROP TABLE entities")
        connection.execute("ALTER TABLE entities_v1 RENAME TO entities")
        connection.execute("CREATE INDEX idx_entities_pilot ON entities(pilot_id, kind)")

        connection.execute(
            """
            CREATE TABLE outcomes_v1 (
                project_id TEXT PRIMARY KEY,
                pilot_id TEXT NOT NULL,
                demand_id TEXT NOT NULL,
                creator_ids_json TEXT NOT NULL,
                payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version = 1),
                payload_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO outcomes_v1(
                project_id, pilot_id, demand_id, creator_ids_json,
                payload_schema_version, payload_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            migrated_outcomes,
        )
        connection.execute("DROP TABLE outcomes")
        connection.execute("ALTER TABLE outcomes_v1 RENAME TO outcomes")
        connection.execute("CREATE INDEX idx_outcomes_pilot ON outcomes(pilot_id, demand_id)")
        return audits, before_recommendations

    @staticmethod
    def _apply_0003(connection: sqlite3.Connection) -> None:
        triggers = (
            (
                "recommendations_history_no_update",
                "BEFORE UPDATE ON recommendations",
            ),
            (
                "recommendations_history_no_delete",
                "BEFORE DELETE ON recommendations",
            ),
            (
                "recommendation_manifests_no_update",
                "BEFORE UPDATE ON recommendation_snapshot_manifests",
            ),
            (
                "recommendation_manifests_no_delete",
                "BEFORE DELETE ON recommendation_snapshot_manifests",
            ),
        )
        for name, timing in triggers:
            connection.execute(
                """
                CREATE TRIGGER {name} {timing}
                BEGIN
                    SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE');
                END
                """.format(name=name, timing=timing)
            )
        for _, definition in MIGRATION_HISTORY_TRIGGER_DEFINITIONS.values():
            connection.execute(definition)

    @staticmethod
    def _logical_fingerprint_connection(connection: sqlite3.Connection) -> str:
        hasher = hashlib.sha256()
        objects = connection.execute(
            """
            SELECT type, name, tbl_name, coalesce(sql, '') AS sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        for row in objects:
            for value in row:
                _feed_value(hasher, value)
        for table in _BUSINESS_TABLES:
            hasher.update(table.encode("ascii"))
            rows = connection.execute(
                'SELECT * FROM "{}" ORDER BY rowid'.format(table)
            ).fetchall()
            for row in rows:
                for value in row:
                    _feed_value(hasher, value)
        return hasher.hexdigest()


__all__ = [
    "MigrationBlocker",
    "MigrationError",
    "MigrationPlan",
    "MigrationResult",
    "MigrationRunner",
    "MigrationStatus",
    "RecordMigrationResult",
    "SqliteBackupService",
    "logical_fingerprint",
    "migrate_record_v0_to_v1",
]
