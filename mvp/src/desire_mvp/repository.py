import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

from .migration_support import (
    CURRENT_DATABASE_VERSION,
    CURRENT_PAYLOAD_SCHEMA_VERSION,
    MIGRATION_APP_VERSION,
    MIGRATION_DESCRIPTORS,
    MIGRATION_HISTORY_TRIGGER_DEFINITIONS,
    MIGRATION_HISTORY_TRIGGER_SCRIPT,
    MigrationError,
    frozen_legacy_variant,
)
from .schema import SchemaContractError, validate_payload_contract, validate_schema_version


SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    kind TEXT NOT NULL CHECK(kind IN ('creator', 'demand')),
    entity_id TEXT NOT NULL,
    pilot_id TEXT,
    payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version = 1),
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, entity_id)
);

CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    demand_id TEXT NOT NULL,
    pilot_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    input_snapshot_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    budget_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recommendation_id INTEGER NOT NULL,
    demand_id TEXT NOT NULL,
    pilot_id TEXT NOT NULL,
    selected_creator_id TEXT,
    invited_creator_ids_json TEXT NOT NULL,
    participant_responses_json TEXT NOT NULL DEFAULT '[]',
    reason_code TEXT NOT NULL,
    reason_note TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(recommendation_id) REFERENCES recommendations(id)
);

CREATE TABLE IF NOT EXISTS outcomes (
    project_id TEXT PRIMARY KEY,
    pilot_id TEXT NOT NULL,
    demand_id TEXT NOT NULL,
    creator_ids_json TEXT NOT NULL,
    payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version = 1),
    payload_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version > 0),
    name TEXT NOT NULL UNIQUE,
    checksum_sha256 TEXT NOT NULL CHECK(length(checksum_sha256) = 64),
    app_version TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS migration_runs (
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
);

CREATE TABLE IF NOT EXISTS payload_migration_audit (
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
);

CREATE TABLE IF NOT EXISTS recommendation_snapshot_manifests (
    recommendation_id INTEGER PRIMARY KEY,
    snapshot_schema_version INTEGER NOT NULL CHECK(snapshot_schema_version IN (0, 1)),
    input_sha256 TEXT NOT NULL CHECK(length(input_sha256) = 64),
    result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
    budget_sha256 TEXT NOT NULL CHECK(length(budget_sha256) = 64),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (recommendation_id) REFERENCES recommendations(id)
);

CREATE INDEX IF NOT EXISTS idx_entities_pilot ON entities(pilot_id, kind);
CREATE INDEX IF NOT EXISTS idx_recommendations_pilot ON recommendations(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pilot ON decisions(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_pilot ON outcomes(pilot_id, demand_id);

CREATE TRIGGER IF NOT EXISTS recommendations_history_no_update
BEFORE UPDATE ON recommendations
BEGIN
    SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS recommendations_history_no_delete
BEFORE DELETE ON recommendations
BEGIN
    SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS recommendation_manifests_no_update
BEFORE UPDATE ON recommendation_snapshot_manifests
BEGIN
    SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS recommendation_manifests_no_delete
BEFORE DELETE ON recommendation_snapshot_manifests
BEGIN
    SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE');
END;
""" + MIGRATION_HISTORY_TRIGGER_SCRIPT


_LEGACY_TABLE_COLUMNS = {
    "entities": frozenset(
        ("kind", "entity_id", "pilot_id", "payload_json", "updated_at")
    ),
    "recommendations": frozenset(
        (
            "id",
            "demand_id",
            "pilot_id",
            "rule_version",
            "input_snapshot_json",
            "result_json",
            "budget_json",
            "created_at",
        )
    ),
    "outcomes": frozenset(
        (
            "project_id",
            "pilot_id",
            "demand_id",
            "creator_ids_json",
            "payload_json",
            "recorded_at",
        )
    ),
}
_LEGACY_DECISION_COLUMNS = (
    frozenset(
        (
            "id",
            "recommendation_id",
            "demand_id",
            "pilot_id",
            "selected_creator_id",
            "invited_creator_ids_json",
            "reason_code",
            "reason_note",
            "created_at",
        )
    ),
    frozenset(
        (
            "id",
            "recommendation_id",
            "demand_id",
            "pilot_id",
            "selected_creator_id",
            "invited_creator_ids_json",
            "participant_responses_json",
            "reason_code",
            "reason_note",
            "created_at",
        )
    ),
)

_CURRENT_STATE = "current"
_LEGACY_STATE = "legacy"
_CURRENT_REQUIRED_COLUMNS = {
    "entities": frozenset(
        ("kind", "entity_id", "pilot_id", "payload_schema_version", "payload_json", "updated_at")
    ),
    "recommendations": _LEGACY_TABLE_COLUMNS["recommendations"],
    "decisions": _LEGACY_DECISION_COLUMNS[1],
    "outcomes": frozenset(
        (
            "project_id",
            "pilot_id",
            "demand_id",
            "creator_ids_json",
            "payload_schema_version",
            "payload_json",
            "recorded_at",
        )
    ),
    "schema_migrations": frozenset(
        ("version", "name", "checksum_sha256", "app_version", "plan_id", "applied_at")
    ),
    "migration_runs": frozenset(
        (
            "plan_id",
            "source_database_version",
            "target_database_version",
            "source_fingerprint",
            "target_fingerprint",
            "resolution_sha256",
            "backup_path",
            "backup_sha256",
            "summary_json",
            "applied_at",
        )
    ),
    "payload_migration_audit": frozenset(
        (
            "plan_id",
            "record_type",
            "record_key",
            "from_version",
            "to_version",
            "before_sha256",
            "after_sha256",
            "change_codes_json",
            "resolution_code",
            "resolution_ref",
        )
    ),
    "recommendation_snapshot_manifests": frozenset(
        (
            "recommendation_id",
            "snapshot_schema_version",
            "input_sha256",
            "result_sha256",
            "budget_sha256",
            "recorded_at",
        )
    ),
}
_CURRENT_REQUIRED_INDEXES = frozenset(
    (
        "idx_entities_pilot",
        "idx_recommendations_pilot",
        "idx_decisions_pilot",
        "idx_outcomes_pilot",
    )
)
_CURRENT_REQUIRED_TRIGGERS = frozenset(
    (
        "recommendations_history_no_update",
        "recommendations_history_no_delete",
        "recommendation_manifests_no_update",
        "recommendation_manifests_no_delete",
    )
) | frozenset(MIGRATION_HISTORY_TRIGGER_DEFINITIONS)
_CURRENT_REQUIRED_INDEX_DEFINITIONS = {
    "idx_entities_pilot": (
        "entities",
        "CREATE INDEX idx_entities_pilot ON entities(pilot_id, kind)",
    ),
    "idx_recommendations_pilot": (
        "recommendations",
        "CREATE INDEX idx_recommendations_pilot ON recommendations(pilot_id, demand_id)",
    ),
    "idx_decisions_pilot": (
        "decisions",
        "CREATE INDEX idx_decisions_pilot ON decisions(pilot_id, demand_id)",
    ),
    "idx_outcomes_pilot": (
        "outcomes",
        "CREATE INDEX idx_outcomes_pilot ON outcomes(pilot_id, demand_id)",
    ),
}
_CURRENT_REQUIRED_TRIGGER_DEFINITIONS = {
    "recommendations_history_no_update": (
        "recommendations",
        """CREATE TRIGGER recommendations_history_no_update
        BEFORE UPDATE ON recommendations
        BEGIN SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE'); END""",
    ),
    "recommendations_history_no_delete": (
        "recommendations",
        """CREATE TRIGGER recommendations_history_no_delete
        BEFORE DELETE ON recommendations
        BEGIN SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE'); END""",
    ),
    "recommendation_manifests_no_update": (
        "recommendation_snapshot_manifests",
        """CREATE TRIGGER recommendation_manifests_no_update
        BEFORE UPDATE ON recommendation_snapshot_manifests
        BEGIN SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE'); END""",
    ),
    "recommendation_manifests_no_delete": (
        "recommendation_snapshot_manifests",
        """CREATE TRIGGER recommendation_manifests_no_delete
        BEFORE DELETE ON recommendation_snapshot_manifests
        BEGIN SELECT RAISE(ABORT, 'RECOMMENDATION_HISTORY_IMMUTABLE'); END""",
    ),
}
_LEGACY_INDEX_NAMES = frozenset(
    (
        "idx_entities_pilot",
        "idx_recommendations_pilot",
        "idx_decisions_pilot",
        "idx_outcomes_pilot",
    )
)
_LEGACY_INDEX_DEFINITIONS = {
    "idx_entities_pilot": ("entities", ("pilot_id", "kind")),
    "idx_recommendations_pilot": ("recommendations", ("pilot_id", "demand_id")),
    "idx_decisions_pilot": ("decisions", ("pilot_id", "demand_id")),
    "idx_outcomes_pilot": ("outcomes", ("pilot_id", "demand_id")),
}
_MANIFEST_COLUMNS = frozenset(
    (
        "recommendation_id",
        "snapshot_schema_version",
        "input_sha256",
        "result_sha256",
        "budget_sha256",
        "recorded_at",
    )
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_schema_sql(value: Any) -> str:
    return " ".join(str(value or "").split())


def canonical_table_sql(value: Any) -> str:
    """Canonicalize managed CREATE TABLE text for exact same-runtime checks."""

    return "".join(str(value or "").replace('"', "").split()).lower()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Repository:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "mvp.sqlite3"

    def connect(self) -> sqlite3.Connection:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def connect_readonly(self) -> sqlite3.Connection:
        """Open the database without creating a directory, file, journal or WAL."""

        if not self.path.is_file():
            raise MigrationError("MIGRATION_REQUIRED")
        database_uri = "file:{}?mode=ro".format(quote(str(self.path.resolve()), safe="/"))
        try:
            connection = sqlite3.connect(database_uri, uri=True)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA query_only = ON")
            return connection
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc

    @contextmanager
    def session(self):
        connection = self.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def readonly_session(self):
        state = self.ensure_readable()
        with self._readonly_connection() as connection:
            yield connection, state

    @contextmanager
    def _readonly_connection(self):
        connection = self.connect_readonly()
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create a new v3 database or validate an already-current database.

        Existing databases are inspected through a read-only connection.  In
        particular, initialize never doubles as a legacy migration.
        """

        if self.path.is_file():
            with self._readonly_connection() as connection:
                tables = self._user_table_names(connection)
                if tables:
                    if "schema_migrations" not in tables:
                        raise MigrationError("MIGRATION_REQUIRED")
                    self._validate_migration_history(connection)
                    self._validate_current_contract(connection)
                    return
        self._bootstrap_current_database()

    def ensure_readable(self) -> str:
        """Validate a source for non-mutating reads and return its adapter state.

        A current database must have an intact registry.  Only the two frozen
        v0 layouts are accepted as legacy read sources.
        """

        with self._readonly_connection() as connection:
            tables = self._user_table_names(connection)
            if "schema_migrations" in tables:
                self._validate_migration_history(connection)
                self._validate_current_contract(connection)
                return _CURRENT_STATE
            if self._is_supported_legacy(connection, tables):
                return _LEGACY_STATE
        raise MigrationError("UNRECOGNIZED_LEGACY_SCHEMA")

    def ensure_writable(self) -> None:
        """Fail closed unless the database is at the complete current version."""

        with self._readonly_connection() as connection:
            self._require_current_connection(connection)
            self._require_payload_column(connection, "entities")
            self._require_payload_column(connection, "outcomes")
            self._require_manifest_table(connection)

    def _bootstrap_current_database(self) -> None:
        connection = self.connect()
        try:
            # executescript otherwise commits before running its first
            # statement.  Putting BEGIN in the script keeps schema + registry
            # creation within one explicit transaction.
            connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
            applied_at = utc_now()
            connection.executemany(
                """
                INSERT INTO schema_migrations(
                    version, name, checksum_sha256, app_version, plan_id, applied_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        descriptor.version,
                        descriptor.name,
                        descriptor.checksum_sha256,
                        MIGRATION_APP_VERSION,
                        "bootstrap-empty-v{}".format(CURRENT_DATABASE_VERSION),
                        applied_at,
                    )
                    for descriptor in MIGRATION_DESCRIPTORS
                ],
            )
            self._validate_migration_history(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _user_table_names(connection: sqlite3.Connection) -> frozenset:
        try:
            rows = connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        return frozenset(row["name"] for row in rows)

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> frozenset:
        # All callers supply internal table constants, never user input.
        try:
            rows = connection.execute("PRAGMA table_info({})".format(table)).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        return frozenset(row["name"] for row in rows)

    @classmethod
    def _is_supported_legacy(
        cls, connection: sqlite3.Connection, tables: frozenset
    ) -> bool:
        try:
            return frozen_legacy_variant(connection) is not None
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc

    @staticmethod
    def _validate_migration_history(connection: sqlite3.Connection) -> None:
        try:
            rows = connection.execute(
                """
                SELECT version, name, checksum_sha256
                FROM schema_migrations ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc

        versions = [row["version"] for row in rows]
        if versions != list(range(1, len(rows) + 1)):
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        if len(rows) > CURRENT_DATABASE_VERSION:
            raise MigrationError("MIGRATION_HISTORY_INVALID")

        for row, descriptor in zip(rows, MIGRATION_DESCRIPTORS):
            if (
                row["name"] != descriptor.name
                or row["checksum_sha256"] != descriptor.checksum_sha256
            ):
                raise MigrationError("MIGRATION_HISTORY_INVALID")
        if len(rows) < CURRENT_DATABASE_VERSION:
            raise MigrationError("MIGRATION_REQUIRED")

    @classmethod
    def _validate_current_contract(cls, connection: sqlite3.Connection) -> None:
        """Verify the managed v3 shape in addition to registry receipts.

        Timestamps and plan IDs are intentionally excluded. Every managed
        table, column, index and trigger must match; unregistered triggers can
        alter write semantics and therefore fail closed.
        """

        tables = cls._user_table_names(connection)
        if not set(_CURRENT_REQUIRED_COLUMNS).issubset(tables):
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        for table, expected_columns in _CURRENT_REQUIRED_COLUMNS.items():
            if cls._table_columns(connection, table) != expected_columns:
                raise MigrationError("MIGRATION_HISTORY_INVALID")
        try:
            reference = sqlite3.connect(":memory:")
            reference.row_factory = sqlite3.Row
            reference.executescript(SCHEMA)
            expected_table_sql = {
                table: canonical_table_sql(
                    reference.execute(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()["sql"]
                )
                for table in _CURRENT_REQUIRED_COLUMNS
            }
            actual_table_sql = {
                table: canonical_table_sql(
                    connection.execute(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()["sql"]
                )
                for table in _CURRENT_REQUIRED_COLUMNS
            }
        except (sqlite3.DatabaseError, KeyError, TypeError) as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        finally:
            try:
                reference.close()
            except (NameError, sqlite3.Error):
                pass
        if actual_table_sql != expected_table_sql:
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql FROM sqlite_master
            WHERE type IN ('index', 'trigger') AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        indexes = {row["name"] for row in rows if row["type"] == "index"}
        triggers = {row["name"] for row in rows if row["type"] == "trigger"}
        if indexes != _CURRENT_REQUIRED_INDEXES:
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        if triggers != _CURRENT_REQUIRED_TRIGGERS:
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        definitions = {
            (row["type"], row["name"]): (
                row["tbl_name"],
                normalize_schema_sql(row["sql"]),
            )
            for row in rows
        }
        expected_definitions = {
            ("index", name): (table, normalize_schema_sql(sql))
            for name, (table, sql) in _CURRENT_REQUIRED_INDEX_DEFINITIONS.items()
        }
        expected_definitions.update(
            {
                ("trigger", name): (table, normalize_schema_sql(sql))
                for name, (table, sql) in _CURRENT_REQUIRED_TRIGGER_DEFINITIONS.items()
            }
        )
        expected_definitions.update(
            {
                ("trigger", name): (table, normalize_schema_sql(sql))
                for name, (table, sql) in MIGRATION_HISTORY_TRIGGER_DEFINITIONS.items()
            }
        )
        if any(
            definitions.get(key) != expected
            for key, expected in expected_definitions.items()
        ):
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        cls._validate_migration_receipt_chain(connection)

    @staticmethod
    def _validate_migration_receipt_chain(connection: sqlite3.Connection) -> None:
        """Validate the immutable registry/receipt link, not mutable business rows."""

        def is_digest(value: Any) -> bool:
            return (
                isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
            )

        try:
            registry_rows = connection.execute(
                "SELECT plan_id FROM schema_migrations ORDER BY version"
            ).fetchall()
            run_rows = connection.execute(
                """
                SELECT plan_id, source_database_version, target_database_version,
                       source_fingerprint, target_fingerprint, resolution_sha256,
                       backup_path, backup_sha256, summary_json
                FROM migration_runs ORDER BY plan_id
                """
            ).fetchall()
            audit_plan_ids = {
                row["plan_id"]
                for row in connection.execute(
                    "SELECT DISTINCT plan_id FROM payload_migration_audit"
                ).fetchall()
            }
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        registry_plan_ids = {row["plan_id"] for row in registry_rows}
        bootstrap_id = "bootstrap-empty-v{}".format(CURRENT_DATABASE_VERSION)
        if registry_plan_ids == {bootstrap_id}:
            if run_rows or audit_plan_ids:
                raise MigrationError("MIGRATION_HISTORY_INVALID")
            return
        if len(registry_plan_ids) != 1 or len(run_rows) != 1:
            raise MigrationError("MIGRATION_HISTORY_INVALID")
        plan_id = next(iter(registry_plan_ids))
        row = run_rows[0]
        digest_values = (
            plan_id,
            row["source_fingerprint"],
            row["target_fingerprint"],
            row["backup_sha256"],
        )
        try:
            summary = json.loads(row["summary_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        expected_summary_fields = {
            "entities",
            "outcomes",
            "v0_records",
            "v1_records",
            "recommendations",
        }
        if (
            row["plan_id"] != plan_id
            or row["source_database_version"] != 0
            or row["target_database_version"] != CURRENT_DATABASE_VERSION
            or any(not is_digest(value) for value in digest_values)
            or (
                row["resolution_sha256"] is not None
                and not is_digest(row["resolution_sha256"])
            )
            or not isinstance(row["backup_path"], str)
            or not row["backup_path"]
            or type(summary) is not dict
            or set(summary) != expected_summary_fields
            or any(type(count) is not int or count < 0 for count in summary.values())
            or audit_plan_ids - {plan_id}
        ):
            raise MigrationError("MIGRATION_HISTORY_INVALID")

    @classmethod
    def _require_current_connection(cls, connection: sqlite3.Connection) -> None:
        tables = cls._user_table_names(connection)
        if "schema_migrations" not in tables:
            raise MigrationError("MIGRATION_REQUIRED")
        cls._validate_migration_history(connection)
        cls._validate_current_contract(connection)

    @classmethod
    def _require_payload_column(cls, connection: sqlite3.Connection, table: str) -> None:
        try:
            columns = connection.execute("PRAGMA table_info({})".format(table)).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MigrationError("MIGRATION_HISTORY_INVALID") from exc
        version_column = next(
            (row for row in columns if row["name"] == "payload_schema_version"), None
        )
        if (
            version_column is None
            or str(version_column["type"]).upper() != "INTEGER"
            or version_column["notnull"] != 1
        ):
            raise MigrationError("MIGRATION_HISTORY_INVALID")

    @classmethod
    def _require_manifest_table(cls, connection: sqlite3.Connection) -> None:
        if (
            cls._table_columns(connection, "recommendation_snapshot_manifests")
            != _MANIFEST_COLUMNS
        ):
            raise MigrationError("MIGRATION_HISTORY_INVALID")

    def put_entity(self, kind: str, record: Dict[str, Any]) -> None:
        self.put_entities(kind, [record])

    @staticmethod
    def _decode_payload(
        record_type: str,
        payload_text: Any,
        *,
        current: bool,
        payload_schema_version: Any = None,
        expected_identity: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            record = json.loads(payload_text)
        except (TypeError, json.JSONDecodeError) as exc:
            raise SchemaContractError() from exc
        if not isinstance(record, dict):
            raise SchemaContractError()
        if current:
            if (
                type(payload_schema_version) is not int
                or payload_schema_version != CURRENT_PAYLOAD_SCHEMA_VERSION
            ):
                raise SchemaContractError()
            validate_payload_contract(record_type, record)
            if record.get("schema_version") != payload_schema_version:
                raise SchemaContractError()
            if expected_identity is not None and any(
                record.get(key) != value for key, value in expected_identity.items()
            ):
                raise SchemaContractError()
        return record

    def put_entities(self, kind: str, records: Iterable[Dict[str, Any]]) -> None:
        if kind not in ("creator", "demand"):
            raise ValueError("未知资料类型: {}".format(kind))
        batch = list(records)
        if not batch:
            raise ValueError("导入批次不能为空")
        entity_ids = [record.get("id") for record in batch]
        if any(not isinstance(entity_id, str) or not entity_id for entity_id in entity_ids):
            raise ValueError("资料 id 必须是非空字符串")
        if len(set(entity_ids)) != len(entity_ids):
            raise ValueError("同一批次不能包含重复 id")
        self.ensure_writable()
        payload_versions = []
        for record in batch:
            validate_payload_contract(kind, record)
            payload_versions.append(validate_schema_version(record))
        timestamp = utc_now()
        rows = [
            (
                kind,
                entity_id,
                record.get("pilot_id") if kind == "demand" else None,
                payload_version,
                canonical_json(record),
                timestamp,
            )
            for entity_id, record, payload_version in zip(
                entity_ids, batch, payload_versions
            )
        ]
        with self.session() as connection:
            self._require_current_connection(connection)
            self._require_payload_column(connection, "entities")
            self._write_entity_rows(connection, rows)

    @staticmethod
    def _write_entity_rows(
        connection: sqlite3.Connection, rows: Iterable[tuple]
    ) -> None:
        connection.executemany(
            """
            INSERT INTO entities(
                kind, entity_id, pilot_id, payload_schema_version,
                payload_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(kind, entity_id) DO UPDATE SET
                pilot_id=excluded.pilot_id,
                payload_schema_version=excluded.payload_schema_version,
                payload_json=excluded.payload_json,
                updated_at=excluded.updated_at
            """,
            rows,
        )

    def get_entity(self, kind: str, entity_id: str) -> Dict[str, Any]:
        if kind not in ("creator", "demand"):
            raise ValueError("未知资料类型: {}".format(kind))
        with self.readonly_session() as (connection, state):
            columns = (
                "entity_id, pilot_id, payload_json, payload_schema_version"
                if state == _CURRENT_STATE
                else "payload_json"
            )
            row = connection.execute(
                "SELECT {} FROM entities WHERE kind=? AND entity_id=?".format(columns),
                (kind, entity_id),
            ).fetchone()
        if row is None:
            raise KeyError("找不到 {}: {}".format(kind, entity_id))
        if state == _CURRENT_STATE and kind == "creator" and row["pilot_id"] is not None:
            raise SchemaContractError()
        return self._decode_payload(
            kind,
            row["payload_json"],
            current=state == _CURRENT_STATE,
            payload_schema_version=(
                row["payload_schema_version"] if state == _CURRENT_STATE else None
            ),
            expected_identity=(
                {
                    "id": row["entity_id"],
                    **({"pilot_id": row["pilot_id"]} if kind == "demand" else {}),
                }
                if state == _CURRENT_STATE
                else None
            ),
        )

    def list_entities(self, kind: str, pilot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if kind not in ("creator", "demand"):
            raise ValueError("未知资料类型: {}".format(kind))
        params: List[Any] = [kind]
        with self.readonly_session() as (connection, state):
            columns = (
                "entity_id, pilot_id, payload_json, payload_schema_version"
                if state == _CURRENT_STATE
                else "payload_json"
            )
            sql = "SELECT {} FROM entities WHERE kind=?".format(columns)
            if pilot_id is not None:
                sql += " AND pilot_id=?"
                params.append(pilot_id)
            sql += " ORDER BY entity_id"
            rows = connection.execute(sql, params).fetchall()
        decoded = []
        for row in rows:
            if state == _CURRENT_STATE and kind == "creator" and row["pilot_id"] is not None:
                raise SchemaContractError()
            decoded.append(self._decode_payload(
                kind,
                row["payload_json"],
                current=state == _CURRENT_STATE,
                payload_schema_version=(
                    row["payload_schema_version"] if state == _CURRENT_STATE else None
                ),
                expected_identity=(
                    {
                        "id": row["entity_id"],
                        **({"pilot_id": row["pilot_id"]} if kind == "demand" else {}),
                    }
                    if state == _CURRENT_STATE
                    else None
                ),
            ))
        return decoded

    def record_recommendation(
        self,
        demand: Dict[str, Any],
        creators: Iterable[Dict[str, Any]],
        rule_version: str,
        result: Dict[str, Any],
        budget: Dict[str, Any],
    ) -> int:
        creator_records = list(creators)
        self.ensure_writable()
        validate_payload_contract("demand", demand)
        validate_schema_version(demand)
        for creator in creator_records:
            validate_payload_contract("creator", creator)
            validate_schema_version(creator)
        snapshot = {
            "schema_version": CURRENT_PAYLOAD_SCHEMA_VERSION,
            "demand": demand,
            "creators": sorted(creator_records, key=lambda item: str(item.get("id", ""))),
        }
        input_snapshot_json = canonical_json(snapshot)
        result_json = canonical_json(result)
        budget_json = canonical_json(budget)
        recorded_at = utc_now()
        with self.session() as connection:
            self._require_current_connection(connection)
            self._require_manifest_table(connection)
            cursor = connection.execute(
                """
                INSERT INTO recommendations(
                    demand_id, pilot_id, rule_version, input_snapshot_json,
                    result_json, budget_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(demand.get("id")),
                    str(demand.get("pilot_id")),
                    rule_version,
                    input_snapshot_json,
                    result_json,
                    budget_json,
                    recorded_at,
                ),
            )
            recommendation_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO recommendation_snapshot_manifests(
                    recommendation_id, snapshot_schema_version, input_sha256,
                    result_sha256, budget_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    recommendation_id,
                    CURRENT_PAYLOAD_SCHEMA_VERSION,
                    sha256_text(input_snapshot_json),
                    sha256_text(result_json),
                    sha256_text(budget_json),
                    recorded_at,
                ),
            )
            return recommendation_id

    def latest_recommendation(self, demand_id: str) -> Dict[str, Any]:
        with self.readonly_session() as (connection, state):
            row = self._recommendation_query(
                connection,
                state,
                "WHERE r.demand_id=? ORDER BY r.id DESC LIMIT 1",
                (demand_id,),
            ).fetchone()
        if row is None:
            raise KeyError("需求 {} 还没有匹配快照".format(demand_id))
        return self._recommendation_row(row, state == _CURRENT_STATE)

    def recommendations_for_pilot(self, pilot_id: str) -> List[Dict[str, Any]]:
        with self.readonly_session() as (connection, state):
            rows = self._recommendation_query(
                connection,
                state,
                "WHERE r.pilot_id=? ORDER BY r.id",
                (pilot_id,),
            ).fetchall()
        return [
            self._recommendation_row(row, state == _CURRENT_STATE) for row in rows
        ]

    @staticmethod
    def _recommendation_query(
        connection: sqlite3.Connection,
        state: str,
        suffix: str,
        params: tuple,
    ) -> sqlite3.Cursor:
        if state == _LEGACY_STATE:
            return connection.execute("SELECT r.* FROM recommendations r " + suffix, params)
        try:
            return connection.execute(
                """
                SELECT r.*,
                       m.snapshot_schema_version AS manifest_schema_version,
                       m.input_sha256 AS manifest_input_sha256,
                       m.result_sha256 AS manifest_result_sha256,
                       m.budget_sha256 AS manifest_budget_sha256
                FROM recommendations r
                LEFT JOIN recommendation_snapshot_manifests m
                  ON m.recommendation_id = r.id
                """
                + suffix,
                params,
            )
        except sqlite3.DatabaseError as exc:
            raise MigrationError("HISTORY_INTEGRITY_ERROR") from exc

    @staticmethod
    def _recommendation_row(row: sqlite3.Row, verify_manifest: bool) -> Dict[str, Any]:
        input_snapshot_json = row["input_snapshot_json"]
        result_json = row["result_json"]
        budget_json = row["budget_json"]
        if verify_manifest:
            manifest_version = row["manifest_schema_version"]
            if type(manifest_version) is not int or manifest_version not in (0, 1):
                raise MigrationError("HISTORY_INTEGRITY_ERROR")
            digests = (
                (input_snapshot_json, row["manifest_input_sha256"]),
                (result_json, row["manifest_result_sha256"]),
                (budget_json, row["manifest_budget_sha256"]),
            )
            if any(
                not isinstance(value, str)
                or not isinstance(expected, str)
                or sha256_text(value) != expected
                for value, expected in digests
            ):
                raise MigrationError("HISTORY_INTEGRITY_ERROR")
        try:
            input_snapshot = json.loads(input_snapshot_json)
            result = json.loads(result_json)
            budget = json.loads(budget_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise MigrationError("HISTORY_INTEGRITY_ERROR") from exc
        if verify_manifest and row["manifest_schema_version"] == 1:
            if (
                not isinstance(input_snapshot, dict)
                or type(input_snapshot.get("schema_version")) is not int
                or input_snapshot["schema_version"] != CURRENT_PAYLOAD_SCHEMA_VERSION
            ):
                raise MigrationError("HISTORY_INTEGRITY_ERROR")
        return {
            "id": row["id"],
            "demand_id": row["demand_id"],
            "pilot_id": row["pilot_id"],
            "rule_version": row["rule_version"],
            "input_snapshot": input_snapshot,
            "result": result,
            "budget": budget,
            "created_at": row["created_at"],
        }

    def record_decision(
        self,
        recommendation_id: int,
        demand_id: str,
        pilot_id: str,
        selected_creator_id: Optional[str],
        invited_creator_ids: List[str],
        participant_responses: List[Dict[str, Any]],
        reason_code: str,
        reason_note: Optional[str],
    ) -> int:
        self.ensure_writable()
        with self.session() as connection:
            self._require_current_connection(connection)
            cursor = connection.execute(
                """
                INSERT INTO decisions(
                    recommendation_id, demand_id, pilot_id, selected_creator_id,
                    invited_creator_ids_json, participant_responses_json,
                    reason_code, reason_note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recommendation_id,
                    demand_id,
                    pilot_id,
                    selected_creator_id,
                    canonical_json(sorted(invited_creator_ids)),
                    canonical_json(participant_responses),
                    reason_code,
                    reason_note,
                    utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    def decisions_for_pilot(self, pilot_id: str) -> List[Dict[str, Any]]:
        with self.readonly_session() as (connection, _):
            rows = connection.execute(
                "SELECT * FROM decisions WHERE pilot_id=? ORDER BY id", (pilot_id,)
            ).fetchall()
        return [
            {
                "id": row["id"],
                "recommendation_id": row["recommendation_id"],
                "demand_id": row["demand_id"],
                "pilot_id": row["pilot_id"],
                "selected_creator_id": row["selected_creator_id"],
                "invited_creator_ids": json.loads(row["invited_creator_ids_json"]),
                "participant_responses": (
                    json.loads(row["participant_responses_json"])
                    if "participant_responses_json" in row.keys()
                    else []
                ),
                "reason_code": row["reason_code"],
                "reason_note": row["reason_note"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_outcome(self, outcome: Dict[str, Any]) -> None:
        required = ("project_id", "pilot_id", "demand_id", "creator_ids")
        missing = [key for key in required if key not in outcome]
        if missing:
            raise ValueError("结果记录缺少: {}".format(", ".join(missing)))
        self.ensure_writable()
        validate_payload_contract("outcome", outcome)
        payload_version = validate_schema_version(outcome)
        with self.session() as connection:
            self._require_current_connection(connection)
            self._require_payload_column(connection, "outcomes")
            connection.execute(
                """
                INSERT INTO outcomes(
                    project_id, pilot_id, demand_id, creator_ids_json,
                    payload_schema_version, payload_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    pilot_id=excluded.pilot_id,
                    demand_id=excluded.demand_id,
                    creator_ids_json=excluded.creator_ids_json,
                    payload_schema_version=excluded.payload_schema_version,
                    payload_json=excluded.payload_json,
                    recorded_at=excluded.recorded_at
                """,
                (
                    str(outcome["project_id"]),
                    str(outcome["pilot_id"]),
                    str(outcome["demand_id"]),
                    canonical_json(outcome["creator_ids"]),
                    payload_version,
                    canonical_json(outcome),
                    utc_now(),
                ),
            )

    def outcomes_for_pilot(self, pilot_id: str) -> List[Dict[str, Any]]:
        with self.readonly_session() as (connection, state):
            columns = (
                "project_id, pilot_id, demand_id, creator_ids_json, payload_json, payload_schema_version"
                if state == _CURRENT_STATE
                else "payload_json"
            )
            rows = connection.execute(
                "SELECT {} FROM outcomes WHERE pilot_id=? ORDER BY project_id".format(
                    columns
                ),
                (pilot_id,),
            ).fetchall()
        decoded = []
        for row in rows:
            expected_identity = None
            if state == _CURRENT_STATE:
                try:
                    creator_ids = json.loads(row["creator_ids_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise SchemaContractError() from exc
                if not isinstance(creator_ids, list):
                    raise SchemaContractError()
                expected_identity = {
                    "project_id": row["project_id"],
                    "pilot_id": row["pilot_id"],
                    "demand_id": row["demand_id"],
                    "creator_ids": creator_ids,
                }
            decoded.append(self._decode_payload(
                "outcome",
                row["payload_json"],
                current=state == _CURRENT_STATE,
                payload_schema_version=(
                    row["payload_schema_version"] if state == _CURRENT_STATE else None
                ),
                expected_identity=expected_identity,
            ))
        return decoded
