import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Optional, Tuple


CURRENT_DATABASE_VERSION = 3
CURRENT_PAYLOAD_SCHEMA_VERSION = 1
MIGRATION_APP_VERSION = "0.2.0"


MIGRATION_HISTORY_TRIGGER_DEFINITIONS = {
    "schema_migrations_no_insert_after_current": (
        "schema_migrations",
        """CREATE TRIGGER schema_migrations_no_insert_after_current
        BEFORE INSERT ON schema_migrations
        WHEN (SELECT count(*) FROM schema_migrations) >= 3
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "schema_migrations_no_update": (
        "schema_migrations",
        """CREATE TRIGGER schema_migrations_no_update
        BEFORE UPDATE ON schema_migrations
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "schema_migrations_no_delete": (
        "schema_migrations",
        """CREATE TRIGGER schema_migrations_no_delete
        BEFORE DELETE ON schema_migrations
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "migration_runs_no_insert_after_registry": (
        "migration_runs",
        """CREATE TRIGGER migration_runs_no_insert_after_registry
        BEFORE INSERT ON migration_runs
        WHEN EXISTS (SELECT 1 FROM schema_migrations)
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "migration_runs_no_update": (
        "migration_runs",
        """CREATE TRIGGER migration_runs_no_update
        BEFORE UPDATE ON migration_runs
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "migration_runs_no_delete": (
        "migration_runs",
        """CREATE TRIGGER migration_runs_no_delete
        BEFORE DELETE ON migration_runs
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "payload_migration_audit_no_insert_after_registry": (
        "payload_migration_audit",
        """CREATE TRIGGER payload_migration_audit_no_insert_after_registry
        BEFORE INSERT ON payload_migration_audit
        WHEN EXISTS (SELECT 1 FROM schema_migrations)
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "payload_migration_audit_no_update": (
        "payload_migration_audit",
        """CREATE TRIGGER payload_migration_audit_no_update
        BEFORE UPDATE ON payload_migration_audit
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
    "payload_migration_audit_no_delete": (
        "payload_migration_audit",
        """CREATE TRIGGER payload_migration_audit_no_delete
        BEFORE DELETE ON payload_migration_audit
        BEGIN SELECT RAISE(ABORT, 'MIGRATION_HISTORY_IMMUTABLE'); END""",
    ),
}

MIGRATION_HISTORY_TRIGGER_SCRIPT = ";\n".join(
    definition[1] for definition in MIGRATION_HISTORY_TRIGGER_DEFINITIONS.values()
) + ";\n"


LEGACY_V0A_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    kind TEXT NOT NULL CHECK(kind IN ('creator', 'demand')),
    entity_id TEXT NOT NULL,
    pilot_id TEXT,
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
    payload_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_pilot ON entities(pilot_id, kind);
CREATE INDEX IF NOT EXISTS idx_recommendations_pilot ON recommendations(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pilot ON decisions(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_pilot ON outcomes(pilot_id, demand_id);
"""

LEGACY_V0B_SCHEMA = LEGACY_V0A_SCHEMA.replace(
    "    invited_creator_ids_json TEXT NOT NULL,\n",
    "    invited_creator_ids_json TEXT NOT NULL,\n"
    "    participant_responses_json TEXT NOT NULL DEFAULT '[]',\n",
)


def _canonical_schema_sql(value: object) -> str:
    return "".join(str(value or "").replace('"', "").split()).lower()


def _schema_objects(connection: sqlite3.Connection) -> Tuple[Tuple[str, ...], ...]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, coalesce(sql, '')
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    return tuple(
        (str(row[0]), str(row[1]), str(row[2]), _canonical_schema_sql(row[3]))
        for row in rows
    )


def frozen_legacy_variant(connection: sqlite3.Connection) -> Optional[str]:
    """Return the exact frozen v0 layout, or ``None`` for any DDL drift."""

    actual = _schema_objects(connection)
    for variant, schema in (("v0a", LEGACY_V0A_SCHEMA), ("v0b", LEGACY_V0B_SCHEMA)):
        reference = sqlite3.connect(":memory:")
        try:
            reference.executescript(schema)
            if actual == _schema_objects(reference):
                return variant
        finally:
            reference.close()
    return None


class MigrationError(ValueError):
    """Expected, stable migration failure safe for CLI reporting."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__("{}{}".format(code, ": {}".format(message) if message else ""))


@dataclass(frozen=True)
class MigrationDescriptor:
    version: int
    name: str
    descriptor: str

    @property
    def checksum_sha256(self) -> str:
        return hashlib.sha256(self.descriptor.encode("utf-8")).hexdigest()


MIGRATION_DESCRIPTORS: Tuple[MigrationDescriptor, ...] = (
    MigrationDescriptor(
        1,
        "0001_bootstrap_and_expand",
        "v1:create-registry-run-audit-snapshot-manifest;add-participant-responses",
    ),
    MigrationDescriptor(
        2,
        "0002_backfill_payload_v1",
        "v1:migrate-current-entities-and-outcomes;preserve-recommendation-blobs",
    ),
    MigrationDescriptor(
        3,
        "0003_contract_v1_and_history",
        "v2:payload-version-columns;recommendation-manifest-and-migration-history-immutability",
    ),
)


def descriptor_for(version: int) -> MigrationDescriptor:
    for descriptor in MIGRATION_DESCRIPTORS:
        if descriptor.version == version:
            return descriptor
    raise MigrationError("MIGRATION_HISTORY_INVALID")
