"""Frozen SQLite v0 fixtures for the schema migration contract tests.

This module deliberately does not import ``desire_mvp.repository.SCHEMA``.  That
constant becomes the v1 schema during the implementation, while these fixtures
must continue to represent the two database layouts already distributed to
operators.
"""

import copy
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from helpers import load_sample


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


def json_text(value: Any, *, pretty: bool = False) -> str:
    """Encode JSON deterministically, retaining a distinct legacy pretty form."""

    if pretty:
        return json.dumps(value, ensure_ascii=False, indent=1, sort_keys=False) + "\n"
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def legacy_records() -> Dict[str, Any]:
    """Return valid v0 records plus one already-v1 identity record.

    The withdrawn creator exercises the only automatic semantic conversion in
    the storage migration.  The second creator is already v1 and its raw JSON
    TEXT must not be reserialized by a mixed-version migration.
    """

    demand = copy.deepcopy(load_sample("demands.json")[0])
    withdrawn_creator = copy.deepcopy(load_sample("creators.json")[0])
    demand.pop("schema_version", None)
    withdrawn_creator.pop("schema_version", None)
    withdrawn_creator["status"] = "withdrawn"
    current_creator = copy.deepcopy(load_sample("creators.json")[1])
    current_creator["schema_version"] = 1
    outcome = copy.deepcopy(load_sample("outcome.json"))
    outcome.pop("schema_version", None)

    snapshot = {"demand": demand, "creators": [withdrawn_creator]}
    result = {
        "ranked": [],
        "excluded": [{"creator_id": withdrawn_creator["id"], "reasons": []}],
        "invalid_creators": [],
    }
    budget = {
        "demand_id": demand["id"],
        "currency": "CNY",
        "recommended_minimum": 24000,
        "budget_maximum": 26000,
        "status": "healthy",
        "config_version": "budget-v1",
    }

    return {
        "demand": demand,
        "withdrawn_creator": withdrawn_creator,
        "current_creator": current_creator,
        "outcome": outcome,
        # Pretty JSON and a trailing newline make accidental canonicalization
        # observable even when the decoded JSON objects would compare equal.
        "recommendation_blobs": (
            json_text(snapshot, pretty=True),
            json_text(result, pretty=True),
            json_text(budget, pretty=True),
        ),
    }


def create_legacy_database(
    data_dir: Path,
    *,
    variant: str = "v0b",
    with_records: bool = True,
    entity_payload_overrides: Optional[Mapping[str, str]] = None,
) -> Path:
    """Create a frozen legacy database and return its SQLite path."""

    if variant not in {"v0a", "v0b"}:
        raise ValueError("variant must be v0a or v0b")
    data_dir.mkdir(parents=True, exist_ok=True)
    database_path = data_dir / "mvp.sqlite3"
    schema = LEGACY_V0A_SCHEMA if variant == "v0a" else LEGACY_V0B_SCHEMA
    records = legacy_records()
    overrides = dict(entity_payload_overrides or {})

    connection = sqlite3.connect(str(database_path))
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema)
        if not with_records:
            connection.commit()
            return database_path

        timestamp = "2026-08-01T00:00:00+00:00"
        entity_rows = [
            (
                "demand",
                records["demand"]["id"],
                records["demand"]["pilot_id"],
                overrides.get(records["demand"]["id"], json_text(records["demand"])),
                timestamp,
            ),
            (
                "creator",
                records["withdrawn_creator"]["id"],
                None,
                overrides.get(
                    records["withdrawn_creator"]["id"],
                    json_text(records["withdrawn_creator"]),
                ),
                timestamp,
            ),
            (
                "creator",
                records["current_creator"]["id"],
                None,
                overrides.get(
                    records["current_creator"]["id"],
                    json_text(records["current_creator"], pretty=True),
                ),
                timestamp,
            ),
        ]
        connection.executemany(
            """
            INSERT INTO entities(kind, entity_id, pilot_id, payload_json, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            entity_rows,
        )

        input_blob, result_blob, budget_blob = records["recommendation_blobs"]
        cursor = connection.execute(
            """
            INSERT INTO recommendations(
                demand_id, pilot_id, rule_version, input_snapshot_json,
                result_json, budget_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                records["demand"]["id"],
                records["demand"]["pilot_id"],
                "matching-v1+budget-v1",
                input_blob,
                result_blob,
                budget_blob,
                timestamp,
            ),
        )
        recommendation_id = int(cursor.lastrowid)

        decision_columns = (
            "recommendation_id, demand_id, pilot_id, selected_creator_id, "
            "invited_creator_ids_json, reason_code, reason_note, created_at"
        )
        decision_values = (
            recommendation_id,
            records["demand"]["id"],
            records["demand"]["pilot_id"],
            None,
            "[]",
            "NO_ELIGIBLE_CREATOR",
            None,
            timestamp,
        )
        if variant == "v0b":
            decision_columns = decision_columns.replace(
                "invited_creator_ids_json,",
                "invited_creator_ids_json, participant_responses_json,",
            )
            decision_values = decision_values[:5] + ("[]",) + decision_values[5:]
        placeholders = ", ".join("?" for _ in decision_values)
        connection.execute(
            "INSERT INTO decisions({}) VALUES ({})".format(decision_columns, placeholders),
            decision_values,
        )

        outcome = records["outcome"]
        connection.execute(
            """
            INSERT INTO outcomes(
                project_id, pilot_id, demand_id, creator_ids_json,
                payload_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                outcome["project_id"],
                outcome["pilot_id"],
                outcome["demand_id"],
                json_text(outcome["creator_ids"]),
                json_text(outcome),
                timestamp,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return database_path


def table_exists(database_path: Path, table_name: str) -> bool:
    with sqlite3.connect(str(database_path)) as connection:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
        ).fetchone()
    return row is not None


def logical_database_snapshot(database_path: Path) -> Dict[str, Any]:
    """Capture schema and raw row values without changing the database."""

    with sqlite3.connect(str(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        objects = [
            tuple(row)
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
        ]
        table_names = [row[1] for row in objects if row[0] == "table"]
        rows: Dict[str, Any] = {}
        for table_name in table_names:
            quoted_name = '"{}"'.format(table_name.replace('"', '""'))
            rows[table_name] = [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM {} ORDER BY rowid".format(quoted_name)
                ).fetchall()
            ]
    return {"objects": objects, "rows": rows}


def recommendation_blob_rows(database_path: Path) -> Iterable[tuple]:
    with sqlite3.connect(str(database_path)) as connection:
        return connection.execute(
            """
            SELECT id, input_snapshot_json, result_json, budget_json
            FROM recommendations ORDER BY id
            """
        ).fetchall()
