import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SCHEMA = """
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
    payload_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_pilot ON entities(pilot_id, kind);
CREATE INDEX IF NOT EXISTS idx_recommendations_pilot ON recommendations(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pilot ON decisions(pilot_id, demand_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_pilot ON outcomes(pilot_id, demand_id);
"""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(decisions)").fetchall()
            }
            if "participant_responses_json" not in columns:
                connection.execute(
                    "ALTER TABLE decisions ADD COLUMN participant_responses_json TEXT NOT NULL DEFAULT '[]'"
                )

    def put_entity(self, kind: str, record: Dict[str, Any]) -> None:
        if kind not in ("creator", "demand"):
            raise ValueError("未知资料类型: {}".format(kind))
        entity_id = record.get("id")
        if not entity_id:
            raise ValueError("资料缺少 id")
        pilot_id = record.get("pilot_id") if kind == "demand" else None
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO entities(kind, entity_id, pilot_id, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(kind, entity_id) DO UPDATE SET
                    pilot_id=excluded.pilot_id,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (kind, str(entity_id), pilot_id, canonical_json(record), utc_now()),
            )

    def get_entity(self, kind: str, entity_id: str) -> Dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM entities WHERE kind=? AND entity_id=?", (kind, entity_id)
            ).fetchone()
        if row is None:
            raise KeyError("找不到 {}: {}".format(kind, entity_id))
        return json.loads(row["payload_json"])

    def list_entities(self, kind: str, pilot_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT payload_json FROM entities WHERE kind=?"
        params: List[Any] = [kind]
        if pilot_id is not None:
            sql += " AND pilot_id=?"
            params.append(pilot_id)
        sql += " ORDER BY entity_id"
        with self.connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def record_recommendation(
        self,
        demand: Dict[str, Any],
        creators: Iterable[Dict[str, Any]],
        rule_version: str,
        result: Dict[str, Any],
        budget: Dict[str, Any],
    ) -> int:
        snapshot = {
            "demand": demand,
            "creators": sorted(creators, key=lambda item: str(item.get("id", ""))),
        }
        with self.connect() as connection:
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
                    canonical_json(snapshot),
                    canonical_json(result),
                    canonical_json(budget),
                    utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    def latest_recommendation(self, demand_id: str) -> Dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM recommendations WHERE demand_id=? ORDER BY id DESC LIMIT 1", (demand_id,)
            ).fetchone()
        if row is None:
            raise KeyError("需求 {} 还没有匹配快照".format(demand_id))
        return self._recommendation_row(row)

    def recommendations_for_pilot(self, pilot_id: str) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM recommendations WHERE pilot_id=? ORDER BY id", (pilot_id,)
            ).fetchall()
        return [self._recommendation_row(row) for row in rows]

    @staticmethod
    def _recommendation_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "demand_id": row["demand_id"],
            "pilot_id": row["pilot_id"],
            "rule_version": row["rule_version"],
            "input_snapshot": json.loads(row["input_snapshot_json"]),
            "result": json.loads(row["result_json"]),
            "budget": json.loads(row["budget_json"]),
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
        with self.connect() as connection:
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
        with self.connect() as connection:
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
                "participant_responses": json.loads(row["participant_responses_json"]),
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
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO outcomes(
                    project_id, pilot_id, demand_id, creator_ids_json, payload_json, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    pilot_id=excluded.pilot_id,
                    demand_id=excluded.demand_id,
                    creator_ids_json=excluded.creator_ids_json,
                    payload_json=excluded.payload_json,
                    recorded_at=excluded.recorded_at
                """,
                (
                    str(outcome["project_id"]),
                    str(outcome["pilot_id"]),
                    str(outcome["demand_id"]),
                    canonical_json(outcome["creator_ids"]),
                    canonical_json(outcome),
                    utc_now(),
                ),
            )

    def outcomes_for_pilot(self, pilot_id: str) -> List[Dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM outcomes WHERE pilot_id=? ORDER BY project_id", (pilot_id,)
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]
