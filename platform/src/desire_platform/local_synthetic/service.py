"""Disposable, loopback-only multi-role workflow for synthetic G1 exercises.

This adapter deliberately keeps its own closed state machine.  It is useful for
browser and product-flow acceptance only; it is not a production persistence or
identity implementation and it never calls an external provider.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


FIXTURE_ID = "scn-g1-001-happy-v1"
STORAGE_PROFILE = "local_synthetic_sqlite"
SESSION_SECONDS = 8 * 60 * 60
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class LocalSyntheticError(RuntimeError):
    """A stable, safe error returned at the local HTTP boundary."""

    def __init__(self, code: str, status: int = 400) -> None:
        self.code = code
        self.status = status
        super().__init__(code)


PERSONAS: Tuple[Dict[str, Any], ...] = (
    {
        "persona_id": "creator-chen",
        "display_name": "创作者陈澄（合成）",
        "workspace_label": "创作者工作台",
        "summary": "处理同意、Profile、邀请、协议、交付、举报与数据权。",
        "user_id": "syn_user_creator_chen",
        "workspace_id": "syn_workspace_creator",
        "kind": "CREATOR",
        "authorities": ("CREATOR_SELF", "PROJECT_WORKER", "PARTICIPANT_RIGHTS"),
    },
    {
        "persona_id": "demand-owner",
        "display_name": "需求负责人（合成）",
        "workspace_label": "需求方工作台",
        "summary": "提交需求、选择已接受候选、接受协议并协调项目。",
        "user_id": "syn_user_demand_owner",
        "workspace_id": "syn_workspace_demand",
        "kind": "DEMAND",
        "authorities": (
            "DEMAND_OWNER",
            "PROBLEM_PROPOSER",
            "PROCUREMENT_SPONSOR",
            "DEMAND_DECIDER",
            "CANDIDATE_SELECTOR",
            "PROJECT_COORDINATOR",
            "DEMAND_SIGNATORY",
        ),
    },
    {
        "persona_id": "acceptance-beneficiary",
        "display_name": "验收人与受益者（合成）",
        "workspace_label": "验收与成果工作台",
        "summary": "分别完成合同验收与受益者成果确认。",
        "user_id": "syn_user_acceptance_beneficiary",
        "workspace_id": "syn_workspace_acceptance",
        "kind": "ACCEPTANCE",
        "authorities": ("CONTRACT_ACCEPTOR", "BENEFICIARY_OUTCOME_CONFIRM"),
    },
    {
        "persona_id": "case-operator",
        "display_name": "服务运营者（合成）",
        "workspace_label": "运营与安全工作台",
        "summary": "审核需求、运行有限匹配、处理初次安全决定与重置 fixture。",
        "user_id": "syn_user_case_operator",
        "workspace_id": "syn_workspace_operations",
        "kind": "OPERATIONS",
        "authorities": (
            "CASE_OPERATOR",
            "DEMAND_REVIEWER",
            "MATCH_COORDINATOR",
            "SAFETY_DECIDER",
            "LOCAL_FIXTURE_ADMIN",
        ),
    },
    {
        "persona_id": "payment-initiator",
        "display_name": "付款发起人（合成）",
        "workspace_label": "付款发起工作台",
        "summary": "发起合成资金与付款义务，但不能核实自己的操作。",
        "user_id": "syn_user_payment_initiator",
        "workspace_id": "syn_workspace_payment_request",
        "kind": "FINANCE_REQUEST",
        "authorities": ("PAYMENT_INITIATOR",),
    },
    {
        "persona_id": "finance-reconciler",
        "display_name": "财务核实人（合成）",
        "workspace_label": "独立对账工作台",
        "summary": "依据合成权威账簿核实资金与付款结果。",
        "user_id": "syn_user_finance_reconciler",
        "workspace_id": "syn_workspace_reconciliation",
        "kind": "FINANCE_RECONCILIATION",
        "authorities": ("FINANCE_RECONCILER",),
    },
    {
        "persona_id": "appeal-reviewer",
        "display_name": "独立申诉复核者（合成）",
        "workspace_label": "独立申诉工作台",
        "summary": "在未参与原决定的前提下复核申诉并给出补救。",
        "user_id": "syn_user_appeal_reviewer",
        "workspace_id": "syn_workspace_appeal",
        "kind": "APPEAL",
        "authorities": ("APPEAL_REVIEWER",),
    },
)
PERSONA_BY_ID = {item["persona_id"]: item for item in PERSONAS}


JOURNEY_STAGES: Tuple[Tuple[str, str], ...] = (
    ("J01", "进入、身份与逐目的同意"),
    ("J02", "创作者 Profile"),
    ("J03", "需求与九角色"),
    ("J04", "独立需求审核"),
    ("J05", "需求资金核实"),
    ("J06", "有限可解释匹配"),
    ("J07", "邀请与创作者决定"),
    ("J08", "同 run 选择"),
    ("J09", "同版协议接受"),
    ("J10", "里程碑、开工、交付与验收"),
    ("J11", "付款未知与独立对账"),
    ("J12", "成果、安全、申诉、数据权与退出"),
)
STAGE_INDEX = {item[0]: index for index, item in enumerate(JOURNEY_STAGES)}


def _choice(name: str, label: str, values: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "type": "choice",
        "required": True,
        "options": [{"value": value, "label": option_label} for value, option_label in values],
    }


OPERATION_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "accept_consent": {
        "label": "决定是否接受逐目的同意",
        "kind": "DECISION",
        "fields": [_choice("decision", "同意决定", (("ACCEPT", "明示接受"), ("DECLINE", "拒绝且不受惩罚")))],
    },
    "publish_profile": {"label": "发布最小合成 Profile", "kind": "CREATE", "fields": []},
    "submit_demand": {"label": "提交合成 Demand v1", "kind": "CREATE", "fields": []},
    "review_demand": {
        "label": "记录需求审核决定",
        "kind": "DECISION",
        "fields": [_choice("decision", "审核决定", tuple((value, value) for value in ("APPROVE", "REVISE", "REJECT", "ESCALATE")))],
    },
    "request_demand_funding": {"label": "发起需求资金核验", "kind": "PAYMENT", "fields": []},
    "reconcile_demand_funding": {
        "label": "核实需求资金事实",
        "kind": "PAYMENT",
        "fields": [_choice("result", "核实结果", tuple((value, value) for value in ("SECURED", "FAILED", "UNKNOWN", "REFUNDED")))],
    },
    "run_matching": {"label": "运行固定有限匹配", "kind": "CREATE", "fields": []},
    "respond_invitation": {
        "label": "回应项目邀请",
        "kind": "DECISION",
        "fields": [_choice("decision", "你的决定", (("ACCEPT", "接受邀请"), ("DECLINE", "拒绝且不受惩罚"), ("WITHDRAW", "撤回接受"), ("EXPIRE", "模拟到期")))],
    },
    "complete_selection": {"label": "选择已接受的同 run 候选", "kind": "DECISION", "fields": []},
    "accept_agreement": {"label": "明示接受 Agreement v1（合成）", "kind": "DECISION", "fields": []},
    "request_milestone_funding": {"label": "发起里程碑资金核验", "kind": "PAYMENT", "fields": []},
    "reconcile_milestone_funding": {
        "label": "核实里程碑资金事实",
        "kind": "PAYMENT",
        "fields": [_choice("result", "核实结果", tuple((value, value) for value in ("SECURED", "FAILED", "UNKNOWN", "REFUNDED")))],
    },
    "start_project": {"label": "在资金已核实后开工", "kind": "DECISION", "fields": []},
    "submit_delivery": {"label": "提交合成交付版本", "kind": "CREATE", "fields": []},
    "decide_delivery": {
        "label": "按冻结标准记录合同验收",
        "kind": "DECISION",
        "fields": [_choice("decision", "验收决定", (("ACCEPT", "按合同接受"), ("REJECT_WITH_REASON", "拒收并给出合成理由"), ("REQUEST_CONTRACTED_REVISION", "请求合同内修订")))],
    },
    "confirm_outcome": {"label": "独立确认受益者成果", "kind": "DECISION", "fields": []},
    "request_payment": {"label": "发起已批准付款义务", "kind": "PAYMENT", "fields": []},
    "advance_payment_provider": {
        "label": "模拟 provider 返回",
        "kind": "PAYMENT",
        "fields": [_choice("result", "合成 provider 信号", tuple((value, value) for value in ("PROCESSING", "UNKNOWN", "FAILED")))],
    },
    "reconcile_payment": {
        "label": "依据独立合成账簿对账",
        "kind": "PAYMENT",
        "fields": [_choice("result", "权威合成财务事实", tuple((value, value) for value in ("PAID", "FAILED", "REFUNDED", "REVERSED")))],
    },
    "record_outcome": {"label": "记录情境成果观察", "kind": "CREATE", "fields": []},
    "submit_report": {"label": "提交合成安全举报", "kind": "CREATE", "fields": []},
    "decide_safety": {
        "label": "记录初次临时保护决定",
        "kind": "DECISION",
        "fields": [_choice("decision", "初次决定", tuple((value, value) for value in ("UPHOLD_PROTECTION", "MODIFY_PROTECTION", "LIFT_PROTECTION", "REMEDY")))],
    },
    "decide_appeal": {
        "label": "由独立复核者处理申诉",
        "kind": "DECISION",
        "fields": [_choice("decision", "申诉结果", tuple((value, value) for value in ("UPHOLD", "MODIFY", "OVERTURN", "REMAND")))],
    },
    "request_data_right": {
        "label": "提出合成数据权请求",
        "kind": "DESTRUCTIVE",
        "fields": [_choice("kind", "请求类型", tuple((value, value) for value in ("ACCESS", "CORRECT", "RESTRICT", "OBJECT", "DELETE", "EXPORT", "WITHDRAW_CONSENT")))],
    },
    "exit_participation": {"label": "退出参与并保留未结权利", "kind": "DESTRUCTIVE", "fields": []},
}
OPERATION_IDS = tuple(OPERATION_DEFINITIONS)


PHASES: Dict[str, Dict[str, str]] = {
    "CONSENT": {"operation": "accept_consent", "persona": "creator-chen", "authority": "CREATOR_SELF", "stage": "J01"},
    "PROFILE": {"operation": "publish_profile", "persona": "creator-chen", "authority": "CREATOR_SELF", "stage": "J02"},
    "DEMAND": {"operation": "submit_demand", "persona": "demand-owner", "authority": "DEMAND_OWNER", "stage": "J03"},
    "REVIEW": {"operation": "review_demand", "persona": "case-operator", "authority": "DEMAND_REVIEWER", "stage": "J04"},
    "DEMAND_FUND_REQUEST": {"operation": "request_demand_funding", "persona": "payment-initiator", "authority": "PAYMENT_INITIATOR", "stage": "J05"},
    "DEMAND_FUND_RECONCILE": {"operation": "reconcile_demand_funding", "persona": "finance-reconciler", "authority": "FINANCE_RECONCILER", "stage": "J05"},
    "MATCH": {"operation": "run_matching", "persona": "case-operator", "authority": "MATCH_COORDINATOR", "stage": "J06"},
    "INVITATION": {"operation": "respond_invitation", "persona": "creator-chen", "authority": "CREATOR_SELF", "stage": "J07"},
    "SELECTION": {"operation": "complete_selection", "persona": "demand-owner", "authority": "CANDIDATE_SELECTOR", "stage": "J08"},
    "AGREEMENT_DEMAND": {"operation": "accept_agreement", "persona": "demand-owner", "authority": "DEMAND_SIGNATORY", "stage": "J09"},
    "AGREEMENT_CREATOR": {"operation": "accept_agreement", "persona": "creator-chen", "authority": "CREATOR_SELF", "stage": "J09"},
    "MILESTONE_REQUEST": {"operation": "request_milestone_funding", "persona": "payment-initiator", "authority": "PAYMENT_INITIATOR", "stage": "J10"},
    "MILESTONE_RECONCILE": {"operation": "reconcile_milestone_funding", "persona": "finance-reconciler", "authority": "FINANCE_RECONCILER", "stage": "J10"},
    "START": {"operation": "start_project", "persona": "creator-chen", "authority": "PROJECT_WORKER", "stage": "J10"},
    "DELIVERY_SUBMIT": {"operation": "submit_delivery", "persona": "creator-chen", "authority": "CREATOR_SELF", "stage": "J10"},
    "DELIVERY_DECIDE": {"operation": "decide_delivery", "persona": "acceptance-beneficiary", "authority": "CONTRACT_ACCEPTOR", "stage": "J10"},
    "OUTCOME_CONFIRM": {"operation": "confirm_outcome", "persona": "acceptance-beneficiary", "authority": "BENEFICIARY_OUTCOME_CONFIRM", "stage": "J10"},
    "PAYMENT_REQUEST": {"operation": "request_payment", "persona": "payment-initiator", "authority": "PAYMENT_INITIATOR", "stage": "J11"},
    "PAYMENT_PROVIDER": {"operation": "advance_payment_provider", "persona": "finance-reconciler", "authority": "FINANCE_RECONCILER", "stage": "J11"},
    "PAYMENT_RECONCILE": {"operation": "reconcile_payment", "persona": "finance-reconciler", "authority": "FINANCE_RECONCILER", "stage": "J11"},
    "OUTCOME_RECORD": {"operation": "record_outcome", "persona": "demand-owner", "authority": "DEMAND_OWNER", "stage": "J12"},
    "REPORT": {"operation": "submit_report", "persona": "creator-chen", "authority": "PARTICIPANT_RIGHTS", "stage": "J12"},
    "SAFETY": {"operation": "decide_safety", "persona": "case-operator", "authority": "SAFETY_DECIDER", "stage": "J12"},
    "APPEAL": {"operation": "decide_appeal", "persona": "appeal-reviewer", "authority": "APPEAL_REVIEWER", "stage": "J12"},
    "DATA_RIGHT": {"operation": "request_data_right", "persona": "creator-chen", "authority": "PARTICIPANT_RIGHTS", "stage": "J12"},
    "EXIT": {"operation": "exit_participation", "persona": "creator-chen", "authority": "PARTICIPANT_RIGHTS", "stage": "J12"},
}

NEXT_PHASE: Dict[str, str] = {
    "CONSENT": "PROFILE",
    "PROFILE": "DEMAND",
    "DEMAND": "REVIEW",
    "REVIEW": "DEMAND_FUND_REQUEST",
    "DEMAND_FUND_REQUEST": "DEMAND_FUND_RECONCILE",
    "DEMAND_FUND_RECONCILE": "MATCH",
    "MATCH": "INVITATION",
    "INVITATION": "SELECTION",
    "SELECTION": "AGREEMENT_DEMAND",
    "AGREEMENT_DEMAND": "AGREEMENT_CREATOR",
    "AGREEMENT_CREATOR": "MILESTONE_REQUEST",
    "MILESTONE_REQUEST": "MILESTONE_RECONCILE",
    "MILESTONE_RECONCILE": "START",
    "START": "DELIVERY_SUBMIT",
    "DELIVERY_SUBMIT": "DELIVERY_DECIDE",
    "DELIVERY_DECIDE": "OUTCOME_CONFIRM",
    "OUTCOME_CONFIRM": "PAYMENT_REQUEST",
    "PAYMENT_REQUEST": "PAYMENT_PROVIDER",
    "PAYMENT_PROVIDER": "PAYMENT_RECONCILE",
    "PAYMENT_RECONCILE": "OUTCOME_RECORD",
    "OUTCOME_RECORD": "REPORT",
    "REPORT": "SAFETY",
    "SAFETY": "APPEAL",
    "APPEAL": "DATA_RIGHT",
    "DATA_RIGHT": "EXIT",
    "EXIT": "COMPLETE",
}

FORBIDDEN_INPUT_FIELDS = {
    "actor",
    "actor_id",
    "authority",
    "role",
    "persona_id",
    "session_id",
    "user_id",
    "workspace_id",
    "tenant_id",
    "organization",
    "organization_id",
    "is_admin",
    "verified",
    "paid",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fresh_state() -> Dict[str, Any]:
    return {
        "fixture_id": FIXTURE_ID,
        "synthetic": True,
        "phase": "CONSENT",
        "stage": "J01",
        "consents": [],
        "delivery_round": 0,
        "agreement_acceptances": [],
        "demand_funding": "NOT_REQUESTED",
        "milestone_funding": "NOT_REQUESTED",
        "invitation_status": "NOT_SENT",
        "payment_provider": "NOT_REQUESTED",
        "payment_fact": "NOT_RECONCILED",
        "last_result": "READY",
        "exit_preserves": ["PAYMENT_CLAIMS", "APPEAL", "DATA_RIGHTS", "REQUIRED_RECORDS"],
    }


class LocalSyntheticService:
    """SQLite-backed, closed synthetic workflow service."""

    def __init__(self, database_path: str) -> None:
        path = Path(database_path).expanduser()
        if str(path) == ":memory:" or not path.is_absolute():
            raise LocalSyntheticError("DATABASE_PATH_MUST_BE_ABSOLUTE", 500)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.database_path = str(path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            isolation_level=None,
            check_same_thread=False,
            timeout=5.0,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._initialize()
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "LocalSyntheticService":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _initialize(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS local_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_scenario (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    revision INTEGER NOT NULL,
                    state_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_sessions (
                    token_digest TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL UNIQUE,
                    persona_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS local_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    intent_sha256 TEXT NOT NULL,
                    csrf_sha256 TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_events (
                    event_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_label TEXT NOT NULL,
                    authority TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                """
            )
            profile = self._meta("storage_profile")
            if profile is not None and profile != STORAGE_PROFILE:
                raise LocalSyntheticError("NON_SYNTHETIC_DATABASE_REJECTED", 503)
            self._put_meta_if_absent("storage_profile", STORAGE_PROFILE)
            self._put_meta_if_absent("fixture_id", FIXTURE_ID)
            self._put_meta_if_absent("instance_epoch", "1")
            self._put_meta_if_absent("secret_hex", secrets.token_hex(32))
            marker = self._meta("fixture_id")
            if marker != FIXTURE_ID:
                raise LocalSyntheticError("UNKNOWN_FIXTURE_DATABASE_REJECTED", 503)
            row = self._connection.execute(
                "SELECT singleton FROM local_scenario WHERE singleton = 1"
            ).fetchone()
            if row is None:
                self._connection.execute(
                    "INSERT INTO local_scenario(singleton, revision, state_json) VALUES(1, 0, ?)",
                    (_canonical(_fresh_state()),),
                )

    def _meta(self, key: str) -> Optional[str]:
        row = self._connection.execute(
            "SELECT value FROM local_meta WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else str(row["value"])

    def _put_meta_if_absent(self, key: str, value: str) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO local_meta(key, value) VALUES(?, ?)", (key, value)
        )

    def _secret(self) -> bytes:
        value = self._meta("secret_hex")
        if value is None:
            raise LocalSyntheticError("LOCAL_STORAGE_UNAVAILABLE", 503)
        return bytes.fromhex(value)

    def _hmac(self, value: str) -> str:
        return hmac.new(self._secret(), value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _epoch(self) -> int:
        value = self._meta("instance_epoch")
        if value is None:
            raise LocalSyntheticError("LOCAL_STORAGE_UNAVAILABLE", 503)
        return int(value)

    def _begin(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _commit(self) -> None:
        self._connection.execute("COMMIT")

    def _rollback(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

    def list_personas(self) -> Dict[str, Any]:
        return {
            "personas": [
                {
                    "persona_id": item["persona_id"],
                    "display_name": item["display_name"],
                    "workspace_label": item["workspace_label"],
                    "summary": item["summary"],
                }
                for item in PERSONAS
            ]
        }

    def create_session(self, persona_id: str) -> Dict[str, Any]:
        if not isinstance(persona_id, str) or persona_id not in PERSONA_BY_ID:
            raise LocalSyntheticError("INVALID_PERSONA_ID", 400)
        raw_cookie = secrets.token_urlsafe(32)
        token_digest = self._hmac("session|" + raw_cookie)
        session_id = "syn_session_" + uuid.uuid4().hex
        issued_at = _utc_now()
        expires_at = issued_at + timedelta(seconds=SESSION_SECONDS)
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO local_sessions(
                    token_digest, session_id, persona_id, epoch, issued_at, expires_at, revoked_at
                ) VALUES(?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    token_digest,
                    session_id,
                    persona_id,
                    self._epoch(),
                    _iso(issued_at),
                    _iso(expires_at),
                ),
            )
            row = self._require_session_locked(raw_cookie)
            csrf = self._csrf_for(row)
        return {
            "cookie": raw_cookie,
            "csrf": csrf,
            "session": {
                "session_id": session_id,
                "persona_id": persona_id,
                "expires_at": _iso(expires_at),
            },
        }

    def close_session(self, raw_cookie: str, csrf: str) -> None:
        with self._lock:
            row = self._require_session_locked(raw_cookie)
            self._require_csrf(row, csrf)
            self._connection.execute(
                "UPDATE local_sessions SET revoked_at = ? WHERE token_digest = ?",
                (_iso(_utc_now()), row["token_digest"]),
            )

    def _require_session_locked(self, raw_cookie: str) -> sqlite3.Row:
        if not isinstance(raw_cookie, str) or not raw_cookie:
            raise LocalSyntheticError("SESSION_REQUIRED", 401)
        digest = self._hmac("session|" + raw_cookie)
        row = self._connection.execute(
            "SELECT * FROM local_sessions WHERE token_digest = ?", (digest,)
        ).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise LocalSyntheticError("SESSION_INVALID", 401)
        if int(row["epoch"]) != self._epoch():
            raise LocalSyntheticError("INSTANCE_RESET_RELOAD_REQUIRED", 409)
        expires_at = datetime.fromisoformat(str(row["expires_at"]))
        if expires_at <= _utc_now():
            raise LocalSyntheticError("SESSION_EXPIRED", 401)
        return row

    def _csrf_for(self, session_row: sqlite3.Row) -> str:
        return self._hmac(
            "csrf|{}|{}|{}".format(
                session_row["session_id"], session_row["token_digest"], session_row["epoch"]
            )
        )

    def _require_csrf(self, session_row: sqlite3.Row, csrf: str) -> None:
        if not isinstance(csrf, str) or not hmac.compare_digest(self._csrf_for(session_row), csrf):
            raise LocalSyntheticError("CSRF_INVALID", 403)

    def bootstrap(self, raw_cookie: str) -> Dict[str, Any]:
        with self._lock:
            session = self._require_session_locked(raw_cookie)
            return self._bootstrap_locked(session)

    def _scenario_locked(self) -> Tuple[int, Dict[str, Any]]:
        row = self._connection.execute(
            "SELECT revision, state_json FROM local_scenario WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise LocalSyntheticError("LOCAL_STORAGE_UNAVAILABLE", 503)
        return int(row["revision"]), json.loads(str(row["state_json"]))

    def _bootstrap_locked(self, session: sqlite3.Row) -> Dict[str, Any]:
        revision, state = self._scenario_locked()
        persona = PERSONA_BY_ID[str(session["persona_id"])]
        phase = str(state["phase"])
        spec = PHASES.get(phase)
        current_stage = str(state.get("stage", "J12" if phase == "COMPLETE" else "J01"))
        allowed: list = []
        pending_consent = phase == "CONSENT" and persona["persona_id"] == "creator-chen"
        if pending_consent:
            definition = OPERATION_DEFINITIONS["accept_consent"]
            allowed = [
                {
                    "operation": "accept_consent",
                    "label": definition["label"],
                    "kind": definition["kind"],
                    "fields": definition["fields"],
                }
            ]
        elif spec is not None and spec["persona"] == persona["persona_id"]:
            operation = spec["operation"]
            definition = OPERATION_DEFINITIONS[operation]
            allowed = [
                {
                    "operation": operation,
                    "label": definition["label"],
                    "kind": definition["kind"],
                    "fields": definition["fields"],
                }
            ]
        display_spec = (
            {"operation": "accept_consent", "authority": persona["authorities"][0], "persona": persona["persona_id"]}
            if pending_consent else spec
        )
        status = "DONE" if phase == "COMPLETE" else (
            "BLOCKED" if phase.startswith("BLOCKED_") else (
                "NEEDS_ACTION" if allowed else "WAITING"
            )
        )
        next_persona = "none" if display_spec is None else PERSONA_BY_ID[display_spec["persona"]]["display_name"]
        task = {
            "task_id": "syn_task_{}".format(revision),
            "title": "旅程已完成" if phase == "COMPLETE" else (
                "当前闸门已受阻" if phase.startswith("BLOCKED_") else OPERATION_DEFINITIONS[spec["operation"]]["label"]
            ),
            "summary": (
                "全部合成步骤已结束；这不构成真实服务事实。"
                if phase == "COMPLETE"
                else "下一责任身份：{}。页面不会允许其他身份代办。".format(next_persona)
            ),
            "status": status,
            "due_at": None,
            "object_id": "syn_case_001",
            "object_type": "SYNTHETIC_CASE",
            "authority": "READ_ONLY" if display_spec is None else display_spec["authority"],
            "allowed_operations": [item["operation"] for item in allowed],
        }
        current_index = STAGE_INDEX.get(current_stage, len(JOURNEY_STAGES) - 1)
        stages = []
        for index, (stage_id, label) in enumerate(JOURNEY_STAGES):
            stage_status = "COMPLETED" if index < current_index or phase == "COMPLETE" else (
                "CURRENT" if index == current_index else "UPCOMING"
            )
            stages.append({"stage": stage_id, "label": label, "status": stage_status})
        events = self._connection.execute(
            "SELECT * FROM local_events ORDER BY revision ASC, event_id ASC LIMIT 100"
        ).fetchall()
        timeline = [
            {
                "event_id": str(event["event_id"]),
                "label": OPERATION_DEFINITIONS.get(str(event["operation"]), {"label": "重置合成场景"})["label"],
                "occurred_at": str(event["occurred_at"]),
                "actor_label": str(event["actor_label"]),
                "authority": str(event["authority"]),
                "detail": str(event["detail"]),
            }
            for event in events
        ]
        object_status = str(state.get("last_result", "READY"))
        if phase == "COMPLETE":
            object_status = "COMPLETED"
        facts = [
            {"label": "场景", "value": "SCN-G1-001 · 完全合成"},
            {"label": "当前阶段", "value": current_stage},
            {"label": "当前闸门", "value": phase},
            {"label": "需求金额", "value": "合成 CNY 6,800"},
            {"label": "付款事实", "value": str(state.get("payment_fact", "NOT_RECONCILED"))},
            {"label": "实质变更", "value": "关闭 · 当前版本未实现 UC-P1-011"},
        ]
        return {
            "session": {
                "session_id": str(session["session_id"]),
                "persona_id": str(session["persona_id"]),
                "expires_at": str(session["expires_at"]),
            },
            "user": {"user_id": persona["user_id"], "display_name": persona["display_name"]},
            "workspaces": [
                {
                    "workspace_id": persona["workspace_id"],
                    "label": persona["workspace_label"],
                    "kind": persona["kind"],
                    "authorities": list(persona["authorities"]),
                }
            ],
            "current_workspace_id": persona["workspace_id"],
            "tasks": [task],
            "workflow": {"current_stage": current_stage, "stages": stages},
            "object": {
                "object_id": "syn_case_001",
                "type": "SYNTHETIC_CASE",
                "title": "无障碍社区活动信息包（合成）",
                "status": object_status,
                "version": revision,
                "facts": facts,
                "timeline": timeline,
            },
            "allowed_operations": allowed,
            "csrf": self._csrf_for(session),
            "revision": revision,
        }

    def execute(self, raw_cookie: str, csrf: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        body = self._validate_action_payload(payload)
        operation = str(body["operation"])
        intent_sha256 = _sha256(_canonical(body))
        with self._lock:
            self._begin()
            try:
                session = self._require_session_locked(raw_cookie)
                receipt_id = self._receipt_id(session, operation, str(body["idempotency_key"]))
                replay = self._load_receipt(receipt_id, intent_sha256, csrf)
                if replay is not None:
                    self._commit()
                    return replay
                self._require_csrf(session, csrf)
                revision, state = self._scenario_locked()
                if int(body["expected_revision"]) != revision:
                    raise LocalSyntheticError("REVISION_MISMATCH", 412)
                phase = str(state["phase"])
                spec = PHASES.get(phase)
                operation_personas = {
                    item["persona"]
                    for item in PHASES.values()
                    if item["operation"] == operation
                }
                if str(session["persona_id"]) not in operation_personas:
                    raise LocalSyntheticError("ACCESS_DENIED", 404)
                if spec is None or spec["operation"] != operation:
                    raise LocalSyntheticError("OPERATION_NOT_AVAILABLE", 409)
                if spec["persona"] != session["persona_id"]:
                    raise LocalSyntheticError("ACCESS_DENIED", 404)
                input_value = self._validate_operation_input(operation, body["input"])
                next_phase, detail = self._transition(
                    state, phase, operation, input_value, str(session["persona_id"])
                )
                state["phase"] = next_phase
                if next_phase in PHASES:
                    state["stage"] = PHASES[next_phase]["stage"]
                elif next_phase == "COMPLETE":
                    state["stage"] = "J12"
                new_revision = revision + 1
                self._connection.execute(
                    "UPDATE local_scenario SET revision = ?, state_json = ? WHERE singleton = 1",
                    (new_revision, _canonical(state)),
                )
                persona = PERSONA_BY_ID[str(session["persona_id"])]
                event_id = "syn_event_{}_{}".format(new_revision, uuid.uuid4().hex[:12])
                occurred_at = _iso(_utc_now())
                self._connection.execute(
                    """
                    INSERT INTO local_events(
                        event_id, revision, operation, actor_id, actor_label, authority, detail, occurred_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        new_revision,
                        operation,
                        persona["user_id"],
                        persona["display_name"],
                        spec["authority"],
                        detail,
                        occurred_at,
                    ),
                )
                response = {
                    "receipt": {
                        "receipt_id": receipt_id,
                        "operation": operation,
                        "status": "COMPLETED",
                        "revision": new_revision,
                        "replayed": False,
                    },
                    "revision": new_revision,
                }
                self._store_receipt(
                    receipt_id,
                    str(session["session_id"]),
                    operation,
                    intent_sha256,
                    csrf,
                    response,
                )
                self._commit()
                return response
            except Exception:
                self._rollback()
                raise

    def reset(self, raw_cookie: str, csrf: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        body = self._validate_reset_payload(payload)
        intent_sha256 = _sha256(_canonical(body))
        with self._lock:
            self._begin()
            try:
                session = self._require_session_locked(raw_cookie)
                persona = PERSONA_BY_ID[str(session["persona_id"])]
                if (
                    session["persona_id"] != "case-operator"
                    or "LOCAL_FIXTURE_ADMIN" not in persona["authorities"]
                ):
                    raise LocalSyntheticError("RESET_NOT_FOUND", 404)
                receipt_id = self._receipt_id(session, "__reset__", str(body["idempotency_key"]))
                replay = self._load_receipt(receipt_id, intent_sha256, csrf)
                if replay is not None:
                    self._commit()
                    return replay
                self._require_csrf(session, csrf)
                revision, _ = self._scenario_locked()
                if int(body["expected_revision"]) != revision:
                    raise LocalSyntheticError("REVISION_MISMATCH", 412)
                new_revision = revision + 1
                new_epoch = self._epoch() + 1
                self._connection.execute(
                    "UPDATE local_scenario SET revision = ?, state_json = ? WHERE singleton = 1",
                    (new_revision, _canonical(_fresh_state())),
                )
                self._connection.execute(
                    "UPDATE local_meta SET value = ? WHERE key = 'instance_epoch'",
                    (str(new_epoch),),
                )
                self._connection.execute(
                    "UPDATE local_sessions SET epoch = ? WHERE token_digest = ?",
                    (new_epoch, session["token_digest"]),
                )
                self._connection.execute("DELETE FROM local_events")
                occurred_at = _iso(_utc_now())
                self._connection.execute(
                    """
                    INSERT INTO local_events(
                        event_id, revision, operation, actor_id, actor_label, authority, detail, occurred_at
                    ) VALUES(?, ?, '__reset__', ?, ?, 'LOCAL_FIXTURE_ADMIN', ?, ?)
                    """,
                    (
                        "syn_event_reset_{}".format(new_revision),
                        new_revision,
                        PERSONA_BY_ID["case-operator"]["user_id"],
                        PERSONA_BY_ID["case-operator"]["display_name"],
                        "已原子恢复固定合成 fixture；没有删除或修改任何真实数据。",
                        occurred_at,
                    ),
                )
                response = {
                    "receipt": {
                        "receipt_id": receipt_id,
                        "operation": "reset",
                        "status": "COMPLETED",
                        "revision": new_revision,
                        "replayed": False,
                    },
                    "revision": new_revision,
                    "instance_epoch": new_epoch,
                }
                self._store_receipt(
                    receipt_id,
                    str(session["session_id"]),
                    "__reset__",
                    intent_sha256,
                    csrf,
                    response,
                )
                self._commit()
                return response
            except Exception:
                self._rollback()
                raise

    def _receipt_id(self, session: sqlite3.Row, operation: str, raw_key: str) -> str:
        return "syn_receipt_" + self._hmac(
            "receipt|{}|{}|{}".format(session["session_id"], operation, raw_key)
        )

    def _load_receipt(
        self, receipt_id: str, intent_sha256: str, csrf: str
    ) -> Optional[Dict[str, Any]]:
        row = self._connection.execute(
            "SELECT intent_sha256, csrf_sha256, response_json FROM local_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(str(row["intent_sha256"]), intent_sha256):
            raise LocalSyntheticError("IDEMPOTENCY_KEY_REUSED", 409)
        if not hmac.compare_digest(str(row["csrf_sha256"]), _sha256(csrf)):
            raise LocalSyntheticError("CSRF_INVALID", 403)
        return json.loads(str(row["response_json"]))

    def _store_receipt(
        self,
        receipt_id: str,
        session_id: str,
        operation: str,
        intent_sha256: str,
        csrf: str,
        response: Mapping[str, Any],
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO local_receipts(
                receipt_id, session_id, operation, intent_sha256, csrf_sha256, response_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id,
                session_id,
                operation,
                intent_sha256,
                _sha256(csrf),
                _canonical(response),
                _iso(_utc_now()),
            ),
        )

    def _validate_action_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise LocalSyntheticError("INVALID_ACTION_SCHEMA", 400)
        if set(payload) & FORBIDDEN_INPUT_FIELDS:
            raise LocalSyntheticError("FORBIDDEN_INPUT_FIELD", 400)
        if set(payload) != {
            "operation",
            "expected_revision",
            "idempotency_key",
            "input",
        }:
            raise LocalSyntheticError("INVALID_ACTION_SCHEMA", 400)
        operation = payload.get("operation")
        if not isinstance(operation, str) or operation not in OPERATION_DEFINITIONS:
            raise LocalSyntheticError("UNKNOWN_OPERATION", 400)
        revision = payload.get("expected_revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise LocalSyntheticError("INVALID_EXPECTED_REVISION", 400)
        key = payload.get("idempotency_key")
        if not isinstance(key, str) or UUID4_RE.fullmatch(key) is None:
            raise LocalSyntheticError("INVALID_IDEMPOTENCY_KEY", 400)
        input_value = payload.get("input")
        if not isinstance(input_value, Mapping):
            raise LocalSyntheticError("INVALID_ACTION_INPUT", 400)
        self._reject_forbidden_fields(input_value)
        return {
            "operation": operation,
            "expected_revision": revision,
            "idempotency_key": key,
            "input": dict(input_value),
        }

    def _validate_reset_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) != {
            "fixture_id",
            "expected_revision",
            "idempotency_key",
        }:
            raise LocalSyntheticError("INVALID_RESET_SCHEMA", 400)
        if payload.get("fixture_id") != FIXTURE_ID:
            raise LocalSyntheticError("UNKNOWN_FIXTURE", 400)
        revision = payload.get("expected_revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise LocalSyntheticError("INVALID_EXPECTED_REVISION", 400)
        key = payload.get("idempotency_key")
        if not isinstance(key, str) or UUID4_RE.fullmatch(key) is None:
            raise LocalSyntheticError("INVALID_IDEMPOTENCY_KEY", 400)
        return dict(payload)

    def _reject_forbidden_fields(self, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in FORBIDDEN_INPUT_FIELDS:
                    raise LocalSyntheticError("FORBIDDEN_INPUT_FIELD", 400)
                self._reject_forbidden_fields(child)
        elif isinstance(value, list):
            for child in value:
                self._reject_forbidden_fields(child)

    def _validate_operation_input(self, operation: str, input_value: Any) -> Dict[str, Any]:
        if not isinstance(input_value, Mapping):
            raise LocalSyntheticError("INVALID_ACTION_INPUT", 400)
        fields = OPERATION_DEFINITIONS[operation]["fields"]
        names = {field["name"] for field in fields}
        if set(input_value) != names:
            raise LocalSyntheticError("INVALID_OPERATION_INPUT", 400)
        for field in fields:
            value = input_value[field["name"]]
            choices = {item["value"] for item in field.get("options", [])}
            if not isinstance(value, str) or (choices and value not in choices):
                raise LocalSyntheticError("INVALID_OPERATION_INPUT", 400)
        return dict(input_value)

    def _transition(
        self,
        state: Dict[str, Any],
        phase: str,
        operation: str,
        input_value: Mapping[str, Any],
        persona_id: str,
    ) -> Tuple[str, str]:
        state["last_result"] = "COMPLETED"
        if operation == "accept_consent":
            if input_value["decision"] == "DECLINE":
                state["last_result"] = "DECLINED"
                return "BLOCKED_CONSENT", "拒绝了逐目的同意；未授予目的权限，也未生成惩罚信号。"
            state["consents"] = [persona_id]
            return "PROFILE", "创作者本人明示完成逐目的同意；没有从其他角色推导同意。"
        if operation == "review_demand" and input_value["decision"] != "APPROVE":
            decision = str(input_value["decision"])
            state["last_result"] = decision
            if decision == "REVISE":
                return "DEMAND", "审核要求修订；旧 DemandVersion 保持只读。"
            return "BLOCKED_REVIEW", "审核未批准；匹配与资金动作保持关闭。"
        if operation == "request_demand_funding":
            state["demand_funding"] = "REQUESTED"
        elif operation == "reconcile_demand_funding":
            result = str(input_value["result"])
            state["demand_funding"] = result
            state["last_result"] = result
            if result != "SECURED":
                return "DEMAND_FUND_RECONCILE", "资金事实为 {}；仍禁止匹配。".format(result)
        elif operation == "run_matching":
            state["invitation_status"] = "SENT"
        elif operation == "respond_invitation":
            decision = str(input_value["decision"])
            state["invitation_status"] = decision
            state["last_result"] = decision
            if decision != "ACCEPT":
                return "BLOCKED_INVITATION", "邀请结果为 {}；不可选择，未来资格保持且未生成负面排序特征。".format(decision)
        elif operation == "complete_selection":
            if state.get("invitation_status") != "ACCEPT":
                raise LocalSyntheticError("CANDIDATE_NOT_ACCEPTED", 409)
        elif operation == "accept_agreement":
            acceptances = list(state.get("agreement_acceptances", []))
            acceptances.append(PHASES[phase]["persona"])
            state["agreement_acceptances"] = acceptances
        elif operation == "request_milestone_funding":
            state["milestone_funding"] = "REQUESTED"
        elif operation == "reconcile_milestone_funding":
            result = str(input_value["result"])
            state["milestone_funding"] = result
            state["last_result"] = result
            if result != "SECURED":
                return "MILESTONE_RECONCILE", "里程碑资金为 {}；仍禁止开工。".format(result)
        elif operation == "start_project":
            if state.get("milestone_funding") != "SECURED":
                raise LocalSyntheticError("MILESTONE_NOT_SECURED", 409)
        elif operation == "submit_delivery":
            state["delivery_round"] = int(state.get("delivery_round", 0)) + 1
        elif operation == "decide_delivery":
            decision = str(input_value["decision"])
            state["last_result"] = decision
            if decision != "ACCEPT":
                return "DELIVERY_SUBMIT", "交付未获合同验收；保留理由并开放合同内重新提交。"
        elif operation == "request_payment":
            state["payment_provider"] = "REQUESTED"
        elif operation == "advance_payment_provider":
            result = str(input_value["result"])
            state["payment_provider"] = result
            state["last_result"] = result
        elif operation == "reconcile_payment":
            result = str(input_value["result"])
            state["payment_fact"] = result
            state["last_result"] = result
            if result != "PAID":
                return "PAYMENT_RECONCILE", "独立对账为 {}；不把它显示为 PAID。".format(result)
        elif operation == "decide_safety":
            state["last_result"] = str(input_value["decision"])
        elif operation == "decide_appeal":
            state["last_result"] = str(input_value["decision"])
        elif operation == "request_data_right":
            state["last_result"] = "{}_PREVIEWED".format(input_value["kind"])
        elif operation == "exit_participation":
            state["last_result"] = "EXITED_RIGHTS_PRESERVED"
        return NEXT_PHASE[phase], "{} 已以合成事实记录；无外部副作用。".format(operation)


__all__ = [
    "FIXTURE_ID",
    "LocalSyntheticError",
    "LocalSyntheticService",
    "OPERATION_IDS",
    "PERSONAS",
]
