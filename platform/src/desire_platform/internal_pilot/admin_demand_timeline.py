"""Read-only, workspace-scoped oversight of durable Demand workflow facts.

The HTTP principal is resolved by the existing session/workspace bridge. Fixed
PostgreSQL programs independently revalidate it under FORCE RLS. The projection
merges existing audits with durable assignment/version facts; it never infers
unimplemented project, delivery, payment or settlement work as completed.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Mapping
from uuid import UUID, uuid5, NAMESPACE_URL

from psycopg.pq import TransactionStatus

from .editor.contracts import EditorPrincipal, EditorServiceError

_STAGES = (
    ("INTAKE", "需求录入"), ("REVIEW", "需求审核"), ("FUNDING", "资金核验"),
    ("MATCHING", "匹配与邀请"), ("SELECTION", "选择合作方"),
    ("AGREEMENT", "项目与协议"), ("DELIVERY", "实施与验收"), ("SETTLEMENT", "结算"),
)
_CURSOR = re.compile(r"^[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}$")
_ACTION = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,95}$")
_DETAILS = ("before_status", "after_status", "reason_code", "before_version", "after_version", "target_kind", "target_id", "result_code", "original_actor_user_id")
_ROLES = frozenset(("DEMAND_OWNER", "OPERATIONS_REVIEWER", "FINANCE_OPERATOR", "CREATOR", "CANDIDATE_SELECTOR", "TRUST_OFFICER", "APPEAL_REVIEWER", "ACCESS_ADMIN", "ORG_ADMIN", "SYSTEM", "UNKNOWN"))
_ACTION_LABELS = {
    "CreateDemand": "创建需求草稿", "CreateDemandVersion": "保存需求新版本",
    "SubmitDemand": "提交需求审核", "RequestDemandChanges": "要求修改需求",
    "VerifyDemand": "审核通过需求", "ReleaseDemandReviewAssignment": "释放需求审核任务",
    "ApplyFundingSecured": "记录资金核验完成", "RequestMatching": "请求匹配",
    "RequestMatchingSystem": "系统发起匹配", "CancelDemandByOwner": "需求方取消需求",
    "CancelDemandByReview": "审核方取消需求", "ExpireDemand": "需求到期关闭",
    "START_MANUAL_FUNDING_REVIEW": "启动资金核验", "JOIN_MANUAL_FUNDING_REVIEW": "加入资金核验",
    "CONFIRM_MANUAL_FUNDING_EVIDENCE": "确认资金核验凭据",
    "CLAIM_DEMAND_REVIEW": "领取需求审核任务", "CREATE_INVITATION": "创建合作邀请",
    "PUBLISH_INVITATION": "发送合作邀请", "RESPOND_INVITATION": "回复合作邀请",
    "CHOOSE_CREATOR": "选择合作方", "COMPLETE_SELECTION_SYSTEM": "系统完成合作方选择",
    "CLAIM_MATCHING_REVIEW": "领取匹配审核任务", "CLAIM_CANDIDATE_SELECTOR": "领取合作方选择任务",
    "INGEST_MATCHING_REQUESTED": "系统接收匹配请求", "RUN_MATCH": "执行匹配计算",
    "CAPTURE_INPUTS": "采集匹配输入", "PUBLISH_MATCH_RUN": "发布匹配结果",
    "START_MATCH_RUN": "开始匹配计算", "COMPLETE_MATCH_RUN": "完成匹配计算",
    "FAIL_MATCH_RUN": "记录匹配计算失败", "RELEASE_MATCHING_REVIEW": "释放匹配审核任务",
    "OPT_IN_CANDIDATE_SELECTOR": "领取合作方选择任务", "ACCEPT_INVITATION": "接受合作邀请",
    "DECLINE_INVITATION": "拒绝合作邀请", "WITHDRAW_ACCEPTED_INVITATION": "撤回已接受的合作邀请",
    "COMPLETE_SELECTION": "系统确认合作方选择", "CLOSE_SELECTION_WITHOUT_CHOICE": "结束选择（未选定合作方）",
    "CLOSE_MATCHING_WITHOUT_SELECTION": "系统结束本轮匹配（未选定合作方）",
    "PUBLISH_MANUAL_FUNDING_FINDINGS": "提交资金核验问题", "RELEASE_MANUAL_FUNDING_REVIEW": "释放资金核验任务",
    "SUBMIT_SAFETY_REPORT": "提交安全报告", "CLAIM_SAFETY_CASE": "领取安全案件",
    "PUBLISH_TRUST_TRIAGE": "发布安全评估", "PLACE_SAFETY_HOLD": "设置安全保护措施",
    "RELEASE_SAFETY_HOLD": "解除安全保护措施", "PUBLISH_TRUST_OUTCOME": "发布安全案件结论",
    "OPEN_APPEAL": "创建申诉", "SUBMIT_APPEAL": "提交申诉", "CLAIM_APPEAL": "领取申诉审核",
    "DECIDE_APPEAL": "发布申诉处理结论",

}
_STATUS_LABELS = {"DRAFT":"草稿", "SUBMITTED":"待审核", "NEEDS_CHANGES":"待修改", "VERIFIED":"审核通过", "FUNDING_PENDING":"核验中", "FUNDED":"核验完成", "MATCHING":"匹配中", "MATCHED":"已选定合作方", "NO_MATCH":"未匹配", "CANCELLED":"已取消", "EXPIRED":"已过期", "ACCEPTED":"已接受", "DECLINED":"已拒绝", "SELECTED":"已选定", "SENT":"已发送", "SUCCEEDED":"成功", "OPEN":"进行中", "ACTIVE":"已领取", "CREATED":"已创建", "QUEUED":"排队中", "RUNNING":"运行中", "COMPLETED":"已完成", "REVOKED":"已释放", "WITHDRAWN":"已撤回", "PENDING_CHOICE":"等待系统确认", "FAILED":"失败", "CLOSED_NO_SELECTION":"未选定合作方", "INVALIDATED":"已失效", "SECURED":"凭据核验完成", "DISCREPANCY":"核验存在差异", "REJECTED":"核验未通过"}


def _error(status: int, code: str) -> None:
    raise EditorServiceError(status=status, code=code)


def _uuid(value: Any) -> str:
    try:
        parsed = UUID(value)
        if str(parsed) != value or parsed.int == 0:
            raise ValueError
        return value
    except (ValueError, TypeError, AttributeError):
        _error(404, "RESOURCE_NOT_FOUND")


def _utc(value: Any) -> str:
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return result.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _principal(principal: EditorPrincipal) -> None:
    if not isinstance(principal, EditorPrincipal):
        _error(404, "RESOURCE_NOT_FOUND")
    platform = principal.workspace_kind == "PLATFORM" and "ACCESS_ADMIN" in principal.role_codes
    organization = principal.workspace_kind == "ORGANIZATION" and "ORG_ADMIN" in principal.role_codes
    if not (platform or organization) or not principal.workspace_id or len(principal.principal_marker_sha256) != 32:
        _error(404, "RESOURCE_NOT_FOUND")
    _uuid(principal.user_id)
    _uuid(principal.session_id)


class AdminDemandCursorCodec:
    """HMAC cursors bound to user, session, workspace, route and snapshot.

    The key remains owned by ManagedRuntimeSecrets; a separate HMAC domain
    prevents these tokens being accepted as IAM or editor cursors.
    """
    def __init__(self, key: bytes | bytearray) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32 or not any(key):
            raise ValueError("admin cursor signing key unavailable")
        self._key = key

    def _sign(self, value: bytes) -> bytes:
        if not any(self._key):
            _error(503, "SERVICE_UNAVAILABLE")
        return hmac.new(self._key, b"desire:admin-demand-cursor:v1\0" + value, hashlib.sha256).digest()

    def encode(self, principal: EditorPrincipal, route: str, position: Any, snapshot: str | None = None) -> str:
        body = json.dumps({"v":1,"u":principal.user_id,"s":principal.session_id,"w":principal.workspace_id,"r":route,"p":position,"h":snapshot},sort_keys=True,separators=(",",":")).encode()
        payload = base64.urlsafe_b64encode(body).rstrip(b"=")
        signature = base64.urlsafe_b64encode(self._sign(payload)).rstrip(b"=")
        return (payload+b"."+signature).decode()

    def decode(self, cursor: str | None, principal: EditorPrincipal, route: str) -> dict | None:
        if cursor is None:
            return None
        try:
            if not isinstance(cursor, str) or _CURSOR.fullmatch(cursor) is None:
                raise ValueError
            payload, signature = cursor.encode().split(b".")
            if not hmac.compare_digest(self._sign(payload),base64.urlsafe_b64decode(signature+b"=")):
                raise ValueError
            value = json.loads(base64.urlsafe_b64decode(payload+b"="*(-len(payload)%4)))
            if set(value) != {"v","u","s","w","r","p","h"} or value["v"] != 1 or (value["u"],value["s"],value["w"],value["r"]) != (principal.user_id,principal.session_id,principal.workspace_id,route):
                raise ValueError
            return value
        except (ValueError, TypeError, KeyError, UnicodeError):
            _error(400,"INVALID_CURSOR")


class PsycopgAdminDemandTimelineService:
    def __init__(self, *, connections: Any, cursor_codec: AdminDemandCursorCodec) -> None:
        self._connections = connections
        self._cursor_codec = cursor_codec

    @contextmanager
    def _read(self, principal: EditorPrincipal, operation: str):
        _principal(principal)
        connection = self._connections.checkout()
        released = False
        try:
            if connection.info.transaction_status != TransactionStatus.IDLE:
                raise ValueError("dirty connection")
            identity = connection.execute("SELECT current_user,session_user,current_setting('server_version_num')::integer").fetchone()
            if identity is None or identity[:2] != ("iam_app","iam_app") or identity[2] // 10000 != 18:
                raise ValueError("role-bound IAM connection required")
            connection.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute("SET LOCAL statement_timeout = '5000ms'")
            connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10000ms'")
            for key,value in (("app.scope_kind","EDITOR_PRINCIPAL"),("app.actor_user_id",principal.user_id),("app.session_id",principal.session_id),("app.admin_workspace_id",principal.workspace_id),("app.authority_marker_sha256",principal.principal_marker_sha256.hex()),("app.operation",operation)):
                connection.execute("SELECT set_config(%s,%s,true)",(key,value))
            authorized = connection.execute("SELECT iam_api.admin_demand_scope_v1(NULL)").fetchone()
            if authorized != (True,):
                _error(404,"RESOURCE_NOT_FOUND")
            yield connection
            connection.execute("COMMIT")
            self._connections.release(connection)
            released = True
        except EditorServiceError:
            raise
        except Exception as error:
            raise EditorServiceError(status=503,code="SERVICE_UNAVAILABLE") from error
        finally:
            if not released:
                try:
                    connection.execute("ROLLBACK")
                finally:
                    self._connections.discard(connection)

    def list_demands(self, *, principal: EditorPrincipal, limit: int = 25, cursor: str | None = None) -> dict:
        _principal(principal)
        _limit(limit)
        claims = self._cursor_codec.decode(cursor,principal,"list")
        at, demand_id = None, None
        if claims:
            try:
                at, demand_id = claims["p"]
                at, demand_id = _utc(at),_uuid(demand_id)
            except (TypeError,ValueError):
                _error(400,"INVALID_CURSOR")
        with self._read(principal,"ADMIN_DEMAND_LIST") as connection:
            data = _json_result(connection,"SELECT demand_api.list_admin_demands_v1(NULL,%s,%s,%s)",(limit+1,at,demand_id))
            generated_at = _utc(connection.execute("SELECT transaction_timestamp()").fetchone()[0])
            summaries=[]
            for item in data[:limit]:
                facts={}
                for source,schema in (("DEMAND","demand"),("MATCHING","matching"),("TRUST","trust")):
                    facts[source]=_json_result(connection,f"SELECT {schema}_api.admin_demand_facts_v1(%s,%s)",(item["organization_id"],item["demand_id"]))
                summaries.append(project_timeline(item,facts,{"events":[]},generated_at)["demand"])
        has_more = len(data)>limit
        rows = data[:limit]
        next_cursor = self._cursor_codec.encode(principal,"list",[rows[-1]["created_at"],rows[-1]["demand_id"]]) if has_more else None
        return {"items":summaries,"next_cursor":next_cursor,"has_more":has_more}

    def get_timeline(self, *, principal: EditorPrincipal, demand_id: str, limit: int = 100, cursor: str | None = None) -> dict:
        _principal(principal)
        demand_id = _uuid(demand_id)
        _limit(limit)
        claims = self._cursor_codec.decode(cursor,principal,demand_id)
        with self._read(principal,"ADMIN_DEMAND_TIMELINE") as connection:
            rows = _json_result(connection,"SELECT demand_api.list_admin_demands_v1(%s,1,NULL,NULL)",(demand_id,))
            if not rows:
                _error(404,"RESOURCE_NOT_FOUND")
            demand = rows[0]
            params=(demand["organization_id"],demand_id)
            facts = {}
            for source,schema in (("DEMAND","demand"),("MATCHING","matching"),("TRUST","trust")):
                facts[source] = _json_result(connection,f"SELECT {schema}_api.admin_demand_facts_v1(%s,%s)",params)
            target_ids={demand_id}
            for source in facts.values():
                for table,items in source.items():
                    if table != "names":
                        for item in items:
                            target_ids.add(item["id"])
                            if item.get("report_id"):
                                target_ids.add(item["report_id"])
            audit = _json_result(connection,"SELECT iam_api.read_admin_demand_audit_v1(%s,%s)",(params[0],[UUID(value) for value in sorted(target_ids)]))
            generated_at = _utc(connection.execute("SELECT transaction_timestamp()").fetchone()[0])
        result = project_timeline(demand,facts,audit,generated_at)
        # Immutable audit IDs plus all mutable facts: changes in Matching or
        # Trust invalidate a page even when Demand.aggregate_version is equal.
        snapshot = hashlib.sha256(json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        start = 0
        if claims:
            if claims["h"] != snapshot:
                _error(409,"TIMELINE_CHANGED")
            if type(claims["p"]) is not int or claims["p"] < 0 or claims["p"] >= len(result["events"]):
                _error(400,"INVALID_CURSOR")
            start = claims["p"]
        all_events = result["events"]
        result["events"] = all_events[start:start+limit]
        result["has_more"] = start+limit < len(all_events)
        result["next_cursor"] = self._cursor_codec.encode(principal,demand_id,start+limit,snapshot) if result["has_more"] else None
        result["generated_at"] = generated_at
        return result


def _limit(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 100:
        _error(400,"INVALID_REQUEST")


def _json_result(connection: Any, sql: str, params: tuple) -> Any:
    row = connection.execute(sql,params).fetchone()
    if row is None or row[0] is None:
        _error(503,"SERVICE_UNAVAILABLE")
    return row[0]


def _summary(row: Mapping[str,Any]) -> dict:
    status = row["status"]
    stage,blocker = {
        "DRAFT":("INTAKE","WAITING_FOR_SUBMISSION"), "SUBMITTED":("REVIEW","WAITING_FOR_REVIEWER"),
        "NEEDS_CHANGES":("REVIEW","REVIEW_CHANGES_REQUIRED"), "VERIFIED":("FUNDING","WAITING_FOR_FINANCE_REVIEW"),
        "FUNDING_PENDING":("FUNDING","WAITING_FOR_SECOND_FINANCE_CONFIRMATION"), "FUNDED":("MATCHING","WAITING_FOR_SYSTEM_MATCHING_REQUEST"),
        "MATCHING":("MATCHING","WAITING_FOR_MATCHING_WORKER"), "NO_MATCH":("MATCHING","NO_SELECTION_AVAILABLE"),
        "MATCHED":("AGREEMENT","AGREEMENT_NOT_IMPLEMENTED"), "CANCELLED":("INTAKE","DEMAND_CANCELLED"),
        "EXPIRED":("INTAKE","DEMAND_EXPIRED"),
    }[status]
    return {"demand_id":row["demand_id"],"organization_id":row["organization_id"],"title":row["title"],"status":status,"aggregate_version":row["aggregate_version"],"created_at":_utc(row["created_at"]),"updated_at":_utc(row["updated_at"]),"expires_at":_utc(row["expires_at"]),"current_stage":stage,"blocker_codes":[blocker]}


def _event_stage(action: str, target_kind: str) -> tuple[str,str]:
    normalized = action.replace("_","").upper()
    if any(word in normalized+target_kind.upper() for word in ("TRUST","SAFETY","APPEAL","TRIAGE")):
        return "REVIEW","TRUST"
    if "FUND" in normalized:
        return "FUNDING","FINANCE"
    if any(word in normalized+target_kind.upper() for word in ("SELECT","CHOOSE")):
        return "SELECTION","MATCHING"
    if any(word in normalized+target_kind.upper() for word in ("MATCH","INVITATION","INVITE","INPUT")):
        return "MATCHING","MATCHING"
    if any(word in normalized for word in ("REVIEW","VERIFY","CHANGES","SUBMIT")):
        return "REVIEW","DEMAND"
    return "INTAKE","DEMAND"


# Durable facts fill historical coverage even when the original producer did
# not write an audit (e.g. older review claims). Facts are explicitly labelled.
_FACT_EVENTS = {
    "demand_versions":("INTAKE","DEMAND","created_by_user_id","DEMAND_OWNER","created_at","DemandVersionRecorded","保存需求版本"),
    "demand_submissions":("REVIEW","DEMAND","submitted_by_user_id","DEMAND_OWNER","submitted_at","DemandSubmissionRecorded","提交需求审核"),
    "demand_review_assignments":("REVIEW","DEMAND","reviewer_user_id","OPERATIONS_REVIEWER","created_at","ReviewAssignmentRecorded","领取需求审核任务"),
    "demand_reviews":("REVIEW","DEMAND","reviewer_user_id","OPERATIONS_REVIEWER","reviewed_at","DemandReviewRecorded","提交需求审核结论"),
    "manual_funding_review_assignments":("FUNDING","FINANCE","actor_user_id","FINANCE_OPERATOR","created_at","FinanceAssignmentRecorded","加入资金核验"),
    "manual_funding_confirmations":("FUNDING","FINANCE","actor_user_id","FINANCE_OPERATOR","confirmed_at","FinanceConfirmationRecorded","确认资金核验凭据"),
    "manual_funding_findings":("FUNDING","FINANCE","actor_user_id","FINANCE_OPERATOR","created_at","FinanceFindingRecorded","提交资金核验问题"),
    "candidate_selector_assignments":("SELECTION","MATCHING","assignee_user_id","CANDIDATE_SELECTOR","assigned_at","SelectorAssignmentRecorded","领取合作方选择任务"),
    "matching_review_assignments":("MATCHING","MATCHING","reviewer_user_id","OPERATIONS_REVIEWER","created_at","MatchingAssignmentRecorded","领取匹配审核任务"),
    "case_assignments":("REVIEW","TRUST","officer_user_id","TRUST_OFFICER","assigned_at","SafetyAssignmentRecorded","领取安全审核任务"),
}


def _historical_actor_role(row: dict, matching_facts: dict) -> str:
    if row["actor_kind"] == "SYSTEM":
        return "SYSTEM"
    if row.get("role_code") in _ROLES:
        return row["role_code"]
    actor, target = row.get("actor_user_id"), row["target_id"]
    if any(item["id"] == target and item["reviewer_user_id"] == actor for item in matching_facts.get("matching_review_assignments", [])):
        return "OPERATIONS_REVIEWER"
    for item in matching_facts.get("invitations", []):
        if item["id"] == target:
            if item["creator_user_id"] == actor:
                return "CREATOR"
            if item["created_by_user_id"] == actor and any(assignment["reviewer_user_id"] == actor for assignment in matching_facts.get("matching_review_assignments", [])):
                return "OPERATIONS_REVIEWER"
    if row["target_kind"] in {"Selection", "CandidateSelectorAssignment"} and any(item["assignee_user_id"] == actor for item in matching_facts.get("candidate_selector_assignments", [])):
        return "CANDIDATE_SELECTOR"
    return "UNKNOWN"


def project_timeline(demand: dict, facts: dict, audit: dict, generated_at: str) -> dict:
    events=[]
    people: dict[str,dict] = {}
    names=dict(audit.get("names",{}))
    for source in facts.values(): names.update(source.get("names",{}))
    def participant(user_id: str | None, role: str) -> None:
        if user_id:
            person=people.setdefault(user_id,{"user_id":user_id,"display_name":names.get(user_id),"roles":set()})
            person["roles"].add(role if role in _ROLES else "UNKNOWN")
    participant(demand.get("creator_user_id"),"DEMAND_OWNER")
    for row in audit["events"]:
        if not _ACTION.fullmatch(row["action"]):
            raise ValueError("unexpected audit action")
        stage,source=_event_stage(row["action"],row["target_kind"])
        role=_historical_actor_role(row,facts["MATCHING"])
        if role not in _ROLES: role="UNKNOWN"
        participant(row.get("actor_user_id"),role)
        participant(row.get("original_actor_user_id"),"DEMAND_OWNER" if row.get("original_actor_user_id")==demand.get("creator_user_id") else "UNKNOWN")
        summary=_ACTION_LABELS.get(row["action"],row["action"])
        if row.get("after_status"):
            summary += " · " + _STATUS_LABELS.get(row["after_status"],row["after_status"])
        events.append({"event_id":row["event_id"],"stage":stage,"source":source,"action":row["action"],"actor_user_id":row["actor_user_id"],"actor_role":role,"occurred_at":_utc(row["occurred_at"]),"summary":summary,"details":{key:row.get(key) for key in _DETAILS}})
    # Equal actor/stage/timestamp is one committed action. Prefer the richer
    # immutable audit; keep a fact where the source never emitted an audit.
    audit_coordinates={(e["stage"],e["actor_user_id"],e["occurred_at"]) for e in events}
    stage_people={stage:set() for stage,_ in _STAGES}
    for source in facts.values():
        for table,items in source.items():
            if table == "names": continue
            spec=_FACT_EVENTS.get(table)
            for item in items:
                if spec:
                    stage,origin,actor_key,role,time_key,action,label=spec
                    actor=item[actor_key]
                    participant(actor,role)
                    stage_people[stage].add(actor)
                    occurred_at=_utc(item[time_key])
                    finding_suffix=""
                    finding_reason=None
                    if table in {"demand_reviews","manual_funding_findings"}:
                        reasons=item.get("reason_codes",[])
                        fields=item.get("required_field_codes",[])
                        reason_labels={"SCOPE_UNCLEAR":"范围不清晰","ACCEPTANCE_UNCLEAR":"验收标准不清晰","CONTENT_INCOMPLETE":"内容不完整","BUDGET_UNHEALTHY":"预算需调整","RISK_UNRESOLVED":"风险未解决","DATA_PLAN_REQUIRED":"缺少数据计划"}
                        field_labels={"scope":"范围与交付","acceptance":"验收标准","budget":"预算","risk":"风险说明","problem":"问题背景","declarations":"承诺声明","data":"数据计划","collaboration":"协作方式","timeline":"时间安排","SCOPE":"范围与交付","ACCEPTANCE":"验收标准","BUDGET":"预算","RISK":"风险说明","DECLARATIONS":"承诺声明"}
                        if reasons: finding_suffix += "；原因："+"、".join(reason_labels.get(code,code) for code in reasons)
                        if fields: finding_suffix += "；需补充："+"、".join(field_labels.get(code,code)+("（"+code+"）" if code in field_labels else "") for code in fields)
                        finding_reason=",".join(reasons) or None
                        for existing in events:
                            if (existing["stage"],existing["actor_user_id"],existing["occurred_at"]) == (stage,actor,occurred_at):
                                existing["summary"] += finding_suffix
                                existing["details"]["reason_code"] = finding_reason
                    if (stage,actor,occurred_at) not in audit_coordinates:
                        status=item.get("decision") or item.get("disposition")
                        suffix=(" · "+_STATUS_LABELS.get(status,status) if status else "")+finding_suffix
                        if table=="demand_versions": suffix=f" · 第 {item['version_no']} 版"
                        events.append({"event_id":str(uuid5(NAMESPACE_URL,f"desire:admin-demand-fact:{table}:{item['id']}")),"stage":stage,"source":origin,"action":action,"actor_user_id":actor,"actor_role":role,"occurred_at":occurred_at,"summary":label+suffix,"details":{"target_id":item["id"],"target_kind":"WorkflowFact","after_status":status,"result_code":"RECORDED","reason_code":finding_reason}})
                if table=="invitations":
                    participant(item["creator_user_id"],"CREATOR")
                    stage_people["MATCHING"].add(item["creator_user_id"])
    for delivery in facts["DEMAND"].get("matching_requested_deliveries",[]):
        if delivery["status"] == "FAILED":
            events.append({"event_id":str(uuid5(NAMESPACE_URL,f"desire:admin-demand-delivery-failure:{delivery['id']}")),"stage":"MATCHING","source":"MATCHING","action":"MatchingDeliveryFailed","actor_user_id":None,"actor_role":"SYSTEM","occurred_at":_utc(delivery.get("terminal_at") or delivery["updated_at"]),"summary":"匹配请求派送失败，需要检查后台任务","details":{"target_kind":"MatchingDelivery","target_id":delivery["id"],"after_status":"FAILED","reason_code":delivery.get("last_failure_code"),"result_code":"FAILED"}})
    for event in events:
        if event["actor_user_id"]: stage_people[event["stage"]].add(event["actor_user_id"])
    summary=_summary(demand)
    df=facts["DEMAND"]; mf=facts["MATCHING"]; tf=facts["TRUST"]
    status=demand["status"]
    blocker=summary["blocker_codes"]
    if status=="FUNDING_PENDING":
        cases=sorted(df.get("manual_funding_review_cases",[]),key=lambda item:(_utc(item["created_at"]),item["id"]))
        if cases and cases[-1]["status"] in {"DISCREPANCY","REJECTED"}:
            blocker[:]=["FUNDING_"+cases[-1]["status"]]
        elif not cases or not any(item.get("funding_review_id")==cases[-1]["id"] for item in df.get("manual_funding_confirmations",[])):
            blocker[:]=["WAITING_FOR_FINANCE_REVIEW"]
    if status=="MATCHING":
        attempts=sorted(mf.get("matching_attempts",[]),key=lambda item:(_utc(item["created_at"]),item["id"]))
        current=next((attempt for attempt in reversed(attempts) if attempt["status"]=="OPEN"),attempts[-1] if attempts else None)
        active_runs=[r for r in mf.get("match_runs",[]) if current and r["id"]==current["current_match_run_id"]]
        invitations=[i for i in mf.get("invitations",[]) if current and i["attempt_id"]==current["id"]]
        jobs=[j for j in mf.get("match_jobs",[]) if current and j["match_run_id"]==current["current_match_run_id"]]
        requests=sorted(df.get("matching_requests",[]),key=lambda item:(_utc(item["requested_at"]),item["id"]))
        current_request=requests[-1] if requests else None
        delivery_failed=any(item["status"]=="FAILED" and current_request and item["matching_request_id"]==current_request["id"] for item in df.get("matching_requested_deliveries",[]))
        if delivery_failed or any(r["status"]=="FAILED" for r in active_runs) or any(j["status"]=="FAILED" for j in jobs):
            blocker[:]=["MATCHING_JOB_FAILED"]
        elif any(i["status"]=="ACCEPTED" for i in invitations):
            blocker[:]=["WAITING_FOR_SELECTOR"]
            summary["current_stage"]="SELECTION"
        elif any(i["status"] in {"CREATED","SENT"} for i in invitations):
            blocker[:]=["WAITING_FOR_INVITATION_RESPONSE"]
        elif active_runs and all(r.get("eligible_count")==0 for r in active_runs):
            blocker[:]=["NO_ELIGIBLE_CREATORS"]
    now=datetime.fromisoformat(generated_at.replace("Z","+00:00"))
    if any(h["status"]=="ACTIVE" and datetime.fromisoformat(h["effective_at"])<=now<datetime.fromisoformat(h["expires_at"]) for h in tf.get("safety_holds",[])):
        blocker.append("SAFETY_HOLD_ACTIVE")
    stages=[]
    current_index=[code for code,_ in _STAGES].index(summary["current_stage"])
    for index,(code,label) in enumerate(_STAGES):
        count=sum(e["stage"]==code for e in events)
        if index>=5: state="NOT_IMPLEMENTED"
        elif status in {"CANCELLED","EXPIRED"}: state="CANCELLED" if count else "PENDING"
        elif index<current_index: state="COMPLETED"
        elif index==current_index: state="BLOCKED" if status in {"NEEDS_CHANGES","NO_MATCH"} or "SAFETY_HOLD_ACTIVE" in blocker or "MATCHING_JOB_FAILED" in blocker or "FUNDING_DISCREPANCY" in blocker or "FUNDING_REJECTED" in blocker else "IN_PROGRESS"
        else: state="PENDING"
        stages.append({"code":code,"label":label,"status":state,"participant_ids":sorted(stage_people[code]),"event_count":count,"blocker_codes":([code+"_NOT_IMPLEMENTED"] if index>=5 else blocker if code==summary["current_stage"] else [])})
    events.sort(key=lambda e:(e["occurred_at"],e["event_id"]))
    participants=[]
    for user_id in sorted(people):
        person=people[user_id]
        if len(person["roles"]) > 1:
            person["roles"].discard("UNKNOWN")
        person["roles"]=sorted(person["roles"])
        participants.append(person)
    return {"demand":summary,"stages":stages,"participants":participants,"events":events,"coverage":[
        {"source":"DEMAND","status":"COMPLETE","description":"已保存的需求版本、提交、审核分配及操作审计；未成功保存的尝试没有持久记录。"},
        {"source":"FINANCE","status":"PARTIAL","description":"内部沙箱双人凭据核验，仅记录零真实资金的操作；不代表支付、托管或真实资金到账。"},
        {"source":"MATCHING","status":"COMPLETE","description":"匹配任务、邀请、审核与选择分配及审计；参与者包含已受邀的创作者。"},
        {"source":"TRUST","status":"PARTIAL","description":"安全案件、保护措施、申诉及人员分配元数据；不展示举报正文、证据或受限备注。"},
        {"source":"AGREEMENT","status":"NOT_IMPLEMENTED","description":"尚未实现项目创建与协议签署，匹配完成不表示已签约。"},
        {"source":"DELIVERY","status":"NOT_IMPLEMENTED","description":"尚未实现交付里程碑与验收流程。"},
        {"source":"SETTLEMENT","status":"NOT_IMPLEMENTED","description":"尚未实现支付与结算流程。"},
    ]}
