#!/usr/bin/env python3
"""Exercise this real brief through the deployed INTERNAL_SANDBOX HTTP API.

Run with run.sh. Credentials stay in a temporary directory; result.json contains
only an explicit allowlist of public business facts. No SQL writes or real money.
The faithful hardware demand remains a draft when its taxonomy is unavailable.
A separately labelled software-analysis sub-demand exercises the implemented path.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_internal_sandbox_e2e as base
import run_internal_sandbox_matching_e2e as matching


ASSUMPTIONS = [
    "原始需求是实体升降喂食机；另建的软件分析子需求只演练交互/控制仿真，不能代表机械研发或制造完成。",
    "所有参与者为已有合成账号；预算、直接成本、报价均为 0 CNY，仅为沙盒资金确认，不代表真实预算或实际收付款。",
    "软件子需求暂按明日起 4 周、每周 20 小时、远程中文协作、中国地区和 5 天验收响应演练；均未获原需求方确认。",
    "狗的体型、合适进食高度、取盆高度、载荷、行程、速度、噪音、尺寸和真实完成进食检测方法均待确认；不从升降桌宣传图推导产品规格。",
    "演练只用合成传感事件和可配置高度参数；防夹、误触发、断电、清洁、食品接触材料和稳定性由后续机械/电气专家及需求方定义验收。",
    "原图仅作本地参考：目录中的电话、地址和手写信息不输入工作台，也不联系图片中的供应商。",
]


def compact_idea() -> str:
    return " ".join((Path(__file__).parent / "idea.md").read_text(encoding="utf-8").split())


def original_content() -> dict[str, Any]:
    # Partial groups are supported in a draft. Do not invent a software domain
    # merely to force the real hardware request through the submission validator.
    return {"scope": {"deliverables": [{"item_id": "pet_feed_original",
        "description": "原始硬件需求，分类待补齐：" + compact_idea()}],
        "out_of_scope": ["尚未确认预算、尺寸、适用犬体型和检测方案，不承诺实体交付。"]}}


def software_content(choices: dict[str, Any], *, original_id: str, refined: bool) -> dict[str, Any]:
    content = base.safe_demand_content(choices)
    content["problem"]["background"] = (
        f"INTERNAL_SANDBOX 宠物升降喂食机的软件分析子需求【合成演练】，来源需求 {original_id}。"
        + compact_idea() + " 本子需求仅针对软件交互和控制仿真；原始硬件需求仍待分类、工程和预算确认。"
    )
    content["problem"]["desired_outcomes"] = [
        "模拟人站立取放盆、按配置的犬体型档位下降，以及模拟进食结束后回升。",
        "输出可审阅的软件状态机、交互说明和异常场景表，供后续硬件可行性评审。",
    ]
    content["scope"] = {
        "deliverables": [{"item_id": "software_state_machine", "description": (
            "软件状态机与交互说明：取盆、下降、进食、结束确认、回升、急停/故障；交付状态转移表和 5 条带输入/预期输出的仿真用例，所有高度仅为可配置参数，不控制真实设备。"
            if refined else "喂食机交互与升降控制软件仿真方案，具体范围待审核补充。"
        )}],
        "out_of_scope": ["真实用户与真实交易", "机械结构、电路、电机选型、实体制造、真实动物试验、医疗或适宜喂食高度建议、真实资金和合同。", "原图附件未上传，保存在 tests/pet-feed/。"],
    }
    content["acceptance"]["criteria"] = [
        {"criterion_id": "manual_bowl", "description": "给定取盆状态和用户开始信号，模拟转入下降；取盆高度为参数，不宣称真实人机尺寸已确定。"},
        {"criterion_id": "dog_height", "description": "为 3 个合成体型档位配置不同目标高度，仿真分别到达对应参数值；实物高度由需求方和专家另行确认。"},
        {"criterion_id": "meal_finish", "description": "模拟进食中不回升；收到模拟结束事件并经确认后回升到取盆参数值。真实检测方案待确认。"},
        {"criterion_id": "obstruction", "description": "在下降或回升时注入障碍事件，软件仿真停止运动并显示人工处理提示。"},
        {"criterion_id": "power_loss", "description": "注入断电/传感故障事件后进入故障状态；恢复需显式人工确认。实物安全能力未验证。"},
    ]
    content["milestone_plan"]["items"] = [
        {"item_id": "requirements", "label": "假设清单与状态机评审", "percent": 30},
        {"item_id": "simulation", "label": "软件仿真用例与交互说明", "percent": 50},
        {"item_id": "review", "label": "需求方审阅与问题回收", "percent": 20},
    ]
    content["risk"]["uncertainty_code"] = "HIGH"
    content["risk"]["data_handling_plan"] = "仅合成事件；照片留本地不上传联系人。预算、期限、体型、高度、进食结束检测和安全指标都是待确认项。本次不产生实体设备。"
    return content


PUBLIC_FIELDS = {"object_id", "resource_type", "status", "revision", "aggregate_version",
    "assignment_id", "funding_review_id", "confirmation_count", "attempt_id", "selection_id",
    "invitation_id", "response_status", "candidate_selector_assignment_id", "code", "path"}


class Recorder:
    def __init__(self, output: Path):
        self.output = output
        self.stage = "LOGIN"
        self.events: list[dict[str, Any]] = []

    def attach(self, session: base.RoleSession) -> None:
        request = session.client.request

        def recorded(**kwargs: Any) -> base.HttpResult:
            response = request(**kwargs)
            if kwargs["method"] != "GET":
                payload = response.json()
                data = payload.get("data", payload.get("error", payload))
                if not isinstance(data, dict):
                    data = {}
                event = {"sequence": len(self.events) + 1,
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "stage": self.stage, "actor": session.account_code,
                    "roles": list(session.role_codes), "method": kwargs["method"],
                    "path": kwargs["path"], "http_status": response.status,
                    "result": {k: v for k, v in data.items() if k in PUBLIC_FIELDS}}
                self.events.append(event)
                self.output.write_text(json.dumps(self.events, ensure_ascii=False, indent=2) + "\n")
            return response

        session.client.request = recorded


class PetFeedJourney(matching.Journey):
    def __init__(self, *args: Any, recorder: Recorder, **kwargs: Any):
        self.recorder = recorder
        self.existing_software_id: str | None = None
        super().__init__(*args, **kwargs)

    def stage(self, name: str) -> None:
        self.recorder.stage = name
        super().stage(name)

    def edit(self, session: base.RoleSession, method: str, path: str,
             body: dict[str, Any], current: dict[str, Any] | None = None,
             expected_status: int = 200) -> dict[str, Any]:
        return base._write_editor(session, method=method, path=path, body=body,
            expected_status=expected_status, resource_type="DEMAND",
            if_match=current["etag"] if current else None)

    def create(self, content: dict[str, Any], label: str) -> dict[str, Any]:
        return self.edit(self.owner, "POST", "/v1/app/demands", {
            "taxonomy_bundle_id": self.configuration["taxonomy_bundle"]["bundle_id"],
            "content": content, "client_reference": f"pet-feed-{label}-{base.uuid4()}",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=60)).isoformat(),
        }, expected_status=201)

    def save(self, current: dict[str, Any], content: dict[str, Any]) -> dict[str, Any]:
        return self.edit(self.owner, "PUT", f"/v1/app/demands/{current['object_id']}/draft", {
            "base_version_id": current["current_version"]["version_id"],
            "taxonomy_bundle_id": self.configuration["taxonomy_bundle"]["bundle_id"],
            "content": content,
        }, current)

    def original(self, existing_id: str | None = None) -> dict[str, Any]:
        self.stage("ORIGINAL_HARDWARE_DRAFT")
        original = self.demand(base._canonical_uuid(existing_id)) if existing_id else self.create(original_content(), "original-hardware")
        matching.require(original["status"] == "DRAFT" and original["current_version"]["content"] == original_content(), "ORIGINAL_DRAFT_CHANGED")
        self.original_id = original["object_id"]
        unavailable = [field for field in self.configuration["editor_choices"]["fields"]
            if field["resource_type"] == "DEMAND" and field["intended_node_kind"] in {"DOMAIN", "SKILL", "TASK"}]
        probe = software_content(self.configuration["editor_choices"], original_id=self.original_id, refined=False)
        # Deliberately unsupported code: this negative probe must be rejected.
        probe["problem"]["domain_code"] = "DOMAIN.HARDWARE"
        path = f"/v1/app/demands/{self.original_id}/draft"
        rejected = self.owner.client.request(method="PUT", path=path,
            headers=base._write_headers(self.owner, if_match=original["etag"]), body={
                "base_version_id": original["current_version"]["version_id"],
                "taxonomy_bundle_id": self.configuration["taxonomy_bundle"]["bundle_id"], "content": probe})
        error_code = rejected.json().get("error", rejected.json()).get("code")
        matching.require(rejected.status == 422 and error_code == "EDITOR_CHOICE_UNAVAILABLE", "HARDWARE_GAP_CHANGED_REVIEW_REQUIRED")
        unchanged = self.demand(self.original_id)
        matching.require(unchanged["revision"] == original["revision"] and unchanged["current_version"] == original["current_version"], "REJECTED_DRAFT_MUTATED")
        return {"demand_id": self.original_id, "status": unchanged["status"], "revision": unchanged["revision"],
            "taxonomy_probe_http_status": rejected.status, "taxonomy_probe_error": error_code,
            "original_content_preserved": True, "available_choices": unavailable}

    def funded_demand(self, label: str) -> dict[str, Any]:
        self.stage("SOFTWARE_SUBDEMAND_DRAFT_SUBMIT")
        created = self.demand(self.existing_software_id) if self.existing_software_id else self.create({}, "software-analysis")
        matching.require(created["status"] == "DRAFT", "SOFTWARE_DEMAND_NOT_DRAFT")
        if self.existing_software_id:
            matching.require(self.original_id in created["current_version"]["content"].get("problem", {}).get("background", ""), "SOFTWARE_SOURCE_MISMATCH")
        current = self.save(created, software_content(self.configuration["editor_choices"], original_id=self.original_id, refined=False))
        path = f"/v1/app/demands/{current['object_id']}"
        submitted = self.edit(self.owner, "POST", path + "/submit", {}, current)
        matching.require(submitted["status"] == "SUBMITTED", "SUBMISSION_FAILED")
        self.stage("OPERATIONS_REQUEST_SCOPE_CLARIFICATION")
        first_claim = base._claim(self.reviewer, demand_id=created["object_id"])
        detail = base._get_resource(self.reviewer, path, resource_type="DEMAND")
        changes = self.edit(self.reviewer, "POST", path + f"/review-assignments/{first_claim['assignment_id']}/findings", {
            "reason_codes": ["SCOPE_UNCLEAR"], "required_field_paths": ["/scope"]}, detail)
        matching.require(changes["status"] == "NEEDS_CHANGES", "FINDING_NOT_APPLIED")
        owner_detail = self.demand(created["object_id"])
        base._require_owner_scope_finding(owner_detail)
        self.stage("OWNER_REFINE_RESUBMIT")
        revised = self.save(owner_detail, software_content(self.configuration["editor_choices"], original_id=self.original_id, refined=True))
        self.edit(self.owner, "POST", path + "/submit", {}, revised)
        second_claim = base._claim(self.reviewer, demand_id=created["object_id"])
        matching.require(second_claim["assignment_id"] != first_claim["assignment_id"], "REVIEW_ASSIGNMENT_NOT_RENEWED")
        detail = base._get_resource(self.reviewer, path, resource_type="DEMAND")
        self.stage("OPERATIONS_VERIFY_SOFTWARE_SCOPE")
        verify_path = path + f"/review-assignments/{second_claim['assignment_id']}/verify"
        verify_headers = base._write_headers(self.reviewer, if_match=detail["etag"])
        verify_response = self.reviewer.client.request(method="POST", path=verify_path, headers=verify_headers, body=base._verification_body())
        base._expect_status(verify_response, 200)
        verified = base._editor_envelope(verify_response, resource_type="DEMAND")
        replay_response = self.reviewer.client.request(method="POST", path=verify_path, headers=verify_headers, body=base._verification_body())
        matching.require(replay_response.status == 200 and replay_response.json() == verify_response.json() and verified["status"] == "VERIFIED", "VERIFICATION_REPLAY_FAILED")
        self.stage("DUAL_ZERO_VALUE_FINANCE_CONFIRMATION")
        for index, operator in enumerate(self.finance):
            queue_item = base._finance_queue_item(operator, demand_id=created["object_id"])
            claim = base._finance_write_exact_replay(operator, path=f"/v1/app/finance/funding-reviews/{created['object_id']}/claim", body={}, if_match=queue_item["etag"])
            confirmed = base._finance_write_exact_replay(operator, path=f"/v1/app/finance/funding-reviews/{claim['funding_review_id']}/confirm", body={"attestation_codes": list(base.FINANCE_FUNDING_ATTESTATION_CODES)}, if_match=claim["etag"])
            matching.require(confirmed["confirmation_count"] == index + 1 and confirmed["status"] == ("PENDING" if index == 0 else "SECURED"), "FINANCE_CONFIRMATION_FAILED")
        funded = self.demand(created["object_id"])
        matching.require(funded["status"] == "FUNDED", "FUNDING_FAILED")
        self.stage("AWAITING_EXPLICIT_SYSTEM_MATCHING")
        target = {"organization_id": self.organization_id, "demand_id": funded["object_id"],
            "expected_version": funded["revision"], "request_id": str(base.uuid4())}
        (self.request_directory / "matching-request.json").write_text(json.dumps(target, indent=2) + "\n")
        temp = self.request_directory / "matching-request.args.tmp"
        temp.write_text(" ".join(str(value) for value in target.values()) + "\n")
        temp.rename(self.request_directory / "matching-request.args")
        print(json.dumps({"stage": self.phase, "target": target}), flush=True)
        return verified


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--edge-host", default="edge")
    parser.add_argument("--original-id", help="Reuse only an unchanged original hardware draft after an interrupted probe.")
    parser.add_argument("--software-id", help="Resume an owned software sub-demand only before its first successful submission.")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    base.RESOLVE_ADDRESS = socket.gethostbyname(args.edge_host)
    recorder = Recorder(args.output_dir / "http-actions.json")
    result: dict[str, Any] = {"schema_version": "pet-feed-simulation-v1", "started_at": datetime.now(timezone.utc).isoformat(),
        "deployment_mode": "INTERNAL_SANDBOX", "assumptions": ASSUMPTIONS,
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(__file__).parent / "idea.md", Path(__file__).parent / "Weixin Image_20260903112219_17_1172.jpg")}}
    journey = None
    try:
        with tempfile.TemporaryDirectory(prefix="pet-feed-private-") as temporary:
            sessions = {code: matching._login(code, Path(temporary), args.ca_file) for code in matching.ACCOUNTS}
            for session in sessions.values():
                recorder.attach(session)
            journey = PetFeedJourney(sessions, timeout=300, request_directory=args.output_dir, recorder=recorder)
            journey.existing_software_id = base._canonical_uuid(args.software_id) if args.software_id else None
            matching.require(journey.configuration["deployment_mode"] == "INTERNAL_SANDBOX", "SANDBOX_REQUIRED")
            result["original_hardware"] = journey.original(args.original_id)
            journey.publish_zero_fee_profile()
            journey.complete_branch("SELECTED", response="accept")
            result["software_subdemand"] = journey.branches[0]
            result["status"] = "HARDWARE_BLOCKED_SOFTWARE_MATCHED"
            result["stop_reason"] = "原始硬件需求分类不可用；软件分析子需求已 MATCHED。当前 PostgreSQL 工作台未实现合同、项目、里程碑交付与验收，未宣称产品已交付。"
            final_demand = journey.demand(journey.branches[0]["demand_id"])
            result["software_revision"] = final_demand["revision"]
            (args.output_dir / "software-demand-content.json").write_text(json.dumps(final_demand["current_version"]["content"], ensure_ascii=False, indent=2) + "\n")
    except (base.InternalSandboxE2eError, matching.CheckError) as error:
        result["status"] = "SIMULATION_BLOCKED"
        result["error"] = {"code": getattr(error, "code", "INTERNAL_SANDBOX_E2E_FAILED"), "stage": journey.phase if journey else recorder.stage,
            "http_status": getattr(error, "status", None)}
    except Exception as error:
        # Do not print an arbitrary transport exception or private HTTP ledger.
        result["status"] = "SIMULATION_BLOCKED"
        result["error"] = {"code": "RUNNER_FAILED", "exception_type": type(error).__name__,
            "stage": journey.phase if journey else recorder.stage}
    finally:
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        result["http_write_attempts"] = len(recorder.events)
        (args.output_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"status": result.get("status", "FAILED"), "output": str(args.output_dir)}, ensure_ascii=False), flush=True)
    return 0 if result.get("status") == "HARDWARE_BLOCKED_SOFTWARE_MATCHED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
