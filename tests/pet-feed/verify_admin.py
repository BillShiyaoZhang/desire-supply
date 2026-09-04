#!/usr/bin/env python3
"""Read existing pet-feed demand timelines after deploying the admin feature.

OIDC authentication creates temporary sessions; all business requests are GET.
No personas, policies, authorities, demands or workflow facts are changed by this
script. Accounts must already have accepted their required policies.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_internal_sandbox_e2e as base
import run_internal_sandbox_matching_e2e as matching

ORIGINAL_ID = "85210ced-f3bc-4a37-b07a-ae98918f0755"
SOFTWARE_ID = "5488cead-7b10-4e78-8e23-9dd1b5318d6f"
ADMIN_CODES = ("access_admin_01", "org_admin_01")
PARTICIPANT_CODES = ("demand_owner_01", "operations_reviewer_01", "finance_operator_01", "finance_operator_02", "creator_01")
COLLECTION = "/v1/app/admin/demands"


def require(condition: Any, code: str) -> None:
    if not condition:
        raise matching.CheckError(code)


def login(code: str, root: Path, ca_file: Path) -> base.RoleSession:
    """Authenticate without the generic runner's automatic policy acceptance."""
    client = base.CurlClient(root=base._role_root(root, code), ca_file=ca_file)
    begin = client.request(method="POST", path="/v1/auth/oidc/authorizations",
        body={"return_to": "/app"}, headers={"Content-Type": "application/json", "Accept": "application/json"})
    base._expect_status(begin, 201)
    parser = base._RequestHandleParser()
    parser.feed(client.get_authorization_page(begin.json()["authorization_url"]).decode("utf-8"))
    require(len(parser.values) == 1, "OIDC_HANDLE_INVALID")
    client.authorize(account_code=code, request_handle=parser.values[0])
    session = base._session(client, expected_status=200)
    me = base._get_json(client, "/v1/me")
    require(me.get("status") == "ACTIVE", "ACCOUNT_NOT_ACTIVE")
    require(all(item.get("satisfied") is True for item in me.get("policy_requirements", [])), "POLICY_ACCEPTANCE_REQUIRED_BEFORE_READ_ONLY_CHECK")
    workspaces = base._get_json(client, "/v1/app/workspaces")["data"]["workspaces"]
    kind, roles = base.ROLE_EXPECTATIONS[code]
    choices = [w for w in workspaces if w["workspace_kind"] == kind and tuple(w["role_codes"]) == roles]
    require(len(choices) == 1, "WORKSPACE_AMBIGUOUS")
    return base.RoleSession(account_code=code, workspace_id=choices[0]["workspace_id"],
        workspace_kind=kind, role_codes=roles, csrf_token=session["csrf_token"],
        client=client, policy_accepted=False)


def get(session: base.RoleSession, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
    response = session.client.request(method="GET", path=path, query=query, headers=base._app_headers(session))
    require(response.status == 200, f"ADMIN_READ_HTTP_{response.status}")
    require("no-store" in response.headers.get("cache-control", ""), "CACHE_POLICY_MISSING")
    value = response.json()
    require(isinstance(value, dict) and set(value) == {"data"} and isinstance(value["data"], dict), "ADMIN_ENVELOPE_INVALID")
    return value


def pages(session: base.RoleSession, path: str, key: str, *, limit: int,
          projections: list[dict[str, Any]]) -> dict[str, Any]:
    cursor = None
    seen_cursors: set[str] = set()
    identifiers: set[str] = set()
    combined: list[dict[str, Any]] = []
    first = None
    count = 0
    while True:
        query = {"limit": str(limit)}
        if cursor is not None:
            query["cursor"] = cursor
        envelope = get(session, path, query)
        data = envelope["data"]
        projections.append({"account": session.account_code, "workspace_id": session.workspace_id,
            "kind": "timeline" if key == "events" else "collection", "payload": envelope})
        count += 1
        require(count < 1000, "PAGINATION_LIMIT_EXCEEDED")
        require(isinstance(data.get(key), list) and len(data[key]) <= limit, "PAGE_SIZE_INVALID")
        if first is None:
            first = data
        elif key == "events":
            require(all(data[name] == first[name] for name in ("demand", "participants", "stages", "coverage")), "TIMELINE_CHANGED_BETWEEN_PAGES")
        id_key = "event_id" if key == "events" else "demand_id"
        for item in data[key]:
            require(item[id_key] not in identifiers, "PAGINATION_DUPLICATE")
            identifiers.add(item[id_key])
            combined.append(item)
        next_cursor = data.get("next_cursor")
        require(data.get("has_more") is (next_cursor is not None), "PAGE_CURSOR_MISMATCH")
        if next_cursor is None:
            break
        require(next_cursor not in seen_cursors and len(data[key]) > 0, "PAGINATION_NOT_PROGRESSING")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    if key == "events":
        coordinates = [(datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00")), event["event_id"]) for event in combined]
        require(coordinates == sorted(coordinates), "TIMELINE_NOT_ORDERED")
        require(sum(stage["event_count"] for stage in first["stages"]) == len(combined), "TIMELINE_EVENTS_MISSING")
    return {**first, key: combined, "page_count": count}


def assert_software(data: dict[str, Any], identities: dict[str, str], demand_id: str) -> None:
    require(data["demand"]["demand_id"] == demand_id and data["demand"]["status"] == "MATCHED", "SOFTWARE_TERMINAL_MISMATCH")
    people = {p["user_id"]: p for p in data["participants"]}
    require(set(identities.values()).issubset(people), "PARTICIPANT_MISSING")
    require(all(people[user]["display_name"] for user in identities.values()), "PARTICIPANT_NAME_MISSING")
    events = data["events"]
    actions = {e["action"] for e in events}
    required = {"SubmitDemand", "RequestDemandChanges", "VerifyDemand", "RequestMatchingSystem",
        "CREATE_INVITATION", "PUBLISH_INVITATION", "ACCEPT_INVITATION", "CHOOSE_CREATOR", "COMPLETE_SELECTION"}
    require(required.issubset(actions), "WORKFLOW_ACTIONS_MISSING")
    require(any(e["action"] == "RequestDemandChanges"
        and e["details"].get("reason_code") == "SCOPE_UNCLEAR"
        and "范围与交付" in e["summary"] for e in events), "REVIEW_FINDING_MISSING")
    for code in ("finance_operator_01", "finance_operator_02"):
        require(any(e["actor_user_id"] == identities[code] and e["actor_role"] == "FINANCE_OPERATOR"
            and e["stage"] == "FUNDING" and e["action"] in {"CONFIRM_MANUAL_FUNDING_EVIDENCE", "FinanceConfirmationRecorded"}
            for e in events), "INDEPENDENT_FINANCE_CONFIRMATION_MISSING")
    require(any(e["actor_user_id"] == identities["creator_01"] and e["action"] == "ACCEPT_INVITATION"
        and e["details"].get("after_status") == "ACCEPTED" for e in events), "CREATOR_ACCEPTANCE_MISSING")
    require(any(e["actor_user_id"] == identities["demand_owner_01"] and e["action"] == "CHOOSE_CREATOR"
        for e in events), "OWNER_CHOICE_MISSING")
    require(any(e["actor_role"] == "SYSTEM" and e["actor_user_id"] is None for e in events), "SYSTEM_ACTOR_NOT_DISTINGUISHED")
    stages = {s["code"]: s for s in data["stages"]}
    require(all(stages[name]["status"] == "NOT_IMPLEMENTED" for name in ("AGREEMENT", "DELIVERY", "SETTLEMENT")), "UNIMPLEMENTED_STAGES_MISREPRESENTED")
    require(all(stages[name]["status"] == "COMPLETED" for name in ("INTAKE", "REVIEW", "FUNDING", "MATCHING", "SELECTION")), "IMPLEMENTED_STAGES_INCOMPLETE")
    require(data["demand"]["current_stage"] == "AGREEMENT" and "AGREEMENT_NOT_IMPLEMENTED" in data["demand"]["blocker_codes"], "NEXT_STEP_GAP_NOT_VISIBLE")


def validate_frontend(projections: list[dict[str, Any]]) -> None:
    """Actual server pages must satisfy the same strict parser used by the UI."""
    program = """
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
const contract = await import(pathToFileURL(process.argv[1]).href);
const pages = JSON.parse(fs.readFileSync(0, 'utf8'));
for (const item of pages) {
  if (item.kind === 'timeline') contract.parseAdminDemandTimeline(item.payload, item.payload.data.demand.demand_id, item.workspace_id);
  else contract.parseAdminDemandCollection(item.payload, item.workspace_id);
}
process.stdout.write(JSON.stringify({validated_pages:pages.length}));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", program,
        str(ROOT / "web/lib/admin-demand-contract.mjs")], input=json.dumps(projections),
        text=True, capture_output=True, check=False, timeout=30)
    require(result.returncode == 0, "FRONTEND_REJECTS_ACTUAL_ADMIN_DTO")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--edge-host", default="edge")
    parser.add_argument("--original-id", default=ORIGINAL_ID)
    parser.add_argument("--software-id", default=SOFTWARE_ID)
    args = parser.parse_args()
    args.original_id = base._canonical_uuid(args.original_id)
    args.software_id = base._canonical_uuid(args.software_id)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    base.RESOLVE_ADDRESS = socket.gethostbyname(args.edge_host)
    result: dict[str, Any] = {"schema_version": "pet-feed-admin-readonly-verification-v1", "status": "BLOCKED"}
    projections: list[dict[str, Any]] = []
    stage = "LOGIN"
    try:
        with tempfile.TemporaryDirectory(prefix="pet-feed-admin-private-") as temporary:
            sessions = {code: login(code, Path(temporary), args.ca_file) for code in ADMIN_CODES + PARTICIPANT_CODES}
            identities = {code: base._get_json(sessions[code].client, "/v1/me")["user_id"] for code in PARTICIPANT_CODES}
            verifications = []
            for code in ADMIN_CODES:
                session = sessions[code]
                stage = "COLLECTION_" + code.upper()
                listed = pages(session, COLLECTION, "items", limit=2, projections=projections)
                require({args.original_id, args.software_id}.issubset({item["demand_id"] for item in listed["items"]}), "PET_FEED_DEMAND_NOT_DISCOVERABLE")
                if code == "org_admin_01":
                    require(all(item["organization_id"] == session.workspace_id.split(":", 1)[1] for item in listed["items"]), "FOREIGN_ORGANIZATION_EXPOSED")
                stage = "ORIGINAL_TIMELINE_" + code.upper()
                original = pages(session, f"{COLLECTION}/{args.original_id}/timeline", "events", limit=2, projections=projections)
                require(original["demand"]["status"] == "DRAFT" and original["demand"]["aggregate_version"] == 1, "ORIGINAL_CHANGED")
                require(any(event["actor_user_id"] == identities["demand_owner_01"] for event in original["events"]), "ORIGINAL_AUTHOR_MISSING")
                stage = "SOFTWARE_TIMELINE_" + code.upper()
                software = pages(session, f"{COLLECTION}/{args.software_id}/timeline", "events", limit=2, projections=projections)
                assert_software(software, identities, args.software_id)
                listed_by_id = {item["demand_id"]: item for item in listed["items"]}
                require(all(listed_by_id[item["demand"]["demand_id"]] == item["demand"]
                    for item in (original, software)), "LIST_TIMELINE_SUMMARY_MISMATCH")
                # A second independently paged read with a larger page verifies
                # completeness and ordering, not merely cursor progress.
                full = pages(session, f"{COLLECTION}/{args.software_id}/timeline", "events", limit=100, projections=projections)
                require(software["events"] == full["events"], "PAGE_SIZE_CHANGES_TIMELINE")
                verifications.append({"account": code, "collection_pages": listed["page_count"],
                    "original_event_count": len(original["events"]), "software_event_count": len(software["events"]),
                    "software_pages_at_limit_2": software["page_count"],
                    "participants": software["participants"], "actions": sorted({e["action"] for e in software["events"]})})
            stage = "NON_ADMIN_DENIED"
            denied = []
            for code in ("demand_owner_01", "creator_01"):
                session = sessions[code]
                for path in (COLLECTION, f"{COLLECTION}/{args.original_id}/timeline", f"{COLLECTION}/{args.software_id}/timeline"):
                    response = session.client.request(method="GET", path=path, headers=base._app_headers(session))
                    require(response.status == 404, "NON_ADMIN_READ_ALLOWED")
                    denied.append({"account": code, "path": path, "http_status": response.status})
            stage = "FRONTEND_CONTRACT"
            validate_frontend(projections)
            (args.output_dir / "admin-projections.json").write_text(json.dumps(projections, ensure_ascii=False, indent=2) + "\n")
            result.update(status="PET_FEED_ADMIN_READONLY_GREEN", checks=verifications, denied_reads=denied,
                frontend_validated_pages=len(projections), business_writes=0)
    except Exception as error:
        result["error"] = {"stage": stage, "code": getattr(error, "code", "ADMIN_VERIFICATION_FAILED"),
            "exception_type": type(error).__name__}
    (args.output_dir / "admin-verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["status"] == "PET_FEED_ADMIN_READONLY_GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
