#!/usr/bin/env python3
"""Real HTTPS editor concurrency checks against synthetic local accounts.

Uses an independent Demand and removes only its private temporary HTTP files.
Does not modify the ten-account journey's Profile, Demand, or role grants.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import traceback
from uuid import uuid4

import run_internal_sandbox_e2e as core


def require(condition: bool, check: str) -> None:
    if not condition:
        raise RuntimeError(check)


def run(ca_file: Path) -> dict:
    ca = core._ca_file(ca_file)
    with tempfile.TemporaryDirectory(prefix="desire-editor-e2e.") as directory:
        root = Path(directory)
        owner = core._login(account_code="demand_owner_01",
                            root=core._role_root(root, "owner"), ca_file=ca)
        creator = core._login(account_code="creator_01",
                              root=core._role_root(root, "creator"), ca_file=ca)
        reviewer = core._login(account_code="operations_reviewer_01",
                               root=core._role_root(root, "reviewer"), ca_file=ca)
        config = core._configuration(owner)
        taxonomy = config["taxonomy_bundle"]["bundle_id"]
        content = core.safe_demand_content(config["editor_choices"])
        created = core._write_editor(owner, method="POST", path="/v1/app/demands",
            body={"taxonomy_bundle_id": taxonomy, "content": content,
                  "client_reference": f"editor-concurrency-{uuid4()}",
                  "expires_at": (datetime.now(timezone.utc) + timedelta(days=60))
                      .replace(microsecond=0).isoformat()},
            expected_status=201, resource_type="DEMAND")
        path = f"/v1/app/demands/{created['object_id']}"
        base = created["current_version"]
        first_content = deepcopy(content)
        first_content["problem"]["background"] = "合成并发验收：第一次保存"
        first_body = {"base_version_id": base["version_id"],
                      "taxonomy_bundle_id": taxonomy, "content": first_content}
        first_headers = core._write_headers(owner, if_match=created["etag"])
        first = owner.client.request(method="PUT", path=path + "/draft",
                                     body=first_body, headers=first_headers)
        core._expect_status(first, 200)
        saved = core._editor_envelope(first, resource_type="DEMAND")
        replay = owner.client.request(method="PUT", path=path + "/draft",
                                      body=first_body, headers=first_headers)
        require(replay.status == 200, f"DRAFT_REPLAY_HTTP_{replay.status}")
        require(replay.json() == first.json(), "EXACT_REPLAY_CHANGED_RESULT")

        stale_content = deepcopy(content)
        stale_content["problem"]["background"] = "合成并发验收：另一个编辑窗口"
        stale_body = {**first_body, "content": stale_content}
        reused = owner.client.request(method="PUT", path=path + "/draft",
                                      body=stale_body, headers=first_headers)
        core._expect_status(reused, 409)
        require(reused.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED",
                "WRONG_IDEMPOTENCY_ERROR")
        stale = owner.client.request(method="PUT", path=path + "/draft",
            body=stale_body, headers=core._write_headers(owner, if_match=created["etag"]))
        core._expect_status(stale, 412)
        details = stale.json()["error"]["details"]
        require(set(details) == {"current", "base", "yours"}, "MISSING_THREE_WAY_DATA")
        require(details["base"]["content"] == content, "BASE_VERSION_CHANGED")
        require(details["yours"]["content"] == stale_content, "LOCAL_EDIT_LOST")
        require(stale.headers["etag"] == saved["etag"], "WRONG_CONFLICT_ETAG")
        current = core._get_resource(owner, path, resource_type="DEMAND")
        require(current == saved, "REJECTED_WRITE_CHANGED_RESOURCE")
        merged_content = deepcopy(first_content)
        merged_content["problem"]["background"] += "；人工合并另一个窗口的修改"
        merged = core._write_editor(owner, method="PUT", path=path + "/draft",
            body={"base_version_id": saved["current_version"]["version_id"],
                  "taxonomy_bundle_id": taxonomy, "content": merged_content},
            if_match=saved["etag"], expected_status=200, resource_type="DEMAND")
        prior = next(v for v in merged["versions"] if v["version_id"] == base["version_id"])
        require(prior == base, "IMMUTABLE_VERSION_CHANGED")
        require(merged["current_version"]["content"] == merged_content, "MERGE_NOT_SAVED")

        # Creator cannot read an Organization Demand; reviewer needs an assignment.
        for session in (creator, reviewer):
            denied = session.client.request(method="GET", path=path,
                                             headers=core._app_headers(session))
            require(denied.status in (403, 404), "UNASSIGNED_DEMAND_VISIBLE")
            require("data" not in denied.json(), "UNASSIGNED_CONTENT_DISCLOSED")
        profiles = core._list_resources(creator, path="/v1/app/profiles",
                                        resource_type="CREATOR_PROFILE")
        require(len(profiles) == 1, "CREATOR_PROFILE_MISSING")
        for session in (owner, reviewer):
            denied = session.client.request(method="GET",
                path=f"/v1/app/profiles/{profiles[0]['object_id']}",
                headers=core._app_headers(session))
            require(denied.status in (403, 404), "PRIVATE_PROFILE_VISIBLE")
            require("data" not in denied.json(), "PRIVATE_PROFILE_DISCLOSED")
        cancelled = core._cancel_demand_exact_replay(owner, demand=merged)
        require(cancelled["versions"] == merged["versions"], "CANCEL_LOST_HISTORY")
        return {"status": "EDITOR_CONCURRENCY_PRIVACY_E2E_GREEN",
                "demand_id": created["object_id"], "exact_replay": True,
                "changed_payload_409": True, "stale_version_412": True,
                "three_way_data_preserved": True, "explicit_merge_saved": True,
                "immutable_version_preserved": True,
                "unassigned_demand_hidden": True, "private_profile_hidden": True,
                "independent_demand_cancelled": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", required=True, type=Path)
    parser.add_argument("--result-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        core._new_absolute_output(args.result_output)
        result = run(args.ca_file)
        serialized = json.dumps(result, separators=(",", ":")) + "\n"
        core._write_new(args.result_output, serialized.encode(), mode=0o600)
        print(serialized, end="")
        return 0
    except (core.InternalSandboxE2eError, RuntimeError, KeyError, ValueError, OSError) as error:
        # No response bodies, cookies, CSRF tokens, or authorization URLs in output.
        check = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(json.dumps({"status": "EDITOR_E2E_FAILED", "check": check,
                          "frames": [{"function": f.name, "line": f.lineno}
                                     for f in traceback.extract_tb(error.__traceback__)]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
