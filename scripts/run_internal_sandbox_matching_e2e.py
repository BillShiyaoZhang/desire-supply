#!/usr/bin/env python3
"""Exercise the deployed Matching v3 workflow through real local HTTPS calls.

Run after the ten-account acceptance journey and its restart check on a dedicated
INTERNAL_SANDBOX Docker project.  Participant actions use normal browser APIs;
each FUNDED demand emits an exact target file for the authenticated SYSTEM
RequestMatching command, then waits for the independent worker/coordinator.
There are no direct SQL writes or test-only authority shortcuts.
The synthetic Creator publishes an explicitly zero-fee profile because this
sandbox permits only zero-value funding.  Project agreements and deliverables
are outside the implemented Matching HTTP surface and are not claimed here.
Successful runs retain only private cookie checkpoints until verify-restart;
Matching selector authority is bound to the original session. Verification
also proves a fresh Owner session cannot read those assigned selections.
Interrupted runs may resume the first target before assignment, reconcile the
first unknown review claim with its original session and exact command key, or
resume a known CREATED invitation after expired assignments are explicitly
claimed again through current IAM authority. A confirmed SENT invitation can
resume without another CREATE or PUBLISH. No general recovery is inferred.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
from typing import Any, Callable, Mapping

import run_internal_sandbox_e2e as base


SCHEMA = "internal-sandbox-matching-http-e2e-v1"
ACCOUNTS = (
    "creator_01", "demand_owner_01", "operations_reviewer_01",
    "finance_operator_01", "finance_operator_02",
)
BRANCH_EXPECTATIONS = {
    "SELECTED": ("MATCHED", "SELECTED", "ACCEPTED"),
    "DECLINED_OWNER_CLOSE": ("NO_MATCH", "CLOSED_NO_SELECTION", "DECLINED"),
    "WITHDRAWN_OWNER_CLOSE": ("NO_MATCH", "CLOSED_NO_SELECTION", "WITHDRAWN"),
    "ZERO_CANDIDATES": ("NO_MATCH", None, None),
}
REVIEW_PATH = "/v1/app/matching-review/assignment"
FORBIDDEN_SHARED_KEYS = frozenset({
    "minimum_project_amount_minor", "private_floor", "private_floor_amount_minor",
    "boundaries", "conflicts", "session_id", "csrf_token", "evidence_locator",
    "raw_input", "match_run_input", "excluded_candidates",
})


class CheckError(RuntimeError):
    def __init__(self, code: str, *, status: int | None = None) -> None:
        self.code = code
        self.status = status
        super().__init__(code)


def require(condition: Any, code: str) -> None:
    if not condition:
        raise CheckError(code)


def _no_private_fields(value: Any, *, recipient: bool = False) -> None:
    forbidden = FORBIDDEN_SHARED_KEYS | (
        frozenset({"rank", "total_score", "component_scores", "creator_user_id"})
        if recipient else frozenset()
    )
    if isinstance(value, dict):
        require(not forbidden.intersection(value), "PRIVATE_PROJECTION_FIELD")
        for child in value.values():
            _no_private_fields(child, recipient=recipient)
    elif isinstance(value, list):
        for child in value:
            _no_private_fields(child, recipient=recipient)


def _payload(result: base.HttpResult, *, status: int = 200) -> dict[str, Any]:
    if result.status != status:
        value = result.json()
        error_code = value.get("code") if isinstance(value, dict) else None
        # Emit only the server's closed error code, never response bodies/IDs.
        if not isinstance(error_code, str) or not base.re.fullmatch(
            r"[A-Z][A-Z0-9_]{1,63}", error_code
        ):
            error_code = "UNEXPECTED_HTTP_STATUS"
        raise CheckError(error_code, status=result.status)
    value = result.json()
    require(isinstance(value, dict), "INVALID_JSON_OBJECT")
    require("no-store" in result.headers.get("cache-control", ""), "MISSING_NO_STORE")
    return value


def _get(session: base.RoleSession, path: str) -> dict[str, Any]:
    return _payload(session.client.request(
        method="GET", path=path, headers=base._app_headers(session),
    ))


def _write(
    session: base.RoleSession, path: str, body: Mapping[str, Any], *,
    version: int | None = None, status: int = 200, replay: bool = True,
    progression: tuple[str, str] | None = None,
) -> dict[str, Any]:
    headers = base._write_headers(
        session, if_match=None if version is None else f'"v{version}"',
    )
    response = session.client.request(method="POST", path=path, body=body, headers=headers)
    data = _payload(response, status=status)
    if replay:
        repeated = session.client.request(method="POST", path=path, body=body, headers=headers)
        recovered = _payload(repeated, status=status)
        if progression is None:
            require(recovered == data, "EXACT_REPLAY_CHANGED")
            require(repeated.headers.get("etag") == response.headers.get("etag"), "REPLAY_ETAG_CHANGED")
        else:
            # Selection commands return a current authorized projection after
            # receipt replay. The coordinator may complete between two calls.
            for field in ("selection_id", "attempt_id", "chosen_invitation_id",
                          "candidate_selector_assignment_id", "current_invitation_set_sha256"):
                require(recovered[field] == data[field], "REPLAY_SELECTION_BINDING_CHANGED")
            require(data["status"] in progression and recovered["status"] in progression
                    and progression.index(recovered["status"]) >= progression.index(data["status"])
                    and recovered["aggregate_version"] >= data["aggregate_version"], "REPLAY_SELECTION_REGRESSED")
    return data


def _login(code: str, root: Path, ca_file: Path) -> base.RoleSession:
    """Use the synthetic OIDC chooser; select the exact role workspace.

    The core journey gives Creator a second organization workspace.  Discovery
    remains authoritative and this runner does not require only one workspace.
    """
    client = base.CurlClient(root=base._role_root(root, code), ca_file=ca_file)
    begin = client.request(
        method="POST", path="/v1/auth/oidc/authorizations", body={"return_to": "/app"},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    base._expect_status(begin, 201)
    authorization_url = begin.json()["authorization_url"]
    parser = base._RequestHandleParser()
    parser.feed(client.get_authorization_page(authorization_url).decode("utf-8"))
    require(len(parser.values) == 1, "OIDC_CHOOSER_HANDLE_INVALID")
    client.authorize(account_code=code, request_handle=parser.values[0])
    return _role_session(code, client)


def _role_session(code: str, client: base.CurlClient) -> base.RoleSession:
    session = base._session(client, expected_status=200)
    me = base._get_json(client, "/v1/me")
    require(me.get("status") == "ACTIVE", "ACCOUNT_NOT_ACTIVE")
    accepted = base._accept_missing_policies(client, session, me)
    discovered = base._get_json(client, "/v1/app/workspaces")["data"]["workspaces"]
    expected_kind, expected_roles = base.ROLE_EXPECTATIONS[code]
    candidates = [item for item in discovered if item["workspace_kind"] == expected_kind
                  and tuple(item["role_codes"]) == expected_roles]
    require(len(candidates) == 1, "ROLE_WORKSPACE_AMBIGUOUS")
    workspace = candidates[0]
    return base.RoleSession(
        account_code=code, workspace_id=workspace["workspace_id"],
        workspace_kind=expected_kind, role_codes=expected_roles,
        csrf_token=session["csrf_token"], client=client, policy_accepted=accepted,
    )


def _restore_session(code: str, root: Path, source: Path, ca_file: Path) -> base.RoleSession:
    cookie_file = base._private_absolute_file(source / code / "cookies.txt")
    client = base.CurlClient(root=base._role_root(root, code), ca_file=ca_file)
    # Copy only into the newly-created 0600 jar, keeping the original ledger
    # intact until every branch succeeds. Neither cookie content is rendered.
    with client._cookie_jar.open("wb") as destination:
        destination.write(cookie_file.read_bytes())
    return _role_session(code, client)


def _private_directory(path: Path, *, parent: Path, prefix: str) -> Path:
    require(path == path.resolve(strict=True) and path.parent == parent
            and path.name.startswith(prefix) and stat.S_ISDIR(path.stat().st_mode)
            and stat.S_IMODE(path.stat().st_mode) == 0o700, "PRIVATE_DIRECTORY_INVALID")
    return path


def _session_checkpoint(sessions: Mapping[str, base.RoleSession], parent: Path) -> Path:
    checkpoint = Path(tempfile.mkdtemp(prefix="matching-http-checkpoint.", dir=parent))
    os.chmod(checkpoint, 0o700)
    for code, session in sessions.items():
        role = base._role_root(checkpoint, code)
        base._write_new(role / "cookies.txt", session.client._cookie_jar.read_bytes(), mode=0o600)
    return checkpoint


def _review_claim_headers(source: Path, reviewer: base.RoleSession) -> dict[str, str]:
    """Recover only the exact first review claim; never render its headers.

    Older interrupted runs predate the explicit pending-command checkpoint.
    Their final four private CurlClient files are accepted only for the known
    first-claim stage and a closed COMMAND_OUTCOME_UNKNOWN response.
    """
    pending = source / "pending-review-claim.json"
    if pending.exists():
        command = json.loads(base._private_absolute_file(pending).read_text())
        require(set(command) == {"method", "path", "body", "headers"}
                and command["method"] == "POST"
                and command["path"] == "/v1/app/matching-review/queue/claim"
                and command["body"] == {}, "RESUME_COMMAND_INVALID")
        headers = command["headers"]
    else:
        role = _private_directory(source / "operations_reviewer_01", parent=source,
                                  prefix="operations_reviewer_01")
        files = [item for item in role.iterdir()
                 if base.re.fullmatch(r"[0-9]{4,}-[a-z-]+", item.name)]
        require(bool(files), "RESUME_COMMAND_MISSING")
        sequence = max(int(item.name.split("-", 1)[0]) for item in files)
        def read(offset: int, label: str) -> str:
            path = role / f"{sequence + offset:04d}-{label}"
            if label.startswith("response"):
                # Curl creates response files using its inherited umask. The
                # validated 0700 role directory encloses these older files.
                path = base._absolute_regular_file(path)
                require(stat.S_IMODE(path.stat().st_mode) in {0o600, 0o644}, "RESUME_COMMAND_INVALID")
            else:
                path = base._private_absolute_file(path)
            return path.read_text()
        require(json.loads(read(0, "request-body")) == {}, "RESUME_COMMAND_INVALID")
        outcome = json.loads(read(-3, "response"))
        require(isinstance(outcome, dict) and outcome.get("code") == "COMMAND_OUTCOME_UNKNOWN",
                "RESUME_COMMAND_OUTCOME_INVALID")
        require(any(base.re.fullmatch(r"HTTP/[0-9.]+ 503(?: .*)?", line)
                    for line in read(-2, "response-headers").splitlines()),
                "RESUME_COMMAND_OUTCOME_INVALID")
        pairs = [line.split(": ", 1) for line in read(-1, "request-headers").splitlines()]
        require(all(len(pair) == 2 for pair in pairs), "RESUME_COMMAND_INVALID")
        headers = dict(pairs)
        require(len(headers) == len(pairs), "RESUME_COMMAND_INVALID")
    require(isinstance(headers, dict)
            and set(headers) == {"Accept", "X-Workspace-Id", "Content-Type",
                                 "Idempotency-Key", "X-CSRF-Token"}
            and headers["Accept"] == headers["Content-Type"] == "application/json"
            and headers["X-Workspace-Id"] == reviewer.workspace_id
            and headers["X-CSRF-Token"] == reviewer.csrf_token
            and isinstance(headers["Idempotency-Key"], str)
            and base.re.fullmatch(r"internal-sandbox-e2e-[0-9a-f-]{36}", headers["Idempotency-Key"]),
            "RESUME_COMMAND_BINDING_INVALID")
    base._canonical_uuid(headers["Idempotency-Key"].removeprefix("internal-sandbox-e2e-"))
    return headers


def _known_created_invitation(source: Path, target: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve conclusive creation evidence without carrying old authority."""
    def responses(code: str) -> list[dict[str, Any]]:
        role = _private_directory(source / code, parent=source, prefix=code)
        documents = [json.loads(base._private_absolute_file(path).read_text())
                     for path in sorted(role.glob("*-response"))]
        return [item for item in documents if isinstance(item, dict)]
    review = responses("operations_reviewer_01")
    require(review and review[-1].get("code") == "INVITATION_ALREADY_EXISTS", "CREATED_RECOVERY_EVIDENCE_INVALID")
    invitations = [item for item in review if item.get("status") == "CREATED" and "invitation_id" in item]
    selectors = [item for item in responses("demand_owner_01") if "candidate_selector_assignment_id" in item]
    require(len(invitations) == 1 and selectors and all(item == selectors[0] for item in selectors), "CREATED_RECOVERY_EVIDENCE_INVALID")
    invitation, selector = invitations[0], selectors[0]
    reviews = [item for item in review if "assignment_id" in item and "attempt_id" in item]
    require(reviews and len({item["assignment_id"] for item in reviews}) == 1
            and selector["demand_id"] == target["demand_id"]
            and invitation["attempt_id"] == selector["attempt_id"] == reviews[0]["attempt_id"]
            and invitation["match_run_id"] == reviews[0]["match_run_id"]
            and invitation["aggregate_version"] == 1, "CREATED_RECOVERY_BINDING_INVALID")
    require(selector["status"] == "ACTIVE" and selector["selection_status"] == "OPEN"
            and all(item["status"] == "ACTIVE" for item in reviews), "CREATED_RECOVERY_BINDING_INVALID")
    for value in (target["demand_id"], invitation["invitation_id"], invitation["attempt_id"],
                  invitation["match_run_id"], selector["selection_id"],
                  selector["candidate_selector_assignment_id"], reviews[0]["assignment_id"]):
        base._canonical_uuid(value)
    require(base.re.fullmatch(r"[0-9a-f]{64}", invitation["snapshot_sha256"]), "CREATED_RECOVERY_BINDING_INVALID")
    return {"demand_id": target["demand_id"], "attempt_id": invitation["attempt_id"],
            "match_run_id": invitation["match_run_id"], "invitation_id": invitation["invitation_id"],
            "snapshot_sha256": invitation["snapshot_sha256"], "selection_id": selector["selection_id"],
            "old_review_assignment_id": reviews[0]["assignment_id"],
            "old_selector_assignment_id": selector["candidate_selector_assignment_id"],
            "review_assignment_expires_at": reviews[0]["expires_at"],
            "selector_assignment_expires_at": selector["expires_at"],
            "first_create_status": "CREATED", "original_exact_replay_failure": "INVITATION_ALREADY_EXISTS"}


def _require_expired_sessions(root: Path, source: Path, ca_file: Path) -> None:
    for code in ACCOUNTS:
        client = base.CurlClient(root=base._role_root(root, "expired_" + code), ca_file=ca_file)
        client._cookie_jar.write_bytes(base._private_absolute_file(source / code / "cookies.txt").read_bytes())
        require(client.request(method="GET", path="/v1/auth/session").status == 401,
                "ORIGINAL_SESSION_STILL_ACTIVE")


def _known_sent_invitation(source: Path, target: Mapping[str, Any]) -> dict[str, Any]:
    """Recover a committed packet from successful HTTP responses, never authority."""
    def responses(code: str) -> list[dict[str, Any]]:
        role = _private_directory(source / code, parent=source, prefix=code)
        values = []
        for path in sorted(role.glob("*-response")):
            try:
                value = json.loads(base._private_absolute_file(path).read_text())
            except json.JSONDecodeError:
                # A fresh login also records empty redirects and HTML pages.
                continue
            if isinstance(value, dict):
                values.append(value)
        return values

    review = responses("operations_reviewer_01")
    previous = source / "created-invitation-recovery.json"
    if previous.exists():
        known = json.loads(base._private_absolute_file(previous).read_text())
    else:
        created = [item for item in review if item.get("status") == "CREATED" and "invitation_id" in item]
        selectors = [item for item in responses("demand_owner_01") if "candidate_selector_assignment_id" in item]
        assignments = [item for item in review if "assignment_id" in item and "attempt_id" in item]
        require(len(created) == 2 and created[0] == created[1]
                and created[0]["aggregate_version"] == 1 and selectors
                and all(item == selectors[0] for item in selectors)
                and assignments and len({item["assignment_id"] for item in assignments}) == 1,
                "SENT_RECOVERY_CREATE_NOT_CONFIRMED")
        invitation, selector = created[0], selectors[0]
        require(selector["demand_id"] == target["demand_id"]
                and invitation["attempt_id"] == selector["attempt_id"] == assignments[0]["attempt_id"]
                and invitation["match_run_id"] == assignments[0]["match_run_id"]
                and selector["status"] == "ACTIVE" and selector["selection_status"] == "OPEN",
                "SENT_RECOVERY_TARGET_INVALID")
        known = {"demand_id": target["demand_id"], "attempt_id": invitation["attempt_id"],
                 "match_run_id": invitation["match_run_id"], "invitation_id": invitation["invitation_id"],
                 "snapshot_sha256": invitation["snapshot_sha256"], "selection_id": selector["selection_id"],
                 "create_exact_replay_verified": True}
    require(known["demand_id"] == target["demand_id"], "SENT_RECOVERY_TARGET_INVALID")
    for key in ("demand_id", "attempt_id", "match_run_id", "invitation_id", "selection_id"):
        base._canonical_uuid(known[key])
    require(base.re.fullmatch(r"[0-9a-f]{64}", known["snapshot_sha256"]), "SENT_RECOVERY_TARGET_INVALID")
    sent = [item for item in review if item.get("invitation_id") == known["invitation_id"]
            and item.get("status") == "SENT"]
    require((len(sent) == 2 and sent[0] == sent[1] and sent[0]["aggregate_version"] == 2
             and sent[0]["snapshot_sha256"] == known["snapshot_sha256"]
             and sent[0]["attempt_id"] == known["attempt_id"]
             and sent[0]["match_run_id"] == known["match_run_id"])
            or (not sent and known.get("publish_exact_replay_verified") is True),
            "SENT_RECOVERY_PUBLISH_NOT_CONFIRMED")
    known["publish_exact_replay_verified"] = True
    return known


def _known_pending_choice(source: Path, target: Mapping[str, Any]) -> dict[str, Any]:
    known = _known_sent_invitation(source, target)
    def responses(role: str, statuses: set[str]) -> list[dict[str, Any]]:
        directory = _private_directory(source / role, parent=source, prefix=role)
        values = []
        for path in sorted(directory.glob("*-response")):
            try:
                value = json.loads(base._private_absolute_file(path).read_text())
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("status") in statuses:
                values.append(value)
        return values
    accepted = responses("creator_01", {"ACCEPTED"})
    choices = responses("demand_owner_01", {"PENDING_CHOICE", "SELECTED"})
    require(len(accepted) == 2 and accepted[0] == accepted[1]
            and accepted[0]["invitation_id"] == known["invitation_id"]
            and accepted[0]["snapshot_sha256"] == known["snapshot_sha256"]
            and accepted[0]["aggregate_version"] == 3
            and accepted[0]["response_status"] == "ACCEPTED"
            and len(choices) >= 2
            and all(item["selection_id"] == known["selection_id"]
                    and item["attempt_id"] == known["attempt_id"]
                    and item["chosen_invitation_id"] == known["invitation_id"] for item in choices),
            "PENDING_CHOICE_RECOVERY_NOT_CONFIRMED")
    return known


def _wait(read: Callable[[], Any], ready: Callable[[Any], bool], *, timeout: int) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        result = read()
        if ready(result):
            return result
        if time.monotonic() >= deadline:
            raise CheckError("WORKFLOW_PROGRESS_TIMEOUT")
        time.sleep(1)


class Journey:
    def __init__(self, sessions: Mapping[str, base.RoleSession], *, timeout: int,
                 request_directory: Path | None = None) -> None:
        self.creator = sessions["creator_01"]
        self.owner = sessions["demand_owner_01"]
        self.reviewer = sessions["operations_reviewer_01"]
        self.finance = (sessions["finance_operator_01"], sessions["finance_operator_02"])
        self.organization_id = self.owner.workspace_id.split(":", 1)[1]
        self.timeout = timeout
        self.request_directory = request_directory
        self.configuration = base._shared_editor_configuration(self.creator, self.owner)
        self.profile: Mapping[str, Any] | None = None
        self.phase = "CONFIGURATION"
        self.branches: list[dict[str, Any]] = []
        self.pending_review_claim: dict[str, Any] | None = None
        self.recovered_invitation: dict[str, Any] | None = None
        self.recovered_sent_invitation: dict[str, Any] | None = None

    def stage(self, name: str) -> None:
        self.phase = name
        print(json.dumps({"stage": name, "status": "RUNNING"}), flush=True)

    def publish_zero_fee_profile(self) -> None:
        self.stage("ZERO_FEE_SYNTHETIC_PROFILE")
        existing = base._list_resources(self.creator, path="/v1/app/profiles", resource_type="CREATOR_PROFILE")
        require(len(existing) <= 1, "MULTIPLE_CREATOR_PROFILES")
        if existing:
            current = base._get_resource(self.creator, f"/v1/app/profiles/{existing[0]['object_id']}", resource_type="CREATOR_PROFILE")
        else:
            current = base._write_editor(self.creator, method="POST", path="/v1/app/profiles", body={}, expected_status=201, resource_type="CREATOR_PROFILE")
        require(current["status"] in {"DRAFT", "ACTIVE"}, "PROFILE_NOT_EDITABLE")
        content = base.safe_profile_content(self.configuration["editor_choices"])
        content["compensation"]["minimum_project_amount_minor"] = 0
        content["compensation"]["direct_cost_amount_minor"] = 0
        drafted = base._write_editor(
            self.creator, method="PUT", path=f"/v1/app/profiles/{current['object_id']}/draft",
            body={"base_version_id": None if current["current_version"] is None else current["current_version"]["version_id"],
                  "taxonomy_bundle_id": self.configuration["taxonomy_bundle"]["bundle_id"], "content": content},
            if_match=current["etag"], expected_status=200, resource_type="CREATOR_PROFILE",
        )
        self.profile = base._write_editor(
            self.creator, method="POST", path=f"/v1/app/profiles/{current['object_id']}/publish",
            body={"draft_version_id": drafted["current_version"]["version_id"]},
            if_match=drafted["etag"], expected_status=200, resource_type="CREATOR_PROFILE",
        )
        require(self.profile["status"] == "ACTIVE", "PROFILE_NOT_PUBLISHED")

    def funded_demand(self, label: str) -> Mapping[str, Any]:
        self.stage(f"{label}_DEMAND_REVIEW")
        reviewable, _ = base._create_reviewable_demand(
            owner=self.owner, reviewer=self.reviewer,
            taxonomy_id=self.configuration["taxonomy_bundle"]["bundle_id"],
            editor_choices=self.configuration["editor_choices"],
        )
        verified = base._verify_demand_after_hold_release(
            self.reviewer, blocked_demand=reviewable,
            blocked_idempotency_key=base._idempotency_key(),
        )
        self.stage(f"{label}_DUAL_FINANCE_CONFIRMATION")
        funding_id = None
        assignments: list[str] = []
        for index, operator in enumerate(self.finance):
            item = base._finance_queue_item(operator, demand_id=verified["object_id"])
            claimed = base._finance_write_exact_replay(
                operator, path=f"/v1/app/finance/funding-reviews/{verified['object_id']}/claim",
                body={}, if_match=item["etag"],
            )
            require(claimed["confirmation_count"] == index, "WRONG_FINANCE_CONFIRMATION_COUNT")
            if funding_id is not None:
                require(claimed["funding_review_id"] == funding_id, "FINANCE_REVIEW_CHANGED")
            funding_id = claimed["funding_review_id"]
            assignments.append(claimed["assignment_id"])
            confirmed = base._finance_write_exact_replay(
                operator, path=f"/v1/app/finance/funding-reviews/{funding_id}/confirm",
                body={"attestation_codes": list(base.FINANCE_FUNDING_ATTESTATION_CODES)},
                if_match=claimed["etag"],
            )
            require(confirmed["confirmation_count"] == index + 1, "FINANCE_CONFIRMATION_MISSING")
            require(confirmed["status"] == ("PENDING" if index == 0 else "SECURED"), "FINANCE_FUNDING_STATE_INVALID")
        require(len(set(assignments)) == 2, "FINANCE_ASSIGNMENTS_NOT_DISTINCT")
        funded = self.demand(verified["object_id"])
        require(funded["status"] == "FUNDED", "DEMAND_NOT_FUNDED")
        require(self.request_directory is not None, "SYSTEM_REQUEST_HANDOFF_MISSING")
        self.stage(f"{label}_REQUEST_MATCHING")
        # Only an authenticated SYSTEM workload may start the next step. The
        # operator runs docker-local.sh match against this exact target; the
        # HTTP runner never receives the workload's database credential.
        target = {"organization_id": self.organization_id,
                  "demand_id": funded["object_id"], "expected_version": funded["revision"],
                  "request_id": str(base.uuid4())}
        request_file = self.request_directory / f"{label.lower()}.json"
        base._write_new(request_file, (json.dumps(target, indent=2) + "\n").encode("utf-8"), mode=0o600)
        print(json.dumps({"stage": f"{label}_REQUEST_MATCHING", "status": "AWAITING_SYSTEM_COMMAND",
                          "request_file": str(request_file)}), flush=True)
        return verified

    def demand(self, demand_id: str) -> Mapping[str, Any]:
        return base._get_resource(self.owner, f"/v1/app/demands/{demand_id}", resource_type="DEMAND")

    def attempts(self, demand_id: str) -> list[dict[str, Any]]:
        value = _get(self.owner, f"/v1/organizations/{self.organization_id}/demands/{demand_id}/matching-attempts")
        require(set(value) == {"items", "next_cursor"} and value["next_cursor"] is None, "ATTEMPT_LIST_INVALID")
        require(all(item["demand_id"] == demand_id for item in value["items"]), "ATTEMPT_DEMAND_MISMATCH")
        return value["items"]

    def prior_no_match(self, target: Mapping[str, Any]) -> dict[str, Any]:
        self.stage("PRIOR_REQUEST_NATURAL_NO_MATCH")
        require(target["organization_id"] == self.organization_id, "PRIOR_ORGANIZATION_CHANGED")
        demand_id = base._canonical_uuid(target["demand_id"])
        demand = _wait(lambda: self.demand(demand_id), lambda value: value["status"] == "NO_MATCH", timeout=self.timeout)
        attempts = self.attempts(demand_id)
        require(attempts == [], "PRIOR_UNASSIGNED_ATTEMPT_VISIBLE")
        return {"demand_id": demand_id, "demand_status": demand["status"],
                "active_selector_attempts_visible": 0}

    def selection(self, attempt_id: str, selection_id: str | None = None) -> dict[str, Any]:
        path = (f"/v1/organizations/{self.organization_id}/selections/{selection_id}" if selection_id
                else f"/v1/organizations/{self.organization_id}/matching-attempts/{attempt_id}/selection")
        value = _get(self.owner, path)
        _no_private_fields(value, recipient=True)
        require(value["attempt_id"] == attempt_id, "SELECTION_ATTEMPT_MISMATCH")
        require(selection_id is None or value["selection_id"] == selection_id, "SELECTION_ID_MISMATCH")
        return value

    def invite(self, demand_id: str, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if label == "SELECTED" and self.recovered_sent_invitation:
            return self.resume_sent_invitation(demand_id)
        self.stage(f"{label}_MATCHING_WORKER")
        _wait(lambda: self.demand(demand_id), lambda value: value["status"] == "MATCHING", timeout=self.timeout)
        require(self.attempts(demand_id) == [], "UNASSIGNED_ATTEMPT_VISIBLE")
        recovered = self.recovered_invitation if label == "SELECTED" else None
        if recovered:
            before_claim = self.owner.client.request(method="GET", path=f"/v1/organizations/{self.organization_id}/selections/{recovered['selection_id']}", headers=base._app_headers(self.owner))
            require(before_claim.status == 404, "NEW_SESSION_INHERITED_SELECTOR_AUTHORITY")
        self.stage(f"{label}_MATCHING_REVIEW_ASSIGNMENT")
        # Claim itself is the queue API. Reuse one key during polling so any
        # unknown outcome is reconciled before another claim can be attempted.
        claim_headers = (self.pending_review_claim["headers"] if self.pending_review_claim
                         else base._write_headers(self.reviewer))
        self.pending_review_claim = {"method": "POST", "path": "/v1/app/matching-review/queue/claim",
                                     "body": {}, "headers": claim_headers}
        def claim() -> dict[str, Any] | None:
            response = self.reviewer.client.request(method="POST", path="/v1/app/matching-review/queue/claim", body={}, headers=claim_headers)
            if response.status == 404:
                return None
            return _payload(response, status=201)
        assignment = _wait(claim, lambda value: value is not None, timeout=self.timeout)
        require(claim() == assignment, "REVIEW_CLAIM_REPLAY_CHANGED")
        workspace = _get(self.reviewer, REVIEW_PATH)
        attempt_id = assignment["attempt_id"]
        require(workspace["attempt_id"] == attempt_id
                and workspace["attempt"]["demand_id"] == demand_id
                and workspace["attempt"]["status"] == "OPEN", "UNRELATED_REVIEW_ASSIGNMENT")
        if recovered:
            require(attempt_id == recovered["attempt_id"]
                    and workspace["match_run_id"] == recovered["match_run_id"]
                    and assignment["assignment_id"] != recovered["old_review_assignment_id"], "RECOVERED_REVIEW_NOT_NEW_ASSIGNMENT")
        self.pending_review_claim = None
        require(workspace["run"]["status"] == "COMPLETED", "MATCH_RUN_NOT_COMPLETED")
        require(workspace["run"]["candidate_count"] == 1 and workspace["run"]["eligible_count"] == 1
                and workspace["run"]["excluded_count"] == 0, "SYNTHETIC_CREATOR_NOT_ELIGIBLE")
        require(len(workspace["eligible_candidates"]) == 1, "ELIGIBLE_CANDIDATE_MISSING")
        _no_private_fields(workspace)
        candidate = workspace["eligible_candidates"][0]
        require(self.profile is not None and candidate["profile_id"] == self.profile["object_id"], "CANDIDATE_PROFILE_MISMATCH")
        # Owner must explicitly claim resource-level candidate-selector authority.
        unassigned = self.owner.client.request(method="GET", path=f"/v1/organizations/{self.organization_id}/matching-attempts/{attempt_id}/selection", headers=base._app_headers(self.owner))
        require(unassigned.status == 404, "SELECTOR_ASSIGNMENT_BOUNDARY_MISSING")
        selector = _write(self.owner, "/v1/matching/candidate-selector-assignments/claim", {"demand_id": demand_id}, status=201)
        require(selector["attempt_id"] == attempt_id and selector["status"] == "ACTIVE", "SELECTOR_ASSIGNMENT_INVALID")
        if recovered:
            require(selector["selection_id"] == recovered["selection_id"]
                    and selector["candidate_selector_assignment_id"] != recovered["old_selector_assignment_id"], "RECOVERED_SELECTOR_NOT_NEW_ASSIGNMENT")
        attempts = self.attempts(demand_id)
        require(len(attempts) == 1 and attempts[0]["attempt_id"] == attempt_id
                and attempts[0]["status"] == "OPEN", "ASSIGNED_ATTEMPT_NOT_VISIBLE")
        self.stage(f"{label}_CREATE_PUBLISH_INVITATION")
        expires_at = (datetime.now(timezone.utc) + timedelta(days=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if recovered:
            existing = [item for item in workspace["invitations"] if item["invitation_id"] == recovered["invitation_id"]]
            require(len(existing) == 1 and existing[0]["status"] == "CREATED"
                    and existing[0]["creator_user_id"] == candidate["creator_user_id"]
                    and existing[0]["snapshot_sha256"] == recovered["snapshot_sha256"], "COMMITTED_INVITATION_CHANGED")
            invitation = existing[0]
        else:
            invitation = _write(
                self.reviewer, f"/v1/operations/match-runs/{workspace['match_run_id']}/invitations",
                {"match_run_id": workspace["match_run_id"], "creator_user_id": candidate["creator_user_id"], "expires_at": expires_at},
                version=workspace["run"]["aggregate_version"], status=201,
            )
        require(invitation["status"] == "CREATED", "INVITATION_NOT_CREATED")
        published = _write(self.reviewer, f"/v1/operations/matching-invitations/{invitation['invitation_id']}/publish",
                           {"snapshot_sha256": invitation["snapshot_sha256"]}, version=invitation["aggregate_version"])
        require(published["status"] == "SENT", "INVITATION_NOT_SENT")
        return self.receive_and_release(demand_id, invitation, selector, assignment, workspace)

    def resume_sent_invitation(self, demand_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self.stage("SELECTED_RESUME_SENT_INVITATION")
        known = self.recovered_sent_invitation
        require(known is not None and known["demand_id"] == demand_id, "SENT_RECOVERY_TARGET_INVALID")
        response = self.reviewer.client.request(method="GET", path=REVIEW_PATH, headers=base._app_headers(self.reviewer))
        if response.status == 404:
            # Assignment expiry is resolved only by another explicit, normal
            # claim under this current session; no old assignment is restored.
            _write(self.reviewer, "/v1/app/matching-review/queue/claim", {}, status=201)
            workspace = _get(self.reviewer, REVIEW_PATH)
        else:
            workspace = _payload(response)
        require(workspace["attempt_id"] == known["attempt_id"]
                and workspace["match_run_id"] == known["match_run_id"]
                and workspace["attempt"]["demand_id"] == demand_id
                and workspace["attempt"]["status"] == "OPEN", "SENT_RECOVERY_REVIEW_CHANGED")
        require(workspace["run"]["status"] == "COMPLETED"
                and (workspace["run"]["candidate_count"], workspace["run"]["eligible_count"], workspace["run"]["excluded_count"]) == (1, 1, 0), "SENT_RECOVERY_RUN_CHANGED")
        _no_private_fields(workspace)
        selection_path = f"/v1/organizations/{self.organization_id}/selections/{known['selection_id']}"
        response = self.owner.client.request(method="GET", path=selection_path, headers=base._app_headers(self.owner))
        if response.status == 404:
            selector = _write(self.owner, "/v1/matching/candidate-selector-assignments/claim", {"demand_id": demand_id}, status=201)
        else:
            selector = _payload(response)
        require(selector["attempt_id"] == known["attempt_id"] and selector["selection_id"] == known["selection_id"], "SENT_RECOVERY_SELECTION_CHANGED")
        invitations = [item for item in workspace["invitations"] if item["invitation_id"] == known["invitation_id"]]
        require(len(invitations) == 1 and invitations[0]["status"] == "SENT"
                and invitations[0]["snapshot_sha256"] == known["snapshot_sha256"]
                and invitations[0]["aggregate_version"] == 2, "SENT_RECOVERY_INVITATION_CHANGED")
        return self.receive_and_release(demand_id, invitations[0], selector, workspace, workspace)

    def receive_and_release(self, demand_id: str, invitation: Mapping[str, Any],
                            selector: dict[str, Any], assignment: Mapping[str, Any],
                            workspace: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        attempt_id = selector["attempt_id"]
        received = _get(self.creator, f"/v1/me/matching-invitations/{invitation['invitation_id']}")
        _no_private_fields(received, recipient=True)
        require(received["status"] == "SENT" and received["response_status"] is None, "INVITATION_NOT_RECEIVED")
        disclosure = received["disclosure"]
        require(disclosure["demand_id"] == demand_id and disclosure["attempt_id"] == attempt_id
                and disclosure["profile_id"] == self.profile["object_id"], "INVITATION_DISCLOSURE_MISMATCH")
        require(disclosure["offer"]["minimum_amount_minor"] == 0 and disclosure["offer"]["maximum_amount_minor"] == 0, "NONZERO_SANDBOX_OFFER")
        unauthorized = self.owner.client.request(method="GET", path=f"/v1/me/matching-invitations/{invitation['invitation_id']}", headers=base._app_headers(self.owner))
        require(unauthorized.status == 400 and unauthorized.json().get("code") == "INVALID_MATCHING_REQUEST",
                "RECIPIENT_WORKSPACE_ROUTE_BOUNDARY_MISSING")
        # The BFF rejects an organization workspace on a personal route. A
        # syntactically valid recipient workspace still grants no authority to
        # the authenticated Owner session, even with the known invitation ID.
        unauthorized = self.owner.client.request(
            method="GET", path=f"/v1/me/matching-invitations/{invitation['invitation_id']}",
            headers={**base._app_headers(self.owner), "X-Workspace-Id": self.creator.workspace_id},
        )
        require(unauthorized.status == 404, "RECIPIENT_BOUNDARY_MISSING")
        # Releasing is a real capability lifecycle operation; claim the same
        # unfinished attempt again to prove it can be resumed safely.
        released = _write(self.reviewer, "/v1/app/matching-review/assignment/release", {}, version=workspace["aggregate_version"])
        require(released["status"] == "REVOKED", "REVIEW_ASSIGNMENT_NOT_RELEASED")
        hidden = self.reviewer.client.request(method="GET", path=REVIEW_PATH, headers=base._app_headers(self.reviewer))
        require(hidden.status == 404, "RELEASED_REVIEW_STILL_VISIBLE")
        reclaimed = _write(self.reviewer, "/v1/app/matching-review/queue/claim", {}, status=201)
        require(reclaimed["attempt_id"] == attempt_id and reclaimed["assignment_id"] != assignment["assignment_id"], "REVIEW_ASSIGNMENT_NOT_RECLAIMED")
        resumed = _get(self.reviewer, REVIEW_PATH)
        require(resumed["attempt_id"] == attempt_id
                and any(item["invitation_id"] == invitation["invitation_id"] and item["status"] == "SENT"
                        for item in resumed["invitations"]), "REVIEW_INVITATION_NOT_RESUMED")
        finished = _write(self.reviewer, "/v1/app/matching-review/assignment/release", {}, version=resumed["aggregate_version"])
        require(finished["status"] == "REVOKED", "FINISHED_REVIEW_NOT_RELEASED")
        return received, selector

    def response(self, invitation: Mapping[str, Any], action: str) -> dict[str, Any]:
        body: dict[str, Any] = {"snapshot_sha256": invitation["snapshot_sha256"]}
        if action != "accept":
            body.update(reason_code="RECIPIENT_DECLINED" if action == "decline" else "RECIPIENT_WITHDREW", note=None)
        result = _write(self.creator, f"/v1/me/matching-invitations/{invitation['invitation_id']}/{action}", body, version=invitation["aggregate_version"])
        expected = {"accept": "ACCEPTED", "decline": "DECLINED", "withdraw": "WITHDRAWN"}[action]
        require(result["status"] == expected and result["response_status"] == expected, "INVITATION_RESPONSE_INVALID")
        _no_private_fields(result, recipient=True)
        return result

    def complete_branch(self, label: str, *, response: str,
                        funded: Mapping[str, Any] | None = None) -> None:
        funded = self.funded_demand(label) if funded is None else funded
        demand_id = funded["object_id"]
        invitation, selector = self.invite(demand_id, label)
        self.stage(f"{label}_CREATOR_RESPONSE")
        current = self.response(invitation, "decline" if response == "decline" else "accept")
        if response == "withdraw":
            current = self.response(current, "withdraw")
        selection = self.selection(selector["attempt_id"], selector["selection_id"])
        accepted = selection["accepted_invitations"]
        require([item["invitation_id"] for item in accepted] == ([invitation["invitation_id"]] if response == "accept" else []), "ACCEPTED_SET_INVALID")
        self.stage(f"{label}_OWNER_SELECTION")
        choose = response == "accept"
        body = {
            "current_invitation_set_sha256": selection["current_invitation_set_sha256"],
            "candidate_selector_assignment_id": selection["candidate_selector_assignment_id"],
            "candidate_selector_assignment_version": selection["candidate_selector_assignment_version"],
        }
        if choose:
            body.update(invitation_id=invitation["invitation_id"], selection_basis_code="CAPABILITY_SUMMARY_FIT")
        else:
            body.update(reason_code="OWNER_CLOSED")
        progression = ("PENDING_CHOICE", "SELECTED") if choose else ("PENDING_CLOSE", "CLOSED_NO_SELECTION")
        command = _write(self.owner, f"/v1/organizations/{self.organization_id}/selections/{selection['selection_id']}/{'choose' if choose else 'close'}", body, version=selection["aggregate_version"], progression=progression)
        require(command["status"] in progression, "SELECTION_INTENT_NOT_QUEUED")
        self.finish_branch(label, funded=funded, invitation=invitation, selector=selector,
                           current=current, choose=choose)

    def finish_branch(self, label: str, *, funded: Mapping[str, Any],
                      invitation: Mapping[str, Any], selector: Mapping[str, Any],
                      current: Mapping[str, Any], choose: bool) -> None:
        demand_id = funded["object_id"]
        self.stage(f"{label}_COORDINATOR_COMPLETION")
        terminal_status = "SELECTED" if choose else "CLOSED_NO_SELECTION"
        terminal = _wait(lambda: self.selection(selector["attempt_id"], selector["selection_id"]), lambda value: value["status"] == terminal_status, timeout=self.timeout)
        terminal_demand = self.demand(demand_id)
        require(terminal_demand["status"] == ("MATCHED" if choose else "NO_MATCH"), "DEMAND_COMPLETION_NOT_ATOMIC")
        require(self.attempts(demand_id) == [], "COMPLETED_ASSIGNMENT_LISTED_AS_ACTIVE")
        require(terminal["chosen_invitation_id"] == (invitation["invitation_id"] if choose else None), "CHOSEN_INVITATION_INVALID")
        active_only = self.owner.client.request(method="GET", path=f"/v1/organizations/{self.organization_id}/matching-attempts/{selector['attempt_id']}/selection", headers=base._app_headers(self.owner))
        require(active_only.status == 404, "COMPLETED_ASSIGNMENT_STILL_ACTIVE")
        # The role retains the immutable terminal read after its active selector
        # assignment is completed. Reviewer work was explicitly released before
        # waiting for participant decisions and independent coordination.
        self.branches.append({
            "branch": label, "demand_id": demand_id,
            "demand_version_id": funded["current_version"]["version_id"],
            "attempt_id": selector["attempt_id"], "selection_id": selector["selection_id"],
            "invitation_id": invitation["invitation_id"], "invitation_status": current["status"],
            "selection_status": terminal_status, "demand_status": terminal_demand["status"],
            "create_exact_replay_verified": (not (label == "SELECTED" and (self.recovered_invitation or self.recovered_sent_invitation))
                or bool(self.recovered_sent_invitation and self.recovered_sent_invitation.get("create_exact_replay_verified"))),
        })
        if label == "SELECTED" and (self.recovered_invitation or self.recovered_sent_invitation):
            known = self.recovered_invitation or self.recovered_sent_invitation
            self.branches[-1]["creation_recovery"] = ("KNOWN_SENT_COMMIT_CURRENT_AUTHORITY" if self.recovered_sent_invitation
                                                     else "KNOWN_COMMIT_NEW_EXPLICIT_ASSIGNMENTS")
            if "original_exact_replay_failure" in known:
                self.branches[-1]["original_create_replay_failure"] = known["original_exact_replay_failure"]
        print(json.dumps({"status": "MATCHING_BRANCH_HTTP_GREEN", **self.branches[-1]}), flush=True)

    def zero_candidates(self) -> None:
        self.stage("ZERO_CANDIDATES_PAUSE_PROFILE")
        require(self.profile is not None, "PROFILE_MISSING")
        self.profile = base._write_editor(
            self.creator, method="POST", path=f"/v1/app/profiles/{self.profile['object_id']}/pause",
            body={"reason_code": "TEMPORARY_UNAVAILABILITY"}, if_match=self.profile["etag"],
            expected_status=200, resource_type="CREATOR_PROFILE",
        )
        require(self.profile["status"] == "PAUSED", "PROFILE_NOT_PAUSED")
        try:
            funded = self.funded_demand("ZERO_CANDIDATES")
            self.stage("ZERO_CANDIDATES_SYSTEM_CLOSE")
            demand_id = funded["object_id"]
            terminal = _wait(lambda: self.demand(demand_id), lambda value: value["status"] == "NO_MATCH", timeout=self.timeout)
            attempts = self.attempts(demand_id)
            require(attempts == [], "UNASSIGNED_EMPTY_CAPTURE_VISIBLE")
            self.branches.append({"branch": "ZERO_CANDIDATES", "demand_id": demand_id,
                "demand_version_id": funded["current_version"]["version_id"], "attempt_id": None,
                "selection_id": None, "invitation_id": None, "invitation_status": None,
                "selection_status": None, "demand_status": terminal["status"]})
            print(json.dumps({"status": "MATCHING_BRANCH_HTTP_GREEN", **self.branches[-1]}), flush=True)
        finally:
            self.profile = base._write_editor(
                self.creator, method="POST", path=f"/v1/app/profiles/{self.profile['object_id']}/resume",
                body={}, if_match=self.profile["etag"], expected_status=200, resource_type="CREATOR_PROFILE",
            )
            require(self.profile["status"] == "ACTIVE", "PROFILE_NOT_RESUMED")

    def run(self, *, resume_target: Mapping[str, Any] | None = None,
            resume_pending_choice: bool = False) -> dict[str, Any]:
        if resume_target is None:
            self.publish_zero_fee_profile()
            self.complete_branch("SELECTED", response="accept")
        else:
            self.stage("RESTORE_KNOWN_CREATED_INVITATION" if self.recovered_invitation
                       else "RESTORE_REVIEW_CLAIM" if self.pending_review_claim else "RESTORE_BEFORE_MATCHING")
            require(set(resume_target) == {"organization_id", "demand_id", "expected_version", "request_id"}, "RESUME_TARGET_INVALID")
            require(resume_target["organization_id"] == self.organization_id, "RESUME_ORGANIZATION_CHANGED")
            for field in ("organization_id", "demand_id", "request_id"):
                base._canonical_uuid(resume_target[field])
            require(type(resume_target["expected_version"]) is int and resume_target["expected_version"] > 0, "RESUME_TARGET_INVALID")
            resumed = self.demand(resume_target["demand_id"])
            require((resumed["status"] == "MATCHING" and resumed["revision"] == resume_target["expected_version"] + 1)
                    or (resume_pending_choice and resumed["status"] == "MATCHED"
                        and resumed["revision"] == resume_target["expected_version"] + 2), "RESUME_DEMAND_CHANGED")
            attempts = self.attempts(resume_target["demand_id"])
            require(len(attempts) <= 1 and all(item["status"] == "OPEN" for item in attempts), "RESUME_ATTEMPT_CHANGED")
            if attempts and self.recovered_sent_invitation is None:
                selector = self.owner.client.request(method="GET", path=f"/v1/organizations/{self.organization_id}/matching-attempts/{attempts[0]['attempt_id']}/selection", headers=base._app_headers(self.owner))
                require(selector.status == 404, "RESUME_SELECTOR_ALREADY_ASSIGNED")
            if self.pending_review_claim is None and self.recovered_sent_invitation is None:
                review = self.reviewer.client.request(method="GET", path=REVIEW_PATH, headers=base._app_headers(self.reviewer))
                require(review.status == 404, "RESUME_REVIEW_ALREADY_ASSIGNED")
            existing = base._list_resources(self.creator, path="/v1/app/profiles", resource_type="CREATOR_PROFILE")
            require(len(existing) == 1, "RESUME_PROFILE_AMBIGUOUS")
            self.profile = base._get_resource(self.creator, f"/v1/app/profiles/{existing[0]['object_id']}", resource_type="CREATOR_PROFILE")
            require(self.profile["status"] == "ACTIVE", "RESUME_PROFILE_NOT_ACTIVE")
            if resume_pending_choice:
                known = self.recovered_sent_invitation
                require(known is not None, "PENDING_CHOICE_RECOVERY_NOT_CONFIRMED")
                invitation = _get(self.creator, f"/v1/me/matching-invitations/{known['invitation_id']}")
                selector = self.selection(known["attempt_id"], known["selection_id"])
                require(invitation["status"] == invitation["response_status"] == "ACCEPTED"
                        and invitation["snapshot_sha256"] == known["snapshot_sha256"]
                        and selector["status"] in {"PENDING_CHOICE", "SELECTED"}
                        and selector["chosen_invitation_id"] == known["invitation_id"], "PENDING_CHOICE_RECOVERY_CHANGED")
                self.finish_branch("SELECTED", funded=resumed, invitation=invitation,
                                   selector=selector, current=invitation, choose=True)
            else:
                self.complete_branch("SELECTED", response="accept", funded=resumed)
        self.complete_branch("DECLINED_OWNER_CLOSE", response="decline")
        self.complete_branch("WITHDRAWN_OWNER_CLOSE", response="withdraw")
        self.zero_candidates()
        return {"schema": SCHEMA, "status": "MATCHING_HTTP_E2E_GREEN",
                "organization_id": self.organization_id, "profile_id": self.profile["object_id"],
                "branches": self.branches, "scope": "MATCHING_THROUGH_DEMAND_MATCHED_OR_NO_MATCH"}

    def verify(self, state: Mapping[str, Any], *, fresh_owner: base.RoleSession) -> dict[str, Any]:
        require(state["schema"] == SCHEMA and state["organization_id"] == self.organization_id, "RESTART_STATE_INVALID")
        require(state["status"] == "MATCHING_HTTP_E2E_GREEN"
                and [branch["branch"] for branch in state["branches"]] == list(BRANCH_EXPECTATIONS), "RESTART_BRANCH_SET_INVALID")
        if "prior_no_match" in state:
            prior = state["prior_no_match"]
            require(self.prior_no_match({"organization_id": self.organization_id, "demand_id": prior["demand_id"]}) == prior, "PRIOR_REQUEST_CHANGED")
        profile = base._get_resource(self.creator, f"/v1/app/profiles/{state['profile_id']}", resource_type="CREATOR_PROFILE")
        require(profile["status"] == "ACTIVE", "RESTART_PROFILE_NOT_ACTIVE")
        for branch in state["branches"]:
            require((branch["demand_status"], branch["selection_status"], branch["invitation_status"])
                    == BRANCH_EXPECTATIONS[branch["branch"]], "RESTART_BRANCH_EXPECTATION_INVALID")
            require((branch["selection_id"] is None and branch["invitation_id"] is None)
                    == (branch["branch"] == "ZERO_CANDIDATES"), "RESTART_BRANCH_IDENTITIES_INVALID")
            self.stage(f"RESTART_{branch['branch']}")
            require(self.demand(branch["demand_id"])["status"] == branch["demand_status"], "RESTART_DEMAND_CHANGED")
            require(self.attempts(branch["demand_id"]) == [], "RESTART_COMPLETED_ASSIGNMENT_LISTED")
            if branch["selection_id"] is not None:
                selection = self.selection(branch["attempt_id"], branch["selection_id"])
                require(selection["selection_id"] == branch["selection_id"] and selection["status"] == branch["selection_status"], "RESTART_SELECTION_CHANGED")
                other_session = fresh_owner.client.request(method="GET", path=f"/v1/organizations/{self.organization_id}/selections/{branch['selection_id']}", headers=base._app_headers(fresh_owner))
                require(other_session.status == 404, "SELECTOR_SESSION_BOUNDARY_MISSING")
                invitation = _get(self.creator, f"/v1/me/matching-invitations/{branch['invitation_id']}")
                require(invitation["status"] == branch["invitation_status"], "RESTART_INVITATION_CHANGED")
        return {"schema": SCHEMA, "status": "MATCHING_HTTP_RESTART_GREEN", "branches_verified": len(state["branches"])}


def main() -> int:
    # Curl response files inherit this mask as well as explicitly-created
    # request files; every new private ledger entry stays owner-readable only.
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "resume-before-matching", "resume-review-claim", "resume-created-invitation", "resume-sent-invitation", "resume-pending-choice", "verify-restart"))
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--resume-ledger", type=Path)
    parser.add_argument("--resume-with-new-sessions", action="store_true",
                        help="Only recover a checkpoint made before any Matching review or selector claim; retain the exact Demand target")
    parser.add_argument("--prior-no-match-target", type=Path,
                        help="Verify an earlier exact target naturally reached NO_MATCH; keep it separate from the four new branches")
    args = parser.parse_args()
    require(5 <= args.timeout <= 600, "TIMEOUT_INVALID")
    journey = None
    private_ledger: Path | None = None
    resume_ledger: Path | None = None
    restart_checkpoint: Path | None = None
    successful = False
    expired_source_verified = False
    created_recovery = None
    sent_recovery = None
    try:
        ca_file = base._ca_file(args.ca_file)
        state_file = args.state_file.absolute()
        resume_target = None
        state = None
        session_source = None
        require((args.resume_ledger is not None) == (args.command in {"resume-before-matching", "resume-review-claim", "resume-created-invitation", "resume-sent-invitation", "resume-pending-choice"}), "RESUME_ARGUMENT_INVALID")
        require(not args.resume_with_new_sessions or args.command in {"resume-before-matching", "resume-sent-invitation"}, "RESUME_ARGUMENT_INVALID")
        require(args.prior_no_match_target is None or args.command != "verify-restart", "PRIOR_TARGET_ARGUMENT_INVALID")
        if args.command == "run":
            base._new_absolute_output(state_file)
            request_directory = state_file.with_suffix(".requests")
            request_directory.mkdir(mode=0o700)
        elif args.command in {"resume-before-matching", "resume-review-claim", "resume-created-invitation", "resume-sent-invitation", "resume-pending-choice"}:
            base._new_absolute_output(state_file)
            resume_ledger = _private_directory(args.resume_ledger.absolute(), parent=state_file.parent, prefix="matching-http-private.")
            checkpoint_state = json.loads(base._private_absolute_file(resume_ledger / "matching-run-checkpoint.json").read_text())
            expected_stage = ("SELECTED_COORDINATOR_COMPLETION" if args.command == "resume-pending-choice"
                              else "SELECTED_CREATE_PUBLISH_INVITATION" if args.command in {"resume-created-invitation", "resume-sent-invitation"}
                              else "SELECTED_MATCHING_REVIEW_ASSIGNMENT" if args.command == "resume-review-claim"
                              else "SELECTED_MATCHING_WORKER")
            require(checkpoint_state == {"stage": expected_stage, "branches_completed": 0}
                    or (args.command == "resume-sent-invitation" and checkpoint_state == {"stage": "SELECTED_RESUME_SENT_INVITATION", "branches_completed": 0}), "RESUME_STAGE_INVALID")
            session_source = None if args.resume_with_new_sessions or args.command == "resume-created-invitation" else resume_ledger
            request_directory = state_file.with_suffix(".requests")
            require(request_directory == request_directory.resolve(strict=True)
                    and {item.name for item in request_directory.iterdir()} == {"selected.json"}, "RESUME_STAGE_INVALID")
            target_file = base._private_absolute_file(request_directory / "selected.json")
            resume_target = json.loads(target_file.read_text())
            if args.command == "resume-created-invitation":
                created_recovery = _known_created_invitation(resume_ledger, resume_target)
                require(all(base._parse_utc_timestamp(created_recovery[key])[0] <= datetime.now(timezone.utc)
                            for key in ("review_assignment_expires_at", "selector_assignment_expires_at")), "ORIGINAL_ASSIGNMENT_NOT_EXPIRED")
            elif args.command == "resume-sent-invitation":
                sent_recovery = _known_sent_invitation(resume_ledger, resume_target)
            elif args.command == "resume-pending-choice":
                sent_recovery = _known_pending_choice(resume_ledger, resume_target)
        else:
            state_file = base._private_absolute_file(state_file)
            request_directory = None
            state = json.loads(state_file.read_text())
            checkpoint_name = state["restart_session_checkpoint"]
            require(isinstance(checkpoint_name, str) and base.re.fullmatch(r"matching-http-checkpoint\.[a-z0-9_]+", checkpoint_name), "RESTART_CHECKPOINT_INVALID")
            restart_checkpoint = _private_directory(state_file.parent / checkpoint_name, parent=state_file.parent, prefix="matching-http-checkpoint.")
            session_source = restart_checkpoint
        private_ledger = Path(tempfile.mkdtemp(prefix="matching-http-private.", dir=state_file.parent))
        os.chmod(private_ledger, 0o700)
        if created_recovery is not None:
            base._write_new(private_ledger / "created-invitation-recovery.json", (json.dumps(created_recovery) + "\n").encode(), mode=0o600)
            _require_expired_sessions(private_ledger, resume_ledger, ca_file)
            expired_source_verified = True
        if sent_recovery is not None:
            base._write_new(private_ledger / "created-invitation-recovery.json", (json.dumps(sent_recovery) + "\n").encode(), mode=0o600)
            if args.resume_with_new_sessions:
                _require_expired_sessions(private_ledger, resume_ledger, ca_file)
                expired_source_verified = True
        sessions = {}
        for code in ACCOUNTS:
            print(json.dumps({"stage": ("RESTORE_" if session_source else "LOGIN_") + code.upper(), "status": "RUNNING"}), flush=True)
            sessions[code] = (_restore_session(code, private_ledger, session_source, ca_file)
                              if session_source else _login(code, private_ledger, ca_file))
        journey = Journey(sessions, timeout=args.timeout, request_directory=request_directory)
        journey.recovered_invitation = created_recovery
        journey.recovered_sent_invitation = sent_recovery
        if args.command == "resume-review-claim":
            journey.pending_review_claim = {"method": "POST", "path": "/v1/app/matching-review/queue/claim",
                                           "body": {}, "headers": _review_claim_headers(resume_ledger, sessions["operations_reviewer_01"])}
        if args.command == "verify-restart":
            fresh_owner = _login("demand_owner_01", base._role_root(private_ledger, "fresh_owner"), ca_file)
            result = journey.verify(state, fresh_owner=fresh_owner)
        else:
            prior_no_match = (journey.prior_no_match(json.loads(
                base._private_absolute_file(args.prior_no_match_target.absolute()).read_text()
            )) if args.prior_no_match_target else None)
            result = journey.run(resume_target=resume_target,
                                 resume_pending_choice=args.command == "resume-pending-choice")
            if expired_source_verified:
                result["expired_original_sessions_rejected"] = len(ACCOUNTS)
            if prior_no_match is not None:
                result["prior_no_match"] = prior_no_match
        if args.command != "verify-restart":
            restart_checkpoint = _session_checkpoint(sessions, state_file.parent)
            result["restart_session_checkpoint"] = restart_checkpoint.name
            base._write_new(state_file, (json.dumps(result, indent=2) + "\n").encode("utf-8"), mode=0o600)
        print(json.dumps({"status": result["status"], "branches_verified": len(result["branches"]) if "branches" in result else result["branches_verified"]}), flush=True)
        successful = True
        return 0
    except (CheckError, base.InternalSandboxE2eError, OSError, KeyError, ValueError, TypeError) as error:
        print(json.dumps({"status": "MATCHING_HTTP_E2E_FAILED", "stage": journey.phase if journey else "INPUT_OR_LOGIN",
                          "code": error.code if isinstance(error, CheckError) else "LOCAL_ACCEPTANCE_FAILED",
                          "http_status": error.status if isinstance(error, CheckError) else None}), flush=True)
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"status": "MATCHING_HTTP_E2E_INTERRUPTED",
                          "stage": journey.phase if journey else "INPUT_OR_LOGIN"}), flush=True)
        return 130
    finally:
        # Retain a private failed-run ledger so exact commands and the original
        # assigned reviewer session can be recovered without database edits.
        # Successful runs erase the request ledger; only a minimal cookie
        # checkpoint remains until restart verification. No summary has cookies.
        if private_ledger is not None:
            if successful:
                shutil.rmtree(private_ledger)
                if resume_ledger is not None and resume_ledger.exists():
                    shutil.rmtree(resume_ledger)
                if args.command == "verify-restart" and restart_checkpoint is not None:
                    shutil.rmtree(restart_checkpoint)
            else:
                if journey is not None:
                    base._write_new(private_ledger / "matching-run-checkpoint.json", (json.dumps({"stage": journey.phase, "branches_completed": len(journey.branches)}) + "\n").encode("utf-8"), mode=0o600)
                    if journey.pending_review_claim is not None:
                        base._write_new(private_ledger / "pending-review-claim.json", (json.dumps(journey.pending_review_claim) + "\n").encode("utf-8"), mode=0o600)
                print(json.dumps({"private_failed_run_ledger": str(private_ledger)}), flush=True)
            if expired_source_verified and resume_ledger is not None and resume_ledger.exists():
                # The new private ledger contains only new-session recovery
                # authority and the public known-commit facts. Retire old secrets.
                shutil.rmtree(resume_ledger)


if __name__ == "__main__":
    raise SystemExit(main())
