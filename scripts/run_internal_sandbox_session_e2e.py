#!/usr/bin/env python3
"""Exercise actor-owned Sessions over the existing local synthetic HTTPS stack.

``prepare`` leaves three short-lived cookie checkpoints in a private system
temporary directory. After the operator restarts the stack, ``verify-restart``
uses those exact cookies without logging in, then removes the checkpoints.
Only synthetic Creator and Access Admin accounts are used. Results never
contain session identifiers, cookies, CSRF tokens, or response bodies.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping
from uuid import uuid4

import run_internal_sandbox_e2e as base


_STATE_KIND = "internal-sandbox-session-checkpoint-v1"
_CHECKPOINT_FILES = frozenset({
    "state.json", "ca.pem", "active.cookies", "remote-revoked.cookies",
    "self-revoked.cookies",
})
_SESSION_KEYS = {
    "session_id", "created_at", "last_activity_at", "expires_at",
    "is_current", "device_label", "status",
}


class SessionAcceptanceError(RuntimeError):
    def __init__(self, stage: str) -> None:
        self.stage = stage
        super().__init__(stage)


def _require(condition: bool, stage: str) -> None:
    if not condition:
        raise SessionAcceptanceError(stage)


def _stage(name: str, function: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return function(*args, **kwargs)
    except SessionAcceptanceError as error:
        raise SessionAcceptanceError(f"{name}_{error.stage}") from None
    except Exception:
        raise SessionAcceptanceError(name) from None


def _state_directory(path: Path, *, create: bool) -> Path:
    # Checkpoints cannot be placed in the checkout or a sealed deployment root.
    _require(path.is_absolute() and not path.is_symlink(), "STATE_DIRECTORY")
    parent = path.parent.resolve(strict=True)
    temporary = Path(tempfile.gettempdir()).resolve(strict=True)
    _require(parent == temporary, "STATE_DIRECTORY")
    _require(re.fullmatch(r"desire-session-[a-zA-Z0-9_-]{4,80}", path.name) is not None,
             "STATE_DIRECTORY")
    target = parent / path.name
    if create:
        target.mkdir(mode=0o700)
    info = target.lstat()
    _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == os.getuid(), "STATE_DIRECTORY")
    return target


def _private_bytes(path: Path) -> bytes:
    base._private_absolute_file(path)
    _require(path.stat().st_uid == os.getuid(), "STATE_OWNER")
    data = path.read_bytes()
    _require(0 < len(data) <= 65536, "STATE_SIZE")
    return data


def _cookie(client: base.CurlClient) -> bytes:
    data = _private_bytes(client._cookie_jar)
    _require(b"__Host-ds_session" in data, "SESSION_COOKIE_MISSING")
    return data


def _restore_client(root: Path, ca: Path, cookie: bytes) -> base.CurlClient:
    client = base.CurlClient(root=root, ca_file=ca)
    # CurlClient exclusive-creates this private file before it is restored.
    client._cookie_jar.write_bytes(cookie)
    return client


def _bootstrap(client: base.CurlClient, status: int = 200) -> Mapping[str, Any]:
    response = client.request(method="GET", path="/v1/auth/session")
    _require(response.status == status,
             f"BOOTSTRAP_EXPECTED_{status}_GOT_{response.status}")
    value = response.json() if status == 200 else {}
    if status == 200:
        base._exact_keys(value, {"session", "user_status", "csrf_token"})
        _require(value["user_status"] == "ACTIVE"
                 and base._CSRF.fullmatch(str(value["csrf_token"])) is not None,
                 "BOOTSTRAP_IDENTITY")
        session = value.get("session")
        _require(isinstance(session, dict), "BOOTSTRAP_SHAPE")
        base._canonical_uuid(session.get("session_id"))
    return value


def _sessions(client: base.CurlClient, current_id: str) -> list[Mapping[str, Any]]:
    items: list[Mapping[str, Any]] = []
    cursor = None
    seen_cursors: set[str] = set()
    for _ in range(100):
        query = {"limit": "1"}
        if cursor is not None:
            query["cursor"] = cursor
        response = client.request(method="GET", path="/v1/me/sessions", query=query)
        base._expect_status(response, 200)
        value = base._exact_keys(response.json(), {"items", "page"})
        page = base._exact_keys(value["page"], {"next_cursor"})
        _require(isinstance(value["items"], list) and len(value["items"]) <= 1,
                 "SESSION_PAGE")
        for item in value["items"]:
            base._exact_keys(item, _SESSION_KEYS)
            base._canonical_uuid(item["session_id"])
            _require(type(item["is_current"]) is bool
                     and item["is_current"] == (item["session_id"] == current_id)
                     and item["status"] in {"ACTIVE", "REVOKED", "EXPIRED"},
                     "SESSION_OWNER_BINDING")
            for field in ("created_at", "last_activity_at", "expires_at"):
                base._utc_timestamp(item[field])
            _require(isinstance(item["device_label"], str)
                     and 1 <= len(item["device_label"]) <= 80, "SESSION_LABEL")
            items.append(item)
        cursor = page["next_cursor"]
        if cursor is None:
            break
        _require(isinstance(cursor, str) and 1 <= len(cursor) <= 2048
                 and cursor not in seen_cursors and bool(value["items"]),
                 "SESSION_CURSOR")
        seen_cursors.add(cursor)
    else:
        raise SessionAcceptanceError("SESSION_PAGE_LIMIT")
    ids = [item["session_id"] for item in items]
    current = [item for item in items if item["is_current"]]
    _require(len(ids) == len(set(ids)) and len(current) == 1
             and current[0]["status"] == "ACTIVE", "SESSION_LIST_BINDING")
    return items


def _delete_session(
    client: base.CurlClient, *, bootstrap: Mapping[str, Any], target: str,
    key: str, expected_status: int,
) -> base.HttpResult:
    """Add the one DELETE operation unsupported by the shared CurlClient."""
    base._canonical_uuid(target)
    current_id = base._canonical_uuid(bootstrap["session"]["session_id"])
    csrf = bootstrap["csrf_token"]
    _require(base._CSRF.fullmatch(str(csrf)) is not None, "DELETE_CSRF")
    _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,127}", key) is not None,
             "DELETE_KEY")
    headers_path = client._new_path("session-delete-headers")
    response_path = client._new_path("session-delete-response")
    response_headers = client._new_path("session-delete-response-headers")
    headers = (
        "Accept: application/json\n"
        f"Origin: {base.PILOT_ORIGIN}\n"
        f"X-CSRF-Token: {csrf}\n"
        f"X-Bootstrap-Session-Id: {current_id}\n"
        f"Idempotency-Key: {key}\n"
    )
    base._write_new(headers_path, headers.encode("ascii"), mode=0o600)
    completed = subprocess.run([
        client._curl, "--disable", "--silent", "--show-error", "--proto", "=https",
        "--noproxy", "*", "--cacert", str(client._ca_file), "--resolve",
        f"pilot.example.test:443:{base.RESOLVE_ADDRESS}",
        "--cookie", str(client._cookie_jar), "--cookie-jar", str(client._cookie_jar),
        "--max-time", "20", "--request", "DELETE", "--header", f"@{headers_path}",
        "--output", str(response_path), "--dump-header", str(response_headers),
        "--write-out", "%{http_code}",
        f"{base.PILOT_ORIGIN}/v1/me/sessions/{target}",
    ], check=False, capture_output=True, text=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath})
    _require(completed.returncode == 0
             and re.fullmatch(r"[1-5][0-9]{2}", completed.stdout) is not None,
             "DELETE_TRANSPORT")
    body = response_path.read_bytes()
    raw_headers = response_headers.read_bytes()
    _require(len(body) <= 1048576 and len(raw_headers) <= 65536, "DELETE_RESPONSE_SIZE")
    result = base.HttpResult(int(completed.stdout), base._parse_last_headers(raw_headers), body)
    _require(result.status == expected_status,
             f"DELETE_EXPECTED_{expected_status}_GOT_{result.status}")
    if expected_status == 204:
        _require(result.body == b"" and "etag" not in result.headers, "DELETE_RESPONSE")
    elif expected_status == 404:
        value = result.json()
        _require(isinstance(value, dict) and value.get("code")
                 == "RESOURCE_NOT_FOUND", "FOREIGN_SESSION_ERROR")
    elif expected_status == 401:
        value = result.json()
        _require(isinstance(value, dict) and value.get("code")
                 == "AUTHENTICATION_REQUIRED", "TERMINAL_SESSION_ERROR")
    return result


def _ids(items: list[Mapping[str, Any]]) -> set[str]:
    return {item["session_id"] for item in items}


def _terminal_or_absent(items: list[Mapping[str, Any]], target: str) -> bool:
    return all(item["status"] in {"REVOKED", "EXPIRED"}
               and item["is_current"] is False
               for item in items if item["session_id"] == target)


def prepare(*, ca_file: Path, state_dir: Path) -> Mapping[str, Any]:
    ca = base._ca_file(ca_file)
    root = _state_directory(state_dir, create=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    try:
        one = _stage("LOGIN_CREATOR_ONE", base._login, account_code="creator_01",
                     root=base._role_root(work, "creator-one"), ca_file=ca)
        two = _stage("LOGIN_CREATOR_TWO", base._login, account_code="creator_01",
                     root=base._role_root(work, "creator-two"), ca_file=ca)
        admin = _stage("LOGIN_OTHER_ACCOUNT", base._login, account_code="access_admin_01",
                       root=base._role_root(work, "access-admin"), ca_file=ca)
        first = _stage("BOOTSTRAP_ONE", _bootstrap, one.client)
        second = _stage("BOOTSTRAP_TWO", _bootstrap, two.client)
        foreign = _stage("BOOTSTRAP_FOREIGN", _bootstrap, admin.client)
        one_id, two_id, foreign_id = (
            value["session"]["session_id"] for value in (first, second, foreign)
        )
        _require(len({one_id, two_id, foreign_id}) == 3, "DISTINCT_SESSIONS")
        creator_user = base._get_json(one.client, "/v1/me")["user_id"]
        _require(base._get_json(two.client, "/v1/me")["user_id"] == creator_user
                 and base._get_json(admin.client, "/v1/me")["user_id"] != creator_user,
                 "ACCOUNT_IDENTITY")
        first_list = _stage("LIST_CREATOR_ONE", _sessions, one.client, one_id)
        second_list = _stage("LIST_CREATOR_TWO", _sessions, two.client, two_id)
        foreign_list = _stage("LIST_FOREIGN", _sessions, admin.client, foreign_id)
        _require({one_id, two_id} <= _ids(first_list)
                 and {one_id, two_id} <= _ids(second_list)
                 and foreign_id not in _ids(first_list)
                 and not {one_id, two_id}.intersection(_ids(foreign_list)), "LIST_ISOLATION")
        for client, bootstrap, target in (
            (one.client, first, foreign_id), (admin.client, foreign, one_id),
        ):
            _stage("FOREIGN_TARGET_REJECTED", _delete_session, client,
                   bootstrap=bootstrap, target=target, key=f"session-denied-{uuid4()}",
                   expected_status=404)
        _stage("FOREIGN_TARGET_UNCHANGED", _bootstrap, admin.client)
        remote_cookie = _cookie(two.client)
        key = f"session-remote-{uuid4()}"
        for _ in range(2):
            _stage("REMOTE_REVOKE_REPLAY", _delete_session, one.client,
                   bootstrap=first, target=two_id, key=key, expected_status=204)
        _stage("REMOTE_COOKIE_REJECTED", _bootstrap, two.client, 401)
        after = _stage("LIST_AFTER_REMOTE_REVOKE", _sessions, one.client, one_id)
        _require(_terminal_or_absent(after, two_id), "REMOTE_REVOKE_POSTCONDITION")
        _require(_bootstrap(one.client)["session"]["session_id"] == one_id,
                 "CURRENT_SESSION_PRESERVED")
        self_cookie = _cookie(admin.client)
        self_key = f"session-self-{uuid4()}"
        _stage("SELF_REVOKE", _delete_session, admin.client, bootstrap=foreign,
               target=foreign_id, key=self_key, expected_status=204)
        replay = _restore_client(base._role_root(work, "self-replay"), ca, self_cookie)
        _stage("SELF_REVOKE_REPLAY", _delete_session, replay, bootstrap=foreign,
               target=foreign_id, key=self_key, expected_status=401)
        _stage("SELF_COOKIE_REJECTED", _bootstrap, replay, 401)
        now = datetime.now(timezone.utc)
        state = {
            "kind": _STATE_KIND,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=2)).isoformat(),
            "active_session_id": one_id,
            "active_csrf_token": first["csrf_token"],
            "revoked_session_id": two_id,
        }
        for name, data in (
            ("ca.pem", ca.read_bytes()), ("active.cookies", _cookie(one.client)),
            ("remote-revoked.cookies", remote_cookie), ("self-revoked.cookies", self_cookie),
            ("state.json", json.dumps(state, separators=(",", ":")).encode()),
        ):
            base._write_new(root / name, data, mode=0o600)
        return {
            "status": "SESSION_MANAGER_PRE_RESTART_GREEN",
            "same_account_distinct_sessions": True,
            "actor_owned_paginated_list": True,
            "foreign_target_rejected_for_creator_and_access_admin": True,
            "remote_revoke_exact_replay": True,
            "remote_revoke_preserved_current_session": True,
            "self_revoke_retry_rejected_after_revocation": True,
            "revoked_cookies_rejected": True,
            "restart_verification_pending": True,
            "checkpoint_max_age_seconds": 7200,
        }
    finally:
        shutil.rmtree(work)


def verify_restart(*, state_dir: Path) -> Mapping[str, Any]:
    root = _state_directory(state_dir, create=False)
    _require({entry.name for entry in root.iterdir()} == _CHECKPOINT_FILES,
             "CHECKPOINT_CONTENTS")
    state = json.loads(_private_bytes(root / "state.json"))
    base._exact_keys(state, {"kind", "created_at", "expires_at", "active_session_id",
                             "active_csrf_token", "revoked_session_id"})
    _require(state["kind"] == _STATE_KIND, "CHECKPOINT_KIND")
    created = datetime.fromisoformat(state["created_at"])
    expires = datetime.fromisoformat(state["expires_at"])
    now = datetime.now(timezone.utc)
    _require(created.tzinfo is not None and expires.tzinfo is not None
             and timedelta(0) < expires - created <= timedelta(hours=2)
             and created <= now < expires, "CHECKPOINT_EXPIRED")
    one_id = base._canonical_uuid(state["active_session_id"])
    revoked_id = base._canonical_uuid(state["revoked_session_id"])
    ca = base._ca_file(root / "ca.pem")
    cookies = {name: _private_bytes(root / name) for name in (
        "active.cookies", "remote-revoked.cookies", "self-revoked.cookies",
    )}
    work = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    try:
        active = _restore_client(base._role_root(work, "active"), ca, cookies["active.cookies"])
        bootstrap = _stage("ACTIVE_COOKIE_AFTER_RESTART", _bootstrap, active)
        _require(bootstrap["session"]["session_id"] == one_id
                 and bootstrap["csrf_token"] == state["active_csrf_token"],
                 "SAME_SESSION_AFTER_RESTART")
        for label in ("remote-revoked", "self-revoked"):
            revoked = _restore_client(base._role_root(work, label), ca, cookies[f"{label}.cookies"])
            _stage("REVOKED_COOKIE_AFTER_RESTART", _bootstrap, revoked, 401)
        after = _stage("SESSION_LIST_AFTER_RESTART", _sessions, active, one_id)
        _require(_terminal_or_absent(after, revoked_id), "REVOKED_LIST_AFTER_RESTART")
        key = f"session-final-{uuid4()}"
        _stage("FINAL_SELF_REVOKE", _delete_session, active, bootstrap=bootstrap,
               target=one_id, key=key, expected_status=204)
        replay = _restore_client(base._role_root(work, "final-replay"), ca, cookies["active.cookies"])
        _stage("FINAL_SELF_REPLAY", _delete_session, replay, bootstrap=bootstrap,
               target=one_id, key=key, expected_status=401)
        _stage("FINAL_COOKIE_REJECTED", _bootstrap, replay, 401)
    finally:
        shutil.rmtree(work)
    # Only the five checked, generated files are removed after successful proof.
    for name in _CHECKPOINT_FILES:
        (root / name).unlink()
    root.rmdir()
    return {
        "status": "SESSION_MANAGER_RESTART_GREEN",
        "verification_used_original_cookies_without_login": True,
        "active_session_and_csrf_survived_restart": True,
        "remote_revoked_cookie_did_not_revive": True,
        "self_revoked_cookie_did_not_revive": True,
        "final_self_revoke_retry_rejected_after_revocation": True,
        "private_checkpoints_removed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    before = commands.add_parser("prepare")
    before.add_argument("--ca-file", required=True, type=Path)
    before.add_argument("--state-dir", required=True, type=Path)
    before.add_argument("--result-output", type=Path)
    after = commands.add_parser("verify-restart")
    after.add_argument("--state-dir", required=True, type=Path)
    after.add_argument("--result-output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    output_validated = False
    try:
        if args.result_output is not None:
            base._new_absolute_output(args.result_output)
            _require(args.state_dir not in args.result_output.parents, "RESULT_LOCATION")
            output_validated = True
        result = _stage("PREPARE", prepare, ca_file=args.ca_file, state_dir=args.state_dir) \
            if args.command == "prepare" else _stage("VERIFY_RESTART", verify_restart, state_dir=args.state_dir)
        output = json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n"
        if args.result_output is not None:
            base._write_new(args.result_output, output.encode(), mode=0o600)
        sys.stdout.write(output)
        return 0
    except Exception as error:
        stage = error.stage if isinstance(error, SessionAcceptanceError) else "INPUT_OR_OUTPUT"
        failure = json.dumps({"status": "SESSION_MANAGER_E2E_FAILED", "stage": stage}) + "\n"
        if output_validated:
            try:
                base._write_new(args.result_output, failure.encode(), mode=0o600)
            except OSError:
                pass
        sys.stderr.write(failure)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
