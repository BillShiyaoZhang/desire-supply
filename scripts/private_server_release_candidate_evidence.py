#!/usr/bin/env python3
"""Generate or verify fail-closed current-head v13 caller claims.

Version 1 cannot verify evidence provenance and therefore always remains
BLOCKED.  It cannot represent readiness, approval, production authority,
private-ingress activation authority, or runtime input.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, NoReturn, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "deploy"
    / "private-server-release-candidate-evidence-v1.schema.json"
)
SCHEMA_VERSION = "desire-private-server-release-candidate-evidence-v1"
BLOCKED = "BLOCKED"
WRITTEN_STATUS = "PRIVATE_SERVER_RELEASE_CANDIDATE_EVIDENCE_WRITTEN"
VERIFIED_STATUS = "PRIVATE_SERVER_RELEASE_CANDIDATE_EVIDENCE_VERIFIED"
ERROR_CODE = "PRIVATE_SERVER_RELEASE_CANDIDATE_EVIDENCE_INVALID"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_FROZEN_ASSET_BYTES = 8 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_CANDIDATE_ID = re.compile(
    r"^current-head-v13-rc-[a-z0-9][a-z0-9._-]{0,63}$"
)
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$")

FROZEN_ASSETS = (
    (
        "IAM37_SQL",
        "platform/src/desire_platform/identity_access/adapters/postgres/"
        "migrations/0037_expand__finance_funding_review_authority_v2.sql",
        "60763a06f50332f7b7317a516d9a9f41006b807165b1fccf32cf8f879e666e01",
    ),
    (
        "IAM_MANIFEST",
        "platform/src/desire_platform/identity_access/adapters/postgres/"
        "migrations/manifest.json",
        "62635dc9eb94f6e62e5bf5c7cab46371b46716cfbb179f28099da48f65d6755b",
    ),
    (
        "DEMAND10_SQL",
        "platform/src/desire_platform/demand/adapters/postgres/migrations/"
        "0010_expand__finance_funding_review_resolution.sql",
        "12971bf1143969ef47875aa0d83c39fade0b3dbabfaf892f269dc24078bc9823",
    ),
    (
        "DEMAND_MANIFEST",
        "platform/src/desire_platform/demand/adapters/postgres/migrations/"
        "manifest.json",
        "7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4",
    ),
    (
        "TRUST7_SQL",
        "platform/src/desire_platform/trust_safety/adapters/postgres/"
        "migrations/0007_expand__iam37_demand10_dependency_repin.sql",
        "16d383778cb794402c786f5cae8c32744af30627928d35fff9182a97128e1fc3",
    ),
    (
        "TRUST_MANIFEST",
        "platform/src/desire_platform/trust_safety/adapters/postgres/"
        "migrations/manifest.json",
        "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124",
    ),
    (
        "TRUST_OPENAPI",
        "platform/src/desire_platform/contracts/api/trust-v1.openapi.yaml",
        "f23f8283ce8334cf48e1c912379451f00efe21382a281c5f5156260ae3a618ed",
    ),
)

DOCKER_REFERENCES = (
    "docker.io/docker/dockerfile:1.12@sha256:"
    "93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25",
    "docker.io/library/python:3.14.1-slim-bookworm@sha256:"
    "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff",
    "docker.io/library/node:22.22.3-bookworm-slim@sha256:"
    "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752",
    "docker.io/library/caddy:2.10.2-alpine@sha256:"
    "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
    "docker.io/library/postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
)
TEST_RUN_IDS = ("PLATFORM_FULL", "WEB_FULL", "DEPLOYMENT_FULL")
QUALITY_CHECK_IDS = (
    "WEB_TYPECHECK",
    "WEB_LINT",
    "GIT_DIFF_CHECK",
    "CONTAINER_STATIC_VERIFY",
)
ONE_SHOT_CHECK_IDS = (
    "primary_project_namespace",
    "restore_project_namespace",
    "image_tags",
    "input_root",
    "evidence_paths",
    "backup_directory",
    "network_subnets",
    "loopback_https_listener",
)
BLOCKING_REASONS = (
    "EVIDENCE_PROVENANCE_NOT_VERIFIED",
    "SOURCE_SNAPSHOT_NOT_VERIFIED",
    "FROZEN_ASSET_NOT_VERIFIED",
    "DOCKER_HUB_MANIFEST_GATE_NOT_PASSED",
    "TEST_RUN_NOT_PASSED",
    "QUALITY_CHECK_NOT_PASSED",
    "TRUST8_DEFERRAL_NOT_ACCEPTED",
    "ONE_SHOT_V13_NOT_UNCONSUMED_VERIFIED",
)


class ReleaseCandidateEvidenceError(RuntimeError):
    """Stable, non-reflective evidence failure."""

    def __init__(self) -> None:
        super().__init__(ERROR_CODE)


def _invalid() -> NoReturn:
    raise ReleaseCandidateEvidenceError()


def _require_object(value: Any, keys: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        _invalid()
    return value


def _require_array(value: Any, length: int) -> list[Any]:
    if not isinstance(value, list) or len(value) != length:
        _invalid()
    return value


def _require_const(value: Any, expected: Any) -> None:
    if type(value) is not type(expected) or value != expected:
        _invalid()


def _require_sha256(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _invalid()
    return value


def _require_timestamp(value: Any, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _invalid()
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _invalid()
    return value


def _require_nonnegative_integer(value: Any, *, nullable: bool = False) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or value < 0:
        _invalid()
    return value


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    try:
        serialized = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        _invalid()
    return (serialized + "\n").encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    _invalid()


def _safe_absolute_path(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        _invalid()
    try:
        parent = value.parent.resolve(strict=True)
    except OSError:
        _invalid()
    if parent != value.parent or _FILE_NAME.fullmatch(value.name) is None:
        _invalid()
    return value


def _safe_parent_descriptor(path: Path) -> int:
    path = _safe_absolute_path(path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.parent, flags)
        parent_stat = os.fstat(descriptor)
    except OSError:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        _invalid()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
        or parent_stat.st_uid != os.getuid()
    ):
        os.close(descriptor)
        _invalid()
    return descriptor


def _read_evidence_file(path: Path) -> bytes:
    path = _safe_absolute_path(path)
    parent_descriptor = _safe_parent_descriptor(path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_uid != os.getuid()
            or file_stat.st_nlink != 1
            or not 0 < file_stat.st_size <= MAX_DOCUMENT_BYTES
        ):
            _invalid()
        chunks: list[bytes] = []
        remaining = MAX_DOCUMENT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != file_stat.st_size or len(raw) > MAX_DOCUMENT_BYTES:
            _invalid()
        return raw
    except ReleaseCandidateEvidenceError:
        raise
    except OSError:
        _invalid()
    finally:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        os.close(parent_descriptor)


def _load_document(path: Path, *, require_canonical: bool) -> dict[str, Any]:
    raw = _read_evidence_file(path)
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        _invalid()
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except ReleaseCandidateEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        _invalid()
    if not isinstance(document, dict):
        _invalid()
    if require_canonical and raw != _canonical_bytes(document):
        _invalid()
    return document


def _write_new(path: Path, value: bytes) -> None:
    path = _safe_absolute_path(path)
    parent_descriptor = _safe_parent_descriptor(path)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        os.fchmod(descriptor, 0o600)
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _invalid()
            view = view[written:]
        os.fsync(descriptor)
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_uid != os.getuid()
            or file_stat.st_nlink != 1
            or file_stat.st_size != len(value)
        ):
            _invalid()
    except ReleaseCandidateEvidenceError:
        raise
    except OSError:
        _invalid()
    finally:
        try:
            os.close(descriptor)
        except (NameError, OSError):
            pass
        os.close(parent_descriptor)


def _read_repository_file(relative_path: str, maximum: int) -> bytes:
    path = REPOSITORY_ROOT / relative_path
    try:
        if path.is_symlink() or not path.is_file():
            _invalid()
        raw = path.read_bytes()
    except ReleaseCandidateEvidenceError:
        raise
    except OSError:
        _invalid()
    if not raw or len(raw) > maximum:
        _invalid()
    return raw


def _validate_current_docker_pins() -> None:
    try:
        dockerfile = _read_repository_file("Dockerfile", 1024 * 1024).decode(
            "utf-8", errors="strict"
        )
        compose = _read_repository_file("compose.yaml", 1024 * 1024).decode(
            "utf-8", errors="strict"
        )
    except ReleaseCandidateEvidenceError:
        raise
    except UnicodeError:
        _invalid()
    expected_lines = (
        "# syntax=" + DOCKER_REFERENCES[0].removeprefix("docker.io/"),
        "ARG PYTHON_IMAGE="
        + DOCKER_REFERENCES[1].removeprefix("docker.io/library/"),
        "ARG NODE_IMAGE="
        + DOCKER_REFERENCES[2].removeprefix("docker.io/library/"),
        "ARG CADDY_IMAGE="
        + DOCKER_REFERENCES[3].removeprefix("docker.io/library/"),
    )
    if any(dockerfile.splitlines().count(line) != 1 for line in expected_lines):
        _invalid()
    postgres_line = (
        "    image: "
        + DOCKER_REFERENCES[4].removeprefix("docker.io/library/")
    )
    if compose.splitlines().count(postgres_line) != 1:
        _invalid()


def _validate_source_snapshot(value: Any) -> str | None:
    source = _require_object(
        value,
        (
            "kind",
            "status",
            "snapshot_sha256",
            "verification_artifact_sha256",
            "verified_at",
        ),
    )
    _require_const(source["kind"], "SOURCE_ARCHIVE_SHA256")
    status = source["status"]
    if status not in ("PENDING", "VERIFIED", "FAILED", "MISMATCH"):
        _invalid()
    snapshot = _require_sha256(source["snapshot_sha256"], nullable=True)
    evidence = _require_sha256(
        source["verification_artifact_sha256"], nullable=True
    )
    verified_at = _require_timestamp(source["verified_at"], nullable=True)
    if status == "PENDING":
        if (snapshot, evidence, verified_at) != (None, None, None):
            _invalid()
    elif None in (snapshot, evidence, verified_at):
        _invalid()
    return snapshot


def _validate_frozen_assets(value: Any, snapshot_sha256: str | None) -> None:
    assets = _require_array(value, len(FROZEN_ASSETS))
    # Both sequences have already been closed to the same exact length above.
    # Avoid ``zip(strict=True)`` so this deployment helper remains runnable on
    # the repository's supported Python 3.9 baseline.
    for item, expected in zip(assets, FROZEN_ASSETS):
        asset = _require_object(
            item,
            (
                "asset_id",
                "path",
                "expected_sha256",
                "observed_sha256",
                "source_snapshot_sha256",
                "status",
            ),
        )
        asset_id, relative_path, expected_sha256 = expected
        _require_const(asset["asset_id"], asset_id)
        _require_const(asset["path"], relative_path)
        _require_const(asset["expected_sha256"], expected_sha256)
        observed = _require_sha256(asset["observed_sha256"], nullable=True)
        bound_snapshot = _require_sha256(
            asset["source_snapshot_sha256"], nullable=True
        )
        status = asset["status"]
        if status not in ("PENDING", "VERIFIED", "MISMATCH"):
            _invalid()
        if status == "PENDING":
            if observed is not None or bound_snapshot is not None:
                _invalid()
            continue
        if snapshot_sha256 is None or bound_snapshot != snapshot_sha256:
            _invalid()
        actual = hashlib.sha256(
            _read_repository_file(relative_path, MAX_FROZEN_ASSET_BYTES)
        ).hexdigest()
        if observed != actual:
            _invalid()
        if status == "VERIFIED" and actual != expected_sha256:
            _invalid()
        if status == "MISMATCH" and actual == expected_sha256:
            _invalid()


def _validate_evidence_triplet(
    value: Mapping[str, Any],
    *,
    snapshot_sha256: str | None,
    pending: bool,
) -> None:
    bound_snapshot = _require_sha256(
        value["source_snapshot_sha256"], nullable=True
    )
    evidence = _require_sha256(value["evidence_sha256"], nullable=True)
    completed = _require_timestamp(value["completed_at"], nullable=True)
    if pending:
        if (bound_snapshot, evidence, completed) != (None, None, None):
            _invalid()
    elif (
        snapshot_sha256 is None
        or bound_snapshot != snapshot_sha256
        or evidence is None
        or completed is None
    ):
        _invalid()


def _validate_docker_gate(value: Any, snapshot_sha256: str | None) -> None:
    gate = _require_object(
        value,
        (
            "gate_id",
            "rounds_required",
            "references_per_round",
            "checks_required",
            "checks_passed",
            "references",
            "status",
            "source_snapshot_sha256",
            "evidence_sha256",
            "completed_at",
        ),
    )
    _require_const(gate["gate_id"], "DOCKER_HUB_PRODUCTION_MANIFESTS_V1")
    _require_const(gate["rounds_required"], 3)
    _require_const(gate["references_per_round"], 5)
    _require_const(gate["checks_required"], 15)
    checks_passed = _require_nonnegative_integer(gate["checks_passed"])
    if checks_passed is None or checks_passed > 15:
        _invalid()
    references = _require_array(gate["references"], len(DOCKER_REFERENCES))
    if tuple(references) != DOCKER_REFERENCES:
        _invalid()
    _validate_current_docker_pins()
    status = gate["status"]
    if status not in ("PENDING", "PASSED", "FAILED", "MISMATCH"):
        _invalid()
    if status == "PENDING" and checks_passed != 0:
        _invalid()
    if status == "PASSED" and checks_passed != 15:
        _invalid()
    _validate_evidence_triplet(
        gate,
        snapshot_sha256=snapshot_sha256,
        pending=status == "PENDING",
    )


def _validate_test_runs(value: Any, snapshot_sha256: str | None) -> None:
    runs = _require_array(value, len(TEST_RUN_IDS))
    for item, check_id in zip(runs, TEST_RUN_IDS):
        run = _require_object(
            item,
            (
                "check_id",
                "status",
                "passed_count",
                "failed_count",
                "skipped_count",
                "source_snapshot_sha256",
                "evidence_sha256",
                "completed_at",
            ),
        )
        _require_const(run["check_id"], check_id)
        status = run["status"]
        if status not in ("PENDING", "PASSED", "FAILED", "MISMATCH"):
            _invalid()
        passed = _require_nonnegative_integer(run["passed_count"], nullable=True)
        failed = _require_nonnegative_integer(run["failed_count"], nullable=True)
        skipped = _require_nonnegative_integer(run["skipped_count"], nullable=True)
        if status == "PENDING":
            if (passed, failed, skipped) != (None, None, None):
                _invalid()
        else:
            if None in (passed, failed, skipped):
                _invalid()
            if status == "PASSED" and (
                passed == 0 or failed != 0 or skipped != 0
            ):
                _invalid()
            if status == "FAILED" and failed == 0:
                _invalid()
        _validate_evidence_triplet(
            run,
            snapshot_sha256=snapshot_sha256,
            pending=status == "PENDING",
        )


def _validate_quality_checks(value: Any, snapshot_sha256: str | None) -> None:
    checks = _require_array(value, len(QUALITY_CHECK_IDS))
    for item, check_id in zip(checks, QUALITY_CHECK_IDS):
        check = _require_object(
            item,
            (
                "check_id",
                "status",
                "source_snapshot_sha256",
                "evidence_sha256",
                "completed_at",
            ),
        )
        _require_const(check["check_id"], check_id)
        status = check["status"]
        if status not in ("PENDING", "PASSED", "FAILED", "MISMATCH"):
            _invalid()
        _validate_evidence_triplet(
            check,
            snapshot_sha256=snapshot_sha256,
            pending=status == "PENDING",
        )


def _validate_trust8(value: Any, snapshot_sha256: str | None) -> None:
    trust8 = _require_object(
        value,
        (
            "implementation_status",
            "boundary",
            "accepted_for_candidate_scope",
            "acceptance_record_sha256",
            "source_snapshot_sha256",
        ),
    )
    _require_const(trust8["implementation_status"], "DEFERRED_NOT_IMPLEMENTED")
    _require_const(trust8["boundary"], "FROZEN_TRUST7_BOUNDARY")
    accepted = trust8["accepted_for_candidate_scope"]
    if type(accepted) is not bool:
        _invalid()
    record = _require_sha256(trust8["acceptance_record_sha256"], nullable=True)
    bound_snapshot = _require_sha256(
        trust8["source_snapshot_sha256"], nullable=True
    )
    if not accepted:
        if record is not None or bound_snapshot is not None:
            _invalid()
    elif (
        snapshot_sha256 is None
        or record is None
        or bound_snapshot != snapshot_sha256
    ):
        _invalid()


def _validate_one_shot(value: Any, snapshot_sha256: str | None) -> None:
    one_shot = _require_object(
        value,
        (
            "claim",
            "checks",
            "source_snapshot_sha256",
            "verification_artifact_sha256",
            "verified_at",
        ),
    )
    checks = _require_object(one_shot["checks"], ONE_SHOT_CHECK_IDS)
    for check_id in ONE_SHOT_CHECK_IDS:
        if checks[check_id] not in ("ABSENT_VERIFIED", "NOT_VERIFIED"):
            _invalid()
    statuses = tuple(checks[check_id] for check_id in ONE_SHOT_CHECK_IDS)
    all_absent = all(status == "ABSENT_VERIFIED" for status in statuses)
    any_absent = any(status == "ABSENT_VERIFIED" for status in statuses)
    expected_claim = "UNCONSUMED_VERIFIED" if all_absent else "NOT_VERIFIED"
    _require_const(one_shot["claim"], expected_claim)
    bound_snapshot = _require_sha256(
        one_shot["source_snapshot_sha256"], nullable=True
    )
    artifact = _require_sha256(
        one_shot["verification_artifact_sha256"], nullable=True
    )
    verified_at = _require_timestamp(one_shot["verified_at"], nullable=True)
    if not any_absent:
        if (bound_snapshot, artifact, verified_at) != (None, None, None):
            _invalid()
    elif (
        snapshot_sha256 is None
        or bound_snapshot != snapshot_sha256
        or artifact is None
        or verified_at is None
    ):
        _invalid()


def _derived_blocking_reasons(document: Mapping[str, Any]) -> tuple[str, ...]:
    # v1 validates caller-supplied shape and local bindings only.  It does not
    # read protected receipts or prove live resource absence, so provenance is
    # unconditionally unverified even when every caller subclaim says PASSED.
    reasons: list[str] = [BLOCKING_REASONS[0]]
    if document["source_snapshot"]["status"] != "VERIFIED":
        reasons.append(BLOCKING_REASONS[1])
    if any(asset["status"] != "VERIFIED" for asset in document["frozen_assets"]):
        reasons.append(BLOCKING_REASONS[2])
    if document["docker_hub_manifest_gate"]["status"] != "PASSED":
        reasons.append(BLOCKING_REASONS[3])
    if any(run["status"] != "PASSED" for run in document["test_runs"]):
        reasons.append(BLOCKING_REASONS[4])
    if any(
        check["status"] != "PASSED" for check in document["quality_checks"]
    ):
        reasons.append(BLOCKING_REASONS[5])
    if not document["trust8_applicant_discovery"][
        "accepted_for_candidate_scope"
    ]:
        reasons.append(BLOCKING_REASONS[6])
    if document["one_shot_v13"]["claim"] != "UNCONSUMED_VERIFIED":
        reasons.append(BLOCKING_REASONS[7])
    return tuple(reasons)


def validate_release_candidate_evidence(document: Any) -> str:
    """Validate exact shape and bindings while remaining fail-closed."""

    candidate = _require_object(
        document,
        (
            "schema_version",
            "candidate_id",
            "created_at",
            "candidate_scope",
            "environment",
            "data_scope",
            "production_authorized",
            "approval_boundary",
            "source_snapshot",
            "frozen_assets",
            "docker_hub_manifest_gate",
            "test_runs",
            "quality_checks",
            "trust8_applicant_discovery",
            "one_shot_v13",
            "overall_status",
            "blocking_reasons",
        ),
    )
    _require_const(candidate["schema_version"], SCHEMA_VERSION)
    if (
        not isinstance(candidate["candidate_id"], str)
        or _CANDIDATE_ID.fullmatch(candidate["candidate_id"]) is None
    ):
        _invalid()
    _require_timestamp(candidate["created_at"])
    _require_const(candidate["candidate_scope"], "RUN_CURRENT_HEAD_V13_ONCE")
    _require_const(candidate["environment"], "INTERNAL_SANDBOX")
    _require_const(candidate["data_scope"], "synthetic_only")
    _require_const(candidate["production_authorized"], False)
    _require_const(
        candidate["approval_boundary"],
        "SEPARATE_HUMAN_APPROVAL_ARTIFACT_REQUIRED",
    )

    snapshot_sha256 = _validate_source_snapshot(candidate["source_snapshot"])
    _validate_frozen_assets(candidate["frozen_assets"], snapshot_sha256)
    _validate_docker_gate(candidate["docker_hub_manifest_gate"], snapshot_sha256)
    _validate_test_runs(candidate["test_runs"], snapshot_sha256)
    _validate_quality_checks(candidate["quality_checks"], snapshot_sha256)
    _validate_trust8(candidate["trust8_applicant_discovery"], snapshot_sha256)
    _validate_one_shot(candidate["one_shot_v13"], snapshot_sha256)

    reasons = _derived_blocking_reasons(candidate)
    provided_reasons = candidate["blocking_reasons"]
    if (
        not isinstance(provided_reasons, list)
        or tuple(provided_reasons) != reasons
    ):
        _invalid()
    _require_const(candidate["overall_status"], BLOCKED)
    return BLOCKED


def generate_release_candidate_evidence(input_path: Path, output_path: Path) -> str:
    """Validate caller evidence and write one new canonical 0600 artifact."""

    if input_path == output_path:
        _invalid()
    document = _load_document(input_path, require_canonical=False)
    overall = validate_release_candidate_evidence(document)
    _write_new(output_path, _canonical_bytes(document))
    return overall


def verify_release_candidate_evidence(input_path: Path) -> str:
    """Read and verify one canonical artifact without writing anything."""

    document = _load_document(input_path, require_canonical=True)
    return validate_release_candidate_evidence(document)


def _success(status: str) -> str:
    return json.dumps(
        {"overall_status": BLOCKED, "status": status},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _failure() -> str:
    return json.dumps(
        {"code": ERROR_CODE, "status": BLOCKED},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if (
            len(arguments) == 5
            and arguments[0] == "generate"
            and arguments[1] == "--input"
            and arguments[3] == "--output"
        ):
            generate_release_candidate_evidence(
                Path(arguments[2]), Path(arguments[4])
            )
            print(_success(WRITTEN_STATUS))
            return 0
        if (
            len(arguments) == 3
            and arguments[0] == "verify"
            and arguments[1] == "--input"
        ):
            verify_release_candidate_evidence(Path(arguments[2]))
            print(_success(VERIFIED_STATUS))
            return 0
        _invalid()
    except ReleaseCandidateEvidenceError:
        print(_failure(), file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
