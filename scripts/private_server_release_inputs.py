#!/usr/bin/env python3
"""Measure, verify, and snapshot one closed private-server release-input tree.

The helper never prints or returns secret material.  It reads every source file
through an anchored, no-follow descriptor and validates the closed tree in
memory.  The read-only measure/verify APIs return only a digest and fixed count;
the separate staging API copies those same in-memory bytes into a pre-created
permanent attempt root.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from types import MappingProxyType
from types import ModuleType
from typing import Callable, Iterator, Mapping, NoReturn, Optional, Sequence, TextIO, Tuple
from uuid import UUID


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PLATFORM_SOURCE = _REPOSITORY_ROOT / "platform" / "src"
_SECRET_PARSER_PATH = (
    _PLATFORM_SOURCE / "desire_platform" / "internal_pilot" / "secrets.py"
)
_RUNTIME_PARSER_PATH = (
    _PLATFORM_SOURCE / "desire_platform" / "runtime" / "config.py"
)
_RUNTIME_PARSER_SHA256 = (
    "110c58ab5ae3db4ac6925134a2dfd3bfde2d5ea50d16b6437ece9f3641b57533"
)
_SECRET_PARSER_SHA256 = (
    "3568af4beb3fc8f4eb4813f36f1e051ff68b6bec513bdc0434d2317d27430862"
)
_BUNDLE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_FILE_COUNT = 91
_MAX_SMALL_FILE = 64 * 1024
_MAX_JSON_FILE = 256 * 1024
_FROZEN_TOKENS = tuple(
    value.encode("ascii")
    for value in (
        "v13",
        "desire-supply-e2e-ten-account-v13",
        "desire-restore-verify-v13drill01",
        "e2e-ten-account-v13-iam37-demand10-trust7",
        "internal-sandbox-bundle-iam37-demand10-trust7",
        "v13drill01",
        "172.16.227.0/24",
        "172.16.228.0/24",
        "172.16.229.0/24",
        "172.16.231.0/24",
        "172.16.232.0/24",
    )
)
_SOURCE_SECRET_FILES = (
    "db_superuser_password.txt",
    "taxonomy_seed_workload_credential",
    "taxonomy_seed_receipt_hmac_key",
    "oidc-client-secret",
)
_PRIVATE_STAGED_FILES = frozenset(
    ("compose.env", "compose.ipam.yaml", "oidc-client-secret")
)
_IDENTITY_DIRECTORY = "internal-sandbox-identity-sources"
_IDENTITY_FILES = {
    "access_admin_01.subject": b"sandbox:access-admin-01",
    "access_admin_01.email": b"sandbox-access-admin-01@example.test",
    "appeal_reviewer_01.subject": b"sandbox:appeal-reviewer-01",
    "appeal_reviewer_01.email": b"sandbox-appeal-reviewer-01@example.test",
    "creator_01.subject": b"sandbox:creator-01",
    "creator_01.email": b"sandbox-creator-01@example.test",
    "demand_owner_01.subject": b"sandbox:demand-owner-01",
    "demand_owner_01.email": b"sandbox-demand-owner-01@example.test",
    "finance_operator_01.subject": b"sandbox:finance-operator-01",
    "finance_operator_01.email": b"sandbox-finance-operator-01@example.test",
    "finance_operator_02.subject": b"sandbox:finance-operator-02",
    "finance_operator_02.email": b"sandbox-finance-operator-02@example.test",
    "operations_reviewer_01.subject": b"sandbox:operations-reviewer-01",
    "operations_reviewer_01.email": b"sandbox-operations-reviewer-01@example.test",
    "org_admin_01.subject": b"sandbox:org-admin-01",
    "org_admin_01.email": b"sandbox-org-admin-01@example.test",
    "trust_officer_01.subject": b"sandbox:trust-officer-01",
    "trust_officer_01.email": b"sandbox-trust-officer-01@example.test",
    "trust_officer_02.subject": b"sandbox:trust-officer-02",
    "trust_officer_02.email": b"sandbox-trust-officer-02@example.test",
}
_TLS_DIRECTORY = "internal-sandbox-tls"
_TLS_FILES = {
    "root-ca.pem": 0o444,
    "edge-tls-chain.pem": 0o444,
    "edge-tls-key.pem": 0o400,
}
_BUNDLE_CONFIG_FILES = frozenset(
    (
        "deployment.json",
        "runtime-config.json",
        "secret-manifest.json",
        "matching-deployment.json",
        "matching-runtime-config.json",
        "matching-secret-manifest.json",
        "online-credentials-deployment.json",
        "online-credentials-runtime-config.json",
        "online-credentials-secret-manifest.json",
    )
)
_API_CAPABILITIES = (
    ("IAM_APP", "iam_app", "db-iam-app-v1"),
    (
        "IAM_SESSION_AUTHENTICATOR",
        "iam_session_authenticator",
        "db-iam-session-authenticator-v1",
    ),
    ("IAM_ONBOARDING", "iam_onboarding", "db-iam-onboarding-v1"),
    ("PROFILE_APP", "profile_app", "db-profile-app-v1"),
    ("DEMAND_SELF", "demand_self", "db-demand-self-v1"),
    ("DEMAND_REVIEW", "demand_review", "db-demand-review-v1"),
    ("DEMAND_FINANCE", "demand_finance", "db-demand-finance-v1"),
    ("TRUST_SELF", "trust_self", "db-trust-self-v1"),
    ("TRUST_OFFICER", "trust_officer", "db-trust-officer-v1"),
    ("TRUST_APPEAL", "trust_appeal", "db-trust-appeal-v1"),
    ("TRUST_DECISION", "trust_decision", "db-trust-decision-v1"),
    ("MATCHING_CREATOR", "matching_creator", "db-matching-creator-v1"),
    ("MATCHING_SELECTOR", "matching_selector", "db-matching-selector-v1"),
    ("MATCHING_ASSIGNMENT", "matching_assignment", "db-matching-assignment-v1"),
    ("MATCHING_REVIEW", "matching_review", "db-matching-review-v1"),
)
_MATCHING_RUNTIME_CAPABILITIES = (
    ("DEMAND_MATCHING", "demand_matching", "db-demand-matching-v1"),
    ("PROFILE_MATCHER", "profile_matcher", "db-profile-matcher-v1"),
    ("TRUST_DECISION", "trust_decision", "db-trust-decision-v1"),
    ("MATCHING_WORKER", "matching_worker", "db-matching-worker-v1"),
    (
        "MATCHING_COORDINATOR",
        "matching_coordinator",
        "db-matching-coordinator-v1",
    ),
)
_ONLINE_CAPABILITIES = _API_CAPABILITIES + tuple(
    item for item in _MATCHING_RUNTIME_CAPABILITIES if item not in _API_CAPABILITIES
)
_CAPABILITIES = _API_CAPABILITIES
_API_KEY_FILES = (
    ("key-oidc-state-v1", "OIDC_STATE", "oidc-state-v1", "ACTIVE"),
    (
        "key-oidc-browser-binding-v1",
        "OIDC_BROWSER_BINDING",
        "oidc-browser-binding-v1",
        "ACTIVE",
    ),
    ("key-oidc-nonce-v1", "OIDC_NONCE", "oidc-nonce-v1", "ACTIVE"),
    ("key-session-handle-v1", "SESSION_HANDLE", "session-handle-v1", "ACTIVE"),
    ("key-csrf-v1", "CSRF", "csrf-v1", "ACTIVE"),
    (
        "key-oidc-protocol-aead-v1",
        "OIDC_PROTOCOL_AEAD",
        "oidc-protocol-aead-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-subject-digest-v1",
        "OIDC_SUBJECT_DIGEST",
        "oidc-subject-digest-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-recipient-binding-v1",
        "OIDC_RECIPIENT_BINDING",
        "oidc-recipient-binding-v1",
        "ACTIVE",
    ),
    (
        "key-oidc-client-secret-v1",
        "OIDC_CLIENT_SECRET",
        "oidc-client-secret-v1",
        "ACTIVE",
    ),
    (
        "key-editor-id-derivation-v1",
        "EDITOR_ID_DERIVATION",
        "editor-id-derivation-v1",
        "ACTIVE",
    ),
    (
        "key-profile-idempotency-v1",
        "PROFILE_IDEMPOTENCY",
        "profile-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-profile-payload-hash-v1",
        "PROFILE_PAYLOAD_HASH",
        "profile-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-demand-idempotency-v1",
        "DEMAND_IDEMPOTENCY",
        "demand-idempotency-2026-01",
        "ACTIVE",
    ),
    (
        "key-demand-idempotency-retained-2025-12",
        "DEMAND_IDEMPOTENCY",
        "demand-idempotency-retained-2025-12",
        "VERIFY_ONLY",
    ),
    (
        "key-demand-payload-hash-v1",
        "DEMAND_PAYLOAD_HASH",
        "demand-payload-2026-01",
        "ACTIVE",
    ),
    (
        "key-demand-payload-retained-2025-12",
        "DEMAND_PAYLOAD_HASH",
        "demand-payload-retained-2025-12",
        "VERIFY_ONLY",
    ),
    (
        "key-demand-client-reference-v1",
        "DEMAND_CLIENT_REFERENCE",
        "demand-client-reference-v1",
        "ACTIVE",
    ),
    (
        "key-iam-receipt-idempotency-hmac-2026-01",
        "PLATFORM_USER_IDEMPOTENCY",
        "iam-receipt-idempotency-hmac-2026-01",
        "ACTIVE",
    ),
    (
        "key-iam-receipt-payload-hmac-2026-01",
        "PLATFORM_USER_PAYLOAD_HASH",
        "iam-receipt-payload-hmac-2026-01",
        "ACTIVE",
    ),
    (
        "key-access-invitation-token-v1",
        "ACCESS_INVITATION_TOKEN",
        "access-invitation-token-v1",
        "ACTIVE",
    ),
    (
        "key-iam-read-cursor-v1",
        "IAM_READ_CURSOR",
        "iam-read-cursor-v1",
        "ACTIVE",
    ),
    (
        "key-trust-idempotency-v1",
        "TRUST_IDEMPOTENCY",
        "trust-idempotency-2026-01",
        "ACTIVE",
    ),
    (
        "key-trust-payload-hash-v1",
        "TRUST_PAYLOAD_HASH",
        "trust-payload-2026-01",
        "ACTIVE",
    ),
    (
        "key-trust-sealed-note-v1",
        "TRUST_SEALED_NOTE",
        "trust-sealed-note-v1",
        "ACTIVE",
    ),
    (
        "key-trust-report-cursor-v1",
        "TRUST_REPORT_CURSOR",
        "trust-report-cursor-2026-01",
        "ACTIVE",
    ),
    (
        "key-matching-idempotency-v1",
        "MATCHING_IDEMPOTENCY",
        "matching-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-payload-v1",
        "MATCHING_PAYLOAD_HASH",
        "matching-payload-v1",
        "ACTIVE",
    ),
    (
        "key-matching-read-cursor-v1",
        "MATCHING_READ_CURSOR",
        "matching-read-cursor-v1",
        "ACTIVE",
    ),
)
_MATCHING_RUNTIME_KEY_FILES = (
    (
        "key-matching-worker-idempotency-v1",
        "MATCHING_WORKER_IDEMPOTENCY",
        "matching-worker-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-worker-payload-hash-v1",
        "MATCHING_WORKER_PAYLOAD_HASH",
        "matching-worker-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-matching-worker-lease-digest-v1",
        "MATCHING_WORKER_LEASE_DIGEST",
        "matching-worker-lease-digest-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-idempotency-v1",
        "MATCHING_COORDINATOR_IDEMPOTENCY",
        "matching-coordinator-idempotency-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-payload-hash-v1",
        "MATCHING_COORDINATOR_PAYLOAD_HASH",
        "matching-coordinator-payload-hash-v1",
        "ACTIVE",
    ),
    (
        "key-matching-coordinator-lease-digest-v1",
        "MATCHING_COORDINATOR_LEASE_DIGEST",
        "matching-coordinator-lease-digest-v1",
        "ACTIVE",
    ),
)
_KEY_FILES = _API_KEY_FILES
_ALL_KEY_FILES = _API_KEY_FILES + _MATCHING_RUNTIME_KEY_FILES
_BUNDLE_SECRET_FILES = frozenset(
    tuple(item[2] for item in _ONLINE_CAPABILITIES)
    + tuple(item[0] for item in _ALL_KEY_FILES)
)


class PrivateServerReleaseInputError(RuntimeError):
    """Stable, non-reflective release-input failure."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_RELEASE_INPUT_INVALID")


@dataclass(frozen=True, repr=False)
class PrivateServerReleaseInputSnapshot:
    """Non-secret identity of one permanent staged input tree."""

    input_root: Path
    stage_root: Path
    tree_sha256: str
    source_to_staged: Mapping[Path, Path]

    def __repr__(self) -> str:
        return (
            "PrivateServerReleaseInputSnapshot("
            f"input_root={str(self.input_root)!r}, "
            f"stage_root={str(self.stage_root)!r}, "
            f"tree_sha256={self.tree_sha256!r}, "
            f"file_count={len(self.source_to_staged)}, material=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class PrivateServerReleaseInputMeasurement:
    """Non-secret identity of one validated source tree."""

    tree_sha256: str
    file_count: int

    def __repr__(self) -> str:
        return (
            "PrivateServerReleaseInputMeasurement("
            f"tree_sha256={self.tree_sha256!r}, file_count={self.file_count})"
        )


@dataclass(frozen=True, repr=False)
class _FileRecord:
    relative: Path
    source: Path
    mode: int
    value: bytes


class _InvalidDocument(Exception):
    pass


def _invalid() -> NoReturn:
    raise PrivateServerReleaseInputError()


def _reject_frozen(value: bytes) -> None:
    lowered = value.lower()
    if any(token in lowered for token in _FROZEN_TOKENS):
        _invalid()


def _closed_bundle_name(value: str) -> str:
    if not isinstance(value, str) or _BUNDLE_NAME.fullmatch(value) is None:
        _invalid()
    _reject_frozen(value.encode("ascii"))
    return value


def _canonical_directory(path: Path, *, mode: int) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _invalid()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        _invalid()
    if resolved != path:
        _invalid()
    _reject_frozen(str(path).encode("utf-8"))
    return path


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _directory_metadata(metadata: os.stat_result, *, mode: int) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != os.geteuid()
    ):
        _invalid()


@contextmanager
def _open_root(path: Path, *, mode: int) -> Iterator[int]:
    canonical = _canonical_directory(path, mode=mode)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(canonical, flags)
    except OSError:
        _invalid()
    try:
        opened = os.fstat(descriptor)
        current = canonical.lstat()
        _directory_metadata(opened, mode=mode)
        if canonical.is_symlink() or not _same_identity(opened, current):
            _invalid()
        yield descriptor
        final = os.fstat(descriptor)
        final_path = canonical.lstat()
        _directory_metadata(final, mode=mode)
        if not _same_identity(opened, final) or not _same_identity(final, final_path):
            _invalid()
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


@contextmanager
def _open_child_directory(
    parent_descriptor: int,
    name: str,
    *,
    mode: int,
) -> Iterator[int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError:
        _invalid()
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        _directory_metadata(opened, mode=mode)
        if not _same_identity(opened, current):
            _invalid()
        yield descriptor
        final = os.fstat(descriptor)
        final_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        _directory_metadata(final, mode=mode)
        if not _same_identity(opened, final) or not _same_identity(final, final_path):
            _invalid()
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _exact_entries(descriptor: int, expected: frozenset[str]) -> None:
    try:
        entries = os.listdir(descriptor)
    except OSError:
        _invalid()
    if len(entries) != len(expected) or frozenset(entries) != expected:
        _invalid()


def _read_file(
    parent_descriptor: int,
    name: str,
    *,
    source: Path,
    mode: int,
    maximum: int,
) -> _FileRecord:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
            or not _same_identity(before, current)
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        final_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_before != stable_after or not _same_identity(after, final_path):
            _invalid()
        return _FileRecord(
            relative=source,
            source=source,
            mode=mode,
            value=b"".join(chunks),
        )
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _relative_record(
    parent_descriptor: int,
    name: str,
    *,
    root: Path,
    relative_parent: Path,
    mode: int,
    maximum: int,
) -> _FileRecord:
    relative = relative_parent / name
    record = _read_file(
        parent_descriptor,
        name,
        source=root / relative,
        mode=mode,
        maximum=maximum,
    )
    return _FileRecord(
        relative=relative,
        source=record.source,
        mode=record.mode,
        value=record.value,
    )


def _read_source_tree(root: Path, bundle_name: str):
    records = {}
    directories = {
        Path("."): 0o700,
        Path(_IDENTITY_DIRECTORY): 0o755,
        Path(_TLS_DIRECTORY): 0o700,
        Path(bundle_name): 0o700,
        Path(bundle_name) / "config": 0o700,
        Path(bundle_name) / "runtime-secrets": 0o700,
    }
    expected_root = frozenset(
        (
            "compose.env",
            "compose.ipam.yaml",
            *_SOURCE_SECRET_FILES,
            _IDENTITY_DIRECTORY,
            _TLS_DIRECTORY,
            bundle_name,
        )
    )
    with _open_root(root, mode=0o700) as root_descriptor:
        _exact_entries(root_descriptor, expected_root)
        for name in ("compose.env", "compose.ipam.yaml", *_SOURCE_SECRET_FILES):
            record = _relative_record(
                root_descriptor,
                name,
                root=root,
                relative_parent=Path("."),
                mode=0o600,
                maximum=_MAX_SMALL_FILE,
            )
            records[record.relative] = record

        with _open_child_directory(
            root_descriptor, _IDENTITY_DIRECTORY, mode=0o755
        ) as identity_descriptor:
            _exact_entries(identity_descriptor, frozenset(_IDENTITY_FILES))
            for name in sorted(_IDENTITY_FILES):
                record = _relative_record(
                    identity_descriptor,
                    name,
                    root=root,
                    relative_parent=Path(_IDENTITY_DIRECTORY),
                    mode=0o444,
                    maximum=_MAX_SMALL_FILE,
                )
                records[record.relative] = record

        with _open_child_directory(
            root_descriptor, _TLS_DIRECTORY, mode=0o700
        ) as tls_descriptor:
            _exact_entries(tls_descriptor, frozenset(_TLS_FILES))
            for name, mode in sorted(_TLS_FILES.items()):
                record = _relative_record(
                    tls_descriptor,
                    name,
                    root=root,
                    relative_parent=Path(_TLS_DIRECTORY),
                    mode=mode,
                    maximum=_MAX_SMALL_FILE,
                )
                records[record.relative] = record

        with _open_child_directory(
            root_descriptor, bundle_name, mode=0o700
        ) as bundle_descriptor:
            _exact_entries(
                bundle_descriptor, frozenset(("config", "runtime-secrets"))
            )
            with _open_child_directory(
                bundle_descriptor, "config", mode=0o700
            ) as config_descriptor:
                _exact_entries(config_descriptor, _BUNDLE_CONFIG_FILES)
                for name in sorted(_BUNDLE_CONFIG_FILES):
                    record = _relative_record(
                        config_descriptor,
                        name,
                        root=root,
                        relative_parent=Path(bundle_name) / "config",
                        mode=0o600,
                        maximum=_MAX_JSON_FILE,
                    )
                    records[record.relative] = record
            with _open_child_directory(
                bundle_descriptor, "runtime-secrets", mode=0o700
            ) as secret_descriptor:
                _exact_entries(secret_descriptor, _BUNDLE_SECRET_FILES)
                for name in sorted(_BUNDLE_SECRET_FILES):
                    record = _relative_record(
                        secret_descriptor,
                        name,
                        root=root,
                        relative_parent=Path(bundle_name) / "runtime-secrets",
                        mode=0o600,
                        maximum=4_096,
                    )
                    records[record.relative] = record
    if len(records) != _SOURCE_FILE_COUNT:
        _invalid()
    return directories, records


def _closed_json(raw: bytes):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise _InvalidDocument()
            result[key] = value
        return result

    def invalid_number(_value):
        raise _InvalidDocument()

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_float=invalid_number,
            parse_constant=invalid_number,
        )
    except _InvalidDocument:
        _invalid()
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        _invalid()
    if not isinstance(value, dict):
        _invalid()
    return value


def _reject_frozen_json(raw: bytes) -> None:
    pending = [_closed_json(raw)]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            try:
                encoded = value.encode("utf-8", errors="strict")
            except UnicodeError:
                _invalid()
            _reject_frozen(encoded)
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def _exact_object(value, keys: Tuple[str, ...]):
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _validate_deployment(
    raw: bytes,
    *,
    expected_runtime_config_path: str,
    expected_secret_manifest_path: str,
) -> None:
    value = _closed_json(raw)
    expected_keys = (
        "schema_name",
        "deployment_mode",
        "external_participants_enabled",
        "internal_bff_origin",
        "runtime_config_path",
        "secret_manifest_path",
        "secret_root",
        "postgres",
        "oidc",
        "system_actor_id",
        "bind",
    )
    root = _exact_object(value, expected_keys)
    postgres = _exact_object(
        root["postgres"], ("host", "port", "database", "transport_security")
    )
    oidc = _exact_object(
        root["oidc"],
        (
            "issuer",
            "client_id",
            "client_secret_key_id",
            "redirect_uri",
            "allowed_signing_algorithms",
            "metadata_ttl_seconds",
            "request_timeout_seconds",
            "maximum_response_bytes",
            "clock_skew_seconds",
            "subject_digest_key_id",
            "network_binding",
        ),
    )
    _exact_object(oidc["network_binding"], ("mode", "pinned_public_ipv4"))
    bind = _exact_object(root["bind"], ("host", "port"))
    if (
        root["schema_name"] != "desire-internal-sandbox-deployment-v1"
        or root["deployment_mode"] != "INTERNAL_SANDBOX"
        or root["external_participants_enabled"] is not False
        or root["internal_bff_origin"] != "http://api:8000"
        or root["runtime_config_path"] != expected_runtime_config_path
        or root["secret_manifest_path"] != expected_secret_manifest_path
        or root["secret_root"] != "/run/secrets"
        or postgres
        != {
            "host": "db",
            "port": 5432,
            "database": "desire",
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        }
        or oidc
        != {
            "issuer": "https://identity.example.test",
            "client_id": "desire-internal-sandbox",
            "client_secret_key_id": "oidc-client-secret-v1",
            "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
            "allowed_signing_algorithms": ["RS256"],
            "metadata_ttl_seconds": 300,
            "request_timeout_seconds": 3,
            "maximum_response_bytes": 262_144,
            "clock_skew_seconds": 30,
            "subject_digest_key_id": "oidc-subject-digest-v1",
            "network_binding": {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": None,
            },
        }
        or bind != {"host": "0.0.0.0", "port": 8000}
    ):
        _invalid()
    try:
        actor = UUID(root["system_actor_id"])
    except (AttributeError, TypeError, ValueError):
        _invalid()
    if actor.int == 0 or str(actor) != root["system_actor_id"]:
        _invalid()


def _read_pinned_parser_source(path: Path, expected_digest: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_JSON_FILE
            or path.is_symlink()
            or not _same_identity(before, current)
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        final_path = path.lstat()
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        value = b"".join(chunks)
        if (
            stable_before != stable_after
            or not _same_identity(after, final_path)
            or hashlib.sha256(value).hexdigest() != expected_digest
        ):
            _invalid()
        return value
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _module_from_pinned_source(name: str, path: Path, value: bytes) -> ModuleType:
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition(".")[0]
    sys.modules[name] = module
    try:
        code = compile(value, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        _invalid()
    return module


def _load_platform_parsers() -> Tuple[Callable[[bytes], object], Callable[[bytes], object]]:
    runtime_bytes = _read_pinned_parser_source(
        _RUNTIME_PARSER_PATH,
        _RUNTIME_PARSER_SHA256,
    )
    secret_bytes = _read_pinned_parser_source(
        _SECRET_PARSER_PATH,
        _SECRET_PARSER_SHA256,
    )
    module_names = (
        "desire_platform",
        "desire_platform.runtime",
        "desire_platform.runtime.config",
        "_desire_private_server_release_secret_parser",
    )
    missing = object()
    previous = {name: sys.modules.get(name, missing) for name in module_names}
    try:
        package = ModuleType("desire_platform")
        package.__path__ = []
        runtime_package = ModuleType("desire_platform.runtime")
        runtime_package.__path__ = []
        sys.modules["desire_platform"] = package
        sys.modules["desire_platform.runtime"] = runtime_package
        runtime_module = _module_from_pinned_source(
            "desire_platform.runtime.config",
            _RUNTIME_PARSER_PATH,
            runtime_bytes,
        )
        package.runtime = runtime_package
        runtime_package.config = runtime_module
        secret_module = _module_from_pinned_source(
            "_desire_private_server_release_secret_parser",
            _SECRET_PARSER_PATH,
            secret_bytes,
        )
        parse_runtime = getattr(runtime_module, "parse_runtime_config", None)
        parse_manifest = getattr(secret_module, "parse_file_secret_manifest", None)
        if not callable(parse_runtime) or not callable(parse_manifest):
            _invalid()
        return parse_runtime, parse_manifest
    finally:
        for name in reversed(module_names):
            value = previous[name]
            if value is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def _expected_key_requirements(key_files):
    result = []
    for purpose in dict.fromkeys(item[1] for item in key_files):
        values = tuple(item for item in key_files if item[1] == purpose)
        active = next(item[2] for item in values if item[3] == "ACTIVE")
        result.append((purpose, active, tuple(item[2] for item in values)))
    return tuple(result)


def _expected_manifest_entries(capabilities, key_files):
    database_entries = []
    for capability, _role, file_name in capabilities:
        slug = capability.lower().replace("_", "-")
        database_entries.append(
            (
                "DATABASE_CREDENTIAL",
                file_name,
                f"secret://sandbox-db/{slug}#v1",
                f"DATABASE_CREDENTIAL:{capability}",
                "v1",
                "ACTIVE",
            )
        )
    key_entries = tuple(
        ("KEY", file_name, None, purpose, key_id, status)
        for file_name, purpose, key_id, status in key_files
    )
    return tuple(database_entries) + key_entries


def _validate_runtime_and_manifest(
    *,
    runtime_raw: bytes,
    manifest_raw: bytes,
    parse_runtime,
    parse_manifest,
    capabilities,
    key_files,
    expected_instance_id: str,
    expected_process_kind: str,
):
    try:
        runtime = parse_runtime(runtime_raw)
        entries = parse_manifest(manifest_raw)
    except BaseException:
        _invalid()

    expected_capabilities = tuple(item[0] for item in capabilities)
    if (
        runtime.identity.environment_id != "internal-sandbox"
        or runtime.identity.region != "trusted-container-network"
        or runtime.identity.instance_id != expected_instance_id
        or runtime.process.kind != expected_process_kind
        or runtime.process.capability_ids != expected_capabilities
        or (
            runtime.budgets.startup_timeout_ms,
            runtime.budgets.readiness_timeout_ms,
            runtime.budgets.shutdown_timeout_ms,
        )
        != (30_000, 3_000, 15_000)
    ):
        _invalid()

    expected_profiles = []
    for capability, role, _file_name in capabilities:
        slug = capability.lower().replace("_", "-")
        credential_ref = f"secret://sandbox-db/{slug}#v1"
        expected_profiles.append(
            (
                capability,
                role,
                credential_ref,
                f"desire-{slug}",
                4,
                2_000,
                15_000,
                2_000,
                15_000,
            )
        )
    observed_profiles = tuple(
        (
            item.capability_id,
            item.online_role,
            item.credential_ref,
            item.application_name,
            item.max_pool_size,
            item.checkout_timeout_ms,
            item.statement_timeout_ms,
            item.lock_timeout_ms,
            item.idle_in_transaction_timeout_ms,
        )
        for item in runtime.database_profiles
    )
    observed_requirements = tuple(
        (item.purpose, item.active_key_id, item.retained_key_ids)
        for item in runtime.key_requirements
    )
    if (
        observed_profiles != tuple(expected_profiles)
        or observed_requirements != _expected_key_requirements(key_files)
    ):
        _invalid()

    observed_entries = tuple(
        (
            item.kind,
            item.file_name,
            item.credential_ref,
            item.purpose,
            item.key_id,
            item.status,
        )
        for item in entries
    )
    expected_entries = _expected_manifest_entries(capabilities, key_files)
    if observed_entries != expected_entries:
        _invalid()
    return entries


def _validate_bundle(root: Path, bundle_name: str, records: Mapping[Path, _FileRecord]) -> None:
    del root
    config_root = Path(bundle_name) / "config"
    config_values = {
        name: records[config_root / name].value
        for name in _BUNDLE_CONFIG_FILES
    }
    for value in config_values.values():
        _reject_frozen_json(value)
    for name, runtime_path, manifest_path in (
        (
            "deployment.json",
            "/run/desire/runtime-config.json",
            "/run/desire/secret-manifest.json",
        ),
        (
            "matching-deployment.json",
            "/run/desire/matching-runtime-config.json",
            "/run/desire/matching-secret-manifest.json",
        ),
        (
            "online-credentials-deployment.json",
            "/run/desire/online-credentials-runtime-config.json",
            "/run/desire/online-credentials-secret-manifest.json",
        ),
    ):
        _validate_deployment(
            config_values[name],
            expected_runtime_config_path=runtime_path,
            expected_secret_manifest_path=manifest_path,
        )

    parse_runtime, parse_manifest = _load_platform_parsers()
    parsed_entry_groups = (
        _validate_runtime_and_manifest(
            runtime_raw=config_values["runtime-config.json"],
            manifest_raw=config_values["secret-manifest.json"],
            parse_runtime=parse_runtime,
            parse_manifest=parse_manifest,
            capabilities=_API_CAPABILITIES,
            key_files=_API_KEY_FILES,
            expected_instance_id="api-0001",
            expected_process_kind="web-api",
        ),
        _validate_runtime_and_manifest(
            runtime_raw=config_values["matching-runtime-config.json"],
            manifest_raw=config_values["matching-secret-manifest.json"],
            parse_runtime=parse_runtime,
            parse_manifest=parse_manifest,
            capabilities=_MATCHING_RUNTIME_CAPABILITIES,
            key_files=_MATCHING_RUNTIME_KEY_FILES,
            expected_instance_id="matching-runtime-0001",
            expected_process_kind="domain-process",
        ),
        _validate_runtime_and_manifest(
            runtime_raw=config_values["online-credentials-runtime-config.json"],
            manifest_raw=config_values[
                "online-credentials-secret-manifest.json"
            ],
            parse_runtime=parse_runtime,
            parse_manifest=parse_manifest,
            capabilities=_ONLINE_CAPABILITIES,
            key_files=(),
            expected_instance_id="online-credentials-0001",
            expected_process_kind="migration",
        ),
    )
    if frozenset(
        entry.file_name
        for entries in parsed_entry_groups
        for entry in entries
    ) != _BUNDLE_SECRET_FILES:
        _invalid()

    secret_root = Path(bundle_name) / "runtime-secrets"
    bundle_materials = []
    expected_metadata = {
        item[1]: item for item in _expected_manifest_entries(
            _ONLINE_CAPABILITIES,
            _ALL_KEY_FILES,
        )
    }
    if frozenset(expected_metadata) != _BUNDLE_SECRET_FILES:
        _invalid()
    for file_name in sorted(_BUNDLE_SECRET_FILES):
        kind, _name, _credential_ref, purpose, _key_id, _status = (
            expected_metadata[file_name]
        )
        material = records[secret_root / file_name].value
        minimum = 24 if kind == "DATABASE_CREDENTIAL" else 32
        if (
            not minimum <= len(material) <= 4_096
            or not any(material)
            or any(token in material for token in (b"\x00", b"\r", b"\n"))
        ):
            _invalid()
        if purpose == "OIDC_PROTOCOL_AEAD" and len(material) != 32:
            _invalid()
        bundle_materials.append(material)
    if len({hashlib.sha256(value).digest() for value in bundle_materials}) != 53:
        _invalid()

    source_oidc = records[Path("oidc-client-secret")].value
    bundle_oidc = records[secret_root / "key-oidc-client-secret-v1"].value
    if not secrets.compare_digest(
        hashlib.sha256(source_oidc).digest(), hashlib.sha256(bundle_oidc).digest()
    ):
        _invalid()

    all_secret_values = [records[Path(name)].value for name in _SOURCE_SECRET_FILES]
    all_secret_values.append(records[Path(_TLS_DIRECTORY) / "edge-tls-key.pem"].value)
    all_secret_values.extend(bundle_materials)
    oidc_digest = hashlib.sha256(source_oidc).digest()
    digests = [hashlib.sha256(value).digest() for value in all_secret_values]
    if digests.count(oidc_digest) != 2 or len(
        {value for value in digests if value != oidc_digest}
    ) != len(digests) - 2:
        _invalid()


def _validate_source_values(records: Mapping[Path, _FileRecord]) -> None:
    for name, expected in _IDENTITY_FILES.items():
        if records[Path(_IDENTITY_DIRECTORY) / name].value != expected:
            _invalid()
    values = []
    for name in _SOURCE_SECRET_FILES:
        value = records[Path(name)].value
        if name == "taxonomy_seed_receipt_hmac_key":
            if len(value) != 32 or not any(value):
                _invalid()
        else:
            maximum = 4_096 if name == "oidc-client-secret" else 256
            if not 32 <= len(value) <= maximum:
                _invalid()
            try:
                decoded = value.decode("ascii", errors="strict")
            except UnicodeError:
                _invalid()
            if not decoded.isprintable() or any(token in value for token in (b"\x00", b"\r", b"\n")):
                _invalid()
        values.append(value)
    if len({hashlib.sha256(value).digest() for value in values}) != 4:
        _invalid()


def _tree_digest(directories: Mapping[Path, int], records: Mapping[Path, _FileRecord]) -> str:
    digest = hashlib.sha256(b"desire-private-server-release-input-tree-v1\x00")

    def add(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    for relative, mode in sorted(directories.items(), key=lambda item: item[0].as_posix()):
        add(b"D")
        add(relative.as_posix().encode("utf-8"))
        add(f"{mode:04o}".encode("ascii"))
    for relative, record in sorted(records.items(), key=lambda item: item[0].as_posix()):
        add(b"F")
        add(relative.as_posix().encode("utf-8"))
        add(f"{record.mode:04o}".encode("ascii"))
        add(len(record.value).to_bytes(8, "big"))
        add(hashlib.sha256(record.value).digest())
    return digest.hexdigest()


def _validated_source_tree(root: Path, bundle_name: str):
    directories, records = _read_source_tree(root, bundle_name)
    _validate_source_values(records)
    _validate_bundle(root, bundle_name, records)
    return directories, records, _tree_digest(directories, records)


def _write_staged_file(
    parent_descriptor: int,
    name: str,
    *,
    value: bytes,
    mode: int,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, mode, dir_fd=parent_descriptor)
    except OSError:
        _invalid()
    try:
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                _invalid()
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != len(value)
            or not _same_identity(metadata, current)
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _stage_tree(
    stage_root: Path,
    directories: Mapping[Path, int],
    records: Mapping[Path, _FileRecord],
) -> Mapping[Path, Path]:
    mapping = {}
    with _open_root(stage_root, mode=0o700) as stage_descriptor:
        _exact_entries(stage_descriptor, frozenset())
        descriptors = {Path("."): os.dup(stage_descriptor)}
        try:
            for relative, mode in sorted(
                (
                    (relative, mode)
                    for relative, mode in directories.items()
                    if relative != Path(".")
                ),
                key=lambda item: (len(item[0].parts), item[0].as_posix()),
            ):
                parent = relative.parent if relative.parent != Path("") else Path(".")
                parent_descriptor = descriptors[parent]
                descriptor = None
                try:
                    os.mkdir(relative.name, mode, dir_fd=parent_descriptor)
                    descriptor = os.open(
                        relative.name,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_descriptor,
                    )
                    os.fchmod(descriptor, mode)
                except OSError:
                    if descriptor is not None:
                        os.close(descriptor)
                    _invalid()
                try:
                    metadata = os.fstat(descriptor)
                    current = os.stat(
                        relative.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    _directory_metadata(metadata, mode=mode)
                    if not _same_identity(metadata, current):
                        _invalid()
                except BaseException:
                    os.close(descriptor)
                    raise
                descriptors[relative] = descriptor

            for relative, record in sorted(
                records.items(), key=lambda item: item[0].as_posix()
            ):
                parent = relative.parent if relative.parent != Path("") else Path(".")
                staged_mode = (
                    0o600
                    if relative.as_posix() in _PRIVATE_STAGED_FILES
                    else 0o444
                )
                _write_staged_file(
                    descriptors[parent],
                    relative.name,
                    value=record.value,
                    mode=staged_mode,
                )
                mapping[record.source] = stage_root / relative

            expected_by_parent = {relative: set() for relative in directories}
            for relative in directories:
                if relative != Path("."):
                    parent = relative.parent if relative.parent != Path("") else Path(".")
                    expected_by_parent[parent].add(relative.name)
            for relative in records:
                parent = relative.parent if relative.parent != Path("") else Path(".")
                expected_by_parent[parent].add(relative.name)
            for relative, descriptor in descriptors.items():
                _exact_entries(descriptor, frozenset(expected_by_parent[relative]))
            for relative in sorted(
                descriptors, key=lambda value: len(value.parts), reverse=True
            ):
                os.fsync(descriptors[relative])
        except OSError:
            _invalid()
        finally:
            for relative, descriptor in sorted(
                descriptors.items(),
                key=lambda item: len(item[0].parts),
                reverse=True,
            ):
                del relative
                os.close(descriptor)
    return MappingProxyType(mapping)


def measure_private_server_release_inputs(
    *,
    input_root: Path,
    bundle_name: str,
) -> PrivateServerReleaseInputMeasurement:
    """Validate and measure one source tree without staging or returning paths."""

    try:
        bundle = _closed_bundle_name(bundle_name)
        source_root = _canonical_directory(input_root, mode=0o700)
        _directories, records, tree_sha256 = _validated_source_tree(
            source_root,
            bundle,
        )
        return PrivateServerReleaseInputMeasurement(
            tree_sha256=tree_sha256,
            file_count=len(records),
        )
    except PrivateServerReleaseInputError:
        raise
    except BaseException:
        _invalid()


def verify_private_server_release_inputs(
    *,
    input_root: Path,
    bundle_name: str,
    expected_tree_sha256: str,
) -> PrivateServerReleaseInputMeasurement:
    """Measure a source tree and compare it with one independently approved digest."""

    if (
        not isinstance(expected_tree_sha256, str)
        or _SHA256.fullmatch(expected_tree_sha256) is None
    ):
        _invalid()
    measurement = measure_private_server_release_inputs(
        input_root=input_root,
        bundle_name=bundle_name,
    )
    if not secrets.compare_digest(
        measurement.tree_sha256,
        expected_tree_sha256,
    ):
        _invalid()
    return measurement


def stage_private_server_release_inputs(
    *,
    input_root: Path,
    bundle_name: str,
    attempt_stage_root: Path,
) -> PrivateServerReleaseInputSnapshot:
    """Validate and snapshot one exact release-input tree without secret output."""

    try:
        bundle = _closed_bundle_name(bundle_name)
        source_root = _canonical_directory(input_root, mode=0o700)
        stage_root = _canonical_directory(attempt_stage_root, mode=0o700)
        if source_root == stage_root:
            _invalid()
        directories, records, tree_sha256 = _validated_source_tree(
            source_root,
            bundle,
        )
        mapping = _stage_tree(stage_root, directories, records)
        return PrivateServerReleaseInputSnapshot(
            input_root=source_root,
            stage_root=stage_root,
            tree_sha256=tree_sha256,
            source_to_staged=mapping,
        )
    except PrivateServerReleaseInputError:
        raise
    except BaseException:
        _invalid()


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


def _add_measure_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--bundle-name", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _ClosedArgumentParser(add_help=False)
    subcommands = parser.add_subparsers(
        dest="action",
        required=True,
        parser_class=_ClosedArgumentParser,
    )
    measure = subcommands.add_parser("measure", add_help=False)
    _add_measure_arguments(measure)
    verify = subcommands.add_parser("verify", add_help=False)
    _add_measure_arguments(verify)
    verify.add_argument("--expected-tree-sha256", required=True)
    return parser


def _result(measurement: PrivateServerReleaseInputMeasurement, status: str) -> str:
    return (
        json.dumps(
            {
                "authority": "NOT_AUTHORITY",
                "execution_permitted": False,
                "file_count": measurement.file_count,
                "production_authorized": False,
                "status": status,
                "tree_sha256": measurement.tree_sha256,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        keywords = {
            "input_root": Path(arguments.input_root),
            "bundle_name": arguments.bundle_name,
        }
        if arguments.action == "measure":
            measurement = measure_private_server_release_inputs(**keywords)
            status = "PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY"
        else:
            measurement = verify_private_server_release_inputs(
                **keywords,
                expected_tree_sha256=arguments.expected_tree_sha256,
            )
            status = "PRIVATE_SERVER_RELEASE_INPUTS_VERIFIED_NOT_AUTHORITY"
    except BaseException:
        stderr.write(
            '{"code":"PRIVATE_SERVER_RELEASE_INPUT_INVALID","status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(_result(measurement, status))
    return 0


__all__ = (
    "PrivateServerReleaseInputError",
    "PrivateServerReleaseInputMeasurement",
    "PrivateServerReleaseInputSnapshot",
    "main",
    "measure_private_server_release_inputs",
    "stage_private_server_release_inputs",
    "verify_private_server_release_inputs",
)


if __name__ == "__main__":
    raise SystemExit(main())
