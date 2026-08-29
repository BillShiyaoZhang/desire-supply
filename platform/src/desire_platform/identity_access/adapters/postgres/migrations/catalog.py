"""Closed, byte-exact catalog for reviewed IAM PostgreSQL migrations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Tuple


class MigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class MigrationCatalogError(Exception):
    """Stable, non-reflective migration catalog rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ManifestInvalid(ValueError):
    """Internal parse sentinel whose details must never cross the boundary."""


@dataclass(frozen=True)
class MigrationDescriptor:
    component: str
    version: int
    phase: MigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes


@dataclass(frozen=True)
class MigrationArtifact:
    descriptor: MigrationDescriptor
    sql_bytes: bytes


IAM_MIGRATION_LAYOUT: Tuple[Tuple[int, MigrationPhase, str, str], ...] = (
    (0, MigrationPhase.EXPAND, "schemas_and_ledger", "0000_expand__schemas_and_ledger.sql"),
    (1, MigrationPhase.EXPAND, "policy_publication", "0001_expand__policy_publication.sql"),
    (
        2,
        MigrationPhase.EXPAND,
        "identity_tenancy_invitation",
        "0002_expand__identity_tenancy_invitation.sql",
    ),
    (3, MigrationPhase.EXPAND, "auth_session_evidence", "0003_expand__auth_session_evidence.sql"),
    (4, MigrationPhase.EXPAND, "receipt_audit_outbox", "0004_expand__receipt_audit_outbox.sql"),
    (5, MigrationPhase.EXPAND, "iam_force_rls", "0005_expand__iam_force_rls.sql"),
    (6, MigrationPhase.EXPAND, "me_self_summary", "0006_expand__me_self_summary.sql"),
    (7, MigrationPhase.CONTRACT, "verify_iam_v1", "0007_contract__verify_iam_v1.sql"),
    (
        8,
        MigrationPhase.EXPAND,
        "outbox_delivery_and_consumer_inbox",
        "0008_expand__outbox_delivery_and_consumer_inbox.sql",
    ),
    (
        9,
        MigrationPhase.EXPAND,
        "accept_policy_graph_lock",
        "0009_expand__accept_policy_graph_lock.sql",
    ),
    (
        10,
        MigrationPhase.CONTRACT,
        "consent_grant_trigger_dispatch",
        "0010_contract__consent_grant_trigger_dispatch.sql",
    ),
    (
        11,
        MigrationPhase.EXPAND,
        "policy_acceptance_reuse_rls",
        "0011_expand__policy_acceptance_reuse_rls.sql",
    ),
    (
        12,
        MigrationPhase.EXPAND,
        "iam_read_models",
        "0012_expand__iam_read_models.sql",
    ),
    (
        13,
        MigrationPhase.EXPAND,
        "consent_grant_accept_expiry_rls",
        "0013_expand__consent_grant_accept_expiry_rls.sql",
    ),
    (
        14,
        MigrationPhase.EXPAND,
        "policy_consent_self_uow",
        "0014_expand__policy_consent_self_uow.sql",
    ),
    (
        15,
        MigrationPhase.EXPAND,
        "creator_profile_authority",
        "0015_expand__creator_profile_authority.sql",
    ),
    (
        16,
        MigrationPhase.EXPAND,
        "demand_authority",
        "0016_expand__demand_authority.sql",
    ),
    (
        17,
        MigrationPhase.EXPAND,
        "platform_duty_grants",
        "0017_expand__platform_duty_grants.sql",
    ),
    (
        18,
        MigrationPhase.EXPAND,
        "platform_user_lifecycle_uow",
        "0018_expand__platform_user_lifecycle_uow.sql",
    ),
    (
        19,
        MigrationPhase.EXPAND,
        "editor_principal_resolver",
        "0019_expand__editor_principal_resolver.sql",
    ),
    (
        20,
        MigrationPhase.EXPAND,
        "oidc_authentication_uow",
        "0020_expand__oidc_authentication_uow.sql",
    ),
    (
        21,
        MigrationPhase.EXPAND,
        "authority_marker_resolver",
        "0021_expand__authority_marker_resolver.sql",
    ),
    (
        22,
        MigrationPhase.EXPAND,
        "profile_migration_compatibility",
        "0022_expand__profile_migration_compatibility.sql",
    ),
    (
        23,
        MigrationPhase.EXPAND,
        "internal_sandbox_identity_bootstrap",
        "0023_expand__internal_sandbox_identity_bootstrap.sql",
    ),
    (
        24,
        MigrationPhase.EXPAND,
        "http_session_security_v2",
        "0024_expand__http_session_security_v2.sql",
    ),
    (
        25,
        MigrationPhase.EXPAND,
        "demand_review_duty_authority_v2",
        "0025_expand__demand_review_duty_authority_v2.sql",
    ),
    (
        26,
        MigrationPhase.EXPAND,
        "internal_sandbox_independent_role_accounts",
        "0026_expand__internal_sandbox_independent_role_accounts.sql",
    ),
    (
        27,
        MigrationPhase.EXPAND,
        "internal_sandbox_account_workbench",
        "0027_expand__internal_sandbox_account_workbench.sql",
    ),
    (
        28,
        MigrationPhase.EXPAND,
        "policy_consent_oidc_time_evidence",
        "0028_expand__policy_consent_oidc_time_evidence.sql",
    ),
    (
        29,
        MigrationPhase.EXPAND,
        "policy_consent_notice_evidence",
        "0029_expand__policy_consent_notice_evidence.sql",
    ),
    (
        30,
        MigrationPhase.EXPAND,
        "internal_sandbox_platform_duty_admin",
        "0030_expand__internal_sandbox_platform_duty_admin.sql",
    ),
    (
        31,
        MigrationPhase.EXPAND,
        "finance_funding_authority_and_accounts",
        "0031_expand__finance_funding_authority_and_accounts.sql",
    ),
    (
        32,
        MigrationPhase.EXPAND,
        "internal_sandbox_account_admin_hardening",
        "0032_expand__internal_sandbox_account_admin_hardening.sql",
    ),
    (
        33,
        MigrationPhase.EXPAND,
        "internal_sandbox_org_admin_account",
        "0033_expand__internal_sandbox_org_admin_account.sql",
    ),
    (
        34,
        MigrationPhase.EXPAND,
        "organization_admin_management",
        "0034_expand__organization_admin_management.sql",
    ),
    (
        35,
        MigrationPhase.EXPAND,
        "organization_admin_contract_hardening",
        "0035_expand__organization_admin_contract_hardening.sql",
    ),
    (
        36,
        MigrationPhase.EXPAND,
        "trust_appeal_authority_and_current_logout",
        "0036_expand__trust_appeal_authority_and_current_logout.sql",
    ),
    (
        37,
        MigrationPhase.EXPAND,
        "finance_funding_review_authority_v2",
        "0037_expand__finance_funding_review_authority_v2.sql",
    ),
    (
        38,
        MigrationPhase.EXPAND,
        "owned_session_revocation",
        "0038_expand__owned_session_revocation.sql",
    ),
    (
        39,
        MigrationPhase.EXPAND,
        "invitation_oidc_enrollment",
        "0039_expand__invitation_oidc_enrollment.sql",
    ),
    (
        40,
        MigrationPhase.EXPAND,
        "invitation_enrollment_acceptance",
        "0040_expand__invitation_enrollment_acceptance.sql",
    ),
    (
        41,
        MigrationPhase.EXPAND,
        "acceptance_canonical_me_snapshot",
        "0041_expand__acceptance_canonical_me_snapshot.sql",
    ),
    (
        42,
        MigrationPhase.EXPAND,
        "organization_public_name_management",
        "0042_expand__organization_public_name_management.sql",
    ),
    (
        43,
        MigrationPhase.EXPAND,
        "demand_review_assignment_release_authority",
        "0043_expand__demand_review_assignment_release_authority.sql",
    ),
    (
        44,
        MigrationPhase.EXPAND,
        "candidate_selector_opt_in_authority",
        "0044_expand__candidate_selector_opt_in_authority.sql",
    ),
    (
        45,
        MigrationPhase.EXPAND,
        "matching_reviewer_authority",
        "0045_expand__matching_reviewer_authority.sql",
    ),
    (
        46,
        MigrationPhase.EXPAND,
        "matching_creator_authority",
        "0046_expand__matching_creator_authority.sql",
    ),
)

_MANIFEST_KEYS = ("component", "version", "phase", "name", "path", "sha256")
_MIGRATION_PATH = re.compile(
    r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z"
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")

# Reviewed digest of the exact restricted-canonical ``manifest.json`` bytes.
IAM_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5"
)


@dataclass(frozen=True)
class MigrationCatalog:
    artifacts: Tuple[MigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, migration_root: Path) -> "MigrationCatalog":
        root = Path(migration_root)
        root_fd = _open_catalog_root(root)
        try:
            manifest_bytes = _read_catalog_file(
                root_fd,
                "manifest.json",
                error_code="MIGRATION_MANIFEST_INVALID",
            )
            entries = _decode_manifest(manifest_bytes)
            _validate_paths(entries)
            _validate_layout(entries)

            artifacts = []
            for entry in entries:
                relative_path = entry["path"]
                sql_bytes = _read_catalog_file(
                    root_fd,
                    relative_path,
                    error_code="MIGRATION_PATH_INVALID",
                )
                _validate_sql_bytes(sql_bytes)
                checksum = hashlib.sha256(sql_bytes).digest()
                expected_checksum = bytes.fromhex(entry["sha256"])
                if not hmac.compare_digest(checksum, expected_checksum):
                    raise MigrationCatalogError("MIGRATION_CHECKSUM_MISMATCH")
                artifacts.append(
                    MigrationArtifact(
                        descriptor=MigrationDescriptor(
                            component="iam",
                            version=entry["version"],
                            phase=MigrationPhase(entry["phase"]),
                            name=entry["name"],
                            relative_path=relative_path,
                            checksum_sha256=checksum,
                        ),
                        sql_bytes=sql_bytes,
                    )
                )
        finally:
            os.close(root_fd)

        return cls(
            artifacts=tuple(artifacts),
            manifest_bytes=manifest_bytes,
            manifest_sha256=hashlib.sha256(manifest_bytes).digest(),
        )


def _open_catalog_root(root: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    root_fd = None
    try:
        root_fd = os.open(root, flags)
        root_stat = os.fstat(root_fd)
    except (OSError, TypeError, ValueError) as exc:
        if root_fd is not None:
            os.close(root_fd)
        raise MigrationCatalogError("MIGRATION_PATH_INVALID") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(root_fd)
        raise MigrationCatalogError("MIGRATION_PATH_INVALID")
    return root_fd


def _read_catalog_file(root_fd: int, relative_path: str, *, error_code: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    file_fd = None
    try:
        file_fd = os.open(relative_path, flags, dir_fd=root_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("catalog entry is not a regular file")
        stream = os.fdopen(file_fd, "rb", closefd=True)
        file_fd = None
        with stream:
            return stream.read()
    except (OSError, TypeError, ValueError) as exc:
        raise MigrationCatalogError(error_code) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _decode_manifest(manifest_bytes: bytes):
    if not _has_one_final_lf(manifest_bytes):
        raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")
    if manifest_bytes.startswith(b"\xef\xbb\xbf") or b"\r" in manifest_bytes:
        raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")
    try:
        manifest_text = manifest_bytes.decode("utf-8")
        entries = json.loads(
            manifest_text,
            object_pairs_hook=_decode_manifest_entry,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _ManifestInvalid) as exc:
        raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID") from exc
    if not isinstance(entries, list):
        raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")
    canonical_bytes = (
        json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        + b"\n"
    )
    if not hmac.compare_digest(manifest_bytes, canonical_bytes):
        raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")
    return entries


def _decode_manifest_entry(pairs):
    keys = tuple(key for key, _value in pairs)
    if keys != _MANIFEST_KEYS or len(set(keys)) != len(keys):
        raise _ManifestInvalid()
    return dict(pairs)


def _validate_paths(entries) -> None:
    for entry in entries:
        if not isinstance(entry, dict):
            raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")
        relative_path = entry.get("path")
        if not isinstance(relative_path, str) or not _MIGRATION_PATH.fullmatch(
            relative_path
        ):
            raise MigrationCatalogError("MIGRATION_PATH_INVALID")


def _validate_layout(entries) -> None:
    if len(entries) != len(IAM_MIGRATION_LAYOUT):
        raise MigrationCatalogError("MIGRATION_VERSION_SEQUENCE_INVALID")
    for entry, expected in zip(entries, IAM_MIGRATION_LAYOUT):
        version, phase, name, relative_path = expected
        if (
            type(entry.get("component")) is not str
            or type(entry.get("version")) is not int
            or type(entry.get("phase")) is not str
            or type(entry.get("name")) is not str
            or type(entry.get("sha256")) is not str
            or entry["component"] != "iam"
            or entry["version"] != version
            or entry["phase"] != phase.value
            or entry["name"] != name
            or entry["path"] != relative_path
        ):
            raise MigrationCatalogError("MIGRATION_VERSION_SEQUENCE_INVALID")
        if not _SHA256_HEX.fullmatch(entry["sha256"]):
            raise MigrationCatalogError("MIGRATION_MANIFEST_INVALID")


def _validate_sql_bytes(sql_bytes: bytes) -> None:
    if (
        not _has_one_final_lf(sql_bytes)
        or sql_bytes.startswith(b"\xef\xbb\xbf")
        or b"\r" in sql_bytes
        or b"\x00" in sql_bytes
    ):
        raise MigrationCatalogError("MIGRATION_SQL_ENCODING_INVALID")
    try:
        sql_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationCatalogError("MIGRATION_SQL_ENCODING_INVALID") from exc


def _has_one_final_lf(value: bytes) -> bool:
    return bool(value) and value.endswith(b"\n") and not value.endswith(b"\n\n")
