"""Closed, byte-exact catalog for independent Trust migrations."""

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


class TrustMigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class TrustMigrationCatalogError(RuntimeError):
    """Stable catalog rejection without filesystem or parser details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ManifestInvalid(ValueError):
    pass


@dataclass(frozen=True)
class TrustMigrationDescriptor:
    component: str
    version: int
    phase: TrustMigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes
    prefix_manifest_sha256: bytes


@dataclass(frozen=True)
class TrustMigrationArtifact:
    descriptor: TrustMigrationDescriptor
    sql_bytes: bytes


TRUST_MIGRATION_LAYOUT: Tuple[
    Tuple[int, TrustMigrationPhase, str, str], ...
] = (
    (
        1,
        TrustMigrationPhase.EXPAND,
        "demand_safety_case_v1",
        "0001_expand__demand_safety_case_v1.sql",
    ),
    (
        2,
        TrustMigrationPhase.EXPAND,
        "appeal_review_v1",
        "0002_expand__appeal_review_v1.sql",
    ),
    (
        3,
        TrustMigrationPhase.EXPAND,
        "appeal_runtime_policy_readiness_v1",
        "0003_expand__appeal_runtime_policy_readiness_v1.sql",
    ),
    (
        4,
        TrustMigrationPhase.EXPAND,
        "claim_receipt_http_status_v2",
        "0004_expand__claim_receipt_http_status_v2.sql",
    ),
    (
        5,
        TrustMigrationPhase.EXPAND,
        "demand9_dependency_repin",
        "0005_expand__demand9_dependency_repin.sql",
    ),
    (
        6,
        TrustMigrationPhase.EXPAND,
        "active_assignment_discovery",
        "0006_expand__active_assignment_discovery.sql",
    ),
    (
        7,
        TrustMigrationPhase.EXPAND,
        "iam37_demand10_dependency_repin",
        "0007_expand__iam37_demand10_dependency_repin.sql",
    ),
    (
        8,
        TrustMigrationPhase.EXPAND,
        "iam38_demand10_dependency_repin",
        "0008_expand__iam38_demand10_dependency_repin.sql",
    ),
    (
        9,
        TrustMigrationPhase.EXPAND,
        "owned_report_discovery",
        "0009_expand__owned_report_discovery.sql",
    ),
    (
        10,
        TrustMigrationPhase.EXPAND,
        "demand11_dependency_repin",
        "0010_expand__demand11_dependency_repin.sql",
    ),
    (
        11,
        TrustMigrationPhase.EXPAND,
        "completed_case_assignment_discovery",
        "0011_expand__completed_case_assignment_discovery.sql",
    ),
    (
        12,
        TrustMigrationPhase.EXPAND,
        "iam39_dependency_repin",
        "0012_expand__iam39_dependency_repin.sql",
    ),
    (
        13,
        TrustMigrationPhase.EXPAND,
        "iam40_dependency_repin",
        "0013_expand__iam40_dependency_repin.sql",
    ),
    (
        14,
        TrustMigrationPhase.EXPAND,
        "iam41_dependency_repin",
        "0014_expand__iam41_dependency_repin.sql",
    ),
    (
        15,
        TrustMigrationPhase.EXPAND,
        "iam42_dependency_repin",
        "0015_expand__iam42_dependency_repin.sql",
    ),
    (
        16,
        TrustMigrationPhase.EXPAND,
        "demand12_dependency_repin",
        "0016_expand__demand12_dependency_repin.sql",
    ),
    (
        17,
        TrustMigrationPhase.EXPAND,
        "completed_case_history_http_contract",
        "0017_expand__completed_case_history_http_contract.sql",
    ),
    (
        18,
        TrustMigrationPhase.EXPAND,
        "completed_appeal_review_history",
        "0018_expand__completed_appeal_review_history.sql",
    ),
    (
        19,
        TrustMigrationPhase.EXPAND,
        "iam43_demand13_dependency_repin",
        "0019_expand__iam43_demand13_dependency_repin.sql",
    ),
    (
        20,
        TrustMigrationPhase.EXPAND,
        "demand14_dependency_repin",
        "0020_expand__demand14_dependency_repin.sql",
    ),
    (
        21,
        TrustMigrationPhase.EXPAND,
        "iam45_demand15_dependency_repin",
        "0021_expand__iam45_demand15_dependency_repin.sql",
    ),
    (
        22,
        TrustMigrationPhase.EXPAND,
        "iam46_dependency_repin",
        "0022_expand__iam46_dependency_repin.sql",
    ),
)

# Reviewed full manifest pin; all earlier migration bytes remain immutable.
TRUST_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
)

_MANIFEST_KEYS = ("component", "version", "phase", "name", "path", "sha256")
_MIGRATION_PATH = re.compile(
    r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z"
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TrustMigrationCatalog:
    artifacts: Tuple[TrustMigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, migration_root: Path) -> "TrustMigrationCatalog":
        root_fd = _open_catalog_root(Path(migration_root))
        try:
            manifest_bytes = _read_catalog_file(
                root_fd,
                "manifest.json",
                error_code="TRUST_MIGRATION_MANIFEST_INVALID",
            )
            entries = _decode_manifest(manifest_bytes)
            _validate_paths(entries)
            _validate_layout(entries)
            artifacts = []
            for ordinal, entry in enumerate(entries, start=1):
                relative_path = entry["path"]
                sql_bytes = _read_catalog_file(
                    root_fd,
                    relative_path,
                    error_code="TRUST_MIGRATION_PATH_INVALID",
                )
                _validate_sql_bytes(sql_bytes)
                checksum = hashlib.sha256(sql_bytes).digest()
                if not hmac.compare_digest(
                    checksum,
                    bytes.fromhex(entry["sha256"]),
                ):
                    raise TrustMigrationCatalogError(
                        "TRUST_MIGRATION_CHECKSUM_MISMATCH"
                    )
                artifacts.append(
                    TrustMigrationArtifact(
                        descriptor=TrustMigrationDescriptor(
                            component="trust",
                            version=entry["version"],
                            phase=TrustMigrationPhase(entry["phase"]),
                            name=entry["name"],
                            relative_path=relative_path,
                            checksum_sha256=checksum,
                            prefix_manifest_sha256=hashlib.sha256(
                                json.dumps(
                                    entries[:ordinal],
                                    ensure_ascii=True,
                                    separators=(",", ":"),
                                ).encode("ascii")
                                + b"\n"
                            ).digest(),
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
    except (OSError, TypeError, ValueError) as error:
        if root_fd is not None:
            os.close(root_fd)
        raise TrustMigrationCatalogError("TRUST_MIGRATION_PATH_INVALID") from error
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(root_fd)
        raise TrustMigrationCatalogError("TRUST_MIGRATION_PATH_INVALID")
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
    except (OSError, TypeError, ValueError) as error:
        raise TrustMigrationCatalogError(error_code) from error
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _decode_manifest(manifest_bytes: bytes):
    if not _has_one_final_lf(manifest_bytes):
        raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")
    if manifest_bytes.startswith(b"\xef\xbb\xbf") or b"\r" in manifest_bytes:
        raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")
    try:
        entries = json.loads(
            manifest_bytes.decode("utf-8"),
            object_pairs_hook=_decode_manifest_entry,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _ManifestInvalid) as error:
        raise TrustMigrationCatalogError(
            "TRUST_MIGRATION_MANIFEST_INVALID"
        ) from error
    if not isinstance(entries, list):
        raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")
    canonical = (
        json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )
    if not hmac.compare_digest(manifest_bytes, canonical):
        raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")
    return entries


def _decode_manifest_entry(pairs):
    keys = tuple(key for key, _value in pairs)
    if keys != _MANIFEST_KEYS or len(set(keys)) != len(keys):
        raise _ManifestInvalid()
    return dict(pairs)


def _validate_paths(entries) -> None:
    for entry in entries:
        if not isinstance(entry, dict):
            raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")
        relative_path = entry.get("path")
        if not isinstance(relative_path, str) or _MIGRATION_PATH.fullmatch(
            relative_path
        ) is None:
            raise TrustMigrationCatalogError("TRUST_MIGRATION_PATH_INVALID")


def _validate_layout(entries) -> None:
    if len(entries) != len(TRUST_MIGRATION_LAYOUT):
        raise TrustMigrationCatalogError("TRUST_MIGRATION_VERSION_SEQUENCE_INVALID")
    for entry, expected in zip(entries, TRUST_MIGRATION_LAYOUT):
        version, phase, name, relative_path = expected
        if (
            type(entry.get("component")) is not str
            or type(entry.get("version")) is not int
            or type(entry.get("phase")) is not str
            or type(entry.get("name")) is not str
            or type(entry.get("sha256")) is not str
            or entry["component"] != "trust"
            or entry["version"] != version
            or entry["phase"] != phase.value
            or entry["name"] != name
            or entry["path"] != relative_path
        ):
            raise TrustMigrationCatalogError(
                "TRUST_MIGRATION_VERSION_SEQUENCE_INVALID"
            )
        if _SHA256_HEX.fullmatch(entry["sha256"]) is None:
            raise TrustMigrationCatalogError("TRUST_MIGRATION_MANIFEST_INVALID")


def _validate_sql_bytes(sql_bytes: bytes) -> None:
    if (
        not _has_one_final_lf(sql_bytes)
        or sql_bytes.startswith(b"\xef\xbb\xbf")
        or b"\r" in sql_bytes
        or b"\x00" in sql_bytes
    ):
        raise TrustMigrationCatalogError("TRUST_MIGRATION_SQL_ENCODING_INVALID")
    try:
        sql_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TrustMigrationCatalogError(
            "TRUST_MIGRATION_SQL_ENCODING_INVALID"
        ) from error


def _has_one_final_lf(value: bytes) -> bool:
    return bool(value) and value.endswith(b"\n") and not value.endswith(b"\n\n")
