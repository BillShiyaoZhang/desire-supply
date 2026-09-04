"""Byte-exact independent Matching PostgreSQL migration catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Tuple


class MatchingMigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class MatchingMigrationCatalogError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MatchingMigrationDescriptor:
    component: str
    version: int
    phase: MatchingMigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes
    prefix_manifest_sha256: bytes


@dataclass(frozen=True)
class MatchingMigrationArtifact:
    descriptor: MatchingMigrationDescriptor
    sql_bytes: bytes


MATCHING_MIGRATION_LAYOUT: Tuple[
    Tuple[int, MatchingMigrationPhase, str, str], ...
] = (
    (
        1,
        MatchingMigrationPhase.EXPAND,
        "matching_v1",
        "0001_expand__matching_v1.sql",
    ),
    (
        2,
        MatchingMigrationPhase.EXPAND,
        "matching_runtime_v1",
        "0002_expand__matching_runtime_v1.sql",
    ),
    (
        3,
        MatchingMigrationPhase.EXPAND,
        "matching_operational_runtime_v1",
        "0003_expand__matching_operational_runtime_v1.sql",
    ),
    (
        4,
        MatchingMigrationPhase.EXPAND,
        "matching_ingest_name_resolution",
        "0004_expand__matching_ingest_name_resolution.sql",
    ),
    (
        5,
        MatchingMigrationPhase.EXPAND,
        "matching_coordinator_claim_scope",
        "0005_expand__matching_coordinator_claim_scope.sql",
    ),
    (
        6,
        MatchingMigrationPhase.EXPAND,
        "matching_review_claim_visibility",
        "0006_expand__matching_review_claim_visibility.sql",
    ),
    (
        7,
        MatchingMigrationPhase.EXPAND,
        "matching_create_invitation_receipt_probe",
        "0007_expand__matching_create_invitation_receipt_probe.sql",
    ),
    (
        8,
        MatchingMigrationPhase.EXPAND,
        "matching_disclosure_utc_timestamp",
        "0008_expand__matching_disclosure_utc_timestamp.sql",
    ),
    (
        9,
        MatchingMigrationPhase.EXPAND,
        "matching_completion_intent_receipt_visibility",
        "0009_expand__matching_completion_intent_receipt_visibility.sql",
    ),
    (
        10,
        MatchingMigrationPhase.EXPAND,
        "iam47_trust23_dependency_repin",
        "0010_expand__iam47_trust23_dependency_repin.sql",
    ),
)

# Updated atomically with the restricted-canonical manifest.
MATCHING_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "83547a319fb2d1e5cc88131570fc889ac795b0dd30643e9bca565058226f2cb6"
)

_PATH = re.compile(r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class MatchingMigrationCatalog:
    artifacts: Tuple[MatchingMigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, root: Path) -> "MatchingMigrationCatalog":
        migration_root = Path(root)
        try:
            manifest_bytes = (migration_root / "manifest.json").read_bytes()
        except OSError as error:
            raise MatchingMigrationCatalogError(
                "MATCHING_MIGRATION_PATH_INVALID"
            ) from error
        if (
            not manifest_bytes.endswith(b"\n")
            or manifest_bytes.endswith(b"\n\n")
            or b"\r" in manifest_bytes
            or manifest_bytes.startswith(b"\xef\xbb\xbf")
        ):
            raise MatchingMigrationCatalogError(
                "MATCHING_MIGRATION_MANIFEST_INVALID"
            )
        try:
            entries = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MatchingMigrationCatalogError(
                "MATCHING_MIGRATION_MANIFEST_INVALID"
            ) from error
        canonical = (
            json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        if not hmac.compare_digest(canonical, manifest_bytes):
            raise MatchingMigrationCatalogError(
                "MATCHING_MIGRATION_MANIFEST_INVALID"
            )
        if not isinstance(entries, list) or len(entries) != len(
            MATCHING_MIGRATION_LAYOUT
        ):
            raise MatchingMigrationCatalogError(
                "MATCHING_MIGRATION_MANIFEST_INVALID"
            )

        artifacts = []
        for ordinal, (entry, expected) in enumerate(
            zip(entries, MATCHING_MIGRATION_LAYOUT),
            start=1,
        ):
            if not isinstance(entry, dict) or tuple(entry) != (
                "component",
                "version",
                "phase",
                "name",
                "path",
                "sha256",
            ):
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_MANIFEST_INVALID"
                )
            version, phase, name, relative_path = expected
            if (
                entry
                != {
                    "component": "matching",
                    "version": version,
                    "phase": phase.value,
                    "name": name,
                    "path": relative_path,
                    "sha256": entry.get("sha256"),
                }
                or not isinstance(entry.get("sha256"), str)
                or not _SHA.fullmatch(entry["sha256"])
                or not _PATH.fullmatch(relative_path)
            ):
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_MANIFEST_INVALID"
                )
            candidate = migration_root / relative_path
            if candidate.parent != migration_root or candidate.is_symlink():
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_PATH_INVALID"
                )
            try:
                sql_bytes = candidate.read_bytes()
                sql_bytes.decode("utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_ARTIFACT_INVALID"
                ) from error
            if (
                not sql_bytes
                or not sql_bytes.endswith(b"\n")
                or sql_bytes.endswith(b"\n\n")
                or b"\x00" in sql_bytes
                or b"\r" in sql_bytes
                or sql_bytes.startswith(b"\xef\xbb\xbf")
            ):
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_ARTIFACT_INVALID"
                )
            checksum = hashlib.sha256(sql_bytes).digest()
            if not hmac.compare_digest(checksum.hex(), entry["sha256"]):
                raise MatchingMigrationCatalogError(
                    "MATCHING_MIGRATION_CHECKSUM_MISMATCH"
                )
            prefix_manifest = (
                json.dumps(
                    entries[:ordinal],
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            )
            artifacts.append(
                MatchingMigrationArtifact(
                    descriptor=MatchingMigrationDescriptor(
                        component="matching",
                        version=version,
                        phase=phase,
                        name=name,
                        relative_path=relative_path,
                        checksum_sha256=checksum,
                        prefix_manifest_sha256=hashlib.sha256(
                            prefix_manifest
                        ).digest(),
                    ),
                    sql_bytes=sql_bytes,
                )
            )
        return cls(
            artifacts=tuple(artifacts),
            manifest_bytes=manifest_bytes,
            manifest_sha256=hashlib.sha256(manifest_bytes).digest(),
        )
