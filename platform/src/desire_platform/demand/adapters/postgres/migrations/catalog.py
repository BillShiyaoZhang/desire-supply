"""Byte-exact independent Demand PostgreSQL migration catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Tuple


class DemandMigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class DemandMigrationCatalogError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class DemandMigrationDescriptor:
    component: str
    version: int
    phase: DemandMigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes
    prefix_manifest_sha256: bytes


@dataclass(frozen=True)
class DemandMigrationArtifact:
    descriptor: DemandMigrationDescriptor
    sql_bytes: bytes


DEMAND_MIGRATION_LAYOUT: Tuple[
    Tuple[int, DemandMigrationPhase, str, str], ...
] = (
    (
        1,
        DemandMigrationPhase.EXPAND,
        "demand_v1",
        "0001_expand__demand_v1.sql",
    ),
    (
        2,
        DemandMigrationPhase.EXPAND,
        "editor_target_discovery",
        "0002_expand__editor_target_discovery.sql",
    ),
    (
        3,
        DemandMigrationPhase.EXPAND,
        "internal_sandbox_review_queue",
        "0003_expand__internal_sandbox_review_queue.sql",
    ),
    (
        4,
        DemandMigrationPhase.EXPAND,
        "review_queue_null_hardening",
        "0004_expand__review_queue_null_hardening.sql",
    ),
    (
        5,
        DemandMigrationPhase.EXPAND,
        "review_queue_claim_lock_rls",
        "0005_expand__review_queue_claim_lock_rls.sql",
    ),
    (
        6,
        DemandMigrationPhase.EXPAND,
        "manual_finance_funding_review",
        "0006_expand__manual_finance_funding_review.sql",
    ),
    (
        7,
        DemandMigrationPhase.EXPAND,
        "owner_findings_and_finance_evidence",
        "0007_expand__owner_findings_and_finance_evidence.sql",
    ),
    (
        8,
        DemandMigrationPhase.EXPAND,
        "trust_target_and_conflict_bridge",
        "0008_expand__trust_target_and_conflict_bridge.sql",
    ),
    (
        9,
        DemandMigrationPhase.EXPAND,
        "completed_verify_receipt_replay",
        "0009_expand__completed_verify_receipt_replay.sql",
    ),
    (
        10,
        DemandMigrationPhase.EXPAND,
        "finance_funding_review_resolution",
        "0010_expand__finance_funding_review_resolution.sql",
    ),
    (
        11,
        DemandMigrationPhase.EXPAND,
        "reviewer_terminal_history",
        "0011_expand__reviewer_terminal_history.sql",
    ),
    (
        12,
        DemandMigrationPhase.EXPAND,
        "finance_funding_terminal_history",
        "0012_expand__finance_funding_terminal_history.sql",
    ),
    (
        13,
        DemandMigrationPhase.EXPAND,
        "review_assignment_release",
        "0013_expand__review_assignment_release.sql",
    ),
    (
        14,
        DemandMigrationPhase.EXPAND,
        "system_request_matching",
        "0014_expand__system_request_matching.sql",
    ),
    (
        15,
        DemandMigrationPhase.EXPAND,
        "matching_completion_and_delivery",
        "0015_expand__matching_completion_and_delivery.sql",
    ),
    (16, DemandMigrationPhase.EXPAND, "admin_demand_timeline", "0016_expand__admin_demand_timeline.sql"),
)

# Updated atomically with the restricted-canonical manifest.
DEMAND_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "4802d0ba44c05a059f3dfdbe0911e7be05cfd5d8508c8ced48a0a3f22bc1290f"
)

_PATH = re.compile(r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class DemandMigrationCatalog:
    artifacts: Tuple[DemandMigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, root: Path) -> "DemandMigrationCatalog":
        migration_root = Path(root)
        try:
            manifest_bytes = (migration_root / "manifest.json").read_bytes()
        except OSError as error:
            raise DemandMigrationCatalogError(
                "DEMAND_MIGRATION_PATH_INVALID"
            ) from error
        if (
            not manifest_bytes.endswith(b"\n")
            or manifest_bytes.endswith(b"\n\n")
            or b"\r" in manifest_bytes
            or manifest_bytes.startswith(b"\xef\xbb\xbf")
        ):
            raise DemandMigrationCatalogError(
                "DEMAND_MIGRATION_MANIFEST_INVALID"
            )
        try:
            entries = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DemandMigrationCatalogError(
                "DEMAND_MIGRATION_MANIFEST_INVALID"
            ) from error
        canonical = (
            json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        if not hmac.compare_digest(canonical, manifest_bytes):
            raise DemandMigrationCatalogError(
                "DEMAND_MIGRATION_MANIFEST_INVALID"
            )
        if not isinstance(entries, list) or len(entries) != len(
            DEMAND_MIGRATION_LAYOUT
        ):
            raise DemandMigrationCatalogError(
                "DEMAND_MIGRATION_MANIFEST_INVALID"
            )

        artifacts = []
        for ordinal, (entry, expected) in enumerate(
            zip(entries, DEMAND_MIGRATION_LAYOUT),
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
                raise DemandMigrationCatalogError(
                    "DEMAND_MIGRATION_MANIFEST_INVALID"
                )
            version, phase, name, relative_path = expected
            if (
                entry != {
                    "component": "demand",
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
                raise DemandMigrationCatalogError(
                    "DEMAND_MIGRATION_MANIFEST_INVALID"
                )
            candidate = migration_root / relative_path
            if candidate.parent != migration_root or candidate.is_symlink():
                raise DemandMigrationCatalogError("DEMAND_MIGRATION_PATH_INVALID")
            try:
                sql_bytes = candidate.read_bytes()
            except OSError as error:
                raise DemandMigrationCatalogError(
                    "DEMAND_MIGRATION_PATH_INVALID"
                ) from error
            if (
                not sql_bytes
                or not sql_bytes.endswith(b"\n")
                or b"\x00" in sql_bytes
                or b"\r" in sql_bytes
            ):
                raise DemandMigrationCatalogError(
                    "DEMAND_MIGRATION_ARTIFACT_INVALID"
                )
            checksum = hashlib.sha256(sql_bytes).digest()
            if not hmac.compare_digest(checksum.hex(), entry["sha256"]):
                raise DemandMigrationCatalogError(
                    "DEMAND_MIGRATION_CHECKSUM_MISMATCH"
                )
            artifacts.append(
                DemandMigrationArtifact(
                    descriptor=DemandMigrationDescriptor(
                        component="demand",
                        version=version,
                        phase=phase,
                        name=name,
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
        return cls(
            artifacts=tuple(artifacts),
            manifest_bytes=manifest_bytes,
            manifest_sha256=hashlib.sha256(manifest_bytes).digest(),
        )
