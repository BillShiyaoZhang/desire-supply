"""Byte-exact independent Creator Profile PostgreSQL migration catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Tuple


class ProfileMigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class ProfileMigrationCatalogError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProfileMigrationDescriptor:
    component: str
    version: int
    phase: ProfileMigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes
    prefix_manifest_sha256: bytes


@dataclass(frozen=True)
class ProfileMigrationArtifact:
    descriptor: ProfileMigrationDescriptor
    sql_bytes: bytes


PROFILE_MIGRATION_LAYOUT: Tuple[
    Tuple[int, ProfileMigrationPhase, str, str], ...
] = (
    (
        1,
        ProfileMigrationPhase.EXPAND,
        "creator_profile_v1",
        "0001_expand__creator_profile_v1.sql",
    ),
    (
        2,
        ProfileMigrationPhase.EXPAND,
        "editor_target_discovery",
        "0002_expand__editor_target_discovery.sql",
    ),
    (
        3,
        ProfileMigrationPhase.EXPAND,
        "internal_sandbox_taxonomy_projection",
        "0003_expand__internal_sandbox_taxonomy_projection.sql",
    ),
    (
        4,
        ProfileMigrationPhase.EXPAND,
        "matching_input_capture",
        "0004_expand__matching_input_capture.sql",
    ),
    (
        5,
        ProfileMigrationPhase.EXPAND,
        "derived_matching_inputs",
        "0005_expand__derived_matching_inputs.sql",
    ),
)

# Updated atomically with the restricted-canonical manifest below.
PROFILE_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8"
)

_PATH = re.compile(r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ProfileMigrationCatalog:
    artifacts: Tuple[ProfileMigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, root: Path) -> "ProfileMigrationCatalog":
        migration_root = Path(root)
        try:
            manifest_bytes = (migration_root / "manifest.json").read_bytes()
        except OSError as error:
            raise ProfileMigrationCatalogError(
                "PROFILE_MIGRATION_PATH_INVALID"
            ) from error
        if (
            not manifest_bytes.endswith(b"\n")
            or manifest_bytes.endswith(b"\n\n")
            or b"\r" in manifest_bytes
            or manifest_bytes.startswith(b"\xef\xbb\xbf")
        ):
            raise ProfileMigrationCatalogError(
                "PROFILE_MIGRATION_MANIFEST_INVALID"
            )
        try:
            entries = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProfileMigrationCatalogError(
                "PROFILE_MIGRATION_MANIFEST_INVALID"
            ) from error
        canonical = (
            json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        if not hmac.compare_digest(canonical, manifest_bytes):
            raise ProfileMigrationCatalogError(
                "PROFILE_MIGRATION_MANIFEST_INVALID"
            )
        if not isinstance(entries, list) or len(entries) != len(
            PROFILE_MIGRATION_LAYOUT
        ):
            raise ProfileMigrationCatalogError(
                "PROFILE_MIGRATION_MANIFEST_INVALID"
            )

        artifacts = []
        for ordinal, (entry, expected) in enumerate(
            zip(entries, PROFILE_MIGRATION_LAYOUT),
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
                raise ProfileMigrationCatalogError(
                    "PROFILE_MIGRATION_MANIFEST_INVALID"
                )
            version, phase, name, relative_path = expected
            if entry != {
                "component": "profile",
                "version": version,
                "phase": phase.value,
                "name": name,
                "path": relative_path,
                "sha256": entry.get("sha256"),
            } or not isinstance(entry.get("sha256"), str) or not _SHA.fullmatch(
                entry["sha256"]
            ) or not _PATH.fullmatch(relative_path):
                raise ProfileMigrationCatalogError(
                    "PROFILE_MIGRATION_MANIFEST_INVALID"
                )
            candidate = migration_root / relative_path
            if candidate.parent != migration_root or candidate.is_symlink():
                raise ProfileMigrationCatalogError("PROFILE_MIGRATION_PATH_INVALID")
            try:
                sql_bytes = candidate.read_bytes()
            except OSError as error:
                raise ProfileMigrationCatalogError(
                    "PROFILE_MIGRATION_PATH_INVALID"
                ) from error
            if (
                not sql_bytes
                or not sql_bytes.endswith(b"\n")
                or b"\x00" in sql_bytes
                or b"\r" in sql_bytes
            ):
                raise ProfileMigrationCatalogError(
                    "PROFILE_MIGRATION_ARTIFACT_INVALID"
                )
            checksum = hashlib.sha256(sql_bytes).digest()
            if not hmac.compare_digest(checksum.hex(), entry["sha256"]):
                raise ProfileMigrationCatalogError(
                    "PROFILE_MIGRATION_CHECKSUM_MISMATCH"
                )
            artifacts.append(
                ProfileMigrationArtifact(
                    descriptor=ProfileMigrationDescriptor(
                        component="profile",
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
