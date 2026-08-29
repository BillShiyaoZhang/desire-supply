"""Byte-exact independent Taxonomy PostgreSQL migration catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Tuple


class TaxonomyMigrationPhase(str, Enum):
    EXPAND = "expand"
    MIGRATE = "migrate"
    CONTRACT = "contract"


class TaxonomyMigrationCatalogError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class TaxonomyMigrationDescriptor:
    component: str
    version: int
    phase: TaxonomyMigrationPhase
    name: str
    relative_path: str
    checksum_sha256: bytes
    prefix_manifest_sha256: bytes


@dataclass(frozen=True)
class TaxonomyMigrationArtifact:
    descriptor: TaxonomyMigrationDescriptor
    sql_bytes: bytes


TAXONOMY_MIGRATION_LAYOUT: Tuple[
    Tuple[int, TaxonomyMigrationPhase, str, str], ...
] = (
    (
        1,
        TaxonomyMigrationPhase.EXPAND,
        "taxonomy_v1",
        "0001_expand__taxonomy_v1.sql",
    ),
    (
        2,
        TaxonomyMigrationPhase.EXPAND,
        "internal_sandbox_seed_authority",
        "0002_expand__internal_sandbox_seed_authority.sql",
    ),
)

# Filled atomically with the restricted-canonical manifest after SQL review.
TAXONOMY_REVIEWED_MANIFEST_SHA256 = bytes.fromhex(
    "74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622"
)

_PATH = re.compile(r"[0-9]{4}_(?:expand|migrate|contract)__[a-z0-9_]+\.sql\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TaxonomyMigrationCatalog:
    artifacts: Tuple[TaxonomyMigrationArtifact, ...]
    manifest_bytes: bytes
    manifest_sha256: bytes

    @classmethod
    def load(cls, root: Path) -> "TaxonomyMigrationCatalog":
        migration_root = Path(root)
        try:
            manifest_bytes = (migration_root / "manifest.json").read_bytes()
        except OSError as error:
            raise TaxonomyMigrationCatalogError(
                "TAXONOMY_MIGRATION_PATH_INVALID"
            ) from error
        if (
            not manifest_bytes.endswith(b"\n")
            or manifest_bytes.endswith(b"\n\n")
            or b"\r" in manifest_bytes
            or manifest_bytes.startswith(b"\xef\xbb\xbf")
        ):
            raise TaxonomyMigrationCatalogError(
                "TAXONOMY_MIGRATION_MANIFEST_INVALID"
            )
        try:
            entries = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TaxonomyMigrationCatalogError(
                "TAXONOMY_MIGRATION_MANIFEST_INVALID"
            ) from error
        canonical = (
            json.dumps(entries, ensure_ascii=True, separators=(",", ":"))
            .encode("ascii")
            + b"\n"
        )
        if not hmac.compare_digest(canonical, manifest_bytes):
            raise TaxonomyMigrationCatalogError(
                "TAXONOMY_MIGRATION_MANIFEST_INVALID"
            )
        if not isinstance(entries, list) or len(entries) != len(
            TAXONOMY_MIGRATION_LAYOUT
        ):
            raise TaxonomyMigrationCatalogError(
                "TAXONOMY_MIGRATION_MANIFEST_INVALID"
            )
        artifacts = []
        for ordinal, (entry, expected) in enumerate(
            zip(entries, TAXONOMY_MIGRATION_LAYOUT),
            start=1,
        ):
            if not isinstance(entry, dict) or tuple(entry) != (
                "component", "version", "phase", "name", "path", "sha256"
            ):
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_MANIFEST_INVALID"
                )
            version, phase, name, relative_path = expected
            if (
                entry.get("component") != "taxonomy"
                or entry.get("version") != version
                or entry.get("phase") != phase.value
                or entry.get("name") != name
                or entry.get("path") != relative_path
                or not isinstance(entry.get("sha256"), str)
                or _SHA.fullmatch(entry["sha256"]) is None
                or _PATH.fullmatch(relative_path) is None
            ):
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_MANIFEST_INVALID"
                )
            candidate = migration_root / relative_path
            if candidate.parent != migration_root or candidate.is_symlink():
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_PATH_INVALID"
                )
            try:
                sql_bytes = candidate.read_bytes()
            except OSError as error:
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_PATH_INVALID"
                ) from error
            if (
                not sql_bytes
                or not sql_bytes.endswith(b"\n")
                or b"\x00" in sql_bytes
                or b"\r" in sql_bytes
            ):
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_ARTIFACT_INVALID"
                )
            checksum = hashlib.sha256(sql_bytes).digest()
            if not hmac.compare_digest(checksum.hex(), entry["sha256"]):
                raise TaxonomyMigrationCatalogError(
                    "TAXONOMY_MIGRATION_CHECKSUM_MISMATCH"
                )
            artifacts.append(
                TaxonomyMigrationArtifact(
                    TaxonomyMigrationDescriptor(
                        "taxonomy",
                        version,
                        phase,
                        name,
                        relative_path,
                        checksum,
                        hashlib.sha256(
                            json.dumps(
                                entries[:ordinal],
                                ensure_ascii=True,
                                separators=(",", ":"),
                            ).encode("ascii")
                            + b"\n"
                        ).digest(),
                    ),
                    sql_bytes,
                )
            )
        return cls(
            tuple(artifacts),
            manifest_bytes,
            hashlib.sha256(manifest_bytes).digest(),
        )
