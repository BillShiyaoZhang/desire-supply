from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile

import pytest

from desire_platform.trust_safety.adapters.postgres.migrations import (
    TRUST_MIGRATION_LAYOUT,
    TrustMigrationCatalog,
    TrustMigrationCatalogError,
    TrustMigrationDescriptor,
    TrustMigrationPhase,
)


def _write_valid(root: Path) -> tuple[bytes, tuple[bytes, ...]]:
    sql_values = tuple(
        f"SELECT 'trust-v{version}';\n".encode("ascii")
        for version, _phase, _name, _relative_path in TRUST_MIGRATION_LAYOUT
    )
    entries = []
    for (version, phase, name, relative_path), sql_bytes in zip(
        TRUST_MIGRATION_LAYOUT, sql_values
    ):
        (root / relative_path).write_bytes(sql_bytes)
        entries.append(
            {
                "component": "trust",
                "version": version,
                "phase": phase.value,
                "name": name,
                "path": relative_path,
                "sha256": hashlib.sha256(sql_bytes).hexdigest(),
            }
        )
    manifest_bytes = json.dumps(
        entries,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    (root / "manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes, sql_values


def test_catalog_is_independent_contiguous_and_immutable() -> None:
    assert TRUST_MIGRATION_LAYOUT == (
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
    )
    descriptor = TrustMigrationDescriptor(
        component="trust",
        version=1,
        phase=TrustMigrationPhase.EXPAND,
        name="demand_safety_case_v1",
        relative_path="0001_expand__demand_safety_case_v1.sql",
        checksum_sha256=b"x" * 32,
        prefix_manifest_sha256=b"m" * 32,
    )
    with pytest.raises(FrozenInstanceError):
        descriptor.version = 2  # type: ignore[misc]


def test_catalog_preserves_exact_canonical_bytes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest_bytes, sql_values = _write_valid(root)
        catalog = TrustMigrationCatalog.load(root)
    assert catalog.manifest_bytes == manifest_bytes
    assert catalog.manifest_sha256 == hashlib.sha256(manifest_bytes).digest()
    assert tuple(value.sql_bytes for value in catalog.artifacts) == sql_values
    assert catalog.artifacts[0].descriptor.component == "trust"
    entries = json.loads(manifest_bytes)
    prefix_bytes = json.dumps(
        entries[:1], ensure_ascii=True, separators=(",", ":")
    ).encode("ascii") + b"\n"
    assert catalog.artifacts[0].descriptor.prefix_manifest_sha256 == (
        hashlib.sha256(prefix_bytes).digest()
    )
    assert catalog.artifacts[-1].descriptor.prefix_manifest_sha256 == (
        catalog.manifest_sha256
    )


def test_reviewed_catalog_preserves_the_frozen_trust0001_through_0007_prefix() -> None:
    root = (
        Path(__file__).resolve().parents[3]
        / "src/desire_platform/trust_safety/adapters/postgres/migrations"
    )
    catalog = TrustMigrationCatalog.load(root)
    assert catalog.artifacts[0].descriptor.prefix_manifest_sha256.hex() == (
        "9bd2be5ccbf62824569b07505e53902e3775675cdfa684524d0ba503846a2c13"
    )
    assert catalog.artifacts[1].descriptor.prefix_manifest_sha256.hex() == (
        "94a1e604044ea60845c44d191cd75c9794cd19731f2b8a52e28547e7172ddf93"
    )
    assert catalog.artifacts[2].descriptor.prefix_manifest_sha256.hex() == (
        "141057a29520dd4027570dda20c95e305053bbb2bb6f8d5a145e5e5b2d8e4863"
    )
    assert catalog.artifacts[3].descriptor.prefix_manifest_sha256.hex() == (
        "4bd6f0e8367e7853adccc28cf868fda1b3cf00b678c252b1d1ae635b422837a8"
    )
    assert catalog.artifacts[4].descriptor.prefix_manifest_sha256.hex() == (
        "8b02df9ea6717265e3d69d22b837c9b5455ebab74cebe0c6a112d15de22b1c04"
    )
    assert catalog.artifacts[5].descriptor.prefix_manifest_sha256.hex() == (
        "05a731b5ce1418e444384b765a22874173e200c3d03005276b507802a9b38415"
    )
    assert catalog.artifacts[6].descriptor.prefix_manifest_sha256.hex() == (
        "27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124"
    )


@pytest.mark.parametrize(
    "mutation,code",
    (
        (lambda value: value[:-1], "TRUST_MIGRATION_MANIFEST_INVALID"),
        (lambda value: value.replace(b"\n", b"\r\n"), "TRUST_MIGRATION_MANIFEST_INVALID"),
        (lambda value: b" " + value, "TRUST_MIGRATION_MANIFEST_INVALID"),
        (
            lambda value: value.replace(
                b'"component":"trust",',
                b'"component":"trust","component":"trust",',
            ),
            "TRUST_MIGRATION_MANIFEST_INVALID",
        ),
    ),
)
def test_manifest_encoding_and_duplicate_keys_fail_closed(mutation, code: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest_bytes, _ = _write_valid(root)
        (root / "manifest.json").write_bytes(mutation(manifest_bytes))
        with pytest.raises(TrustMigrationCatalogError) as raised:
            TrustMigrationCatalog.load(root)
    assert raised.value.code == code


@pytest.mark.parametrize(
    "entry_index", tuple(range(len(TRUST_MIGRATION_LAYOUT)))
)
def test_path_escape_symlink_and_checksum_drift_fail_closed(
    entry_index: int,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest_bytes, _ = _write_valid(root)
        relative_path = TRUST_MIGRATION_LAYOUT[entry_index][3]
        escaped = manifest_bytes.replace(
            f'"path":"{relative_path}"'.encode("ascii"),
            f'"path":"../{relative_path}"'.encode("ascii"),
        )
        (root / "manifest.json").write_bytes(escaped)
        with pytest.raises(TrustMigrationCatalogError) as raised:
            TrustMigrationCatalog.load(root)
        assert raised.value.code == "TRUST_MIGRATION_PATH_INVALID"

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _, sql_values = _write_valid(root)
        target = root / "unreviewed.sql"
        target.write_bytes(sql_values[entry_index])
        artifact = root / TRUST_MIGRATION_LAYOUT[entry_index][3]
        artifact.unlink()
        artifact.symlink_to(target)
        with pytest.raises(TrustMigrationCatalogError) as raised:
            TrustMigrationCatalog.load(root)
        assert raised.value.code == "TRUST_MIGRATION_PATH_INVALID"

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_valid(root)
        (root / TRUST_MIGRATION_LAYOUT[entry_index][3]).write_bytes(
            b"SELECT 'changed';\n"
        )
        with pytest.raises(TrustMigrationCatalogError) as raised:
            TrustMigrationCatalog.load(root)
        assert raised.value.code == "TRUST_MIGRATION_CHECKSUM_MISMATCH"
