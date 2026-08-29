from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from desire_platform.internal_pilot.deployment_config import (
    parse_internal_sandbox_deployment_config,
)
from desire_platform.internal_pilot.production_plan import (
    INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS,
    INTERNAL_SANDBOX_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_KEY_PURPOSES,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES,
    INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES,
)
from desire_platform.internal_pilot.secrets import parse_file_secret_manifest
from desire_platform.runtime.config import parse_runtime_config


NOW = datetime(2026, 8, 12, 12, 0, 0, tzinfo=timezone.utc)
CLIENT_SECRET = b"synthetic-oidc-client-secret-material-v1"


def _material(purpose: str, length: int) -> bytes:
    value = hashlib.sha512(("bundle-test:" + purpose).encode("ascii")).hexdigest()
    return value[:length].encode("ascii")


def test_creates_one_closed_atomic_bundle_with_distinct_purpose_material(tmp_path: Path) -> None:
    from desire_platform.deployment.internal_sandbox_bundle import (
        InternalSandboxBundleRequest,
        create_internal_sandbox_bundle,
    )

    client_secret = tmp_path / "provider-client-secret"
    client_secret.write_bytes(CLIENT_SECRET)
    client_secret.chmod(0o600)
    output = tmp_path / "runtime-bundle"

    report = create_internal_sandbox_bundle(
        InternalSandboxBundleRequest(
            output_dir=output,
            oidc_issuer="https://identity.example.test/tenant",
            oidc_client_id="desire-internal-sandbox",
            oidc_redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
            oidc_client_secret_file=client_secret,
            oidc_network_binding_mode="SYSTEM_DNS_SYNTHETIC",
            oidc_pinned_public_ipv4=None,
            deployment_id="sandbox-20260812",
            release_id="release-20260812-01",
        ),
        clock=lambda: NOW,
        material_factory=_material,
    )

    assert report.output_dir == output.resolve()
    assert report.secret_count == 53
    assert report.database_credential_count == len(
        INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES
    )
    assert report.key_count == report.secret_count - report.database_credential_count
    assert report.system_actor_id.int != 0
    assert "secret" not in repr(report).lower()

    config = output / "config"
    secrets = output / "runtime-secrets"
    deployment = parse_internal_sandbox_deployment_config(
        (config / "deployment.json").read_bytes()
    )
    runtime = parse_runtime_config((config / "runtime-config.json").read_bytes())
    entries = parse_file_secret_manifest((config / "secret-manifest.json").read_bytes())
    matching_runtime = parse_runtime_config(
        (config / "matching-runtime-config.json").read_bytes()
    )
    matching_entries = parse_file_secret_manifest(
        (config / "matching-secret-manifest.json").read_bytes()
    )
    online_runtime = parse_runtime_config(
        (config / "online-credentials-runtime-config.json").read_bytes()
    )
    online_entries = parse_file_secret_manifest(
        (config / "online-credentials-secret-manifest.json").read_bytes()
    )
    matching_deployment = parse_internal_sandbox_deployment_config(
        (config / "matching-deployment.json").read_bytes()
    )
    online_deployment = parse_internal_sandbox_deployment_config(
        (config / "online-credentials-deployment.json").read_bytes()
    )

    assert deployment.oidc.issuer == "https://identity.example.test/tenant"
    assert deployment.oidc.redirect_uri.endswith("/v1/auth/oidc/callback")
    assert deployment.oidc.network_binding.mode == "SYSTEM_DNS_SYNTHETIC"
    assert deployment.runtime_config_path == "/run/desire/runtime-config.json"
    assert deployment.secret_manifest_path == "/run/desire/secret-manifest.json"
    assert deployment.secret_root == "/run/secrets"
    assert runtime.process.capability_ids == tuple(
        item[0] for item in INTERNAL_SANDBOX_CAPABILITY_ROLES
    )
    assert matching_runtime.process.kind == "domain-process"
    assert matching_runtime.process.capability_ids == tuple(
        item[0] for item in INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
    )
    assert tuple(
        item.purpose for item in matching_runtime.key_requirements
    ) == INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
    assert online_runtime.process.kind == "migration"
    assert online_runtime.process.capability_ids == tuple(
        item[0] for item in INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES
    )
    assert online_runtime.key_requirements == ()
    assert matching_deployment.runtime_config_path.endswith(
        "/matching-runtime-config.json"
    )
    assert matching_deployment.secret_manifest_path.endswith(
        "/matching-secret-manifest.json"
    )
    assert online_deployment.runtime_config_path.endswith(
        "/online-credentials-runtime-config.json"
    )
    assert online_deployment.secret_manifest_path.endswith(
        "/online-credentials-secret-manifest.json"
    )
    assert runtime.artifacts == INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
    assert tuple(item.purpose for item in runtime.key_requirements) == (
        INTERNAL_SANDBOX_KEY_PURPOSES
    )
    database_count = len(INTERNAL_SANDBOX_CAPABILITY_ROLES)
    assert tuple(item.kind for item in entries[:database_count]) == (
        "DATABASE_CREDENTIAL",
    ) * database_count
    assert tuple(item.purpose for item in entries[database_count:]) == tuple(
        requirement.purpose
        for requirement in runtime.key_requirements
        for _key_id in requirement.retained_key_ids
    )
    trust_profiles = tuple(
        (profile.capability_id, profile.online_role)
        for profile in runtime.database_profiles
        if profile.capability_id.startswith("TRUST_")
    )
    assert trust_profiles == (
        ("TRUST_SELF", "trust_self"),
        ("TRUST_OFFICER", "trust_officer"),
        ("TRUST_APPEAL", "trust_appeal"),
        ("TRUST_DECISION", "trust_decision"),
    )
    assert tuple(entry.file_name for entry in entries[7:11]) == (
        "db-trust-self-v1",
        "db-trust-officer-v1",
        "db-trust-appeal-v1",
        "db-trust-decision-v1",
    )
    matching_profiles = tuple(
        (profile.capability_id, profile.online_role)
        for profile in runtime.database_profiles
        if profile.capability_id.startswith("MATCHING_")
    )
    assert matching_profiles == (
        ("MATCHING_CREATOR", "matching_creator"),
        ("MATCHING_SELECTOR", "matching_selector"),
        ("MATCHING_ASSIGNMENT", "matching_assignment"),
        ("MATCHING_REVIEW", "matching_review"),
    )
    assert tuple(
        (profile.capability_id, profile.online_role)
        for profile in matching_runtime.database_profiles
    ) == INTERNAL_SANDBOX_MATCHING_RUNTIME_CAPABILITY_ROLES
    assert tuple(entry.kind for entry in online_entries) == (
        "DATABASE_CREDENTIAL",
    ) * len(INTERNAL_SANDBOX_ONLINE_CAPABILITY_ROLES)
    assert tuple(entry.purpose for entry in matching_entries[-6:]) == (
        INTERNAL_SANDBOX_MATCHING_RUNTIME_KEY_PURPOSES
    )
    api_database_files = {
        entry.file_name for entry in entries if entry.kind == "DATABASE_CREDENTIAL"
    }
    worker_only_database_files = {
        entry.file_name
        for entry in matching_entries
        if entry.kind == "DATABASE_CREDENTIAL"
        and entry.purpose != "DATABASE_CREDENTIAL:TRUST_DECISION"
    }
    assert api_database_files.isdisjoint(worker_only_database_files)

    values = [(secrets / entry.file_name).read_bytes() for entry in entries]
    assert len({hashlib.sha256(value).digest() for value in values}) == len(values)
    client_entry = next(item for item in entries if item.purpose == "OIDC_CLIENT_SECRET")
    assert (secrets / client_entry.file_name).read_bytes() == CLIENT_SECRET
    aead_entry = next(item for item in entries if item.purpose == "OIDC_PROTOCOL_AEAD")
    assert len((secrets / aead_entry.file_name).read_bytes()) == 32
    platform_user_idempotency = next(
        item
        for item in entries
        if item.purpose == "PLATFORM_USER_IDEMPOTENCY"
    )
    platform_user_payload = next(
        item
        for item in entries
        if item.purpose == "PLATFORM_USER_PAYLOAD_HASH"
    )
    assert (
        platform_user_idempotency.key_id
        == "iam-receipt-idempotency-hmac-2026-01"
    )
    assert platform_user_payload.key_id == "iam-receipt-payload-hmac-2026-01"
    demand_idempotency = tuple(
        item for item in entries if item.purpose == "DEMAND_IDEMPOTENCY"
    )
    demand_payload = tuple(
        item for item in entries if item.purpose == "DEMAND_PAYLOAD_HASH"
    )
    assert tuple(item.key_id for item in demand_idempotency) == (
        "demand-idempotency-2026-01",
        "demand-idempotency-retained-2025-12",
    )
    assert tuple(item.key_id for item in demand_payload) == (
        "demand-payload-2026-01",
        "demand-payload-retained-2025-12",
    )
    # Compose secret source names remain stable while the manifest owns the
    # cryptographic key identity carried into durable Demand receipts.
    assert tuple(item.file_name for item in demand_idempotency) == (
        "key-demand-idempotency-v1",
        "key-demand-idempotency-retained-2025-12",
    )
    assert tuple(item.file_name for item in demand_payload) == (
        "key-demand-payload-hash-v1",
        "key-demand-payload-retained-2025-12",
    )
    assert tuple(item.status for item in demand_idempotency) == (
        "ACTIVE",
        "VERIFY_ONLY",
    )
    assert tuple(item.status for item in demand_payload) == (
        "ACTIVE",
        "VERIFY_ONLY",
    )
    demand_requirements = {
        item.purpose: item
        for item in runtime.key_requirements
        if item.purpose in {"DEMAND_IDEMPOTENCY", "DEMAND_PAYLOAD_HASH"}
    }
    assert demand_requirements["DEMAND_IDEMPOTENCY"].retained_key_ids == tuple(
        item.key_id for item in demand_idempotency
    )
    assert demand_requirements["DEMAND_PAYLOAD_HASH"].retained_key_ids == tuple(
        item.key_id for item in demand_payload
    )
    demand_ids = tuple(
        item.key_id for item in demand_idempotency + demand_payload
    )
    assert len(demand_ids) == len(set(demand_ids)) == 4
    demand_materials = tuple(
        (secrets / item.file_name).read_bytes()
        for item in demand_idempotency + demand_payload
    )
    assert len({hashlib.sha256(value).digest() for value in demand_materials}) == 4
    trust_idempotency = next(
        item for item in entries if item.purpose == "TRUST_IDEMPOTENCY"
    )
    trust_payload = next(
        item for item in entries if item.purpose == "TRUST_PAYLOAD_HASH"
    )
    trust_sealed_note = next(
        item for item in entries if item.purpose == "TRUST_SEALED_NOTE"
    )
    assert trust_idempotency.key_id == "trust-idempotency-2026-01"
    assert trust_payload.key_id == "trust-payload-2026-01"
    assert trust_sealed_note.key_id == "trust-sealed-note-v1"
    assert trust_idempotency.file_name == "key-trust-idempotency-v1"
    assert trust_payload.file_name == "key-trust-payload-hash-v1"
    assert trust_sealed_note.file_name == "key-trust-sealed-note-v1"
    trust_requirements = tuple(
        requirement
        for requirement in runtime.key_requirements
        if requirement.purpose.startswith("TRUST_")
    )
    assert all(
        requirement.retained_key_ids == (requirement.active_key_id,)
        for requirement in trust_requirements
    )
    assert all(
        entry.status == "ACTIVE"
        for entry in entries
        if entry.purpose.startswith("TRUST_")
    )
    assert (
        secrets / platform_user_idempotency.file_name
    ).read_bytes() != (secrets / platform_user_payload.file_name).read_bytes()
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in config.iterdir())
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in secrets.iterdir())
    assert (output.stat().st_mode & 0o777) == 0o700
    assert (config.stat().st_mode & 0o777) == 0o700
    assert (secrets.stat().st_mode & 0o777) == 0o700


def test_rejects_existing_target_insecure_input_and_partial_output(tmp_path: Path) -> None:
    from desire_platform.deployment.internal_sandbox_bundle import (
        InternalSandboxBundleError,
        InternalSandboxBundleRequest,
        create_internal_sandbox_bundle,
    )

    client_secret = tmp_path / "provider-client-secret"
    client_secret.write_bytes(CLIENT_SECRET)
    client_secret.chmod(0o644)
    output = tmp_path / "runtime-bundle"
    request = InternalSandboxBundleRequest(
        output_dir=output,
        oidc_issuer="https://identity.example.test/tenant",
        oidc_client_id="desire-internal-sandbox",
        oidc_redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
        oidc_client_secret_file=client_secret,
        oidc_network_binding_mode="SYSTEM_DNS_SYNTHETIC",
        oidc_pinned_public_ipv4=None,
        deployment_id="sandbox-20260812",
        release_id="release-20260812-01",
    )

    with pytest.raises(InternalSandboxBundleError) as insecure:
        create_internal_sandbox_bundle(request, clock=lambda: NOW)
    assert insecure.value.code == "INTERNAL_SANDBOX_BUNDLE_CLIENT_SECRET_INVALID"
    assert not output.exists()

    client_secret.chmod(0o600)
    output.mkdir()
    marker = output / "belongs-to-user"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(InternalSandboxBundleError) as existing:
        create_internal_sandbox_bundle(request, clock=lambda: NOW)
    assert existing.value.code == "INTERNAL_SANDBOX_BUNDLE_TARGET_EXISTS"
    assert marker.read_text(encoding="utf-8") == "keep"


def test_cli_prints_only_non_secret_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from desire_platform.deployment.internal_sandbox_bundle import main

    client_secret = tmp_path / "provider-client-secret"
    client_secret.write_bytes(CLIENT_SECRET)
    client_secret.chmod(0o600)
    output = tmp_path / "runtime-bundle"

    exit_code = main(
        [
            "create",
            "--output-dir",
            str(output),
            "--oidc-issuer",
            "https://identity.example.test/tenant",
            "--oidc-client-id",
            "desire-internal-sandbox",
            "--oidc-redirect-uri",
            "https://pilot.example.test/v1/auth/oidc/callback",
            "--oidc-client-secret-file",
            str(client_secret),
            "--oidc-network-binding-mode",
            "SYSTEM_DNS_SYNTHETIC",
            "--deployment-id",
            "sandbox-20260812",
            "--release-id",
            "release-20260812-01",
        ],
        clock=lambda: NOW,
        material_factory=_material,
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    document = json.loads(captured.out)
    assert document == {
        "database_credential_count": 19,
        "key_count": 34,
        "output_dir": str(output.resolve()),
        "secret_count": 53,
        "status": "INTERNAL_SANDBOX_BUNDLE_CREATED",
    }
    assert CLIENT_SECRET.decode("ascii") not in captured.out + captured.err
