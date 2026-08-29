"""Closed manifest generation for fictional INTERNAL_SANDBOX identities."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict

import pytest

from desire_platform.deployment.identity_bootstrap import (
    parse_internal_sandbox_identity_manifest,
)
from desire_platform.deployment.identity_bootstrap_manifest import (
    IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    IdentityBootstrapManifestGenerationError,
    generate_internal_sandbox_identity_manifest,
    main,
)
from desire_platform.deployment import identity_bootstrap_manifest as manifest_module
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)
from tests.support.identity_bootstrap_builders import identity_bootstrap_document


ISSUER = "https://identity.example.test/tenant"
SUBJECT_KEY = bytearray(b"s" * 32)
RECIPIENT_KEY = bytearray(b"r" * 32)
SUBJECT_KEY_ID = "oidc-subject-digest-v1"
RECIPIENT_KEY_ID = "oidc-recipient-binding-v1"
PLATFORM_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_TEMPLATE = (
    PLATFORM_ROOT
    / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
)
EXAMPLE_TEMPLATE_SHA256 = (
    "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942"
)


def _canonical(document: Dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _template_document() -> Dict[str, Any]:
    document = identity_bootstrap_document()
    document.pop("issuer")
    document["schema_name"] = (
        "desire-internal-sandbox-identity-bootstrap-template-v1"
    )
    for account in document["accounts"]:
        code = account["account_code"]
        account["external_identity"] = {
            "id": account["external_identity"]["id"],
            "subject_file_name": code + ".subject",
        }
        account["contact_point"] = {
            "id": account["contact_point"]["id"],
            "verified_email_file_name": code + ".email",
        }
    return document


def _sources(*, collision: bool = False):
    values = {
        "access_admin_01.subject": bytearray(b"sandbox:access-admin-01"),
        "access_admin_01.email": bytearray(
            b"sandbox-access-admin-01@example.test"
        ),
        "creator_01.subject": bytearray(b"sandbox:creator-01"),
        "creator_01.email": bytearray(b"sandbox-creator-01@example.test"),
        "demand_owner_01.subject": bytearray(b"sandbox:demand-owner-01"),
        "demand_owner_01.email": bytearray(
            b"sandbox-demand-owner-01@example.test"
        ),
        "finance_operator_01.subject": bytearray(
            b"sandbox:finance-operator-01"
        ),
        "finance_operator_01.email": bytearray(
            b"sandbox-finance-operator-01@example.test"
        ),
        "finance_operator_02.subject": bytearray(
            b"sandbox:finance-operator-02"
        ),
        "finance_operator_02.email": bytearray(
            b"sandbox-finance-operator-02@example.test"
        ),
        "operations_reviewer_01.subject": bytearray(
            b"sandbox:operations-reviewer-01"
        ),
        "operations_reviewer_01.email": bytearray(
            b"sandbox-operations-reviewer-01@example.test"
        ),
        "trust_officer_01.subject": bytearray(b"sandbox:trust-officer-01"),
        "trust_officer_01.email": bytearray(
            b"sandbox-trust-officer-01@example.test"
        ),
        "trust_officer_02.subject": bytearray(b"sandbox:trust-officer-02"),
        "trust_officer_02.email": bytearray(
            b"sandbox-trust-officer-02@example.test"
        ),
        "appeal_reviewer_01.subject": bytearray(
            b"sandbox:appeal-reviewer-01"
        ),
        "appeal_reviewer_01.email": bytearray(
            b"sandbox-appeal-reviewer-01@example.test"
        ),
        "org_admin_01.subject": bytearray(b"sandbox:org-admin-01"),
        "org_admin_01.email": bytearray(
            b"sandbox-org-admin-01@example.test"
        ),
    }
    if collision:
        values["trust_officer_02.subject"] = bytearray(
            b"sandbox:access-admin-01"
        )
    return values


def test_generator_matches_production_oidc_domains_and_zeroizes_raw_sources() -> None:
    template = _canonical(_template_document())
    sources = _sources()
    raw_values = tuple(sources.values())
    generated = generate_internal_sandbox_identity_manifest(
        template_bytes=template,
        expected_template_sha256=hashlib.sha256(template).hexdigest(),
        issuer=ISSUER,
        subject_digest_key_id=SUBJECT_KEY_ID,
        subject_digest_key=bytearray(SUBJECT_KEY),
        recipient_binding_key_id=RECIPIENT_KEY_ID,
        recipient_binding_key=bytearray(RECIPIENT_KEY),
        read_source=lambda file_name: sources[file_name],
    )
    parsed = parse_internal_sandbox_identity_manifest(
        generated.canonical_bytes,
        expected_sha256=generated.manifest_sha256,
        expected_issuer=ISSUER,
    )
    expected_subject = hmac.new(
        bytes(SUBJECT_KEY),
        b"oidc-subject-v1\x00"
        + ISSUER.encode("ascii")
        + b"\x00sandbox:access-admin-01",
        hashlib.sha256,
    ).digest()
    expected_recipient = hmac.new(
        bytes(RECIPIENT_KEY),
        b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
        b"sandbox-access-admin-01@example.test",
        hashlib.sha256,
    ).digest()
    assert parsed.accounts[0].subject_digest == expected_subject
    assert parsed.accounts[0].recipient_binding_digest == expected_recipient
    assert parsed.accounts[0].subject_digest_key_id == SUBJECT_KEY_ID
    assert parsed.accounts[0].recipient_binding_digest_key_id == RECIPIENT_KEY_ID
    assert generated.account_count == 10
    assert all(set(value) <= {0} for value in raw_values)
    assert b"sandbox:access-admin-01" not in generated.canonical_bytes
    assert b"sandbox-access-admin-01@example.test" not in generated.canonical_bytes


def test_generator_rejects_digest_collision_and_nonfictional_source_fail_closed() -> None:
    template = _canonical(_template_document())
    sources = _sources(collision=True)
    with pytest.raises(IdentityBootstrapManifestGenerationError) as collision:
        generate_internal_sandbox_identity_manifest(
            template_bytes=template,
            expected_template_sha256=hashlib.sha256(template).hexdigest(),
            issuer=ISSUER,
            subject_digest_key_id=SUBJECT_KEY_ID,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=RECIPIENT_KEY_ID,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=lambda file_name: sources[file_name],
        )
    assert collision.value.code == "IDENTITY_BOOTSTRAP_MANIFEST_GENERATION_INVALID"
    assert all(set(value) <= {0} for value in sources.values())

    real_source = _sources()
    real_source["creator_01.email"] = bytearray(b"person@gmail.com")
    with pytest.raises(IdentityBootstrapManifestGenerationError):
        generate_internal_sandbox_identity_manifest(
            template_bytes=template,
            expected_template_sha256=hashlib.sha256(template).hexdigest(),
            issuer=ISSUER,
            subject_digest_key_id=SUBJECT_KEY_ID,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=RECIPIENT_KEY_ID,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=lambda file_name: real_source[file_name],
        )
    assert set(real_source["access_admin_01.subject"]) <= {0}
    assert set(real_source["creator_01.email"]) <= {0}


def test_file_cli_uses_active_runtime_keys_and_emits_only_digest_manifest() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        secret_root = root / "secrets"
        source_root = root / "sources"
        output_root = root / "output"
        secret_root.mkdir(mode=0o700)
        source_root.mkdir(mode=0o700)
        output_root.mkdir(mode=0o700)
        template = EXAMPLE_TEMPLATE.read_bytes()
        assert hashlib.sha256(template).hexdigest() == EXAMPLE_TEMPLATE_SHA256
        template_path = root / "template.json"
        template_path.write_bytes(template)
        output_path = output_root / "identities.json"
        for file_name, value in _sources().items():
            (source_root / file_name).write_bytes(bytes(value) + b"\n")
        (secret_root / "subject-key").write_bytes(bytes(SUBJECT_KEY))
        (secret_root / "recipient-key").write_bytes(bytes(RECIPIENT_KEY))

        runtime_path = root / "runtime.json"
        secret_manifest_path = root / "secret-manifest.json"
        deployment_path = root / "deployment.json"
        runtime_path.write_bytes(_canonical(_runtime_document()))
        secret_manifest_path.write_bytes(_canonical(_secret_manifest_document()))
        deployment_path.write_bytes(
            _canonical(
                _deployment_document(
                    runtime_path=runtime_path,
                    secret_manifest_path=secret_manifest_path,
                    secret_root=secret_root,
                )
            )
        )
        environment = {
            DEPLOYMENT_CONFIG_POINTER_ENV: str(deployment_path),
            IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV: str(template_path),
            IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV: hashlib.sha256(
                template
            ).hexdigest(),
            IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV: str(source_root),
            IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV: str(output_path),
        }
        assert main(["generate"], environment=environment) == 0
        output = output_path.read_bytes()
        parsed = parse_internal_sandbox_identity_manifest(
            output,
            expected_sha256=hashlib.sha256(output).hexdigest(),
            expected_issuer=ISSUER,
        )
        assert len(parsed.accounts) == 10
        assert output_path.stat().st_mode & 0o777 == 0o600
        for raw in (
            b"sandbox:access-admin-01",
            b"sandbox:creator-01",
            b"sandbox:demand-owner-01",
            b"sandbox:operations-reviewer-01",
            b"sandbox:finance-operator-01",
            b"sandbox:finance-operator-02",
            b"sandbox:org-admin-01",
            b"sandbox-access-admin-01@example.test",
            b"sandbox-creator-01@example.test",
            b"sandbox-demand-owner-01@example.test",
            b"sandbox-operations-reviewer-01@example.test",
            b"sandbox-finance-operator-01@example.test",
            b"sandbox-finance-operator-02@example.test",
            b"sandbox-org-admin-01@example.test",
            b"sandbox:trust-officer-01",
            b"sandbox-trust-officer-01@example.test",
            b"sandbox:trust-officer-02",
            b"sandbox-trust-officer-02@example.test",
            b"sandbox:appeal-reviewer-01",
            b"sandbox-appeal-reviewer-01@example.test",
        ):
            assert raw not in output


def test_regular_source_reader_zeroizes_partial_buffer_when_readv_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "abc.subject"
    source.write_bytes(b"reviewed-subject")
    captured: list[bytearray] = []
    original_readv = os.readv

    def interrupted_readv(descriptor: int, buffers: list[memoryview]) -> int:
        captured.append(buffers[0].obj)
        original_readv(descriptor, [buffers[0][:3]])
        raise OSError("simulated partial read failure")

    monkeypatch.setattr(manifest_module.os, "readv", interrupted_readv)
    with pytest.raises(IdentityBootstrapManifestGenerationError):
        manifest_module._read_source(tmp_path, source.name)

    assert captured
    assert all(set(material) <= {0} for material in captured)


def _runtime_document() -> Dict[str, Any]:
    return {
        "artifacts": [{"artifact_id": "bootstrap", "sha256": "a" * 64}],
        "budgets": {
            "readiness_timeout_ms": 1000,
            "shutdown_timeout_ms": 1000,
            "startup_timeout_ms": 1000,
        },
        "database_profiles": [],
        "identity": {
            "deployment_id": "sandbox-bootstrap",
            "environment_id": "internal-sandbox",
            "instance_id": "bootstrap-01",
            "region": "local-container",
            "release_id": "bootstrap-v1",
        },
        "key_requirements": [
            {
                "active_key_id": SUBJECT_KEY_ID,
                "purpose": "OIDC_SUBJECT_DIGEST",
                "retained_key_ids": [SUBJECT_KEY_ID],
            },
            {
                "active_key_id": RECIPIENT_KEY_ID,
                "purpose": "OIDC_RECIPIENT_BINDING",
                "retained_key_ids": [RECIPIENT_KEY_ID],
            },
        ],
        "process": {
            "capability_ids": ["IAM_SANDBOX_BOOTSTRAP"],
            "kind": "migration",
        },
        "schema_name": "desire-runtime-config-v1",
    }


def _secret_manifest_document() -> Dict[str, Any]:
    return {
        "entries": [
            {
                "credential_ref": None,
                "file_name": "subject-key",
                "key_id": SUBJECT_KEY_ID,
                "kind": "KEY",
                "not_after": "2099-01-01T00:00:00Z",
                "not_before": "2020-01-01T00:00:00Z",
                "purpose": "OIDC_SUBJECT_DIGEST",
                "status": "ACTIVE",
            },
            {
                "credential_ref": None,
                "file_name": "recipient-key",
                "key_id": RECIPIENT_KEY_ID,
                "kind": "KEY",
                "not_after": "2099-01-01T00:00:00Z",
                "not_before": "2020-01-01T00:00:00Z",
                "purpose": "OIDC_RECIPIENT_BINDING",
                "status": "ACTIVE",
            },
        ],
        "schema_name": "desire-file-secret-manifest-v1",
    }


def _deployment_document(
    *, runtime_path: Path, secret_manifest_path: Path, secret_root: Path
) -> Dict[str, Any]:
    return {
        "bind": {"host": "0.0.0.0", "port": 8000},
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_participants_enabled": False,
        "internal_bff_origin": "http://api:8000",
        "oidc": {
            "allowed_signing_algorithms": ["RS256"],
            "client_id": "desire-internal-sandbox",
            "client_secret_key_id": "oidc-client-secret-v1",
            "clock_skew_seconds": 30,
            "issuer": ISSUER,
            "maximum_response_bytes": 262144,
            "metadata_ttl_seconds": 300,
            "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
            "request_timeout_seconds": 3,
            "subject_digest_key_id": SUBJECT_KEY_ID,
            "network_binding": {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": None,
            },
        },
        "postgres": {
            "database": "desire",
            "host": "db",
            "port": 5432,
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        },
        "runtime_config_path": str(runtime_path),
        "schema_name": "desire-internal-sandbox-deployment-v1",
        "secret_manifest_path": str(secret_manifest_path),
        "secret_root": str(secret_root),
        "system_actor_id": "10000000-0000-4000-8000-000000000001",
    }
