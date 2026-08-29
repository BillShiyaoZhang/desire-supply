"""Closed generation tests for reviewed real OIDC account bindings."""

from __future__ import annotations

import hashlib
from io import StringIO
import os
from pathlib import Path
import tempfile
from typing import Any, Dict

import pytest

from desire_platform.deployment.identity_bootstrap import (
    parse_internal_sandbox_identity_manifest,
)
from desire_platform.deployment.identity_bootstrap_manifest import (
    IdentityBootstrapManifestGenerationError,
    generate_internal_sandbox_identity_manifest,
)
from desire_platform.deployment.preprovisioned_identity_bootstrap_manifest import (
    PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
    PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
    PreprovisionedIdentityBootstrapManifestGenerationError,
    generate_preprovisioned_identity_bootstrap_manifest,
    generate_preprovisioned_identity_bootstrap_manifest_file,
    main,
)
from desire_platform.deployment import (
    preprovisioned_identity_bootstrap_manifest as manifest_module,
)
from desire_platform.identity_access.adapters.oidc import (
    ClosedOidcProvider,
    OidcProviderConfiguration,
)
from desire_platform.identity_access.ports.identity_provider import (
    ProviderExchangeRequest,
)
from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
)
from desire_platform.internal_pilot.runtime_crypto import (
    HmacRecipientBinding,
    RuntimeKeyMaterial,
)
from tests.deployment.test_identity_bootstrap_manifest_generator_red import (
    _canonical,
    _deployment_document,
    _runtime_document,
    _secret_manifest_document,
    _template_document,
)


ISSUER = "https://identity.example.test/tenant"
SUBJECT_KEY = bytearray(b"s" * 32)
RECIPIENT_KEY = bytearray(b"r" * 32)
SUBJECT_KEY_ID = "oidc-subject-digest-v1"
RECIPIENT_KEY_ID = "oidc-recipient-binding-v1"
NOW_SECONDS = 1_787_572_800


def _real_sources() -> dict[str, bytearray]:
    result: dict[str, bytearray] = {}
    for index, account in enumerate(_template_document()["accounts"]):
        code = account["account_code"]
        subject = f"provider|tenant-a|{index:02d}|{code}"
        email = f"  Person+{code}@Example.TEST  "
        result[f"{code}.subject"] = bytearray(subject.encode("utf-8"))
        result[f"{code}.email"] = bytearray(email.encode("utf-8"))
    first_code = _template_document()["accounts"][0]["account_code"]
    result[f"{first_code}.email"] = bytearray(
        "  Pe\N{COMBINING ACUTE ACCENT}RSON+access@Example.TEST  ".encode(
            "utf-8"
        )
    )
    return result


def _file_generation_case(root: Path):
    secret_root = root / "secrets"
    source_root = root / "identity-sources"
    output_root = root / "identity-output"
    config_root = root / "config"
    template_root = root / "reviewed-template"
    for directory in (
        secret_root,
        source_root,
        output_root,
        config_root,
        template_root,
    ):
        directory.mkdir(mode=0o700)
    template = _canonical(_template_document())
    template_path = template_root / "template.json"
    template_path.write_bytes(template)
    output_path = output_root / "manifest.json"
    real_sources = _real_sources()
    raw_copies = tuple(bytes(value) for value in real_sources.values())
    for name, value in real_sources.items():
        (source_root / name).write_bytes(bytes(value) + b"\n")
    (secret_root / "subject-key").write_bytes(bytes(SUBJECT_KEY))
    (secret_root / "recipient-key").write_bytes(bytes(RECIPIENT_KEY))

    runtime_path = config_root / "runtime.json"
    secret_manifest_path = config_root / "secret-manifest.json"
    deployment_path = config_root / "deployment.json"
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
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV: str(template_path),
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV: hashlib.sha256(
            template
        ).hexdigest(),
        PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV: str(source_root),
        PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV: str(output_path),
    }
    protected_paths = {
        "deployment": deployment_path,
        "runtime": runtime_path,
        "secret_manifest": secret_manifest_path,
        "template": template_path,
    }
    return (
        environment,
        source_root,
        output_path,
        raw_copies,
        protected_paths,
    )


def _set_source_tree_read_only(source_root: Path, *, value: bool) -> None:
    if not value:
        source_root.chmod(0o700)
    for candidate in source_root.iterdir():
        if candidate.is_file() and not candidate.is_symlink():
            candidate.chmod(0o400 if value else 0o600)
    if value:
        source_root.chmod(0o500)


def _with_locked_sources(source_root: Path, operation):
    _set_source_tree_read_only(source_root, value=True)
    try:
        return operation()
    finally:
        _set_source_tree_read_only(source_root, value=False)


class _OidcTransport:
    def __init__(self) -> None:
        self.get_count = 0

    def get_json(self, **_values: Any) -> Dict[str, Any]:
        self.get_count += 1
        if self.get_count == 1:
            return {
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }
        return {"keys": [{"kty": "RSA", "kid": "test-key"}]}

    def post_form_json(self, **_values: Any) -> Dict[str, Any]:
        return {"token_type": "Bearer", "id_token": "header.payload.signature"}


class _OidcVerifier:
    def __init__(self, *, subject: str, email: str) -> None:
        self.subject = subject
        self.email = email

    def verify_id_token(self, **_values: Any) -> Dict[str, Any]:
        return {
            "iss": ISSUER,
            "sub": self.subject,
            "aud": "desire-internal-pilot",
            "nonce": "expected-nonce",
            "iat": NOW_SECONDS - 10,
            "exp": NOW_SECONDS + 300,
            "auth_time": NOW_SECONDS - 20,
            "acr": "urn:desire:acr:mfa",
            "amr": ["pwd", "otp"],
            "email": self.email,
            "email_verified": True,
        }


def _online_identity(*, subject: str, email: str):
    recipient = HmacRecipientBinding(
        key=RuntimeKeyMaterial(
            purpose="OIDC_RECIPIENT_BINDING",
            key_id=RECIPIENT_KEY_ID,
            material=bytearray(RECIPIENT_KEY),
        )
    )
    provider = ClosedOidcProvider(
        configuration=OidcProviderConfiguration(
            issuer=ISSUER,
            client_id="desire-internal-pilot",
            client_secret="not-rendered",
            redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
            allowed_signing_algorithms=("RS256",),
            metadata_ttl_seconds=300,
            request_timeout_seconds=3,
            maximum_response_bytes=262_144,
            clock_skew_seconds=30,
            subject_digest_key_id=SUBJECT_KEY_ID,
        ),
        transport=_OidcTransport(),
        token_verifier=_OidcVerifier(subject=subject, email=email),
        recipient_binding=recipient,
        subject_digest_key=bytearray(SUBJECT_KEY),
    )
    from datetime import datetime, timezone

    return provider.exchange(
        ProviderExchangeRequest(
            auth_transaction_id="transaction-01",
            code="authorization-code",
            state="state-01",
            redirect_uri="https://pilot.example.test/v1/auth/oidc/callback",
            code_verifier="v" * 43,
            expected_nonce="expected-nonce",
            expected_issuer=ISSUER,
            expected_audience="desire-internal-pilot",
            server_now=datetime.fromtimestamp(NOW_SECONDS, tz=timezone.utc),
        )
    )


def test_real_generator_matches_online_oidc_and_recipient_binding_exactly() -> None:
    template = _canonical(_template_document())
    sources = _real_sources()
    first_account = _template_document()["accounts"][0]["account_code"]
    first_subject = bytes(sources[f"{first_account}.subject"]).decode("utf-8")
    first_email = bytes(sources[f"{first_account}.email"]).decode("utf-8")
    raw_values = tuple(sources.values())

    generated = generate_preprovisioned_identity_bootstrap_manifest(
        template_bytes=template,
        expected_template_sha256=hashlib.sha256(template).hexdigest(),
        issuer=ISSUER,
        subject_digest_key_id=SUBJECT_KEY_ID,
        subject_digest_key=bytearray(SUBJECT_KEY),
        recipient_binding_key_id=RECIPIENT_KEY_ID,
        recipient_binding_key=bytearray(RECIPIENT_KEY),
        read_source=lambda name: sources[name],
    )
    parsed = parse_internal_sandbox_identity_manifest(
        generated.canonical_bytes,
        expected_sha256=generated.manifest_sha256,
        expected_issuer=ISSUER,
    )
    online = _online_identity(subject=first_subject, email=first_email)

    assert parsed.accounts[0].subject_digest.hex() == online.subject_digest
    assert (
        parsed.accounts[0].recipient_binding_digest.hex()
        == online.verified_recipient_binding.binding_digest
    )
    assert parsed.accounts[0].subject_digest_key_id == SUBJECT_KEY_ID
    assert parsed.accounts[0].recipient_binding_digest_key_id == RECIPIENT_KEY_ID
    assert generated.account_count == 10
    assert all(set(value) <= {0} for value in raw_values)
    assert first_subject.encode() not in generated.canonical_bytes
    assert first_email.encode() not in generated.canonical_bytes
    assert first_subject not in repr(generated)
    assert first_email not in repr(generated)


def test_existing_synthetic_generator_still_rejects_real_identity_inputs() -> None:
    template = _canonical(_template_document())
    sources = _real_sources()
    first_code = _template_document()["accounts"][0]["account_code"]
    with pytest.raises(IdentityBootstrapManifestGenerationError):
        generate_internal_sandbox_identity_manifest(
            template_bytes=template,
            expected_template_sha256=hashlib.sha256(template).hexdigest(),
            issuer=ISSUER,
            subject_digest_key_id=SUBJECT_KEY_ID,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=RECIPIENT_KEY_ID,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=lambda name: sources[name],
        )
    assert set(sources[f"{first_code}.subject"]) <= {0}
    assert set(sources[f"{first_code}.email"]) <= {0}


@pytest.mark.parametrize(
    "mutation",
    ("duplicate_subject", "duplicate_email", "bad_utf8", "control", "too_large"),
)
def test_real_source_failures_are_closed_zeroized_and_non_reflective(
    mutation: str,
) -> None:
    template = _canonical(_template_document())
    sources = _real_sources()
    accounts = _template_document()["accounts"]
    first = accounts[0]["account_code"]
    second = accounts[1]["account_code"]
    raw_secret = "raw-person-secret@example.test"
    if mutation == "duplicate_subject":
        sources[f"{second}.subject"] = bytearray(sources[f"{first}.subject"])
    elif mutation == "duplicate_email":
        sources[f"{first}.email"] = bytearray(b"  Duplicate@Example.TEST ")
        sources[f"{second}.email"] = bytearray(b"duplicate@example.test")
    elif mutation == "bad_utf8":
        sources[f"{first}.subject"] = bytearray(b"provider-\xff-secret")
    elif mutation == "control":
        sources[f"{first}.email"] = bytearray(
            (raw_secret + "\N{RIGHT-TO-LEFT OVERRIDE}").encode("utf-8")
        )
    else:
        sources[f"{first}.subject"] = bytearray(b"x" * 513)
    observed: list[bytearray] = []

    def read_source(name: str) -> bytearray:
        value = sources[name]
        observed.append(value)
        return value

    with pytest.raises(
        PreprovisionedIdentityBootstrapManifestGenerationError
    ) as caught:
        generate_preprovisioned_identity_bootstrap_manifest(
            template_bytes=template,
            expected_template_sha256=hashlib.sha256(template).hexdigest(),
            issuer=ISSUER,
            subject_digest_key_id=SUBJECT_KEY_ID,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=RECIPIENT_KEY_ID,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=read_source,
        )
    assert caught.value.code == "PREPROVISIONED_IDENTITY_BOOTSTRAP_MANIFEST_INVALID"
    assert observed and all(set(value) <= {0} for value in observed)
    rendered = repr(caught.value)
    assert raw_secret not in rendered
    assert "provider-" not in rendered


@pytest.mark.parametrize(
    ("issuer", "subject_key_id", "recipient_key_id", "template_digest"),
    (
        ("http://identity.example.test", SUBJECT_KEY_ID, RECIPIENT_KEY_ID, None),
        (ISSUER + "/", SUBJECT_KEY_ID, RECIPIENT_KEY_ID, None),
        (ISSUER, "subject:key", RECIPIENT_KEY_ID, None),
        (ISSUER, SUBJECT_KEY_ID, "recipient:key", None),
        (ISSUER, SUBJECT_KEY_ID, RECIPIENT_KEY_ID, "0" * 64),
    ),
)
def test_generator_rejects_unreviewed_issuer_keys_and_template(
    issuer: str,
    subject_key_id: str,
    recipient_key_id: str,
    template_digest: str | None,
) -> None:
    template = _canonical(_template_document())
    calls: list[str] = []
    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        generate_preprovisioned_identity_bootstrap_manifest(
            template_bytes=template,
            expected_template_sha256=(
                template_digest or hashlib.sha256(template).hexdigest()
            ),
            issuer=issuer,
            subject_digest_key_id=subject_key_id,
            subject_digest_key=bytearray(SUBJECT_KEY),
            recipient_binding_key_id=recipient_key_id,
            recipient_binding_key=bytearray(RECIPIENT_KEY),
            read_source=lambda name: calls.append(name) or bytearray(b"unused"),
        )
    assert calls == []


def test_file_cli_uses_regular_sources_and_emits_digest_only_manifest() -> None:
    from datetime import datetime, timezone

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        (
            environment,
            source_root,
            output_path,
            raw_copies,
            _protected_paths,
        ) = _file_generation_case(root)
        invoke = lambda: main(
            ["generate"],
            environment=environment,
            clock=lambda: datetime(2026, 8, 24, tzinfo=timezone.utc),
        )
        assert _with_locked_sources(source_root, invoke) == 0
        output = output_path.read_bytes()
        parse_internal_sandbox_identity_manifest(
            output,
            expected_sha256=hashlib.sha256(output).hexdigest(),
            expected_issuer=ISSUER,
        )
        assert output_path.stat().st_mode & 0o777 == 0o600
        assert all(value not in output for value in raw_copies)

        def blocked() -> None:
            stdout = StringIO()
            stderr = StringIO()
            operation = lambda: main(
                ["generate"],
                environment=environment,
                stdout=stdout,
                stderr=stderr,
                clock=lambda: datetime(2026, 8, 24, tzinfo=timezone.utc),
            )
            assert _with_locked_sources(source_root, operation) == 78
            assert stdout.getvalue() == ""
            assert "PREPROVISIONED_IDENTITY_BOOTSTRAP_MANIFEST_INVALID" in (
                stderr.getvalue()
            )

        extra = source_root / "unreviewed.subject"
        extra.write_bytes(b"unreviewed")
        blocked()
        extra.unlink()

        real_source_names = set(_real_sources())
        first_name = next(iter(real_source_names))
        first_path = source_root / first_name
        first_bytes = first_path.read_bytes()
        first_path.unlink()
        first_path.symlink_to(
            source_root / next(iter(real_source_names - {first_name}))
        )
        blocked()
        first_path.unlink()
        first_path.mkdir()
        blocked()
        first_path.rmdir()
        first_path.write_bytes(first_bytes)


def test_file_generator_rejects_writable_identity_source_metadata(
    tmp_path: Path,
) -> None:
    from datetime import datetime, timezone

    environment, _source_root, output_path, _raw, _protected = (
        _file_generation_case(tmp_path)
    )
    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=environment,
            now=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )
    assert not output_path.exists()


@pytest.mark.parametrize(
    "protected_name",
    ("deployment", "runtime", "secret_manifest", "template"),
)
def test_output_cannot_overwrite_any_deployment_input(
    tmp_path: Path,
    protected_name: str,
) -> None:
    from datetime import datetime, timezone

    environment, source_root, _output_path, _raw, protected = (
        _file_generation_case(tmp_path)
    )
    target = protected[protected_name]
    original = target.read_bytes()
    environment[PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV] = str(target)

    def generate() -> None:
        generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=environment,
            now=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )

    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        _with_locked_sources(source_root, generate)
    assert target.read_bytes() == original


def test_output_cannot_hardlink_alias_a_deployment_input(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    environment, source_root, output_path, _raw, protected = (
        _file_generation_case(tmp_path)
    )
    runtime_path = protected["runtime"]
    original = runtime_path.read_bytes()
    os.link(runtime_path, output_path)

    def generate() -> None:
        generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=environment,
            now=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )

    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        _with_locked_sources(source_root, generate)
    assert runtime_path.read_bytes() == original
    assert output_path.read_bytes() == original


def test_directory_fd_snapshot_detects_swap_and_zeroizes_read_buffers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import datetime, timezone

    environment, source_root, output_path, _raw, _protected = (
        _file_generation_case(tmp_path)
    )
    victim = source_root / "org_admin_01.subject"
    captured: list[bytearray] = []
    original_reader = manifest_module._read_source_descriptor

    def swap_after_read(descriptor: int, *, expected_fingerprint):
        material = original_reader(
            descriptor,
            expected_fingerprint=expected_fingerprint,
        )
        captured.append(material)
        if len(captured) == 1:
            source_root.chmod(0o700)
            victim.unlink()
            victim.write_bytes(b"attacker-controlled-subject\n")
            victim.chmod(0o400)
            source_root.chmod(0o500)
        return material

    monkeypatch.setattr(
        manifest_module,
        "_read_source_descriptor",
        swap_after_read,
    )

    def generate() -> None:
        generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=environment,
            now=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )

    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        _with_locked_sources(source_root, generate)
    assert captured
    assert all(set(material) <= {0} for material in captured)
    assert not output_path.exists()


def test_file_entrypoint_environment_is_exact_and_cannot_mix_synthetic_inputs() -> None:
    environment = {
        DEPLOYMENT_CONFIG_POINTER_ENV: "/run/desire/deployment.json",
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV: "/run/template.json",
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV: "a" * 64,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV: "/run/secrets",
        PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV: "/run/secrets/out.json",
    }
    # The closed environment cannot be widened with a legacy/synthetic input.
    environment["DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_SOURCE_ROOT"] = (
        "/run/other"
    )
    with pytest.raises(PreprovisionedIdentityBootstrapManifestGenerationError):
        from desire_platform.deployment.preprovisioned_identity_bootstrap_manifest import (
            generate_preprovisioned_identity_bootstrap_manifest_file,
        )

        generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=environment,
            now=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
