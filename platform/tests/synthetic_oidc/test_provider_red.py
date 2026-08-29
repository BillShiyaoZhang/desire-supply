"""Executable contract for the controlled INTERNAL_SANDBOX OIDC fixture."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import html
import json
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from desire_platform.identity_access.adapters.oidc import (
    ClosedOidcProvider,
    OidcProviderConfiguration,
    PyJwtOidcTokenVerifier,
)
from desire_platform.identity_access.ports.identity_provider import (
    ProviderExchangeRequest,
)
from desire_platform.synthetic_oidc import (
    CLIENT_ID,
    ISSUER,
    REDIRECT_URI,
    SYNTHETIC_ACCOUNTS,
    SYNTHETIC_BOOTSTRAP_ACCOUNTS,
    SYNTHETIC_PROVIDER_ACCOUNTS,
    SYNTHETIC_PROVIDER_ONLY_ACCOUNTS,
    SyntheticOidcConfigurationError,
    SyntheticOidcProvider,
    load_synthetic_oidc_configuration,
)


NOW = datetime(2026, 8, 13, 7, 0, tzinfo=timezone.utc)
CLIENT_SECRET = bytearray(b"fixture-client-secret-material-0001")
SUBJECT_DIGEST_KEY = bytearray(b"fixture-subject-digest-key-material")
RECIPIENT_BINDING_KEY = b"fixture-recipient-binding-key-material"
VERIFIER = "closed-verifier-abcdefghijklmnopqrstuvwxyz0123456789"
CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER.encode("ascii")).digest()
).rstrip(b"=").decode("ascii")
STATE = base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode("ascii")
NONCE = base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=").decode("ascii")
PUBLIC_HEADERS = (
    ("Host", "identity.example.test"),
    ("X-Forwarded-Host", "identity.example.test"),
    ("X-Forwarded-Proto", "https"),
)


class _Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class _RecipientBinding:
    def bind_verified(self, *, contact_type, verified_locator):
        digest = hmac.new(
            RECIPIENT_BINDING_KEY,
            b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
            + verified_locator.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return type(
            "Binding",
            (),
            {
                "contact_type": contact_type,
                "binding_digest": digest,
                "digest_key_id": "recipient-binding-key-v1",
            },
        )()


class _ApplicationTransport:
    """Exercise ClosedOidcProvider against the fixture without network I/O."""

    def __init__(self, application: SyntheticOidcProvider) -> None:
        self.application = application

    def get_json(self, *, url, timeout_seconds, maximum_bytes):
        del timeout_seconds
        parsed = urlsplit(url)
        response = self.application.handle(
            method="GET",
            raw_target=parsed.path + (("?" + parsed.query) if parsed.query else ""),
            headers=PUBLIC_HEADERS,
            body=b"",
        )
        assert response.status == 200
        assert len(response.body) <= maximum_bytes
        return json.loads(response.body)

    def post_form_json(self, *, url, form, timeout_seconds, maximum_bytes):
        del timeout_seconds
        parsed = urlsplit(url)
        response = self.application.handle(
            method="POST",
            raw_target=parsed.path,
            headers=PUBLIC_HEADERS
            + (("Content-Type", "application/x-www-form-urlencoded"),),
            body=urlencode(form).encode("ascii"),
        )
        if response.status != 200:
            raise RuntimeError("synthetic OIDC token endpoint rejected request")
        assert len(response.body) <= maximum_bytes
        return json.loads(response.body)


def _provider(*, clock: _Clock | None = None):
    clock = clock or _Clock()
    application = SyntheticOidcProvider(
        client_secret=bytearray(CLIENT_SECRET),
        clock=clock,
    )
    transport = _ApplicationTransport(application)
    adapter = ClosedOidcProvider(
        configuration=OidcProviderConfiguration(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            client_secret=bytearray(CLIENT_SECRET),
            redirect_uri=REDIRECT_URI,
            allowed_signing_algorithms=("RS256",),
            metadata_ttl_seconds=300,
            request_timeout_seconds=3,
            maximum_response_bytes=262_144,
            clock_skew_seconds=30,
            subject_digest_key_id="subject-digest-key-v1",
        ),
        transport=transport,
        token_verifier=PyJwtOidcTokenVerifier(),
        recipient_binding=_RecipientBinding(),
        subject_digest_key=SUBJECT_DIGEST_KEY,
    )
    return application, adapter


def _authorization(application: SyntheticOidcProvider):
    query = urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email",
            "state": STATE,
            "nonce": NONCE,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        }
    )
    return application.handle(
        method="GET",
        raw_target="/authorize?" + query,
        headers=PUBLIC_HEADERS,
        body=b"",
    )


def _interaction_handle(response) -> str:
    body = html.unescape(response.body.decode("utf-8"))
    marker = 'name="request_handle" value="'
    return body.split(marker, 1)[1].split('"', 1)[0]


def _select(application: SyntheticOidcProvider, account_code: str):
    chooser = _authorization(application)
    handle = _interaction_handle(chooser)
    return application.handle(
        method="POST",
        raw_target="/authorize",
        headers=PUBLIC_HEADERS
        + (("Content-Type", "application/x-www-form-urlencoded"),),
        body=urlencode(
            {"request_handle": handle, "account_code": account_code}
        ).encode("ascii"),
    )


def _code(response) -> str:
    location = dict(response.headers)["Location"]
    assert urlsplit(location)._replace(query="", fragment="").geturl() == REDIRECT_URI
    values = parse_qs(urlsplit(location).query, strict_parsing=True)
    assert values["state"] == [STATE]
    return values["code"][0]


def _token(application, code: str, *, verifier: str = VERIFIER, **changes):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET.decode("ascii"),
        "code_verifier": verifier,
    }
    form.update(changes)
    return application.handle(
        method="POST",
        raw_target="/token",
        headers=PUBLIC_HEADERS
        + (("Content-Type", "application/x-www-form-urlencoded"),),
        body=urlencode(form).encode("ascii"),
    )


def test_discovery_and_jwks_are_closed_public_only_documents():
    application, _ = _provider()
    assert SYNTHETIC_ACCOUNTS is SYNTHETIC_BOOTSTRAP_ACCOUNTS
    assert tuple(
        (value.account_code, value.subject, value.email)
        for value in SYNTHETIC_BOOTSTRAP_ACCOUNTS
    ) == (
        (
            "access_admin_01",
            "sandbox:access-admin-01",
            "sandbox-access-admin-01@example.test",
        ),
        (
            "appeal_reviewer_01",
            "sandbox:appeal-reviewer-01",
            "sandbox-appeal-reviewer-01@example.test",
        ),
        (
            "creator_01",
            "sandbox:creator-01",
            "sandbox-creator-01@example.test",
        ),
        (
            "demand_owner_01",
            "sandbox:demand-owner-01",
            "sandbox-demand-owner-01@example.test",
        ),
        (
            "finance_operator_01",
            "sandbox:finance-operator-01",
            "sandbox-finance-operator-01@example.test",
        ),
        (
            "finance_operator_02",
            "sandbox:finance-operator-02",
            "sandbox-finance-operator-02@example.test",
        ),
        (
            "operations_reviewer_01",
            "sandbox:operations-reviewer-01",
            "sandbox-operations-reviewer-01@example.test",
        ),
        (
            "org_admin_01",
            "sandbox:org-admin-01",
            "sandbox-org-admin-01@example.test",
        ),
        (
            "trust_officer_01",
            "sandbox:trust-officer-01",
            "sandbox-trust-officer-01@example.test",
        ),
        (
            "trust_officer_02",
            "sandbox:trust-officer-02",
            "sandbox-trust-officer-02@example.test",
        ),
    )
    assert tuple(
        (value.account_code, value.subject, value.email)
        for value in SYNTHETIC_PROVIDER_ONLY_ACCOUNTS
    ) == (
        (
            "invited_demand_owner_02",
            "sandbox:invited-demand-owner-02",
            "sandbox-invited-demand-owner-02@example.test",
        ),
    )
    assert SYNTHETIC_PROVIDER_ACCOUNTS == (
        SYNTHETIC_BOOTSTRAP_ACCOUNTS + SYNTHETIC_PROVIDER_ONLY_ACCOUNTS
    )
    assert len({value.account_code for value in SYNTHETIC_PROVIDER_ACCOUNTS}) == 11
    discovery = application.handle(
        method="GET",
        raw_target="/.well-known/openid-configuration",
        headers=PUBLIC_HEADERS,
        body=b"",
    )
    assert discovery.status == 200
    assert json.loads(discovery.body) == {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }
    jwks = application.handle(
        method="GET", raw_target="/jwks", headers=PUBLIC_HEADERS, body=b""
    )
    document = json.loads(jwks.body)
    assert set(document) == {"keys"}
    assert len(document["keys"]) == 1
    assert set(document["keys"][0]) == {"alg", "e", "kid", "kty", "n", "use"}
    assert not set(document["keys"][0]).intersection(
        {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    )


@pytest.mark.parametrize("account", SYNTHETIC_PROVIDER_ACCOUNTS)
def test_each_frozen_provider_account_completes_real_provider_and_pyjwt(account):
    application, adapter = _provider()
    adapter.preflight_exchange(
        expected_issuer=ISSUER,
        expected_audience=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
    )
    code = _code(_select(application, account.account_code))
    subject = adapter.exchange(
        ProviderExchangeRequest(
            auth_transaction_id="auth-transaction-001",
            code=code,
            state=STATE,
            redirect_uri=REDIRECT_URI,
            code_verifier=VERIFIER,
            expected_nonce=NONCE,
            expected_issuer=ISSUER,
            expected_audience=CLIENT_ID,
            server_now=NOW,
        )
    )
    expected_subject = hmac.new(
        SUBJECT_DIGEST_KEY,
        ("oidc-subject-v1\x00" + ISSUER + "\x00" + account.subject).encode(),
        hashlib.sha256,
    ).hexdigest()
    expected_recipient = hmac.new(
        RECIPIENT_BINDING_KEY,
        b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
        + account.email.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    assert subject.issuer == ISSUER
    assert subject.subject_digest == expected_subject
    assert subject.verified_recipient_binding.binding_digest == expected_recipient
    assert subject.acr_code == "urn:desire:acr:synthetic-internal-sandbox:mfa"
    assert "mfa" in subject.acr_code.lower()
    assert subject.amr_codes == ("mfa", "synthetic")
    assert "mfa" in subject.amr_codes


def test_chooser_represents_ten_bootstrap_accounts_and_one_provider_only_invitee():
    application, _ = _provider()
    chooser = _authorization(application)
    text = chooser.body.decode("utf-8")
    assert chooser.status == 200
    assert text.count('name="account_code"') == 11
    for account in SYNTHETIC_PROVIDER_ACCOUNTS:
        assert account.account_code in text
        assert account.email in text
        assert account.subject not in text
    assert "受邀身份未预置账号或权限" in text
    assert "register" not in text.lower()
    rejected = _select(application, "arbitrary_account_12")
    assert rejected.status == 400
    assert b"arbitrary_account_12" not in rejected.body
    for path in ("/register", "/userinfo", "/reset", "/clients"):
        response = application.handle(
            method="GET", raw_target=path, headers=PUBLIC_HEADERS, body=b""
        )
        assert response.status == 404


def test_provider_only_invitee_is_absent_from_identity_bootstrap_and_role_inputs():
    platform_root = Path(__file__).resolve().parents[2]
    template = json.loads(
        (
            platform_root
            / "examples/internal-sandbox-identity-bootstrap-template-v1.json"
        ).read_bytes()
    )
    bootstrap_codes = tuple(account["account_code"] for account in template["accounts"])
    assert set(bootstrap_codes) == {
        account.account_code for account in SYNTHETIC_BOOTSTRAP_ACCOUNTS
    }
    assert len(bootstrap_codes) == len(SYNTHETIC_BOOTSTRAP_ACCOUNTS) == 10
    assert {
        account.account_code for account in SYNTHETIC_PROVIDER_ONLY_ACCOUNTS
    }.isdisjoint(bootstrap_codes)


def test_authorization_contract_rejects_unknown_duplicate_or_widened_inputs():
    application, _ = _provider()
    base = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email",
        "state": STATE,
        "nonce": NONCE,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    cases = (
        urlencode({**base, "scope": "openid email profile"}),
        urlencode({**base, "redirect_uri": "https://evil.example.test/callback"}),
        urlencode({**base, "subject": "arbitrary"}),
        urlencode(base) + "&state=" + STATE,
    )
    for query in cases:
        response = application.handle(
            method="GET",
            raw_target="/authorize?" + query,
            headers=PUBLIC_HEADERS,
            body=b"",
        )
        assert response.status == 400
        assert REDIRECT_URI.encode() not in response.body


def test_code_is_single_use_and_wrong_pkce_consumes_it():
    application, _ = _provider()
    code = _code(_select(application, "creator_01"))
    first = _token(application, code, verifier="wrong-verifier-abcdefghijklmnopqrstuvwxyz0123456789")
    second = _token(application, code)
    assert first.status == second.status == 400
    assert json.loads(first.body) == {"error": "invalid_grant"}
    assert json.loads(second.body) == {"error": "invalid_grant"}

    code = _code(_select(application, "creator_01"))
    wrong_binding = _token(application, code, redirect_uri="https://evil.example.test/cb")
    replay = _token(application, code)
    assert wrong_binding.status == replay.status == 400
    assert json.loads(wrong_binding.body) == {"error": "invalid_grant"}
    assert json.loads(replay.body) == {"error": "invalid_grant"}


def test_interaction_and_code_expire_and_provider_has_bounded_state():
    clock = _Clock()
    application, _ = _provider(clock=clock)
    chooser = _authorization(application)
    handle = _interaction_handle(chooser)
    clock.value += timedelta(minutes=6)
    expired_interaction = application.handle(
        method="POST",
        raw_target="/authorize",
        headers=PUBLIC_HEADERS
        + (("Content-Type", "application/x-www-form-urlencoded"),),
        body=urlencode(
            {"request_handle": handle, "account_code": "creator_01"}
        ).encode("ascii"),
    )
    assert expired_interaction.status == 400

    chooser = _authorization(application)
    handle = _interaction_handle(chooser)
    selected = application.handle(
        method="POST",
        raw_target="/authorize",
        headers=PUBLIC_HEADERS
        + (("Content-Type", "application/x-www-form-urlencoded"),),
        body=urlencode(
            {"request_handle": handle, "account_code": "creator_01"}
        ).encode("ascii"),
    )
    code = _code(selected)
    clock.value += timedelta(minutes=2)
    assert _token(application, code).status == 400


def test_public_protocol_requires_exact_https_proxy_boundary():
    application, _ = _provider()
    cases = (
        (("Host", "identity.example.test"),),
        (("Host", "identity.example.test"), ("X-Forwarded-Proto", "http")),
        (("Host", "evil.example.test"), ("X-Forwarded-Proto", "https")),
        (
            ("Host", "identity.example.test"),
            ("X-Forwarded-Host", "evil.example.test"),
            ("X-Forwarded-Proto", "https"),
        ),
        (
            ("Host", "identity.example.test"),
            ("X-Forwarded-Proto", "https"),
        ),
        PUBLIC_HEADERS + (("Forwarded", "proto=https"),),
        PUBLIC_HEADERS + (("X-Forwarded-Host", "identity.example.test"),),
        PUBLIC_HEADERS + (("Host", "identity.example.test"),),
    )
    for headers in cases:
        response = application.handle(
            method="GET",
            raw_target="/.well-known/openid-configuration",
            headers=headers,
            body=b"",
        )
        assert response.status == 403


def test_configuration_is_internal_sandbox_only_and_secret_safe(tmp_path: Path):
    secret = tmp_path / "oidc-client-secret"
    secret.write_bytes(CLIENT_SECRET)
    secret.chmod(0o600)
    environment = {
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
        "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": str(secret),
    }
    configuration = load_synthetic_oidc_configuration(
        environment=environment,
        allowed_secret_root=tmp_path,
    )
    assert configuration.bind_host == "0.0.0.0"
    assert configuration.bind_port == 8081
    assert CLIENT_SECRET.decode() not in repr(configuration)
    assert CLIENT_SECRET.decode() not in repr(
        SyntheticOidcProvider(client_secret=configuration.client_secret)
    )
    configuration.close()
    assert set(configuration.client_secret) == {0}

    for changes in (
        {"DESIRE_DEPLOYMENT_MODE": "PRODUCTION"},
        {"DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "true"},
        {"DESIRE_SYNTHETIC_OIDC_ISSUER": ISSUER},
    ):
        with pytest.raises(SyntheticOidcConfigurationError):
            load_synthetic_oidc_configuration(
                environment={**environment, **changes},
                allowed_secret_root=tmp_path,
            )

    insecure = tmp_path / "insecure-client-secret"
    insecure.write_bytes(CLIENT_SECRET)
    insecure.chmod(0o622)
    with pytest.raises(SyntheticOidcConfigurationError):
        load_synthetic_oidc_configuration(
            environment={
                **environment,
                "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": str(insecure),
            },
            allowed_secret_root=tmp_path,
        )


def test_client_secret_and_private_key_never_leave_closed_responses():
    application, _ = _provider()
    responses = [
        application.handle(
            method="GET",
            raw_target="/.well-known/openid-configuration",
            headers=PUBLIC_HEADERS,
            body=b"",
        ),
        application.handle(
            method="GET", raw_target="/jwks", headers=PUBLIC_HEADERS, body=b""
        ),
        _token(application, "unknown-code"),
    ]
    joined = b"\n".join(response.body for response in responses)
    assert bytes(CLIENT_SECRET) not in joined
    assert b'"d"' not in responses[1].body
    assert b"unknown-code" not in joined
