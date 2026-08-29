from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from uuid import UUID

import pytest

from desire_platform.identity_access.adapters.postgres.policy_consent_commands import (
    PolicyConsentPostgresCommitOutcomeUnknownError,
    PolicyConsentPostgresDatabaseResult,
    PolicyConsentPostgresOperation,
)
from desire_platform.identity_access.application.policy_consent_commands import (
    AcceptCurrentPoliciesCommand,
    PolicyConsentActor,
    PolicyRequirementReference,
    PolicyRequirementScopeType,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.policies import PolicyAcceptance
from desire_platform.internal_pilot.contract_validation import (
    IamPostgresContractValidator,
)
from desire_platform.internal_pilot.policy_acceptance import (
    IAM_RECEIPT_IDEMPOTENCY_KEY_ID,
    IAM_RECEIPT_PAYLOAD_KEY_ID,
    IamReceiptPolicyKeys,
    PolicyAcceptancePostgresScope,
    PostgresAcceptCurrentPoliciesHandler,
)


NOW = datetime(2026, 8, 15, 8, 0, tzinfo=timezone.utc)
ACTOR_ID = UUID("10000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("10000000-0000-4000-8000-000000000002")
FAMILY_ID = UUID("10000000-0000-4000-8000-000000000003")
AUTH_TRANSACTION_ID = UUID("10000000-0000-4000-8000-000000000004")
ORGANIZATION_ID = UUID("10000000-0000-4000-8000-000000000005")
BUNDLE_ID = UUID("10000000-0000-4000-8000-000000000006")
DOCUMENT_ID = UUID("10000000-0000-4000-8000-000000000007")
DOCUMENT_ID_2 = UUID("10000000-0000-4000-8000-00000000000b")
SELECTOR = hashlib.sha256(b"policy-selector").hexdigest()
DOCUMENT_SHA = hashlib.sha256(b"policy-document").hexdigest()
DOCUMENT_SHA_2 = hashlib.sha256(b"policy-document-2").hexdigest()


class _Clock:
    @staticmethod
    def now() -> datetime:
        return NOW


class _Ids:
    def __init__(self) -> None:
        self._next = 100

    def new_id(self, purpose: str) -> UUID:
        assert purpose in {
            "policy_consent_command",
            "policy_consent_acceptance",
            "policy_consent_audit",
            "policy_consent_outbox",
        }
        self._next += 1
        return UUID(int=self._next)


class _ScopeResolver:
    def __init__(self, organization_id: UUID = ORGANIZATION_ID) -> None:
        self.calls = []
        self.organization_id = organization_id

    def resolve(self, *, actor, policy_requirement):
        self.calls.append((actor, policy_requirement))
        assert policy_requirement.scope_id == str(self.organization_id)
        return PolicyAcceptancePostgresScope(
            actor_user_id=ACTOR_ID,
            session_id=SESSION_ID,
            session_family_id=FAMILY_ID,
            auth_transaction_id=AUTH_TRANSACTION_ID,
            selector_digest=bytes.fromhex(SELECTOR),
            authority_scope_type="ORGANIZATION_ROLE",
            authority_scope_id=self.organization_id,
            organization_id=self.organization_id,
        )


class _Uow:
    def __init__(self) -> None:
        self.request = None
        self.failure = None

    def execute_accept_current_policies(self, request):
        self.request = request
        if self.failure is not None:
            raise self.failure
        return PolicyConsentPostgresDatabaseResult(
            operation=PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES,
            replayed=False,
            safe_response={
                "selector_digest": SELECTOR,
                "purpose": "ORGANIZATION_MEMBERSHIP",
                "role": "DEMAND_OWNER",
                "scope_type": "ORGANIZATION_ROLE",
                "scope_id": str(ORGANIZATION_ID),
                "satisfied": True,
                "required_policy_bundle_id": str(BUNDLE_ID),
                "missing_document_ids": [],
            },
            response_entity_tag='"v2"',
            current_user_entity_tag='"v2"',
        )


class _ReceiptCollisionUow(_Uow):
    def __init__(self) -> None:
        super().__init__()
        self.requests = []

    def execute_accept_current_policies(self, request):
        self.requests.append(request)
        if len(self.requests) > 1:
            first = self.requests[0].receipt
            current = request.receipt
            assert hmac.compare_digest(
                first.identity_candidates[0].digest,
                current.identity_candidates[0].digest,
            )
            if not hmac.compare_digest(
                first.payload_candidates[0].digest,
                current.payload_candidates[0].digest,
            ):
                raise IamError("IDEMPOTENCY_KEY_REUSED")
        return super().execute_accept_current_policies(request)


class _HiddenAuthorityResolver:
    @staticmethod
    def resolve(*, actor, policy_requirement):
        del actor, policy_requirement
        raise IamError("NOT_FOUND")


def _actor() -> PolicyConsentActor:
    return PolicyConsentActor(
        actor_user_id=str(ACTOR_ID),
        current_session_id=str(SESSION_ID),
        original_actor_id=None,
        correlation_id="10000000-0000-4000-8000-000000000008",
        causation_id="10000000-0000-4000-8000-000000000009",
        trace_id="10000000-0000-4000-8000-000000000010",
    )


def _command(
    *, organization_id: UUID = ORGANIZATION_ID
) -> AcceptCurrentPoliciesCommand:
    return AcceptCurrentPoliciesCommand(
        policy_requirement=PolicyRequirementReference(
            selector_digest=SELECTOR,
            scope_type=PolicyRequirementScopeType.ORGANIZATION_ROLE,
            scope_id=str(organization_id),
        ),
        policy_bundle_id=str(BUNDLE_ID),
        policy_acceptances=(
            PolicyAcceptance(
                document_id=str(DOCUMENT_ID_2),
                content_sha256=DOCUMENT_SHA_2,
                affirmed=True,
            ),
            PolicyAcceptance(
                document_id=str(DOCUMENT_ID),
                content_sha256=DOCUMENT_SHA,
                affirmed=True,
            ),
        ),
        expected_user_version=1,
        idempotency_key="first-login-policy-acceptance-0001",
    )


def test_builds_the_exact_pg_request_without_raw_carriers() -> None:
    resolver = _ScopeResolver()
    uow = _Uow()
    identity_key = b"i" * 32
    payload_key = b"p" * 32
    handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=resolver,
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=identity_key,
            payload_hash_key=payload_key,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )

    result = handler.handle(actor=_actor(), command=_command())

    request = uow.request
    assert request.operation is PolicyConsentPostgresOperation.ACCEPT_CURRENT_POLICIES
    assert request.scope.session_family_id == FAMILY_ID
    assert request.scope.auth_transaction_id == AUTH_TRANSACTION_ID
    assert request.scope.authority_scope_id == ORGANIZATION_ID
    assert request.policy_bundle_id == BUNDLE_ID
    assert tuple(item.document_id for item in request.policy_acceptances) == (
        DOCUMENT_ID,
        DOCUMENT_ID_2,
    )
    assert request.generated_ids.consent_grant_id is None
    assert len(request.generated_ids.policy_acceptance_ids) == 2
    assert len(request.generated_ids.outbox_event_ids) == 3
    assert request.receipt.retain_until == NOW + timedelta(days=30)
    assert request.receipt.active_identity_key_id == IAM_RECEIPT_IDEMPOTENCY_KEY_ID
    assert request.receipt.active_payload_key_id == IAM_RECEIPT_PAYLOAD_KEY_ID

    identity_bytes = json.dumps(
        {
            "domain": "iam-self-command-idempotency-key-v1",
            "idempotency_key": "first-login-policy-acceptance-0001",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert hmac.compare_digest(
        request.receipt.identity_candidates[0].digest,
        hmac.new(identity_key, identity_bytes, hashlib.sha256).digest(),
    )
    payload_projection = {
        "body": {
            "policy_requirement": {
                "selector_digest": SELECTOR,
                "scope_type": "ORGANIZATION_ROLE",
                "scope_id": str(ORGANIZATION_ID),
            },
            "policy_bundle_id": str(BUNDLE_ID),
            "policy_acceptances": [
                {
                    "document_id": str(DOCUMENT_ID),
                    "content_sha256": DOCUMENT_SHA,
                    "affirmed": True,
                },
                {
                    "document_id": str(DOCUMENT_ID_2),
                    "content_sha256": DOCUMENT_SHA_2,
                    "affirmed": True,
                },
            ],
        },
        "canonicalization_version": "restricted-canonical-json-v1",
        "command_name": "AcceptCurrentPolicies",
        "command_version": 1,
        "http_method": "POST",
        "if_match_version": 1,
        "path": "/v1/me/policy-acceptances",
        "target_id": str(ACTOR_ID),
        "target_kind": "User",
    }
    payload_bytes = json.dumps(
        payload_projection,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert hmac.compare_digest(
        request.receipt.payload_candidates[0].digest,
        hmac.new(payload_key, payload_bytes, hashlib.sha256).digest(),
    )
    assert "first-login-policy-acceptance-0001" not in repr(request)
    assert result.operation_id == "acceptCurrentPolicies"
    assert result.http_status == 200
    assert result.replayed is False


def test_same_key_cannot_replay_across_organization_policy_scopes() -> None:
    other_organization_id = UUID("10000000-0000-4000-8000-00000000000c")
    uow = _ReceiptCollisionUow()
    keys = IamReceiptPolicyKeys(
        idempotency_key=b"i" * 32,
        payload_hash_key=b"p" * 32,
    )
    ids = _Ids()
    first_handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=_ScopeResolver(ORGANIZATION_ID),
        uow_factory=uow,
        keys=keys,
        clock=_Clock(),
        id_source=ids,
    )
    second_handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=_ScopeResolver(other_organization_id),
        uow_factory=uow,
        keys=keys,
        clock=_Clock(),
        id_source=ids,
    )

    first_handler.handle(actor=_actor(), command=_command())
    with pytest.raises(IamError) as raised:
        second_handler.handle(
            actor=_actor(),
            command=_command(organization_id=other_organization_id),
        )

    first_receipt = uow.requests[0].receipt
    second_receipt = uow.requests[1].receipt
    assert hmac.compare_digest(
        first_receipt.identity_candidates[0].digest,
        second_receipt.identity_candidates[0].digest,
    )
    assert not hmac.compare_digest(
        first_receipt.payload_candidates[0].digest,
        second_receipt.payload_candidates[0].digest,
    )
    assert raised.value.code == "IDEMPOTENCY_KEY_REUSED"


@pytest.mark.parametrize("failure_source", ("scope_resolver", "postgres_uow"))
def test_forged_policy_authority_is_always_a_public_404(failure_source: str) -> None:
    resolver = _ScopeResolver()
    uow = _Uow()
    if failure_source == "scope_resolver":
        resolver = _HiddenAuthorityResolver()
    else:
        uow.failure = IamError("NOT_FOUND")
    handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=resolver,
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )

    with pytest.raises(IamError) as raised:
        handler.handle(actor=_actor(), command=_command())

    assert raised.value.code == "RESOURCE_NOT_FOUND"


def test_maps_uncertain_commit_to_the_published_retry_contract() -> None:
    uow = _Uow()
    uow.failure = PolicyConsentPostgresCommitOutcomeUnknownError()
    handler = PostgresAcceptCurrentPoliciesHandler(
        scope_resolver=_ScopeResolver(),
        uow_factory=uow,
        keys=IamReceiptPolicyKeys(
            idempotency_key=b"i" * 32,
            payload_hash_key=b"p" * 32,
        ),
        clock=_Clock(),
        id_source=_Ids(),
    )

    with pytest.raises(IamError) as raised:
        handler.handle(actor=_actor(), command=_command())

    assert raised.value.code == "COMMAND_OUTCOME_UNKNOWN"


def test_iam_validator_opens_only_the_policy_requirement_response_schema() -> None:
    validator = IamPostgresContractValidator()
    validator.validate(
        {
            "selector_digest": SELECTOR,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "role": "DEMAND_OWNER",
            "scope_type": "ORGANIZATION_ROLE",
            "scope_id": str(ORGANIZATION_ID),
            "satisfied": True,
            "required_policy_bundle_id": str(BUNDLE_ID),
            "missing_document_ids": [],
        },
        "PolicyRequirementStatusDto",
    )

    with pytest.raises(ValueError):
        validator.validate({}, "ConsentGrantDto")
