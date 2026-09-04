from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.internal_pilot.api_server import InternalSandboxApiServerPlan
from desire_platform.internal_pilot.production_plan import (
    INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS,
    INTERNAL_SANDBOX_CAPABILITY_ROLES,
    INTERNAL_SANDBOX_KEY_PURPOSES,
    InternalSandboxProductionPlanError,
    build_internal_sandbox_server_plan,
)
from desire_platform.internal_pilot.secrets import ManagedRuntimeSecrets
from desire_platform.internal_pilot.secrets import FilesystemSecretProvider
from desire_platform.internal_pilot.current_session_logout import (
    PostgresRevokeOwnedSessionHandler,
)
from desire_platform.internal_pilot.matching_postgres import (
    MatchingPostgresOperationalHttpService,
    PostgresCreateMatchingInvitationHandler,
    PostgresInvalidateMatchingAttemptHandler,
    PostgresPublishMatchingInvitationHandler,
    PsycopgMatchingReviewerAssignmentResolver,
)
from desire_platform.identity_access.application.read_models import (
    ListMySessionsHandler,
)
from desire_platform.internal_pilot.editor import (
    PsycopgProfileCompletedLifecycleReceiptProbe,
)
from desire_platform.identity_access.adapters.postgres.current_session_logout import (
    PsycopgOwnedSessionRevocationUnitOfWorkFactory,
)
from desire_platform.identity_access.adapters.postgres.organization_public_name import (
    PostgresUpdateOrganizationPublicNameHandler,
    PsycopgOrganizationPublicNameUnitOfWorkFactory,
)
from desire_platform.internal_pilot.seed_readiness import (
    PostgresInternalSandboxSeedReadiness,
)
from desire_platform.internal_pilot.schema_readiness import (
    PostgresSchemaCompatibilityReadiness,
)
from desire_platform.internal_pilot.synthetic_seed import (
    load_internal_sandbox_synthetic_seed,
)
from desire_platform.trust_safety.adapters.postgres import (
    PostgresClaimSafetyCaseHandler,
    PostgresClaimSafetyHoldReleaseHandler,
    PostgresPlaceSafetyHoldHandler,
    PostgresPublishTrustOutcomeHandler,
    PostgresPublishTrustTriageHandler,
    PostgresReleaseSafetyCaseAssignmentHandler,
    PostgresReleaseSafetyHoldHandler,
    PostgresSaveTrustTriageDraftHandler,
    PostgresSubmitSafetyReportHandler,
    PsycopgTrustDemandSafetyHoldProvider,
    PsycopgTrustHttpProjectionAdapter,
    TrustPostgresReceiptKeyring,
    TrustSealedTextKeyring,
)


_DEPLOYMENT_PATH = "/run/desire/deployment.json"
_RUNTIME_PATH = "/run/desire/runtime-config.json"
_MANIFEST_PATH = "/run/desire/secret-manifest.json"


class _NoConnectDbApi:
    def __init__(self) -> None:
        self.calls = []

    def connect(self, **kwargs):
        self.calls.append(kwargs)
        raise AssertionError("plan construction must not connect")


def _secret_material(index: int) -> bytes:
    return hashlib.sha256(f"internal-sandbox-test-secret-{index}".encode()).hexdigest()[
        :32
    ].encode("ascii")


def _documents(secret_root: Path):
    profiles = []
    manifest_entries = []
    secret_index = 0
    for capability, role in INTERNAL_SANDBOX_CAPABILITY_ROLES:
        key_id = "v1"
        slug = capability.lower().replace("_", "-")
        credential_ref = f"secret://sandbox-db/{slug}#{key_id}"
        file_name = f"db-{slug}"
        (secret_root / file_name).write_bytes(_secret_material(secret_index))
        secret_index += 1
        profiles.append(
            {
                "capability_id": capability,
                "online_role": role,
                "credential_ref": credential_ref,
                "application_name": f"desire-{slug}",
                "max_pool_size": 2,
                "checkout_timeout_ms": 500,
                "statement_timeout_ms": 5000,
                "lock_timeout_ms": 500,
                "idle_in_transaction_timeout_ms": 5000,
            }
        )
        manifest_entries.append(
            {
                "kind": "DATABASE_CREDENTIAL",
                "file_name": file_name,
                "credential_ref": credential_ref,
                "purpose": f"DATABASE_CREDENTIAL:{capability}",
                "key_id": key_id,
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": "2099-01-01T00:00:00Z",
                "status": "ACTIVE",
            }
        )

    key_requirements = []
    active_key_ids = {}
    for purpose in INTERNAL_SANDBOX_KEY_PURPOSES:
        key_id = {
            "DEMAND_IDEMPOTENCY": "demand-idempotency-2026-01",
            "DEMAND_PAYLOAD_HASH": "demand-payload-2026-01",
            "TRUST_IDEMPOTENCY": "trust-idempotency-2026-01",
            "TRUST_PAYLOAD_HASH": "trust-payload-2026-01",
            "TRUST_REPORT_CURSOR": "trust-report-cursor-2026-01",
            "MATCHING_PAYLOAD_HASH": "matching-payload-v1",
            "PLATFORM_USER_IDEMPOTENCY": (
                "iam-receipt-idempotency-hmac-2026-01"
            ),
            "PLATFORM_USER_PAYLOAD_HASH": (
                "iam-receipt-payload-hmac-2026-01"
            ),
        }.get(purpose, purpose.lower().replace("_", "-") + "-v1")
        active_key_ids[purpose] = key_id
        retained_key_ids = (
            (key_id, "demand-idempotency-retained-2025-12")
            if purpose == "DEMAND_IDEMPOTENCY"
            else (key_id, "demand-payload-retained-2025-12")
            if purpose == "DEMAND_PAYLOAD_HASH"
            else (key_id,)
        )
        key_requirements.append(
            {
                "purpose": purpose,
                "active_key_id": key_id,
                "retained_key_ids": list(retained_key_ids),
            }
        )
        for retained_key_id in retained_key_ids:
            file_name = f"key-{retained_key_id}"
            (secret_root / file_name).write_bytes(_secret_material(secret_index))
            secret_index += 1
            manifest_entries.append(
                {
                    "kind": "KEY",
                    "file_name": file_name,
                    "credential_ref": None,
                    "purpose": purpose,
                    "key_id": retained_key_id,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                    "status": (
                        "ACTIVE" if retained_key_id == key_id else "VERIFY_ONLY"
                    ),
                }
            )

    runtime = {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "internal-sandbox",
            "deployment_id": "sandbox-20260812",
            "release_id": "release-test-v1",
            "region": "local-container",
            "instance_id": "api-0001",
        },
        "process": {
            "kind": "web-api",
            "capability_ids": [item[0] for item in INTERNAL_SANDBOX_CAPABILITY_ROLES],
        },
        "artifacts": [
            {"artifact_id": item.artifact_id, "sha256": item.sha256}
            for item in INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
        ],
        "database_profiles": profiles,
        "key_requirements": key_requirements,
        "budgets": {
            "startup_timeout_ms": 30000,
            "readiness_timeout_ms": 1000,
            "shutdown_timeout_ms": 15000,
        },
    }
    manifest = {
        "schema_name": "desire-file-secret-manifest-v1",
        "entries": manifest_entries,
    }
    deployment = {
        "schema_name": "desire-internal-sandbox-deployment-v1",
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_participants_enabled": False,
        "internal_bff_origin": "http://api:8000",
        "runtime_config_path": _RUNTIME_PATH,
        "secret_manifest_path": _MANIFEST_PATH,
        "secret_root": str(secret_root),
        "postgres": {
            "host": "db",
            "port": 5432,
            "database": "desire",
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        },
        "oidc": {
            "issuer": "https://identity.example.test/tenant",
            "client_id": "desire-internal-sandbox",
            "client_secret_key_id": active_key_ids["OIDC_CLIENT_SECRET"],
            "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
            "allowed_signing_algorithms": ["RS256"],
            "metadata_ttl_seconds": 300,
            "request_timeout_seconds": 3,
            "maximum_response_bytes": 262144,
            "clock_skew_seconds": 30,
            "subject_digest_key_id": active_key_ids["OIDC_SUBJECT_DIGEST"],
            "network_binding": {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": None,
            },
        },
        "system_actor_id": "10000000-0000-4000-8000-000000000001",
        "bind": {"host": "0.0.0.0", "port": 8000},
    }
    return deployment, runtime, manifest


def _reader(documents, calls):
    encoded = {
        path: json.dumps(document, separators=(",", ":")).encode("utf-8")
        for path, document in documents.items()
    }

    def read(path):
        calls.append(path)
        return encoded[path]

    return read


def _add_retained_key(
    *,
    secret_root: Path,
    runtime: dict,
    manifest: dict,
    purpose: str,
    key_id: str,
    secret_index: int,
) -> None:
    requirement = next(
        item for item in runtime["key_requirements"] if item["purpose"] == purpose
    )
    requirement["retained_key_ids"].append(key_id)
    file_name = f"key-{key_id}"
    (secret_root / file_name).write_bytes(_secret_material(secret_index))
    active_entry_index = next(
        index
        for index, item in enumerate(manifest["entries"])
        if item["kind"] == "KEY" and item["purpose"] == purpose
    )
    manifest["entries"].insert(
        active_entry_index + 1,
        {
            "kind": "KEY",
            "file_name": file_name,
            "credential_ref": None,
            "purpose": purpose,
            "key_id": key_id,
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": "2099-01-01T00:00:00Z",
            "status": "VERIFY_ONLY",
        },
    )


def test_blocked_seed_fails_before_manifest_secret_or_database_access():
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        calls = []
        dbapi = _NoConnectDbApi()
        seed = load_internal_sandbox_synthetic_seed()
        with pytest.raises(InternalSandboxProductionPlanError) as raised:
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    seed,
                    blockers=(
                        "TAXONOMY_PROVISIONING_PORT_UNAVAILABLE",
                    ),
                ),
            )
        # Until the reviewed seed is executable, no secret manifest is read and
        # no PostgreSQL adapter can attempt a connection.
        assert raised.value.code == "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED"
        assert _MANIFEST_PATH not in calls
        assert dbapi.calls == []


def test_builds_exact_role_bound_pool_plan_and_zeroizes_every_secret_on_close():
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        calls = []
        dbapi = _NoConnectDbApi()
        seed = load_internal_sandbox_synthetic_seed()
        plan = build_internal_sandbox_server_plan(
            environment={
                "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
            },
            read_bytes=_reader(
                {
                    _DEPLOYMENT_PATH: deployment,
                    _RUNTIME_PATH: runtime,
                    _MANIFEST_PATH: manifest,
                },
                calls,
            ),
            dbapi=dbapi,
            seed_loader=lambda: replace(seed, blockers=()),
        )

        assert isinstance(plan, InternalSandboxApiServerPlan)
        assert plan.graceful_shutdown_timeout_seconds == 15
        registry = plan.runtime._resources[0]
        assert isinstance(registry, ManagedRuntimeSecrets)
        pool_end = 1 + len(INTERNAL_SANDBOX_CAPABILITY_ROLES)
        assert len(plan.runtime._resources[1:pool_end]) == len(
            INTERNAL_SANDBOX_CAPABILITY_ROLES
        )
        assert tuple(
            pool._profile.online_role
            for pool in plan.runtime._resources[1:pool_end]
        ) == tuple(role for _, role in INTERNAL_SANDBOX_CAPABILITY_ROLES)
        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH, _MANIFEST_PATH]
        assert dbapi.calls == []
        seed_readiness = next(
            resource
            for resource in plan.runtime._resources
            if isinstance(resource, PostgresInternalSandboxSeedReadiness)
        )
        assert seed_readiness._pool is plan.runtime._resources[4]
        materials = tuple(carrier.material for carrier in registry.carriers)
        assert all(any(material) for material in materials)
        oidc_readiness = next(
            resource
            for resource in plan.runtime._resources
            if resource.__class__.__name__ == "OidcProviderReadiness"
        )
        assert (
            oidc_readiness._provider._transport.__class__.__name__
            == "StdlibOidcJsonTransport"
        )
        assert any(
            oidc_readiness._provider._configuration.client_secret is material
            for material in materials
        )
        assert any(
            oidc_readiness._provider._subject_digest_key is material
            for material in materials
        )
        iam_application = plan.runtime._delegate._application.application._iam_application
        logout_handler = (
            iam_application._transport._dispatcher.bindings.revoke_my_session
        )
        assert isinstance(logout_handler, PostgresRevokeOwnedSessionHandler)
        assert isinstance(
            logout_handler._uow_factory,
            PsycopgOwnedSessionRevocationUnitOfWorkFactory,
        )
        assert logout_handler._uow_factory.connections is plan.runtime._resources[1]
        iam_bindings = iam_application._transport._dispatcher.bindings
        session_list_handler = iam_bindings.list_my_sessions
        assert isinstance(session_list_handler, ListMySessionsHandler)
        assert session_list_handler._repository is iam_bindings.get_me._repository
        assert session_list_handler._repository._app_connections is (
            plan.runtime._resources[1]
        )
        assert session_list_handler._cursor_codec is (
            iam_bindings.list_organization_access_invitations._cursor_codec
        )
        assert session_list_handler._cursor_codec is (
            iam_bindings.list_organization_memberships._cursor_codec
        )
        public_name_handler = iam_bindings.update_organization_public_name
        assert isinstance(
            public_name_handler,
            PostgresUpdateOrganizationPublicNameHandler,
        )
        assert isinstance(
            public_name_handler._uow_factory,
            PsycopgOrganizationPublicNameUnitOfWorkFactory,
        )
        assert public_name_handler._uow_factory.connections is (
            plan.runtime._resources[1]
        )
        assert public_name_handler._keys is (
            iam_bindings.issue_organization_access_invitation._keys
        )

        artifact_ids = tuple(
            item.artifact_id for item in INTERNAL_SANDBOX_ARTIFACT_REQUIREMENTS
        )
        assert artifact_ids[-8:] == (
            "trust-openapi-v1",
            "trust-events-v1",
            "trust-report-v1",
            "trust-triage-v1",
            "appeal-openapi-v1",
            "appeal-events-v1",
            "appeal-application-v1",
            "appeal-review-v1",
        )
        schema_readiness = tuple(
            resource
            for resource in plan.runtime._resources
            if isinstance(resource, PostgresSchemaCompatibilityReadiness)
        )
        assert tuple(
            item._requirement.component for item in schema_readiness
        ) == ("iam", "profile", "demand", "trust", "matching")
        iam_requirement = schema_readiness[0]._requirement
        demand_requirement = next(
            item._requirement
            for item in schema_readiness
            if item._requirement.component == "demand"
        )
        trust_requirement = next(
            item._requirement
            for item in schema_readiness
            if item._requirement.component == "trust"
        )
        matching_requirement = schema_readiness[-1]._requirement
        assert iam_requirement.expected_schema_head == 46
        assert iam_requirement.expected_contract_sha256.hex() == (
            "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
        )
        assert demand_requirement.expected_schema_head == 15
        assert demand_requirement.required_iam_schema_version == 45
        assert trust_requirement.expected_schema_head == 22
        assert trust_requirement.required_iam_schema_version == 46
        assert trust_requirement.required_demand_schema_version == 15
        assert trust_requirement.expected_iam_contract_sha256.hex() == (
            "14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d"
        )
        assert trust_requirement.expected_contract_sha256.hex() == (
            "3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8"
        )
        assert trust_requirement.expected_combined_contract_sha256.hex() == (
            "68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6"
        )
        assert matching_requirement.expected_schema_head == 9
        assert matching_requirement.required_iam_schema_version == 46
        trust_application = (
            plan.runtime._delegate._application.application._trust_application
        )
        assert trust_application is not None
        assert (
            trust_application._session_security._settings.additional_csrf_operation_ids
            == (
                "internalPilotEditorWrite",
                "trustSafetyWrite",
                "appealWrite",
                "acceptMatchingInvitation",
                "declineMatchingInvitation",
                "withdrawMatchingInvitationAcceptance",
                "chooseMatchingCreator",
                "closeMatchingSelection",
                "createMatchingInvitation",
                "publishMatchingInvitation",
                "invalidateMatchingAttempt",
                "claimCandidateSelectorAssignment",
                "claimMatchingReviewAssignment",
                "releaseMatchingReviewAssignment",
            )
        )
        trust_bindings = trust_application._dispatcher._bindings
        assert tuple(
            type(getattr(trust_bindings, name))
            for name in (
                "submit_report",
                "claim_case",
                "release_assignment",
                "save_triage",
                "publish_triage",
                "place_hold",
                "claim_hold_release",
                "release_hold",
                "publish_outcome",
            )
        ) == (
            PostgresSubmitSafetyReportHandler,
            PostgresClaimSafetyCaseHandler,
            PostgresReleaseSafetyCaseAssignmentHandler,
            PostgresSaveTrustTriageDraftHandler,
            PostgresPublishTrustTriageHandler,
            PostgresPlaceSafetyHoldHandler,
            PostgresClaimSafetyHoldReleaseHandler,
            PostgresReleaseSafetyHoldHandler,
            PostgresPublishTrustOutcomeHandler,
        )
        trust_runtime = trust_bindings.projections
        assert isinstance(trust_runtime._projections, PsycopgTrustHttpProjectionAdapter)
        assert isinstance(trust_runtime._receipt_keyring, TrustPostgresReceiptKeyring)
        assert isinstance(
            trust_runtime._sealed_notes._keyring, TrustSealedTextKeyring
        )
        assert callable(trust_runtime.list_my_completed_case_assignments)
        editor_application = (
            plan.runtime._delegate._application.application._editor_application
        )
        task_service = editor_application._api._task_service
        assert task_service._trust is trust_runtime
        demand_uows = editor_application._api._service._repo._demand_uows
        assert demand_uows[DemandPostgresOperation.CANCEL_OWNER] is demand_uows[
            DemandPostgresOperation.CREATE
        ]
        appeal_application = (
            plan.runtime._delegate._application.application._appeal_application
        )
        assert appeal_application is not None
        assert appeal_application._session_security is (
            trust_application._session_security
        )
        appeal_bindings = appeal_application._dispatcher._bindings
        assert tuple(
            type(getattr(appeal_bindings, name)).__name__
            for name in (
                "open_appeal",
                "save_application_draft",
                "submit_appeal",
                "claim_appeal",
                "release_assignment",
                "save_review_draft",
                "decide_appeal",
            )
        ) == (
            "PostgresOpenAppealHandler",
            "PostgresSaveAppealDraftHandler",
            "PostgresSubmitAppealHandler",
            "PostgresClaimAppealHandler",
            "PostgresReleaseAppealAssignmentHandler",
            "PostgresSaveAppealReviewDraftHandler",
            "PostgresDecideAppealHandler",
        )
        appeal_runtime = appeal_bindings.projections
        assert type(appeal_runtime).__name__ == "InternalSandboxAppealPostgresRuntime"
        assert appeal_runtime._command_gateway._applicant_connections is (
            plan.runtime._resources[8]
        )
        assert appeal_runtime._command_gateway._reviewer_connections is (
            plan.runtime._resources[10]
        )
        assert appeal_runtime._receipt_keyring.idempotency_key_digest_key_ids == (
            "trust-idempotency-2026-01",
        )
        assert appeal_runtime._receipt_keyring.payload_hash_key_ids == (
            "trust-payload-2026-01",
        )
        assert appeal_runtime._sealed_text._keyring.active_key_id == (
            "trust-sealed-note-v1"
        )
        for item in appeal_runtime._receipt_keyring._keys.values():
            assert any(item.material is material for material in materials)
        for item in appeal_runtime._sealed_text._keyring._keys.values():
            assert any(item.material is material for material in materials)
        matching_application = (
            plan.runtime._delegate._application.application._matching_application
        )
        assert matching_application is not None
        matching_bindings = matching_application._dispatcher._bindings
        assert isinstance(
            matching_bindings.create_invitation,
            PostgresCreateMatchingInvitationHandler,
        )
        assert isinstance(
            matching_bindings.publish_invitation,
            PostgresPublishMatchingInvitationHandler,
        )
        assert isinstance(
            matching_bindings.invalidate_attempt,
            PostgresInvalidateMatchingAttemptHandler,
        )
        assert isinstance(
            matching_bindings.reviewer_assignments,
            PsycopgMatchingReviewerAssignmentResolver,
        )
        matching_operational_service = matching_application._operational_service
        assert isinstance(
            matching_operational_service,
            MatchingPostgresOperationalHttpService,
        )
        assert (
            matching_operational_service._assignment_runtime._gateway.connections
            is plan.runtime._resources[14]
        )
        assert (
            matching_operational_service._review_runtime._gateway.connections
            is plan.runtime._resources[15]
        )
        assert (
            matching_operational_service._assignment_runtime._gateway.role
            == "matching_assignment"
        )
        assert (
            matching_operational_service._review_runtime._gateway.role
            == "matching_review"
        )
        matching_runtime = matching_bindings.projections._runtime
        assert matching_runtime._creator_connections is (
            plan.runtime._resources[12]
        )
        assert matching_runtime._selector_connections is (
            plan.runtime._resources[13]
        )
        assert matching_bindings.command_actors._runtime is matching_runtime
        assert (
            matching_bindings.command_actors._review_runtime
            is matching_operational_service._review_runtime
        )
        assert matching_bindings.respond_invitation._runtime is matching_runtime
        assert matching_bindings.choose_creator._runtime is matching_runtime
        assert matching_bindings.respond_invitation._keys is (
            matching_bindings.projections._keys
        )
        for matching_material in (
            matching_bindings.projections._keys.idempotency_key,
            matching_bindings.projections._keys.payload_hash_key,
            matching_bindings.projections._keys.read_cursor_key,
        ):
            assert any(matching_material is material for material in materials)
        editor_evidence = next(
            resource
            for resource in plan.runtime._resources
            if resource.__class__.__name__ == "InternalSandboxEditorEvidenceProvider"
        )
        assert isinstance(
            editor_evidence._demand_safety_hold,
            PsycopgTrustDemandSafetyHoldProvider,
        )
        assert (
            editor_evidence._demand_safety_hold._connections
            is plan.runtime._resources[11]
        )
        completed_verify_receipts = (
            plan.runtime._delegate._application.application._editor_application._api
            ._service._completed_verify_receipts
        )
        assert tuple(
            key_id for key_id, _material in completed_verify_receipts._idempotency_keys
        ) == (
            "demand-idempotency-2026-01",
            "demand-idempotency-retained-2025-12",
        )
        assert tuple(
            key_id for key_id, _material in completed_verify_receipts._payload_hash_keys
        ) == (
            "demand-payload-2026-01",
            "demand-payload-retained-2025-12",
        )
        completed_profile_lifecycle_receipts = (
            plan.runtime._delegate._application.application._editor_application._api
            ._service._completed_profile_lifecycle_receipts
        )
        assert isinstance(
            completed_profile_lifecycle_receipts,
            PsycopgProfileCompletedLifecycleReceiptProbe,
        )
        assert (
            completed_profile_lifecycle_receipts._connections
            is plan.runtime._resources[4]
        )
        assert tuple(
            key_id
            for key_id, _material
            in completed_profile_lifecycle_receipts._idempotency_keys
        ) == (
            "profile-idempotency-v1",
        )
        assert tuple(
            key_id
            for key_id, _material
            in completed_profile_lifecycle_receipts._payload_hash_keys
        ) == (
            "profile-payload-hash-v1",
        )

        plan.runtime.close()
        assert completed_profile_lifecycle_receipts._closed is True
        assert all(set(material) == {0} for material in materials)


def test_real_oidc_plan_selects_exact_pinned_public_ip_transport():
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        deployment["oidc"]["issuer"] = "https://login.example.com/tenant"
        deployment["oidc"]["network_binding"] = {
            "mode": "PINNED_PUBLIC_IP",
            "pinned_public_ipv4": "8.8.8.8",
        }
        calls = []
        seed = load_internal_sandbox_synthetic_seed()
        with patch(
            "desire_platform.internal_pilot.production_plan."
            "PinnedPublicIpOidcJsonTransport"
        ) as pinned_transport:
            plan = build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                        _DEPLOYMENT_PATH
                    )
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(seed, blockers=()),
            )
        pinned_transport.assert_called_once_with(
            issuer="https://login.example.com/tenant",
            pinned_public_ipv4="8.8.8.8",
        )
        oidc_readiness = next(
            resource
            for resource in plan.runtime._resources
            if resource.__class__.__name__ == "OidcProviderReadiness"
        )
        assert oidc_readiness._provider._transport is pinned_transport.return_value
        plan.runtime.close()


def test_distinct_secret_carriers_cannot_reuse_the_same_key_material():
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        entries = {
            item["purpose"]: item
            for item in manifest["entries"]
            if item["kind"] == "KEY"
        }
        source = secret_root / entries["OIDC_RECIPIENT_BINDING"]["file_name"]
        destination = secret_root / entries["IAM_READ_CURSOR"]["file_name"]
        destination.write_bytes(source.read_bytes())
        calls = []
        dbapi = _NoConnectDbApi()

        with pytest.raises(InternalSandboxProductionPlanError) as raised:
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                        _DEPLOYMENT_PATH
                    )
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )
        assert raised.value.code == "INTERNAL_SANDBOX_PRODUCTION_PLAN_INVALID"
        assert dbapi.calls == []
        assert "secret" not in repr(raised.value).lower()


def test_runtime_artifact_drift_fails_before_secret_manifest_is_read():
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        runtime["artifacts"][0]["sha256"] = "0" * 64
        calls = []
        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )
        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH]


@pytest.mark.parametrize(
    ("purpose", "unreviewed_key_id"),
    (
        ("DEMAND_IDEMPOTENCY", "demand-idempotency-v1"),
        ("DEMAND_PAYLOAD_HASH", "demand-payload-hash-v1"),
        ("TRUST_IDEMPOTENCY", "trust-idempotency-v1"),
        ("TRUST_PAYLOAD_HASH", "trust-payload-hash-v1"),
    ),
)
def test_receipt_key_identity_drift_fails_before_secret_manifest_is_read(
    purpose: str,
    unreviewed_key_id: str,
):
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        requirement = next(
            item for item in runtime["key_requirements"] if item["purpose"] == purpose
        )
        requirement["active_key_id"] = unreviewed_key_id
        requirement["retained_key_ids"] = [unreviewed_key_id]
        entry = next(item for item in manifest["entries"] if item["purpose"] == purpose)
        entry["key_id"] = unreviewed_key_id
        calls = []

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH]


@pytest.mark.parametrize(
    ("purpose", "retained_key_ids"),
    (
        ("DEMAND_IDEMPOTENCY", ["demand-idempotency-2026-01"]),
        (
            "DEMAND_IDEMPOTENCY",
            [
                "demand-idempotency-2026-01",
                "demand-idempotency-retained-2025-12",
                "demand-idempotency-unreviewed",
            ],
        ),
        (
            "DEMAND_IDEMPOTENCY",
            [
                "demand-idempotency-retained-2025-12",
                "demand-idempotency-2026-01",
            ],
        ),
        ("DEMAND_PAYLOAD_HASH", ["demand-payload-2026-01"]),
        (
            "DEMAND_PAYLOAD_HASH",
            [
                "demand-payload-2026-01",
                "demand-payload-retained-2025-12",
                "demand-payload-unreviewed",
            ],
        ),
        (
            "DEMAND_PAYLOAD_HASH",
            [
                "demand-payload-retained-2025-12",
                "demand-payload-2026-01",
            ],
        ),
    ),
)
def test_demand_receipt_key_history_must_be_exact_active_first_before_manifest_read(
    purpose: str,
    retained_key_ids: list[str],
):
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        requirement = next(
            item for item in runtime["key_requirements"] if item["purpose"] == purpose
        )
        requirement["retained_key_ids"] = retained_key_ids
        calls = []

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH]


def test_demand_key_ids_cannot_alias_another_purpose_before_manifest_read():
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        requirement = next(
            item
            for item in runtime["key_requirements"]
            if item["purpose"] == "DEMAND_CLIENT_REFERENCE"
        )
        requirement["active_key_id"] = "demand-idempotency-retained-2025-12"
        requirement["retained_key_ids"] = [
            "demand-idempotency-retained-2025-12"
        ]
        calls = []

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH]


@pytest.mark.parametrize("failure", ("missing", "wrong_order"))
def test_demand_retained_manifest_entry_is_mandatory_and_ordered(failure: str):
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        entries = manifest["entries"]
        retained_index = next(
            index
            for index, item in enumerate(entries)
            if item["key_id"] == "demand-idempotency-retained-2025-12"
        )
        retained = entries.pop(retained_index)
        if failure == "wrong_order":
            payload_index = next(
                index
                for index, item in enumerate(entries)
                if item["key_id"] == "demand-payload-2026-01"
            )
            entries.insert(payload_index + 1, retained)
        calls = []
        dbapi = _NoConnectDbApi()

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH, _MANIFEST_PATH]
        assert dbapi.calls == []


@pytest.mark.parametrize("failure", ("missing", "alias"))
def test_demand_retained_material_must_be_present_and_purpose_distinct(failure: str):
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        entries = {
            (item["purpose"], item["key_id"]): item
            for item in manifest["entries"]
            if item["kind"] == "KEY"
        }
        active = secret_root / entries[
            ("DEMAND_IDEMPOTENCY", "demand-idempotency-2026-01")
        ]["file_name"]
        retained = secret_root / entries[
            (
                "DEMAND_PAYLOAD_HASH",
                "demand-payload-retained-2025-12",
            )
        ]["file_name"]
        if failure == "missing":
            retained.unlink()
        else:
            retained.write_bytes(active.read_bytes())
        dbapi = _NoConnectDbApi()

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    [],
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert dbapi.calls == []


def test_demand_retained_material_is_verify_only():
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        retained = next(
            item
            for item in manifest["entries"]
            if item["key_id"] == "demand-payload-retained-2025-12"
        )
        retained["status"] = "ACTIVE"
        dbapi = _NoConnectDbApi()

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    [],
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert dbapi.calls == []


@pytest.mark.parametrize(
    "purpose",
    ("MATCHING_IDEMPOTENCY", "MATCHING_PAYLOAD_HASH", "MATCHING_READ_CURSOR"),
)
def test_matching_keys_reject_unbound_retained_history(purpose: str):
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        _add_retained_key(
            secret_root=secret_root,
            runtime=runtime,
            manifest=manifest,
            purpose=purpose,
            key_id="matching-retained-v0",
            secret_index=510,
        )
        dbapi = _NoConnectDbApi()

        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    [],
                ),
                dbapi=dbapi,
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )

        assert dbapi.calls == []


@pytest.mark.parametrize(
    "purpose",
    ("TRUST_IDEMPOTENCY", "TRUST_PAYLOAD_HASH", "TRUST_SEALED_NOTE"),
)
def test_trust_keys_accept_bounded_active_first_retained_history(purpose: str):
    with tempfile.TemporaryDirectory() as directory:
        secret_root = Path(directory)
        deployment, runtime, manifest = _documents(secret_root)
        retained_id = "trust-retained-2025-12"
        _add_retained_key(
            secret_root=secret_root,
            runtime=runtime,
            manifest=manifest,
            purpose=purpose,
            key_id=retained_id,
            secret_index=500,
        )
        calls = []
        plan = build_internal_sandbox_server_plan(
            environment={
                "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
            },
            read_bytes=_reader(
                {
                    _DEPLOYMENT_PATH: deployment,
                    _RUNTIME_PATH: runtime,
                    _MANIFEST_PATH: manifest,
                },
                calls,
            ),
            dbapi=_NoConnectDbApi(),
            seed_loader=lambda: replace(
                load_internal_sandbox_synthetic_seed(), blockers=()
            ),
        )
        trust_application = (
            plan.runtime._delegate._application.application._trust_application
        )
        trust_runtime = trust_application._dispatcher._bindings.projections
        trust_retained = (
            trust_runtime._receipt_keyring.idempotency_key_digest_key_ids
            if purpose == "TRUST_IDEMPOTENCY"
            else trust_runtime._receipt_keyring.payload_hash_key_ids
            if purpose == "TRUST_PAYLOAD_HASH"
            else trust_runtime._sealed_notes._keyring.retained_key_ids
        )
        appeal_application = (
            plan.runtime._delegate._application.application._appeal_application
        )
        appeal_runtime = appeal_application._dispatcher._bindings.projections
        appeal_retained = (
            appeal_runtime._receipt_keyring.idempotency_key_digest_key_ids
            if purpose == "TRUST_IDEMPOTENCY"
            else appeal_runtime._receipt_keyring.payload_hash_key_ids
            if purpose == "TRUST_PAYLOAD_HASH"
            else appeal_runtime._sealed_text._keyring.retained_key_ids
        )
        active_id = next(
            item["active_key_id"]
            for item in runtime["key_requirements"]
            if item["purpose"] == purpose
        )
        assert trust_retained == (active_id, retained_id)
        assert appeal_retained == (active_id, retained_id)
        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH, _MANIFEST_PATH]
        plan.runtime.close()


@pytest.mark.parametrize(
    "purpose",
    ("TRUST_IDEMPOTENCY", "TRUST_PAYLOAD_HASH", "TRUST_SEALED_NOTE"),
)
def test_trust_keys_reject_more_than_four_retained_identities(purpose: str):
    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        requirement = next(
            item
            for item in runtime["key_requirements"]
            if item["purpose"] == purpose
        )
        requirement["retained_key_ids"].extend(
            f"trust-retained-2025-{month:02d}" for month in range(8, 12)
        )
        calls = []
        with pytest.raises(InternalSandboxProductionPlanError):
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                        _DEPLOYMENT_PATH
                    )
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    calls,
                ),
                dbapi=_NoConnectDbApi(),
                seed_loader=lambda: replace(
                    load_internal_sandbox_synthetic_seed(), blockers=()
                ),
            )
        assert calls == [_DEPLOYMENT_PATH, _RUNTIME_PATH]


def test_failure_after_secret_resolution_zeroizes_all_issued_carriers():
    captured = []

    class RecordingProvider(FilesystemSecretProvider):
        def resolve_credential(self, profile):
            carrier = super().resolve_credential(profile)
            captured.append(carrier)
            return carrier

        def resolve_key(self, purpose, key_id):
            carrier = super().resolve_key(purpose, key_id)
            captured.append(carrier)
            return carrier

    with tempfile.TemporaryDirectory() as directory:
        deployment, runtime, manifest = _documents(Path(directory))
        seed = load_internal_sandbox_synthetic_seed()
        with patch(
            "desire_platform.internal_pilot.production_plan.FilesystemSecretProvider",
            RecordingProvider,
        ), pytest.raises(InternalSandboxProductionPlanError) as raised:
            build_internal_sandbox_server_plan(
                environment={
                    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": _DEPLOYMENT_PATH
                },
                read_bytes=_reader(
                    {
                        _DEPLOYMENT_PATH: deployment,
                        _RUNTIME_PATH: runtime,
                        _MANIFEST_PATH: manifest,
                    },
                    [],
                ),
                dbapi=object(),
                seed_loader=lambda: replace(seed, blockers=()),
            )

        assert raised.value.code == "INTERNAL_SANDBOX_PRODUCTION_PLAN_INVALID"
        assert captured
        assert all(set(carrier.material) == {0} for carrier in captured)
        assert "secret" not in repr(raised.value).lower()
