"""TEST-APP-IAM-READ-001 semantic RED for the nine IAM read models.

The production module is intentionally importable but default-deny in this
slice.  These tests specify the application behaviour without using the HTTP
router, command handlers, PostgreSQL adapter, or outbox implementation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import hashlib
import json
import unittest
from typing import Any

from desire_platform.identity_access.application.read_models import (
    GetSessionBootstrapQuery,
    PageRequest,
    ReadActor,
    project_canonical_me_dto,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.ports.read_models import (
    ReadModelSnapshot,
)
from tests.support.iam_read_model_builders import (
    ACTOR_USER_ID,
    CONTACT_SENTINEL,
    CREATOR_POLICY_BUNDLE_ID,
    CURRENT_SESSION_ID,
    MASKED_CSRF_RESPONSE,
    NOW,
    OPERATION_IDS,
    ORGANIZATION_ID,
    OTHER_ORGANIZATION_ID,
    OTHER_USER_ID,
    RAW_INVITATION_TOKEN_SENTINEL,
    RAW_SESSION_HANDLE_SENTINEL,
    STATEMENT_BUDGETS,
    TERMS_DOCUMENT_ID,
    all_secret_sentinels,
    build_read_model_fixture,
    cursor_claims,
    expected_page,
    expected_response,
    next_cursor_for,
    paged_query,
)


PAGED_OPERATIONS = (
    "listMyConsentGrants",
    "listMySessions",
    "listOrganizationAccessInvitations",
    "listOrganizationMemberships",
)


def _observe(fixture, operation_id: str, query=None) -> dict[str, object]:
    """Convert only the closed IAM rejection into a comparable observation."""

    selected_query = fixture.queries[operation_id] if query is None else query
    try:
        response = fixture.handlers[operation_id].handle(selected_query)
    except IamError as error:
        return {"kind": "error", "code": error.code}
    return {
        "kind": "ok",
        "operation_id": response.operation_id,
        "body": response.body_copy(),
        "entity_tag": response.entity_tag,
        "cache_policy": response.cache_policy.value,
    }


def _expect_error(code: str) -> dict[str, str]:
    return {"kind": "error", "code": code}


class _SequencedClock:
    def __init__(self, *values) -> None:
        self._values = values
        self.calls = 0

    def now(self):
        if self.calls >= len(self._values):
            raise AssertionError("read-model clock was called too many times")
        value = self._values[self.calls]
        self.calls += 1
        return value


def _secret_found(value: object, sentinel: object) -> bool:
    if isinstance(value, dict):
        return any(_secret_found(item, sentinel) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_secret_found(item, sentinel) for item in value)
    if isinstance(sentinel, bytes):
        return value == sentinel
    return isinstance(value, str) and str(sentinel) in value


def _make_demand_owner_policy_share_terms(
    facts: dict[str, Any], *, canonical_body: str | None = None
) -> tuple[dict[str, Any], str]:
    creator_policy = facts["policies"][0]
    demand_policy = facts["policies"][1]
    creator_document = deepcopy(creator_policy["documents"][0])
    demand_bundle_id = "policy_bundle_read_demand_owner_0003"
    selector_payload = {
        "access_purpose": "ORGANIZATION_MEMBERSHIP",
        "scope_type": "ORGANIZATION_ROLE",
        "target_role": "DEMAND_OWNER",
        "jurisdiction": "CN",
        "locale": "en",
    }
    selector_digest = hashlib.sha256(
        json.dumps(
            selector_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    demand_policy["selector"].update(
        **selector_payload,
        selector_digest=selector_digest,
        current_bundle_id=demand_bundle_id,
    )
    demand_policy["bundle"].update(
        policy_bundle_id=demand_bundle_id,
        selector_digest=selector_digest,
    )
    creator_document["bundle_id"] = demand_bundle_id
    if canonical_body is not None:
        creator_document["canonical_body"] = canonical_body
        creator_document["content_sha256"] = hashlib.sha256(
            canonical_body.encode("utf-8")
        ).hexdigest()
    demand_policy["documents"] = [creator_document]

    membership = facts["memberships"][0]
    membership["role_grants"][0].update(
        role_code="DEMAND_OWNER",
        policy_selector_digest=selector_digest,
    )
    invitation_id = membership["membership"]["source_invitation_id"]
    source_invitation = next(
        invitation
        for invitation in facts["source_invitations"]
        if invitation["invitation_id"] == invitation_id
    )
    source_invitation.update(
        target_role="DEMAND_OWNER",
        policy_selector_digest=selector_digest,
        issued_policy_bundle_id=demand_bundle_id,
    )
    return creator_document, demand_bundle_id


class IamReadModelSemanticRedTests(unittest.TestCase):
    def test_canonical_me_projector_accepts_json_facts_without_session_context(
        self,
    ) -> None:
        fixture = build_read_model_fixture()
        facts = deepcopy(fixture.repository.facts("getMe"))
        facts.pop("session")
        facts.pop("family")
        json_facts = json.loads(
            json.dumps(
                facts,
                default=lambda value: value.isoformat().replace("+00:00", "Z"),
            )
        )

        projected = project_canonical_me_dto(json_facts, at=NOW)

        self.assertEqual(projected, fixture.expected["getMe"])
        self.assertIsInstance(
            json_facts["policies"][0]["bundle"]["effective_at"], str
        )

    def test_nine_operations_project_exact_closed_success_contracts(self) -> None:
        fixture = build_read_model_fixture()

        for operation_id in OPERATION_IDS:
            with self.subTest(operation_id=operation_id):
                self.assertEqual(
                    _observe(fixture, operation_id),
                    expected_response(fixture, operation_id),
                )

        self.assertEqual(fixture.repository.write_count, 0)
        self.assertEqual(fixture.repository.lock_count, 0)

    def test_cross_subject_and_cross_tenant_facts_fail_without_disclosure(self) -> None:
        cases = []

        fixture = build_read_model_fixture()
        fixture.repository.facts("getMe")["user"]["user_id"] = OTHER_USER_ID
        cases.append(
            ("me-user-mismatch", fixture, "getMe", "SERVICE_UNAVAILABLE", None)
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("listMyConsentGrants")["rows"][0]["grant"][
            "user_id"
        ] = OTHER_USER_ID
        cases.append(
            (
                "consent-owner-mismatch",
                fixture,
                "listMyConsentGrants",
                "SERVICE_UNAVAILABLE",
                None,
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("listMySessions")["rows"][1]["user_id"] = OTHER_USER_ID
        cases.append(
            (
                "session-owner-mismatch",
                fixture,
                "listMySessions",
                "SERVICE_UNAVAILABLE",
                None,
            )
        )

        fixture = build_read_model_fixture()
        summary_facts = fixture.repository.facts("getOrganizationSummary")
        summary_facts["actor"]["membership"] = None
        summary_facts["actor"]["roles"] = []
        summary_facts["organization"] = None
        cross_tenant_query = replace(
            fixture.queries["getOrganizationSummary"],
            organization_id=OTHER_ORGANIZATION_ID,
        )
        cases.append(
            (
                "cross-tenant-summary-is-not-disclosed",
                fixture,
                "getOrganizationSummary",
                "RESOURCE_NOT_FOUND",
                cross_tenant_query,
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("listOrganizationAccessInvitations")["actor"][
            "roles"
        ] = []
        cases.append(
            (
                "invitation-list-not-admin",
                fixture,
                "listOrganizationAccessInvitations",
                "RESOURCE_NOT_FOUND",
                None,
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("listOrganizationMemberships")["actor"][
            "membership"
        ]["status"] = "SUSPENDED"
        cases.append(
            (
                "membership-list-inactive-actor",
                fixture,
                "listOrganizationMemberships",
                "RESOURCE_NOT_FOUND",
                None,
            )
        )

        for name, fixture, operation_id, expected_code, query in cases:
            with self.subTest(case=name):
                self.assertEqual(
                    _observe(fixture, operation_id, query),
                    _expect_error(expected_code),
                )

    def test_adjacent_statuses_are_rejected_or_projected_at_the_read_time(self) -> None:
        cases: list[tuple[str, object, str, dict[str, object]]] = []

        fixture = build_read_model_fixture()
        fixture.repository.facts("getSessionBootstrap")["family"]["status"] = "REVOKED"
        cases.append(
            (
                "revoked-current-family",
                fixture,
                "getSessionBootstrap",
                _expect_error("AUTHENTICATION_REQUIRED"),
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("inspectAccessInvitation")["invitation"]["status"] = "ACCEPTED"
        cases.append(
            (
                "accepted-invitation-is-not-previewable",
                fixture,
                "inspectAccessInvitation",
                _expect_error("ACCESS_INVITATION_UNAVAILABLE"),
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("getPolicyBundle")["bundle"]["status"] = "SUPERSEDED"
        cases.append(
            (
                "superseded-public-bundle",
                fixture,
                "getPolicyBundle",
                _expect_error("RESOURCE_NOT_FOUND"),
            )
        )

        fixture = build_read_model_fixture()
        fixture.repository.facts("getMe")["user"]["status"] = "SUSPENDED"
        cases.append(
            ("suspended-self", fixture, "getMe", _expect_error("AUTHENTICATION_REQUIRED"))
        )

        fixture = build_read_model_fixture()
        consent = fixture.repository.facts("listMyConsentGrants")["rows"][0]["grant"]
        consent["expires_at"] = NOW
        expected = expected_response(fixture, "listMyConsentGrants")
        expected["body"]["items"][0]["expires_at"] = "2026-08-08T12:00:00Z"
        expected["body"]["items"][0]["status"] = "EXPIRED"
        cases.append(("consent-deadline-is-exclusive", fixture, "listMyConsentGrants", expected))

        fixture = build_read_model_fixture()
        old_session = fixture.repository.facts("listMySessions")["rows"][1]
        old_session.update(
            {
                "status": "ACTIVE",
                "idle_expires_at": NOW,
                "absolute_expires_at": NOW + timedelta(hours=1),
            }
        )
        expected = expected_response(fixture, "listMySessions")
        expected["body"]["items"][1]["expires_at"] = "2026-08-08T12:00:00Z"
        expected["body"]["items"][1]["status"] = "EXPIRED"
        cases.append(("session-deadline-is-exclusive", fixture, "listMySessions", expected))

        fixture = build_read_model_fixture()
        fixture.repository.facts("getOrganizationSummary")["organization"]["status"] = "SUSPENDED"
        cases.append(
            (
                "suspended-organization-summary",
                fixture,
                "getOrganizationSummary",
                _expect_error("RESOURCE_NOT_FOUND"),
            )
        )

        fixture = build_read_model_fixture()
        invitation = fixture.repository.facts("listOrganizationAccessInvitations")["rows"][0][
            "invitation"
        ]
        invitation["expires_at"] = NOW
        expected = expected_response(fixture, "listOrganizationAccessInvitations")
        expected["body"]["items"][0]["expires_at"] = "2026-08-08T12:00:00Z"
        expected["body"]["items"][0]["status"] = "EXPIRED"
        cases.append(
            (
                "issued-invitation-deadline-is-exclusive",
                fixture,
                "listOrganizationAccessInvitations",
                expected,
            )
        )

        fixture = build_read_model_fixture()
        membership_row = fixture.repository.facts("listOrganizationMemberships")["rows"][1]
        membership_row["membership"]["status"] = "REVOKED"
        membership_row["role_grants"][0]["revoked_at"] = NOW - timedelta(days=1)
        expected = expected_response(fixture, "listOrganizationMemberships")
        expected["body"]["items"][1]["status"] = "REVOKED"
        cases.append(
            (
                "revoked-membership-retains-historical-role-label",
                fixture,
                "listOrganizationMemberships",
                expected,
            )
        )

        for name, fixture, operation_id, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(_observe(fixture, operation_id), expected)

    def test_policy_current_pointer_orphan_and_hash_drift_fail_closed(self) -> None:
        mutators = (
            (
                "public-document-body-hash-drift",
                "getPolicyBundle",
                lambda facts: facts["documents"][0].update(
                    canonical_body="tampered canonical body"
                ),
            ),
            (
                "public-current-pointer-missing",
                "getPolicyBundle",
                lambda facts: facts["selector"].update(current_bundle_id=None),
            ),
            (
                "public-offer-fact-drift",
                "getPolicyBundle",
                lambda facts: facts["offers"][0].update(
                    recipient_ref="different-internal-recipient"
                ),
            ),
            (
                "duplicate-document-release-identity",
                "getPolicyBundle",
                _duplicate_document_identity,
            ),
            (
                "preview-selector-digest-drift",
                "inspectAccessInvitation",
                lambda facts: facts["policy"]["selector"].update(
                    selector_digest="f" * 64
                ),
            ),
            (
                "preview-invitation-selector-drift",
                "inspectAccessInvitation",
                lambda facts: facts["invitation"].update(
                    policy_selector_digest="f" * 64
                ),
            ),
            (
                "me-source-invitation-orphan",
                "getMe",
                lambda facts: facts["source_invitations"].clear(),
            ),
            (
                "me-current-document-hash-drift",
                "getMe",
                lambda facts: facts["policies"][0]["documents"][0].update(
                    content_sha256="e" * 64
                ),
            ),
            (
                "admin-list-current-pointer-missing",
                "listOrganizationAccessInvitations",
                lambda facts: facts["rows"][0]["policy"]["selector"].update(
                    current_bundle_id=None
                ),
            ),
        )

        for name, operation_id, mutate in mutators:
            with self.subTest(case=name):
                fixture = build_read_model_fixture()
                mutate(fixture.repository.facts(operation_id))
                self.assertEqual(
                    _observe(fixture, operation_id),
                    _expect_error("POLICY_CONFIGURATION_UNAVAILABLE"),
                )

    def test_get_me_reuses_identical_acceptance_across_policy_bundles(self) -> None:
        fixture = build_read_model_fixture()
        facts = fixture.repository.facts("getMe")
        creator_document, demand_bundle_id = _make_demand_owner_policy_share_terms(
            facts
        )

        self.assertEqual(
            facts["acceptances"],
            [
                {
                    "user_id": ACTOR_USER_ID,
                    "document_id": creator_document["document_id"],
                    "content_sha256": creator_document["content_sha256"],
                    "policy_bundle_id": CREATOR_POLICY_BUNDLE_ID,
                }
            ],
        )

        observation = _observe(fixture, "getMe")

        self.assertEqual(observation["kind"], "ok")
        requirements = {
            item["role"]: item
            for item in observation["body"]["policy_requirements"]
        }
        self.assertTrue(requirements["CREATOR"]["satisfied"])
        self.assertEqual(
            {
                key: requirements["DEMAND_OWNER"][key]
                for key in (
                    "purpose",
                    "role",
                    "scope_type",
                    "scope_id",
                    "satisfied",
                    "required_policy_bundle_id",
                    "missing_document_ids",
                )
            },
            {
                "purpose": "ORGANIZATION_MEMBERSHIP",
                "role": "DEMAND_OWNER",
                "scope_type": "ORGANIZATION_ROLE",
                "scope_id": ORGANIZATION_ID,
                "satisfied": True,
                "required_policy_bundle_id": demand_bundle_id,
                "missing_document_ids": [],
            },
        )

    def test_get_me_does_not_reuse_same_document_with_different_content_hash(
        self,
    ) -> None:
        fixture = build_read_model_fixture()
        facts = fixture.repository.facts("getMe")
        _, demand_bundle_id = _make_demand_owner_policy_share_terms(
            facts,
            canonical_body="A materially revised demand-owner terms body.",
        )

        observation = _observe(fixture, "getMe")

        self.assertEqual(observation["kind"], "ok")
        demand_requirement = next(
            item
            for item in observation["body"]["policy_requirements"]
            if item["role"] == "DEMAND_OWNER"
        )
        self.assertEqual(
            demand_requirement["required_policy_bundle_id"], demand_bundle_id
        )
        self.assertFalse(demand_requirement["satisfied"])
        self.assertEqual(
            demand_requirement["missing_document_ids"], [TERMS_DOCUMENT_ID]
        )

    def test_get_me_rejects_damaged_policy_acceptance_facts(self) -> None:
        mutators = (
            (
                "malformed-content-hash",
                lambda acceptance: acceptance.update(content_sha256="not-a-sha256"),
            ),
            (
                "missing-source-bundle",
                lambda acceptance: acceptance.update(policy_bundle_id=None),
            ),
        )

        for name, mutate in mutators:
            with self.subTest(case=name):
                fixture = build_read_model_fixture()
                mutate(fixture.repository.facts("getMe")["acceptances"][0])
                self.assertEqual(
                    _observe(fixture, "getMe"),
                    _expect_error("SERVICE_UNAVAILABLE"),
                )

    def test_keyset_pagination_is_stable_and_cursor_bound(self) -> None:
        for operation_id in PAGED_OPERATIONS:
            fixture = build_read_model_fixture()
            with self.subTest(operation_id=operation_id, page="first"):
                self.assertEqual(
                    _observe(
                        fixture,
                        operation_id,
                        paged_query(fixture, operation_id, cursor=None),
                    ),
                    expected_page(fixture, operation_id, index=0),
                )
            with self.subTest(operation_id=operation_id, page="second"):
                self.assertEqual(
                    _observe(
                        fixture,
                        operation_id,
                        paged_query(
                            fixture,
                            operation_id,
                            cursor=next_cursor_for(operation_id),
                        ),
                    ),
                    expected_page(fixture, operation_id, index=1),
                )

        invalid_cases: list[tuple[str, object, str, str]] = []

        fixture = build_read_model_fixture()
        invalid_cases.append(
            ("tampered", fixture, "listMySessions", "not_a_signed_cursor")
        )

        for name, changed_claims in (
            (
                "wrong-actor",
                {"actor_user_id": OTHER_USER_ID},
            ),
            (
                "wrong-operation",
                {"operation_id": "listMyConsentGrants"},
            ),
            (
                "wrong-organization",
                {"organization_id": OTHER_ORGANIZATION_ID},
            ),
            (
                "expired",
                {"expires_at": NOW},
            ),
        ):
            fixture = build_read_model_fixture()
            raw = f"cursor_override_{name}_0001"
            base = cursor_claims(
                operation_id="listOrganizationMemberships",
                after_created_at=NOW - timedelta(days=30),
                after_id="membership_read_actor_0001",
                organization_id=ORGANIZATION_ID,
                page_limit=1,
            )
            fixture.cursor_codec.overrides[raw] = replace(base, **changed_claims)
            invalid_cases.append(
                (name, fixture, "listOrganizationMemberships", raw)
            )

        for name, fixture, operation_id, raw_cursor in invalid_cases:
            with self.subTest(cursor_case=name):
                self.assertEqual(
                    _observe(
                        fixture,
                        operation_id,
                        paged_query(
                            fixture,
                            operation_id,
                            cursor=raw_cursor,
                        ),
                    ),
                    _expect_error("INVALID_REQUEST"),
                )

    def test_paged_reads_use_post_read_time_for_database_snapshots_and_new_cursors(
        self,
    ) -> None:
        request_now = NOW
        transaction_time = NOW + timedelta(microseconds=1)
        response_now = NOW + timedelta(microseconds=2)

        for operation_id in PAGED_OPERATIONS:
            with self.subTest(operation_id=operation_id):
                fixture = build_read_model_fixture()
                clock = _SequencedClock(request_now, response_now)
                fixture.handlers[operation_id]._clock = clock
                fixture.repository.transaction_time_overrides[operation_id] = (
                    transaction_time
                )
                original_snapshot = fixture.repository._snapshot

                def database_snapshot(selected_operation_id, **arguments):
                    self.assertEqual(clock.calls, 1)
                    snapshot = original_snapshot(
                        selected_operation_id, **arguments
                    )
                    facts = snapshot.facts_copy()
                    facts["snapshot_at"] = transaction_time
                    return ReadModelSnapshot.from_mapping(
                        transaction_time=transaction_time,
                        statement_count=snapshot.statement_count,
                        facts=facts,
                    )

                fixture.repository._snapshot = database_snapshot

                self.assertEqual(
                    _observe(
                        fixture,
                        operation_id,
                        paged_query(
                            fixture,
                            operation_id,
                            cursor=None,
                            limit=1,
                        ),
                    ),
                    expected_page(fixture, operation_id, index=0),
                )
                self.assertEqual(clock.calls, 2)
                self.assertEqual(len(fixture.cursor_codec.encoded), 1)
                claims = fixture.cursor_codec.encoded[0]
                self.assertEqual(claims.snapshot_at, transaction_time)
                self.assertEqual(claims.issued_at, response_now)
                self.assertEqual(
                    claims.expires_at,
                    response_now + timedelta(minutes=15),
                )

    def test_strong_etags_and_cache_policy_are_owned_by_server_versions(self) -> None:
        fixture = build_read_model_fixture()
        expected_meta = {
            "getSessionBootstrap": (None, "no-store"),
            "inspectAccessInvitation": ('"v1"', "no-store"),
            "getPolicyBundle": ('"v1"', "public, max-age=31536000, immutable"),
            "getMe": ('"v7"', "no-store"),
            "listMyConsentGrants": (None, "no-store"),
            "listMySessions": (None, "no-store"),
            "getOrganizationSummary": ('"v4"', "no-store"),
            "listOrganizationAccessInvitations": (None, "no-store"),
            "listOrganizationMemberships": (None, "no-store"),
        }

        for operation_id, expected in expected_meta.items():
            with self.subTest(operation_id=operation_id):
                observed = _observe(fixture, operation_id)
                self.assertEqual(
                    (observed.get("entity_tag"), observed.get("cache_policy")),
                    expected,
                )

    def test_statement_budget_utc_and_repository_order_corruption_fail_closed(self) -> None:
        for operation_id in OPERATION_IDS:
            fixture = build_read_model_fixture()
            fixture.repository.statement_overrides[operation_id] = (
                STATEMENT_BUDGETS[operation_id] + 1
            )
            with self.subTest(operation_id=operation_id, corruption="query-budget"):
                self.assertEqual(
                    _observe(fixture, operation_id),
                    _expect_error("SERVICE_UNAVAILABLE"),
                )

        fixture = build_read_model_fixture()
        fixture.repository.transaction_time_overrides["getMe"] = NOW.replace(
            tzinfo=None
        )
        with self.subTest(operation_id="getMe", corruption="naive-transaction-time"):
            self.assertEqual(
                _observe(fixture, "getMe"),
                _expect_error("SERVICE_UNAVAILABLE"),
            )

        for operation_id in PAGED_OPERATIONS:
            fixture = build_read_model_fixture()
            rows = fixture.repository.facts(operation_id)["rows"]
            rows.reverse()
            with self.subTest(operation_id=operation_id, corruption="row-order"):
                self.assertEqual(
                    _observe(fixture, operation_id),
                    _expect_error("SERVICE_UNAVAILABLE"),
                )

            fixture = build_read_model_fixture()
            rows = fixture.repository.facts(operation_id)["rows"]
            rows.append(deepcopy(rows[0]))
            with self.subTest(operation_id=operation_id, corruption="duplicate-row"):
                self.assertEqual(
                    _observe(fixture, operation_id),
                    _expect_error("SERVICE_UNAVAILABLE"),
                )

    def test_secret_sentinels_are_absent_from_repr_results_and_telemetry(self) -> None:
        fixture = build_read_model_fixture()

        self.assertNotIn(
            RAW_SESSION_HANDLE_SENTINEL,
            repr(fixture.queries["getSessionBootstrap"]),
        )
        self.assertNotIn(
            RAW_INVITATION_TOKEN_SENTINEL,
            repr(fixture.queries["inspectAccessInvitation"]),
        )
        cursor_query = paged_query(
            fixture,
            "listMySessions",
            cursor=next_cursor_for("listMySessions"),
        )
        self.assertNotIn(next_cursor_for("listMySessions"), repr(cursor_query))

        snapshot = ReadModelSnapshot.from_mapping(
            transaction_time=NOW,
            statement_count=1,
            facts={
                "contact_locator": CONTACT_SENTINEL,
                "raw_handle": RAW_SESSION_HANDLE_SENTINEL,
            },
        )
        self.assertNotIn(CONTACT_SENTINEL, repr(snapshot))
        self.assertNotIn(RAW_SESSION_HANDLE_SENTINEL, repr(snapshot))

        for operation_id in OPERATION_IDS:
            with self.subTest(operation_id=operation_id):
                observed = _observe(fixture, operation_id)
                self.assertEqual(observed.get("kind"), "ok")
                for sentinel in all_secret_sentinels():
                    self.assertFalse(
                        _secret_found(observed, sentinel),
                        f"{operation_id} exposed a secret sentinel",
                    )
                for event in fixture.telemetry.events:
                    for sentinel in (*all_secret_sentinels(), MASKED_CSRF_RESPONSE):
                        self.assertFalse(
                            _secret_found(event.__dict__, sentinel),
                            f"{operation_id} exposed a secret in telemetry",
                        )

    def test_query_and_snapshot_contracts_are_immutable_and_detached(self) -> None:
        actor = ReadActor(
            actor_user_id=ACTOR_USER_ID,
            current_session_id=CURRENT_SESSION_ID,
            trace_id="trace_immutable_0001",
        )
        query = GetSessionBootstrapQuery(
            actor=actor,
            raw_session_handle=RAW_SESSION_HANDLE_SENTINEL,
        )
        with self.assertRaises(FrozenInstanceError):
            query.raw_session_handle = "replacement"  # type: ignore[misc]

        page = PageRequest(limit=1, cursor="cursor_secret_immutable_0001")
        with self.assertRaises(FrozenInstanceError):
            page.limit = 2  # type: ignore[misc]
        self.assertNotIn("cursor_secret_immutable_0001", repr(page))

        original = {"nested": {"values": [1, 2]}}
        snapshot = ReadModelSnapshot.from_mapping(
            transaction_time=NOW,
            statement_count=1,
            facts=original,
        )
        original["nested"]["values"].append(3)
        detached = snapshot.facts_copy()
        self.assertEqual(detached, {"nested": {"values": [1, 2]}})
        detached["nested"]["values"].append(4)
        self.assertEqual(snapshot.facts_copy(), {"nested": {"values": [1, 2]}})

        fixture = build_read_model_fixture()
        self.assertFalse(hasattr(fixture.repository, "get"))
        self.assertFalse(hasattr(fixture.repository, "write"))
        self.assertFalse(hasattr(fixture.repository, "lock"))


def _duplicate_document_identity(facts: dict[str, object]) -> None:
    duplicate = deepcopy(facts["documents"][0])
    duplicate.update(
        {
            "document_id": "policy_document_duplicate_0004",
            "position": 3,
        }
    )
    facts["documents"].append(duplicate)


if __name__ == "__main__":
    unittest.main()
