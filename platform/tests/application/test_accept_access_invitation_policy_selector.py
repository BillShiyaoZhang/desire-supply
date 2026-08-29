"""TEST-APP-POLICY-SELECTOR-002 executable application RED tests.

The fixtures contain only facts that IssueAccessInvitation and
PublishPolicyBundle would already have persisted.  These tests deliberately use
an opaque selector digest and a stale legacy ``(purpose, role)`` lookup so the
Accept handler and safe projection must follow the stored digest.
"""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import timedelta
import unittest

from desire_platform.identity_access.application.access_invitations import (
    _acceptance_safe_response,
)
from desire_platform.identity_access.domain.errors import IamError
from desire_platform.identity_access.domain.invitations import (
    AccessInvitation,
    InvitationStatus,
)
from desire_platform.identity_access.domain.policies import PolicyBundle
from tests.support.iam_application_builders import (
    OTHER_POLICY_SELECTOR_DIGEST,
    AcceptanceFixture,
    creator_acceptance_fixture,
    initial_admin_acceptance_fixture,
    policy_bundle_fixture,
)


class AcceptAccessInvitationPolicySelectorTest(unittest.TestCase):
    """Accept resolves current policy from immutable persisted selector facts."""

    def test_selector_fields_are_owned_by_production_domain_facts(self) -> None:
        """Pending-field fixture seams cannot replace real immutable fields."""

        expected = {
            AccessInvitation: {"policy_selector_digest"},
            PolicyBundle: {
                "selector_digest",
                "status",
                "effective_at",
                "effective_until",
            },
        }
        missing = {
            fact_type.__name__: sorted(
                field_names
                - {declared.name for declared in fields(fact_type)}
            )
            for fact_type, field_names in expected.items()
        }
        missing = {
            fact_type: names
            for fact_type, names in missing.items()
            if names
        }
        self.assertEqual(missing, {})

    def test_stale_issued_bundle_is_409_before_hold_or_writes(self) -> None:
        """A valid newer current makes an old client refresh, not authorize."""

        fixture = creator_acceptance_fixture()
        self._install_policy_upgrade(
            fixture,
            legacy_current_bundle_id=fixture.ids.current_policy_bundle_id,
        )
        before = fixture.store.snapshot()

        with self.assertRaises(IamError) as raised:
            fixture.handler.handle(actor=fixture.actor, command=fixture.command)

        # IamError has no safe details contract yet, so this RED fixes only the
        # stable code.  HTTP presentation will later expose current bundle ID.
        self.assertEqual(raised.exception.code, "POLICY_BUNDLE_CHANGED")
        self.assertEqual(fixture.store.snapshot(), before)
        self.assertEqual(fixture.hold.calls, [])
        self.assertEqual(fixture.fault_injector.write_count, 0)

    def test_current_bundle_can_differ_from_issued_and_resolves_by_digest(self) -> None:
        """The stored digest beats both issued history and the legacy role key."""

        fixture = creator_acceptance_fixture()
        current_command = self._install_policy_upgrade(
            fixture,
            # This decoy remains on v1.  A purpose/role lookup therefore cannot
            # pass this test even though selector.current_bundle_id is valid v2.
            legacy_current_bundle_id=fixture.ids.policy_bundle_id,
        )

        try:
            result = fixture.handler.handle(
                actor=fixture.actor,
                command=current_command,
            )
        except IamError as error:
            self.fail(
                "stored-selector current v2 should succeed although issued is v1; "
                "got %s" % error.code
            )

        snapshot = fixture.store.snapshot()
        accepted = snapshot["invitations"][fixture.ids.invitation_id]
        self.assertEqual(accepted.status, InvitationStatus.ACCEPTED)
        self.assertEqual(
            accepted.issued_policy_bundle_id,
            fixture.ids.policy_bundle_id,
        )
        self.assertEqual(
            {
                acceptance["policy_bundle_id"]
                for acceptance in snapshot["policy_acceptances"].values()
            },
            {fixture.ids.current_policy_bundle_id},
        )
        self.assertEqual(
            {
                grant["policy_bundle_id"]
                for grant in snapshot["consent_grants"].values()
            },
            {fixture.ids.current_policy_bundle_id},
        )
        self.assertEqual(
            result.safe_response["invitation"]["required_policy_bundle_id"],
            fixture.ids.current_policy_bundle_id,
        )

    def test_invalid_current_configuration_fails_before_hold_and_writes(self) -> None:
        """Selector identity, status and the UTC window are all fail-closed."""

        cases = (
            "missing-selector",
            "wrong-selector-row",
            "missing-current-pointer",
            "pointer-to-missing-bundle",
            "current-bundle-id-mismatch",
            "current-bundle-cross-selector",
            "current-bundle-draft",
            "current-bundle-superseded",
            "current-bundle-retired",
            "current-bundle-future",
            "current-bundle-effective-until-equal",
            "current-bundle-expired",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = creator_acceptance_fixture(
                    include_policy_selector=case != "missing-selector"
                )
                self._make_policy_configuration_invalid(fixture, case=case)
                before = fixture.store.snapshot()
                writes_before = fixture.fault_injector.write_count
                hold_before = len(fixture.hold.calls)
                observed_code = None

                try:
                    fixture.handler.handle(
                        actor=fixture.actor,
                        command=fixture.command,
                    )
                except IamError as error:
                    observed_code = error.code

                self.assertEqual(
                    {
                        "code": observed_code,
                        "snapshot_unchanged": fixture.store.snapshot() == before,
                        "hold_call_delta": len(fixture.hold.calls) - hold_before,
                        "write_delta": (
                            fixture.fault_injector.write_count - writes_before
                        ),
                    },
                    {
                        "code": "POLICY_CONFIGURATION_UNAVAILABLE",
                        "snapshot_unchanged": True,
                        "hold_call_delta": 0,
                        "write_delta": 0,
                    },
                )

    def test_role_grants_copy_the_invitation_selector_digest(self) -> None:
        """Both authority fact kinds retain the selector that authorized them."""

        cases = (
            (
                "creator",
                creator_acceptance_fixture,
                "user_role_grants",
                "user_role_grant_id",
            ),
            (
                "initial-admin",
                initial_admin_acceptance_fixture,
                "membership_role_grants",
                "membership_role_grant_id",
            ),
        )
        for name, factory, table_name, id_attribute in cases:
            with self.subTest(case=name):
                fixture = factory()
                fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                snapshot = fixture.store.snapshot()
                grant = snapshot[table_name][getattr(fixture.ids, id_attribute)]
                accepted = snapshot["invitations"][fixture.ids.invitation_id]

                self.assertEqual(
                    {
                        "grant_selector_digest": grant.get(
                            "policy_selector_digest"
                        ),
                        "accepted_invitation_selector_digest": getattr(
                            accepted,
                            "policy_selector_digest",
                            None,
                        ),
                    },
                    {
                        "grant_selector_digest": fixture.policy_selector_digest,
                        "accepted_invitation_selector_digest": (
                            fixture.policy_selector_digest
                        ),
                    },
                )

    def test_me_requirement_reads_each_persisted_grant_selector(self) -> None:
        """Presentation cannot reconstruct selector identity from role/scope."""

        cases = (
            (
                "creator",
                creator_acceptance_fixture,
                "user_role_grants",
                "user_role_grant_id",
                "CREATOR_ENROLLMENT",
                "CREATOR",
                "USER_ROLE",
                None,
            ),
            (
                "initial-admin",
                initial_admin_acceptance_fixture,
                "membership_role_grants",
                "membership_role_grant_id",
                "ORGANIZATION_MEMBERSHIP",
                "ORG_ADMIN",
                "ORGANIZATION_ROLE",
                "organization_initial_admin_001",
            ),
        )
        for (
            name,
            factory,
            table_name,
            id_attribute,
            purpose,
            role,
            scope_type,
            scope_id,
        ) in cases:
            with self.subTest(case=name):
                fixture = factory()
                result = fixture.handler.handle(
                    actor=fixture.actor,
                    command=fixture.command,
                )
                snapshot = fixture.store.snapshot()
                grant = snapshot[table_name][getattr(fixture.ids, id_attribute)]
                requirements = result.safe_response["me"]["policy_requirements"]
                self.assertEqual(len(requirements), 1)
                requirement = requirements[0]
                selector = snapshot["policy_selectors"][
                    fixture.policy_selector_digest
                ]

                self.assertEqual(
                    {
                        "persisted_grant_selector": grant.get(
                            "policy_selector_digest"
                        ),
                        "projected_selector": requirement["selector_digest"],
                        "required_bundle": requirement[
                            "required_policy_bundle_id"
                        ],
                        "satisfied": requirement["satisfied"],
                        "missing": requirement["missing_document_ids"],
                        "purpose": requirement["purpose"],
                        "role": requirement["role"],
                        "scope_type": requirement["scope_type"],
                        "scope_id": requirement["scope_id"],
                    },
                    {
                        "persisted_grant_selector": fixture.policy_selector_digest,
                        "projected_selector": fixture.policy_selector_digest,
                        "required_bundle": selector["current_bundle_id"],
                        "satisfied": True,
                        "missing": [],
                        "purpose": purpose,
                        "role": role,
                        "scope_type": scope_type,
                        "scope_id": scope_id,
                    },
                )

    def test_role_grants_persist_closed_authority_source_facts(self) -> None:
        """Projection never has to guess source, grantor, version or revocation."""

        cases = (
            (
                "creator",
                creator_acceptance_fixture,
                "user_role_grants",
                "user_role_grant_id",
            ),
            (
                "initial-admin",
                initial_admin_acceptance_fixture,
                "membership_role_grants",
                "membership_role_grant_id",
            ),
        )
        for name, factory, table_name, id_attribute in cases:
            with self.subTest(case=name):
                fixture = factory()
                fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                grant = fixture.store.snapshot()[table_name][
                    getattr(fixture.ids, id_attribute)
                ]

                self.assertEqual(
                    {
                        "source_invitation_id": grant.get(
                            "source_invitation_id"
                        ),
                        "policy_selector_digest": grant.get(
                            "policy_selector_digest"
                        ),
                        "granted_by_kind": grant.get("granted_by_kind"),
                        "granted_by_id": grant.get("granted_by_id"),
                        "revoked_at": grant.get("revoked_at"),
                        "revocation_reason_code": grant.get(
                            "revocation_reason_code"
                        ),
                        "aggregate_version": grant.get("aggregate_version"),
                    },
                    {
                        "source_invitation_id": fixture.ids.invitation_id,
                        "policy_selector_digest": fixture.policy_selector_digest,
                        "granted_by_kind": "USER",
                        "granted_by_id": fixture.ids.user_id,
                        "revoked_at": None,
                        "revocation_reason_code": None,
                        "aggregate_version": 1,
                    },
                )

    def test_inactive_membership_or_organization_has_no_policy_requirement(self) -> None:
        """A retained relationship row is not an active authority source."""

        cases = (
            ("membership-suspended", "memberships", "status", "SUSPENDED"),
            ("membership-revoked", "memberships", "status", "REVOKED"),
            ("organization-suspended", "organizations", "status", "SUSPENDED"),
        )
        for name, table_name, field_name, value in cases:
            with self.subTest(case=name):
                fixture = initial_admin_acceptance_fixture()
                fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                snapshot = fixture.store.snapshot()
                key = (
                    fixture.ids.membership_id
                    if table_name == "memberships"
                    else fixture.ids.organization_id
                )
                snapshot[table_name][key][field_name] = value

                response = self._project(snapshot, fixture)

                self.assertEqual(
                    response["me"]["policy_requirements"],
                    [],
                )

    def test_orphan_role_grant_source_fails_the_projection_closed(self) -> None:
        """A grant cannot authorize when its accepted Invitation fact is absent."""

        fixture = creator_acceptance_fixture()
        fixture.handler.handle(actor=fixture.actor, command=fixture.command)
        snapshot = fixture.store.snapshot()
        snapshot["invitations"].pop(fixture.ids.invitation_id)

        with self.assertRaises(IamError) as raised:
            self._project(snapshot, fixture)

        self.assertEqual(
            raised.exception.code,
            "POLICY_CONFIGURATION_UNAVAILABLE",
        )

    def test_requirement_needs_exact_current_document_evidence(self) -> None:
        """A reused document ID cannot hide hash or legal-effect drift."""

        cases = (
            ("wrong-hash", "policy_document_sha256", "f" * 64),
            ("wrong-legal-effect", "legal_effect", "CONSENT_TEXT"),
            ("wrong-user", "user_id", "user_other_009"),
            ("wrong-bundle", "policy_bundle_id", "policy_bundle_other_009"),
        )
        for name, field_name, value in cases:
            with self.subTest(case=name):
                fixture = creator_acceptance_fixture()
                fixture.handler.handle(actor=fixture.actor, command=fixture.command)
                snapshot = fixture.store.snapshot()
                acceptance = snapshot["policy_acceptances"][
                    fixture.ids.terms_acceptance_id
                ]
                acceptance[field_name] = value

                response = self._project(snapshot, fixture)
                requirement = response["me"]["policy_requirements"][0]

                self.assertFalse(requirement["satisfied"])
                self.assertEqual(
                    requirement["missing_document_ids"],
                    [fixture.ids.terms_document_id],
                )

    def _install_policy_upgrade(
        self,
        fixture: AcceptanceFixture,
        *,
        legacy_current_bundle_id: str,
    ):
        now = fixture.clock.now()
        superseded_issued = policy_bundle_fixture(
            fixture.ids,
            policy_bundle_id=fixture.ids.policy_bundle_id,
            selector_digest=fixture.policy_selector_digest,
            status="SUPERSEDED",
            effective_at=now - timedelta(days=2),
            effective_until=now,
        )
        current = policy_bundle_fixture(
            fixture.ids,
            policy_bundle_id=fixture.ids.current_policy_bundle_id,
            selector_digest=fixture.policy_selector_digest,
            status="ACTIVE",
            # Inclusive boundary: effective_at == server_now is current.
            effective_at=now,
            effective_until=None,
        )
        selector = dict(
            fixture.store.snapshot()["policy_selectors"][
                fixture.policy_selector_digest
            ]
        )
        selector["current_bundle_id"] = fixture.ids.current_policy_bundle_id
        selector["aggregate_version"] += 1
        legacy_key = (
            fixture.invitation.purpose.value,
            fixture.invitation.target_role.value,
        )
        fixture.store.seed(
            policy_bundles={
                fixture.ids.policy_bundle_id: superseded_issued,
                fixture.ids.current_policy_bundle_id: current,
            },
            policy_selectors={fixture.policy_selector_digest: selector},
            current_policy_bundles={
                legacy_key: legacy_current_bundle_id,
            },
        )
        return replace(
            fixture.command,
            policy_bundle_id=fixture.ids.current_policy_bundle_id,
        )

    @staticmethod
    def _project(snapshot, fixture: AcceptanceFixture):
        return _acceptance_safe_response(
            snapshot,
            invitation=snapshot.get("invitations", {}).get(
                fixture.ids.invitation_id,
                fixture.invitation,
            ),
            actor_id=fixture.ids.user_id,
            activated_scope=(
                "USER_ROLE"
                if fixture.invitation.organization_id is None
                else "ORGANIZATION_MEMBERSHIP"
            ),
            now=fixture.clock.now(),
        )

    def _make_policy_configuration_invalid(
        self,
        fixture: AcceptanceFixture,
        *,
        case: str,
    ) -> None:
        if case == "missing-selector":
            return
        if case == "wrong-selector-row":
            self._replace_selector(
                fixture,
                selector_digest=OTHER_POLICY_SELECTOR_DIGEST,
            )
            return
        if case == "missing-current-pointer":
            self._replace_selector(fixture, current_bundle_id=None)
            return
        if case == "pointer-to-missing-bundle":
            self._replace_selector(
                fixture,
                current_bundle_id="policy_bundle_missing_current_009",
            )
            return
        if case == "current-bundle-id-mismatch":
            self._replace_current_bundle(
                fixture,
                fact_policy_bundle_id="policy_bundle_mismatched_fact_009",
            )
            return
        if case == "current-bundle-cross-selector":
            self._replace_current_bundle(
                fixture,
                selector_digest=OTHER_POLICY_SELECTOR_DIGEST,
            )
            return
        if case.startswith("current-bundle-"):
            suffix = case.removeprefix("current-bundle-")
            now = fixture.clock.now()
            changes = {
                "draft": {
                    "status": "DRAFT",
                    "effective_at": None,
                },
                "superseded": {"status": "SUPERSEDED"},
                "retired": {"status": "RETIRED"},
                "future": {"effective_at": now + timedelta(microseconds=1)},
                "effective-until-equal": {"effective_until": now},
                "expired": {
                    "effective_until": now - timedelta(microseconds=1)
                },
            }
            self._replace_current_bundle(fixture, **changes[suffix])
            return
        raise AssertionError("unknown policy configuration case: %s" % case)

    def _replace_selector(self, fixture: AcceptanceFixture, **changes) -> None:
        selector = dict(
            fixture.store.snapshot()["policy_selectors"][
                fixture.policy_selector_digest
            ]
        )
        selector.update(changes)
        fixture.store.seed(
            policy_selectors={fixture.policy_selector_digest: selector}
        )

    def _replace_current_bundle(
        self,
        fixture: AcceptanceFixture,
        *,
        selector_digest=None,
        status="ACTIVE",
        effective_at=None,
        effective_until=None,
        fact_policy_bundle_id=None,
    ) -> None:
        if effective_at is None and status != "DRAFT":
            effective_at = fixture.clock.now() - timedelta(days=1)
        bundle = policy_bundle_fixture(
            fixture.ids,
            policy_bundle_id=(
                fixture.ids.policy_bundle_id
                if fact_policy_bundle_id is None
                else fact_policy_bundle_id
            ),
            selector_digest=(
                fixture.policy_selector_digest
                if selector_digest is None
                else selector_digest
            ),
            status=status,
            effective_at=effective_at,
            effective_until=effective_until,
        )
        fixture.store.seed(
            policy_bundles={fixture.ids.policy_bundle_id: bundle}
        )


if __name__ == "__main__":
    unittest.main()
