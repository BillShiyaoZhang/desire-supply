"""Closed unit checks for the PostgreSQL Accept response projection."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from uuid import UUID
from zoneinfo import ZoneInfo

from desire_platform.identity_access.adapters.postgres.accept_access_invitation import (
    AcceptPostgresConfigurationError,
    PsycopgAcceptAccessInvitationUnitOfWorkFactory,
    _acceptance_response_has_exact_authority,
    _read_acceptance_me_snapshot,
    _read_transaction_timestamp_utc,
    _response_matches_request,
    _safe_response,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_authority_lifecycle_builders import ClosedSchemaValidator
from tests.support.iam_read_model_builders import (
    NOW,
    build_authoritative_facts,
    build_expected_bodies,
)


class AcceptAccessInvitationResponseProjectionTest(unittest.TestCase):
    def test_transaction_execution_profile_pins_closed_utc_first(self) -> None:
        connection = _TransactionProfileConnection()
        request = SimpleNamespace(
            scope=SimpleNamespace(
                actor_user_id=UUID(int=1),
                invitation_id=UUID(int=2),
                session_id=UUID(int=3),
                session_family_id=UUID(int=4),
                auth_transaction_id=UUID(int=5),
                policy_selector_digest=b"s" * 32,
                policy_bundle_id=UUID(int=6),
                command_id=UUID(int=7),
                organization_id=None,
            ),
            receipt=SimpleNamespace(
                idempotency_key_digest_key_id="idempotency-v1",
                idempotency_key_digest=b"i" * 32,
            ),
        )
        factory = PsycopgAcceptAccessInvitationUnitOfWorkFactory(
            connections=object(),
            event_validator=object(),
            response_validator=object(),
        )

        factory._configure_transaction(connection, request)

        self.assertEqual(
            connection.calls[0],
            ("SET LOCAL TIME ZONE 'UTC'", None),
        )
        self.assertEqual(
            [
                call
                for call in connection.calls
                if call[0].startswith("SET LOCAL TIME ZONE")
            ],
            [("SET LOCAL TIME ZONE 'UTC'", None)],
        )
        self.assertNotIn("TimeZone", connection.settings)

    def test_database_transaction_time_normalizes_non_utc_and_rejects_naive(self) -> None:
        database_now = datetime(
            2026,
            8,
            26,
            18,
            30,
            tzinfo=ZoneInfo("Asia/Shanghai"),
        )

        normalized = _read_transaction_timestamp_utc(
            _TimestampConnection(database_now)
        )

        self.assertEqual(
            normalized,
            datetime(2026, 8, 26, 10, 30, tzinfo=timezone.utc),
        )
        self.assertIs(normalized.tzinfo, timezone.utc)
        self.assertEqual(database_now.utcoffset(), timedelta(hours=8))
        with self.assertRaises(AcceptPostgresConfigurationError):
            _read_transaction_timestamp_utc(
                _TimestampConnection(database_now.replace(tzinfo=None))
            )

    def test_post_write_snapshot_uses_the_canonical_full_me_projector(self) -> None:
        authoritative = build_authoritative_facts()
        facts = deepcopy(authoritative["getMe"])
        facts.pop("session")
        facts.pop("family")
        connection = _SnapshotConnection([[(facts,)]])

        projected = _read_acceptance_me_snapshot(connection, now=NOW)

        self.assertEqual(projected, build_expected_bodies(authoritative)["getMe"])
        self.assertEqual(
            connection.statements,
            ["SELECT iam_api.read_acceptance_me_snapshot_v2()"],
        )

    def test_post_write_snapshot_rejects_null_open_or_ambiguous_rows(self) -> None:
        for rows in (
            [],
            [(None,)],
            [({"user": {}},)],
            [({},), ({},)],
        ):
            with self.subTest(rows=rows):
                with self.assertRaises(IamError) as captured:
                    _read_acceptance_me_snapshot(
                        _SnapshotConnection([rows]),
                        now=NOW,
                    )
                self.assertEqual(captured.exception.code, "SERVICE_UNAVAILABLE")

    def test_new_authority_projects_its_satisfied_policy_requirement(self) -> None:
        actor_id = UUID("10000000-0000-4000-8000-000000000001")
        invitation_id = UUID("20000000-0000-4000-8000-000000000001")
        membership_id = UUID("30000000-0000-4000-8000-000000000001")
        organization_id = UUID("40000000-0000-4000-8000-000000000001")
        bundle_id = UUID("50000000-0000-4000-8000-000000000001")
        selector_digest = bytes.fromhex("a" * 64)
        timestamp = datetime(2026, 8, 25, 8, 0, tzinfo=timezone.utc)

        cases = (
            (
                "creator",
                "USER_ROLE",
                "CREATOR_ENROLLMENT",
                "CREATOR",
                None,
                None,
            ),
            (
                "demand-owner",
                "ORGANIZATION_MEMBERSHIP",
                "ORGANIZATION_MEMBERSHIP",
                "DEMAND_OWNER",
                organization_id,
                SimpleNamespace(
                    organization_type="BUSINESS",
                    public_name="Synthetic Organization",
                    status="ACTIVE",
                    aggregate_version=1,
                ),
            ),
        )
        for (
            name,
            activated_scope,
            purpose,
            role,
            target_organization_id,
            organization,
        ) in cases:
            with self.subTest(case=name):
                request = SimpleNamespace(
                    scope=SimpleNamespace(
                        actor_user_id=actor_id,
                        invitation_id=invitation_id,
                        organization_id=target_organization_id,
                        policy_selector_digest=selector_digest,
                        policy_bundle_id=bundle_id,
                        target_role=role,
                    ),
                    generated_ids=SimpleNamespace(membership_id=membership_id),
                    expected_invitation_version=1,
                )
                plan = SimpleNamespace(
                    user=SimpleNamespace(display_handle="invited_user"),
                    organization=organization,
                    invitation=SimpleNamespace(
                        purpose=purpose,
                        target_role=role,
                        masked_recipient_label="i***@example.test",
                        is_initial_admin=False,
                        expires_at=timestamp,
                        created_at=timestamp,
                    ),
                )

                requirement = {
                    "selector_digest": selector_digest.hex(),
                    "purpose": purpose,
                    "role": role,
                    "scope_type": (
                        "USER_ROLE"
                        if target_organization_id is None
                        else "ORGANIZATION_ROLE"
                    ),
                    "scope_id": (
                        None
                        if target_organization_id is None
                        else str(target_organization_id)
                    ),
                    "satisfied": True,
                    "required_policy_bundle_id": str(bundle_id),
                    "missing_document_ids": [],
                }
                me = {
                    "user_id": str(actor_id),
                    "status": "ACTIVE",
                    "display_handle": "invited_user",
                    "user_roles": ["CREATOR"] if role == "CREATOR" else [],
                    "memberships": (
                        []
                        if target_organization_id is None
                        else [
                            {
                                "membership_id": str(membership_id),
                                "organization": {
                                    "organization_id": str(organization_id),
                                    "public_name": "Synthetic Organization",
                                    "type": "BUSINESS",
                                    "status": "ACTIVE",
                                    "aggregate_version": 1,
                                    "entity_tag": '"v1"',
                                },
                                "status": "ACTIVE",
                                "roles": [role],
                                "aggregate_version": 1,
                                "entity_tag": '"v1"',
                            }
                        ]
                    ),
                    "policy_requirements": [requirement],
                    "aggregate_version": 2,
                    "entity_tag": '"v2"',
                }
                response = _safe_response(
                    request=request,
                    plan=plan,
                    invitation_version=2,
                    activated_scope=activated_scope,
                    me=me,
                )
                ClosedSchemaValidator.for_openapi().validate(
                    response,
                    "AccessInvitationAcceptanceDto",
                )
                self.assertTrue(_response_matches_request(response, request))
                self.assertTrue(
                    _acceptance_response_has_exact_authority(
                        response,
                        actor_user_id=actor_id,
                        invitation_id=invitation_id,
                        expected_version=1,
                        policy_selector_digest=selector_digest,
                        policy_bundle_id=bundle_id,
                        target_role=role,
                        organization_id=target_organization_id,
                    )
                )

                self.assertEqual(
                    response["me"]["policy_requirements"],
                    [requirement],
                )

                response_with_other_requirement = deepcopy(response)
                other_requirement = deepcopy(
                    response_with_other_requirement["me"]["policy_requirements"][0]
                )
                other_requirement["selector_digest"] = "b" * 64
                response_with_other_requirement["me"]["policy_requirements"].append(
                    other_requirement
                )
                self.assertTrue(
                    _response_matches_request(response_with_other_requirement, request)
                )

                mutations = {
                    "inactive-me": lambda body: body["me"].__setitem__(
                        "status", "PENDING_ENROLLMENT"
                    ),
                    "authority-absent": (
                        lambda body: body["me"].__setitem__(
                            "user_roles" if role == "CREATOR" else "memberships",
                            [],
                        )
                    ),
                    "requirement-absent": lambda body: body["me"].__setitem__(
                        "policy_requirements", []
                    ),
                    "requirement-not-unique": lambda body: body["me"].__setitem__(
                        "policy_requirements",
                        body["me"]["policy_requirements"] * 2,
                    ),
                    "wrong-selector": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__("selector_digest", "b" * 64),
                    "wrong-purpose": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__(
                        "purpose",
                        (
                            "CREATOR_ENROLLMENT"
                            if role != "CREATOR"
                            else "ORGANIZATION_MEMBERSHIP"
                        ),
                    ),
                    "wrong-role": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__(
                        "role",
                        "ORG_ADMIN" if role != "ORG_ADMIN" else "DEMAND_OWNER",
                    ),
                    "wrong-scope": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__(
                        "scope_type",
                        "ORGANIZATION_ROLE" if role == "CREATOR" else "USER_ROLE",
                    ),
                    "wrong-scope-id": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__(
                        "scope_id",
                        str(organization_id) if role == "CREATOR" else None,
                    ),
                    "wrong-bundle": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__(
                        "required_policy_bundle_id", str(invitation_id)
                    ),
                    "unsatisfied": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__("satisfied", False),
                    "documents-missing": lambda body: body["me"][
                        "policy_requirements"
                    ][0].__setitem__("missing_document_ids", [str(invitation_id)]),
                }
                for mutation_name, mutate in mutations.items():
                    with self.subTest(case=name, corruption=mutation_name):
                        corrupted = deepcopy(response)
                        mutate(corrupted)
                        self.assertFalse(
                            _response_matches_request(corrupted, request),
                            f"{name}:{mutation_name}",
                        )

class _SnapshotCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _SnapshotConnection:
    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        return _SnapshotCursor(self._outcomes.pop(0))


class _TimestampCursor:
    def __init__(self, value):
        self._value = value

    def fetchone(self):
        return (self._value,)


class _TimestampConnection:
    def __init__(self, value):
        self._value = value

    def execute(self, statement):
        if statement != "SELECT transaction_timestamp()":
            raise AssertionError(statement)
        return _TimestampCursor(self._value)


class _TransactionProfileCursor:
    def __init__(self, value=None):
        self._value = value

    def fetchone(self):
        return self._value


class _TransactionProfileConnection:
    def __init__(self):
        self.calls = []
        self.settings = {}

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if statement.startswith("SET LOCAL"):
            return _TransactionProfileCursor()
        if statement == "SELECT pg_catalog.set_config(%s,%s,true)":
            name, value = parameters
            self.settings[name] = value
            return _TransactionProfileCursor((value,))
        if statement == "SELECT current_setting(%s,true)":
            return _TransactionProfileCursor((self.settings[parameters[0]],))
        raise AssertionError(statement)


if __name__ == "__main__":
    unittest.main()
