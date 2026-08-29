"""Contracts for the secret-safe ten-account Trust deployment runner."""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_internal_sandbox_e2e.py"
PRODUCTION_EDITOR_CONTRACTS = (
    ROOT
    / "platform"
    / "src"
    / "desire_platform"
    / "internal_pilot"
    / "editor"
    / "contracts.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "run_internal_sandbox_e2e", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("ten-account E2E runner cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _json_copy(value):
    return json.loads(json.dumps(value, ensure_ascii=False))


def _valid_editor_choices(module):
    taxonomy_options = {
        "DOMAIN": (
            ("DOMAIN.SOFTWARE", "软件", "TAXONOMY_BUNDLE_NODE"),
        ),
        "PROBLEM_TYPE": (
            ("PROBLEM.OPERATIONS", "运营改进", "TAXONOMY_BUNDLE_NODE"),
        ),
        "TASK": (
            ("TASK.ANALYSIS", "分析", "TAXONOMY_BUNDLE_NODE"),
        ),
        "SKILL": (
            ("SKILL.SYSTEMS_ANALYSIS", "系统分析", "TAXONOMY_BUNDLE_NODE"),
        ),
    }
    fields = []
    for binding in module._EDITOR_CHOICE_BINDINGS:
        (
            resource_type,
            path_template,
            value_contract,
            intended_node_kind,
            status,
            reason_code,
            _source,
            fixed_options,
        ) = binding
        options = (
            taxonomy_options[intended_node_kind]
            if fixed_options is None
            else fixed_options
        )
        fields.append(
            {
                "resource_type": resource_type,
                "path_template": path_template,
                "value_contract": value_contract,
                "intended_node_kind": intended_node_kind,
                "status": status,
                "reason_code": reason_code,
                "options": [
                    {"value": value, "label": label, "source": source}
                    for value, label, source in options
                ],
            }
        )
    return {
        "schema_version": "editor-choices-v1",
        "locale": "zh-CN",
        "fields": fields,
    }


def _valid_configuration_data(module):
    now = module.datetime.now(module.timezone.utc).replace(microsecond=0)
    return {
        "schema_version": "editor-configuration-v2",
        "deployment_mode": "INTERNAL_SANDBOX",
        "taxonomy_bundle": {
            "bundle_id": "50000000-0000-4000-8000-000000000001",
            "status": "CURRENT_APPROVED",
            "effective_at": (now - module.timedelta(days=1)).isoformat(),
            "effective_until": (now + module.timedelta(days=1)).isoformat(),
        },
        "editor_choices": _valid_editor_choices(module),
    }


def _active_creator_second_authority_fixture():
    organization_id = "11111111-1111-4111-8111-111111111111"
    user_id = "22222222-2222-4222-8222-222222222222"
    membership_id = "33333333-3333-4333-8333-333333333333"
    creator_bundle_id = "44444444-4444-4444-8444-444444444444"
    owner_bundle_id = "55555555-5555-4555-8555-555555555555"
    organization = {
        "organization_id": organization_id,
        "public_name": "INTERNAL_SANDBOX 合成组织",
        "type": "CREATOR_TEAM",
        "status": "ACTIVE",
        "aggregate_version": 1,
        "entity_tag": '"v1"',
    }
    creator_requirement = {
        "selector_digest": "a" * 64,
        "purpose": "CREATOR_ENROLLMENT",
        "role": "CREATOR",
        "scope_type": "USER_ROLE",
        "scope_id": None,
        "satisfied": True,
        "required_policy_bundle_id": creator_bundle_id,
        "missing_document_ids": [],
    }
    owner_requirement = {
        "selector_digest": "b" * 64,
        "purpose": "ORGANIZATION_MEMBERSHIP",
        "role": "DEMAND_OWNER",
        "scope_type": "ORGANIZATION_ROLE",
        "scope_id": organization_id,
        "satisfied": True,
        "required_policy_bundle_id": owner_bundle_id,
        "missing_document_ids": [],
    }
    before = {
        "user_id": user_id,
        "status": "ACTIVE",
        "display_handle": "creator_01",
        "user_roles": ["CREATOR"],
        "memberships": [],
        "policy_requirements": [creator_requirement],
        "aggregate_version": 7,
        "entity_tag": '"v7"',
    }
    accepted = {
        **before,
        "memberships": [
            {
                "membership_id": membership_id,
                "organization": organization,
                "status": "ACTIVE",
                "roles": ["DEMAND_OWNER"],
                "aggregate_version": 1,
                "entity_tag": '"v1"',
            }
        ],
        "policy_requirements": [creator_requirement, owner_requirement],
        "aggregate_version": 8,
        "entity_tag": '"v8"',
    }
    return organization_id, before, accepted


def _production_editor_choice_bindings():
    syntax = ast.parse(
        PRODUCTION_EDITOR_CONTRACTS.read_text(encoding="utf-8"),
        filename=str(PRODUCTION_EDITOR_CONTRACTS),
    )
    for statement in syntax.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name)
            and target.id == "_EDITOR_CHOICES_V1_BINDINGS"
            for target in statement.targets
        ):
            value = ast.literal_eval(statement.value)
            if not isinstance(value, dict):
                raise AssertionError("production editor bindings are not closed")
            return value
    raise AssertionError("production editor bindings are unavailable")


def _production_membership_validator():
    """Load the pure production choice validator without DB-only extras."""

    prefix = "desire_platform.internal_pilot"
    pilot_root = ROOT / "platform" / "src" / "desire_platform" / "internal_pilot"
    editor_root = pilot_root / "editor"
    desire_platform = importlib.import_module("desire_platform")
    saved_module_table = dict(sys.modules)
    saved_package_attributes = {
        name: dict(vars(module))
        for name, module in saved_module_table.items()
        if name == "desire_platform" or name.startswith("desire_platform.")
    }
    saved_modules = {
        name: module
        for name, module in saved_module_table.items()
        if name == prefix or name.startswith(prefix + ".")
    }
    for name in saved_modules:
        del sys.modules[name]

    pilot = types.ModuleType(prefix)
    pilot.__package__ = prefix
    pilot.__path__ = [str(pilot_root)]
    editor_name = prefix + ".editor"
    editor = types.ModuleType(editor_name)
    editor.__package__ = editor_name
    editor.__path__ = [str(editor_root)]
    sys.modules[prefix] = pilot
    sys.modules[editor_name] = editor
    setattr(desire_platform, "internal_pilot", pilot)
    setattr(pilot, "editor", editor)
    try:
        module = importlib.import_module(editor_name + ".content_choices")
        return module.validate_editor_choice_membership
    finally:
        for name in tuple(sys.modules):
            if name not in saved_module_table:
                del sys.modules[name]
        sys.modules.update(saved_module_table)
        for name, attributes in saved_package_attributes.items():
            namespace = vars(saved_module_table[name])
            for attribute in tuple(namespace):
                if attribute not in attributes:
                    del namespace[attribute]
            namespace.update(attributes)


class _StatefulDutyAdminClient:
    USER_ID = "22222222-2222-4222-8222-222222222222"

    def __init__(
        self,
        module,
        *,
        grant_failure=None,
        revoke_failure=None,
        grant_commit_after_clean_gets=None,
    ):
        allowed = {
            None,
            "FIRST_UNKNOWN_COMMITTED",
            "FIRST_UNKNOWN_UNCOMMITTED",
            "PERSISTENT_UNKNOWN",
            "REPLAY_FAILURE",
            "UNKNOWN_UNTIL_LATE_COMMIT",
        }
        if grant_failure not in allowed or revoke_failure not in allowed:
            raise ValueError("invalid test failure mode")
        self.module = module
        self.grant_failure = grant_failure
        self.revoke_failure = revoke_failure
        self.grant_commit_after_clean_gets = grant_commit_after_clean_gets
        self.roles = ("FINANCE_OPERATOR",)
        self.version = 1
        self.action_counts = {"grant": 0, "revoke": 0}
        self.receipts = {}
        self.requests = []
        self.events = []
        self.detail_count = 0
        self.late_grant_receipt_key = None

    def account_document(self):
        return {
            "account_code": "finance_operator_01",
            "user_id": self.USER_ID,
            "display_handle": "Finance Operator 01",
            "status": "ACTIVE",
            "aggregate_version": self.version,
            "entity_tag": f'"v{self.version}"',
            "role_codes": list(self.roles),
            "active_session_count": 1,
            "created_at": "2026-08-24T08:00:00+00:00",
            "updated_at": "2026-08-24T08:00:00+00:00",
            "is_self": False,
        }

    def request(self, *, method, path, headers, body=None):
        self.requests.append(
            {
                "method": method,
                "path": path,
                "headers": dict(headers),
                "body": body,
            }
        )
        if method == "GET" and path == f"/v1/app/admin/accounts/{self.USER_ID}":
            self.detail_count += 1
            document = self.account_document()
            self.events.append(
                f"GET:v{self.version}:{'+'.join(self.roles)}"
            )
            if (
                self.late_grant_receipt_key is not None
                and self.grant_commit_after_clean_gets is not None
                and self.detail_count >= self.grant_commit_after_clean_gets
            ):
                self.roles = ("FINANCE_OPERATOR", "TRUST_OFFICER")
                self.version += 1
                self.receipts[self.late_grant_receipt_key] = self.version
                self.late_grant_receipt_key = None
                self.events.append("LATE:grant:COMMIT")
            return self.module.HttpResult(
                200,
                {},
                json.dumps({"data": document}).encode("utf-8"),
            )
        if method != "POST" or not path.endswith(("/grant", "/revoke")):
            raise AssertionError("unexpected request")
        action = path.rsplit("/", 1)[-1]
        self.action_counts[action] += 1
        ordinal = self.action_counts[action]
        idempotency_key = headers["Idempotency-Key"]
        receipt_key = (action, idempotency_key)
        failure = (
            self.grant_failure if action == "grant" else self.revoke_failure
        )
        if receipt_key in self.receipts:
            if failure == "REPLAY_FAILURE" and ordinal == 2:
                self.events.append(f"POST:{action}:{ordinal}:REPLAY_FAILURE")
                raise TimeoutError("simulated unknown replay outcome")
            self.events.append(f"POST:{action}:{ordinal}:REPLAY")
            return self._receipt(
                version=self.receipts[receipt_key],
                replayed=True,
            )
        if failure == "FIRST_UNKNOWN_UNCOMMITTED" and ordinal == 1:
            self.events.append(f"POST:{action}:{ordinal}:UNKNOWN_UNCOMMITTED")
            raise TimeoutError("simulated unknown first outcome")
        if (
            action == "grant"
            and failure == "UNKNOWN_UNTIL_LATE_COMMIT"
        ):
            if self.late_grant_receipt_key is None:
                self.late_grant_receipt_key = receipt_key
            if self.late_grant_receipt_key != receipt_key:
                raise AssertionError("grant convergence changed idempotency key")
            self.events.append(f"POST:{action}:{ordinal}:UNKNOWN_PENDING")
            raise TimeoutError("simulated pending first outcome")
        if action == "grant" and failure == "PERSISTENT_UNKNOWN":
            self.events.append(f"POST:{action}:{ordinal}:UNKNOWN_PERSISTENT")
            raise TimeoutError("simulated persistent unknown outcome")

        if action == "grant":
            self.roles = ("FINANCE_OPERATOR", "TRUST_OFFICER")
        else:
            self.roles = ("FINANCE_OPERATOR",)
        self.version += 1
        self.receipts[receipt_key] = self.version
        if failure == "FIRST_UNKNOWN_COMMITTED" and ordinal == 1:
            self.events.append(f"POST:{action}:{ordinal}:UNKNOWN_COMMITTED")
            raise TimeoutError("simulated committed unknown outcome")
        self.events.append(f"POST:{action}:{ordinal}:COMMIT")
        return self._receipt(version=self.version, replayed=False)

    def _receipt(self, *, version, replayed):
        entity_tag = f'"v{version}"'
        return self.module.HttpResult(
            200,
            {"etag": entity_tag},
            json.dumps(
                {
                    "data": {
                        "user_id": self.USER_ID,
                        "display_handle": "Finance Operator 01",
                        "status": "ACTIVE",
                        "aggregate_version": version,
                        "entity_tag": entity_tag,
                        "revoked_session_count": 0,
                        "revoked_session_family_count": 0,
                        "replayed": replayed,
                    }
                }
            ).encode("utf-8"),
        )


class TenAccountTrustE2eRunnerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _configuration_session(self, data, *, account_code="creator_01"):
        response = self.module.HttpResult(
            200,
            {},
            json.dumps({"data": data}, ensure_ascii=False).encode("utf-8"),
        )
        client = mock.Mock()
        client.request.return_value = response
        kind, roles = self.module.ROLE_EXPECTATIONS[account_code]
        prefix = {
            "PERSONAL": "personal:",
            "ORGANIZATION": "org:",
            "PLATFORM": "platform:",
        }[kind]
        return self.module.RoleSession(
            account_code=account_code,
            workspace_id=(
                prefix + "11111111-1111-4111-8111-111111111111"
            ),
            workspace_kind=kind,
            role_codes=roles,
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )

    def test_editor_choice_binding_is_the_current_production_contract(self) -> None:
        runner = {
            (binding[0], binding[1]): binding[2:]
            for binding in self.module._EDITOR_CHOICE_BINDINGS
        }
        production = _production_editor_choice_bindings()

        self.assertEqual(len(runner), 23)
        self.assertEqual(runner, production)
        self.assertEqual(
            tuple(runner),
            tuple(
                sorted(
                    runner,
                    key=lambda identity: (
                        identity[0].encode("utf-8"),
                        identity[1].encode("utf-8"),
                    ),
                )
            ),
        )

    def test_configuration_is_closed_v2_with_complete_ordered_choices(self) -> None:
        valid = _valid_configuration_data(self.module)
        self.assertEqual(
            self.module._configuration(self._configuration_session(valid)),
            valid,
        )

        invalid_cases = {}

        legacy = _json_copy(valid)
        legacy["schema_version"] = "editor-configuration-v1"
        invalid_cases["v1"] = legacy

        bad_locale = _json_copy(valid)
        bad_locale["editor_choices"]["locale"] = "en-US"
        invalid_cases["bad_locale"] = bad_locale

        missing = _json_copy(valid)
        missing["editor_choices"]["fields"].pop()
        invalid_cases["field_missing"] = missing

        extra = _json_copy(valid)
        extra["editor_choices"]["fields"].append(
            _json_copy(extra["editor_choices"]["fields"][-1])
        )
        invalid_cases["field_extra"] = extra

        duplicate = _json_copy(valid)
        duplicate["editor_choices"]["fields"][1] = _json_copy(
            duplicate["editor_choices"]["fields"][0]
        )
        invalid_cases["field_duplicate"] = duplicate

        unordered = _json_copy(valid)
        unordered["editor_choices"]["fields"][0:2] = reversed(
            unordered["editor_choices"]["fields"][0:2]
        )
        invalid_cases["field_unordered"] = unordered

        unavailable_only = _json_copy(valid)
        for field in unavailable_only["editor_choices"]["fields"]:
            field["status"] = "UNAVAILABLE"
            field["reason_code"] = "NO_REVIEWED_CHOICE_SET"
            field["options"] = []
        invalid_cases["unavailable_only"] = unavailable_only

        bad_binding = _json_copy(valid)
        bad_binding["editor_choices"]["fields"][1][
            "path_template"
        ] = "/boundaries/unknown/*/code"
        invalid_cases["bad_binding"] = bad_binding

        unknown_option_field = _json_copy(valid)
        unknown_option_field["editor_choices"]["fields"][1]["options"][0][
            "authority"
        ] = "OPEN"
        invalid_cases["unknown_option_field"] = unknown_option_field

        bad_option_source = _json_copy(valid)
        bad_option_source["editor_choices"]["fields"][1]["options"][0][
            "source"
        ] = "INTERNAL_SANDBOX_PRESET"
        invalid_cases["bad_option_source"] = bad_option_source

        bad_option_value = _json_copy(valid)
        bad_option_value["editor_choices"]["fields"][1]["options"][0][
            "value"
        ] = "domain.software"
        invalid_cases["bad_option_value"] = bad_option_value

        non_normalized_label = _json_copy(valid)
        non_normalized_label["editor_choices"]["fields"][1]["options"][0][
            "label"
        ] = "e\u0301"
        invalid_cases["non_normalized_label"] = non_normalized_label

        control_label = _json_copy(valid)
        control_label["editor_choices"]["fields"][1]["options"][0][
            "label"
        ] = "software\nlabel"
        invalid_cases["control_label"] = control_label

        available_empty = _json_copy(valid)
        available_empty["editor_choices"]["fields"][1]["options"] = []
        invalid_cases["available_empty"] = available_empty

        inconsistent_domain_options = _json_copy(valid)
        inconsistent_domain_options["editor_choices"]["fields"][5]["options"] = [
            {
                "value": "DOMAIN.ZETA",
                "label": "Zeta",
                "source": "TAXONOMY_BUNDLE_NODE",
            }
        ]
        invalid_cases["inconsistent_domain_options"] = (
            inconsistent_domain_options
        )

        duplicate_option = _json_copy(valid)
        duplicate_option["editor_choices"]["fields"][1]["options"].append(
            _json_copy(
                duplicate_option["editor_choices"]["fields"][1]["options"][0]
            )
        )
        invalid_cases["duplicate_option"] = duplicate_option

        unordered_options = _json_copy(valid)
        reversed_domain = [
            {
                "value": "DOMAIN.ZETA",
                "label": "Zeta",
                "source": "TAXONOMY_BUNDLE_NODE",
            },
            {
                "value": "DOMAIN.ALPHA",
                "label": "Alpha",
                "source": "TAXONOMY_BUNDLE_NODE",
            },
        ]
        for field in unordered_options["editor_choices"]["fields"]:
            if field["intended_node_kind"] == "DOMAIN":
                field["options"] = _json_copy(reversed_domain)
        invalid_cases["unordered_options"] = unordered_options

        bad_fixed_option = _json_copy(valid)
        bad_fixed_option["editor_choices"]["fields"][3]["options"][0][
            "value"
        ] = "en-US"
        invalid_cases["bad_fixed_option"] = bad_fixed_option

        bad_taxonomy_window = _json_copy(valid)
        bad_taxonomy_window["taxonomy_bundle"]["effective_until"] = (
            bad_taxonomy_window["taxonomy_bundle"]["effective_at"]
        )
        invalid_cases["bad_taxonomy_window"] = bad_taxonomy_window

        future_taxonomy = _json_copy(valid)
        future_taxonomy["taxonomy_bundle"]["effective_at"] = (
            self.module.datetime.now(self.module.timezone.utc)
            + self.module.timedelta(days=1)
        ).replace(microsecond=0).isoformat()
        future_taxonomy["taxonomy_bundle"]["effective_until"] = None
        invalid_cases["future_taxonomy"] = future_taxonomy

        expired_taxonomy = _json_copy(valid)
        expired_taxonomy["taxonomy_bundle"]["effective_at"] = (
            self.module.datetime.now(self.module.timezone.utc)
            - self.module.timedelta(days=2)
        ).replace(microsecond=0).isoformat()
        expired_taxonomy["taxonomy_bundle"]["effective_until"] = (
            self.module.datetime.now(self.module.timezone.utc)
            - self.module.timedelta(days=1)
        ).replace(microsecond=0).isoformat()
        invalid_cases["expired_taxonomy"] = expired_taxonomy

        open_taxonomy = _json_copy(valid)
        open_taxonomy["taxonomy_bundle"]["family_code"] = "OPEN"
        invalid_cases["open_taxonomy"] = open_taxonomy

        for name, configuration in invalid_cases.items():
            with self.subTest(name=name):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._configuration(
                        self._configuration_session(configuration)
                    )

    def test_creator_and_demand_owner_require_exact_same_configuration(self) -> None:
        creator = self._configuration_session(
            _valid_configuration_data(self.module),
            account_code="creator_01",
        )
        owner = self._configuration_session(
            _valid_configuration_data(self.module),
            account_code="demand_owner_01",
        )
        shared = _valid_configuration_data(self.module)
        with mock.patch.object(
            self.module,
            "_configuration",
            side_effect=(_json_copy(shared), _json_copy(shared)),
        ):
            self.assertEqual(
                self.module._shared_editor_configuration(creator, owner),
                shared,
            )

        taxonomy_mismatch = _json_copy(shared)
        taxonomy_mismatch["taxonomy_bundle"]["bundle_id"] = (
            "60000000-0000-4000-8000-000000000001"
        )
        choice_mismatch = _json_copy(shared)
        choice_mismatch["editor_choices"]["fields"][1]["options"][0][
            "label"
        ] = "不同标签"
        for name, mismatch in (
            ("taxonomy", taxonomy_mismatch),
            ("choice_catalog", choice_mismatch),
        ):
            with self.subTest(name=name):
                with mock.patch.object(
                    self.module,
                    "_configuration",
                    side_effect=(_json_copy(shared), mismatch),
                ):
                    with self.assertRaises(
                        self.module.InternalSandboxE2eError
                    ):
                        self.module._shared_editor_configuration(creator, owner)

    def _duty_recovery_context(self, client):
        admin = self.module.RoleSession(
            account_code="access_admin_01",
            workspace_id="platform:11111111-1111-4111-8111-111111111111",
            workspace_kind="PLATFORM",
            role_codes=("ACCESS_ADMIN",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        target = self.module.RoleSession(
            account_code="finance_operator_01",
            workspace_id=(
                "platform:22222222-2222-4222-8222-222222222222"
            ),
            workspace_kind="PLATFORM",
            role_codes=("FINANCE_OPERATOR",),
            csrf_token="y" * 32,
            client=object(),
            policy_accepted=False,
        )
        target_account = client.account_document()
        accounts = [
            (
                target_account
                if code == target.account_code
                else {"account_code": code}
            )
            for code in self.module.ROLE_EXPECTATIONS
        ]
        return admin, target, accounts

    @staticmethod
    def _secured_finance_detail():
        return {
            "funding_review_id": "33333333-3333-4333-8333-333333333333",
            "status": "SECURED",
            "assignment_status": "COMPLETED",
            "confirmation_by_me": True,
            "available_actions": [],
            "can_confirm": False,
        }

    def test_runner_is_fixed_to_loopback_synthetic_https_and_closed_roles(self) -> None:
        self.assertEqual(
            self.module.PILOT_ORIGIN,
            "https://pilot.example.test",
        )
        self.assertEqual(
            self.module.IDENTITY_ORIGIN,
            "https://identity.example.test",
        )
        self.assertEqual(self.module.RESOLVE_ADDRESS, "127.0.0.1")
        self.assertEqual(
            self.module.ROLE_EXPECTATIONS,
            {
                "access_admin_01": ("PLATFORM", ("ACCESS_ADMIN",)),
                "appeal_reviewer_01": ("PLATFORM", ("APPEAL_REVIEWER",)),
                "creator_01": ("PERSONAL", ("CREATOR",)),
                "demand_owner_01": (
                    "ORGANIZATION",
                    ("DEMAND_OWNER",),
                ),
                "operations_reviewer_01": (
                    "PLATFORM",
                    ("OPERATIONS_REVIEWER",),
                ),
                "finance_operator_01": (
                    "PLATFORM",
                    ("FINANCE_OPERATOR",),
                ),
                "finance_operator_02": (
                    "PLATFORM",
                    ("FINANCE_OPERATOR",),
                ),
                "org_admin_01": (
                    "ORGANIZATION",
                    ("ORG_ADMIN",),
                ),
                "trust_officer_01": ("PLATFORM", ("TRUST_OFFICER",)),
                "trust_officer_02": ("PLATFORM", ("TRUST_OFFICER",)),
            },
        )
        source = inspect.getsource(self.module)
        self.assertEqual(
            self.module.JOURNEY_GREEN_STATUS,
            "TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN",
        )
        self.assertEqual(
            self.module.RESTART_GREEN_STATUS,
            "TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN",
        )
        self.assertEqual(
            self.module.STATE_SCHEMA,
            "internal-sandbox-ten-account-trust-appeal-e2e-v8",
        )
        self.assertTrue(
            {
                "TRUST_REPORT",
                "TRUST_CASE_REVIEW",
                "TRUST_HOLD_ENFORCEMENT",
                "TRUST_HOLD_RELEASE",
                "TRUST_OUTCOME",
                "TRUST_APPEAL",
                "ASSIGNMENT_DISCOVERY_BOUNDARY",
                "RESTART_TRUST",
                "RESTART_APPEAL",
            }.issubset(self.module._FAILURE_STAGES)
        )
        for forbidden in (
            "--insecure",
            "--location",
            "--trace",
            "--trace-ascii",
            "--verbose",
            "set -x",
        ):
            self.assertNotIn(forbidden, source)

    def test_provider_only_invitee_is_additive_not_an_eleventh_bootstrap_role(
        self,
    ) -> None:
        code = "invited_demand_owner_02"
        self.assertNotIn(code, self.module.ROLE_EXPECTATIONS)
        self.assertEqual(len(self.module.ROLE_EXPECTATIONS), 10)
        self.assertEqual(
            self.module.OIDC_CHOOSER_ACCOUNT_CODES,
            (*self.module.ROLE_EXPECTATIONS, code),
        )
        self.assertEqual(
            self.module.PROVIDER_ONLY_INVITED_DEMAND_OWNER_EMAIL,
            "sandbox-invited-demand-owner-02@example.test",
        )
        self.assertEqual(
            self.module.INVITED_DEMAND_OWNER_GREEN_STATUS,
            "PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN",
        )
        self.assertTrue(
            {
                "INVITED_DEMAND_OWNER_INVITATION",
                "INVITED_DEMAND_OWNER_PENDING",
                "INVITED_DEMAND_OWNER_PENDING_SESSION",
                "INVITED_DEMAND_OWNER_PENDING_ME",
                "INVITED_DEMAND_OWNER_PENDING_WORKSPACES",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_BODY",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_EXPOSED",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_BAD_REQUEST",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAUTHENTICATED",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_FORBIDDEN",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_WORKSPACE_REQUIRED",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_METHOD_REJECTED",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_INVALID_REQUEST",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_SERVER_ERROR",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_GATEWAY_ERROR",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAVAILABLE",
                "INVITED_DEMAND_OWNER_PENDING_ADMIN_OTHER",
                "INVITED_DEMAND_OWNER_ACCEPTANCE",
                "INVITED_DEMAND_OWNER_ACCEPTANCE_POLICY",
                "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
                "INVITED_DEMAND_OWNER_ACCEPTANCE_SESSION",
                "INVITED_DEMAND_OWNER_AUTHORITY",
                "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
                "INVITED_DEMAND_OWNER_AUTHORITY_REFRESHED_ME",
                "INVITED_DEMAND_OWNER_AUTHORITY_WORKSPACES",
                "INVITED_DEMAND_OWNER_AUTHORITY_ADMIN",
                "INVITED_DEMAND_OWNER_DEMAND",
            }.issubset(self.module._FAILURE_STAGES)
        )
        arguments = self.module._parser().parse_args(
            ["invited-demand-owner", "--ca-file", "/private/tmp/root-ca.pem"]
        )
        self.assertEqual(arguments.command, "invited-demand-owner")
        self.assertFalse(hasattr(arguments, "state_output"))

    def test_provider_only_callback_is_pending_and_authority_empty_before_acceptance(
        self,
    ) -> None:
        organization_id = "11111111-1111-4111-8111-111111111111"
        invitation_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        user_id = "44444444-4444-4444-8444-444444444444"
        token = "t" * 96
        invitation = {
            "invitation_id": invitation_id,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": organization_id,
            "target_role": "DEMAND_OWNER",
            "masked_recipient_label": "s***@example.test",
            "is_initial_admin": False,
            "status": "ISSUED",
            "expires_at": "2026-08-30T08:00:00Z",
            "created_at": "2026-08-25T08:00:00Z",
            "required_policy_bundle_id": bundle_id,
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        preview = {
            "invitation_id": invitation_id,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization": {"public_name": "Synthetic Organization"},
            "target_role": "DEMAND_OWNER",
            "expires_at": "2026-08-30T08:00:00Z",
            "required_policy_bundle_id": bundle_id,
            "status": "ISSUED",
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        pending_me = {
            "user_id": user_id,
            "status": "PENDING_ENROLLMENT",
            "display_handle": "invited_demand_owner_02",
            "user_roles": [],
            "memberships": [],
            "policy_requirements": [],
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }

        class Client:
            instance = None

            def __init__(self, **_kwargs):
                type(self).instance = self
                self.requests = []
                self.authorizations = []

            def request(self, **kwargs):
                self.requests.append(kwargs)
                if kwargs["path"] == "/v1/auth/oidc/authorizations":
                    return self_module.HttpResult(
                        201,
                        {},
                        json.dumps(
                            {
                                "auth_transaction_id": "transaction",
                                "authorization_url": "https://identity.example.test/authorize?closed",
                                "expires_at": "2026-08-25T08:10:00Z",
                            }
                        ).encode(),
                    )
                return self_module.HttpResult(
                    404,
                    {},
                    b'{"error":{"code":"RESOURCE_NOT_FOUND"}}',
                )

            def get_authorization_page(self, _url):
                return (
                    '<input type="hidden" name="request_handle" value="'
                    + "r" * 43
                    + '">'
                ).encode()

            def authorize(self, **kwargs):
                self.authorizations.append(kwargs)

        self_module = self.module
        with mock.patch.multiple(
            self.module,
            CurlClient=Client,
            _inspect_organization_invitation=mock.Mock(return_value=preview),
            _pending_session=mock.Mock(
                return_value={
                    "session": {"safe": True},
                    "user_status": "PENDING_ENROLLMENT",
                    "csrf_token": "x" * 32,
                }
            ),
            _get_json=mock.Mock(return_value=pending_me),
            _workspace_candidates=mock.Mock(return_value=([], False)),
        ):
            pending, observed_preview, observed_user_id = (
                self.module._authenticate_provider_only_invitee(
                    root=Path("/unused/provider-only"),
                    ca_file=Path("/unused/ca.pem"),
                    organization_id=organization_id,
                    issued={
                        "invitation": invitation,
                        "access_invitation_token": token,
                        "join_fragment_url": (
                            "/join#access_invitation_token=" + token
                        ),
                    },
                )
            )
        client = Client.instance
        self.assertIsNotNone(client)
        begin = client.requests[0]
        self.assertEqual(
            begin["body"],
            {"return_to": "/app", "access_invitation_token": token},
        )
        self.assertIs(begin["sensitive_body"], True)
        self.assertEqual(
            client.authorizations,
            [
                {
                    "account_code": "invited_demand_owner_02",
                    "request_handle": "r" * 43,
                }
            ],
        )
        self.assertEqual(pending.role_codes, ())
        self.assertEqual(pending.workspace_id, "")
        self.assertEqual(observed_preview, preview)
        self.assertEqual(observed_user_id, user_id)
        self.assertEqual(client.requests[-1]["path"], "/v1/app/admin/accounts")

    def test_pending_invitee_admin_surface_is_closed_by_exact_workspace_gate(
        self,
    ) -> None:
        response = self.module.HttpResult(
            status=400,
            headers={"content-type": "application/json"},
            body=(
                b'{"code":"WORKSPACE_REQUIRED",'
                b'"message":"workspace selection is required"}'
            ),
        )

        self.module._expect_pending_admin_hidden(response)

        rejected = self.module.HttpResult(
            status=400,
            headers={"content-type": "application/json"},
            body=b'{"code":"INVALID_REQUEST","message":"closed"}',
        )
        with self.assertRaises(self.module.InternalSandboxE2eError) as raised:
            self.module._expect_pending_admin_hidden(rejected)
        self.assertEqual(
            raised.exception.stage,
            "INVITED_DEMAND_OWNER_PENDING_ADMIN_BAD_REQUEST",
        )

    def test_invitation_acceptance_malformed_command_response_keeps_command_stage(
        self,
    ) -> None:
        invitation_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        client = mock.Mock()
        client.request.return_value = self.module.HttpResult(
            status=200,
            headers={"etag": '"v2"'},
            body=b"not-json",
        )
        session = self.module.RoleSession(
            account_code="invited_demand_owner_02",
            workspace_id="",
            workspace_kind="",
            role_codes=(),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        preview = {
            "invitation_id": invitation_id,
            "required_policy_bundle_id": bundle_id,
            "entity_tag": '"v1"',
        }
        with mock.patch.object(
            self.module, "_invitation_preview", return_value=preview
        ), mock.patch.object(
            self.module,
            "_invitation_policy_acceptances",
            return_value=[
                {
                    "document_id": "44444444-4444-4444-8444-444444444444",
                    "content_sha256": "a" * 64,
                    "affirmed": True,
                }
            ],
        ):
            with self.assertRaises(self.module.InternalSandboxE2eError) as raised:
                self.module._accept_organization_invitation(
                    session,
                    preview=preview,
                )
        self.assertEqual(
            raised.exception.stage,
            "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        )

    def test_accepted_provider_identity_has_only_target_org_owner_authority(
        self,
    ) -> None:
        organization_id = "11111111-1111-4111-8111-111111111111"
        invitation_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        user_id = "44444444-4444-4444-8444-444444444444"
        membership_id = "55555555-5555-4555-8555-555555555555"
        organization = {
            "organization_id": organization_id,
            "public_name": "Synthetic Organization",
            "type": "BUSINESS",
            "status": "ACTIVE",
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        me = {
            "user_id": user_id,
            "status": "ACTIVE",
            "display_handle": "invited_demand_owner_02",
            "user_roles": [],
            "memberships": [
                {
                    "membership_id": membership_id,
                    "organization": organization,
                    "status": "ACTIVE",
                    "roles": ["DEMAND_OWNER"],
                    "aggregate_version": 1,
                    "entity_tag": '"v1"',
                }
            ],
            "policy_requirements": [
                {
                    "selector_digest": "a" * 64,
                    "purpose": "ORGANIZATION_MEMBERSHIP",
                    "role": "DEMAND_OWNER",
                    "scope_type": "ORGANIZATION_ROLE",
                    "scope_id": organization_id,
                    "satisfied": True,
                    "required_policy_bundle_id": bundle_id,
                    "missing_document_ids": [],
                }
            ],
            "aggregate_version": 2,
            "entity_tag": '"v2"',
        }
        accepted_invitation = {
            "invitation_id": invitation_id,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": organization_id,
            "target_role": "DEMAND_OWNER",
            "masked_recipient_label": "s***@example.test",
            "is_initial_admin": False,
            "status": "ACCEPTED",
            "expires_at": "2026-08-30T08:00:00Z",
            "created_at": "2026-08-25T08:00:00Z",
            "required_policy_bundle_id": bundle_id,
            "aggregate_version": 2,
            "entity_tag": '"v2"',
        }

        class Client:
            def request(self, **_kwargs):
                return self_module.HttpResult(
                    404,
                    {},
                    b'{"error":{"code":"RESOURCE_NOT_FOUND"}}',
                )

        self_module = self.module
        session = self.module.RoleSession(
            account_code="invited_demand_owner_02",
            workspace_id="",
            workspace_kind="",
            role_codes=(),
            csrf_token="x" * 32,
            client=Client(),
            policy_accepted=False,
        )
        incomplete_me = dict(me)
        incomplete_me["policy_requirements"] = []
        refreshed = mock.Mock(return_value=me)
        with mock.patch.multiple(
            self.module,
            _get_json=refreshed,
            _workspace_candidates=mock.Mock(
                return_value=(
                    [
                        {
                            "workspace_id": f"org:{organization_id}",
                            "workspace_kind": "ORGANIZATION",
                            "role_codes": ["DEMAND_OWNER"],
                        }
                    ],
                    False,
                )
            ),
        ):
            with self.assertRaises(
                self.module.InternalSandboxE2eError
            ) as raised:
                self.module._activate_invited_demand_owner(
                    session,
                    acceptance={
                        "invitation": accepted_invitation,
                        "me": incomplete_me,
                        "activated_scope": "ORGANIZATION_MEMBERSHIP",
                    },
                    organization_id=organization_id,
                    expected_user_id=user_id,
                )
        self.assertEqual(
            raised.exception.stage,
            "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
        )
        refreshed.assert_not_called()
        with mock.patch.multiple(
            self.module,
            _get_json=mock.Mock(return_value=me),
            _workspace_candidates=mock.Mock(
                return_value=(
                    [
                        {
                            "workspace_id": f"org:{organization_id}",
                            "workspace_kind": "ORGANIZATION",
                            "role_codes": ["DEMAND_OWNER"],
                        }
                    ],
                    False,
                )
            ),
        ):
            owner = self.module._activate_invited_demand_owner(
                session,
                acceptance={
                    "invitation": accepted_invitation,
                    "me": me,
                    "activated_scope": "ORGANIZATION_MEMBERSHIP",
                },
                organization_id=organization_id,
                expected_user_id=user_id,
            )
        self.assertEqual(owner.workspace_id, f"org:{organization_id}")
        self.assertEqual(owner.workspace_kind, "ORGANIZATION")
        self.assertEqual(owner.role_codes, ("DEMAND_OWNER",))
        self.assertTrue(owner.policy_accepted)

    def test_invited_owner_cancel_replays_exactly_and_is_completed_history(
        self,
    ) -> None:
        demand_id = "11111111-1111-4111-8111-111111111111"
        version_id = "22222222-2222-4222-8222-222222222222"
        cancelled = {
            "resource_type": "DEMAND",
            "object_id": demand_id,
            "status": "CANCELLED",
            "revision": 3,
            "etag": '"demand-3-aaaaaaaaaaaaaaaaaaaaaaaa"',
            "capabilities": [],
            "editable_paths": [],
            "current_version": {"version_id": version_id},
            "versions": [{"version_id": version_id}],
            "submissions": [],
            "findings": [],
            "review_assignment": None,
        }
        task = {
            "classification": "COMPLETED",
            "resource_kind": "DEMAND",
            "resource_id": demand_id,
            "source_status": "CANCELLED",
            "next_action": "VIEW_DEMAND_HISTORY",
            "resource_path": f"/v1/app/demands/{demand_id}",
            "updated_at": "2026-08-25T08:00:00Z",
            "due_at": None,
        }

        class Client:
            def __init__(self):
                self.requests = []

            def request(self, **kwargs):
                self.requests.append(kwargs)
                if kwargs["path"] == "/v1/app/tasks":
                    body = {
                        "data": {
                            "schema_version": "current-account-task-discovery-v1",
                            "items": [task],
                            "has_more": False,
                        }
                    }
                    return self_module.HttpResult(
                        200, {}, json.dumps(body).encode()
                    )
                return self_module.HttpResult(
                    200,
                    {"etag": cancelled["etag"]},
                    json.dumps({"data": cancelled}).encode(),
                )

        self_module = self.module
        client = Client()
        owner = self.module.RoleSession(
            account_code="invited_demand_owner_02",
            workspace_id="org:33333333-3333-4333-8333-333333333333",
            workspace_kind="ORGANIZATION",
            role_codes=("DEMAND_OWNER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=True,
        )
        drafted = {
            **cancelled,
            "status": "DRAFT",
            "revision": 2,
            "etag": '"demand-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "capabilities": ["SAVE_DRAFT", "SUBMIT", "CANCEL"],
            "editable_paths": ["/problem"],
        }
        observed = self.module._cancel_demand_exact_replay(
            owner, demand=drafted
        )
        self.assertEqual(observed, cancelled)
        writes = client.requests[:2]
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0]["path"], f"/v1/app/demands/{demand_id}/cancel")
        self.assertEqual(writes[0]["body"], {"reason_code": "OWNER_WITHDREW"})
        self.assertIs(writes[0]["headers"], writes[1]["headers"])
        self.assertIn("Idempotency-Key", writes[0]["headers"])
        self.module._require_cancelled_demand_history_task(
            owner, demand_id=demand_id
        )

    def test_provider_only_journey_summary_contains_no_identity_or_capability_secret(
        self,
    ) -> None:
        organization_id = "11111111-1111-4111-8111-111111111111"
        admin = self.module.RoleSession(
            account_code="org_admin_01",
            workspace_id=f"org:{organization_id}",
            workspace_kind="ORGANIZATION",
            role_codes=("ORG_ADMIN",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        pending = self.module.RoleSession(
            account_code="invited_demand_owner_02",
            workspace_id="",
            workspace_kind="",
            role_codes=(),
            csrf_token="y" * 32,
            client=object(),
            policy_accepted=False,
        )
        owner = self.module.RoleSession(
            account_code="invited_demand_owner_02",
            workspace_id=f"org:{organization_id}",
            workspace_kind="ORGANIZATION",
            role_codes=("DEMAND_OWNER",),
            csrf_token="z" * 32,
            client=object(),
            policy_accepted=True,
        )
        with tempfile.TemporaryDirectory(prefix="invited-e2e-summary-") as directory:
            ca_file = Path(directory).resolve() / "root-ca.pem"
            ca_file.write_text(
                "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
                encoding="ascii",
            )
            with mock.patch.multiple(
                self.module,
                _login=mock.Mock(return_value=admin),
                _organization_summary=mock.Mock(return_value={"safe": True}),
                _issue_organization_invitation_exact_replay=mock.Mock(
                    return_value={"private": "not serialized"}
                ),
                _authenticate_provider_only_invitee=mock.Mock(
                    return_value=(pending, {"private": "not serialized"}, organization_id)
                ),
                _accept_organization_invitation=mock.Mock(
                    return_value=(pending, {"private": "not serialized"})
                ),
                _activate_invited_demand_owner=mock.Mock(return_value=owner),
                _create_cancelled_demand_with_history=mock.Mock(
                    return_value={
                        "created_and_cancelled": True,
                        "exact_replay_verified": True,
                        "read_only": True,
                        "version_history_preserved": True,
                        "completed_history_discovered": True,
                    }
                ),
            ):
                summary = self.module.run_invited_demand_owner_journey(
                    ca_file=ca_file
                )
        self.assertEqual(
            summary["status"], "PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN"
        )
        serialized = json.dumps(summary, sort_keys=True).lower()
        for forbidden in (
            "invited_demand_owner_02",
            "sandbox-invited-demand-owner-02@example.test",
            "access_invitation_token",
            "csrf",
            "authorization_url",
            "request_handle",
            "idempotency",
            organization_id,
        ):
            self.assertNotIn(forbidden, serialized)

    def test_utc_timestamp_normalizes_postgres_fractional_precision_for_python39(
        self,
    ) -> None:
        real_datetime = self.module.datetime

        class Python39Datetime:
            seen: list[str] = []

            @classmethod
            def fromisoformat(cls, value: str):
                cls.seen.append(value)
                fraction = re.search(r"\.(\d+)(?=\+00:00$)", value)
                if fraction is not None and len(fraction.group(1)) not in {3, 6}:
                    raise ValueError("Python 3.9 fractional precision")
                return real_datetime.fromisoformat(value)

        accepted = tuple(
            "2026-08-19T08:00:00"
            + ("" if precision == 0 else "." + "1" * precision)
            + suffix
            for precision in range(10)
            for suffix in ("Z", "+00:00")
        )
        with mock.patch.object(self.module, "datetime", Python39Datetime):
            for value in accepted:
                with self.subTest(value=value):
                    self.assertEqual(self.module._utc_timestamp(value), value)

        self.assertEqual(
            Python39Datetime.seen,
            ["2026-08-19T08:00:00+00:00"] * len(accepted),
        )
        self.assertEqual(
            self.module._parse_utc_timestamp(
                "2026-08-19T08:00:00.123456789Z"
            )[1],
            123_456_789,
        )
        for value in (
            "2026-08-19 08:00:00Z",
            "2026-08-19T08:00:00.1234567890Z",
            "2026-08-19T08:00:00+08:00",
            "2026-08-19T08:00:00-00:00",
            "2026-08-19T08:00:00+0000",
            "2026-08-19T08:00:00z",
            "2026-08-19T08:00:00Z\n",
        ):
            with self.subTest(rejected=value):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._utc_timestamp(value)
        self.assertEqual(
            inspect.getsource(self.module).count("datetime.fromisoformat("),
            1,
        )

    def test_submicrosecond_timestamp_ordering_is_exact_and_fail_closed(
        self,
    ) -> None:
        earlier_plus = "2026-08-19T08:00:00.123456788+00:00"
        pivot_plus = "2026-08-19T08:00:00.123456789+00:00"
        later_plus = "2026-08-19T08:00:00.123456790+00:00"
        earlier_z = "2026-08-19T08:00:00.123456788Z"
        pivot_z = "2026-08-19T08:00:00.123456789Z"
        later_z = "2026-08-19T08:00:00.123456790Z"

        self.assertLess(
            self.module._parse_utc_timestamp(earlier_plus),
            self.module._parse_utc_timestamp(pivot_plus),
        )
        self.assertLess(
            self.module._parse_utc_timestamp(pivot_plus),
            self.module._parse_utc_timestamp(later_plus),
        )

        report = {
            "category": "WORKFLOW_INTEGRITY",
            "evidence_reference_ids": [
                "11111111-1111-4111-8111-111111111111"
            ],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": later_plus,
            "incident_started_at": pivot_plus,
            "requested_protection_codes": ["PAUSE_VERIFICATION"],
        }
        self.assertEqual(self.module._trust_report_summary(report), report)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_report_summary(
                {**report, "incident_ended_at": earlier_plus}
            )

        hold = {
            "action_codes": ["VERIFY_DEMAND"],
            "effective_at": pivot_plus,
            "entity_tag": '"trust-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
            "expires_at": later_plus,
            "hold_id": "22222222-2222-4222-8222-222222222222",
            "status": "ACTIVE",
        }
        self.assertEqual(self.module._trust_hold_projection(hold), hold)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_hold_projection(
                {**hold, "expires_at": earlier_plus}
            )

        source = {
            "action_codes": ["VERIFY_DEMAND"],
            "appeal_deadline": later_z,
            "appeal_eligibility_code": "ELIGIBLE",
            "appeal_eligible": True,
            "case_id": "33333333-3333-4333-8333-333333333333",
            "content_sha256": "a" * 64,
            "decided_at": pivot_z,
            "demand_id": "44444444-4444-4444-8444-444444444444",
            "demand_version_id": "55555555-5555-4555-8555-555555555555",
            "evidence_packet_sha256": "b" * 64,
            "evidence_packet_version_id": (
                "66666666-6666-4666-8666-666666666666"
            ),
            "outcome_code": "PROTECTION_MODIFIED",
            "outcome_version_id": "77777777-7777-4777-8777-777777777777",
            "policy_version": "trust-case-outcome-v1",
            "reason_codes": ["RISK_MITIGATED"],
        }
        self.assertEqual(self.module._appeal_source(source), source)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_source(
                {
                    **source,
                    "appeal_deadline": earlier_z,
                    "decided_at": pivot_z,
                }
            )

    def test_every_response_timestamp_uses_the_unified_utc_gate(self) -> None:
        invalid = "2026-08-19T08:00:00+08:00"
        valid = "2026-08-19T08:00:00+00:00"

        class AuthorizationClient:
            def __init__(self, **_kwargs):
                pass

            def request(self, **_kwargs):
                return self_module.HttpResult(
                    201,
                    {},
                    json.dumps(
                        {
                            "auth_transaction_id": "transaction",
                            "authorization_url": "https://identity.example.test",
                            "expires_at": invalid,
                        }
                    ).encode("utf-8"),
                )

            def get_authorization_page(self, _url):
                raise AssertionError("invalid expiry must stop authorization")

        self_module = self.module
        with mock.patch.object(self.module, "CurlClient", AuthorizationClient):
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._login(
                    account_code="creator_01",
                    root=Path("/unused/login"),
                    ca_file=Path("/unused/ca.pem"),
                )

        authorization_client = AuthorizationClient()
        invitation_session = self.module.RoleSession(
            account_code="creator_01",
            workspace_id="personal:11111111-1111-4111-8111-111111111111",
            workspace_kind="PERSONAL",
            role_codes=("CREATOR",),
            csrf_token="x" * 32,
            client=authorization_client,
            policy_accepted=False,
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._invitation_step_up(
                invitation_session,
                token="t" * 96,
                invitation_id="22222222-2222-4222-8222-222222222222",
            )

        bundle_id = "33333333-3333-4333-8333-333333333333"

        class OneResponseClient:
            def __init__(self, response):
                self.response = response

            def request(self, **_kwargs):
                return self.response

        def session_for(response):
            return self.module.RoleSession(
                account_code="operations_reviewer_01",
                workspace_id=(
                    "platform:44444444-4444-4444-8444-444444444444"
                ),
                workspace_kind="PLATFORM",
                role_codes=("OPERATIONS_REVIEWER",),
                csrf_token="x" * 32,
                client=OneResponseClient(response),
                policy_accepted=False,
            )

        taxonomy = {
            "bundle_id": bundle_id,
            "status": "CURRENT_APPROVED",
            "effective_at": valid,
            "effective_until": None,
        }
        configuration = _valid_configuration_data(self.module)
        for field in ("effective_at", "effective_until"):
            with self.subTest(timestamp_field=f"taxonomy.{field}"):
                response = self.module.HttpResult(
                    200,
                    {},
                    json.dumps(
                        {
                            "data": {
                                **configuration,
                                "taxonomy_bundle": {
                                    **taxonomy,
                                    field: invalid,
                                },
                            }
                        }
                    ).encode("utf-8"),
                )
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._configuration(session_for(response))

        demand_id = "55555555-5555-4555-8555-555555555555"
        queue_item = {
            "demand_id": demand_id,
            "demand_revision": 1,
            "demand_version_no": 1,
            "submitted_at": valid,
            "demand_expires_at": valid,
            "etag": '"demand-1-review-queue"',
        }
        for field in ("submitted_at", "demand_expires_at"):
            with self.subTest(timestamp_field=f"review_queue.{field}"):
                response = self.module.HttpResult(
                    200,
                    {},
                    json.dumps({"data": [{**queue_item, field: invalid}]}).encode(
                        "utf-8"
                    ),
                )
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._review_queue(session_for(response))

        claim = {
            "assignment_id": "66666666-6666-4666-8666-666666666666",
            "demand_id": demand_id,
            "demand_revision": 1,
            "status": "ACTIVE",
            "expires_at": invalid,
            "etag": queue_item["etag"],
            "replayed": False,
        }
        claim_response = self.module.HttpResult(
            200,
            {"etag": queue_item["etag"]},
            json.dumps({"data": claim}).encode("utf-8"),
        )
        with mock.patch.object(
            self.module, "_review_queue", return_value=[queue_item]
        ):
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._claim(session_for(claim_response), demand_id=demand_id)

        account = {
            "account_code": "creator_01",
            "user_id": "77777777-7777-4777-8777-777777777777",
            "display_handle": "Creator 01",
            "status": "ACTIVE",
            "aggregate_version": 1,
            "entity_tag": '"v1"',
            "role_codes": ["CREATOR"],
            "active_session_count": 1,
            "created_at": valid,
            "updated_at": valid,
            "is_self": False,
        }
        account_list_response = self.module.HttpResult(
            200,
            {},
            json.dumps(
                {
                    "data": {
                        "schema_version": "internal-sandbox-account-admin-v1",
                        "evaluated_at": invalid,
                        "accounts": [account],
                    }
                }
            ).encode("utf-8"),
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._account_list(session_for(account_list_response))
        for field in ("created_at", "updated_at"):
            with self.subTest(timestamp_field=f"account.{field}"):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._account({**account, field: invalid})

        finding = {
            "finding_id": "88888888-8888-4888-8888-888888888888",
            "version_id": "99999999-9999-4999-8999-999999999999",
            "assignment_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "result": "VERIFIED",
            "reason_codes": [],
            "required_field_paths": [],
            "reviewed_at": invalid,
        }
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_verified_finding(
                {"findings": [finding]},
                demand_version_id=finding["version_id"],
            )

    def test_trust_journey_uses_canonical_routes_and_closed_events(self) -> None:
        source = inspect.getsource(self.module)
        for route_fragment in (
            'path="/v1/app/trust/reports"',
            'path="/v1/app/trust/queue"',
            'path="/v1/app/trust/assignments"',
            "/v1/app/trust/queue/{case_id}/claim",
            "/v1/app/trust/cases/{case_id}",
            "/v1/app/trust/cases/{case_id}/triage-draft",
            "/v1/app/trust/cases/{case_id}/triage-publish",
            "/v1/app/trust/cases/{case_id}/holds",
            'path="/v1/app/trust/hold-release-queue"',
            "/v1/app/trust/hold-release-queue/{hold_id}/claim",
            "/v1/app/trust/assigned-holds/{hold_id}",
            "/v1/app/trust/holds/{hold_id}/release",
            "/v1/app/trust/cases/{case_id}/decisions",
        ):
            with self.subTest(route=route_fragment):
                self.assertIn(route_fragment, source)
        for event_type in (
            "TrustReportSubmitted",
            "TrustCaseClaimed",
            "TrustTriageDraftSaved",
            "TrustTriagePublished",
            "SafetyHoldPlaced",
            "TrustHoldReleaseClaimed",
            "SafetyHoldReleased",
            "TrustCaseOutcomePublished",
        ):
            with self.subTest(event_type=event_type):
                self.assertIn(event_type, source)
        self.assertIn('body={"expected_draft_version": draft_version}', source)
        self.assertIn('released["hold_version"] != 3', source)

    def test_appeal_journey_uses_canonical_routes_events_and_sensitive_bodies(self) -> None:
        source = inspect.getsource(self.module)
        for route_fragment in (
            'path="/v1/app/appeals"',
            "/v1/app/appeals/{appeal_id}",
            "/v1/app/appeals/{appeal_id}/draft",
            "/v1/app/appeals/{appeal_id}/submit",
            'path="/v1/app/appeal-review/queue"',
            'path="/v1/app/appeal-review/assignments"',
            "/v1/app/appeal-review/queue/{appeal_id}/claim",
            "/v1/app/appeal-review/appeals/{appeal_id}",
            "/v1/app/appeal-review/appeals/{appeal_id}/assignment/release",
            "/v1/app/appeal-review/appeals/{appeal_id}/review-draft",
            "/v1/app/appeal-review/appeals/{appeal_id}/decide",
        ):
            with self.subTest(route=route_fragment):
                self.assertIn(route_fragment, source)
        for event_type in (
            "AppealOpened",
            "AppealApplicationDraftSaved",
            "AppealSubmitted",
            "AppealReviewClaimed",
            "AppealReviewAssignmentReleased",
            "AppealReviewDraftSaved",
            "AppealDecisionPublished",
        ):
            with self.subTest(event_type=event_type):
                self.assertIn(event_type, source)
        self.assertIn("sensitive_body=True", source)
        self.assertIn("COMMAND_OUTCOME_UNKNOWN", source)

    def test_curl_disables_ambient_config_proxy_and_keeps_loopback_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-e2e-curl-") as directory:
            root = Path(directory).resolve() / "role"
            root.mkdir(mode=0o700)
            ca_file = Path(directory).resolve() / "root-ca.pem"
            ca_file.write_text("test-ca", encoding="ascii")
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                Path(command[command.index("--output") + 1]).write_bytes(b"{}")
                Path(command[command.index("--dump-header") + 1]).write_bytes(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                )
                return subprocess.CompletedProcess(command, 0, "200", "")

            hostile = {
                "http_proxy": "http://attacker.invalid:8080",
                "https_proxy": "http://attacker.invalid:8080",
                "all_proxy": "http://attacker.invalid:8080",
                "HTTP_PROXY": "http://attacker.invalid:8080",
                "HTTPS_PROXY": "http://attacker.invalid:8080",
                "ALL_PROXY": "http://attacker.invalid:8080",
                "NO_PROXY": "attacker.invalid",
                "CURL_HOME": str(Path(directory) / "attacker-curl-home"),
                "SSLKEYLOGFILE": str(Path(directory) / "keys.log"),
            }
            with mock.patch.dict(os.environ, hostile, clear=False), mock.patch.object(
                self.module.subprocess, "run", side_effect=fake_run
            ):
                client = self.module.CurlClient(root=root, ca_file=ca_file)
                result = client.request(method="GET", path="/health/live")

            self.assertEqual(result.status, 200)
            command = captured["command"]
            self.assertEqual(command[1], "--disable")
            self.assertEqual(command[command.index("--noproxy") + 1], "*")
            self.assertNotIn("--location", command)
            self.assertEqual(
                captured["kwargs"]["env"],
                {
                    "HOME": str(root),
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                },
            )

    def test_sensitive_appeal_body_uses_stdin_and_never_a_request_file(self) -> None:
        raw_statement = "memory-only applicant statement sentinel"
        with tempfile.TemporaryDirectory(prefix="desire-e2e-sensitive-") as directory:
            root = Path(directory).resolve() / "role"
            root.mkdir(mode=0o700)
            ca_file = Path(directory).resolve() / "root-ca.pem"
            ca_file.write_text("test-ca", encoding="ascii")
            captured = {}

            def fake_run(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                Path(command[command.index("--output") + 1]).write_bytes(b"{}")
                Path(command[command.index("--dump-header") + 1]).write_bytes(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                )
                return subprocess.CompletedProcess(command, 0, "200", "")

            with mock.patch.object(
                self.module.subprocess, "run", side_effect=fake_run
            ):
                client = self.module.CurlClient(root=root, ca_file=ca_file)
                client.request(
                    method="PUT",
                    path=(
                        "/v1/app/appeals/"
                        "11111111-1111-4111-8111-111111111111/draft"
                    ),
                    body={"applicant_statement": raw_statement},
                    headers={"Content-Type": "application/json"},
                    sensitive_body=True,
                )

            command = captured["command"]
            self.assertEqual(command[command.index("--data-binary") + 1], "@-")
            self.assertIn(raw_statement, captured["kwargs"]["input"])
            self.assertFalse(any("request-body" in path.name for path in root.iterdir()))
            sentinel = raw_statement.encode("utf-8")
            self.assertTrue(
                all(sentinel not in path.read_bytes() for path in root.iterdir())
            )

    def test_malicious_oidc_redirects_never_trigger_an_outbound_followup(self) -> None:
        valid_callback = (
            "https://pilot.example.test/v1/auth/oidc/callback?"
            f"code={'c' * 43}&state={'s' * 43}"
        )
        with tempfile.TemporaryDirectory(prefix="desire-e2e-redirect-") as directory:
            root = Path(directory).resolve() / "role"
            root.mkdir(mode=0o700)
            ca_file = Path(directory).resolve() / "root-ca.pem"
            ca_file.write_text("test-ca", encoding="ascii")
            client = self.module.CurlClient(root=root, ca_file=ca_file)

            for location in (
                (
                    "https://evil.example.test/collect?"
                    "access_invitation_token=" + "t" * 96
                ),
                valid_callback + "&access_invitation_token=" + "t" * 96,
            ):
                with self.subTest(location=location):
                    first_hop = mock.Mock(
                        return_value=self.module.HttpResult(
                            303, {"location": location}, b""
                        )
                    )
                    with mock.patch.object(client, "_run", first_hop):
                        with self.assertRaises(
                            self.module.InternalSandboxE2eError
                        ):
                            client.authorize(
                                account_code="creator_01",
                                request_handle="r" * 43,
                            )
                    self.assertEqual(first_hop.call_count, 1)

            two_hops = mock.Mock(
                side_effect=(
                    self.module.HttpResult(
                        303, {"location": valid_callback}, b""
                    ),
                    self.module.HttpResult(
                        303,
                        {
                            "location": (
                                "https://evil.example.test/collect?token="
                                + "t" * 96
                            )
                        },
                        b"",
                    ),
                )
            )
            with mock.patch.object(client, "_run", two_hops):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    client.authorize(
                        account_code="creator_01",
                        request_handle="q" * 43,
                    )
            self.assertEqual(two_hops.call_count, 2)

    def test_oidc_callback_redirect_is_exact_and_rejects_external_or_duplicate_fields(self) -> None:
        valid = (
            "https://pilot.example.test/v1/auth/oidc/callback?"
            f"code={'c' * 43}&state={'s' * 43}"
        )
        result = self.module.HttpResult(303, {"location": valid}, b"")
        self.assertEqual(
            self.module._validated_oidc_callback_location(result),
            valid,
        )
        for location in (
            f"https://evil.example.test/v1/auth/oidc/callback?code={'c' * 43}&state={'s' * 43}",
            f"https://pilot.example.test/v1/auth/oidc/callback?code={'c' * 43}&state={'s' * 43}&state={'x' * 43}",
            f"https://pilot.example.test/v1/auth/oidc/callback?code={'c' * 43}&state={'s' * 43}#fragment",
        ):
            with self.subTest(location=location):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._validated_oidc_callback_location(
                        self.module.HttpResult(303, {"location": location}, b"")
                    )

    def test_authorization_url_is_exact_and_never_carries_invitation_capability(self) -> None:
        values = {
            "client_id": "desire-internal-sandbox",
            "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
            "response_type": "code",
            "scope": "openid email",
            "state": "s" * 43,
            "nonce": "n" * 43,
            "code_challenge": "c" * 43,
            "code_challenge_method": "S256",
        }
        valid = (
            "https://identity.example.test/authorize?"
            + self.module.urlencode(values)
        )
        self.assertEqual(self.module._validated_authorization_url(valid), valid)
        invalid = (
            valid + "&access_invitation_token=" + "t" * 96,
            valid + "&state=" + "x" * 43,
            valid.replace("&nonce=" + "n" * 43, ""),
            valid.replace("desire-internal-sandbox", "forged-client"),
            valid.replace("identity.example.test", "evil.example.test"),
            valid.replace("identity.example.test", "identity.example.test:444"),
            valid.replace("response_type=code", "response_type=token"),
            valid.replace("scope=openid+email", "scope=openid+email+offline_access"),
            valid.replace("code_challenge_method=S256", "code_challenge_method=plain"),
            valid.replace("state=" + "s" * 43, "state=" + "s" * 42),
            valid + "#access_token=forbidden",
        )
        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._validated_authorization_url(target)

    def test_finance_funding_is_zero_funds_two_person_and_exactly_replayed(self) -> None:
        review = {
            "funding_review_id": "11111111-1111-4111-8111-111111111111",
            "demand_id": "22222222-2222-4222-8222-222222222222",
            "demand_version_id": "33333333-3333-4333-8333-333333333333",
            "status": "PENDING",
            "revision": 1,
            "assignment_id": "44444444-4444-4444-8444-444444444444",
            "assignment_expires_at": "2026-08-16T12:00:00+00:00",
            "target_sha256": "a" * 64,
            "target_content_sha256": "c" * 64,
            "planned_budget_currency": "CNY",
            "planned_budget_minimum_amount_minor": 0,
            "planned_budget_maximum_amount_minor": 0,
            "planned_budget_direct_cost_amount_minor": 0,
            "evidence_kind": "INTERNAL_SANDBOX_ZERO_FUNDS_V1",
            "evidence_reference_sha256": "b" * 64,
            "sandbox_funds_amount_minor": 0,
            "provider_code": "NONE",
            "payment_operation_code": "NONE",
            "synthetic": True,
            "legal_effect": "NO_REAL_FUNDS_OR_PAYMENT",
            "confirmation_count": 0,
            "required_confirmations": 2,
            "assignment_status": "ACTIVE",
            "confirmation_by_me": False,
            "available_actions": [
                "CONFIRM",
                "RELEASE_ASSIGNMENT",
                "SUBMIT_FINDING",
            ],
            "can_confirm": True,
            "etag": '"funding-review-1"',
            "replayed": False,
        }
        replay = {**review, "replayed": True}

        class Client:
            def __init__(self):
                self.calls = []
                self.responses = [review, replay]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                value = self.responses.pop(0)
                return self_module.HttpResult(
                    200,
                    {"etag": value["etag"]},
                    json.dumps({"data": value}).encode("utf-8"),
                )

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="finance_operator_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("FINANCE_OPERATOR",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        result = self.module._finance_write_exact_replay(
            session,
            path=(
                "/v1/app/finance/funding-reviews/"
                "22222222-2222-4222-8222-222222222222/claim"
            ),
            body={},
            if_match='"demand-7-finance-queue"',
        )
        self.assertFalse(result["replayed"])
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0]["headers"], client.calls[1]["headers"])
        self.assertEqual(client.calls[0]["body"], client.calls[1]["body"])
        self.assertEqual(
            self.module.FINANCE_FUNDING_ATTESTATION_CODES,
            (
                "SYNTHETIC_ONLY",
                "ZERO_REAL_FUNDS",
                "NO_PROVIDER_OR_PAYMENT",
                "TARGET_AND_EVIDENCE_MATCH",
            ),
        )
        self.assertEqual(
            self.module.FINANCE_FUNDING_ACTIONS,
            ("CONFIRM", "RELEASE_ASSIGNMENT", "SUBMIT_FINDING"),
        )

        unsafe = {**review, "sandbox_funds_amount_minor": 1}
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._finance_review_envelope(
                self.module.HttpResult(
                    200,
                    {"etag": unsafe["etag"]},
                    json.dumps({"data": unsafe}).encode("utf-8"),
                )
            )
        unsafe_provider = {**review, "provider_code": "FORGED_PROVIDER"}
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._finance_review_envelope(
                self.module.HttpResult(
                    200,
                    {"etag": unsafe_provider["etag"]},
                    json.dumps({"data": unsafe_provider}).encode("utf-8"),
                )
            )
        missing_projection = dict(review)
        missing_projection.pop("assignment_status")
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._finance_review_envelope(
                self.module.HttpResult(
                    200,
                    {"etag": review["etag"]},
                    json.dumps({"data": missing_projection}).encode("utf-8"),
                )
            )
        discrepancy = {
            **review,
            "status": "DISCREPANCY",
            "revision": 2,
            "assignment_status": "COMPLETED",
            "available_actions": [],
            "can_confirm": False,
            "etag": '"funding-review-2"',
        }
        self.assertEqual(
            self.module._finance_review_envelope(
                self.module.HttpResult(
                    200,
                    {"etag": discrepancy["etag"]},
                    json.dumps({"data": discrepancy}).encode("utf-8"),
                )
            )["status"],
            "DISCREPANCY",
        )
        journey_source = inspect.getsource(self.module._fund_verified_demand)
        self.assertLess(
            journey_source.index("/assignment/release"),
            journey_source.index("/findings"),
        )
        self.assertIn("release_reclaimed_with_new_assignment", journey_source)
        self.assertIn("active_assignments_absent", journey_source)
        self.assertIn("terminal_history_discoverable", journey_source)
        self.assertIn("terminal_history_actor_scoped", journey_source)

    def test_finance_terminal_history_is_closed_paged_and_discoverable(self) -> None:
        self.assertEqual(
            self.module._run_stage(
                "RESTART_FINANCE_HISTORY", lambda: "HISTORY_STAGE_CLOSED"
            ),
            "HISTORY_STAGE_CLOSED",
        )
        cursor = "a" * 64 + "." + "b" * 43
        first = {
            "data": {
                "schema_version": "finance-funding-review-history-v1",
                "items": [
                    {
                        "funding_review_id": (
                            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                        ),
                        "demand_id": "11111111-1111-4111-8111-111111111111",
                        "demand_version_id": (
                            "22222222-2222-4222-8222-222222222222"
                        ),
                        "status": "SECURED",
                        "completed_at": "2026-08-26T13:00:00+00:00",
                    }
                ],
                "next_cursor": cursor,
                "has_more": True,
            }
        }
        second = {
            "data": {
                "schema_version": "finance-funding-review-history-v1",
                "items": [
                    {
                        "funding_review_id": (
                            "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
                        ),
                        "demand_id": "11111111-1111-4111-8111-111111111111",
                        "demand_version_id": (
                            "22222222-2222-4222-8222-222222222222"
                        ),
                        "status": "DISCREPANCY",
                        "completed_at": "2026-08-26T12:00:00+00:00",
                    }
                ],
                "next_cursor": None,
                "has_more": False,
            }
        }

        class Client:
            def __init__(self):
                self.calls = []
                self.responses = [first, second]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                value = self.responses.pop(0)
                return self_module.HttpResult(
                    200, {}, json.dumps(value).encode("utf-8")
                )

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="finance_operator_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("FINANCE_OPERATOR",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        history = self.module._finance_history(session, limit=1)
        self.assertEqual(
            [item["status"] for item in history],
            ["SECURED", "DISCREPANCY"],
        )
        self.assertEqual(
            client.calls[0]["path"],
            "/v1/app/finance/funding-review-history",
        )
        self.assertEqual(client.calls[0]["query"], {"limit": "1"})
        self.assertEqual(
            client.calls[1]["query"],
            {"limit": "1", "cursor": cursor},
        )

    def test_trust_terminal_history_get_is_closed_and_safe(self) -> None:
        entity_tag = '"trust-8-aaaaaaaaaaaaaaaaaaaaaaaa"'
        history = {
            "data": {
                "entity_tag": entity_tag,
                "has_more": False,
                "items": [
                    {
                        "case_id": "22222222-2222-4222-8222-222222222222",
                        "decided_at": "2026-08-26T13:00:00+00:00",
                        "outcome_code": "PROTECTION_MODIFIED",
                    },
                    {
                        "case_id": "11111111-1111-4111-8111-111111111111",
                        "decided_at": "2026-08-26T13:00:00Z",
                        "outcome_code": "NO_ACTION",
                    },
                ],
            }
        }

        class Client:
            def __init__(self):
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self_module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": entity_tag,
                    },
                    json.dumps(history).encode("utf-8"),
                )

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="trust_officer_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )

        parsed = self.module._trust_terminal_history(session)

        self.assertEqual(parsed, history["data"])
        self.assertEqual(
            client.calls,
            [
                {
                    "method": "GET",
                    "path": "/v1/app/trust/history",
                    "headers": {
                        "Accept": "application/json",
                        "X-Workspace-Id": session.workspace_id,
                    },
                }
            ],
        )
        unsafe = _json_copy(history)
        unsafe["data"]["items"][0]["assigned_officer_user_id"] = (
            "33333333-3333-4333-8333-333333333333"
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_terminal_history_envelope(
                self.module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": entity_tag,
                    },
                    json.dumps(unsafe).encode("utf-8"),
                )
            )

        reverse_tie = _json_copy(history)
        reverse_tie["data"]["items"].reverse()
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_terminal_history_envelope(
                self.module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": entity_tag,
                    },
                    json.dumps(reverse_tie).encode("utf-8"),
                )
            )

    def test_trust_command_replay_reuses_exact_idempotency_etag_and_safe_body(self) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        report_id = "22222222-2222-4222-8222-222222222222"
        completed = "2026-08-19T08:00:00Z"

        def result(replayed: bool) -> dict:
            return {
                "aggregate_version": 2,
                "case_id": case_id,
                "case_status": "IN_REVIEW",
                "completed_at": completed,
                "event_types": ["TrustCaseClaimed"],
                "hold_id": None,
                "hold_version": None,
                "outcome_version_id": None,
                "replayed": replayed,
                "report_id": report_id,
                "triage_draft_version": None,
                "triage_version": None,
            }

        class Client:
            def __init__(self):
                self.calls = []
                self.responses = [result(False), result(True)]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                value = self.responses.pop(0)
                return self_module.HttpResult(
                    201,
                    {"cache-control": "no-store"},
                    json.dumps({"data": value}).encode("utf-8"),
                )

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="trust_officer_01",
            workspace_id="platform:33333333-3333-4333-8333-333333333333",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        command = self.module._trust_write_exact_replay(
            session,
            method="POST",
            path=f"/v1/app/trust/queue/{case_id}/claim",
            body={},
            if_match='"trust-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
            expected_status=201,
            expected_event_type="TrustCaseClaimed",
        )
        self.assertFalse(command["replayed"])
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0]["headers"], client.calls[1]["headers"])
        self.assertEqual(client.calls[0]["body"], client.calls[1]["body"])
        self.assertEqual(
            client.calls[0]["headers"]["If-Match"],
            '"trust-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
        )
        self.assertNotIn("actor", json.dumps(client.calls).lower())
        self.assertNotIn("assignment", json.dumps(client.calls).lower())

    def test_appeal_command_replay_is_exact_and_unknown_outcome_stops_retry(self) -> None:
        appeal_id = "11111111-1111-4111-8111-111111111111"
        completed = "2026-08-19T08:00:00Z"

        def result(replayed: bool) -> dict:
            return {
                "aggregate_version": 2,
                "appeal_id": appeal_id,
                "appeal_status": "DRAFT",
                "application_draft_version": 1,
                "application_version": None,
                "completed_at": completed,
                "decision_version_id": None,
                "event_types": ["AppealApplicationDraftSaved"],
                "replayed": replayed,
                "review_draft_version": None,
            }

        class Client:
            def __init__(self, responses):
                self.calls = []
                self.responses = list(responses)

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self.responses.pop(0)

        def response(value):
            return self.module.HttpResult(
                200,
                {
                    "cache-control": "no-store",
                    "content-type": "application/json",
                },
                json.dumps({"data": value}).encode("utf-8"),
            )

        client = Client((response(result(False)), response(result(True))))
        session = self.module.RoleSession(
            account_code="demand_owner_01",
            workspace_id="org:22222222-2222-4222-8222-222222222222",
            workspace_kind="ORGANIZATION",
            role_codes=("DEMAND_OWNER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        body = {
            "applicant_statement": "memory-only synthetic appeal statement",
            "grounds": ["PROCEDURAL_ERROR"],
            "new_evidence_reference_ids": [],
            "requested_outcome": "VACATE_AND_REMAND",
        }
        command = self.module._appeal_write_exact_replay(
            session,
            method="PUT",
            path=f"/v1/app/appeals/{appeal_id}/draft",
            body=body,
            if_match='"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
            expected_status=200,
            expected_event_type="AppealApplicationDraftSaved",
            sensitive_body=True,
        )
        self.assertFalse(command["replayed"])
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0]["headers"], client.calls[1]["headers"])
        self.assertEqual(
            client.calls[0]["headers"]["Origin"],
            "https://pilot.example.test",
        )
        self.assertEqual(client.calls[0]["body"], client.calls[1]["body"])
        self.assertTrue(client.calls[0]["sensitive_body"])

        unknown = self.module.HttpResult(
            503,
            {
                "cache-control": "no-store",
                "content-type": "application/json",
            },
            b'{"error":{"code":"COMMAND_OUTCOME_UNKNOWN"}}',
        )
        unknown_client = Client((unknown,))
        unknown_session = self.module.RoleSession(
            **{
                **vars(session),
                "client": unknown_client,
            }
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_write_exact_replay(
                unknown_session,
                method="POST",
                path="/v1/app/appeals",
                body={
                    "source_outcome_version_id": (
                        "33333333-3333-4333-8333-333333333333"
                    )
                },
                expected_status=201,
                expected_event_type="AppealOpened",
            )
        self.assertEqual(len(unknown_client.calls), 1)

    def test_appeal_receipt_error_and_queue_parsers_are_closed(self) -> None:
        appeal_id = "11111111-1111-4111-8111-111111111111"
        receipt = {
            "aggregate_version": 1,
            "appeal_id": appeal_id,
            "appeal_status": "DRAFT",
            "application_draft_version": None,
            "application_version": None,
            "completed_at": "2026-08-19T08:00:00Z",
            "decision_version_id": None,
            "event_types": ["AppealOpened"],
            "replayed": False,
            "review_draft_version": None,
        }

        def response(body, *, status=201, etag=False):
            headers = {
                "cache-control": "no-store",
                "content-type": "application/json",
            }
            if etag:
                headers["etag"] = '"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"'
            return self.module.HttpResult(
                status,
                headers,
                json.dumps(body).encode("utf-8"),
            )

        parsed = self.module._appeal_command_receipt(
            response({"data": receipt}), expected_event_type="AppealOpened"
        )
        self.assertEqual(parsed["appeal_id"], appeal_id)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_command_receipt(
                response({"data": {**receipt, "private_diagnostic": "forbidden"}}),
                expected_event_type="AppealOpened",
            )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_command_receipt(
                response(
                    {
                        "data": {
                            **receipt,
                            "completed_at": "2026-08-19T08:00:00+00:00",
                        }
                    }
                ),
                expected_event_type="AppealOpened",
            )
        error = response(
            {"error": {"code": "COMMAND_OUTCOME_UNKNOWN"}}, status=503
        )
        self.assertEqual(
            self.module._appeal_error(error)["code"],
            "COMMAND_OUTCOME_UNKNOWN",
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_error(
                response(
                    {
                        "error": {
                            "code": "COMMAND_OUTCOME_UNKNOWN",
                            "private_diagnostic": "forbidden",
                        }
                    },
                    status=503,
                )
            )

        queue_response = response(
            {
                "data": {
                    "entity_tag": '"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
                    "items": [
                        {
                            "appeal_id": appeal_id,
                            "entity_tag": '"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
                            "grounds": ["PROCEDURAL_ERROR"],
                            "requested_outcome": "VACATE_AND_REMAND",
                            "source_case_id": (
                                "22222222-2222-4222-8222-222222222222"
                            ),
                            "source_outcome_version_id": (
                                "33333333-3333-4333-8333-333333333333"
                            ),
                            "submitted_at": "2026-08-19T08:00:00Z",
                        }
                    ],
                }
            },
            status=200,
            etag=True,
        )

        class Client:
            def request(self, **_kwargs):
                return queue_response

        session = self.module.RoleSession(
            account_code="appeal_reviewer_01",
            workspace_id="platform:44444444-4444-4444-8444-444444444444",
            workspace_kind="PLATFORM",
            role_codes=("APPEAL_REVIEWER",),
            csrf_token="x" * 32,
            client=Client(),
            policy_accepted=False,
        )
        self.assertEqual(
            self.module._appeal_queue(session)["items"][0]["appeal_id"],
            appeal_id,
        )

    def test_appeal_terminal_history_and_detail_parsers_are_closed(self) -> None:
        newer_id = "22222222-2222-4222-8222-222222222222"
        older_id = "11111111-1111-4111-8111-111111111111"
        decision_id = "33333333-3333-4333-8333-333333333333"
        etag = '"appeal-8-aaaaaaaaaaaaaaaaaaaaaaaa"'
        decided_at = "2026-08-19T08:00:00Z"
        application = {
            "grounds": ["PROCEDURAL_ERROR"],
            "new_evidence_reference_ids": [],
            "requested_outcome": "VACATE_AND_REMAND",
            "statement_recorded": True,
            "submitted_at": "2026-08-19T07:00:00Z",
        }
        decision = {
            "assessments": [
                {
                    "accepted_evidence_reference_ids": [],
                    "assessment_code": "ACCEPTED",
                    "finding_codes": ["PROCEDURE_MATERIAL_ERROR"],
                    "ground": "PROCEDURAL_ERROR",
                }
            ],
            "decided_at": decided_at,
            "decision_code": "VACATE_AND_REMAND",
            "decision_sha256": "a" * 64,
            "decision_version_id": decision_id,
            "policy_version": "appeal-policy-v1",
            "reason_codes": ["PROCEDURAL_REVIEW_COMPLETE"],
            "remedy_delta_codes": ["RETURN_TO_TRUST_REVIEW"],
        }
        history = {
            "data": {
                "entity_tag": etag,
                "has_more": False,
                "items": [
                    {
                        "appeal_id": newer_id,
                        "decided_at": decided_at,
                        "decision_code": "VACATE_AND_REMAND",
                    },
                    {
                        "appeal_id": older_id,
                        "decided_at": decided_at,
                        "decision_code": "AFFIRM",
                    },
                ],
            }
        }
        detail = {
            "data": {
                "appeal_id": newer_id,
                "application": application,
                "decision": decision,
                "entity_tag": etag,
                "review_note_recorded": True,
                "status": "DECIDED",
            }
        }

        class Client:
            def __init__(self):
                self.history = history
                self.detail = detail
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                body = (
                    self.history
                    if kwargs["path"] == "/v1/app/appeal-review/history"
                    else self.detail
                )
                return self_module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": etag,
                    },
                    json.dumps(body).encode("utf-8"),
                )

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="appeal_reviewer_01",
            workspace_id="platform:44444444-4444-4444-8444-444444444444",
            workspace_kind="PLATFORM",
            role_codes=("APPEAL_REVIEWER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        self.assertEqual(
            [
                item["appeal_id"]
                for item in self.module._appeal_terminal_history(session)[
                    "items"
                ]
            ],
            [newer_id, older_id],
        )
        terminal = self.module._get_terminal_appeal(
            session, appeal_id=newer_id
        )
        self.assertEqual(terminal["application"], application)
        self.assertEqual(terminal["decision"], decision)
        self.assertEqual(
            [call["path"] for call in client.calls],
            [
                "/v1/app/appeal-review/history",
                f"/v1/app/appeal-review/history/{newer_id}",
            ],
        )

        client.history = json.loads(json.dumps(history))
        client.history["data"]["items"].reverse()
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_terminal_history(session)
        client.detail = json.loads(json.dumps(detail))
        client.detail["data"]["source_case_id"] = older_id
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._get_terminal_appeal(session, appeal_id=newer_id)

    def test_active_assignment_discovery_parsers_are_exact_role_closed_and_queryless(
        self,
    ) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        appeal_id = "22222222-2222-4222-8222-222222222222"
        workspace_id = "platform:33333333-3333-4333-8333-333333333333"
        expires_at = "2026-08-19T12:00:00Z"
        trust_etag = '"trust-3-aaaaaaaaaaaaaaaaaaaaaaaa"'
        appeal_etag = '"appeal-4-bbbbbbbbbbbbbbbbbbbbbbbb"'

        class Client:
            def __init__(self, response):
                self.response = response
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self.response

        def session(code, roles, client):
            return self.module.RoleSession(
                account_code=code,
                workspace_id=workspace_id,
                workspace_kind="PLATFORM",
                role_codes=roles,
                csrf_token="x" * 32,
                client=client,
                policy_accepted=False,
            )

        trust_body = {
            "data": {
                "entity_tag": trust_etag,
                "items": [
                    {
                        "case_id": case_id,
                        "assignment_purpose": "CASE_TRIAGE",
                        "assignment_expires_at": expires_at,
                        "hold_id": None,
                    }
                ],
            }
        }
        trust_client = Client(
            self.module.HttpResult(
                200,
                {
                    "cache-control": "no-store",
                    "content-type": "application/json",
                    "etag": trust_etag,
                },
                json.dumps(trust_body).encode("utf-8"),
            )
        )
        trust = session(
            "trust_officer_01", ("TRUST_OFFICER",), trust_client
        )
        self.assertEqual(
            self.module._trust_active_assignments(trust)["items"][0],
            trust_body["data"]["items"][0],
        )
        trust_body["data"]["items"].append(
            {
                "case_id": case_id,
                "assignment_purpose": "HOLD_RELEASE",
                "assignment_expires_at": expires_at,
                "hold_id": "99999999-9999-4999-8999-999999999999",
            }
        )
        trust_client.response = self.module.HttpResult(
            200,
            {
                "cache-control": "no-store",
                "content-type": "application/json",
                "etag": trust_etag,
            },
            json.dumps(trust_body).encode("utf-8"),
        )
        self.assertEqual(
            [
                item["assignment_purpose"]
                for item in self.module._trust_active_assignments(trust)["items"]
            ],
            ["CASE_TRIAGE", "HOLD_RELEASE"],
        )
        self.assertEqual(
            trust_client.calls,
            [
                {
                    "method": "GET",
                    "path": "/v1/app/trust/assignments",
                    "headers": self.module._app_headers(trust),
                },
                {
                    "method": "GET",
                    "path": "/v1/app/trust/assignments",
                    "headers": self.module._app_headers(trust),
                },
            ],
        )

        duplicate_trust = json.loads(json.dumps(trust_body))
        duplicate_trust["data"]["items"].append(
            duplicate_trust["data"]["items"][0]
        )
        trust_client.response = self.module.HttpResult(
            200,
            {
                "cache-control": "no-store",
                "content-type": "application/json",
                "etag": trust_etag,
            },
            json.dumps(duplicate_trust).encode("utf-8"),
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_active_assignments(trust)

        appeal_body = {
            "data": {
                "entity_tag": appeal_etag,
                "items": [
                    {
                        "appeal_id": appeal_id,
                        "assignment_expires_at": expires_at,
                    }
                ],
            }
        }
        appeal_client = Client(
            self.module.HttpResult(
                200,
                {
                    "cache-control": "no-store",
                    "content-type": "application/json",
                    "etag": appeal_etag,
                },
                json.dumps(appeal_body).encode("utf-8"),
            )
        )
        appeal = session(
            "appeal_reviewer_01", ("APPEAL_REVIEWER",), appeal_client
        )
        self.assertEqual(
            self.module._appeal_active_assignments(appeal)["items"][0],
            appeal_body["data"]["items"][0],
        )
        self.assertEqual(
            appeal_client.calls,
            [
                {
                    "method": "GET",
                    "path": "/v1/app/appeal-review/assignments",
                    "headers": self.module._app_headers(appeal),
                }
            ],
        )

        forged_trust = json.loads(json.dumps(trust_body))
        forged_trust["data"]["items"][0]["assignment_id"] = case_id
        trust_client.response = self.module.HttpResult(
            200,
            {
                "cache-control": "no-store",
                "content-type": "application/json",
                "etag": trust_etag,
            },
            json.dumps(forged_trust).encode("utf-8"),
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_active_assignments(trust)

        forged_appeal = json.loads(json.dumps(appeal_body))
        forged_appeal["data"]["items"][0]["reviewer_user_id"] = case_id
        appeal_client.response = self.module.HttpResult(
            200,
            {
                "cache-control": "no-store",
                "content-type": "application/json",
                "etag": appeal_etag,
            },
            json.dumps(forged_appeal).encode("utf-8"),
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._appeal_active_assignments(appeal)

        wrong_role = session(
            "operations_reviewer_01", ("OPERATIONS_REVIEWER",), trust_client
        )
        wrong_role_calls = len(trust_client.calls)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_active_assignments(wrong_role)
        self.assertEqual(len(trust_client.calls), wrong_role_calls)

    def test_trust_assignment_hold_identity_allows_distinct_holds_and_rejects_exact_triples(
        self,
    ) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        hold_one = "22222222-2222-4222-8222-222222222222"
        hold_two = "33333333-3333-4333-8333-333333333333"
        trust_etag = '"trust-3-aaaaaaaaaaaaaaaaaaaaaaaa"'
        expires_at = "2026-08-19T12:00:00Z"

        class Client:
            def __init__(self, items):
                self.items = items

            def request(self, **_kwargs):
                return self_module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": trust_etag,
                    },
                    json.dumps(
                        {
                            "data": {
                                "entity_tag": trust_etag,
                                "items": self.items,
                            }
                        }
                    ).encode("utf-8"),
                )

        self_module = self.module
        base = {
            "case_id": case_id,
            "assignment_expires_at": expires_at,
        }
        triage = {
            **base,
            "assignment_purpose": "CASE_TRIAGE",
            "hold_id": None,
        }
        release_one = {
            **base,
            "assignment_purpose": "HOLD_RELEASE",
            "hold_id": hold_one,
        }
        release_two = {
            **base,
            "assignment_purpose": "HOLD_RELEASE",
            "hold_id": hold_two,
        }

        def session(items):
            return self.module.RoleSession(
                account_code="trust_officer_01",
                workspace_id=(
                    "platform:44444444-4444-4444-8444-444444444444"
                ),
                workspace_kind="PLATFORM",
                role_codes=("TRUST_OFFICER",),
                csrf_token="x" * 32,
                client=Client(items),
                policy_accepted=False,
            )

        parsed = self.module._trust_active_assignments(
            session([triage, release_one, release_two])
        )
        self.assertEqual(
            [item["hold_id"] for item in parsed["items"]],
            [None, hold_one, hold_two],
        )
        for invalid_items in (
            [release_one, release_one],
            [
                release_one,
                {
                    **release_one,
                    "assignment_expires_at": "2026-08-19T12:30:00Z",
                },
            ],
            [{**triage, "hold_id": hold_one}],
            [{**release_one, "hold_id": None}],
        ):
            with self.subTest(invalid_items=invalid_items):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._trust_active_assignments(session(invalid_items))

    def test_assigned_hold_projection_is_exact_path_bound_and_role_closed(
        self,
    ) -> None:
        hold_id = "11111111-1111-4111-8111-111111111111"
        wrong_hold_id = "22222222-2222-4222-8222-222222222222"
        case_id = "33333333-3333-4333-8333-333333333333"
        entity_tag = '"trust-6-aaaaaaaaaaaaaaaaaaaaaaaa"'
        projection = {
            "action_codes": ["VERIFY_DEMAND"],
            "assignment_expires_at": "2026-08-19T12:30:00Z",
            "case_id": case_id,
            "case_status": "IN_REVIEW",
            "effective_at": "2026-08-19T11:00:00Z",
            "entity_tag": entity_tag,
            "expires_at": "2026-08-19T13:00:00Z",
            "hold_id": hold_id,
            "hold_status": "ACTIVE",
            "reason_code": "PARTICIPANT_SAFETY_RISK",
        }

        class Client:
            def __init__(self, value):
                self.value = value
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self_module.HttpResult(
                    200,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                        "etag": entity_tag,
                    },
                    json.dumps({"data": self.value}).encode("utf-8"),
                )

        self_module = self.module
        client = Client(projection)
        officer = self.module.RoleSession(
            account_code="trust_officer_02",
            workspace_id="platform:44444444-4444-4444-8444-444444444444",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        self.assertEqual(
            self.module._get_assigned_trust_hold(officer, hold_id=hold_id),
            projection,
        )
        self.assertEqual(
            client.calls,
            [
                {
                    "method": "GET",
                    "path": f"/v1/app/trust/assigned-holds/{hold_id}",
                    "headers": self.module._app_headers(officer),
                }
            ],
        )

        boundary_projection = {
            **projection,
            "assignment_expires_at": projection["expires_at"],
        }
        client.value = boundary_projection
        self.assertEqual(
            self.module._get_assigned_trust_hold(officer, hold_id=hold_id),
            boundary_projection,
        )

        for forged in (
            {**projection, "hold_id": wrong_hold_id},
            {**projection, "assignment_id": wrong_hold_id},
            {**projection, "hold_status": "RELEASED"},
            {**projection, "case_status": "DECIDED"},
            {
                **projection,
                "assignment_expires_at": "2026-08-19T14:00:00Z",
            },
        ):
            client.value = forged
            with self.subTest(forged=forged):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._get_assigned_trust_hold(
                        officer, hold_id=hold_id
                    )

        wrong_role = self.module.RoleSession(
            account_code="operations_reviewer_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("OPERATIONS_REVIEWER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        prior_calls = len(client.calls)
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._get_assigned_trust_hold(
                wrong_role, hold_id=hold_id
            )
        self.assertEqual(len(client.calls), prior_calls)

    def test_assignment_discovery_wrong_roles_and_extra_queries_fail_closed(
        self,
    ) -> None:
        workspace_id = "platform:11111111-1111-4111-8111-111111111111"
        completed_appeal_id = "22222222-2222-4222-8222-222222222222"

        def error(status, code, path=None):
            detail = {"code": code}
            if path is not None:
                detail["path"] = path
            return self.module.HttpResult(
                status,
                {
                    "cache-control": "no-store",
                    "content-type": "application/json",
                },
                json.dumps({"error": detail}).encode("utf-8"),
            )

        class Client:
            def __init__(self, responses):
                self.responses = iter(responses)
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return next(self.responses)

        def session(code, roles, client):
            return self.module.RoleSession(
                account_code=code,
                workspace_id=workspace_id,
                workspace_kind="PLATFORM",
                role_codes=roles,
                csrf_token="x" * 32,
                client=client,
                policy_accepted=False,
            )

        wrong_client = Client(
            (
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
            )
        )
        trust_client = Client(
            (
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
                error(404, "RESOURCE_NOT_FOUND"),
            )
        )
        appeal_client = Client(
            (
                error(400, "INVALID_REQUEST", "/query"),
                error(400, "INVALID_REQUEST", "/query"),
                error(400, "INVALID_REQUEST", "/query"),
            )
        )
        admin = session(
            "access_admin_01", ("ACCESS_ADMIN",), Client(())
        )
        wrong = session(
            "operations_reviewer_01", ("OPERATIONS_REVIEWER",), wrong_client
        )
        trust = session(
            "trust_officer_01", ("TRUST_OFFICER",), trust_client
        )
        appeal = session(
            "appeal_reviewer_01", ("APPEAL_REVIEWER",), appeal_client
        )
        second_reviewer_candidate = session(
            "trust_officer_02", ("TRUST_OFFICER",), Client(())
        )
        second_actor_boundary = mock.Mock(
            return_value={
                "second_reviewer_history_empty": True,
                "second_reviewer_detail_hidden": True,
                "temporary_reviewer_duty_restored": True,
            }
        )

        with mock.patch.object(
            self.module,
            "_verify_second_appeal_reviewer_history_boundary",
            second_actor_boundary,
        ):
            summary = self.module._verify_assignment_discovery_boundaries(
                admin=admin,
                trust_officer=trust,
                appeal_reviewer=appeal,
                second_reviewer_candidate=second_reviewer_candidate,
                wrong_role=wrong,
                completed_appeal_id=completed_appeal_id,
            )

        self.assertEqual(
            summary,
            {
                "wrong_role_reads_hidden": True,
                "extra_queries_rejected": True,
                "wrong_hold_reads_hidden": True,
                "assigned_hold_extra_queries_rejected": True,
                "wrong_role_history_hidden": True,
                "history_extra_queries_rejected": True,
                "second_reviewer_history_empty": True,
                "second_reviewer_detail_hidden": True,
                "temporary_reviewer_duty_restored": True,
            },
        )
        self.assertEqual(
            [(call["path"], call.get("query")) for call in wrong_client.calls],
            [
                ("/v1/app/trust/assignments", None),
                ("/v1/app/appeal-review/assignments", None),
                ("/v1/app/appeal-review/history", None),
                (
                    f"/v1/app/appeal-review/history/{completed_appeal_id}",
                    None,
                ),
                (trust_client.calls[1]["path"], None),
            ],
        )
        self.assertEqual(trust_client.calls[0]["query"], {"limit": "1"})
        assigned_hold_path = trust_client.calls[1]["path"]
        self.assertRegex(
            assigned_hold_path,
            r"^/v1/app/trust/assigned-holds/"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$",
        )
        self.assertEqual(wrong_client.calls[4]["path"], assigned_hold_path)
        self.assertEqual(trust_client.calls[1].get("query"), None)
        self.assertEqual(trust_client.calls[2]["path"], assigned_hold_path)
        self.assertEqual(trust_client.calls[2]["query"], {"limit": "1"})
        self.assertEqual(appeal_client.calls[0]["query"], {"limit": "1"})
        self.assertEqual(
            [
                (call["path"], call.get("query"))
                for call in appeal_client.calls[1:]
            ],
            [
                ("/v1/app/appeal-review/history", {"limit": "1"}),
                (
                    f"/v1/app/appeal-review/history/{completed_appeal_id}",
                    {"limit": "1"},
                ),
            ],
        )
        second_actor_boundary.assert_called_once_with(
            admin=admin,
            candidate=second_reviewer_candidate,
            completed_appeal_id=completed_appeal_id,
        )

    def test_second_appeal_reviewer_history_is_empty_and_foreign_detail_hidden(
        self,
    ) -> None:
        workspace_id = "platform:11111111-1111-4111-8111-111111111111"
        user_id = "22222222-2222-4222-8222-222222222222"
        completed_appeal_id = "33333333-3333-4333-8333-333333333333"
        etag = '"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"'

        class CandidateClient:
            def __init__(self):
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                if kwargs["path"] == "/v1/app/appeal-review/history":
                    return self_module.HttpResult(
                        200,
                        {
                            "cache-control": "no-store",
                            "content-type": "application/json",
                            "etag": etag,
                        },
                        json.dumps(
                            {
                                "data": {
                                    "entity_tag": etag,
                                    "has_more": False,
                                    "items": [],
                                }
                            }
                        ).encode("utf-8"),
                    )
                return self_module.HttpResult(
                    404,
                    {
                        "cache-control": "no-store",
                        "content-type": "application/json",
                    },
                    b'{"error":{"code":"RESOURCE_NOT_FOUND"}}',
                )

        self_module = self.module
        admin = self.module.RoleSession(
            account_code="access_admin_01",
            workspace_id=workspace_id,
            workspace_kind="PLATFORM",
            role_codes=("ACCESS_ADMIN",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        candidate_client = CandidateClient()
        candidate = self.module.RoleSession(
            account_code="trust_officer_02",
            workspace_id="platform:44444444-4444-4444-8444-444444444444",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="y" * 32,
            client=candidate_client,
            policy_accepted=False,
        )
        target = {
            "account_code": "trust_officer_02",
            "user_id": user_id,
            "entity_tag": '"v1"',
            "status": "ACTIVE",
            "role_codes": ["TRUST_OFFICER"],
            "is_self": False,
        }
        grant_send = mock.Mock(
            side_effect=(
                {"entity_tag": '"v2"', "replayed": False},
                {"entity_tag": '"v2"', "replayed": True},
            )
        )
        cleanup = mock.Mock(return_value=True)
        workspace_check = mock.Mock()
        with mock.patch.multiple(
            self.module,
            _account_list=mock.Mock(return_value=[target]),
            _send_platform_duty_command=grant_send,
            _account_detail=mock.Mock(
                return_value={
                    **target,
                    "entity_tag": '"v2"',
                    "role_codes": ["APPEAL_REVIEWER", "TRUST_OFFICER"],
                }
            ),
            _reconcile_platform_duty_cleanup=cleanup,
            _expect_single_platform_workspace=workspace_check,
        ):
            result = (
                self.module._verify_second_appeal_reviewer_history_boundary(
                    admin=admin,
                    candidate=candidate,
                    completed_appeal_id=completed_appeal_id,
                )
            )

        self.assertEqual(
            result,
            {
                "second_reviewer_history_empty": True,
                "second_reviewer_detail_hidden": True,
                "temporary_reviewer_duty_restored": True,
            },
        )
        self.assertEqual(
            [
                (call["path"], call.get("query"), call.get("body"))
                for call in candidate_client.calls
            ],
            [
                ("/v1/app/appeal-review/history", None, None),
                (
                    f"/v1/app/appeal-review/history/{completed_appeal_id}",
                    None,
                    None,
                ),
            ],
        )
        self.assertEqual(grant_send.call_count, 2)
        self.assertIs(
            grant_send.call_args_list[0].args[1],
            grant_send.call_args_list[1].args[1],
        )
        grant_command = grant_send.call_args_list[0].args[1]
        self.assertEqual(grant_command.duty_code, "APPEAL_REVIEWER")
        self.assertEqual(grant_command.action, "grant")
        cleanup.assert_called_once_with(
            admin,
            target_account_code="trust_officer_02",
            user_id=user_id,
            duty_code="APPEAL_REVIEWER",
            original_role_codes=("TRUST_OFFICER",),
        )
        self.assertEqual(
            [call.kwargs["expected_role_codes"] for call in workspace_check.call_args_list],
            [
                ("APPEAL_REVIEWER", "TRUST_OFFICER"),
                ("TRUST_OFFICER",),
            ],
        )
        serialized = json.dumps(result, sort_keys=True)
        for forbidden in (
            completed_appeal_id,
            user_id,
            "access_admin_01",
            "trust_officer_02",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_appeal_journey_releases_requeues_reclaims_and_decides(self) -> None:
        appeal_id = "11111111-1111-4111-8111-111111111111"
        case_id = "22222222-2222-4222-8222-222222222222"
        outcome_id = "33333333-3333-4333-8333-333333333333"
        decision_id = "44444444-4444-4444-8444-444444444444"

        def session(code, roles):
            return self.module.RoleSession(
                account_code=code,
                workspace_id=(
                    "org:55555555-5555-4555-8555-555555555555"
                    if code == "demand_owner_01"
                    else "platform:66666666-6666-4666-8666-666666666666"
                ),
                workspace_kind=(
                    "ORGANIZATION" if code == "demand_owner_01" else "PLATFORM"
                ),
                role_codes=roles,
                csrf_token="x" * 32,
                client=object(),
                policy_accepted=False,
            )

        owner = session("demand_owner_01", ("DEMAND_OWNER",))
        reviewer = session("appeal_reviewer_01", ("APPEAL_REVIEWER",))
        discovered = {
            "appeal_id": appeal_id,
            "entity_tag": '"appeal-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
        }
        drafted = {
            "appeal_id": appeal_id,
            "source_case_id": case_id,
            "source_outcome_version_id": outcome_id,
            "status": "DRAFT",
            "entity_tag": '"appeal-2-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "application_draft": {
                "version": 1,
                "statement_recorded": True,
                "grounds": ["PROCEDURAL_ERROR"],
                "new_evidence_reference_ids": [],
                "requested_outcome": "VACATE_AND_REMAND",
            },
        }
        submitted = {
            "appeal_id": appeal_id,
            "source_case_id": case_id,
            "source_outcome_version_id": outcome_id,
            "status": "SUBMITTED",
            "entity_tag": '"appeal-3-cccccccccccccccccccccccc"',
            "application": {
                "statement_recorded": True,
                "grounds": ["PROCEDURAL_ERROR"],
                "requested_outcome": "VACATE_AND_REMAND",
            },
        }
        queue_item = {
            "appeal_id": appeal_id,
            "entity_tag": '"appeal-3-cccccccccccccccccccccccc"',
            "source_case_id": case_id,
            "source_outcome_version_id": outcome_id,
            "grounds": ["PROCEDURAL_ERROR"],
            "requested_outcome": "VACATE_AND_REMAND",
        }
        released_item = {
            **queue_item,
            "entity_tag": '"appeal-5-eeeeeeeeeeeeeeeeeeeeeeee"',
        }
        first_assignment = {
            "entity_tag": '"appeal-4-dddddddddddddddddddddddd"'
        }
        active_assignment = {
            "appeal_id": appeal_id,
            "assignment_expires_at": "2026-08-19T12:00:00Z",
        }
        second_assignment = {
            "entity_tag": '"appeal-6-ffffffffffffffffffffffff"',
            "appeal": {
                "appeal_id": appeal_id,
                "source_case_id": case_id,
                "source_outcome_version_id": outcome_id,
            },
        }
        reviewed_assignment = {
            "entity_tag": '"appeal-7-111111111111111111111111"',
            "review_draft": {
                "version": 1,
                "review_note_recorded": True,
                "reason_codes": [
                    "PROCEDURAL_REVIEW_COMPLETE",
                    "REMAND_REQUIRED",
                ],
                "remedy_delta_codes": ["RETURN_TO_TRUST_REVIEW"],
            },
        }
        final = {
            "appeal_id": appeal_id,
            "source_case_id": case_id,
            "source_outcome_version_id": outcome_id,
            "status": "DECIDED",
            "entity_tag": '"appeal-8-222222222222222222222222"',
            "application": {
                "statement_recorded": True,
                "grounds": ["PROCEDURAL_ERROR"],
                "requested_outcome": "VACATE_AND_REMAND",
            },
            "decision": {
                "decision_version_id": decision_id,
                "decision_code": "VACATE_AND_REMAND",
            },
        }
        write = mock.Mock(
            side_effect=(
                {"appeal_id": appeal_id, "appeal_status": "DRAFT"},
                {"application_draft_version": 1},
                {"application_version": 1},
                {"appeal_status": "IN_REVIEW"},
                {"appeal_status": "SUBMITTED"},
                {"appeal_status": "IN_REVIEW"},
                {"review_draft_version": 1},
                {"decision_version_id": decision_id},
            )
        )
        active_assignments = mock.Mock(
            side_effect=(
                {"items": [active_assignment]},
                {"items": []},
                {"items": [active_assignment]},
                {"items": []},
            )
        )
        with mock.patch.multiple(
            self.module,
            _find_own_appeal_by_source=mock.Mock(
                side_effect=(None, discovered)
            ),
            _appeal_write_exact_replay=write,
            _get_own_appeal=mock.Mock(
                side_effect=(drafted, submitted, final)
            ),
            _appeal_queue=mock.Mock(
                side_effect=(
                    {"items": [queue_item]},
                    {"items": [released_item]},
                    {"items": []},
                )
            ),
            _appeal_active_assignments=active_assignments,
            _get_assigned_appeal=mock.Mock(
                side_effect=(
                    first_assignment,
                    second_assignment,
                    reviewed_assignment,
                )
            ),
            _appeal_terminal_history=mock.Mock(
                return_value={
                    "items": [
                        {
                            "appeal_id": appeal_id,
                            "decision_code": "VACATE_AND_REMAND",
                        }
                    ]
                }
            ),
            _get_terminal_appeal=mock.Mock(
                return_value={
                    "appeal_id": appeal_id,
                    "status": "DECIDED",
                    "entity_tag": final["entity_tag"],
                    "application": final["application"],
                    "decision": final["decision"],
                    "review_note_recorded": True,
                }
            ),
        ):
            summary = self.module._exercise_trust_appeal(
                owner=owner,
                reviewer=reviewer,
                trust_summary={
                    "report_status": "DECIDED",
                    "case_status": "DECIDED",
                    "appeal_eligibility_code": "ELIGIBLE",
                    "outcome_code": "PROTECTION_MODIFIED",
                    "outcome_version_id": outcome_id,
                    "case_id": case_id,
                },
            )

        self.assertEqual(summary["appeal_status"], "DECIDED")
        self.assertEqual(summary["write_kinds_verified"], 7)
        self.assertTrue(summary["assignment_release_replay_verified"])
        self.assertTrue(summary["reclaim_replay_verified"])
        self.assertTrue(summary["active_assignment_discovery_verified"])
        self.assertEqual(active_assignments.call_count, 4)
        events = [call.kwargs["expected_event_type"] for call in write.call_args_list]
        self.assertEqual(
            events,
            [
                "AppealOpened",
                "AppealApplicationDraftSaved",
                "AppealSubmitted",
                "AppealReviewClaimed",
                "AppealReviewAssignmentReleased",
                "AppealReviewClaimed",
                "AppealReviewDraftSaved",
                "AppealDecisionPublished",
            ],
        )
        release_call = write.call_args_list[4]
        self.assertEqual(release_call.kwargs["body"], {"reason_code": "WORKLOAD_RELEASE"})
        self.assertEqual(
            release_call.kwargs["if_match"], first_assignment["entity_tag"]
        )
        self.assertEqual(
            write.call_args_list[5].kwargs["if_match"],
            released_item["entity_tag"],
        )
        self.assertTrue(write.call_args_list[1].kwargs["sensitive_body"])
        self.assertTrue(write.call_args_list[6].kwargs["sensitive_body"])
        self.assertNotIn(
            "memory-only",
            json.dumps(summary, ensure_ascii=False).casefold(),
        )

    def test_reporter_safe_outcome_and_case_projection_reject_restricted_note(self) -> None:
        report_id = "11111111-1111-4111-8111-111111111111"
        case_id = "22222222-2222-4222-8222-222222222222"
        demand_id = "33333333-3333-4333-8333-333333333333"
        demand_version_id = "44444444-4444-4444-8444-444444444444"
        outcome_id = "55555555-5555-4555-8555-555555555555"
        packet_id = "66666666-6666-4666-8666-666666666666"
        outcome = {
            "action_codes": ["VERIFY_DEMAND"],
            "appeal_deadline": "2026-09-18T08:00:00+00:00",
            "appeal_eligibility_code": "ELIGIBLE",
            "content_sha256": "a" * 64,
            "decided_at": "2026-08-19T08:00:00+00:00",
            "evidence_packet_digest": "b" * 64,
            "evidence_packet_version_id": packet_id,
            "outcome_code": "PROTECTION_MODIFIED",
            "outcome_version_id": outcome_id,
            "policy_version": "trust-case-outcome-v1",
            "reason_codes": ["RISK_MITIGATED"],
            "redaction_profile_code": "PARTY_SAFE_V1",
            "source_digest": "c" * 64,
        }
        report_summary = {
            "category": "WORKFLOW_INTEGRITY",
            "evidence_reference_ids": [
                "77777777-7777-4777-8777-777777777777"
            ],
            "impact_codes": ["WORKFLOW_INTEGRITY_RISK"],
            "incident_ended_at": None,
            "incident_started_at": "2026-08-19T07:00:00+00:00",
            "requested_protection_codes": ["PAUSE_VERIFICATION"],
        }
        report = {
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "entity_tag": '"trust-8-aaaaaaaaaaaaaaaaaaaaaaaa"',
            "outcome": outcome,
            "report": report_summary,
            "report_id": report_id,
            "status": "DECIDED",
            "submitted_at": "2026-08-19T07:05:00+00:00",
        }
        parsed_report = self.module._trust_report_envelope(
            self.module.HttpResult(
                200,
                {"etag": report["entity_tag"]},
                json.dumps({"data": report}).encode("utf-8"),
            )
        )
        self.assertEqual(
            parsed_report["outcome"]["appeal_eligibility_code"], "ELIGIBLE"
        )
        self.assertIsNotNone(parsed_report["outcome"]["appeal_deadline"])

        triage_content = {
            "investigation_step_codes": ["CHECK_DEMAND_VERSION"],
            "issue_codes": ["WORKFLOW_INTEGRITY_GAP"],
            "jurisdiction_code": "PLATFORM_INTERNAL",
            "priority_code": "P1",
            "proposed_hold_actions": ["VERIFY_DEMAND"],
            "proposed_hold_ttl_minutes": 60,
            "sealed_note_reference": "sealed://trust/case/note-v2",
            "sealed_note_sha256": "d" * 64,
            "severity_code": "HIGH",
        }
        case = {
            "active_hold": None,
            "aggregate_version": 8,
            "case_id": case_id,
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "entity_tag": '"trust-8-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "outcome": outcome,
            "report": report_summary,
            "report_id": report_id,
            "status": "DECIDED",
            "triage_draft": {
                "content": triage_content,
                "content_sha256": "e" * 64,
                "saved_at": "2026-08-19T07:30:00+00:00",
                "triage_version": 2,
            },
        }
        parsed_case = self.module._trust_case_envelope(
            self.module.HttpResult(
                200,
                {"etag": case["entity_tag"]},
                json.dumps({"data": case}).encode("utf-8"),
            )
        )
        self.assertNotIn("restricted_note", parsed_case["triage_draft"]["content"])
        forged = json.loads(json.dumps(case))
        forged["triage_draft"]["content"]["restricted_note"] = "must-not-return"
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._trust_case_envelope(
                self.module.HttpResult(
                    200,
                    {"etag": case["entity_tag"]},
                    json.dumps({"data": forged}).encode("utf-8"),
                )
            )

    def test_triage_projection_requires_canonical_closed_array_order(self) -> None:
        request = {
            "investigation_step_codes": [
                "CHECK_POLICY_REQUIREMENTS",
                "CHECK_DEMAND_VERSION",
            ],
            "issue_codes": [
                "WORKFLOW_INTEGRITY_GAP",
                "SCOPE_DISCLOSURE_RISK",
            ],
            "jurisdiction_code": "PLATFORM_INTERNAL",
            "priority_code": "P0",
            "proposed_hold_actions": ["VERIFY_DEMAND", "SUBMIT_DEMAND"],
            "proposed_hold_ttl_minutes": 60,
            "severity_code": "CRITICAL",
        }
        canonical_content = {
            **request,
            "investigation_step_codes": sorted(
                request["investigation_step_codes"]
            ),
            "issue_codes": sorted(request["issue_codes"]),
            "proposed_hold_actions": sorted(
                request["proposed_hold_actions"]
            ),
        }
        case = {
            "triage_draft": {
                "content": canonical_content,
                "triage_version": 2,
            }
        }

        self.module._require_triage_projection(
            case,
            request=request,
            expected_version=2,
        )

        noncanonical = json.loads(json.dumps(case))
        noncanonical["triage_draft"]["content"]["issue_codes"] = request[
            "issue_codes"
        ]
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_triage_projection(
                noncanonical,
                request=request,
                expected_version=2,
            )

    def test_triage_publish_keeps_draft_and_published_versions_independent(
        self,
    ) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        report_id = "22222222-2222-4222-8222-222222222222"
        demand_id = "33333333-3333-4333-8333-333333333333"
        demand_version_id = "44444444-4444-4444-8444-444444444444"
        report_context = {
            "case_id": case_id,
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "report_id": report_id,
            "report_etag": '"trust-1-aaaaaaaaaaaaaaaaaaaaaaaa"',
        }
        queue_item = {
            "case_id": case_id,
            "category": "WORKFLOW_INTEGRITY",
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "entity_tag": '"trust-1-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "impact_codes": ["PARTICIPANT_SAFETY_RISK"],
            "report_id": report_id,
        }

        def projected(version: int, *, status: str = "TRIAGING"):
            return {
                "entity_tag": f'"trust-{version + 2}-cccccccccccccccccccccccc"',
                "status": status,
                "triage_draft": {
                    "content": {"priority_code": f"P{2 - version}"},
                    "content_sha256": str(version) * 64,
                    "triage_version": version,
                },
            }

        current = {
            "entity_tag": '"trust-2-dddddddddddddddddddddddd"',
            "status": "TRIAGING",
            "triage_draft": None,
        }
        first = projected(1)
        second = projected(2)
        reviewed = projected(2, status="IN_REVIEW")
        writes = mock.Mock(
            side_effect=(
                {
                    "aggregate_version": 2,
                    "case_id": case_id,
                    "case_status": "TRIAGING",
                },
                {"triage_draft_version": 1},
                {"triage_draft_version": 2},
                {
                    "case_status": "IN_REVIEW",
                    "triage_draft_version": None,
                    "triage_version": 1,
                },
            )
        )
        officer = self.module.RoleSession(
            account_code="trust_officer_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        with mock.patch.multiple(
            self.module,
            _trust_case_queue=mock.Mock(return_value={"items": [queue_item]}),
            _trust_active_assignments=mock.Mock(
                return_value={
                    "items": [
                        {
                            "case_id": case_id,
                            "assignment_purpose": "CASE_TRIAGE",
                            "assignment_expires_at": (
                                "2026-08-19T12:00:00Z"
                            ),
                            "hold_id": None,
                        }
                    ]
                }
            ),
            _trust_write_exact_replay=writes,
            _get_trust_case=mock.Mock(
                side_effect=(current, first, second, reviewed)
            ),
            _require_trust_case_identity=mock.Mock(),
            _require_triage_projection=mock.Mock(),
        ):
            result = self.module._review_trust_case(
                officer=officer,
                report_context=report_context,
            )

        publish_call = writes.call_args_list[3]
        self.assertEqual(
            publish_call.kwargs["body"], {"expected_draft_version": 2}
        )
        self.assertEqual(result["triage_draft_versions"], [1, 2])
        self.assertEqual(result["case"]["status"], "IN_REVIEW")

    def test_trust_hold_release_assignment_is_discovered_then_disappears(
        self,
    ) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        hold_id = "22222222-2222-4222-8222-222222222222"
        other_hold_id = "77777777-7777-4777-8777-777777777777"
        demand_id = "33333333-3333-4333-8333-333333333333"
        version_id = "44444444-4444-4444-8444-444444444444"
        queue_item = {
            "case_id": case_id,
            "hold_id": hold_id,
            "demand_id": demand_id,
            "demand_version_id": version_id,
            "action_codes": ["VERIFY_DEMAND"],
            "reason_code": "PARTICIPANT_SAFETY_RISK",
            "entity_tag": '"trust-4-aaaaaaaaaaaaaaaaaaaaaaaa"',
        }
        assigned_hold = {
            "action_codes": ["VERIFY_DEMAND"],
            "assignment_expires_at": "2026-08-19T12:30:00Z",
            "case_id": case_id,
            "case_status": "IN_REVIEW",
            "effective_at": "2026-08-19T11:00:00Z",
            "entity_tag": '"trust-6-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "expires_at": "2026-08-19T13:00:00Z",
            "hold_id": hold_id,
            "hold_status": "ACTIVE",
            "reason_code": "PARTICIPANT_SAFETY_RISK",
        }
        released_case = {"active_hold": None}
        active_assignment = {
            "case_id": case_id,
            "assignment_purpose": "HOLD_RELEASE",
            "assignment_expires_at": "2026-08-19T12:00:00Z",
            "hold_id": hold_id,
        }
        other_active_assignment = {
            **active_assignment,
            "hold_id": other_hold_id,
        }

        def officer(code):
            return self.module.RoleSession(
                account_code=code,
                workspace_id=(
                    "platform:55555555-5555-4555-8555-555555555555"
                ),
                workspace_kind="PLATFORM",
                role_codes=("TRUST_OFFICER",),
                csrf_token="x" * 32,
                client=object(),
                policy_accepted=False,
            )

        releasing_officer = officer("trust_officer_02")
        deciding_officer = officer("trust_officer_01")
        assignments = mock.Mock(
            side_effect=(
                {
                    "items": [
                        active_assignment,
                        other_active_assignment,
                    ]
                },
                {"items": [other_active_assignment]},
            )
        )
        assigned_hold_read = mock.Mock(return_value=assigned_hold)
        case_read = mock.Mock(return_value=released_case)
        writes = mock.Mock(
            side_effect=(
                {"case_id": case_id, "hold_id": hold_id},
                {
                    "case_id": case_id,
                    "hold_id": hold_id,
                    "hold_version": 3,
                },
            )
        )
        with mock.patch.multiple(
            self.module,
            _trust_hold_release_queue=mock.Mock(
                side_effect=({"items": [queue_item]}, {"items": []})
            ),
            _trust_active_assignments=assignments,
            _trust_write_exact_replay=writes,
            _get_assigned_trust_hold=assigned_hold_read,
            _get_trust_case=case_read,
            _require_trust_case_identity=mock.Mock(),
            _verify_demand_after_hold_release=mock.Mock(
                return_value={"status": "VERIFIED"}
            ),
        ):
            released, verified = self.module._release_trust_hold_and_verify(
                releasing_officer=releasing_officer,
                deciding_officer=deciding_officer,
                reviewer=self.module.RoleSession(
                    account_code="operations_reviewer_01",
                    workspace_id=(
                        "platform:66666666-6666-4666-8666-666666666666"
                    ),
                    workspace_kind="PLATFORM",
                    role_codes=("OPERATIONS_REVIEWER",),
                    csrf_token="x" * 32,
                    client=object(),
                    policy_accepted=False,
                ),
                hold_context={
                    "case_id": case_id,
                    "hold_id": hold_id,
                    "demand_id": demand_id,
                    "demand_version_id": version_id,
                    "blocked_demand": {"status": "SUBMITTED"},
                    "blocked_idempotency_key": "x" * 16,
                },
            )

        self.assertTrue(released["hold_released"])
        self.assertTrue(released["assigned_hold_read_verified"])
        self.assertEqual(verified["status"], "VERIFIED")
        self.assertEqual(assignments.call_count, 2)
        assigned_hold_read.assert_called_once_with(
            releasing_officer, hold_id=hold_id
        )
        case_read.assert_called_once_with(deciding_officer, case_id=case_id)
        self.assertEqual(
            writes.call_args_list[1].kwargs["if_match"],
            assigned_hold["entity_tag"],
        )

    def test_trust_terminal_decision_removes_case_triage_assignment(self) -> None:
        case_id = "11111111-1111-4111-8111-111111111111"
        report_id = "22222222-2222-4222-8222-222222222222"
        hold_id = "33333333-3333-4333-8333-333333333333"
        outcome_id = "44444444-4444-4444-8444-444444444444"
        demand_id = "55555555-5555-4555-8555-555555555555"
        version_id = "66666666-6666-4666-8666-666666666666"
        officer = self.module.RoleSession(
            account_code="trust_officer_01",
            workspace_id="platform:77777777-7777-4777-8777-777777777777",
            workspace_kind="PLATFORM",
            role_codes=("TRUST_OFFICER",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        owner = self.module.RoleSession(
            account_code="demand_owner_01",
            workspace_id="org:88888888-8888-4888-8888-888888888888",
            workspace_kind="ORGANIZATION",
            role_codes=("DEMAND_OWNER",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        decided_case = {
            "entity_tag": '"trust-8-aaaaaaaaaaaaaaaaaaaaaaaa"',
            "status": "DECIDED",
            "active_hold": None,
            "outcome": {"safe": True},
        }
        owner_report = {
            "entity_tag": '"trust-8-bbbbbbbbbbbbbbbbbbbbbbbb"',
            "status": "DECIDED",
            "demand_id": demand_id,
            "demand_version_id": version_id,
            "outcome": {"safe": True},
        }
        assignments = mock.Mock(return_value={"items": []})
        with mock.patch.multiple(
            self.module,
            _trust_write_exact_replay=mock.Mock(
                return_value={
                    "case_id": case_id,
                    "case_status": "DECIDED",
                    "outcome_version_id": outcome_id,
                }
            ),
            _get_trust_case=mock.Mock(return_value=decided_case),
            _get_trust_report=mock.Mock(return_value=owner_report),
            _trust_active_assignments=assignments,
            _require_trust_case_identity=mock.Mock(),
            _require_eligible_outcome=mock.Mock(),
        ):
            summary = self.module._publish_trust_outcome(
                owner=owner,
                officer=officer,
                released_context={
                    "case_id": case_id,
                    "report_id": report_id,
                    "hold_id": hold_id,
                    "demand_id": demand_id,
                    "demand_version_id": version_id,
                    "case": {"active_hold": None, "entity_tag": '"trust-7-cccccccccccccccccccccccc"'},
                    "hold_released": True,
                    "triage_draft_versions": [1, 2],
                    "triage_configuration_changed": True,
                    "blocked_verification": {"http_status": 403},
                    "assigned_hold_read_verified": True,
                },
            )

        self.assertEqual(summary["case_status"], "DECIDED")
        self.assertTrue(summary["active_assignment_absent"])
        self.assertTrue(summary["assigned_hold_read_verified"])
        assignments.assert_called_once_with(officer)

    def test_high_risk_hold_blocks_verify_without_public_demand_mutation(self) -> None:
        demand_id = "11111111-1111-4111-8111-111111111111"
        version_id = "22222222-2222-4222-8222-222222222222"
        assignment_id = "33333333-3333-4333-8333-333333333333"
        etag = '"demand-6-aaaaaaaaaaaaaaaaaaaaaaaa"'
        demand = {
            "resource_type": "DEMAND",
            "object_id": demand_id,
            "status": "SUBMITTED",
            "revision": 6,
            "etag": etag,
            "capabilities": [],
            "editable_paths": [],
            "current_version": {"version_id": version_id},
            "versions": [],
            "submissions": [],
            "findings": [],
            "review_assignment": {"assignment_id": assignment_id},
        }

        class Client:
            def __init__(self):
                self.calls = []
                self.responses = [
                    self_module.HttpResult(
                        200,
                        {"etag": etag},
                        json.dumps({"data": demand}).encode("utf-8"),
                    ),
                    self_module.HttpResult(
                        403,
                        {},
                        json.dumps(
                            {
                                "error": {"code": "SAFETY_HOLD_BLOCKED"},
                            }
                        ).encode("utf-8"),
                    ),
                    self_module.HttpResult(
                        200,
                        {"etag": etag},
                        json.dumps({"data": demand}).encode("utf-8"),
                    ),
                ]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self.responses.pop(0)

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="operations_reviewer_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("OPERATIONS_REVIEWER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )
        observed, idempotency_key = self.module._blocked_verify_under_trust_hold(
            session,
            reviewable_demand=demand,
        )
        self.assertEqual(observed, demand)
        self.assertTrue(idempotency_key.startswith("internal-sandbox-e2e-"))
        self.assertEqual([call["method"] for call in client.calls], ["GET", "POST", "GET"])
        verify_call = client.calls[1]
        self.assertEqual(verify_call["headers"]["If-Match"], etag)
        self.assertEqual(
            verify_call["headers"]["Idempotency-Key"], idempotency_key
        )
        self.assertTrue(
            all(
                token not in call["path"]
                for call in client.calls
                for token in ("audit", "outbox", "receipt")
            )
        )

    def test_released_hold_reuses_blocked_key_then_exactly_replays_success(self) -> None:
        demand_id = "11111111-1111-4111-8111-111111111111"
        version_id = "22222222-2222-4222-8222-222222222222"
        assignment_id = "33333333-3333-4333-8333-333333333333"
        finding_id = "44444444-4444-4444-8444-444444444444"
        before_etag = '"demand-6-aaaaaaaaaaaaaaaaaaaaaaaa"'
        after_etag = '"demand-7-bbbbbbbbbbbbbbbbbbbbbbbb"'
        blocked_key = "internal-sandbox-e2e-blocked-key-recovery"
        before = {
            "resource_type": "DEMAND",
            "object_id": demand_id,
            "status": "SUBMITTED",
            "revision": 6,
            "etag": before_etag,
            "capabilities": [],
            "editable_paths": [],
            "current_version": {"version_id": version_id},
            "versions": [],
            "submissions": [],
            "findings": [],
            "review_assignment": {"assignment_id": assignment_id},
        }
        verified = {
            **before,
            "status": "VERIFIED",
            "revision": 7,
            "etag": after_etag,
            "findings": [
                {
                    "finding_id": finding_id,
                    "version_id": version_id,
                    "assignment_id": assignment_id,
                    "result": "VERIFIED",
                    "reason_codes": [],
                    "required_field_paths": [],
                    "reviewed_at": "2026-08-19T08:00:00Z",
                }
            ],
        }

        class Client:
            def __init__(self):
                self.calls = []
                self.responses = [
                    self_module.HttpResult(
                        200,
                        {"etag": before_etag},
                        json.dumps({"data": before}).encode("utf-8"),
                    ),
                    self_module.HttpResult(
                        200,
                        {"etag": after_etag},
                        json.dumps({"data": verified}).encode("utf-8"),
                    ),
                    self_module.HttpResult(
                        200,
                        {"etag": after_etag},
                        json.dumps({"data": verified}).encode("utf-8"),
                    ),
                ]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self.responses.pop(0)

        self_module = self.module
        client = Client()
        session = self.module.RoleSession(
            account_code="operations_reviewer_01",
            workspace_id="platform:55555555-5555-4555-8555-555555555555",
            workspace_kind="PLATFORM",
            role_codes=("OPERATIONS_REVIEWER",),
            csrf_token="x" * 32,
            client=client,
            policy_accepted=False,
        )

        result = self.module._verify_demand_after_hold_release(
            session,
            blocked_demand=before,
            blocked_idempotency_key=blocked_key,
        )

        self.assertEqual(result, verified)
        self.assertEqual(
            [call["method"] for call in client.calls], ["GET", "POST", "POST"]
        )
        first, replay = client.calls[1:]
        self.assertEqual(first["headers"]["Idempotency-Key"], blocked_key)
        self.assertEqual(replay["headers"]["Idempotency-Key"], blocked_key)
        self.assertEqual(first["headers"]["If-Match"], before_etag)
        self.assertEqual(replay["headers"]["If-Match"], before_etag)
        self.assertEqual(first["body"], replay["body"])

    def test_active_creator_second_authority_preserves_canonical_me_and_user_etag(
        self,
    ) -> None:
        organization_id, before, accepted = (
            _active_creator_second_authority_fixture()
        )
        required_policy_bundle_id = accepted["policy_requirements"][1][
            "required_policy_bundle_id"
        ]
        self.module._require_active_creator_second_authority_transition(
            before=before,
            accepted=accepted,
            refreshed=_json_copy(accepted),
            organization_id=organization_id,
            required_policy_bundle_id=required_policy_bundle_id,
        )

        corruptions = {}
        dropped_role = _json_copy(accepted)
        dropped_role["user_roles"] = []
        corruptions["old-role-dropped"] = (dropped_role, _json_copy(dropped_role))

        dropped_requirement = _json_copy(accepted)
        dropped_requirement["policy_requirements"] = [
            dropped_requirement["policy_requirements"][1]
        ]
        corruptions["old-requirement-dropped"] = (
            dropped_requirement,
            _json_copy(dropped_requirement),
        )

        skipped_version = _json_copy(accepted)
        skipped_version["aggregate_version"] = 9
        skipped_version["entity_tag"] = '"v9"'
        corruptions["user-version-skipped"] = (
            skipped_version,
            _json_copy(skipped_version),
        )

        wrong_scope = _json_copy(accepted)
        wrong_scope["policy_requirements"][1]["scope_id"] = (
            "66666666-6666-4666-8666-666666666666"
        )
        corruptions["new-requirement-wrong-scope"] = (
            wrong_scope,
            _json_copy(wrong_scope),
        )

        wrong_bundle = _json_copy(accepted)
        wrong_bundle["policy_requirements"][1][
            "required_policy_bundle_id"
        ] = "77777777-7777-4777-8777-777777777777"
        corruptions["new-requirement-wrong-bundle"] = (
            wrong_bundle,
            _json_copy(wrong_bundle),
        )

        refreshed_drift = _json_copy(accepted)
        refreshed_drift["policy_requirements"].reverse()
        corruptions["refreshed-me-drift"] = (accepted, refreshed_drift)

        for name, (accept_body, refreshed_body) in corruptions.items():
            with self.subTest(name=name):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._require_active_creator_second_authority_transition(
                        before=before,
                        accepted=accept_body,
                        refreshed=refreshed_body,
                        organization_id=organization_id,
                        required_policy_bundle_id=required_policy_bundle_id,
                    )

    def test_active_me_read_requires_body_user_etag_in_response_header(self) -> None:
        _organization_id, before, _accepted = (
            _active_creator_second_authority_fixture()
        )

        class Client:
            def __init__(self, etag):
                self.etag = etag
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self_module.HttpResult(
                    200,
                    {"etag": self.etag},
                    json.dumps(before).encode("utf-8"),
                )

        self_module = self.module
        valid = Client('"v7"')
        self.assertEqual(
            self.module._read_active_me_with_etag(valid),
            before,
        )
        self.assertEqual(
            valid.calls,
            [
                {
                    "method": "GET",
                    "path": "/v1/me",
                    "headers": {"Accept": "application/json"},
                }
            ],
        )
        for etag in (None, '"v6"', 'W/"v7"'):
            with self.subTest(etag=etag):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._read_active_me_with_etag(Client(etag))

    def test_accept_http_etag_remains_invitation_etag_not_user_etag(self) -> None:
        organization_id, _before, accepted_me = (
            _active_creator_second_authority_fixture()
        )
        invitation_id = "66666666-6666-4666-8666-666666666666"
        preview = {
            "invitation_id": invitation_id,
            "required_policy_bundle_id": (
                accepted_me["policy_requirements"][1][
                    "required_policy_bundle_id"
                ]
            ),
            "entity_tag": '"v1"',
        }
        accepted_invitation = {
            "invitation_id": invitation_id,
            "organization_id": organization_id,
            "target_role": "DEMAND_OWNER",
            "status": "ACCEPTED",
            "entity_tag": '"v2"',
        }
        acceptance = {
            "invitation": accepted_invitation,
            "me": accepted_me,
            "activated_scope": "ORGANIZATION_MEMBERSHIP",
        }

        class Client:
            def __init__(self, response_etag):
                self.responses = [
                    self_module.HttpResult(
                        200,
                        {"etag": response_etag},
                        json.dumps(acceptance).encode("utf-8"),
                    ),
                    self_module.HttpResult(
                        200,
                        {},
                        json.dumps(
                            {
                                "session": {"status": "ACTIVE"},
                                "user_status": "ACTIVE",
                                "csrf_token": "y" * 32,
                            }
                        ).encode("utf-8"),
                    ),
                ]

            def request(self, **_kwargs):
                return self.responses.pop(0)

        self_module = self.module
        session = self.module.RoleSession(
            account_code="creator_01",
            workspace_id="personal:77777777-7777-4777-8777-777777777777",
            workspace_kind="PERSONAL",
            role_codes=("CREATOR",),
            csrf_token="x" * 32,
            client=Client('"v2"'),
            policy_accepted=True,
        )
        with mock.patch.multiple(
            self.module,
            _invitation_preview=mock.Mock(return_value=preview),
            _invitation_policy_acceptances=mock.Mock(return_value=[{"safe": True}]),
            _invitation_admin=mock.Mock(return_value=accepted_invitation),
        ):
            refreshed, observed = self.module._accept_organization_invitation(
                session,
                preview=preview,
            )
        self.assertEqual(observed, acceptance)
        self.assertEqual(refreshed.csrf_token, "y" * 32)

        rejected_session = self.module.RoleSession(
            **{**session.__dict__, "client": Client(accepted_me["entity_tag"])}
        )
        with mock.patch.multiple(
            self.module,
            _invitation_preview=mock.Mock(return_value=preview),
            _invitation_policy_acceptances=mock.Mock(return_value=[{"safe": True}]),
            _invitation_admin=mock.Mock(return_value=accepted_invitation),
        ):
            with self.assertRaises(
                self.module.InternalSandboxE2eError
            ) as raised:
                self.module._accept_organization_invitation(
                    rejected_session,
                    preview=preview,
                )
        self.assertEqual(
            raised.exception.stage,
            "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        )

    def test_org_admin_issue_and_membership_commands_require_exact_receipt_replay(self) -> None:
        organization_id = "11111111-1111-4111-8111-111111111111"
        invitation_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        membership_id = "44444444-4444-4444-8444-444444444444"
        user_id = "55555555-5555-4555-8555-555555555555"
        token = "t" * 96
        organization = {
            "organization_id": organization_id,
            "public_name": "INTERNAL_SANDBOX 合成组织",
            "type": "CREATOR_TEAM",
            "status": "ACTIVE",
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        invitation = {
            "invitation_id": invitation_id,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "organization_id": organization_id,
            "target_role": "DEMAND_OWNER",
            "masked_recipient_label": "s***@example.test",
            "is_initial_admin": False,
            "status": "ISSUED",
            "expires_at": "2026-08-23T08:00:00+00:00",
            "created_at": "2026-08-16T08:00:00+00:00",
            "required_policy_bundle_id": bundle_id,
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        issued = {
            "invitation": invitation,
            "access_invitation_token": token,
            "join_fragment_url": f"/join#access_invitation_token={token}",
        }

        class Client:
            def __init__(self, responses):
                self.responses = list(responses)
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self.responses.pop(0)

        def response(value, etag):
            return self.module.HttpResult(
                201 if "access_invitation_token" in value else 200,
                {"etag": etag},
                json.dumps(value).encode("utf-8"),
            )

        issue_client = Client([
            response(issued, '"v1"'),
            response(issued, '"v1"'),
        ])
        session = self.module.RoleSession(
            account_code="org_admin_01",
            workspace_id=f"org:{organization_id}",
            workspace_kind="ORGANIZATION",
            role_codes=("ORG_ADMIN",),
            csrf_token="x" * 32,
            client=issue_client,
            policy_accepted=False,
        )
        result = self.module._issue_organization_invitation_exact_replay(
            session,
            organization=organization,
            recipient_email="sandbox-creator-01@example.test",
            target_role="DEMAND_OWNER",
        )
        self.assertEqual(result, issued)
        self.assertEqual(issue_client.calls[0]["headers"], issue_client.calls[1]["headers"])
        self.assertEqual(issue_client.calls[0]["body"], issue_client.calls[1]["body"])
        self.assertNotIn("X-Workspace-Id", issue_client.calls[0]["headers"])

        renamed_organization = {
            **organization,
            "public_name": self.module.UPDATED_ORGANIZATION_PUBLIC_NAME,
            "aggregate_version": 2,
            "entity_tag": '"v2"',
        }
        rename_client = Client([
            response(renamed_organization, '"v2"'),
            response(renamed_organization, '"v2"'),
        ])
        rename_session = self.module.RoleSession(
            **{**session.__dict__, "client": rename_client}
        )
        self.assertEqual(
            self.module._update_organization_public_name_exact_replay(
                rename_session,
                organization=organization,
                public_name=self.module.UPDATED_ORGANIZATION_PUBLIC_NAME,
            ),
            renamed_organization,
        )
        self.assertEqual(
            rename_client.calls[0]["headers"],
            rename_client.calls[1]["headers"],
        )
        self.assertEqual(
            rename_client.calls[0]["body"],
            {
                "public_name": self.module.UPDATED_ORGANIZATION_PUBLIC_NAME,
                "reason_code": "PUBLIC_NAME_CORRECTION",
            },
        )
        self.assertEqual(
            rename_client.calls[0]["path"],
            f"/v1/organizations/{organization_id}/public-name",
        )

        membership = {
            "membership_id": membership_id,
            "organization_id": organization_id,
            "user_id": user_id,
            "display_handle": "creator_01",
            "status": "ACTIVE",
            "roles": ["DEMAND_OWNER"],
            "aggregate_version": 1,
            "entity_tag": '"v1"',
        }
        suspended = {
            **membership,
            "status": "SUSPENDED",
            "aggregate_version": 2,
            "entity_tag": '"v2"',
        }
        lifecycle_client = Client([
            response(suspended, '"v2"'),
            response(suspended, '"v2"'),
        ])
        lifecycle_session = self.module.RoleSession(
            **{**session.__dict__, "client": lifecycle_client}
        )
        self.assertEqual(
            self.module._organization_lifecycle_exact_replay(
                lifecycle_session,
                resource=membership,
                action="suspend",
                reason_code="SECURITY_REVIEW",
            ),
            suspended,
        )
        self.assertEqual(
            lifecycle_client.calls[0]["headers"],
            lifecycle_client.calls[1]["headers"],
        )

        altered = {**issued, "access_invitation_token": "u" * 96}
        altered["join_fragment_url"] = (
            "/join#access_invitation_token=" + altered["access_invitation_token"]
        )
        bad_client = Client([
            response(issued, '"v1"'),
            response(altered, '"v1"'),
        ])
        bad_session = self.module.RoleSession(
            **{**session.__dict__, "client": bad_client}
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._issue_organization_invitation_exact_replay(
                bad_session,
                organization=organization,
                recipient_email="sandbox-creator-01@example.test",
                target_role="DEMAND_OWNER",
            )

    def test_policy_bundle_and_org_pagination_match_the_closed_web_contract(self) -> None:
        bundle_id = "11111111-1111-4111-8111-111111111111"
        document_id = "22222222-2222-4222-8222-222222222222"
        consent_document_id = "33333333-3333-4333-8333-333333333333"
        consent_offer_id = "44444444-4444-4444-8444-444444444444"
        body = "INTERNAL_SANDBOX 合成组织条款"
        digest = self.module.hashlib.sha256(body.encode("utf-8")).hexdigest()
        consent_body = "INTERNAL_SANDBOX 可选研究同意文本"
        consent_digest = self.module.hashlib.sha256(
            consent_body.encode("utf-8")
        ).hexdigest()
        bundle = {
            "policy_bundle_id": bundle_id,
            "purpose": "ORGANIZATION_MEMBERSHIP",
            "jurisdiction": "CN",
            "locale": "zh-CN",
            "documents": [
                {
                    "document_id": document_id,
                    "kind": "TERMS",
                    "semantic_version": "1.0.0",
                    "locale": "zh-CN",
                    "content_sha256": digest,
                    "legal_effect": "CONTRACT_ACCEPTANCE",
                    "body": body,
                },
                {
                    "document_id": consent_document_id,
                    "kind": "CONSENT_TEXT",
                    "semantic_version": "1.0.0",
                    "locale": "zh-CN",
                    "content_sha256": consent_digest,
                    "legal_effect": "CONSENT_TEXT",
                    "body": consent_body,
                },
            ],
            "consent_offers": [
                {
                    "consent_offer_id": consent_offer_id,
                    "purpose": "PILOT_RESEARCH",
                    "scope_type": "PLATFORM_PARTICIPATION",
                    "data_categories": ["PROFILE", "RESEARCH"],
                    "document_id": consent_document_id,
                    "content_sha256": consent_digest,
                    "recipient_label": "INTERNAL_SANDBOX research",
                    "expiry_rule": (
                        "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER"
                    ),
                    "not_after": "2027-08-16T08:00:00+00:00",
                    "canonical_offer_sha256": "f" * 64,
                    "optional": True,
                }
            ],
            "effective_at": "2026-08-16T08:00:00+00:00",
            "entity_tag": '"v1"',
        }
        response = self.module.HttpResult(
            200,
            {"etag": '"v1"'},
            json.dumps(bundle, ensure_ascii=False).encode("utf-8"),
        )
        self.assertEqual(
            self.module._policy_bundle(
                response,
                expected_id=bundle_id,
                expected_purpose="ORGANIZATION_MEMBERSHIP",
            ),
            bundle,
        )
        forged = {
            **bundle,
            "documents": [
                bundle["documents"][0],
                {
                    **bundle["documents"][1],
                    "body": consent_body + "篡改",
                },
            ],
        }
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._policy_bundle(
                self.module.HttpResult(
                    200,
                    {"etag": '"v1"'},
                    json.dumps(forged, ensure_ascii=False).encode("utf-8"),
                ),
                expected_id=bundle_id,
                expected_purpose="ORGANIZATION_MEMBERSHIP",
            )

        forged_offer = {
            **bundle,
            "consent_offers": [
                {**bundle["consent_offers"][0], "content_sha256": digest}
            ],
        }
        for bad_response in (
            self.module.HttpResult(
                200,
                {"etag": '"v2"'},
                json.dumps(bundle, ensure_ascii=False).encode("utf-8"),
            ),
            self.module.HttpResult(
                200,
                {"etag": '"v1"'},
                json.dumps(forged_offer, ensure_ascii=False).encode("utf-8"),
            ),
        ):
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._policy_bundle(
                    bad_response,
                    expected_id=bundle_id,
                    expected_purpose="ORGANIZATION_MEMBERSHIP",
                )

        cursor = "c" * 64 + "." + "s" * 43

        class PageClient:
            def __init__(self):
                self.calls = []
                self.pages = [
                    {"items": [{"id": "first"}], "page": {"next_cursor": cursor}},
                    {"items": [{"id": "second"}], "page": {"next_cursor": None}},
                ]

            def request(self, **kwargs):
                self.calls.append(kwargs)
                return self_module.HttpResult(
                    200,
                    {},
                    json.dumps(self.pages.pop(0)).encode("utf-8"),
                )

        self_module = self.module
        page_client = PageClient()
        session = self.module.RoleSession(
            account_code="org_admin_01",
            workspace_id="org:33333333-3333-4333-8333-333333333333",
            workspace_kind="ORGANIZATION",
            role_codes=("ORG_ADMIN",),
            csrf_token="x" * 32,
            client=page_client,
            policy_accepted=False,
        )
        self.assertEqual(
            self.module._organization_page(
                session,
                path="/v1/organizations/33333333-3333-4333-8333-333333333333/memberships",
                parser=lambda item: item,
                identity_field="id",
            ),
            [{"id": "first"}, {"id": "second"}],
        )
        self.assertEqual(page_client.calls[0]["query"], {"limit": "100"})
        self.assertEqual(
            page_client.calls[1]["query"],
            {"limit": "100", "cursor": cursor},
        )

    def test_policy_acceptance_stops_on_mismatched_bundle_etag_before_write(self) -> None:
        bundle_id = "11111111-1111-4111-8111-111111111111"
        document_id = "22222222-2222-4222-8222-222222222222"
        body = "INTERNAL_SANDBOX creator terms"
        bundle = {
            "policy_bundle_id": bundle_id,
            "purpose": "CREATOR_ENROLLMENT",
            "jurisdiction": "CN",
            "locale": "zh-CN",
            "documents": [
                {
                    "document_id": document_id,
                    "kind": "TERMS",
                    "semantic_version": "1.0.0",
                    "locale": "zh-CN",
                    "content_sha256": self.module.hashlib.sha256(
                        body.encode("utf-8")
                    ).hexdigest(),
                    "legal_effect": "CONTRACT_ACCEPTANCE",
                    "body": body,
                }
            ],
            "consent_offers": [],
            "effective_at": "2026-08-16T08:00:00+00:00",
            "entity_tag": '"v1"',
        }

        class Client:
            def __init__(self):
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                if len(self.calls) != 1:
                    raise AssertionError("policy acceptance write must not run")
                return self_module.HttpResult(
                    200,
                    {"etag": '"v2"'},
                    json.dumps(bundle).encode("utf-8"),
                )

        self_module = self.module
        client = Client()
        initial_me = {
            "entity_tag": '"v1"',
            "policy_requirements": [
                {
                    "selector_digest": "a" * 64,
                    "purpose": "CREATOR_ENROLLMENT",
                    "role": "CREATOR",
                    "scope_type": "USER_ROLE",
                    "scope_id": None,
                    "satisfied": False,
                    "required_policy_bundle_id": bundle_id,
                    "missing_document_ids": [document_id],
                }
            ],
        }
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._accept_missing_policies(
                client,
                {"csrf_token": "x" * 32},
                initial_me,
            )
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(
            client.calls[0],
            {
                "method": "GET",
                "path": f"/v1/policy-bundles/{bundle_id}",
                "headers": {"Accept": "application/json"},
            },
        )

    def test_pagination_rejects_duplicate_items_and_non_single_dot_cursors(self) -> None:
        self_module = self.module

        class PageClient:
            def __init__(self, pages):
                self.pages = list(pages)

            def request(self, **_kwargs):
                return self_module.HttpResult(
                    200,
                    {},
                    json.dumps(self.pages.pop(0)).encode("utf-8"),
                )

        def session(pages):
            return self.module.RoleSession(
                account_code="org_admin_01",
                workspace_id="org:11111111-1111-4111-8111-111111111111",
                workspace_kind="ORGANIZATION",
                role_codes=("ORG_ADMIN",),
                csrf_token="x" * 32,
                client=PageClient(pages),
                policy_accepted=False,
            )

        cursor = "c" * 64 + "." + "s" * 43
        duplicate_pages = (
            {"items": [{"id": "same"}], "page": {"next_cursor": cursor}},
            {"items": [{"id": "same"}], "page": {"next_cursor": None}},
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._organization_page(
                session(duplicate_pages),
                path="/v1/organizations/11111111-1111-4111-8111-111111111111/memberships",
                parser=lambda item: item,
                identity_field="id",
            )

        jwt_shaped = "a" * 64 + "." + "b" * 43 + "." + "c" * 43
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._organization_page(
                session(
                    ({"items": [], "page": {"next_cursor": jwt_shaped}},)
                ),
                path="/v1/organizations/11111111-1111-4111-8111-111111111111/memberships",
                parser=lambda item: item,
                identity_field="id",
            )

    def test_role_lists_are_closed_unique_and_order_independent(self) -> None:
        workspace_id = "platform:11111111-1111-4111-8111-111111111111"

        class Client:
            def __init__(self, roles):
                self.roles = roles

            def request(self, **_kwargs):
                return self_module.HttpResult(
                    200,
                    {},
                    json.dumps(
                        {
                            "data": {
                                "workspaces": [
                                    {
                                        "workspace_id": workspace_id,
                                        "workspace_kind": "PLATFORM",
                                        "role_codes": self.roles,
                                    }
                                ],
                                "selection_required": False,
                            }
                        }
                    ).encode("utf-8"),
                )

        self_module = self.module
        candidates, selection_required = self.module._workspace_candidates(
            Client(["TRUST_OFFICER", "ACCESS_ADMIN"])
        )
        self.assertFalse(selection_required)
        self.assertEqual(
            candidates[0]["role_codes"],
            ["TRUST_OFFICER", "ACCESS_ADMIN"],
        )
        for roles in (["ROOT"], ["TRUST_OFFICER", "TRUST_OFFICER"]):
            with self.subTest(roles=roles):
                with self.assertRaises(self.module.InternalSandboxE2eError):
                    self.module._workspace_candidates(Client(roles))

        admin = self.module.RoleSession(
            account_code="access_admin_01",
            workspace_id=workspace_id,
            workspace_kind="PLATFORM",
            role_codes=("ACCESS_ADMIN",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        target_workspace_id = "platform:22222222-2222-4222-8222-222222222222"
        events = []

        class TargetClient:
            def __init__(self):
                self.role_sets = [
                    ["FINANCE_OPERATOR", "TRUST_OFFICER"],
                    ["FINANCE_OPERATOR"],
                ]
                self.calls = []

            def request(self, **kwargs):
                self.calls.append(kwargs)
                roles = self.role_sets.pop(0)
                events.append(f"workspace:{'+'.join(roles)}")
                return self_module.HttpResult(
                    200,
                    {},
                    json.dumps(
                        {
                            "data": {
                                "workspaces": [
                                    {
                                        "workspace_id": target_workspace_id,
                                        "workspace_kind": "PLATFORM",
                                        "role_codes": roles,
                                    }
                                ],
                                "selection_required": False,
                            }
                        }
                    ).encode("utf-8"),
                )

        target_client = TargetClient()
        target = self.module.RoleSession(
            account_code="finance_operator_01",
            workspace_id=target_workspace_id,
            workspace_kind="PLATFORM",
            role_codes=("FINANCE_OPERATOR",),
            csrf_token="y" * 32,
            client=target_client,
            policy_accepted=False,
        )
        target_account = {
            "account_code": "finance_operator_01",
            "user_id": "22222222-2222-4222-8222-222222222222",
            "entity_tag": '"v1"',
            "status": "ACTIVE",
            "role_codes": ["FINANCE_OPERATOR"],
            "is_self": False,
        }
        after_grant = {
            **target_account,
            "entity_tag": '"v2"',
            "role_codes": [
                "TRUST_OFFICER",
                "FINANCE_OPERATOR",
            ],
        }
        restored = {
            **target_account,
            "entity_tag": '"v3"',
            "role_codes": ["FINANCE_OPERATOR"],
        }
        accounts = [
            (
                {"account_code": code}
                if code != "finance_operator_01"
                else target_account
            )
            for code in self.module.ROLE_EXPECTATIONS
        ]

        grant_receipts = (
            {"entity_tag": '"v2"', "replayed": False},
            {"entity_tag": '"v2"', "replayed": True},
        )

        def grant_side_effect(*_args, **_kwargs):
            ordinal = grant_send.call_count
            events.append("grant" if ordinal == 1 else "grant-replay")
            return grant_receipts[ordinal - 1]

        grant_send = mock.Mock(side_effect=grant_side_effect)

        def duty_side_effect(*_args, action, **_kwargs):
            events.append(action)
            return {"entity_tag": '"v3"'}

        duty_command = mock.Mock(side_effect=duty_side_effect)
        account_detail = mock.Mock(
            side_effect=(after_grant, after_grant, restored, restored)
        )

        def finance_side_effect(*_args, **_kwargs):
            events.append("finance-detail")
            return {
                "funding_review_id": "33333333-3333-4333-8333-333333333333",
                "status": "SECURED",
                "assignment_status": "COMPLETED",
                "confirmation_by_me": True,
                "available_actions": [],
                "can_confirm": False,
            }

        finance_detail = mock.Mock(side_effect=finance_side_effect)
        with mock.patch.multiple(
            self.module,
            _account_list=mock.Mock(return_value=accounts),
            _send_platform_duty_command=grant_send,
            _platform_duty_command_exact_replay=duty_command,
            _account_detail=account_detail,
            _finance_detail=finance_detail,
        ):
            result = self.module._exercise_platform_duty_configuration(
                admin=admin,
                target=target,
                funding_review_id="33333333-3333-4333-8333-333333333333",
            )
        self.assertEqual(
            result,
            {
                "target_account_code": "finance_operator_01",
                "duty_code": "TRUST_OFFICER",
                "combined_role_codes": [
                    "FINANCE_OPERATOR",
                    "TRUST_OFFICER",
                ],
                "grant_observed": True,
                "target_workspace_discovery_observed": True,
                "target_finance_operation_observed": True,
                "revoke_observed": True,
                "roles_restored": True,
            },
        )
        self.assertEqual(target_client.role_sets, [])
        self.assertEqual(
            events,
            [
                "grant",
                "grant-replay",
                "workspace:FINANCE_OPERATOR+TRUST_OFFICER",
                "finance-detail",
                "revoke",
                "workspace:FINANCE_OPERATOR",
            ],
        )
        self.assertEqual(
            [call["path"] for call in target_client.calls],
            ["/v1/app/workspaces", "/v1/app/workspaces"],
        )
        duty_command.assert_has_calls(
            [
                mock.call(
                    admin,
                    user_id=target_account["user_id"],
                    duty_code="TRUST_OFFICER",
                    action="revoke",
                    if_match='"v2"',
                ),
            ]
        )
        self.assertEqual(grant_send.call_count, 2)
        self.assertIs(
            grant_send.call_args_list[0].args[1],
            grant_send.call_args_list[1].args[1],
        )
        grant_command = grant_send.call_args_list[0].args[1]
        self.assertEqual(grant_command.if_match, '"v1"')
        self.assertEqual(
            grant_command.body_items,
            (("reason_code", "ACCESS_REVIEW"),),
        )
        self.assertNotIn(
            grant_command.idempotency_key,
            repr(grant_command),
        )
        finance_detail.assert_called_once_with(
            target,
            funding_review_id="33333333-3333-4333-8333-333333333333",
        )

    def test_platform_duty_configuration_revokes_after_target_operation_failure(
        self,
    ) -> None:
        admin = self.module.RoleSession(
            account_code="access_admin_01",
            workspace_id="platform:11111111-1111-4111-8111-111111111111",
            workspace_kind="PLATFORM",
            role_codes=("ACCESS_ADMIN",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )
        target = self.module.RoleSession(
            account_code="finance_operator_01",
            workspace_id="platform:22222222-2222-4222-8222-222222222222",
            workspace_kind="PLATFORM",
            role_codes=("FINANCE_OPERATOR",),
            csrf_token="y" * 32,
            client=object(),
            policy_accepted=False,
        )
        target_account = {
            "account_code": "finance_operator_01",
            "user_id": "22222222-2222-4222-8222-222222222222",
            "entity_tag": '"v1"',
            "status": "ACTIVE",
            "role_codes": ["FINANCE_OPERATOR"],
            "is_self": False,
        }
        accounts = [
            (
                {"account_code": code}
                if code != target.account_code
                else target_account
            )
            for code in self.module.ROLE_EXPECTATIONS
        ]
        grant_send = mock.Mock(
            side_effect=(
                {"entity_tag": '"v2"', "replayed": False},
                {"entity_tag": '"v2"', "replayed": True},
            )
        )
        duty_command = mock.Mock(return_value={"entity_tag": '"v3"'})
        account_detail = mock.Mock(
            side_effect=(
                {
                    **target_account,
                    "entity_tag": '"v2"',
                    "role_codes": ["FINANCE_OPERATOR", "TRUST_OFFICER"],
                },
                {
                    **target_account,
                    "entity_tag": '"v2"',
                    "role_codes": ["FINANCE_OPERATOR", "TRUST_OFFICER"],
                },
                {
                    **target_account,
                    "entity_tag": '"v3"',
                },
                {
                    **target_account,
                    "entity_tag": '"v3"',
                },
            )
        )
        workspace_check = mock.Mock()
        with mock.patch.multiple(
            self.module,
            _account_list=mock.Mock(return_value=accounts),
            _send_platform_duty_command=grant_send,
            _platform_duty_command_exact_replay=duty_command,
            _account_detail=account_detail,
            _expect_single_platform_workspace=workspace_check,
            _finance_detail=mock.Mock(
                side_effect=self.module.InternalSandboxE2eError()
            ),
        ):
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._exercise_platform_duty_configuration(
                    admin=admin,
                    target=target,
                    funding_review_id=(
                        "33333333-3333-4333-8333-333333333333"
                    ),
                )
        self.assertEqual(grant_send.call_count, 2)
        self.assertEqual(duty_command.call_count, 1)
        self.assertEqual(
            duty_command.call_args.kwargs["action"],
            "revoke",
        )
        self.assertEqual(
            duty_command.call_args.kwargs["if_match"],
            '"v2"',
        )
        self.assertEqual(
            [
                call.kwargs["expected_role_codes"]
                for call in workspace_check.call_args_list
            ],
            [
                ("FINANCE_OPERATOR", "TRUST_OFFICER"),
                ("FINANCE_OPERATOR",),
            ],
        )

    def test_platform_duty_cleanup_reconciles_uncertain_grant_outcomes(
        self,
    ) -> None:
        cases = {
            "FIRST_UNKNOWN_COMMITTED": [
                "POST:grant:1:UNKNOWN_COMMITTED",
                "POST:grant:2:REPLAY",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:1:COMMIT",
                "POST:revoke:2:REPLAY",
                "GET:v3:FINANCE_OPERATOR",
                "GET:v3:FINANCE_OPERATOR",
            ],
            "FIRST_UNKNOWN_UNCOMMITTED": [
                "POST:grant:1:UNKNOWN_UNCOMMITTED",
                "POST:grant:2:COMMIT",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:1:COMMIT",
                "POST:revoke:2:REPLAY",
                "GET:v3:FINANCE_OPERATOR",
                "GET:v3:FINANCE_OPERATOR",
            ],
            "REPLAY_FAILURE": [
                "POST:grant:1:COMMIT",
                "POST:grant:2:REPLAY_FAILURE",
                "POST:grant:3:REPLAY",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:1:COMMIT",
                "POST:revoke:2:REPLAY",
                "GET:v3:FINANCE_OPERATOR",
                "GET:v3:FINANCE_OPERATOR",
            ],
        }
        for failure, expected_events in cases.items():
            with self.subTest(failure=failure):
                client = _StatefulDutyAdminClient(
                    self.module,
                    grant_failure=failure,
                )
                admin, target, accounts = self._duty_recovery_context(client)
                workspace_check = mock.Mock()
                finance_detail = mock.Mock(
                    return_value=self._secured_finance_detail()
                )
                with mock.patch.multiple(
                    self.module,
                    _account_list=mock.Mock(return_value=accounts),
                    _expect_single_platform_workspace=workspace_check,
                    _finance_detail=finance_detail,
                ):
                    with self.assertRaises(
                        self.module.InternalSandboxE2eError
                    ) as caught:
                        self.module._exercise_platform_duty_configuration(
                            admin=admin,
                            target=target,
                            funding_review_id=(
                                "33333333-3333-4333-8333-333333333333"
                            ),
                        )
                self.assertEqual(
                    str(caught.exception),
                    "INTERNAL_SANDBOX_E2E_FAILED",
                )
                self.assertEqual(client.roles, ("FINANCE_OPERATOR",))
                self.assertEqual(client.events, expected_events)
                workspace_check.assert_called_once_with(
                    target,
                    expected_role_codes=("FINANCE_OPERATOR",),
                )
                finance_detail.assert_not_called()
                post_requests = [
                    request
                    for request in client.requests
                    if request["method"] == "POST"
                ]
                grant_requests = [
                    request
                    for request in post_requests
                    if request["path"].endswith("/grant")
                ]
                self.assertEqual(
                    len(
                        {
                            request["headers"]["Idempotency-Key"]
                            for request in grant_requests
                        }
                    ),
                    1,
                )
                self.assertTrue(
                    all(
                        request["headers"]["If-Match"] == '"v1"'
                        and request["body"]
                        == {"reason_code": "ACCESS_REVIEW"}
                        for request in grant_requests
                    )
                )
                revoke_requests = [
                    request
                    for request in post_requests
                    if request["path"].endswith("/revoke")
                ]
                self.assertEqual(len(revoke_requests), 2)
                self.assertEqual(
                    revoke_requests[0]["headers"]["Idempotency-Key"],
                    revoke_requests[1]["headers"]["Idempotency-Key"],
                )
                self.assertEqual(
                    revoke_requests[0]["headers"]["If-Match"],
                    '"v2"',
                )
                safe_output = json.dumps(
                    {"error": str(caught.exception)}
                )
                for forbidden in (
                    _StatefulDutyAdminClient.USER_ID,
                    "Idempotency-Key",
                    '"v1"',
                    '"v2"',
                    '"v3"',
                ):
                    self.assertNotIn(forbidden, safe_output)

    def test_platform_duty_grant_convergence_uses_original_key_after_clean_reads(
        self,
    ) -> None:
        for clean_reads in (1, 2, 3):
            with self.subTest(clean_reads=clean_reads):
                client = _StatefulDutyAdminClient(
                    self.module,
                    grant_failure="UNKNOWN_UNTIL_LATE_COMMIT",
                    grant_commit_after_clean_gets=clean_reads,
                )
                admin, target, accounts = self._duty_recovery_context(client)
                workspace_check = mock.Mock()
                with mock.patch.multiple(
                    self.module,
                    _account_list=mock.Mock(return_value=accounts),
                    _expect_single_platform_workspace=workspace_check,
                    _finance_detail=mock.Mock(),
                ):
                    with self.assertRaises(
                        self.module.InternalSandboxE2eError
                    ):
                        self.module._exercise_platform_duty_configuration(
                            admin=admin,
                            target=target,
                            funding_review_id=(
                                "33333333-3333-4333-8333-333333333333"
                            ),
                        )
                self.assertEqual(client.roles, ("FINANCE_OPERATOR",))
                grant_requests = [
                    request
                    for request in client.requests
                    if request["method"] == "POST"
                    and request["path"].endswith("/grant")
                ]
                self.assertEqual(len(grant_requests), clean_reads + 2)
                self.assertEqual(
                    len(
                        {
                            request["headers"]["Idempotency-Key"]
                            for request in grant_requests
                        }
                    ),
                    1,
                )
                self.assertTrue(
                    all(
                        request["headers"]["If-Match"] == '"v1"'
                        and request["body"]
                        == {"reason_code": "ACCESS_REVIEW"}
                        for request in grant_requests
                    )
                )
                self.assertEqual(
                    client.events.count("GET:v1:FINANCE_OPERATOR"),
                    clean_reads,
                )
                self.assertEqual(client.events.count("LATE:grant:COMMIT"), 1)
                workspace_check.assert_called_once_with(
                    target,
                    expected_role_codes=("FINANCE_OPERATOR",),
                )

    def test_platform_duty_persistent_grant_unknown_never_claims_cleanup(
        self,
    ) -> None:
        client = _StatefulDutyAdminClient(
            self.module,
            grant_failure="UNKNOWN_UNTIL_LATE_COMMIT",
            grant_commit_after_clean_gets=5,
        )
        admin, target, accounts = self._duty_recovery_context(client)
        workspace_check = mock.Mock()
        finance_detail = mock.Mock()
        cleanup = mock.Mock(
            wraps=self.module._reconcile_platform_duty_cleanup
        )
        with mock.patch.multiple(
            self.module,
            _account_list=mock.Mock(return_value=accounts),
            _expect_single_platform_workspace=workspace_check,
            _finance_detail=finance_detail,
            _reconcile_platform_duty_cleanup=cleanup,
        ):
            with self.assertRaises(
                self.module.InternalSandboxE2eError
            ) as caught:
                self.module._exercise_platform_duty_configuration(
                    admin=admin,
                    target=target,
                    funding_review_id=(
                        "33333333-3333-4333-8333-333333333333"
                    ),
                )
        self.assertEqual(
            str(caught.exception),
            "INTERNAL_SANDBOX_E2E_FAILED",
        )
        self.assertEqual(client.roles, ("FINANCE_OPERATOR",))
        self.assertEqual(client.action_counts["grant"], 5)
        self.assertEqual(client.action_counts["revoke"], 0)
        self.assertEqual(client.detail_count, 4)
        self.assertIsNotNone(client.late_grant_receipt_key)
        grant_requests = [
            request
            for request in client.requests
            if request["method"] == "POST"
        ]
        self.assertEqual(
            len(
                {
                    request["headers"]["Idempotency-Key"]
                    for request in grant_requests
                }
            ),
            1,
        )
        cleanup.assert_not_called()
        workspace_check.assert_not_called()
        finance_detail.assert_not_called()

    def test_platform_duty_cleanup_reconciles_uncertain_revoke_outcomes(
        self,
    ) -> None:
        cases = {
            "FIRST_UNKNOWN_COMMITTED": [
                "POST:grant:1:COMMIT",
                "POST:grant:2:REPLAY",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:1:UNKNOWN_COMMITTED",
                "GET:v3:FINANCE_OPERATOR",
                "GET:v3:FINANCE_OPERATOR",
            ],
            "FIRST_UNKNOWN_UNCOMMITTED": [
                "POST:grant:1:COMMIT",
                "POST:grant:2:REPLAY",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:1:UNKNOWN_UNCOMMITTED",
                "GET:v2:FINANCE_OPERATOR+TRUST_OFFICER",
                "POST:revoke:2:COMMIT",
                "POST:revoke:3:REPLAY",
                "GET:v3:FINANCE_OPERATOR",
                "GET:v3:FINANCE_OPERATOR",
            ],
        }
        for failure, expected_events in cases.items():
            with self.subTest(failure=failure):
                client = _StatefulDutyAdminClient(
                    self.module,
                    revoke_failure=failure,
                )
                admin, target, accounts = self._duty_recovery_context(client)
                workspace_check = mock.Mock()
                finance_detail = mock.Mock(
                    return_value=self._secured_finance_detail()
                )
                with mock.patch.multiple(
                    self.module,
                    _account_list=mock.Mock(return_value=accounts),
                    _expect_single_platform_workspace=workspace_check,
                    _finance_detail=finance_detail,
                ):
                    result = self.module._exercise_platform_duty_configuration(
                        admin=admin,
                        target=target,
                        funding_review_id=(
                            "33333333-3333-4333-8333-333333333333"
                        ),
                    )
                self.assertTrue(result["roles_restored"])
                self.assertEqual(client.roles, ("FINANCE_OPERATOR",))
                self.assertEqual(client.events, expected_events)
                self.assertEqual(
                    [
                        call.kwargs["expected_role_codes"]
                        for call in workspace_check.call_args_list
                    ],
                    [
                        ("FINANCE_OPERATOR", "TRUST_OFFICER"),
                        ("FINANCE_OPERATOR",),
                    ],
                )
                finance_detail.assert_called_once_with(
                    target,
                    funding_review_id=(
                        "33333333-3333-4333-8333-333333333333"
                    ),
                )
                post_requests = [
                    request
                    for request in client.requests
                    if request["method"] == "POST"
                ]
                grant_requests = [
                    request
                    for request in post_requests
                    if request["path"].endswith("/grant")
                ]
                self.assertEqual(
                    grant_requests[0]["headers"]["Idempotency-Key"],
                    grant_requests[1]["headers"]["Idempotency-Key"],
                )
                revoke_requests = [
                    request
                    for request in post_requests
                    if request["path"].endswith("/revoke")
                ]
                self.assertTrue(
                    all(
                        request["headers"]["If-Match"] == '"v2"'
                        for request in revoke_requests
                    )
                )
                if failure == "FIRST_UNKNOWN_UNCOMMITTED":
                    self.assertNotEqual(
                        revoke_requests[0]["headers"]["Idempotency-Key"],
                        revoke_requests[1]["headers"]["Idempotency-Key"],
                    )
                    self.assertEqual(
                        revoke_requests[1]["headers"]["Idempotency-Key"],
                        revoke_requests[2]["headers"]["Idempotency-Key"],
                    )
                safe_output = json.dumps(result)
                for forbidden in (
                    _StatefulDutyAdminClient.USER_ID,
                    "Idempotency-Key",
                    '"v1"',
                    '"v2"',
                    '"v3"',
                ):
                    self.assertNotIn(forbidden, safe_output)

    def test_platform_duty_cleanup_accepts_only_stable_singleton_restoration(
        self,
    ) -> None:
        session = self.module.RoleSession(
            account_code="access_admin_01",
            workspace_id="platform:11111111-1111-4111-8111-111111111111",
            workspace_kind="PLATFORM",
            role_codes=("ACCESS_ADMIN",),
            csrf_token="x" * 32,
            client=object(),
            policy_accepted=False,
        )

        def snapshot(*, entity_tag, role_codes):
            return {
                "account_code": "finance_operator_01",
                "user_id": _StatefulDutyAdminClient.USER_ID,
                "status": "ACTIVE",
                "entity_tag": entity_tag,
                "role_codes": role_codes,
                "is_self": False,
            }

        combined = snapshot(
            entity_tag='"v2"',
            role_codes=["FINANCE_OPERATOR", "TRUST_OFFICER"],
        )
        cases = {
            "extra_duty": (
                snapshot(
                    entity_tag='"v3"',
                    role_codes=["APPEAL_REVIEWER", "FINANCE_OPERATOR"],
                ),
            ),
            "etag_drift": (
                snapshot(
                    entity_tag='"v3"',
                    role_codes=["FINANCE_OPERATOR"],
                ),
                snapshot(
                    entity_tag='"v4"',
                    role_codes=["FINANCE_OPERATOR"],
                ),
            ),
        }
        for name, after_revoke in cases.items():
            with self.subTest(name=name):
                duty_command = mock.Mock(return_value={"entity_tag": '"v3"'})
                with mock.patch.multiple(
                    self.module,
                    _account_detail=mock.Mock(
                        side_effect=(combined, *after_revoke)
                    ),
                    _platform_duty_command_exact_replay=duty_command,
                ):
                    restored = self.module._reconcile_platform_duty_cleanup(
                        session,
                        target_account_code="finance_operator_01",
                        user_id=_StatefulDutyAdminClient.USER_ID,
                        duty_code="TRUST_OFFICER",
                        original_role_codes=("FINANCE_OPERATOR",),
                    )
                self.assertFalse(restored)
                duty_command.assert_called_once_with(
                    session,
                    user_id=_StatefulDutyAdminClient.USER_ID,
                    duty_code="TRUST_OFFICER",
                    action="revoke",
                    if_match='"v2"',
                )

    def test_safe_payloads_are_editable_closed_and_have_no_real_funds(self) -> None:
        editor_choices = _valid_editor_choices(self.module)
        profile = self.module.safe_profile_content(editor_choices)
        demand = self.module.safe_demand_content(editor_choices)
        self.assertEqual(
            self.module.safe_profile_content(editor_choices),
            profile,
        )
        self.assertEqual(
            self.module.safe_demand_content(editor_choices),
            demand,
        )
        self.module._validate_editor_content_choices(
            resource_type="CREATOR_PROFILE",
            content=profile,
            editor_choices=editor_choices,
        )
        self.module._validate_editor_content_choices(
            resource_type="DEMAND",
            content=demand,
            editor_choices=editor_choices,
        )
        self.assertEqual(
            tuple(profile),
            self.module.PROFILE_SECTION_KEYS,
        )
        self.assertEqual(
            tuple(demand),
            self.module.DEMAND_SECTION_KEYS,
        )
        self.assertEqual(
            profile["boundaries"]["allowed_data_sensitivity"][
                "data_sensitivity"
            ],
            "INTERNAL",
        )
        self.assertFalse(profile["ai"]["allowed"])
        self.assertFalse(profile["ai"]["requires_ai"])
        self.assertEqual(profile["ai"]["prohibited_case_codes"], [])
        self.assertEqual(profile["boundaries"]["prohibited_domains"], [])
        self.assertEqual(profile["boundaries"]["prohibited_tasks"], [])
        self.assertEqual(
            profile["interests"][0],
            {
                "problem_code": "PROBLEM.OPERATIONS",
                "domain_code": "DOMAIN.SOFTWARE",
                "task_code": "TASK.ANALYSIS",
                "strength": 4,
                "visibility": "MATCH_ONLY",
                "source_kind": "SELF_ASSERTED",
                "evidence_ids": [],
            },
        )
        self.assertEqual(
            profile["skills"][0]["skill_code"],
            "SKILL.SYSTEMS_ANALYSIS",
        )
        self.assertTrue(demand["problem"]["background"].startswith("INTERNAL_SANDBOX"))
        self.assertEqual(
            demand["problem"]["target_user_category_codes"],
            ["SYNTHETIC_USER"],
        )
        self.assertIn("真实用户与真实交易", demand["scope"]["out_of_scope"])
        self.assertEqual(
            {
                demand["budget"]["minimum_amount_minor"],
                demand["budget"]["maximum_amount_minor"],
                demand["budget"]["direct_cost_amount_minor"],
            },
            {0},
        )
        self.assertEqual(demand["risk"]["data_sensitivity"], "INTERNAL")
        self.assertEqual(demand["risk"]["dependency_codes"], [])
        self.assertEqual(
            demand["problem"]["domain_code"],
            "DOMAIN.SOFTWARE",
        )
        self.assertEqual(
            demand["problem"]["problem_type_codes"],
            ["PROBLEM.OPERATIONS"],
        )
        self.assertEqual(
            demand["skills"]["must_have"][0]["skill_code"],
            "SKILL.SYSTEMS_ANALYSIS",
        )
        self.assertEqual(demand["skills"]["nice_to_have"], [])
        self.assertEqual(
            demand["matching"],
            {
                "problem_codes": ["PROBLEM.OPERATIONS"],
                "domain_codes": ["DOMAIN.SOFTWARE"],
                "task_codes": ["TASK.ANALYSIS"],
            },
        )
        self.assertEqual(demand["ai"]["allowed"], False)
        self.assertEqual(demand["ai"]["required"], False)
        self.assertTrue(all(demand["declarations"].values()))

        platform_source = str(ROOT / "platform" / "src")
        sys.path.insert(0, platform_source)
        try:
            from desire_platform.creator_profile.domain import (
                freeze_profile_content,
            )
            from desire_platform.demand.domain import (
                DemandContent,
                validate_demand_content,
            )
            modules_before_validator = dict(sys.modules)
            package_attributes_before_validator = {
                name: dict(vars(module))
                for name, module in modules_before_validator.items()
                if name == "desire_platform"
                or name.startswith("desire_platform.")
            }
            validate_editor_choice_membership = (
                _production_membership_validator()
            )
            self.assertEqual(sys.modules, modules_before_validator)
            for name, attributes in package_attributes_before_validator.items():
                self.assertEqual(
                    vars(modules_before_validator[name]),
                    attributes,
                )
        finally:
            self.assertEqual(sys.path.pop(0), platform_source)

        def freeze_demand(value):
            if isinstance(value, dict):
                return DemandContent(
                    tuple(
                        (key, freeze_demand(child))
                        for key, child in value.items()
                    )
                )
            if isinstance(value, list):
                return tuple(freeze_demand(child) for child in value)
            return value

        validate_editor_choice_membership(
            resource_type="CREATOR_PROFILE",
            content=profile,
        )
        validate_editor_choice_membership(
            resource_type="DEMAND",
            content=demand,
        )
        freeze_profile_content(profile, for_publish=True)
        validate_demand_content(
            freeze_demand(demand),
            for_submission=True,
        )

        rejected_profile = _json_copy(profile)
        rejected_profile["ai"]["prohibited_case_codes"] = [
            "AI.BIOMETRIC_SURVEILLANCE"
        ]
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._validate_editor_content_choices(
                resource_type="CREATOR_PROFILE",
                content=rejected_profile,
                editor_choices=editor_choices,
            )
        rejected_demand = _json_copy(demand)
        rejected_demand["risk"]["dependency_codes"] = [
            "DEPENDENCY.GENERAL"
        ]
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._validate_editor_content_choices(
                resource_type="DEMAND",
                content=rejected_demand,
                editor_choices=editor_choices,
            )

    def test_safe_payloads_choose_first_available_catalog_options(self) -> None:
        editor_choices = _valid_editor_choices(self.module)
        options_by_kind = {
            "DOMAIN": ("DOMAIN.ALPHA", "DOMAIN.OMEGA"),
            "PROBLEM_TYPE": ("PROBLEM.ALPHA", "PROBLEM.OMEGA"),
            "TASK": ("TASK.ALPHA", "TASK.OMEGA"),
            "SKILL": ("SKILL.ALPHA", "SKILL.OMEGA"),
        }
        for field in editor_choices["fields"]:
            values = options_by_kind.get(field["intended_node_kind"])
            if field["options"] and values is not None:
                field["options"] = [
                    {
                        "value": value,
                        "label": value,
                        "source": "TAXONOMY_BUNDLE_NODE",
                    }
                    for value in values
                ]

        profile = self.module.safe_profile_content(editor_choices)
        demand = self.module.safe_demand_content(editor_choices)

        self.assertEqual(
            (
                profile["interests"][0]["problem_code"],
                profile["interests"][0]["domain_code"],
                profile["interests"][0]["task_code"],
                profile["skills"][0]["skill_code"],
            ),
            (
                "PROBLEM.ALPHA",
                "DOMAIN.ALPHA",
                "TASK.ALPHA",
                "SKILL.ALPHA",
            ),
        )
        self.assertEqual(
            (
                demand["problem"]["problem_type_codes"],
                demand["problem"]["domain_code"],
                demand["matching"]["task_codes"],
                demand["skills"]["must_have"][0]["skill_code"],
            ),
            (
                ["PROBLEM.ALPHA"],
                "DOMAIN.ALPHA",
                ["TASK.ALPHA"],
                "SKILL.ALPHA",
            ),
        )
        self.assertEqual(profile["ai"]["prohibited_case_codes"], [])
        self.assertEqual(demand["risk"]["dependency_codes"], [])

    def test_owner_must_read_reviewer_reason_and_required_scope_field(self) -> None:
        finding = {
            "finding_id": "11111111-1111-4111-8111-111111111111",
            "version_id": "22222222-2222-4222-8222-222222222222",
            "assignment_id": "33333333-3333-4333-8333-333333333333",
            "result": "NEEDS_CHANGES",
            "reason_codes": ["SCOPE_UNCLEAR"],
            "required_field_paths": ["SCOPE"],
            "reviewed_at": "2026-08-16T08:00:00+00:00",
        }
        self.module._require_owner_scope_finding({"findings": [finding]})
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_owner_scope_finding({"findings": []})
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_owner_scope_finding(
                {"findings": [{**finding, "reason_codes": ["CONTENT_INCOMPLETE"]}]}
            )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_owner_scope_finding(
                {"findings": [{**finding, "required_field_paths": ["PROBLEM"]}]}
            )

        verified = {
            **finding,
            "result": "VERIFIED",
            "reason_codes": [],
            "required_field_paths": [],
        }
        self.module._require_verified_finding(
            {"findings": [verified]},
            demand_version_id=finding["version_id"],
        )
        discrepancy = {
            **finding,
            "assignment_id": None,
            "result": "DISCREPANCY",
            "reason_codes": ["TARGET_CONTENT_MISMATCH"],
            "required_field_paths": ["/scope"],
        }
        self.module._require_verified_finding(
            {"findings": [verified, discrepancy]},
            demand_version_id=finding["version_id"],
        )
        self.module._require_finance_discrepancy_finding(
            {"findings": [verified, discrepancy]},
            demand_version_id=finding["version_id"],
        )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_finance_discrepancy_finding(
                {"findings": [{**discrepancy, "assignment_id": finding["assignment_id"]}]},
                demand_version_id=finding["version_id"],
            )
        with self.assertRaises(self.module.InternalSandboxE2eError):
            self.module._require_verified_finding(
                {"findings": [verified]},
                demand_version_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            )

    def test_state_file_is_closed_private_and_rejects_unknown_fields(self) -> None:
        state = self.module.JourneyState(
            profile_id="11111111-1111-4111-8111-111111111111",
            demand_id="22222222-2222-4222-8222-222222222222",
            demand_version_id="77777777-7777-4777-8777-777777777777",
            funding_review_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            profile_revision=3,
            demand_revision=7,
            trust_report_id="88888888-8888-4888-8888-888888888888",
            trust_case_id="99999999-9999-4999-8999-999999999999",
            trust_hold_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            trust_outcome_version_id=(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ),
            trust_report_etag='"trust-9-aaaaaaaaaaaaaaaaaaaaaaaa"',
            trust_case_etag='"trust-9-bbbbbbbbbbbbbbbbbbbbbbbb"',
            expected_trust_outcome_code="PROTECTION_MODIFIED",
            expected_appeal_eligibility_code="ELIGIBLE",
            expected_operations_result="VERIFIED",
            appeal_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            appeal_decision_version_id=(
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
            ),
            appeal_etag='"appeal-7-cccccccccccccccccccccccc"',
            expected_appeal_status="DECIDED",
            expected_appeal_decision_code="VACATE_AND_REMAND",
            organization_id="33333333-3333-4333-8333-333333333333",
            accepted_invitation_id="44444444-4444-4444-8444-444444444444",
            accepted_membership_id="55555555-5555-4555-8555-555555555555",
            revoked_invitation_id="66666666-6666-4666-8666-666666666666",
        )
        with tempfile.TemporaryDirectory(prefix="desire-e2e-state-") as directory:
            path = Path(directory).resolve() / "state.json"
            self.module.write_state(path, state)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(self.module.load_state(path), state)
            serialized = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(serialized),
                {
                    "schema",
                    "profile_id",
                    "demand_id",
                    "demand_version_id",
                    "funding_review_id",
                    "profile_revision",
                    "demand_revision",
                    "trust_report_id",
                    "trust_case_id",
                    "trust_hold_id",
                    "trust_outcome_version_id",
                    "trust_report_etag",
                    "trust_case_etag",
                    "expected_trust_outcome_code",
                    "expected_appeal_eligibility_code",
                    "expected_operations_result",
                    "appeal_id",
                    "appeal_decision_version_id",
                    "appeal_etag",
                    "expected_appeal_status",
                    "expected_appeal_decision_code",
                    "organization_id",
                    "accepted_invitation_id",
                    "accepted_membership_id",
                    "revoked_invitation_id",
                },
            )
            self.assertFalse(
                any(
                    word in path.read_text(encoding="utf-8").lower()
                    for word in (
                        "cookie",
                        "csrf",
                        "request_handle",
                        "idempotency_key",
                        "restricted_note",
                        "evidence_reference",
                        "applicant_statement",
                        "reviewer_note",
                        "sealed_",
                        "assignment_id",
                    )
                )
            )

            serialized["cookie"] = "forbidden"
            path.write_text(json.dumps(serialized), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module.load_state(path)

    def test_restart_requires_reporter_outcome_released_hold_and_both_officers(self) -> None:
        state = self.module.JourneyState(
            profile_id="11111111-1111-4111-8111-111111111111",
            demand_id="22222222-2222-4222-8222-222222222222",
            demand_version_id="33333333-3333-4333-8333-333333333333",
            funding_review_id="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            profile_revision=3,
            demand_revision=11,
            trust_report_id="44444444-4444-4444-8444-444444444444",
            trust_case_id="55555555-5555-4555-8555-555555555555",
            trust_hold_id="66666666-6666-4666-8666-666666666666",
            trust_outcome_version_id=(
                "77777777-7777-4777-8777-777777777777"
            ),
            trust_report_etag='"trust-9-aaaaaaaaaaaaaaaaaaaaaaaa"',
            trust_case_etag='"trust-9-bbbbbbbbbbbbbbbbbbbbbbbb"',
            expected_trust_outcome_code="PROTECTION_MODIFIED",
            expected_appeal_eligibility_code="ELIGIBLE",
            expected_operations_result="VERIFIED",
            appeal_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            appeal_decision_version_id=(
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
            ),
            appeal_etag='"appeal-7-cccccccccccccccccccccccc"',
            expected_appeal_status="DECIDED",
            expected_appeal_decision_code="VACATE_AND_REMAND",
            organization_id="88888888-8888-4888-8888-888888888888",
            accepted_invitation_id="99999999-9999-4999-8999-999999999999",
            accepted_membership_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            revoked_invitation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )

        def session(code, roles):
            return self.module.RoleSession(
                account_code=code,
                workspace_id="platform:cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                workspace_kind="PLATFORM",
                role_codes=roles,
                csrf_token="x" * 32,
                client=object(),
                policy_accepted=False,
            )

        owner = session("demand_owner_01", ("DEMAND_OWNER",))
        officer_one = session("trust_officer_01", ("TRUST_OFFICER",))
        officer_two = session("trust_officer_02", ("TRUST_OFFICER",))
        report = {
            "entity_tag": state.trust_report_etag,
            "demand_id": state.demand_id,
            "demand_version_id": state.demand_version_id,
            "status": "DECIDED",
            "outcome": {"safe": True},
        }
        case = {
            "entity_tag": state.trust_case_etag,
            "report_id": state.trust_report_id,
            "demand_id": state.demand_id,
            "demand_version_id": state.demand_version_id,
            "status": "DECIDED",
            "active_hold": None,
            "outcome": {"safe": True},
        }
        terminal_item = {
            "case_id": state.trust_case_id,
            "decided_at": "2026-08-26T13:00:00Z",
            "outcome_code": state.expected_trust_outcome_code,
        }
        terminal_history = mock.Mock(
            side_effect=lambda session: {
                "items": [terminal_item] if session is officer_one else []
            }
        )
        with mock.patch.multiple(
            self.module,
            _get_trust_report=mock.Mock(return_value=report),
            _get_trust_case=mock.Mock(return_value=case),
            _trust_case_queue=mock.Mock(return_value={"items": []}),
            _trust_hold_release_queue=mock.Mock(return_value={"items": []}),
            _trust_active_assignments=mock.Mock(return_value={"items": []}),
            _trust_terminal_history=terminal_history,
            _require_eligible_outcome=mock.Mock(),
        ):
            summary = self.module._verify_trust_restart(
                owner=owner,
                officer_one=officer_one,
                officer_two=officer_two,
                state=state,
            )
            terminal_history.side_effect = lambda _session: {
                "items": [terminal_item]
            }
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._verify_trust_restart(
                    owner=owner,
                    officer_one=officer_one,
                    officer_two=officer_two,
                    state=state,
                )
        self.assertEqual(
            summary["officer_accounts_authenticated"],
            ["trust_officer_01", "trust_officer_02"],
        )
        self.assertEqual(summary["outcome_code"], "PROTECTION_MODIFIED")
        self.assertEqual(summary["appeal_eligibility_code"], "ELIGIBLE")
        self.assertTrue(summary["hold_released"])
        self.assertEqual(summary["operations_result"], "VERIFIED")
        self.assertTrue(summary["active_assignment_lists_absent"])
        self.assertTrue(summary["terminal_history_discoverable"])
        self.assertTrue(summary["terminal_history_actor_scoped"])
        self.assertIn(
            '"trust_terminal_history_discoverable"',
            inspect.getsource(self.module.verify_restart),
        )

        appeal_reviewer = session(
            "appeal_reviewer_01", ("APPEAL_REVIEWER",)
        )
        own_appeal = {
            "appeal_id": state.appeal_id,
            "entity_tag": state.appeal_etag,
            "source_case_id": state.trust_case_id,
            "source_outcome_version_id": state.trust_outcome_version_id,
            "status": "DECIDED",
            "application": {"statement_recorded": True},
            "decision": {
                "decision_code": "VACATE_AND_REMAND",
                "decision_version_id": state.appeal_decision_version_id,
            },
        }
        with mock.patch.multiple(
            self.module,
            _get_own_appeal=mock.Mock(return_value=own_appeal),
            _appeal_queue=mock.Mock(return_value={"items": []}),
            _appeal_active_assignments=mock.Mock(return_value={"items": []}),
            _appeal_terminal_history=mock.Mock(
                return_value={
                    "items": [
                        {
                            "appeal_id": state.appeal_id,
                            "decision_code": (
                                state.expected_appeal_decision_code
                            ),
                        }
                    ]
                }
            ),
            _get_terminal_appeal=mock.Mock(
                return_value={
                    "appeal_id": state.appeal_id,
                    "status": "DECIDED",
                    "entity_tag": state.appeal_etag,
                    "application": own_appeal["application"],
                    "decision": own_appeal["decision"],
                    "review_note_recorded": True,
                }
            ),
        ):
            appeal_summary = self.module._verify_appeal_restart(
                owner=owner,
                reviewer=appeal_reviewer,
                state=state,
            )
        self.assertEqual(appeal_summary["appeal_status"], "DECIDED")
        self.assertEqual(
            appeal_summary["decision_code"], "VACATE_AND_REMAND"
        )
        self.assertTrue(appeal_summary["review_queue_absent"])
        self.assertTrue(appeal_summary["active_assignment_list_absent"])

        with mock.patch.multiple(
            self.module,
            _get_own_appeal=mock.Mock(return_value=own_appeal),
            _appeal_queue=mock.Mock(return_value={"items": []}),
            _appeal_active_assignments=mock.Mock(
                return_value={
                    "items": [
                        {
                            "appeal_id": state.appeal_id,
                            "assignment_expires_at": (
                                "2026-08-19T12:00:00Z"
                            ),
                        }
                    ]
                }
            ),
        ):
            with self.assertRaises(self.module.InternalSandboxE2eError):
                self.module._verify_appeal_restart(
                    owner=owner,
                    reviewer=appeal_reviewer,
                    state=state,
                )

    def test_cli_failures_are_stable_and_non_reflective(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = self.module.main(
            [
                "journey",
                "--ca-file",
                "relative-ca.pem",
                "--state-output",
                "relative-state.json",
            ],
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(exit_code, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            '{"code":"INTERNAL_SANDBOX_E2E_FAILED",'
            '"stage":"INPUT","status":"BLOCKED"}\n',
        )

    def test_provider_only_invited_owner_cli_is_separate_and_secret_safe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            ca_file = root / "root-ca.pem"
            result_output = root / "invited-result.json"
            ca_file.write_text(
                "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
                encoding="ascii",
            )
            expected = {
                "status": self.module.INVITED_DEMAND_OWNER_GREEN_STATUS,
                "pending_boundary": {"roles_absent": True},
            }
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                self.module,
                "run_invited_demand_owner_journey",
                return_value=expected,
            ) as journey, mock.patch.object(self.module, "run_journey") as original:
                exit_code = self.module.main(
                    [
                        "invited-demand-owner",
                        "--ca-file",
                        str(ca_file),
                        "--result-output",
                        str(result_output),
                    ],
                    stdout=stdout,
                    stderr=stderr,
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(json.loads(stdout.getvalue()), expected)
            self.assertEqual(json.loads(result_output.read_text()), expected)
            self.assertEqual(stat.S_IMODE(result_output.stat().st_mode), 0o600)
            journey.assert_called_once_with(ca_file=ca_file)
            original.assert_not_called()

    def test_cli_result_output_is_private_exclusive_and_preflighted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca_file = root / "root-ca.pem"
            state_output = root / "state.json"
            result_output = root / "result.json"
            ca_file.write_text("unused by mocked journey", encoding="ascii")
            stdout = io.StringIO()
            stderr = io.StringIO()
            expected = {"status": self.module.JOURNEY_GREEN_STATUS}
            with mock.patch.object(
                self.module, "run_journey", return_value=expected
            ) as journey:
                exit_code = self.module.main(
                    [
                        "journey",
                        "--ca-file",
                        str(ca_file),
                        "--state-output",
                        str(state_output),
                        "--result-output",
                        str(result_output),
                    ],
                    stdout=stdout,
                    stderr=stderr,
                )
            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(stdout.getvalue(), result_output.read_text())
            self.assertEqual(json.loads(result_output.read_text()), expected)
            self.assertEqual(stat.S_IMODE(result_output.stat().st_mode), 0o600)
            journey.assert_called_once_with(
                ca_file=ca_file,
                state_output=state_output,
            )

            for blocked_output in (result_output, state_output):
                with self.subTest(blocked_output=blocked_output):
                    blocked_stdout = io.StringIO()
                    blocked_stderr = io.StringIO()
                    with mock.patch.object(self.module, "run_journey") as blocked:
                        blocked_exit = self.module.main(
                            [
                                "journey",
                                "--ca-file",
                                str(ca_file),
                                "--state-output",
                                str(state_output),
                                "--result-output",
                                str(blocked_output),
                            ],
                            stdout=blocked_stdout,
                            stderr=blocked_stderr,
                        )
                    self.assertEqual(blocked_exit, 78)
                    self.assertEqual(blocked_stdout.getvalue(), "")
                    self.assertEqual(
                        blocked_stderr.getvalue(),
                        '{"code":"INTERNAL_SANDBOX_E2E_FAILED",'
                        '"stage":"RESULT_OUTPUT","status":"BLOCKED"}\n',
                    )
                    blocked.assert_not_called()

    def test_cli_rejects_outputs_inside_a_sealed_manager_input_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manager_root = root / "manager-input"
            metadata = manager_root / ".local-internal-sandbox"
            evidence = manager_root / "evidence"
            nested_evidence = evidence / "nested"
            outside = root / "outside"
            metadata.mkdir(parents=True)
            nested_evidence.mkdir(parents=True)
            outside.mkdir()
            alias = root / "manager-evidence-alias"
            alias.symlink_to(evidence, target_is_directory=True)
            (metadata / "prepared-receipt.json").write_text(
                "{}\n", encoding="utf-8"
            )
            ca_file = outside / "root-ca.pem"
            ca_file.write_text("unused by mocked journey", encoding="ascii")

            cases = (
                (
                    evidence / "state.json",
                    outside / "result.json",
                    "INPUT",
                ),
                (
                    outside / "state.json",
                    evidence / "result.json",
                    "RESULT_OUTPUT",
                ),
                (
                    alias / "nested" / "state.json",
                    outside / "symlink-result.json",
                    "INPUT",
                ),
                (
                    outside / "symlink-state.json",
                    alias / "nested" / "result.json",
                    "RESULT_OUTPUT",
                ),
            )
            for state_output, result_output, stage in cases:
                with self.subTest(stage=stage):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with mock.patch.object(self.module, "run_journey") as journey:
                        exit_code = self.module.main(
                            [
                                "journey",
                                "--ca-file",
                                str(ca_file),
                                "--state-output",
                                str(state_output),
                                "--result-output",
                                str(result_output),
                            ],
                            stdout=stdout,
                            stderr=stderr,
                        )
                    self.assertEqual(exit_code, 78)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(
                        stderr.getvalue(),
                        '{"code":"INTERNAL_SANDBOX_E2E_FAILED",'
                        f'"stage":"{stage}","status":"BLOCKED"}}\n',
                    )
                    self.assertFalse(state_output.exists())
                    self.assertFalse(result_output.exists())
                    journey.assert_not_called()

    def test_journey_preserves_initial_policy_acceptance_evidence_after_relogin(self) -> None:
        profile_id = "11111111-1111-4111-8111-111111111111"
        demand_id = "22222222-2222-4222-8222-222222222222"
        demand_version_id = "77777777-7777-4777-8777-777777777777"
        funding_review_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        report_id = "88888888-8888-4888-8888-888888888888"
        case_id = "99999999-9999-4999-8999-999999999999"
        hold_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        outcome_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        appeal_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        appeal_decision_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        report_etag = '"trust-9-aaaaaaaaaaaaaaaaaaaaaaaa"'
        case_etag = '"trust-9-bbbbbbbbbbbbbbbbbbbbbbbb"'
        appeal_etag = '"appeal-7-cccccccccccccccccccccccc"'
        report_context = {
            "case_id": case_id,
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "report_id": report_id,
            "report_etag": '"trust-1-cccccccccccccccccccccccc"',
        }
        case_context = {
            **report_context,
            "case": {"status": "IN_REVIEW"},
            "triage_draft_versions": [1, 2],
            "triage_configuration_changed": True,
        }
        hold_context = {
            **case_context,
            "hold_id": hold_id,
            "blocked_demand": {"status": "SUBMITTED"},
            "blocked_idempotency_key": "transient-not-serialized",
            "blocked_verification": {
                "http_status": 403,
                "error_code": "SAFETY_HOLD_BLOCKED",
                "public_demand_projection_unchanged": True,
                "expected_receipt_delta": 0,
                "expected_audit_delta": 0,
                "expected_outbox_delta": 0,
            },
        }
        released_context = {**hold_context, "hold_released": True}
        trust_summary = {
            "report_id": report_id,
            "case_id": case_id,
            "hold_id": hold_id,
            "outcome_version_id": outcome_id,
            "demand_version_id": demand_version_id,
            "report_etag": report_etag,
            "case_etag": case_etag,
            "report_status": "DECIDED",
            "case_status": "DECIDED",
            "outcome_code": "PROTECTION_MODIFIED",
            "appeal_eligibility_code": "ELIGIBLE",
            "appeal_deadline_present": True,
            "owner_outcome_visible": True,
            "hold_released": True,
            "independent_release": True,
            "triage_draft_versions": [1, 2],
            "triage_configuration_changed": True,
            "blocked_verification": hold_context["blocked_verification"],
        }
        appeal_summary = {
            "appeal_id": appeal_id,
            "source_outcome_version_id": outcome_id,
            "decision_version_id": appeal_decision_id,
            "appeal_etag": appeal_etag,
            "appeal_status": "DECIDED",
            "decision_code": "VACATE_AND_REMAND",
            "application_version": 1,
            "review_draft_version": 1,
            "applicant_replays_verified": True,
            "reviewer_replays_verified": True,
            "assignment_release_replay_verified": True,
            "reclaim_replay_verified": True,
            "write_kinds_verified": 7,
            "review_queue_absent": True,
        }

        def role_session(code, *, accepted):
            kind, roles = self.module.ROLE_EXPECTATIONS[code]
            return self.module.RoleSession(
                account_code=code,
                workspace_id=(
                    "org:" if kind == "ORGANIZATION" else kind.casefold() + ":"
                )
                + "33333333-3333-4333-8333-333333333333",
                workspace_kind=kind,
                role_codes=roles,
                csrf_token="x" * 32,
                client=object(),
                policy_accepted=accepted,
            )

        def fake_login(*, account_code, **_kwargs):
            return role_session(
                account_code,
                accepted=account_code in {"creator_01", "demand_owner_01"},
            )

        with tempfile.TemporaryDirectory(prefix="desire-e2e-summary-") as directory:
            root = Path(directory).resolve()
            ca_file = root / "root-ca.pem"
            ca_file.write_text(
                "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
                encoding="ascii",
            )
            state_file = root / "state.json"
            with mock.patch.multiple(
                self.module,
                _login=fake_login,
                _verify_assignment_discovery_boundaries=mock.Mock(
                    return_value={
                        "wrong_role_reads_hidden": True,
                        "extra_queries_rejected": True,
                        "wrong_hold_reads_hidden": True,
                        "assigned_hold_extra_queries_rejected": True,
                        "wrong_role_history_hidden": True,
                        "history_extra_queries_rejected": True,
                        "second_reviewer_history_empty": True,
                        "second_reviewer_detail_hidden": True,
                        "temporary_reviewer_duty_restored": True,
                    }
                ),
                _configuration=mock.Mock(
                    return_value=_valid_configuration_data(self.module)
                ),
                _create_and_publish_profile=mock.Mock(
                    return_value={
                        "object_id": profile_id,
                        "status": "ACTIVE",
                        "revision": 3,
                    }
                ),
                _create_reviewable_demand=mock.Mock(
                    return_value=(
                        {
                            "object_id": demand_id,
                            "status": "SUBMITTED",
                            "revision": 6,
                            "current_version": {
                                "version_id": demand_version_id,
                            },
                            "review_assignment": {
                                "assignment_id": (
                                    "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                                )
                            },
                        },
                        True,
                    )
                ),
                _submit_trust_report=mock.Mock(return_value=report_context),
                _review_trust_case=mock.Mock(return_value=case_context),
                _place_trust_hold_and_prove_blocked=mock.Mock(
                    return_value=hold_context
                ),
                _release_trust_hold_and_verify=mock.Mock(
                    return_value=(
                        released_context,
                        {
                            "object_id": demand_id,
                            "status": "VERIFIED",
                            "revision": 7,
                        },
                    )
                ),
                _publish_trust_outcome=mock.Mock(return_value=trust_summary),
                _exercise_trust_appeal=mock.Mock(return_value=appeal_summary),
                _fund_verified_demand=mock.Mock(
                    return_value=(
                        {
                            "object_id": demand_id,
                            "status": "FUNDED",
                            "revision": 11,
                        },
                        {
                            "funding_review_id": funding_review_id,
                            "review_status": "SECURED",
                            "confirmation_count": 2,
                            "assignments_distinct": True,
                            "release_reclaimed_with_new_assignment": True,
                            "discrepancy_cycle_terminal": True,
                            "historical_cycles_distinct": True,
                            "active_assignments_absent": True,
                            "demand_status": "FUNDED",
                        },
                    )
                ),
                _exercise_platform_duty_configuration=mock.Mock(
                    return_value={
                        "target_account_code": "finance_operator_01",
                        "duty_code": "TRUST_OFFICER",
                        "combined_role_codes": [
                            "FINANCE_OPERATOR",
                            "TRUST_OFFICER",
                        ],
                        "grant_observed": True,
                        "target_workspace_discovery_observed": True,
                        "target_finance_operation_observed": True,
                        "revoke_observed": True,
                        "roles_restored": True,
                    }
                ),
                _exercise_organization_admin=mock.Mock(
                    return_value=(
                        role_session("creator_01", accepted=False),
                        {
                            "organization_id": "33333333-3333-4333-8333-333333333333",
                            "accepted_invitation_id": "44444444-4444-4444-8444-444444444444",
                            "accepted_membership_id": "55555555-5555-4555-8555-555555555555",
                            "revoked_invitation_id": "66666666-6666-4666-8666-666666666666",
                            "active_second_authority_canonical_me_verified": True,
                            "creator_workspace_added": True,
                            "suspend_removed_org_workspace": True,
                            "resume_restored_org_workspace": True,
                            "revoke_removed_org_workspace": True,
                            "unaccepted_invitation_revoked": True,
                        },
                    )
                ),
                _exercise_account_lifecycle=mock.Mock(
                    return_value=role_session("creator_01", accepted=False)
                ),
            ):
                summary = self.module.run_journey(
                    ca_file=ca_file,
                    state_output=state_file,
                )
        self.assertEqual(
            summary["policy_acceptance_performed"],
            {"creator_01": True, "demand_owner_01": True},
        )
        self.assertEqual(
            summary["status"], "TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN"
        )
        self.assertEqual(summary["demand"]["status"], "FUNDED")
        self.assertEqual(summary["trust"], trust_summary)
        self.assertEqual(summary["appeal"], appeal_summary)
        self.assertEqual(
            summary["assignment_discovery_boundary"],
            {
                "wrong_role_reads_hidden": True,
                "extra_queries_rejected": True,
                "wrong_hold_reads_hidden": True,
                "assigned_hold_extra_queries_rejected": True,
                "wrong_role_history_hidden": True,
                "history_extra_queries_rejected": True,
                "second_reviewer_history_empty": True,
                "second_reviewer_detail_hidden": True,
                "temporary_reviewer_duty_restored": True,
            },
        )
        self.assertEqual(
            summary["finance"],
            {
                "funding_review_id": funding_review_id,
                "review_status": "SECURED",
                "confirmation_count": 2,
                "assignments_distinct": True,
                "release_reclaimed_with_new_assignment": True,
                "discrepancy_cycle_terminal": True,
                "historical_cycles_distinct": True,
                "active_assignments_absent": True,
                "demand_status": "FUNDED",
            },
        )
        self.assertEqual(
            summary["platform_duty_configuration"],
            {
                "target_account_code": "finance_operator_01",
                "duty_code": "TRUST_OFFICER",
                "combined_role_codes": [
                    "FINANCE_OPERATOR",
                    "TRUST_OFFICER",
                ],
                "grant_observed": True,
                "target_workspace_discovery_observed": True,
                "target_finance_operation_observed": True,
                "revoke_observed": True,
                "roles_restored": True,
            },
        )
        self.assertEqual(
            summary["organization_admin"],
            {
                "organization_id": "33333333-3333-4333-8333-333333333333",
                "accepted_invitation_id": "44444444-4444-4444-8444-444444444444",
                "accepted_membership_id": "55555555-5555-4555-8555-555555555555",
                "revoked_invitation_id": "66666666-6666-4666-8666-666666666666",
                "active_second_authority_canonical_me_verified": True,
                "creator_workspace_added": True,
                "suspend_removed_org_workspace": True,
                "resume_restored_org_workspace": True,
                "revoke_removed_org_workspace": True,
                "unaccepted_invitation_revoked": True,
            },
        )
        serialized_summary = json.dumps(summary, ensure_ascii=False).lower()
        for forbidden in (
            "access_invitation_token",
            "csrf_token",
            "authorization_url",
            "request_handle",
            "cookie",
            "restricted_note",
            "evidence_reference_ids",
            "blocked_idempotency_key",
            "sealed_note_reference",
            "applicant_statement",
            "reviewer_note",
        ):
            self.assertNotIn(forbidden, serialized_summary)


if __name__ == "__main__":
    unittest.main()
