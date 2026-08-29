"""Machine checks for the IAM-01 OpenAPI and event contracts.

These tests intentionally import no production package. They keep the pre-red-test
contracts executable while the platform implementation is still being built.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator
import unittest

import yaml


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"
EVENT_SCHEMA_PATH = (
    PLATFORM_ROOT / "contracts" / "events" / "iam-v1.schema.json"
)


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects silently overwritten mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise AssertionError(
                f"duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_openapi() -> dict[str, Any]:
    with OPENAPI_PATH.open(encoding="utf-8") as contract_file:
        loaded = yaml.load(contract_file, Loader=_UniqueKeyLoader)
    if not isinstance(loaded, dict):
        raise AssertionError("OpenAPI root must be a mapping")
    return loaded


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_event_schema() -> dict[str, Any]:
    with EVENT_SCHEMA_PATH.open(encoding="utf-8") as contract_file:
        loaded = json.load(contract_file, object_pairs_hook=_unique_json_pairs)
    if not isinstance(loaded, dict):
        raise AssertionError("event schema root must be an object")
    return loaded


def _resolve_local_ref(document: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise AssertionError(f"non-local reference is not allowed: {reference}")
    current: Any = document
    for encoded_part in reference[2:].split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise AssertionError(f"unresolved local reference: {reference}")
        current = current[part]
    return current


def _walk_local_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            yield reference
        for child in value.values():
            yield from _walk_local_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_local_refs(child)


def _schema_property_names(
    document: dict[str, Any], schema: Any, seen_refs: set[str] | None = None
) -> set[str]:
    """Collect property names from a schema and all locally referenced schemas."""

    if seen_refs is None:
        seen_refs = set()
    if isinstance(schema, list):
        names: set[str] = set()
        for child in schema:
            names.update(_schema_property_names(document, child, seen_refs))
        return names
    if not isinstance(schema, dict):
        return set()

    names = set(schema.get("properties", {}))
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference not in seen_refs:
        seen_refs.add(reference)
        names.update(
            _schema_property_names(
                document,
                _resolve_local_ref(document, reference),
                seen_refs,
            )
        )
    for keyword in ("allOf", "anyOf", "oneOf"):
        names.update(_schema_property_names(document, schema.get(keyword, []), seen_refs))
    for child in schema.get("properties", {}).values():
        names.update(_schema_property_names(document, child, seen_refs))
    names.update(_schema_property_names(document, schema.get("items"), seen_refs))
    return names


def _direct_local_refs(value: Any) -> set[str]:
    return {reference for reference in _walk_local_refs(value) if reference.startswith("#/")}


class IamOpenApiContractTest(unittest.TestCase):
    """TEST-API-IAM-001 and TEST-API-IAM-PROTOCOL-001."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load_openapi()
        cls.schemas = cls.contract["components"]["schemas"]

    def operation(self, path: str, method: str) -> dict[str, Any]:
        return self.contract["paths"][path][method]

    @staticmethod
    def parameter_component_names(operation: dict[str, Any]) -> set[str]:
        names = set()
        for parameter in operation.get("parameters", []):
            reference = parameter.get("$ref")
            if isinstance(reference, str):
                names.add(reference.rsplit("/", 1)[-1])
        return names

    def dereference(self, value: Any) -> Any:
        seen: set[str] = set()
        while isinstance(value, dict) and isinstance(value.get("$ref"), str):
            reference = value["$ref"]
            self.assertNotIn(reference, seen, f"cyclic reference: {reference}")
            seen.add(reference)
            value = _resolve_local_ref(self.contract, reference)
        return value

    def assert_no_store(self, path: str, method: str, status: str) -> None:
        response = self.dereference(self.operation(path, method)["responses"][status])
        cache_header = self.dereference(response["headers"]["Cache-Control"])
        self.assertEqual(cache_header["schema"]["const"], "no-store")

    def test_openapi_31_parses_and_all_local_references_resolve(self) -> None:
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertEqual(
            self.contract["jsonSchemaDialect"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        references = list(_walk_local_refs(self.contract))
        self.assertTrue(references)
        for reference in references:
            with self.subTest(reference=reference):
                _resolve_local_ref(self.contract, reference)

    def test_contract_status_matches_executable_contract_evidence(self) -> None:
        self.assertEqual(
            self.contract["info"]["x-contract-status"],
            "contract-tests-green-implementation-in-progress",
        )
        description = self.contract["info"]["description"].casefold()
        self.assertNotIn("pre-red", description)
        self.assertIn("synthetic", description)

    def test_operation_ids_are_present_and_unique(self) -> None:
        operation_ids: list[str] = []
        for path_item in self.contract["paths"].values():
            for method, operation in path_item.items():
                if method not in {"get", "post", "put", "patch", "delete"}:
                    continue
                self.assertIn("responses", operation)
                self.assertIn("operationId", operation)
                operation_ids.append(operation["operationId"])
        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        self.assertEqual(len(operation_ids), 25)

    def test_all_typed_object_schemas_are_closed(self) -> None:
        object_schemas = {
            name: schema
            for name, schema in self.schemas.items()
            if schema.get("type") == "object"
        }
        self.assertTrue(object_schemas)
        for name, schema in object_schemas.items():
            with self.subTest(schema=name):
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertLessEqual(
                    set(schema.get("required", [])),
                    set(schema.get("properties", {})),
                )

    def test_exact_iam_path_surface_is_published(self) -> None:
        expected_paths = {
            "/v1/auth/oidc/authorizations",
            "/v1/auth/oidc/callback",
            "/v1/auth/session",
            "/v1/access-invitations/inspect",
            "/v1/access-invitations/{invitation_id}/accept",
            "/v1/access-invitations/{invitation_id}/revoke",
            "/v1/policy-bundles/{policy_bundle_id}",
            "/v1/me",
            "/v1/me/policy-acceptances",
            "/v1/me/consents",
            "/v1/me/consents/{consent_grant_id}/withdraw",
            "/v1/me/sessions",
            "/v1/me/sessions/{session_id}",
            "/v1/organizations/{organization_id}",
            "/v1/organizations/{organization_id}/public-name",
            "/v1/organizations/{organization_id}/access-invitations",
            "/v1/organizations/{organization_id}/memberships",
            "/v1/memberships/{membership_id}/suspend",
            "/v1/memberships/{membership_id}/resume",
            "/v1/memberships/{membership_id}/revoke",
            "/v1/platform/users/{user_id}/suspend",
            "/v1/platform/users/{user_id}/resume",
            "/v1/platform/users/{user_id}/revoke-all-sessions",
        }
        self.assertEqual(set(self.contract["paths"]), expected_paths)

    def test_accept_has_no_token_while_capability_fields_use_one_name(self) -> None:
        accept = self.schemas["AcceptAccessInvitationRequest"]
        accept_property_names = _schema_property_names(self.contract, accept)
        self.assertFalse(
            {name for name in accept_property_names if "token" in name.casefold()}
        )

        capability_field = "access_invitation_token"
        begin = self.schemas["BeginOidcAuthorizationRequest"]
        inspect = self.schemas["InspectAccessInvitationRequest"]
        issue = self.schemas["IssueAccessInvitationResponse"]
        begin_token = begin["properties"][capability_field]
        inspect_token = inspect["properties"][capability_field]
        issue_token = issue["properties"][capability_field]
        protocol_secret_ref = "#/components/schemas/ProtocolSecret"
        capability_response_ref = "#/components/schemas/CapabilityTokenResponse"
        self.assertIn(protocol_secret_ref, _direct_local_refs(begin_token))
        self.assertEqual(inspect_token["$ref"], protocol_secret_ref)
        self.assertEqual(issue_token["$ref"], capability_response_ref)
        self.assertNotIn("access_token", inspect["properties"])
        self.assertNotIn("join_token", issue["properties"])

        legacy_capability_fields = {"access_token", "invitation_token", "join_token"}
        for schema_name, schema in self.schemas.items():
            with self.subTest(schema=schema_name):
                self.assertTrue(
                    legacy_capability_fields.isdisjoint(schema.get("properties", {}))
                )

    def test_oidc_begin_models_cookie_or_anonymous_identity_binding(self) -> None:
        begin = self.operation("/v1/auth/oidc/authorizations", "post")
        self.assertEqual(begin["security"], [{"cookieAuth": []}, {}])
        self.assertEqual(
            begin["x-auth-purpose-matrix"],
            {
                "anonymous_without_invitation": "LOGIN",
                "anonymous_with_invitation": "ENROLLMENT",
                "cookie_without_invitation_and_reauthenticate_false": "INVALID",
                "cookie_without_invitation_and_reauthenticate_true": "STEP_UP",
                "cookie_with_invitation": "STEP_UP",
            },
        )
        self.assertEqual(
            begin["x-step-up-expected-user-source"],
            "current_session.user_id",
        )
        description = begin["description"]
        for expected in ("LOGIN", "ENROLLMENT", "STEP_UP", "expected User"):
            with self.subTest(expected=expected):
                self.assertIn(expected, description)

        token_schema = self.schemas["BeginOidcAuthorizationRequest"]["properties"][
            "access_invitation_token"
        ]
        self.assertEqual(token_schema["$ref"], "#/components/schemas/ProtocolSecret")

    def test_access_invitation_contract_has_exactly_one_target_role(self) -> None:
        for schema_name in (
            "AccessInvitationPreviewDto",
            "AccessInvitationAdminDto",
            "IssueOrganizationAccessInvitationRequest",
        ):
            schema = self.schemas[schema_name]
            properties = set(schema["properties"])
            with self.subTest(schema=schema_name):
                self.assertIn("target_role", properties)
                self.assertNotIn("roles", properties)
                self.assertNotIn("target_roles", properties)
                self.assertIn("target_role", schema["required"])

        preview = self.schemas["AccessInvitationPreviewDto"]
        self.assertIn("aggregate_version", preview["properties"])
        self.assertIn("aggregate_version", preview["required"])
        organization = preview["properties"]["organization"]
        self.assertIn(
            "#/components/schemas/OrganizationInvitationPreviewDto",
            _direct_local_refs(organization),
        )
        minimal_organization = self.schemas["OrganizationInvitationPreviewDto"]
        self.assertEqual(set(minimal_organization["properties"]), {"public_name"})
        self.assertEqual(set(minimal_organization["required"]), {"public_name"})

        admin = self.schemas["AccessInvitationAdminDto"]
        reloadable_admin_fields = {
            "required_policy_bundle_id",
            "aggregate_version",
            "entity_tag",
        }
        self.assertTrue(reloadable_admin_fields.issubset(admin["properties"]))
        self.assertTrue(reloadable_admin_fields.issubset(admin["required"]))

    def test_consent_choice_is_closed_and_cannot_author_derived_fields(self) -> None:
        choice = self.schemas["ConsentOfferChoiceInput"]
        self.assertIs(choice["additionalProperties"], False)
        expected = {
            "consent_offer_id",
            "document_id",
            "content_sha256",
            "affirmed",
        }
        self.assertEqual(set(choice["properties"]), expected)
        self.assertEqual(set(choice["required"]), expected)
        self.assertTrue(choice["properties"]["affirmed"]["const"])

    def test_consent_offer_discloses_safe_terms_and_commits_all_derived_facts(self) -> None:
        offer = self.schemas["ConsentOfferDto"]
        required_terms = {
            "recipient_label",
            "expiry_rule",
            "not_after",
            "canonical_offer_sha256",
        }
        self.assertTrue(required_terms.issubset(offer["properties"]))
        self.assertTrue(required_terms.issubset(offer["required"]))
        self.assertNotIn("recipient_reference", offer["properties"])
        self.assertNotIn("recipient_ref", offer["properties"])
        self.assertEqual(
            offer["properties"]["canonical_offer_sha256"]["$ref"],
            "#/components/schemas/ContentSha256",
        )

    def test_me_policy_requirements_are_selector_and_scope_aware(self) -> None:
        requirements = self.schemas["MeDto"]["properties"]["policy_requirements"]
        self.assertEqual(requirements["type"], "array")
        self.assertEqual(
            requirements["items"]["$ref"],
            "#/components/schemas/PolicyRequirementStatusDto",
        )
        requirement = self.schemas["PolicyRequirementStatusDto"]
        scoped_fields = {
            "selector_digest",
            "purpose",
            "role",
            "scope_type",
            "scope_id",
            "satisfied",
            "required_policy_bundle_id",
            "missing_document_ids",
        }
        self.assertEqual(set(requirement["properties"]), scoped_fields)
        self.assertEqual(set(requirement["required"]), scoped_fields)
        self.assertEqual(
            requirement["properties"]["role"]["$ref"],
            "#/components/schemas/RoleCode",
        )

    def test_my_consent_list_is_a_reloadable_grant_etag_source(self) -> None:
        operation = self.operation("/v1/me/consents", "get")
        self.assertEqual(operation["security"], [{"cookieAuth": []}])
        self.assertEqual(
            self.parameter_component_names(operation),
            {"Cursor", "Limit"},
        )
        response = operation["responses"]["200"]
        schema = response["content"]["application/json"]["schema"]
        self.assertEqual(schema["$ref"], "#/components/schemas/ConsentGrantPageDto")
        page = self.schemas["ConsentGrantPageDto"]
        self.assertEqual(
            page["properties"]["items"]["items"]["$ref"],
            "#/components/schemas/ConsentGrantDto",
        )
        grant = self.schemas["ConsentGrantDto"]
        self.assertIn("entity_tag", grant["required"])
        self.assertNotIn("recipient_reference", grant["properties"])
        self.assertNotIn("recipient_ref", grant["properties"])
        self.assert_no_store("/v1/me/consents", "get", "200")

    def test_database_access_profiles_are_narrow_and_reachable(self) -> None:
        profiles = self.contract["x-iam-database-access"]
        self.assertEqual(
            set(profiles),
            {"ME_SELF_SUMMARY", "PUBLIC_POLICY_READ", "POLICY_PUBLISH"},
        )

        me_profile = profiles["ME_SELF_SUMMARY"]
        self.assertEqual(me_profile["operation_id"], "getMe")
        self.assertEqual(me_profile["mode"], "SECURITY_DEFINER")
        self.assertEqual(me_profile["database_role"], "iam_app")
        self.assertEqual(me_profile["rls_scope"], "SELF")
        self.assertEqual(
            me_profile["search_path"],
            ["pg_catalog", "iam", "pg_temp"],
        )
        self.assertIs(me_profile["dynamic_sql"], False)
        self.assertIs(me_profile["public_execute"], False)
        self.assertEqual(me_profile["execute_grantees"], ["iam_app"])
        self.assertIs(me_profile["direct_organization_read"], False)
        self.assertEqual(
            set(me_profile["organization_field_allowlist"]),
            {
                "organization_id",
                "public_name",
                "type",
                "status",
                "aggregate_version",
            },
        )

        public_policy = profiles["PUBLIC_POLICY_READ"]
        self.assertEqual(public_policy["operation_id"], "getPolicyBundle")
        self.assertEqual(public_policy["database_role"], "iam_app")
        self.assertEqual(public_policy["rls_scope"], "PUBLIC_POLICY_READ")
        self.assertEqual(public_policy["scope_keys"], ["policy_bundle_id"])
        self.assertEqual(public_policy["allowed_statuses"], ["ACTIVE"])
        self.assertEqual(
            public_policy["relations"],
            ["policy_bundles", "policy_documents", "consent_offers"],
        )
        self.assertIs(public_policy["immutable_only"], True)
        self.assertIs(public_policy["global_scope"], False)

        policy_publish = profiles["POLICY_PUBLISH"]
        self.assertEqual(policy_publish["application_command"], "PublishPolicyBundle")
        self.assertEqual(policy_publish["database_role"], "iam_system")
        self.assertEqual(policy_publish["rls_scope"], "POLICY_PUBLISH")
        self.assertEqual(
            policy_publish["scope_keys"],
            ["selector_digest", "policy_bundle_id"],
        )
        self.assertIs(policy_publish["global_scope"], False)
        self.assertEqual(policy_publish["activation_entrypoint"], "application_command")
        self.assertEqual(
            policy_publish["initial_release_entrypoint"],
            "PublishPolicyBundle",
        )
        self.assertIs(policy_publish["fixture_direct_activation"], False)
        self.assertIs(policy_publish["migration_direct_activation"], False)

    def test_sensitive_protocol_carriers_have_machine_readable_log_policy(self) -> None:
        def assert_sensitive(schema: dict[str, Any], label: str) -> None:
            with self.subTest(carrier=label):
                self.assertIs(schema.get("x-sensitive"), True)
                self.assertEqual(schema.get("x-log-policy"), "redact")

        for schema_name in (
            "CsrfToken",
            "ProtocolSecret",
            "CapabilityTokenResponse",
        ):
            assert_sensitive(self.schemas[schema_name], schema_name)

        direct_properties = (
            (
                self.schemas["BeginOidcAuthorizationRequest"]["properties"][
                    "access_invitation_token"
                ],
                "begin.access_invitation_token",
            ),
            (
                self.schemas["InspectAccessInvitationRequest"]["properties"][
                    "access_invitation_token"
                ],
                "inspect.access_invitation_token",
            ),
            (
                self.schemas["IssueAccessInvitationResponse"]["properties"][
                    "access_invitation_token"
                ],
                "issue.access_invitation_token",
            ),
            (
                self.schemas["BeginOidcAuthorizationResponse"]["properties"][
                    "authorization_url"
                ],
                "authorization_url",
            ),
            (
                self.schemas["IssueAccessInvitationResponse"]["properties"][
                    "join_fragment_url"
                ],
                "join_fragment_url",
            ),
            (
                self.schemas["SessionBootstrapDto"]["properties"]["csrf_token"],
                "session.csrf_token",
            ),
        )
        for schema, label in direct_properties:
            assert_sensitive(schema, label)

        assert_sensitive(
            self.contract["components"]["securitySchemes"]["cookieAuth"],
            "cookieAuth",
        )
        assert_sensitive(
            self.contract["components"]["parameters"]["CsrfToken"],
            "X-CSRF-Token",
        )

        callback = self.operation("/v1/auth/oidc/callback", "get")
        callback_parameters = {
            parameter["name"]: parameter for parameter in callback["parameters"]
        }
        for parameter_name in ("state", "code", "error_description"):
            assert_sensitive(
                callback_parameters[parameter_name]["schema"],
                f"callback.{parameter_name}",
            )

        for path, method, status in (
            ("/v1/auth/oidc/callback", "get", "303"),
            ("/v1/access-invitations/{invitation_id}/accept", "post", "200"),
        ):
            response = self.dereference(self.operation(path, method)["responses"][status])
            assert_sensitive(response["headers"]["Set-Cookie"]["schema"], f"{path}.cookie")

        info_description = self.contract["info"]["description"]
        self.assertIn("explicit no-store protocol responses", info_description)

    def test_hold_block_and_unavailable_have_distinct_contract_codes(self) -> None:
        error_codes = set(self.schemas["ErrorCode"]["enum"])
        self.assertIn("SAFETY_HOLD_BLOCKED", error_codes)
        self.assertIn("SAFETY_DECISION_UNAVAILABLE", error_codes)
        for path, method in (
            ("/v1/access-invitations/{invitation_id}/accept", "post"),
            ("/v1/organizations/{organization_id}/access-invitations", "post"),
            ("/v1/memberships/{membership_id}/resume", "post"),
        ):
            operation = self.operation(path, method)
            with self.subTest(path=path):
                self.assertEqual(
                    operation["responses"]["403"]["$ref"],
                    "#/components/responses/HoldAwareForbidden",
                )
                self.assertEqual(
                    operation["responses"]["503"]["$ref"],
                    "#/components/responses/HoldAwareServiceUnavailable",
                )

        forbidden = self.contract["components"]["responses"]["HoldAwareForbidden"]
        service_unavailable = self.contract["components"]["responses"][
            "HoldAwareServiceUnavailable"
        ]
        self.assertIn("SAFETY_HOLD_BLOCKED", forbidden["x-error-codes"])
        self.assertNotIn("SAFETY_DECISION_UNAVAILABLE", forbidden["x-error-codes"])
        self.assertIn(
            "SAFETY_DECISION_UNAVAILABLE",
            service_unavailable["x-error-codes"],
        )
        self.assertNotIn(
            "SAFETY_HOLD_BLOCKED",
            service_unavailable["x-error-codes"],
        )

        blocked = self.schemas["SafetyHoldBlockedError"]
        unavailable = self.schemas["SafetyDecisionUnavailableError"]
        self.assertEqual(blocked["properties"]["code"]["const"], "SAFETY_HOLD_BLOCKED")
        self.assertEqual(
            unavailable["properties"]["code"]["const"],
            "SAFETY_DECISION_UNAVAILABLE",
        )

    def test_mutating_endpoints_publish_concurrency_and_csrf_controls(self) -> None:
        fully_guarded = (
            ("/v1/access-invitations/{invitation_id}/accept", "post"),
            ("/v1/access-invitations/{invitation_id}/revoke", "post"),
            ("/v1/me/policy-acceptances", "post"),
            ("/v1/me/consents", "post"),
            ("/v1/me/consents/{consent_grant_id}/withdraw", "post"),
            ("/v1/organizations/{organization_id}/access-invitations", "post"),
            ("/v1/organizations/{organization_id}/public-name", "post"),
            ("/v1/memberships/{membership_id}/suspend", "post"),
            ("/v1/memberships/{membership_id}/resume", "post"),
            ("/v1/memberships/{membership_id}/revoke", "post"),
        )
        required = {"IdempotencyKey", "IfMatch", "CsrfToken"}
        for path, method in fully_guarded:
            with self.subTest(path=path):
                self.assertTrue(
                    required.issubset(
                        self.parameter_component_names(self.operation(path, method))
                    )
                )

        revoke_session = self.operation("/v1/me/sessions/{session_id}", "delete")
        revoke_parameters = self.parameter_component_names(revoke_session)
        self.assertTrue({"IdempotencyKey", "CsrfToken"}.issubset(revoke_parameters))
        self.assertNotIn("IfMatch", revoke_parameters)

    def test_etag_sources_and_sensitive_success_responses_are_explicit(self) -> None:
        etag_responses = (
            ("/v1/access-invitations/inspect", "post", "200"),
            ("/v1/access-invitations/{invitation_id}/accept", "post", "200"),
            ("/v1/access-invitations/{invitation_id}/revoke", "post", "200"),
            ("/v1/me", "get", "200"),
            ("/v1/me/policy-acceptances", "post", "200"),
            ("/v1/me/consents", "post", "201"),
            ("/v1/me/consents/{consent_grant_id}/withdraw", "post", "200"),
            ("/v1/organizations/{organization_id}", "get", "200"),
            ("/v1/organizations/{organization_id}/public-name", "post", "200"),
            (
                "/v1/organizations/{organization_id}/access-invitations",
                "post",
                "201",
            ),
            ("/v1/memberships/{membership_id}/suspend", "post", "200"),
            ("/v1/memberships/{membership_id}/resume", "post", "200"),
            ("/v1/memberships/{membership_id}/revoke", "post", "200"),
        )
        for path, method, status in etag_responses:
            response = self.dereference(self.operation(path, method)["responses"][status])
            with self.subTest(path=path, status=status):
                self.assertIn("ETag", response["headers"])

        for schema_name in (
            "MeDto",
            "OrganizationSummaryDto",
            "MembershipSelfDto",
            "MembershipAdminDto",
            "AccessInvitationPreviewDto",
            "AccessInvitationAdminDto",
            "ConsentGrantDto",
        ):
            with self.subTest(schema=schema_name):
                self.assertIn("entity_tag", self.schemas[schema_name]["properties"])
                self.assertIn("entity_tag", self.schemas[schema_name]["required"])

        no_store_responses = (
            ("/v1/auth/oidc/authorizations", "post", "201"),
            ("/v1/auth/oidc/callback", "get", "303"),
            ("/v1/auth/session", "get", "200"),
            ("/v1/access-invitations/inspect", "post", "200"),
            ("/v1/access-invitations/{invitation_id}/accept", "post", "200"),
            ("/v1/access-invitations/{invitation_id}/revoke", "post", "200"),
            ("/v1/me", "get", "200"),
            ("/v1/me/policy-acceptances", "post", "200"),
            ("/v1/me/consents", "get", "200"),
            ("/v1/me/consents", "post", "201"),
            ("/v1/me/consents/{consent_grant_id}/withdraw", "post", "200"),
            ("/v1/me/sessions", "get", "200"),
            ("/v1/me/sessions/{session_id}", "delete", "204"),
            ("/v1/organizations/{organization_id}", "get", "200"),
            ("/v1/organizations/{organization_id}/public-name", "post", "200"),
            (
                "/v1/organizations/{organization_id}/access-invitations",
                "get",
                "200",
            ),
            (
                "/v1/organizations/{organization_id}/access-invitations",
                "post",
                "201",
            ),
            ("/v1/organizations/{organization_id}/memberships", "get", "200"),
            ("/v1/memberships/{membership_id}/suspend", "post", "200"),
            ("/v1/memberships/{membership_id}/resume", "post", "200"),
            ("/v1/memberships/{membership_id}/revoke", "post", "200"),
        )
        for path, method, status in no_store_responses:
            with self.subTest(path=path, status=status):
                self.assert_no_store(path, method, status)

    def test_public_name_correction_is_one_closed_same_resource_contract(self) -> None:
        operation = self.operation(
            "/v1/organizations/{organization_id}/public-name", "post"
        )
        self.assertEqual(operation["operationId"], "updateOrganizationPublicName")
        request_schema = self.dereference(
            operation["requestBody"]["content"]["application/json"]["schema"]
        )
        self.assertEqual(
            set(request_schema["properties"]), {"public_name", "reason_code"}
        )
        self.assertEqual(
            set(request_schema["required"]), {"public_name", "reason_code"}
        )
        self.assertIs(request_schema["additionalProperties"], False)
        self.assertEqual(
            request_schema["properties"]["reason_code"]["const"],
            "PUBLIC_NAME_CORRECTION",
        )
        response = self.dereference(operation["responses"]["200"])
        response_schema = response["content"]["application/json"]["schema"]
        self.assertEqual(
            response_schema["$ref"], "#/components/schemas/OrganizationSummaryDto"
        )
        stale = self.dereference(operation["responses"]["412"])
        self.assertIn("ETag", stale["headers"])


class IamEventSchemaContractTest(unittest.TestCase):
    """TEST-EVENT-AUDIT-IAM-001 schema and privacy checks."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load_event_schema()
        cls.definitions = cls.contract["$defs"]

    def test_draft_2020_12_json_and_all_local_references_resolve(self) -> None:
        self.assertEqual(
            self.contract["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        references = list(_walk_local_refs(self.contract))
        self.assertTrue(references)
        for reference in references:
            with self.subTest(reference=reference):
                _resolve_local_ref(self.contract, reference)

    def test_exact_event_type_vocabulary_and_root_variants_are_published(self) -> None:
        expected_event_types = {
            "OrganizationBootstrapped",
            "OrganizationActivated",
            "OrganizationSuspended",
            "OrganizationResumed",
            "OrganizationClosed",
            "OrganizationPublicNameChanged",
            "AccessInvitationIssued",
            "AccessInvitationAccepted",
            "AccessInvitationRevoked",
            "AccessInvitationExpired",
            "UserEnrollmentStarted",
            "UserActivated",
            "PendingEnrollmentExpired",
            "UserSuspended",
            "UserResumed",
            "UserClosed",
            "UserRoleGranted",
            "MembershipActivated",
            "MembershipRoleGranted",
            "MembershipSuspended",
            "MembershipResumed",
            "MembershipRevoked",
            "MembershipRolesRevoked",
            "PolicyAccepted",
            "PolicyRequirementsSatisfied",
            "PolicyBundlePublished",
            "PolicyBundleSuperseded",
            "ConsentGranted",
            "ConsentWithdrawn",
            "SessionRevoked",
            "SessionsRevoked",
            "PlatformDutyGranted",
            "PlatformDutyRevoked",
        }
        self.assertEqual(
            set(self.definitions["EventType"]["enum"]),
            expected_event_types,
        )
        self.assertEqual(len(self.contract["oneOf"]), 38)

    def test_public_name_event_is_invalidation_only(self) -> None:
        payload = self.definitions["OrganizationPublicNameChangedPayload"]
        self.assertEqual(set(payload["properties"]), {"organization_id"})
        self.assertEqual(set(payload["required"]), {"organization_id"})
        self.assertIs(payload["additionalProperties"], False)

    def test_all_typed_event_objects_are_closed(self) -> None:
        typed_objects = {
            name: schema
            for name, schema in self.definitions.items()
            if schema.get("type") == "object"
        }
        self.assertTrue(typed_objects)
        for name, schema in typed_objects.items():
            with self.subTest(schema=name):
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertLessEqual(
                    set(schema.get("required", [])),
                    set(schema.get("properties", {})),
                )

    def test_event_properties_cannot_represent_secrets_pii_or_free_text(self) -> None:
        property_names: set[str] = set()
        for schema in self.definitions.values():
            if isinstance(schema, dict):
                property_names.update(schema.get("properties", {}))

        forbidden_fragments = (
            "token",
            "cookie",
            "recipient",
            "contact",
            "subject",
            "csrf",
            "handle",
            "secret",
            "verifier",
            "consent_evidence",
        )
        forbidden_exact = {
            "body",
            "details",
            "error_description",
            "free_text",
            "message",
            "note",
            "notes",
            "policy_body",
            "reason_note",
            "reason_text",
        }
        violations = {
            name
            for name in property_names
            if name in forbidden_exact
            or any(fragment in name for fragment in forbidden_fragments)
        }
        self.assertEqual(violations, set())

    def test_events_use_one_target_role_and_server_derived_consent(self) -> None:
        property_names: set[str] = set()
        for schema in self.definitions.values():
            if isinstance(schema, dict):
                property_names.update(schema.get("properties", {}))
        self.assertIn("target_role", property_names)
        self.assertNotIn("roles", property_names)
        self.assertNotIn("target_roles", property_names)

        derived = self.definitions["DerivedConsentAuthorization"]
        expected_derived_fields = {
            "consent_offer_id",
            "consent_offer_version",
            "policy_bundle_id",
            "purpose",
            "scope_type",
            "scope_id",
            "data_categories",
            "supporting_policy_document_id",
            "supporting_document_sha256",
            "expires_at",
        }
        self.assertEqual(set(derived["properties"]), expected_derived_fields)
        self.assertEqual(set(derived["required"]), expected_derived_fields)


if __name__ == "__main__":
    unittest.main()
