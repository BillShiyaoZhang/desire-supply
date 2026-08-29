"""Contract gates required before IAM read-model application behavior exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import unittest

import yaml


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts" / "api" / "iam-v1.openapi.yaml"

READ_OPERATIONS = {
    ("GET", "/v1/auth/session"): "getSessionBootstrap",
    ("POST", "/v1/access-invitations/inspect"): "inspectAccessInvitation",
    ("GET", "/v1/policy-bundles/{policy_bundle_id}"): "getPolicyBundle",
    ("GET", "/v1/me"): "getMe",
    ("GET", "/v1/me/consents"): "listMyConsentGrants",
    ("GET", "/v1/me/sessions"): "listMySessions",
    ("GET", "/v1/organizations/{organization_id}"): "getOrganizationSummary",
    (
        "GET",
        "/v1/organizations/{organization_id}/access-invitations",
    ): "listOrganizationAccessInvitations",
    (
        "GET",
        "/v1/organizations/{organization_id}/memberships",
    ): "listOrganizationMemberships",
}


def _load_openapi() -> dict[str, Any]:
    with OPENAPI_PATH.open(encoding="utf-8") as source:
        document = yaml.safe_load(source)
    if not isinstance(document, dict):
        raise AssertionError("OpenAPI root must be an object")
    return document


class IamReadModelContractTests(unittest.TestCase):
    def test_every_read_operation_declares_fail_closed_service_unavailable(self) -> None:
        document = _load_openapi()
        for (method, path), operation_id in READ_OPERATIONS.items():
            with self.subTest(operation_id=operation_id):
                operation = document["paths"][path][method.lower()]
                self.assertEqual(operation["operationId"], operation_id)
                self.assertEqual(
                    operation["responses"].get("503"),
                    {"$ref": "#/components/responses/ServiceUnavailable"},
                )

    def test_v1_deliberately_has_no_conditional_get_contract(self) -> None:
        document = _load_openapi()
        self.assertNotIn("IfNoneMatch", document["components"]["parameters"])
        for (method, path), operation_id in READ_OPERATIONS.items():
            with self.subTest(operation_id=operation_id):
                operation = document["paths"][path][method.lower()]
                self.assertNotIn("304", operation["responses"])
                parameters = operation.get("parameters", [])
                self.assertFalse(
                    any(
                        parameter.get("name", "").lower() == "if-none-match"
                        for parameter in parameters
                        if isinstance(parameter, dict)
                    )
                )


if __name__ == "__main__":
    unittest.main()
