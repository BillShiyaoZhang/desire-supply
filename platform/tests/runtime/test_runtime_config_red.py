from __future__ import annotations

import json
import pathlib
import unittest
from dataclasses import FrozenInstanceError

from desire_platform.runtime.config import (
    RuntimeConfigurationError,
    parse_runtime_config,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "contracts" / "config" / "runtime-config-v1.schema.json"
SECRET_REF = "secret://prod-db/iam-web#2026-08"


def valid_document() -> dict:
    return {
        "schema_name": "desire-runtime-config-v1",
        "identity": {
            "environment_id": "production-cn",
            "deployment_id": "deploy-20260808",
            "release_id": "release-20260808-1",
            "region": "cn-east-1",
            "instance_id": "web-api-0001",
        },
        "process": {
            "kind": "web-api",
            "capability_ids": ["IAM_HTTP", "PROFILE_SELF"],
        },
        "artifacts": [
            {"artifact_id": "iam-openapi-v1", "sha256": "a" * 64},
            {"artifact_id": "profile-openapi-v1", "sha256": "b" * 64},
        ],
        "database_profiles": [
            {
                "capability_id": "IAM_HTTP",
                "online_role": "iam_app",
                "credential_ref": SECRET_REF,
                "application_name": "desire-web-iam",
                "max_pool_size": 8,
                "checkout_timeout_ms": 500,
                "statement_timeout_ms": 5000,
                "lock_timeout_ms": 500,
                "idle_in_transaction_timeout_ms": 5000,
            },
            {
                "capability_id": "PROFILE_SELF",
                "online_role": "profile_app",
                "credential_ref": "secret://prod-db/profile-web#2026-08",
                "application_name": "desire-web-profile",
                "max_pool_size": 4,
                "checkout_timeout_ms": 500,
                "statement_timeout_ms": 5000,
                "lock_timeout_ms": 500,
                "idle_in_transaction_timeout_ms": 5000,
            },
        ],
        "key_requirements": [
            {
                "purpose": "SESSION_HANDLE",
                "active_key_id": "session-2026-08",
                "retained_key_ids": ["session-2026-07", "session-2026-08"],
            },
            {
                "purpose": "CSRF",
                "active_key_id": "csrf-2026-08",
                "retained_key_ids": ["csrf-2026-08"],
            },
        ],
        "budgets": {
            "startup_timeout_ms": 30000,
            "readiness_timeout_ms": 2000,
            "shutdown_timeout_ms": 15000,
        },
    }


def encode(document: dict) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class RuntimeConfigurationContractTests(unittest.TestCase):
    def test_machine_schema_is_closed_and_importable(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "schema_name",
                "identity",
                "process",
                "artifacts",
                "database_profiles",
                "key_requirements",
                "budgets",
            },
        )
        for name, definition in schema["$defs"].items():
            if definition.get("type") == "object":
                with self.subTest(definition=name):
                    self.assertIs(definition.get("additionalProperties"), False)

    def test_exact_document_parses_to_frozen_detached_secret_safe_facts(self) -> None:
        try:
            config = parse_runtime_config(encode(valid_document()))
        except RuntimeConfigurationError as error:
            self.assertEqual(
                ("ok", None),
                ("error", error.code),
                "semantic RED: the exact closed runtime document must parse",
            )
            return
        self.assertEqual(config.schema_name, "desire-runtime-config-v1")
        self.assertEqual(config.process.kind, "web-api")
        self.assertEqual(config.process.capability_ids, ("IAM_HTTP", "PROFILE_SELF"))
        self.assertIsInstance(config.artifacts, tuple)
        self.assertIsInstance(config.database_profiles, tuple)
        self.assertIsInstance(config.key_requirements, tuple)
        self.assertEqual(config.database_profiles[0].online_role, "iam_app")
        self.assertEqual(
            config.key_requirements[0].retained_key_ids,
            ("session-2026-07", "session-2026-08"),
        )
        with self.assertRaises(FrozenInstanceError):
            config.identity.region = "mutated"  # type: ignore[misc]
        self.assertNotIn(SECRET_REF, repr(config))

    def test_malformed_or_open_json_fails_closed_before_returning_facts(self) -> None:
        base = valid_document()
        unknown = valid_document()
        unknown["debug"] = True
        nested_unknown = valid_document()
        nested_unknown["budgets"]["retry_forever"] = True
        float_budget = valid_document()
        float_budget["budgets"]["startup_timeout_ms"] = 30000.0
        boolean_budget = valid_document()
        boolean_budget["budgets"]["startup_timeout_ms"] = True
        non_nfc = valid_document()
        non_nfc["identity"]["environment_id"] = "e\u0301"
        surrounding_space = valid_document()
        surrounding_space["identity"]["region"] = " cn-east-1"
        cases = {
            "invalid-utf8": b"\xff",
            "oversized": b" " * (256 * 1024 + 1),
            "duplicate-top-level": (
                b'{"schema_name":"desire-runtime-config-v1",'
                b'"schema_name":"desire-runtime-config-v1"}'
            ),
            "duplicate-nested": encode(base).replace(
                b'"kind":"web-api"',
                b'"kind":"web-api","kind":"web-api"',
            ),
            "unknown-top-level": encode(unknown),
            "unknown-nested": encode(nested_unknown),
            "float": encode(float_budget),
            "boolean-as-integer": encode(boolean_budget),
            "nan": encode(base).replace(b"30000", b"NaN", 1),
            "non-nfc": encode(non_nfc),
            "surrounding-space": encode(surrounding_space),
            "surrogate": encode(base).replace(b"production-cn", b"\\ud800"),
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(RuntimeConfigurationError) as raised:
                    parse_runtime_config(raw)
                self.assertEqual(raised.exception.code, "INVALID_RUNTIME_CONFIGURATION")
                self.assertNotIn(SECRET_REF, repr(raised.exception))

    def test_uniqueness_ranges_secret_locator_and_active_retention_are_enforced(self) -> None:
        cases = []
        duplicate_capability = valid_document()
        duplicate_capability["process"]["capability_ids"].append("IAM_HTTP")
        cases.append(duplicate_capability)
        duplicate_artifact = valid_document()
        duplicate_artifact["artifacts"].append(dict(duplicate_artifact["artifacts"][0]))
        cases.append(duplicate_artifact)
        duplicate_profile = valid_document()
        duplicate_profile["database_profiles"].append(
            dict(duplicate_profile["database_profiles"][0])
        )
        cases.append(duplicate_profile)
        shared_credential = valid_document()
        shared_credential["database_profiles"][1]["credential_ref"] = (
            shared_credential["database_profiles"][0]["credential_ref"]
        )
        cases.append(shared_credential)
        shared_application_name = valid_document()
        shared_application_name["database_profiles"][1]["application_name"] = (
            shared_application_name["database_profiles"][0]["application_name"]
        )
        cases.append(shared_application_name)
        duplicate_key_purpose = valid_document()
        duplicate_key_purpose["key_requirements"].append(
            dict(duplicate_key_purpose["key_requirements"][0])
        )
        cases.append(duplicate_key_purpose)
        active_not_retained = valid_document()
        active_not_retained["key_requirements"][0]["retained_key_ids"] = [
            "session-2026-07"
        ]
        cases.append(active_not_retained)
        raw_dsn = valid_document()
        raw_dsn["database_profiles"][0]["credential_ref"] = (
            "postgresql://user:password@db.example/production"
        )
        cases.append(raw_dsn)
        query_locator = valid_document()
        query_locator["database_profiles"][0]["credential_ref"] = (
            "secret://prod-db/iam-web#2026-08?token=raw"
        )
        cases.append(query_locator)
        zero_pool = valid_document()
        zero_pool["database_profiles"][0]["max_pool_size"] = 0
        cases.append(zero_pool)
        excessive_timeout = valid_document()
        excessive_timeout["database_profiles"][0]["statement_timeout_ms"] = 120001
        cases.append(excessive_timeout)
        for index, document in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeConfigurationError) as raised:
                    parse_runtime_config(encode(document))
                self.assertEqual(raised.exception.code, "INVALID_RUNTIME_CONFIGURATION")


if __name__ == "__main__":
    unittest.main()
