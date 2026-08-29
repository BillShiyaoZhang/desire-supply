"""Contract-first executable gates for Taxonomy & Rule Catalog v1."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator
import unittest

from tests.contract.test_demand_contracts import (
    _SchemaViolation,
    _load,
    _resolve,
    _validate,
    _walk_refs,
)
from tests.support.taxonomy_contract_builders import (
    crosswalk,
    edges,
    event,
    labels,
    nodes,
    release,
)


PLATFORM_ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = PLATFORM_ROOT / "contracts/api/taxonomy-v1.openapi.yaml"
EVENT_PATH = PLATFORM_ROOT / "contracts/events/taxonomy-v1.schema.json"
DOMAIN_PATHS = (
    PLATFORM_ROOT / "contracts/domain/taxonomy-release-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/taxonomy-nodes-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/taxonomy-edges-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/taxonomy-labels-v1.schema.json",
    PLATFORM_ROOT / "contracts/domain/taxonomy-crosswalk-v1.schema.json",
)
ALL_PATHS = (OPENAPI_PATH, EVENT_PATH, *DOMAIN_PATHS)
EVENT_TYPES = (
    "TaxonomyBundlePublished",
    "TaxonomyBundleSuperseded",
    "TaxonomyBundleRetired",
    "TaxonomyCrosswalkPublished",
)
BANNED_FRAGMENTS = (
    "signature_secret",
    "private_key",
    "credential",
    "provider_token",
    "artifact_url",
    "bucket_name",
    "idempotency_key",
    "session_id",
    "contact",
)


def _contract(test: unittest.TestCase, path: Path) -> dict[str, Any]:
    test.assertTrue(path.is_file(), f"missing Taxonomy contract: {path.name}")
    return _load(path)


def _assert_valid(test: unittest.TestCase, path: Path, instance: Any) -> None:
    document = _contract(test, path)
    _validate(document, path, document, instance)


def _assert_invalid(test: unittest.TestCase, path: Path, instance: Any) -> None:
    document = _contract(test, path)
    with test.assertRaises(_SchemaViolation):
        _validate(document, path, document, instance)


def _property_names(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            yield from properties
        for child in value.values():
            yield from _property_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from _property_names(child)


class TaxonomyMachineContractTests(unittest.TestCase):
    """TEST-CONTRACT-TAXONOMY-001 and TEST-SEC-TAXONOMY-001."""

    def test_all_contracts_exist_have_unique_keys_and_resolvable_refs(self) -> None:
        for path in ALL_PATHS:
            with self.subTest(path=path.name):
                document = _contract(self, path)
                for reference in _walk_refs(document):
                    _resolve(document, path, reference)

    def test_openapi_exposes_only_exact_reads_and_two_internal_commands(self) -> None:
        document = _contract(self, OPENAPI_PATH)
        self.assertEqual(document["openapi"], "3.1.0")
        self.assertEqual(
            set(document["paths"]),
            {
                "/v1/taxonomy-bundles/{bundle_id}",
                "/v1/taxonomy-bundles/{bundle_id}/nodes/{code}",
                "/v1/taxonomy-bundles/{bundle_id}/nodes",
                "/v1/taxonomy-bundles/{source_bundle_id}/crosswalks/{target_bundle_id}",
                "/internal/v1/taxonomy-bundles:publish",
                "/internal/v1/taxonomy-bundles/{bundle_id}:retire",
            },
        )
        operation_ids = {
            operation["operationId"]
            for item in document["paths"].values()
            for method, operation in item.items()
            if method in {"get", "post"}
        }
        self.assertEqual(
            operation_ids,
            {
                "getTaxonomyBundle",
                "getTaxonomyNode",
                "listTaxonomyNodes",
                "getTaxonomyCrosswalk",
                "publishTaxonomyBundle",
                "retireTaxonomyBundle",
            },
        )

    def test_openapi_closes_mutations_errors_cache_and_database_profiles(self) -> None:
        document = _contract(self, OPENAPI_PATH)
        schemas = document["components"]["schemas"]
        self.assertIs(schemas["PublishTaxonomyBundleRequest"]["additionalProperties"], False)
        self.assertIs(schemas["RetireTaxonomyBundleRequest"]["additionalProperties"], False)
        for path, item in document["paths"].items():
            operation = item.get("post")
            if operation is not None:
                refs = {parameter.get("$ref") for parameter in operation["parameters"]}
                self.assertIn("#/components/parameters/IdempotencyKey", refs, path)
                self.assertNotIn("#/components/parameters/CsrfToken", refs, path)
            for method, candidate in item.items():
                if method not in {"get", "post"}:
                    continue
                self.assertTrue(candidate["x-error-codes"])
        profiles = document["x-taxonomy-database-access"]
        self.assertEqual(
            set(profiles),
            {
                "PUBLIC_EXACT_TAXONOMY_READ",
                "TAXONOMY_PUBLISH",
                "TAXONOMY_CONSUMER_SYNC",
            },
        )
        for profile in profiles.values():
            self.assertFalse(profile["public_execute"])
            self.assertFalse(profile["dynamic_sql"])
            self.assertEqual(profile["search_path"], ["pg_catalog", "taxonomy", "pg_temp"])

    def test_release_manifest_is_closed_and_rejects_secrets_float_and_bool_integer(self) -> None:
        path = DOMAIN_PATHS[0]
        valid = release()
        _assert_valid(self, path, valid)
        for mutation in (
            lambda value: value.update(release_manifest_sha256="a" * 64),
            lambda value: value["artifacts"][0].update(artifact_url="https://secret.invalid"),
            lambda value: value["selector"].update(semantic_major=True),
            lambda value: value["artifacts"][0].update(item_count=1.5),
            lambda value: value.update(compatibility_level="MINOR_COMPATIBLE"),
        ):
            broken = deepcopy(valid)
            mutation(broken)
            _assert_invalid(self, path, broken)

    def test_nodes_are_closed_and_attribute_value_shape_is_exact(self) -> None:
        path = DOMAIN_PATHS[1]
        valid = nodes()
        _assert_valid(self, path, valid)
        broken = deepcopy(valid)
        broken["nodes"][0]["attributes"][0]["integer_value"] = True
        _assert_invalid(self, path, broken)
        broken = deepcopy(valid)
        broken["nodes"][0]["display_label"] = "not machine meaning"
        _assert_invalid(self, path, broken)

    def test_edges_are_closed_integer_ordinal_and_do_not_accept_free_conditions(self) -> None:
        path = DOMAIN_PATHS[2]
        valid = edges()
        _assert_valid(self, path, valid)
        broken = deepcopy(valid)
        broken["edges"][0]["ordinal"] = True
        _assert_invalid(self, path, broken)
        broken = deepcopy(valid)
        broken["edges"][0]["condition"] = "user supplied"
        _assert_invalid(self, path, broken)

    def test_labels_are_closed_localized_text_without_html_or_locator_fields(self) -> None:
        path = DOMAIN_PATHS[3]
        valid = labels()
        _assert_valid(self, path, valid)
        broken = deepcopy(valid)
        broken["labels"][0]["html"] = "<b>Internal</b>"
        _assert_invalid(self, path, broken)
        broken = deepcopy(valid)
        broken["labels"][0]["short_label"] = "x" * 257
        _assert_invalid(self, path, broken)

    def test_crosswalk_is_closed_and_never_chooses_one_split_target_implicitly(self) -> None:
        path = DOMAIN_PATHS[4]
        valid = crosswalk()
        _assert_valid(self, path, valid)
        broken = deepcopy(valid)
        broken["mappings"][0]["mapping_kind"] = "AUTO_FIRST"
        _assert_invalid(self, path, broken)
        broken = deepcopy(valid)
        broken["mappings"][0]["confidence"] = 0.99
        _assert_invalid(self, path, broken)

    def test_event_schema_accepts_only_four_closed_minimal_events(self) -> None:
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                _assert_valid(self, EVENT_PATH, event(event_type))
                broken = event(event_type)
                broken["payload"]["label"] = "private expansion"
                _assert_invalid(self, EVENT_PATH, broken)

    def test_machine_contract_cannot_represent_credentials_or_storage_locators(self) -> None:
        documents = [_contract(self, path) for path in ALL_PATHS]
        names = {
            name.lower()
            for document in documents
            for name in _property_names(document)
        }
        for banned in BANNED_FRAGMENTS:
            with self.subTest(banned=banned):
                self.assertFalse(any(banned in name for name in names), banned)

    def test_release_artifact_order_is_part_of_fixture_signature_surface(self) -> None:
        value = release()
        order = tuple(
            (descriptor["artifact_kind"], descriptor["locale"] or "")
            for descriptor in value["artifacts"]
        )
        self.assertEqual(order, tuple(sorted(order)))
        self.assertEqual(
            tuple(node["code"] for node in nodes()["nodes"]),
            tuple(
                node["code"]
                for node in sorted(nodes()["nodes"], key=lambda item: (item["kind"].encode(), item["code"].encode()))
            ),
        )


if __name__ == "__main__":
    unittest.main()
