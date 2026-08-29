"""Secret-free canonical fixtures for Taxonomy machine-contract gates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
NOW = "2035-01-01T00:00:00Z"
BUNDLE_ID = "taxonomy_bundle_0000001"
SUCCESSOR_ID = "taxonomy_bundle_0000002"


def release() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "taxonomy-release-json-v1",
        "bundle_id": BUNDLE_ID,
        "family_code": "PLATFORM_WORK_V1",
        "semantic_version": "1.0.0",
        "selector": {
            "jurisdiction_code": "JURISDICTION.CN",
            "locale_set_digest": SHA_A,
            "semantic_major": 1,
            "intended_consumer_set_digest": SHA_B,
            "selector_digest": SHA_C,
        },
        "compatibility_level": "INITIAL",
        "predecessor_bundle_id": None,
        "effective_at": NOW,
        "effective_until": None,
        "artifacts": [
            {
                "artifact_kind": "EDGES",
                "schema_name": "taxonomy-edges-v1",
                "locale": None,
                "sha256": SHA_A,
                "item_count": 1,
            },
            {
                "artifact_kind": "LABELS",
                "schema_name": "taxonomy-labels-v1",
                "locale": "en",
                "sha256": SHA_B,
                "item_count": 3,
            },
            {
                "artifact_kind": "LABELS",
                "schema_name": "taxonomy-labels-v1",
                "locale": "zh-CN",
                "sha256": SHA_C,
                "item_count": 3,
            },
            {
                "artifact_kind": "NODES",
                "schema_name": "taxonomy-nodes-v1",
                "locale": None,
                "sha256": SHA_D,
                "item_count": 3,
            },
        ],
    }


def nodes() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "taxonomy-nodes-json-v1",
        "bundle_id": BUNDLE_ID,
        "family_code": "PLATFORM_WORK_V1",
        "nodes": [
            {
                "code": "DATA_SENSITIVITY.INTERNAL",
                "kind": "DATA_SENSITIVITY",
                "definition_code": "DEFINITION.DATA_SENSITIVITY.INTERNAL",
                "status": "ACTIVE",
                "introduced_in_bundle_id": BUNDLE_ID,
                "deprecated_reason_code": None,
                "replacement_codes": [],
                "attributes": [
                    {
                        "key": "classification_rank",
                        "value_kind": "INTEGER",
                        "code_value": None,
                        "integer_value": 2,
                    }
                ],
            },
            {
                "code": "DOMAIN.ENERGY",
                "kind": "DOMAIN",
                "definition_code": "DEFINITION.DOMAIN.ENERGY",
                "status": "ACTIVE",
                "introduced_in_bundle_id": BUNDLE_ID,
                "deprecated_reason_code": None,
                "replacement_codes": [],
                "attributes": [],
            },
            {
                "code": "PROBLEM.EFFICIENCY",
                "kind": "PROBLEM_TYPE",
                "definition_code": "DEFINITION.PROBLEM.EFFICIENCY",
                "status": "ACTIVE",
                "introduced_in_bundle_id": BUNDLE_ID,
                "deprecated_reason_code": None,
                "replacement_codes": [],
                "attributes": [],
            },
        ],
    }


def edges() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "taxonomy-edges-json-v1",
        "bundle_id": BUNDLE_ID,
        "family_code": "PLATFORM_WORK_V1",
        "edges": [
            {
                "edge_kind": "RELATED_TO",
                "from_code": "DOMAIN.ENERGY",
                "to_code": "PROBLEM.EFFICIENCY",
                "ordinal": 1,
            }
        ],
    }


def labels(*, locale: str = "en") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "taxonomy-labels-json-v1",
        "bundle_id": BUNDLE_ID,
        "family_code": "PLATFORM_WORK_V1",
        "locale": locale,
        "labels": [
            {
                "code": "DATA_SENSITIVITY.INTERNAL",
                "short_label": "Internal",
                "description": "Controlled internal data.",
                "accessibility_label": "Internal data sensitivity",
            },
            {
                "code": "DOMAIN.ENERGY",
                "short_label": "Energy",
                "description": "Energy systems and efficiency.",
                "accessibility_label": "Energy domain",
            },
            {
                "code": "PROBLEM.EFFICIENCY",
                "short_label": "Efficiency",
                "description": None,
                "accessibility_label": None,
            },
        ],
    }


def crosswalk() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "canonicalization_version": "taxonomy-crosswalk-json-v1",
        "crosswalk_id": "taxonomy_crosswalk_00001",
        "source_bundle_id": BUNDLE_ID,
        "target_bundle_id": SUCCESSOR_ID,
        "compatibility_level": "MINOR_COMPATIBLE",
        "mappings": [
            {
                "source_code": "DOMAIN.ENERGY",
                "target_codes": ["DOMAIN.ENERGY"],
                "mapping_kind": "EXACT",
                "confidence_code": "REVIEWED_HIGH",
                "review_reason_code": "UNCHANGED_DEFINITION",
            }
        ],
    }


def event(event_type: str) -> dict[str, Any]:
    payloads = {
        "TaxonomyBundlePublished": {
            "bundle_id": BUNDLE_ID,
            "family_code": "PLATFORM_WORK_V1",
            "semantic_version": "1.0.0",
            "selector_digest": SHA_A,
            "release_manifest_sha256": SHA_B,
            "effective_at": NOW,
            "status": "ACTIVE",
        },
        "TaxonomyBundleSuperseded": {
            "bundle_id": BUNDLE_ID,
            "successor_bundle_id": SUCCESSOR_ID,
            "status": "SUPERSEDED",
        },
        "TaxonomyBundleRetired": {
            "bundle_id": BUNDLE_ID,
            "status": "RETIRED",
            "reason_code": "SECURITY_REVIEW",
        },
        "TaxonomyCrosswalkPublished": {
            "crosswalk_id": "taxonomy_crosswalk_00001",
            "source_bundle_id": BUNDLE_ID,
            "target_bundle_id": SUCCESSOR_ID,
            "manifest_sha256": SHA_C,
        },
    }
    value = {
        "event_id": "taxonomy_event_000000001",
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": NOW,
        "aggregate_type": (
            "TaxonomyCrosswalk"
            if event_type == "TaxonomyCrosswalkPublished"
            else "TaxonomyBundle"
        ),
        "aggregate_id": (
            "taxonomy_crosswalk_00001"
            if event_type == "TaxonomyCrosswalkPublished"
            else BUNDLE_ID
        ),
        "aggregate_version": 1,
        "actor_kind": "SYSTEM",
        "actor_id": "taxonomy_publisher_0001",
        "original_actor_id": None,
        "correlation_id": "taxonomy_correlation_001",
        "causation_id": "taxonomy_causation_00001",
        "trace_id": "taxonomy_trace_00000001",
        "organization_id": None,
        "payload": payloads[event_type],
    }
    return deepcopy(value)
