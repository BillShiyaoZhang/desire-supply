"""One reviewed Taxonomy release for the synthetic internal sandbox.

The release is deliberately code-native and tiny.  Its manifest/artifact
digests are repeated in the immutable seed manifest, so a code or resource
change cannot silently select another Taxonomy release.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional, Tuple

from ..taxonomy.domain import (
    TaxonomyArtifactDescriptor,
    TaxonomyAttribute,
    TaxonomyCompatibilityLevel,
    TaxonomyEdge,
    TaxonomyEdgeKind,
    TaxonomyEdgesArtifact,
    TaxonomyLabel,
    TaxonomyLabelsArtifact,
    TaxonomyNode,
    TaxonomyNodeKind,
    TaxonomyNodeStatus,
    TaxonomyNodesArtifact,
    TaxonomyReleaseCandidate,
    TaxonomyReleaseManifest,
    TaxonomySelector,
    ValidatedTaxonomyRelease,
    canonical_taxonomy_artifact_bytes,
    taxonomy_artifact_sha256,
    validate_taxonomy_release,
)


INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID = (
    "50000000-0000-4000-8000-000000000001"
)
INTERNAL_SANDBOX_TAXONOMY_FAMILY = "PLATFORM_WORK_V1"
INTERNAL_SANDBOX_TAXONOMY_VERSION = "1.0.0"
INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_AT = datetime(
    2020, 1, 1, tzinfo=timezone.utc
)
INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_UNTIL = datetime(
    2100, 1, 1, tzinfo=timezone.utc
)


def _node(
    code: str,
    kind: TaxonomyNodeKind,
    *,
    attributes: Tuple[TaxonomyAttribute, ...] = (),
) -> TaxonomyNode:
    return TaxonomyNode(
        code=code,
        kind=kind,
        definition_code="DEFINITION." + code,
        status=TaxonomyNodeStatus.ACTIVE,
        introduced_in_bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
        deprecated_reason_code=None,
        replacement_codes=(),
        attributes=attributes,
    )


def _labels(
    locale: str,
    values: Tuple[Tuple[str, str], ...],
) -> TaxonomyLabelsArtifact:
    return TaxonomyLabelsArtifact(
        schema_version=1,
        canonicalization_version="taxonomy-labels-json-v1",
        bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
        family_code=INTERNAL_SANDBOX_TAXONOMY_FAMILY,
        locale=locale,
        labels=tuple(
            TaxonomyLabel(
                code=code,
                short_label=label,
                description=None,
                accessibility_label=label,
            )
            for code, label in values
        ),
    )


def _candidate() -> TaxonomyReleaseCandidate:
    nodes = TaxonomyNodesArtifact(
        schema_version=1,
        canonicalization_version="taxonomy-nodes-json-v1",
        bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
        family_code=INTERNAL_SANDBOX_TAXONOMY_FAMILY,
        nodes=tuple(
            sorted(
                (
                    _node(
                        "DATA_SENSITIVITY.INTERNAL",
                        TaxonomyNodeKind.DATA_SENSITIVITY,
                        attributes=(
                            TaxonomyAttribute(
                                key="classification_rank",
                                value_kind="INTEGER",
                                code_value=None,
                                integer_value=2,
                            ),
                        ),
                    ),
                    _node("DOMAIN.SOFTWARE", TaxonomyNodeKind.DOMAIN),
                    _node(
                        "PROBLEM.OPERATIONS",
                        TaxonomyNodeKind.PROBLEM_TYPE,
                    ),
                    _node(
                        "SKILL.SYSTEMS_ANALYSIS",
                        TaxonomyNodeKind.SKILL,
                    ),
                    _node(
                        "TARGET_USER.SMALL_TEAM",
                        TaxonomyNodeKind.TARGET_USER_CATEGORY,
                    ),
                    _node("TASK.ANALYSIS", TaxonomyNodeKind.TASK),
                ),
                key=lambda item: (item.kind.value.encode(), item.code.encode()),
            )
        ),
    )
    edges = TaxonomyEdgesArtifact(
        schema_version=1,
        canonicalization_version="taxonomy-edges-json-v1",
        bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
        family_code=INTERNAL_SANDBOX_TAXONOMY_FAMILY,
        edges=tuple(
            sorted(
                (
                    TaxonomyEdge(
                        TaxonomyEdgeKind.RELATED_TO,
                        "DOMAIN.SOFTWARE",
                        "PROBLEM.OPERATIONS",
                        1,
                    ),
                    TaxonomyEdge(
                        TaxonomyEdgeKind.REQUIRES,
                        "TASK.ANALYSIS",
                        "SKILL.SYSTEMS_ANALYSIS",
                        1,
                    ),
                ),
                key=lambda item: (
                    item.edge_kind.value.encode(),
                    item.from_code.encode(),
                    item.to_code.encode(),
                    item.ordinal,
                ),
            )
        ),
    )
    english = (
        ("DATA_SENSITIVITY.INTERNAL", "Internal data"),
        ("DOMAIN.SOFTWARE", "Software"),
        ("PROBLEM.OPERATIONS", "Operations improvement"),
        ("SKILL.SYSTEMS_ANALYSIS", "Systems analysis"),
        ("TARGET_USER.SMALL_TEAM", "Small team"),
        ("TASK.ANALYSIS", "Analysis"),
    )
    chinese = (
        ("DATA_SENSITIVITY.INTERNAL", "内部数据"),
        ("DOMAIN.SOFTWARE", "软件"),
        ("PROBLEM.OPERATIONS", "运营改进"),
        ("SKILL.SYSTEMS_ANALYSIS", "系统分析"),
        ("TARGET_USER.SMALL_TEAM", "小团队"),
        ("TASK.ANALYSIS", "分析"),
    )
    labels = (_labels("en", english), _labels("zh-CN", chinese))
    locale_digest = taxonomy_artifact_sha256(tuple(item.locale for item in labels))
    consumer_digest = taxonomy_artifact_sha256(
        ("DEMAND", "MATCHING", "PROFILE")
    )
    selector = TaxonomySelector(
        jurisdiction_code="JURISDICTION.CN",
        locale_set_digest=locale_digest,
        semantic_major=1,
        intended_consumer_set_digest=consumer_digest,
        selector_digest="0" * 64,
    )
    selector = replace(
        selector,
        selector_digest=taxonomy_artifact_sha256(
            {
                "canonicalization_version": "taxonomy-selector-json-v1",
                "jurisdiction_code": selector.jurisdiction_code,
                "locale_set_digest": selector.locale_set_digest,
                "semantic_major": selector.semantic_major,
                "intended_consumer_set_digest": (
                    selector.intended_consumer_set_digest
                ),
            }
        ),
    )
    artifact_values = (
        ("EDGES", "taxonomy-edges-v1", None, edges, len(edges.edges)),
        *(
            (
                "LABELS",
                "taxonomy-labels-v1",
                item.locale,
                item,
                len(item.labels),
            )
            for item in labels
        ),
        ("NODES", "taxonomy-nodes-v1", None, nodes, len(nodes.nodes)),
    )
    descriptors = tuple(
        TaxonomyArtifactDescriptor(
            artifact_kind=kind,
            schema_name=schema_name,
            locale=locale,
            sha256=taxonomy_artifact_sha256(value),
            item_count=count,
        )
        for kind, schema_name, locale, value, count in artifact_values
    )
    manifest = TaxonomyReleaseManifest(
        schema_version=1,
        canonicalization_version="taxonomy-release-json-v1",
        bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID,
        family_code=INTERNAL_SANDBOX_TAXONOMY_FAMILY,
        semantic_version=INTERNAL_SANDBOX_TAXONOMY_VERSION,
        selector=selector,
        compatibility_level=TaxonomyCompatibilityLevel.INITIAL,
        predecessor_bundle_id=None,
        effective_at=INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_AT,
        effective_until=INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_UNTIL,
        artifacts=descriptors,
    )
    return TaxonomyReleaseCandidate(
        manifest=manifest,
        nodes=nodes,
        edges=edges,
        labels=labels,
        crosswalk=None,
    )


def build_internal_sandbox_taxonomy_release() -> ValidatedTaxonomyRelease:
    """Build and fully domain-validate the one synthetic release."""

    return validate_taxonomy_release(
        candidate=_candidate(),
        predecessor=None,
        permanent_code_registry=(),
        server_now=datetime.now(timezone.utc),
    )


def internal_sandbox_taxonomy_artifact_bytes(
    release: ValidatedTaxonomyRelease,
) -> Tuple[Tuple[str, Optional[str], bytes], ...]:
    candidate = release.candidate
    return (
        (
            "RELEASE",
            None,
            canonical_taxonomy_artifact_bytes(candidate.manifest),
        ),
        ("EDGES", None, canonical_taxonomy_artifact_bytes(candidate.edges)),
        *(
            (
                "LABELS",
                labels.locale,
                canonical_taxonomy_artifact_bytes(labels),
            )
            for labels in candidate.labels
        ),
        ("NODES", None, canonical_taxonomy_artifact_bytes(candidate.nodes)),
    )


__all__ = [
    "INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID",
    "INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_AT",
    "INTERNAL_SANDBOX_TAXONOMY_EFFECTIVE_UNTIL",
    "INTERNAL_SANDBOX_TAXONOMY_FAMILY",
    "INTERNAL_SANDBOX_TAXONOMY_VERSION",
    "build_internal_sandbox_taxonomy_release",
    "internal_sandbox_taxonomy_artifact_bytes",
]
