"""Immutable Taxonomy domain surface for contract-first TDD."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import unicodedata
from typing import Any, Mapping, Optional, Tuple


TAXONOMY_DOMAIN_BEHAVIOR_NOT_AVAILABLE = (
    "TAXONOMY_DOMAIN_BEHAVIOR_NOT_AVAILABLE"
)


class TaxonomyDomainBehaviorNotAvailable(RuntimeError):
    """Stable default-deny sentinel until domain GREEN."""


class TaxonomyDomainError(ValueError):
    """Closed validation error without artifact values or canonical bytes."""

    def __init__(self, code: str, field_path: str, reason_code: str) -> None:
        self.code = code
        self.field_path = field_path
        self.reason_code = reason_code
        super().__init__(code)


class TaxonomyBundleStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class TaxonomyNodeStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"


class TaxonomyNodeKind(str, Enum):
    DOMAIN = "DOMAIN"
    PROBLEM_TYPE = "PROBLEM_TYPE"
    TASK = "TASK"
    SKILL = "SKILL"
    SKILL_LEVEL = "SKILL_LEVEL"
    TARGET_USER_CATEGORY = "TARGET_USER_CATEGORY"
    WORK_MODE = "WORK_MODE"
    FEEDBACK_CADENCE = "FEEDBACK_CADENCE"
    TEAM_PREFERENCE = "TEAM_PREFERENCE"
    REGION = "REGION"
    LANGUAGE = "LANGUAGE"
    DATA_SENSITIVITY = "DATA_SENSITIVITY"
    AI_USE = "AI_USE"
    RISK = "RISK"
    DELIVERY_KIND = "DELIVERY_KIND"
    REVIEW_REASON = "REVIEW_REASON"


class TaxonomyEdgeKind(str, Enum):
    BROADER_THAN = "BROADER_THAN"
    NARROWER_THAN = "NARROWER_THAN"
    REQUIRES = "REQUIRES"
    INCOMPATIBLE_WITH = "INCOMPATIBLE_WITH"
    RELATED_TO = "RELATED_TO"
    ALLOWED_LEVEL = "ALLOWED_LEVEL"
    LOCATED_IN = "LOCATED_IN"


class TaxonomyCompatibilityLevel(str, Enum):
    INITIAL = "INITIAL"
    PATCH_COMPATIBLE = "PATCH_COMPATIBLE"
    MINOR_COMPATIBLE = "MINOR_COMPATIBLE"
    MAJOR_BREAKING = "MAJOR_BREAKING"


class TaxonomyMappingKind(str, Enum):
    EXACT = "EXACT"
    NARROWER = "NARROWER"
    BROADER = "BROADER"
    SPLIT = "SPLIT"
    MERGE = "MERGE"
    NO_SUCCESSOR = "NO_SUCCESSOR"


@dataclass(frozen=True)
class TaxonomySelector:
    jurisdiction_code: str
    locale_set_digest: str
    semantic_major: int
    intended_consumer_set_digest: str
    selector_digest: str


@dataclass(frozen=True)
class TaxonomyArtifactDescriptor:
    artifact_kind: str
    schema_name: str
    locale: Optional[str]
    sha256: str
    item_count: int


@dataclass(frozen=True)
class TaxonomyReleaseManifest:
    schema_version: int
    canonicalization_version: str
    bundle_id: str
    family_code: str
    semantic_version: str
    selector: TaxonomySelector
    compatibility_level: TaxonomyCompatibilityLevel
    predecessor_bundle_id: Optional[str]
    effective_at: datetime
    effective_until: Optional[datetime]
    artifacts: Tuple[TaxonomyArtifactDescriptor, ...]


@dataclass(frozen=True)
class TaxonomyAttribute:
    key: str
    value_kind: str
    code_value: Optional[str]
    integer_value: Optional[int]


@dataclass(frozen=True)
class TaxonomyNode:
    code: str
    kind: TaxonomyNodeKind
    definition_code: str
    status: TaxonomyNodeStatus
    introduced_in_bundle_id: str
    deprecated_reason_code: Optional[str]
    replacement_codes: Tuple[str, ...]
    attributes: Tuple[TaxonomyAttribute, ...]


@dataclass(frozen=True)
class TaxonomyNodesArtifact:
    schema_version: int
    canonicalization_version: str
    bundle_id: str
    family_code: str
    nodes: Tuple[TaxonomyNode, ...]


@dataclass(frozen=True)
class TaxonomyEdge:
    edge_kind: TaxonomyEdgeKind
    from_code: str
    to_code: str
    ordinal: int


@dataclass(frozen=True)
class TaxonomyEdgesArtifact:
    schema_version: int
    canonicalization_version: str
    bundle_id: str
    family_code: str
    edges: Tuple[TaxonomyEdge, ...]


@dataclass(frozen=True)
class TaxonomyLabel:
    code: str
    short_label: str
    description: Optional[str]
    accessibility_label: Optional[str]


@dataclass(frozen=True)
class TaxonomyLabelsArtifact:
    schema_version: int
    canonicalization_version: str
    bundle_id: str
    family_code: str
    locale: str
    labels: Tuple[TaxonomyLabel, ...]


@dataclass(frozen=True)
class TaxonomyCrosswalkMapping:
    source_code: str
    target_codes: Tuple[str, ...]
    mapping_kind: TaxonomyMappingKind
    confidence_code: str
    review_reason_code: str


@dataclass(frozen=True)
class TaxonomyCrosswalkArtifact:
    schema_version: int
    canonicalization_version: str
    crosswalk_id: str
    source_bundle_id: str
    target_bundle_id: str
    compatibility_level: TaxonomyCompatibilityLevel
    mappings: Tuple[TaxonomyCrosswalkMapping, ...]


@dataclass(frozen=True)
class TaxonomyReleaseCandidate:
    manifest: TaxonomyReleaseManifest
    nodes: TaxonomyNodesArtifact
    edges: TaxonomyEdgesArtifact
    labels: Tuple[TaxonomyLabelsArtifact, ...]
    crosswalk: Optional[TaxonomyCrosswalkArtifact]


@dataclass(frozen=True)
class TaxonomyCodeMeaning:
    family_code: str
    code: str
    kind: TaxonomyNodeKind
    definition_code: str
    attributes: Tuple[TaxonomyAttribute, ...]


@dataclass(frozen=True)
class ValidatedTaxonomyRelease:
    candidate: TaxonomyReleaseCandidate = field(repr=False)
    release_manifest_sha256: str
    selector_digest: str
    node_manifest_sha256: str
    edge_manifest_sha256: str
    label_manifest_sha256: Tuple[Tuple[str, str], ...]
    crosswalk_manifest_sha256: Optional[str]
    canonical_release_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class TaxonomyBundle:
    bundle_id: str
    family_code: str
    semantic_version: str
    selector_digest: str
    release_manifest_sha256: str
    status: TaxonomyBundleStatus
    aggregate_version: int
    predecessor_bundle_id: Optional[str]
    successor_bundle_id: Optional[str]
    effective_at: datetime
    effective_until: Optional[datetime]
    retired_reason_code: Optional[str]
    updated_at: datetime

    def supersede(
        self, *, successor_bundle_id: str, server_now: datetime
    ) -> "TaxonomyBundle":
        if self.status is not TaxonomyBundleStatus.ACTIVE:
            raise _domain_error("bundle.status", "TERMINAL_STATE")
        if self.successor_bundle_id is not None:
            raise _domain_error("bundle.successor_bundle_id", "SUCCESSOR_ALREADY_BOUND")
        return replace(
            self,
            status=TaxonomyBundleStatus.SUPERSEDED,
            aggregate_version=self.aggregate_version + 1,
            successor_bundle_id=successor_bundle_id,
            updated_at=server_now,
        )

    def retire(
        self, *, reason_code: str, server_now: datetime
    ) -> "TaxonomyBundle":
        if self.status not in (
            TaxonomyBundleStatus.ACTIVE,
            TaxonomyBundleStatus.SUPERSEDED,
        ):
            raise _domain_error("bundle.status", "TERMINAL_STATE")
        return replace(
            self,
            status=TaxonomyBundleStatus.RETIRED,
            aggregate_version=self.aggregate_version + 1,
            retired_reason_code=reason_code,
            updated_at=server_now,
        )


def canonical_taxonomy_artifact_bytes(artifact: Any) -> bytes:
    try:
        return json.dumps(
            _json_value(artifact),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _domain_error("artifact", "CANONICAL_VALUE_INVALID") from error


def taxonomy_artifact_sha256(artifact: Any) -> str:
    return hashlib.sha256(canonical_taxonomy_artifact_bytes(artifact)).hexdigest()


def validate_taxonomy_release(
    *,
    candidate: TaxonomyReleaseCandidate,
    predecessor: Optional[TaxonomyReleaseCandidate],
    permanent_code_registry: Tuple[TaxonomyCodeMeaning, ...],
    server_now: datetime,
) -> ValidatedTaxonomyRelease:
    _validate_closed_values(candidate)
    _validate_order(candidate)
    _validate_identity_chain(candidate)
    _validate_descriptors(candidate)
    nodes_by_code = _validate_nodes(candidate, permanent_code_registry)
    _validate_edges(candidate, nodes_by_code)
    _validate_labels(candidate, nodes_by_code)
    _validate_crosswalk(candidate, predecessor, nodes_by_code)
    _validate_compatibility(candidate, predecessor)
    _validate_selector(candidate)

    return ValidatedTaxonomyRelease(
        candidate=candidate,
        release_manifest_sha256=taxonomy_artifact_sha256(candidate.manifest),
        selector_digest=candidate.manifest.selector.selector_digest,
        node_manifest_sha256=taxonomy_artifact_sha256(candidate.nodes),
        edge_manifest_sha256=taxonomy_artifact_sha256(candidate.edges),
        label_manifest_sha256=tuple(
            (labels.locale, taxonomy_artifact_sha256(labels))
            for labels in candidate.labels
        ),
        crosswalk_manifest_sha256=(
            taxonomy_artifact_sha256(candidate.crosswalk)
            if candidate.crosswalk is not None
            else None
        ),
        canonical_release_bytes=canonical_taxonomy_artifact_bytes(
            candidate.manifest
        ),
    )


_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{1,63}$")
_HIERARCHY_KINDS = {
    TaxonomyEdgeKind.BROADER_THAN,
    TaxonomyEdgeKind.NARROWER_THAN,
    TaxonomyEdgeKind.LOCATED_IN,
}


def _domain_error(field_path: str, reason_code: str) -> TaxonomyDomainError:
    return TaxonomyDomainError(
        "TAXONOMY_RELEASE_INVALID", field_path, reason_code
    )


def _compatibility_error(field_path: str, reason_code: str) -> TaxonomyDomainError:
    return TaxonomyDomainError(
        "TAXONOMY_COMPATIBILITY_REJECTED", field_path, reason_code
    )


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _json_value(child) for key, child in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, tuple):
        return [_json_value(child) for child in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    return value


def _walk(value: Any, path: str = "release") -> Any:
    if is_dataclass(value):
        for key, child in value.__dict__.items():
            yield from _walk(child, f"{path}.{key}")
        return
    if isinstance(value, Enum) or value is None:
        return
    if isinstance(value, tuple):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")
        return
    yield path, value


def _validate_closed_values(candidate: TaxonomyReleaseCandidate) -> None:
    for path, value in _walk(candidate):
        if isinstance(value, bool):
            if path.endswith("integer_value"):
                raise _domain_error(path, "INTEGER_BOOL_FORBIDDEN")
            continue
        if isinstance(value, float):
            raise _domain_error(path, "FLOAT_FORBIDDEN")
        if isinstance(value, str):
            if unicodedata.normalize("NFC", value) != value:
                raise _domain_error(path, "TEXT_NOT_NFC")
            if any(unicodedata.category(char) == "Cc" for char in value):
                raise _domain_error(path, "TEXT_CONTROL_FORBIDDEN")
            limit = 2048 if path.endswith("description") else 256
            if len(value.encode("utf-8")) > limit:
                raise _domain_error(path, "TEXT_UTF8_LIMIT")


def _validate_order(candidate: TaxonomyReleaseCandidate) -> None:
    expected_nodes = tuple(
        sorted(
            candidate.nodes.nodes,
            key=lambda item: (item.kind.value.encode(), item.code.encode()),
        )
    )
    if candidate.nodes.nodes != expected_nodes:
        raise _domain_error("nodes.nodes", "INPUT_ORDER_INVALID")
    expected_edges = tuple(
        sorted(
            candidate.edges.edges,
            key=lambda item: (
                item.edge_kind.value.encode(),
                item.from_code.encode(),
                item.to_code.encode(),
                item.ordinal,
            ),
        )
    )
    if candidate.edges.edges != expected_edges:
        raise _domain_error("edges.edges", "INPUT_ORDER_INVALID")
    if candidate.labels != tuple(
        sorted(candidate.labels, key=lambda item: item.locale.encode())
    ):
        raise _domain_error("labels", "INPUT_ORDER_INVALID")
    for index, labels in enumerate(candidate.labels):
        if labels.labels != tuple(
            sorted(labels.labels, key=lambda item: item.code.encode())
        ):
            raise _domain_error(f"labels[{index}].labels", "INPUT_ORDER_INVALID")
    expected_descriptors = tuple(
        sorted(
            candidate.manifest.artifacts,
            key=lambda item: (
                item.artifact_kind.encode(), (item.locale or "").encode()
            ),
        )
    )
    if candidate.manifest.artifacts != expected_descriptors:
        raise _domain_error("manifest.artifacts", "INPUT_ORDER_INVALID")


def _validate_identity_chain(candidate: TaxonomyReleaseCandidate) -> None:
    manifest = candidate.manifest
    if (
        manifest.schema_version != 1
        or manifest.canonicalization_version != "taxonomy-release-json-v1"
        or candidate.nodes.schema_version != 1
        or candidate.nodes.canonicalization_version != "taxonomy-nodes-json-v1"
        or candidate.edges.schema_version != 1
        or candidate.edges.canonicalization_version != "taxonomy-edges-json-v1"
    ):
        raise _domain_error("release.schema_version", "SCHEMA_IDENTITY_MISMATCH")
    artifacts = (candidate.nodes, candidate.edges, *candidate.labels)
    for index, artifact in enumerate(artifacts):
        if artifact.bundle_id != manifest.bundle_id:
            raise _domain_error(f"artifacts[{index}].bundle_id", "BUNDLE_ID_MISMATCH")
        if artifact.family_code != manifest.family_code:
            raise _domain_error(f"artifacts[{index}].family_code", "FAMILY_MISMATCH")
    if len({labels.locale for labels in candidate.labels}) != len(candidate.labels):
        raise _domain_error("labels.locale", "LOCALE_DUPLICATE")
    for index, labels in enumerate(candidate.labels):
        if (
            labels.schema_version != 1
            or labels.canonicalization_version != "taxonomy-labels-json-v1"
        ):
            raise _domain_error(f"labels[{index}]", "SCHEMA_IDENTITY_MISMATCH")
    if candidate.crosswalk is not None and (
        candidate.crosswalk.schema_version != 1
        or candidate.crosswalk.canonicalization_version
        != "taxonomy-crosswalk-json-v1"
    ):
        raise _domain_error("crosswalk", "SCHEMA_IDENTITY_MISMATCH")


def _artifact_values(candidate: TaxonomyReleaseCandidate) -> Mapping[tuple[str, Optional[str]], Any]:
    values: dict[tuple[str, Optional[str]], Any] = {
        ("NODES", None): candidate.nodes,
        ("EDGES", None): candidate.edges,
    }
    values.update({("LABELS", labels.locale): labels for labels in candidate.labels})
    if candidate.crosswalk is not None:
        values[("CROSSWALK", None)] = candidate.crosswalk
    return values


def _validate_descriptors(candidate: TaxonomyReleaseCandidate) -> None:
    values = _artifact_values(candidate)
    described = {(item.artifact_kind, item.locale) for item in candidate.manifest.artifacts}
    if described != set(values):
        raise _domain_error("manifest.artifacts", "ARTIFACT_SET_MISMATCH")
    for index, descriptor in enumerate(candidate.manifest.artifacts):
        artifact = values[(descriptor.artifact_kind, descriptor.locale)]
        expected_schema = {
            "NODES": "taxonomy-nodes-v1",
            "EDGES": "taxonomy-edges-v1",
            "LABELS": "taxonomy-labels-v1",
            "CROSSWALK": "taxonomy-crosswalk-v1",
        }.get(descriptor.artifact_kind)
        if descriptor.schema_name != expected_schema or (
            descriptor.artifact_kind == "LABELS"
        ) != (descriptor.locale is not None):
            raise _domain_error(
                f"manifest.artifacts[{index}]", "ARTIFACT_DESCRIPTOR_INVALID"
            )
        if descriptor.artifact_kind == "NODES":
            count = len(artifact.nodes)
        elif descriptor.artifact_kind == "EDGES":
            count = len(artifact.edges)
        elif descriptor.artifact_kind == "LABELS":
            count = len(artifact.labels)
        else:
            count = len(artifact.mappings)
        if descriptor.item_count != count:
            raise _domain_error(f"manifest.artifacts[{index}].item_count", "ARTIFACT_COUNT_MISMATCH")
        if descriptor.sha256 != taxonomy_artifact_sha256(artifact):
            raise _domain_error(f"manifest.artifacts[{index}].sha256", "ARTIFACT_HASH_MISMATCH")


def _validate_nodes(
    candidate: TaxonomyReleaseCandidate,
    permanent_code_registry: Tuple[TaxonomyCodeMeaning, ...],
) -> Mapping[str, TaxonomyNode]:
    nodes: dict[str, TaxonomyNode] = {}
    for index, node in enumerate(candidate.nodes.nodes):
        if _CODE.fullmatch(node.code) is None or _CODE.fullmatch(node.definition_code) is None:
            raise _domain_error(f"nodes.nodes[{index}].code", "CODE_FORMAT_INVALID")
        if node.code in nodes:
            raise _domain_error(f"nodes.nodes[{index}].code", "CODE_DUPLICATE")
        nodes[node.code] = node
        if node.status is TaxonomyNodeStatus.DEPRECATED:
            if node.deprecated_reason_code is None:
                raise _domain_error(f"nodes.nodes[{index}].deprecated_reason_code", "DEPRECATION_REASON_REQUIRED")
        elif node.deprecated_reason_code is not None or node.replacement_codes:
            raise _domain_error(f"nodes.nodes[{index}].status", "ACTIVE_REPLACEMENT_FORBIDDEN")
        for attribute in node.attributes:
            if attribute.value_kind == "INTEGER":
                if attribute.code_value is not None or attribute.integer_value is None:
                    raise _domain_error(f"nodes.nodes[{index}].attributes", "ATTRIBUTE_SHAPE_INVALID")
            elif attribute.value_kind == "CODE":
                if attribute.code_value is None or attribute.integer_value is not None:
                    raise _domain_error(f"nodes.nodes[{index}].attributes", "ATTRIBUTE_SHAPE_INVALID")
            else:
                raise _domain_error(f"nodes.nodes[{index}].attributes", "ATTRIBUTE_KIND_INVALID")
    for entry in permanent_code_registry:
        node = nodes.get(entry.code)
        if node is not None and (
            node.kind,
            node.definition_code,
            node.attributes,
        ) != (entry.kind, entry.definition_code, entry.attributes):
            raise _compatibility_error("nodes.nodes", "CODE_MEANING_CHANGED")
    for index, node in enumerate(candidate.nodes.nodes):
        for replacement_code in node.replacement_codes:
            if replacement_code not in nodes:
                raise _domain_error(f"nodes.nodes[{index}].replacement_codes", "REPLACEMENT_UNKNOWN")
        if len(node.replacement_codes) > 5 or len(set(node.replacement_codes)) != len(node.replacement_codes):
            raise _domain_error(f"nodes.nodes[{index}].replacement_codes", "REPLACEMENT_SET_INVALID")
    return nodes


def _validate_edges(
    candidate: TaxonomyReleaseCandidate,
    nodes_by_code: Mapping[str, TaxonomyNode],
) -> None:
    identities: set[tuple[Any, ...]] = set()
    graph: dict[str, set[str]] = {}
    for index, edge in enumerate(candidate.edges.edges):
        identity = (edge.edge_kind, edge.from_code, edge.to_code, edge.ordinal)
        if edge.from_code == edge.to_code:
            raise _domain_error(f"edges.edges[{index}]", "EDGE_SELF_FORBIDDEN")
        if identity in identities:
            raise _domain_error(f"edges.edges[{index}]", "EDGE_DUPLICATE")
        identities.add(identity)
        if edge.from_code not in nodes_by_code or edge.to_code not in nodes_by_code:
            raise _domain_error(f"edges.edges[{index}]", "EDGE_ENDPOINT_UNKNOWN")
        if edge.edge_kind in _HIERARCHY_KINDS:
            graph.setdefault(edge.from_code, set()).add(edge.to_code)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(code: str) -> None:
        if code in visiting:
            raise _domain_error("edges.edges", "HIERARCHY_CYCLE")
        if code in visited:
            return
        visiting.add(code)
        for child in graph.get(code, ()):
            visit(child)
        visiting.remove(code)
        visited.add(code)

    for code in graph:
        visit(code)


def _validate_labels(
    candidate: TaxonomyReleaseCandidate,
    nodes_by_code: Mapping[str, TaxonomyNode],
) -> None:
    expected_codes = set(nodes_by_code)
    for index, artifact in enumerate(candidate.labels):
        actual_codes = [label.code for label in artifact.labels]
        if len(set(actual_codes)) != len(actual_codes):
            raise _domain_error(f"labels[{index}].labels", "LABEL_DUPLICATE")
        if set(actual_codes) != expected_codes:
            raise _domain_error(f"labels[{index}].labels", "LOCALE_COVERAGE_INCOMPLETE")


def _validate_crosswalk(
    candidate: TaxonomyReleaseCandidate,
    predecessor: Optional[TaxonomyReleaseCandidate],
    nodes_by_code: Mapping[str, TaxonomyNode],
) -> None:
    crosswalk = candidate.crosswalk
    if crosswalk is None:
        return
    if crosswalk.compatibility_level is TaxonomyCompatibilityLevel.INITIAL:
        raise _compatibility_error("crosswalk.compatibility_level", "CROSSWALK_INITIAL_FORBIDDEN")
    if predecessor is None:
        raise _compatibility_error("crosswalk", "CROSSWALK_PREDECESSOR_REQUIRED")
    if (
        crosswalk.source_bundle_id != predecessor.manifest.bundle_id
        or crosswalk.target_bundle_id != candidate.manifest.bundle_id
    ):
        raise _compatibility_error("crosswalk", "CROSSWALK_BUNDLE_MISMATCH")
    source_codes = {node.code for node in predecessor.nodes.nodes}
    source_nodes = {node.code: node for node in predecessor.nodes.nodes}
    for index, mapping in enumerate(crosswalk.mappings):
        if mapping.source_code not in source_codes or any(
            code not in nodes_by_code for code in mapping.target_codes
        ):
            raise _compatibility_error(f"crosswalk.mappings[{index}]", "CROSSWALK_CODE_UNKNOWN")
        if mapping.mapping_kind is TaxonomyMappingKind.EXACT and len(mapping.target_codes) != 1:
            raise _compatibility_error(f"crosswalk.mappings[{index}].target_codes", "EXACT_TARGET_CARDINALITY")
        if mapping.mapping_kind is TaxonomyMappingKind.EXACT:
            source = source_nodes[mapping.source_code]
            target = nodes_by_code[mapping.target_codes[0]]
            if (source.kind, source.definition_code, source.attributes) != (
                target.kind,
                target.definition_code,
                target.attributes,
            ):
                raise _compatibility_error(
                    f"crosswalk.mappings[{index}]", "EXACT_DEFINITION_MISMATCH"
                )
        if mapping.mapping_kind is TaxonomyMappingKind.NO_SUCCESSOR and mapping.target_codes:
            raise _compatibility_error(f"crosswalk.mappings[{index}].target_codes", "NO_SUCCESSOR_TARGET_FORBIDDEN")
        if len(mapping.target_codes) > 5 or len(set(mapping.target_codes)) != len(mapping.target_codes):
            raise _compatibility_error(
                f"crosswalk.mappings[{index}].target_codes",
                "TARGET_SET_INVALID",
            )


def _parse_semver(value: str, field_path: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise _compatibility_error(field_path, "SEMVER_INVALID")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _validate_compatibility(
    candidate: TaxonomyReleaseCandidate,
    predecessor: Optional[TaxonomyReleaseCandidate],
) -> None:
    manifest = candidate.manifest
    current_version = _parse_semver(manifest.semantic_version, "manifest.semantic_version")
    if predecessor is None:
        if manifest.predecessor_bundle_id is not None:
            raise _compatibility_error("manifest.predecessor_bundle_id", "PREDECESSOR_SNAPSHOT_REQUIRED")
        if manifest.compatibility_level is not TaxonomyCompatibilityLevel.INITIAL:
            raise _compatibility_error("manifest.compatibility_level", "INITIAL_COMPATIBILITY_REQUIRED")
        if current_version != (1, 0, 0):
            raise _compatibility_error("manifest.semantic_version", "INITIAL_VERSION_INVALID")
        if candidate.crosswalk is not None:
            raise _compatibility_error("crosswalk", "INITIAL_CROSSWALK_FORBIDDEN")
        return

    if manifest.compatibility_level is TaxonomyCompatibilityLevel.INITIAL:
        raise _compatibility_error("manifest.compatibility_level", "INITIAL_HAS_PREDECESSOR")
    if manifest.predecessor_bundle_id != predecessor.manifest.bundle_id:
        raise _compatibility_error("manifest.predecessor_bundle_id", "PREDECESSOR_MISMATCH")
    if manifest.family_code != predecessor.manifest.family_code:
        raise _compatibility_error("manifest.family_code", "FAMILY_MISMATCH")
    if manifest.selector != predecessor.manifest.selector:
        raise _compatibility_error("manifest.selector", "SELECTOR_MISMATCH")
    predecessor_nodes = {node.code: node for node in predecessor.nodes.nodes}
    candidate_nodes = {node.code: node for node in candidate.nodes.nodes}
    predecessor_edges = set(predecessor.edges.edges)
    candidate_edges = set(candidate.edges.edges)
    machine_equal = (
        predecessor_nodes == candidate_nodes
        and predecessor_edges == candidate_edges
    )
    additive = (
        set(predecessor_nodes).issubset(candidate_nodes)
        and all(candidate_nodes[code] == node for code, node in predecessor_nodes.items())
        and predecessor_edges.issubset(candidate_edges)
    )
    derived = (
        TaxonomyCompatibilityLevel.PATCH_COMPATIBLE
        if machine_equal
        else TaxonomyCompatibilityLevel.MINOR_COMPATIBLE
        if additive
        else TaxonomyCompatibilityLevel.MAJOR_BREAKING
    )
    if manifest.compatibility_level is not derived:
        raise _compatibility_error(
            "manifest.compatibility_level", "COMPATIBILITY_LEVEL_MISMATCH"
        )
    previous_version = _parse_semver(predecessor.manifest.semantic_version, "predecessor.semantic_version")
    expected: tuple[int, int, int]
    if manifest.compatibility_level is TaxonomyCompatibilityLevel.PATCH_COMPATIBLE:
        expected = (previous_version[0], previous_version[1], previous_version[2] + 1)
    elif manifest.compatibility_level is TaxonomyCompatibilityLevel.MINOR_COMPATIBLE:
        expected = (previous_version[0], previous_version[1] + 1, 0)
    else:
        expected = (previous_version[0] + 1, 0, 0)
    if current_version != expected:
        raise _compatibility_error("manifest.semantic_version", "SEMVER_INCREMENT_INVALID")


def _validate_selector(candidate: TaxonomyReleaseCandidate) -> None:
    selector = candidate.manifest.selector
    major, _, _ = _parse_semver(candidate.manifest.semantic_version, "manifest.semantic_version")
    if selector.semantic_major != major:
        raise _compatibility_error("manifest.selector.semantic_major", "SEMANTIC_MAJOR_MISMATCH")
    locale_digest = taxonomy_artifact_sha256(
        tuple(labels.locale for labels in candidate.labels)
    )
    if selector.locale_set_digest != locale_digest:
        raise _domain_error(
            "manifest.selector.locale_set_digest", "LOCALE_SET_DIGEST_MISMATCH"
        )
    surface = {
        "canonicalization_version": "taxonomy-selector-json-v1",
        "jurisdiction_code": selector.jurisdiction_code,
        "locale_set_digest": selector.locale_set_digest,
        "semantic_major": selector.semantic_major,
        "intended_consumer_set_digest": selector.intended_consumer_set_digest,
    }
    if selector.selector_digest != taxonomy_artifact_sha256(surface):
        raise _domain_error("manifest.selector.selector_digest", "SELECTOR_DIGEST_MISMATCH")
