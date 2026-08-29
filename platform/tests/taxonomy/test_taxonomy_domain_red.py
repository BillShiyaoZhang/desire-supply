"""Robust semantic RED for Taxonomy canonical validation and lifecycle."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import unittest

from desire_platform.taxonomy.domain import (
    TAXONOMY_DOMAIN_BEHAVIOR_NOT_AVAILABLE,
    TaxonomyAttribute,
    TaxonomyBundleStatus,
    TaxonomyCompatibilityLevel,
    TaxonomyDomainBehaviorNotAvailable,
    TaxonomyDomainError,
    TaxonomyEdge,
    TaxonomyEdgeKind,
    TaxonomyMappingKind,
    TaxonomyNodeKind,
    TaxonomyNodeStatus,
    canonical_taxonomy_artifact_bytes,
    taxonomy_artifact_sha256,
    validate_taxonomy_release,
)
from tests.support.taxonomy_builders import (
    BUNDLE_ID,
    NOW,
    SUCCESSOR_ID,
    bundle,
    fixture_canonical_bytes,
    fixture_sha256,
    permanent_registry,
    rebind_artifact_descriptors,
    release_candidate,
)


class TaxonomyDomainSemanticRedTests(unittest.TestCase):
    def _call_semantic(self, callback):
        try:
            return ("value", callback())
        except TaxonomyDomainBehaviorNotAvailable as error:
            self.assertEqual(
                str(error), TAXONOMY_DOMAIN_BEHAVIOR_NOT_AVAILABLE
            )
            return ("sentinel", None)
        except TaxonomyDomainError as error:
            return (
                "error",
                (error.code, error.field_path, error.reason_code),
            )

    def _validate(self, candidate, *, predecessor=None, registry=()):
        return self._call_semantic(
            lambda: validate_taxonomy_release(
                candidate=candidate,
                predecessor=predecessor,
                permanent_code_registry=tuple(registry),
                server_now=NOW,
            )
        )

    def test_canonical_bytes_and_every_artifact_hash_are_locally_recomputed(self) -> None:
        candidate = release_candidate()
        expected_bytes = fixture_canonical_bytes(candidate.nodes)
        bytes_outcome = self._call_semantic(
            lambda: canonical_taxonomy_artifact_bytes(candidate.nodes)
        )
        hash_outcome = self._call_semantic(
            lambda: taxonomy_artifact_sha256(candidate.nodes)
        )
        release_outcome = self._validate(candidate)
        self.assertEqual(
            {
                "bytes": bytes_outcome,
                "hash": hash_outcome,
                "release_hash": (
                    release_outcome[1].release_manifest_sha256
                    if release_outcome[0] == "value"
                    else release_outcome[0]
                ),
                "selector_hash": (
                    release_outcome[1].selector_digest
                    if release_outcome[0] == "value"
                    else release_outcome[0]
                ),
            },
            {
                "bytes": ("value", expected_bytes),
                "hash": ("value", hashlib.sha256(expected_bytes).hexdigest()),
                "release_hash": fixture_sha256(candidate.manifest),
                "selector_hash": candidate.manifest.selector.selector_digest,
            },
        )

    def test_input_order_is_rejected_without_silent_sorting(self) -> None:
        candidate = release_candidate()
        bad_nodes = replace(
            candidate.nodes, nodes=tuple(reversed(candidate.nodes.nodes))
        )
        bad = rebind_artifact_descriptors(replace(candidate, nodes=bad_nodes))
        outcome = self._validate(bad)
        self.assertEqual(
            outcome,
            (
                "error",
                (
                    "TAXONOMY_RELEASE_INVALID",
                    "nodes.nodes",
                    "INPUT_ORDER_INVALID",
                ),
            ),
        )

    def test_nfc_utf8_control_bool_and_float_are_closed(self) -> None:
        candidate = release_candidate()
        first_labels = candidate.labels[0]
        decomposed = replace(
            first_labels.labels[1], short_label="E\u0301nergy"
        )
        bad_unicode = replace(
            candidate,
            labels=(
                replace(
                    first_labels,
                    labels=(first_labels.labels[0], decomposed, *first_labels.labels[2:]),
                ),
                *candidate.labels[1:],
            ),
        )
        too_many_bytes = replace(
            candidate,
            labels=(
                replace(
                    first_labels,
                    labels=(
                        first_labels.labels[0],
                        replace(first_labels.labels[1], short_label="界" * 257),
                        *first_labels.labels[2:],
                    ),
                ),
                *candidate.labels[1:],
            ),
        )
        control_text = replace(
            candidate,
            labels=(
                replace(
                    first_labels,
                    labels=(
                        first_labels.labels[0],
                        replace(first_labels.labels[1], short_label="Energy\n"),
                        *first_labels.labels[2:],
                    ),
                ),
                *candidate.labels[1:],
            ),
        )
        first_node = candidate.nodes.nodes[0]
        bool_attribute = replace(first_node.attributes[0], integer_value=True)
        float_attribute = replace(first_node.attributes[0], integer_value=1.5)
        candidates = (
            rebind_artifact_descriptors(bad_unicode),
            rebind_artifact_descriptors(too_many_bytes),
            rebind_artifact_descriptors(control_text),
            rebind_artifact_descriptors(replace(
                candidate,
                nodes=replace(
                    candidate.nodes,
                    nodes=(
                        replace(first_node, attributes=(bool_attribute,)),
                        *candidate.nodes.nodes[1:],
                    ),
                ),
            )),
            rebind_artifact_descriptors(replace(
                candidate,
                nodes=replace(
                    candidate.nodes,
                    nodes=(
                        replace(first_node, attributes=(float_attribute,)),
                        *candidate.nodes.nodes[1:],
                    ),
                ),
            )),
        )
        outcomes = [self._validate(value) for value in candidates]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            [
                "TEXT_NOT_NFC",
                "TEXT_UTF8_LIMIT",
                "TEXT_CONTROL_FORBIDDEN",
                "INTEGER_BOOL_FORBIDDEN",
                "FLOAT_FORBIDDEN",
            ],
        )

    def test_code_is_permanently_unique_and_cannot_change_meaning(self) -> None:
        predecessor = release_candidate()
        successor = release_candidate(successor=True)
        domain_index = next(
            index
            for index, node in enumerate(successor.nodes.nodes)
            if node.code == "DOMAIN.ENERGY"
        )
        changed = replace(
            successor.nodes.nodes[domain_index],
            definition_code="DEFINITION.DOMAIN.ENERGY.REDEFINED",
        )
        nodes = list(successor.nodes.nodes)
        nodes[domain_index] = changed
        bad = rebind_artifact_descriptors(
            replace(successor, nodes=replace(successor.nodes, nodes=tuple(nodes)))
        )
        duplicate_node = replace(
            successor.nodes.nodes[domain_index],
            kind=TaxonomyNodeKind.SKILL,
            definition_code="DEFINITION.SKILL.ENERGY",
        )
        duplicate = rebind_artifact_descriptors(
            replace(
                successor,
                nodes=replace(
                    successor.nodes,
                    nodes=tuple(
                        sorted(
                            (*successor.nodes.nodes, duplicate_node),
                            key=lambda item: (
                                item.kind.value.encode(), item.code.encode()
                            ),
                        )
                    ),
                ),
            )
        )
        outcomes = [self._validate(
            bad,
            predecessor=predecessor,
            registry=permanent_registry(predecessor),
        ), self._validate(
            duplicate,
            predecessor=predecessor,
            registry=permanent_registry(predecessor),
        )]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            ["CODE_MEANING_CHANGED", "CODE_DUPLICATE"],
        )

    def test_edges_reject_self_duplicate_and_hierarchy_cycle(self) -> None:
        candidate = release_candidate()
        self_edge = TaxonomyEdge(
            TaxonomyEdgeKind.RELATED_TO,
            "DOMAIN.ENERGY",
            "DOMAIN.ENERGY",
            1,
        )
        duplicate = candidate.edges.edges[0]
        cycle = (
            TaxonomyEdge(
                TaxonomyEdgeKind.BROADER_THAN,
                "DOMAIN.ENERGY",
                "PROBLEM.EFFICIENCY",
                1,
            ),
            TaxonomyEdge(
                TaxonomyEdgeKind.BROADER_THAN,
                "PROBLEM.EFFICIENCY",
                "DOMAIN.ENERGY",
                1,
            ),
        )
        bad_values = (
            rebind_artifact_descriptors(replace(candidate, edges=replace(candidate.edges, edges=(self_edge,)))),
            rebind_artifact_descriptors(replace(candidate, edges=replace(candidate.edges, edges=(duplicate, duplicate)))),
            rebind_artifact_descriptors(replace(candidate, edges=replace(candidate.edges, edges=cycle))),
        )
        outcomes = [self._validate(value) for value in bad_values]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            ["EDGE_SELF_FORBIDDEN", "EDGE_DUPLICATE", "HIERARCHY_CYCLE"],
        )

    def test_deprecated_replacement_and_locale_coverage_are_exact(self) -> None:
        candidate = release_candidate()
        domain_index = next(
            index
            for index, node in enumerate(candidate.nodes.nodes)
            if node.code == "DOMAIN.ENERGY"
        )
        deprecated = replace(
            candidate.nodes.nodes[domain_index],
            status=TaxonomyNodeStatus.DEPRECATED,
            deprecated_reason_code="REPLACED",
            replacement_codes=("DOMAIN.UNKNOWN",),
        )
        nodes = list(candidate.nodes.nodes)
        nodes[domain_index] = deprecated
        bad_replacement = rebind_artifact_descriptors(replace(
            candidate, nodes=replace(candidate.nodes, nodes=tuple(nodes))
        ))
        missing_label = rebind_artifact_descriptors(replace(
            candidate,
            labels=(
                replace(
                    candidate.labels[0], labels=candidate.labels[0].labels[:-1]
                ),
                candidate.labels[1],
            ),
        ))
        outcomes = [
            self._validate(bad_replacement),
            self._validate(missing_label),
        ]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            ["REPLACEMENT_UNKNOWN", "LOCALE_COVERAGE_INCOMPLETE"],
        )

    def test_initial_semver_and_derived_compatibility_are_consistent(self) -> None:
        initial = release_candidate()
        successor = release_candidate(successor=True)
        bad_initial = replace(
            initial,
            manifest=replace(initial.manifest, semantic_version="1.0.1"),
        )
        bad_successor_initial = replace(
            successor,
            manifest=replace(
                successor.manifest,
                compatibility_level=TaxonomyCompatibilityLevel.INITIAL,
            ),
        )
        bad_increment = replace(
            successor,
            manifest=replace(successor.manifest, semantic_version="1.0.1"),
        )
        outcomes = [
            self._validate(bad_initial),
            self._validate(bad_successor_initial, predecessor=initial),
            self._validate(
                bad_increment,
                predecessor=initial,
                registry=permanent_registry(initial),
            ),
        ]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            ["INITIAL_VERSION_INVALID", "INITIAL_HAS_PREDECESSOR", "SEMVER_INCREMENT_INVALID"],
        )

    def test_crosswalk_never_auto_selects_and_binds_exact_definitions(self) -> None:
        predecessor = release_candidate()
        successor = release_candidate(successor=True)
        assert successor.crosswalk is not None
        mapping = successor.crosswalk.mappings[0]
        bad_exact = replace(
            successor.crosswalk,
            mappings=(replace(mapping, target_codes=("DOMAIN.ENERGY", "TASK.AUDIT")),),
        )
        bad_initial = replace(
            successor.crosswalk,
            compatibility_level=TaxonomyCompatibilityLevel.INITIAL,
        )
        outcomes = [
            self._validate(
                rebind_artifact_descriptors(replace(successor, crosswalk=bad_exact)),
                predecessor=predecessor,
                registry=permanent_registry(predecessor),
            ),
            self._validate(
                rebind_artifact_descriptors(replace(successor, crosswalk=bad_initial)),
                predecessor=predecessor,
                registry=permanent_registry(predecessor),
            ),
        ]
        self.assertEqual(
            [item[1][2] if item[0] == "error" else item[0] for item in outcomes],
            ["EXACT_TARGET_CARDINALITY", "CROSSWALK_INITIAL_FORBIDDEN"],
        )

    def test_bundle_supersession_and_retirement_are_irreversible(self) -> None:
        active = bundle()
        superseded = self._call_semantic(
            lambda: active.supersede(
                successor_bundle_id=SUCCESSOR_ID, server_now=NOW
            )
        )
        if superseded[0] == "value":
            retired = self._call_semantic(
                lambda: superseded[1].retire(
                    reason_code="SECURITY_REVIEW", server_now=NOW
                )
            )
        else:
            retired = superseded
        if retired[0] == "value":
            terminal = self._call_semantic(
                lambda: retired[1].supersede(
                    successor_bundle_id="taxonomy_bundle_0000003",
                    server_now=NOW,
                )
            )
        else:
            terminal = retired
        self.assertEqual(
            (
                superseded[1].status.value if superseded[0] == "value" else superseded[0],
                retired[1].status.value if retired[0] == "value" else retired[0],
                terminal[1][2] if terminal[0] == "error" else terminal[0],
            ),
            (
                TaxonomyBundleStatus.SUPERSEDED.value,
                TaxonomyBundleStatus.RETIRED.value,
                "TERMINAL_STATE",
            ),
        )

    def test_all_domain_shapes_are_immutable(self) -> None:
        candidate = release_candidate()
        with self.assertRaises(FrozenInstanceError):
            candidate.manifest.bundle_id = SUCCESSOR_ID  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            candidate.nodes.nodes[0].kind = TaxonomyNodeKind.SKILL  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
