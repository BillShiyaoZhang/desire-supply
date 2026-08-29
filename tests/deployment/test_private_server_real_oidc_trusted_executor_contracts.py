"""Offline mutation tests for the trusted-executor create-intent contract."""

from __future__ import annotations

import ast
import builtins
import copy
from dataclasses import FrozenInstanceError, fields
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    ROOT / "scripts/private_server_real_oidc_trusted_executor_contracts.py"
)
SCHEMA_PATH = (
    ROOT / "deploy/private-server-real-oidc-broker-create-intent-v1.schema.json"
)


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


contracts = _module("test_real_oidc_trusted_executor_contracts", CONTRACT_PATH)


PROJECT = "desire-real-oidc-broker01"
SERVICES = (
    "api",
    "db",
    "edge",
    "identity-bootstrap",
    "migrate",
    "matching-runtime",
    "oidc-egress-guard",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "taxonomy-seed",
    "web",
)
NETWORKS = ("app", "data", "ingress", "oidc-egress")
IMAGE_REFERENCES = (
    "desire-supply-edge:broker-contract",
    "desire-supply-oidc-egress-guard:broker-contract",
    "desire-supply-platform:broker-contract",
    "desire-supply-web:broker-contract",
    "postgres:17.6-alpine",
)


def _canonical(value) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _document() -> dict:
    snapshot_sha256 = hashlib.sha256(b"snapshot-manifest").hexdigest()
    return {
        "format": "desire-real-oidc-broker-create-intent-v1",
        "status": "VALIDATED_REQUEST_NOT_AUTHORITY",
        "authority": "NOT_AUTHORITY",
        "legacy_execution_accepted": False,
        "bindings": {
            "project": PROJECT,
            "snapshot_sha256": snapshot_sha256,
            "snapshot_manifest": {
                "sha256": snapshot_sha256,
                "device": 123,
                "inode": 456,
            },
            "compose_sha256": hashlib.sha256(b"compose").hexdigest(),
        },
        "images": [
            {
                "reference": reference,
                "id": "sha256:"
                + hashlib.sha256(("image:" + reference).encode("ascii")).hexdigest(),
            }
            for reference in IMAGE_REFERENCES
        ],
        "expected_prestate": {
            "containers": {
                service: {
                    "name": PROJECT + "-" + service + "-1",
                    "prestate": "ABSENT",
                }
                for service in SERVICES
            },
            "networks": {
                logical: {
                    "name": PROJECT + "_" + logical,
                    "prestate": "ABSENT",
                }
                for logical in NETWORKS
            },
            "postgres_volume": {
                "name": PROJECT + "_postgres-data",
                "prestate": "ABSENT",
            },
        },
        "operation_template_id": "CREATE_BOUND_REAL_OIDC_RESOURCES_ZERO_START_V1",
        "expected_postcondition": {
            "state": "CREATED_ZERO_START",
            "containers_created": len(SERVICES),
            "containers_started": 0,
            "process_start_allowed": False,
            "post_create_reinspection_required": True,
        },
        "rollback_policy": "PRESERVE_POSTGRES_VOLUME",
    }


class TrustedExecutorContractTest(unittest.TestCase):
    def assert_invalid(self, value) -> None:
        raw = value if isinstance(value, bytes) else _canonical(value)
        with self.assertRaises(contracts.TrustedExecutorContractError):
            contracts.parse_trusted_executor_ingress(raw)
        with self.assertRaises(contracts.TrustedExecutorContractError):
            contracts.parse_broker_create_intent(raw)

    def test_schema_is_closed_and_matches_the_frozen_parser_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "format",
                "status",
                "authority",
                "legacy_execution_accepted",
                "bindings",
                "images",
                "expected_prestate",
                "operation_template_id",
                "expected_postcondition",
                "rollback_policy",
            },
        )
        self.assertEqual(
            schema["properties"]["format"]["const"],
            "desire-real-oidc-broker-create-intent-v1",
        )
        self.assertEqual(
            schema["properties"]["status"]["const"],
            "VALIDATED_REQUEST_NOT_AUTHORITY",
        )
        self.assertEqual(schema["properties"]["authority"]["const"], "NOT_AUTHORITY")
        self.assertIs(
            schema["properties"]["legacy_execution_accepted"]["const"], False
        )
        self.assertEqual(schema["properties"]["images"]["minItems"], 5)
        self.assertEqual(schema["properties"]["images"]["maxItems"], 5)
        for definition in (
            "Bindings",
            "SnapshotManifest",
            "Image",
            "AbsentResource",
            "ExpectedPrestate",
            "Containers",
            "Networks",
            "ExpectedPostcondition",
        ):
            self.assertIs(schema["$defs"][definition]["additionalProperties"], False)
        self.assertEqual(
            set(schema["$defs"]["Containers"]["required"]), set(SERVICES)
        )
        self.assertEqual(set(schema["$defs"]["Networks"]["required"]), set(NETWORKS))

    def test_valid_intent_returns_a_frozen_redacted_value(self) -> None:
        raw = _canonical(_document())
        value = contracts.parse_trusted_executor_ingress(raw)
        self.assertIsInstance(value, contracts.BrokerCreateIntent)
        self.assertEqual(value.raw, raw)
        self.assertEqual(value.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(value.project, PROJECT)
        self.assertEqual(value.status, "VALIDATED_REQUEST_NOT_AUTHORITY")
        self.assertEqual(value.authority, "NOT_AUTHORITY")
        self.assertEqual(value.images, tuple(
            (item["reference"], item["id"]) for item in _document()["images"]
        ))
        self.assertEqual(len(value.containers), len(SERVICES))
        self.assertEqual(len(value.networks), 4)
        self.assertEqual(value.postgres_volume, PROJECT + "_postgres-data")
        self.assertEqual(
            value.operation_template_id,
            "CREATE_BOUND_REAL_OIDC_RESOURCES_ZERO_START_V1",
        )
        self.assertFalse(
            contracts.BrokerCreateIntent.__dataclass_params__.repr
        )
        self.assertTrue(
            contracts.BrokerCreateIntent.__dataclass_params__.frozen
        )
        with self.assertRaises(FrozenInstanceError):
            value.project = "desire-real-oidc-replaced"
        rendered = repr(value)
        self.assertIn("BrokerCreateIntent object at", rendered)
        self.assertNotIn(PROJECT, rendered)
        self.assertNotIn(value.sha256, rendered)
        self.assertNotIn(value.snapshot_sha256, rendered)
        self.assertNotIn(value.compose_sha256, rendered)
        self.assertNotIn(IMAGE_REFERENCES[0], rendered)
        self.assertNotIn(_document()["images"][0]["id"], rendered)
        self.assertNotIn(raw.decode("ascii"), rendered)
        self.assertEqual(
            {field.name for field in fields(value)},
            {
                "raw",
                "sha256",
                "project",
                "snapshot_sha256",
                "snapshot_manifest_sha256",
                "snapshot_manifest_device",
                "snapshot_manifest_inode",
                "compose_sha256",
                "images",
                "containers",
                "networks",
                "postgres_volume",
                "operation_template_id",
                "status",
                "authority",
            },
        )

    def test_every_root_field_is_required_and_the_shape_is_exact(self) -> None:
        valid = _document()
        for key in tuple(valid):
            with self.subTest(missing=key):
                changed = copy.deepcopy(valid)
                del changed[key]
                self.assert_invalid(changed)
        for key in (
            "extra",
            "command",
            "argv",
            "env",
            "path",
            "socket",
            "cwd",
        ):
            with self.subTest(extra=key):
                changed = copy.deepcopy(valid)
                changed[key] = "forbidden"
                self.assert_invalid(changed)

    def test_all_nested_objects_reject_missing_and_extra_fields(self) -> None:
        targets = (
            ("bindings",),
            ("bindings", "snapshot_manifest"),
            ("images", 0),
            ("expected_prestate",),
            ("expected_prestate", "containers"),
            ("expected_prestate", "containers", "api"),
            ("expected_prestate", "networks"),
            ("expected_prestate", "networks", "app"),
            ("expected_prestate", "postgres_volume"),
            ("expected_postcondition",),
        )
        for target_path in targets:
            valid = _document()
            target = valid
            for part in target_path:
                target = target[part]
            with self.subTest(target=target_path, mutation="extra"):
                target["extra"] = False
                self.assert_invalid(valid)

            valid = _document()
            target = valid
            for part in target_path:
                target = target[part]
            removed = next(iter(target))
            with self.subTest(target=target_path, mutation="missing", key=removed):
                del target[removed]
                self.assert_invalid(valid)

    def test_fixed_non_authority_and_zero_start_values_are_not_upgradeable(self) -> None:
        mutations = (
            (("format",), "desire-real-oidc-broker-create-intent-v2"),
            (("status",), "APPROVED"),
            (("authority",), "AUTHORITY"),
            (("legacy_execution_accepted",), True),
            (("operation_template_id",), "CALLER_SUPPLIED_TEMPLATE"),
            (("rollback_policy",), "DELETE_ALL"),
            (("expected_postcondition", "state"), "STARTED"),
            (("expected_postcondition", "containers_created"), 10),
            (("expected_postcondition", "containers_created"), True),
            (("expected_postcondition", "containers_started"), 1),
            (("expected_postcondition", "containers_started"), False),
            (("expected_postcondition", "process_start_allowed"), True),
            (("expected_postcondition", "process_start_allowed"), 0),
            (("expected_postcondition", "post_create_reinspection_required"), False),
            (("expected_postcondition", "post_create_reinspection_required"), 1),
        )
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                changed = _document()
                target = changed
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assert_invalid(changed)

    def test_snapshot_manifest_compose_and_project_bindings_are_exact(self) -> None:
        mutations = (
            (("bindings", "project"), "other-project"),
            (("bindings", "project"), PROJECT + "/escape"),
            (("bindings", "project"), "desire-real-oidc-broker_01"),
            (("bindings", "project"), "desire-real-oidc-broker-"),
            (("bindings", "project"), "desire-real-oidc-" + "a" * 41),
            (("bindings", "snapshot_sha256"), "f" * 63),
            (("bindings", "snapshot_sha256"), "F" * 64),
            (("bindings", "snapshot_manifest", "sha256"), "e" * 64),
            (("bindings", "snapshot_manifest", "device"), 0),
            (("bindings", "snapshot_manifest", "device"), True),
            (("bindings", "snapshot_manifest", "inode"), -1),
            (("bindings", "snapshot_manifest", "inode"), False),
            (("bindings", "compose_sha256"), "sha256:" + "e" * 64),
        )
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                changed = _document()
                target = changed
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = replacement
                self.assert_invalid(changed)

    def test_image_binding_requires_exactly_five_sorted_unique_refs_and_ids(self) -> None:
        valid = _document()
        variants = []
        too_few = copy.deepcopy(valid)
        too_few["images"].pop()
        variants.append(("too_few", too_few))
        too_many = copy.deepcopy(valid)
        too_many["images"].append(
            {"reference": "sixth:image", "id": "sha256:" + "6" * 64}
        )
        variants.append(("too_many", too_many))
        reordered = copy.deepcopy(valid)
        reordered["images"][0], reordered["images"][1] = (
            reordered["images"][1], reordered["images"][0]
        )
        variants.append(("reordered", reordered))
        duplicate_reference = copy.deepcopy(valid)
        duplicate_reference["images"][1]["reference"] = duplicate_reference["images"][0]["reference"]
        variants.append(("duplicate_reference", duplicate_reference))
        duplicate_id = copy.deepcopy(valid)
        duplicate_id["images"][1]["id"] = duplicate_id["images"][0]["id"]
        variants.append(("duplicate_id", duplicate_id))
        bad_id = copy.deepcopy(valid)
        bad_id["images"][0]["id"] = "sha256:" + "F" * 64
        variants.append(("bad_id", bad_id))
        bad_reference = copy.deepcopy(valid)
        bad_reference["images"][0]["reference"] = "repo image:tag"
        variants.append(("bad_reference", bad_reference))
        non_list = copy.deepcopy(valid)
        non_list["images"] = {}
        variants.append(("non_list", non_list))
        for name, changed in variants:
            with self.subTest(name=name):
                self.assert_invalid(changed)

    def test_all_ten_containers_four_networks_and_volume_must_be_absent(self) -> None:
        for kind, logical_names, separator, suffix in (
            ("containers", SERVICES, "-", "-1"),
            ("networks", NETWORKS, "_", ""),
        ):
            for logical in logical_names:
                with self.subTest(kind=kind, logical=logical, mutation="missing"):
                    changed = _document()
                    del changed["expected_prestate"][kind][logical]
                    self.assert_invalid(changed)
                with self.subTest(kind=kind, logical=logical, mutation="name"):
                    changed = _document()
                    changed["expected_prestate"][kind][logical]["name"] = (
                        PROJECT + separator + logical + suffix + "-foreign"
                    )
                    self.assert_invalid(changed)
                with self.subTest(kind=kind, logical=logical, mutation="state"):
                    changed = _document()
                    changed["expected_prestate"][kind][logical]["prestate"] = "PRESENT"
                    self.assert_invalid(changed)
        for field, value in (
            ("name", PROJECT + "_other-volume"),
            ("prestate", "PRESENT"),
        ):
            changed = _document()
            changed["expected_prestate"]["postgres_volume"][field] = value
            self.assert_invalid(changed)

    def test_parser_rejects_noncanonical_duplicate_float_constant_and_oversize_json(self) -> None:
        document = _document()
        raw = _canonical(document)
        self.assert_invalid(json.dumps(document).encode("ascii"))
        self.assert_invalid(raw[:-1])
        self.assert_invalid(b"\xef\xbb\xbf" + raw)
        duplicate = raw.replace(
            b'{"authority":"NOT_AUTHORITY",',
            b'{"authority":"NOT_AUTHORITY","authority":"NOT_AUTHORITY",',
            1,
        )
        self.assert_invalid(duplicate)
        floating = copy.deepcopy(document)
        floating["bindings"]["snapshot_manifest"]["device"] = 1.0
        self.assert_invalid(_canonical(floating))
        nan = raw.replace(b'"device":123', b'"device":NaN', 1)
        self.assert_invalid(nan)
        self.assert_invalid(b"{" + b" " * (64 * 1024) + b"}")
        for value in (None, "", bytearray(raw), memoryview(raw)):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(contracts.TrustedExecutorContractError):
                    contracts.parse_trusted_executor_ingress(value)

    def test_every_legacy_format_is_permanently_rejected_at_root_and_in_wrappers(self) -> None:
        required = {
            "desire-real-oidc-activation-authorization-v1",
            "desire-real-oidc-start-authorization-v1",
            "desire-real-oidc-create-plan-v1",
            "desire-real-oidc-start-plan-v1",
            "desire-real-oidc-execution-stage-v1",
            "desire-real-oidc-post-create-evidence-v1",
            "desire-real-oidc-post-create-evidence-v2",
        }
        self.assertTrue(
            required.issubset(set(contracts.PERMANENTLY_REJECTED_LEGACY_FORMATS))
        )
        for legacy_format in contracts.PERMANENTLY_REJECTED_LEGACY_FORMATS:
            for document in (
                {"format": legacy_format},
                {
                    "format": "caller-wrapper-v1",
                    "payload": {"artifact": {"format": legacy_format}},
                },
            ):
                with self.subTest(format=legacy_format, wrapped=len(document) > 1):
                    with self.assertRaises(
                        contracts.LegacyExecutionArtifactPermanentlyRejected
                    ):
                        contracts.parse_trusted_executor_ingress(_canonical(document))

    def test_unknown_formats_and_wrapped_new_intents_are_rejected(self) -> None:
        for document in (
            {"format": "desire-real-oidc-future-unknown-v99"},
            {"format": ["desire-real-oidc-broker-create-intent-v1"]},
            {"payload": _document()},
            {"format": "caller-wrapper-v1", "payload": _document()},
        ):
            with self.subTest(document=document):
                self.assert_invalid(document)

    def test_forbidden_execution_transport_fields_are_rejected_recursively(self) -> None:
        forbidden = (
            "arg",
            "args",
            "argument",
            "arguments",
            "argv",
            "command",
            "commands",
            "cwd",
            "docker_socket",
            "endpoint",
            "env",
            "environment",
            "path",
            "paths",
            "socket",
            "socket_path",
            "working_directory",
        )
        for key in forbidden:
            changed = _document()
            changed["expected_prestate"]["containers"]["api"][key] = "injected"
            with self.subTest(field=key):
                self.assert_invalid(changed)

    def test_parser_has_zero_host_or_lifecycle_side_effects_and_no_execute_api(self) -> None:
        raw = _canonical(_document())
        with (
            mock.patch.object(builtins, "open") as builtins_open,
            mock.patch.object(os, "open") as os_open,
            mock.patch.object(subprocess, "run") as run,
            mock.patch.object(subprocess, "Popen") as popen,
            mock.patch.object(socket, "socket") as socket_open,
        ):
            value = contracts.parse_broker_create_intent(raw)
        self.assertEqual(value.raw, raw)
        for call in (builtins_open, os_open, run, popen, socket_open):
            call.assert_not_called()
        for name in (
            "execute",
            "execute_create",
            "create_resources",
            "claim_nonce",
            "acquire_lease",
        ):
            self.assertFalse(hasattr(contracts, name))

        tree = ast.parse(CONTRACT_PATH.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            {"subprocess", "socket", "pathlib", "fcntl", "os"}.isdisjoint(imported)
        )

    def test_existing_activation_execute_ingress_remains_unreachable(self) -> None:
        activate = _module(
            "test_real_oidc_activate_execute_stays_blocked",
            ROOT / "scripts/activate_private_server_real_oidc.py",
        )
        stdout = io.StringIO()
        with mock.patch.object(subprocess, "run") as run:
            result = activate.main(
                ("--action", "execute", "--attempt-root", "/not-inspected"),
                stdout=stdout,
            )
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), activate.BLOCKED)
        run.assert_not_called()

    def test_frozen_input_contract_does_not_remove_create_or_origin_blockers(self) -> None:
        preflight = _module(
            "test_real_oidc_create_intent_keeps_execute_blockers",
            ROOT / "scripts/preflight_private_server_real_oidc.py",
        )
        for blocker in (
            "TRUSTED_CREATE_ONLY_PROTOCOL_UNIMPLEMENTED",
            "RESOURCE_ORIGIN_ATTESTATION_UNIMPLEMENTED",
        ):
            with self.subTest(blocker=blocker):
                self.assertIn(blocker, preflight._CREATE_PLAN_BLOCKERS)
                self.assertIn(blocker, preflight._START_EXECUTE_BLOCKERS)
                self.assertIn(blocker, preflight._COLLECTED_START_EXECUTE_BLOCKERS)


if __name__ == "__main__":
    unittest.main()
