"""Offline tests for the container verifier's manifest-gate binding."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts" / "verify_container_stack.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_container_stack_manifest_binding",
        VERIFY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()
GATE_RELATIVE = "scripts/preflight_docker_hub_manifests.py"
GATE_PATH = ROOT / GATE_RELATIVE
EXPECTED_GATE_SHA256 = (
    "0665199dc79fd359d435d9159bed69bc21d73d19887fe2f77f2c79ab199ea5b0"
)


class ContainerVerifierManifestBindingTest(unittest.TestCase):
    def test_checked_in_gate_bytes_match_the_closed_digest(self) -> None:
        self.assertEqual(
            VERIFIER.DOCKER_HUB_MANIFEST_PREFLIGHT_RELATIVE_PATH,
            GATE_RELATIVE,
        )
        self.assertEqual(
            VERIFIER.DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256,
            EXPECTED_GATE_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(GATE_PATH.read_bytes()).hexdigest(),
            EXPECTED_GATE_SHA256,
        )

    def test_missing_gate_blocks_before_compose_is_inspected(self) -> None:
        original_is_file = Path.is_file

        def gate_is_missing(path: Path) -> bool:
            if path == GATE_PATH:
                return False
            return original_is_file(path)

        with (
            mock.patch.object(Path, "is_file", new=gate_is_missing),
            mock.patch.object(
                VERIFIER,
                "_compose",
                side_effect=AssertionError("compose must not be inspected"),
            ) as compose,
        ):
            failures = VERIFIER.verify(ROOT)

        self.assertEqual(failures, (f"missing:{GATE_RELATIVE}",))
        compose.assert_not_called()

    def test_arbitrary_gate_byte_mutation_blocks_before_compose(self) -> None:
        original_read_bytes = Path.read_bytes
        approved = GATE_PATH.read_bytes()
        self.assertGreater(len(approved), 2)
        self.assertEqual(
            hashlib.sha256(approved).hexdigest(),
            VERIFIER.DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256,
        )

        for index in (0, len(approved) // 2, len(approved) - 1):
            with self.subTest(byte_index=index):
                mutated = bytearray(approved)
                mutated[index] ^= 0x01

                def read_with_mutated_gate(path: Path) -> bytes:
                    if path == GATE_PATH:
                        return bytes(mutated)
                    return original_read_bytes(path)

                with (
                    mock.patch.object(
                        Path,
                        "read_bytes",
                        new=read_with_mutated_gate,
                    ),
                    mock.patch.object(
                        VERIFIER,
                        "_compose",
                        side_effect=AssertionError(
                            "compose must not be inspected"
                        ),
                    ) as compose,
                ):
                    failures = VERIFIER.verify(ROOT)

                self.assertEqual(
                    failures,
                    ("docker-hub-manifest-preflight-digest-open",),
                )
                compose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
