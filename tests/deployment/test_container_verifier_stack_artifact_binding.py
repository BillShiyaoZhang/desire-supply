"""Offline tests for the reviewed Dockerfile and Compose byte bindings."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "scripts" / "verify_container_stack.py"
GATE_PATH = ROOT / "scripts" / "preflight_docker_hub_manifests.py"
EXPECTED_ARTIFACT_SHA256 = (
    (
        "Dockerfile",
        "6d16a0a7179dcf62fe7cdf2b2a76b39b1d1db8c450ea2d1df35ed0ec84b14677",
    ),
    (
        "compose.yaml",
        "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd",
    ),
)


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_container_stack_artifact_binding",
        VERIFY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()


class ContainerVerifierStackArtifactBindingTest(unittest.TestCase):
    def test_checked_in_bytes_match_the_closed_reviewed_digests(self) -> None:
        self.assertEqual(
            VERIFIER.REVIEWED_CONTAINER_ARTIFACT_SHA256,
            EXPECTED_ARTIFACT_SHA256,
        )
        for relative, expected_sha256 in EXPECTED_ARTIFACT_SHA256:
            with self.subTest(path=relative):
                self.assertEqual(
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                    expected_sha256,
                )

    def test_missing_artifact_blocks_before_any_compose_invocation(self) -> None:
        original_is_file = Path.is_file
        original_read_bytes = Path.read_bytes
        gate_bytes = GATE_PATH.read_bytes()
        gate_sha256 = hashlib.sha256(gate_bytes).hexdigest()

        for relative, _expected_sha256 in EXPECTED_ARTIFACT_SHA256:
            with self.subTest(path=relative):
                target = ROOT / relative

                def is_file_with_missing_target(path: Path) -> bool:
                    if path == target:
                        return False
                    return original_is_file(path)

                def read_with_stable_gate(path: Path) -> bytes:
                    if path == GATE_PATH:
                        return gate_bytes
                    return original_read_bytes(path)

                with (
                    mock.patch.object(
                        Path,
                        "is_file",
                        new=is_file_with_missing_target,
                    ),
                    mock.patch.object(
                        Path,
                        "read_bytes",
                        new=read_with_stable_gate,
                    ),
                    mock.patch.object(
                        VERIFIER,
                        "DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256",
                        gate_sha256,
                    ),
                    mock.patch.object(
                        VERIFIER,
                        "_compose",
                        side_effect=AssertionError(
                            "compose must not be invoked"
                        ),
                    ) as compose,
                ):
                    failures = VERIFIER.verify(ROOT)

                self.assertEqual(failures, (f"missing:{relative}",))
                compose.assert_not_called()

    def test_first_middle_or_last_byte_mutation_blocks_before_compose(self) -> None:
        original_read_bytes = Path.read_bytes
        gate_bytes = GATE_PATH.read_bytes()
        gate_sha256 = hashlib.sha256(gate_bytes).hexdigest()

        for relative, expected_sha256 in EXPECTED_ARTIFACT_SHA256:
            target = ROOT / relative
            approved = target.read_bytes()
            self.assertGreater(len(approved), 2)
            self.assertEqual(
                hashlib.sha256(approved).hexdigest(),
                expected_sha256,
            )
            for index in (0, len(approved) // 2, len(approved) - 1):
                with self.subTest(path=relative, byte_index=index):
                    mutated = bytearray(approved)
                    mutated[index] ^= 0x01

                    def read_with_mutated_target(path: Path) -> bytes:
                        if path == target:
                            return bytes(mutated)
                        if path == GATE_PATH:
                            return gate_bytes
                        return original_read_bytes(path)

                    with (
                        mock.patch.object(
                            Path,
                            "read_bytes",
                            new=read_with_mutated_target,
                        ),
                        mock.patch.object(
                            VERIFIER,
                            "DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256",
                            gate_sha256,
                        ),
                        mock.patch.object(
                            VERIFIER,
                            "_compose",
                            side_effect=AssertionError(
                                "compose must not be invoked"
                            ),
                        ) as compose,
                    ):
                        failures = VERIFIER.verify(ROOT)

                    self.assertEqual(
                        failures,
                        (
                            "reviewed-container-artifact-digest-open:"
                            f"{relative}",
                        ),
                    )
                    compose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
