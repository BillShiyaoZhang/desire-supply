"""Contracts for local-only INTERNAL_SANDBOX deployment input preparation."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare_internal_sandbox_inputs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "prepare_internal_sandbox_inputs", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("input preparer cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InternalSandboxInputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_create_and_verify_closed_inputs_without_printing_material(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-input-test-") as directory:
            root = Path(directory).resolve()
            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(
                self.module.main(
                    ["create", "--output-root", str(root)],
                    stdout=stdout,
                    stderr=stderr,
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_INPUTS_CREATED"}\n',
            )
            self.assertEqual(stderr.getvalue(), "")
            for name in self.module.SECRET_FILES:
                path = root / name
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(path.read_text("ascii", errors="ignore"), stdout.getvalue())
            identity = root / self.module.IDENTITY_DIRECTORY
            self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o755)
            self.assertEqual(
                {path.name for path in identity.iterdir()},
                set(self.module.IDENTITY_FILES),
            )
            for name, expected in self.module.IDENTITY_FILES.items():
                path = identity / name
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)

            stdout = io.StringIO()
            self.assertEqual(
                self.module.main(
                    ["verify", "--input-root", str(root)], stdout=stdout
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_INPUTS_VERIFIED"}\n',
            )

    def test_existing_target_refuses_overwrite_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-input-test-") as directory:
            root = Path(directory).resolve()
            marker = root / "db_superuser_password.txt"
            marker.write_bytes(b"unchanged")
            marker.chmod(0o600)
            stderr = io.StringIO()
            self.assertEqual(
                self.module.main(
                    ["create", "--output-root", str(root)], stderr=stderr
                ),
                78,
            )
            self.assertEqual(marker.read_bytes(), b"unchanged")
            self.assertEqual(
                stderr.getvalue(),
                '{"code":"INTERNAL_SANDBOX_INPUTS_INVALID","status":"BLOCKED"}\n',
            )

    def test_verify_rejects_permissions_aliases_identity_drift_and_relative_root(self) -> None:
        mutations = (
            lambda root: (root / "oidc-client-secret").chmod(0o644),
            lambda root: (root / "taxonomy_seed_receipt_hmac_key").write_bytes(b"x" * 31),
            lambda root: (
                (root / "internal-sandbox-identity-sources" / "creator_01.subject").chmod(0o600),
                (root / "internal-sandbox-identity-sources" / "creator_01.subject").write_bytes(b"real-person"),
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                with tempfile.TemporaryDirectory(prefix="desire-input-test-") as directory:
                    root = Path(directory).resolve()
                    self.module.create_inputs(root)
                    mutate(root)
                    with self.assertRaises(self.module.InternalSandboxInputError):
                        self.module.verify_inputs(root)
        with self.assertRaises(self.module.InternalSandboxInputError):
            self.module.verify_inputs(Path("relative"))


if __name__ == "__main__":
    unittest.main()
