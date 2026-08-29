"""Contracts for closed INTERNAL_SANDBOX Compose input preparation."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prepare_internal_sandbox_compose_inputs.py"
IMAGE_TAG = "e2e-ten-account-v13-iam37-demand10-trust7"
BUNDLE_DIR_NAME = "internal-sandbox-bundle-iam37-demand10-trust7"
SUBNETS = {
    "ingress_subnet": "172.16.227.0/24",
    "oidc_subnet": "172.16.228.0/24",
    "app_subnet": "172.16.229.0/24",
    "data_subnet": "172.16.231.0/24",
}
BLOCKED = (
    '{"code":"INTERNAL_SANDBOX_COMPOSE_INPUTS_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "prepare_internal_sandbox_compose_inputs", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Compose input preparer cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _cli_arguments(command: str, root: Path) -> list[str]:
    return [
        command,
        "--input-root",
        str(root),
        "--image-tag",
        IMAGE_TAG,
        "--bundle-dir-name",
        BUNDLE_DIR_NAME,
        "--ingress-subnet",
        SUBNETS["ingress_subnet"],
        "--oidc-subnet",
        SUBNETS["oidc_subnet"],
        "--app-subnet",
        SUBNETS["app_subnet"],
        "--data-subnet",
        SUBNETS["data_subnet"],
    ]


def _call_arguments(root: Path) -> dict[str, object]:
    return {
        "input_root": root,
        "image_tag": IMAGE_TAG,
        "bundle_dir_name": BUNDLE_DIR_NAME,
        **SUBNETS,
    }


def _private_root() -> tempfile.TemporaryDirectory[str]:
    directory = tempfile.TemporaryDirectory(prefix="desire-compose-input-test-")
    os.chmod(directory.name, 0o700)
    return directory


class InternalSandboxComposeInputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_create_and_verify_exact_private_files_without_secret_output(self) -> None:
        with _private_root() as directory:
            root = Path(directory).resolve()
            secret = "do-not-print-this-deployment-secret"
            secret_path = root / "db_superuser_password.txt"
            secret_path.write_text(secret, encoding="ascii")
            secret_path.chmod(0o600)

            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(
                self.module.main(
                    _cli_arguments("create", root),
                    stdout=stdout,
                    stderr=stderr,
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED"}\n',
            )
            self.assertEqual(stderr.getvalue(), "")
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

            compose_env = root / "compose.env"
            compose_ipam = root / "compose.ipam.yaml"
            expected_env = (
                f"DESIRE_IMAGE_TAG={IMAGE_TAG}\n"
                f"DESIRE_DB_PASSWORD_FILE={root}/db_superuser_password.txt\n"
                "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE="
                f"{root}/taxonomy_seed_workload_credential\n"
                "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE="
                f"{root}/taxonomy_seed_receipt_hmac_key\n"
                f"DESIRE_IDENTITY_SOURCE_DIR={root}/internal-sandbox-identity-sources\n"
                f"DESIRE_INTERNAL_SANDBOX_TLS_DIR={root}/internal-sandbox-tls\n"
                f"DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR={root}/{BUNDLE_DIR_NAME}\n"
            ).encode("ascii")
            expected_ipam = (
                "networks:\n"
                "  ingress:\n"
                "    ipam:\n"
                "      config:\n"
                "        - subnet: 172.16.227.0/24\n"
                "  oidc-backend:\n"
                "    ipam:\n"
                "      config:\n"
                "        - subnet: 172.16.228.0/24\n"
                "  app:\n"
                "    ipam:\n"
                "      config:\n"
                "        - subnet: 172.16.229.0/24\n"
                "  data:\n"
                "    ipam:\n"
                "      config:\n"
                "        - subnet: 172.16.231.0/24\n"
            ).encode("ascii")
            self.assertEqual(compose_env.read_bytes(), expected_env)
            self.assertEqual(compose_ipam.read_bytes(), expected_ipam)
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {
                    "db_superuser_password.txt",
                    "compose.env",
                    "compose.ipam.yaml",
                },
            )
            for path in (compose_env, compose_ipam):
                with self.subTest(path=path):
                    file_stat = path.lstat()
                    self.assertTrue(stat.S_ISREG(file_stat.st_mode))
                    self.assertFalse(path.is_symlink())
                    self.assertEqual(stat.S_IMODE(file_stat.st_mode), 0o600)
                    self.assertEqual(file_stat.st_nlink, 1)

            before = {
                path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (compose_env, compose_ipam)
            }
            stdout = io.StringIO()
            stderr = io.StringIO()
            self.assertEqual(
                self.module.main(
                    _cli_arguments("verify", root),
                    stdout=stdout,
                    stderr=stderr,
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_VERIFIED"}\n',
            )
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                before,
                {
                    path.name: (path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in (compose_env, compose_ipam)
                },
            )

    def test_existing_target_refuses_overwrite_without_partial_creation(self) -> None:
        with _private_root() as directory:
            root = Path(directory).resolve()
            marker = root / "compose.env"
            marker.write_bytes(b"unchanged")
            marker.chmod(0o600)
            stdout = io.StringIO()
            stderr = io.StringIO()

            self.assertEqual(
                self.module.main(
                    _cli_arguments("create", root),
                    stdout=stdout,
                    stderr=stderr,
                ),
                78,
            )
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), BLOCKED)
            self.assertEqual(marker.read_bytes(), b"unchanged")
            self.assertFalse((root / "compose.ipam.yaml").exists())

    def test_create_failure_rolls_back_only_the_owned_output(self) -> None:
        with _private_root() as directory:
            root = Path(directory).resolve()
            real_write = self.module._write_new

            def fail_second(path, value, *, mode):
                if path.name == "compose.ipam.yaml":
                    raise OSError("fixture")
                return real_write(path, value, mode=mode)

            with mock.patch.object(self.module, "_write_new", side_effect=fail_second):
                with self.assertRaises(OSError):
                    self.module.create_compose_inputs(**_call_arguments(root))
            self.assertFalse((root / "compose.env").exists())
            self.assertFalse((root / "compose.ipam.yaml").exists())

        with _private_root() as directory:
            root = Path(directory).resolve()
            with mock.patch.object(
                self.module, "_write_all", side_effect=OSError("fixture")
            ):
                with self.assertRaises(OSError):
                    self.module.create_compose_inputs(**_call_arguments(root))
            self.assertFalse((root / "compose.env").exists())
            self.assertFalse((root / "compose.ipam.yaml").exists())

    def test_private_root_with_spaces_is_safely_single_quoted(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="desire-compose-input-parent-"
        ) as parent_directory:
            root = Path(parent_directory).resolve() / "private input root"
            root.mkdir(mode=0o700)
            self.module.create_compose_inputs(**_call_arguments(root))
            environment = (root / "compose.env").read_text(encoding="utf-8")
            self.assertIn(
                f"DESIRE_DB_PASSWORD_FILE='{root}/db_superuser_password.txt'\n",
                environment,
            )
            self.module.verify_compose_inputs(**_call_arguments(root))

    def test_verify_rejects_byte_mode_symlink_hardlink_and_argument_drift(self) -> None:
        mutations = (
            "bytes",
            "mode",
            "symlink",
            "hardlink",
            "argument",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with _private_root() as directory:
                    root = Path(directory).resolve()
                    self.module.create_compose_inputs(**_call_arguments(root))
                    compose_env = root / "compose.env"
                    compose_ipam = root / "compose.ipam.yaml"
                    arguments = _call_arguments(root)
                    if mutation == "bytes":
                        compose_env.write_bytes(compose_env.read_bytes() + b"EXTRA=1\n")
                        compose_env.chmod(0o600)
                    elif mutation == "mode":
                        compose_ipam.chmod(0o644)
                    elif mutation == "symlink":
                        compose_env.unlink()
                        compose_env.symlink_to(compose_ipam)
                    elif mutation == "hardlink":
                        os.link(compose_ipam, root / "compose.ipam.alias")
                    else:
                        arguments["image_tag"] = IMAGE_TAG + "-drift"
                    with self.assertRaises(
                        self.module.InternalSandboxComposeInputError
                    ):
                        self.module.verify_compose_inputs(**arguments)

    def test_rejects_non_private_root_and_unsafe_tokens(self) -> None:
        with _private_root() as directory:
            root = Path(directory).resolve()
            root.chmod(0o755)
            with self.assertRaises(self.module.InternalSandboxComposeInputError):
                self.module.create_compose_inputs(**_call_arguments(root))

        with tempfile.TemporaryDirectory(
            prefix="desire-compose-input-parent-"
        ) as parent_directory:
            parent = Path(parent_directory).resolve()
            real_root = parent / "real"
            real_root.mkdir(mode=0o700)
            linked_root = parent / "linked"
            linked_root.symlink_to(real_root, target_is_directory=True)
            with self.assertRaises(self.module.InternalSandboxComposeInputError):
                self.module.create_compose_inputs(**_call_arguments(linked_root))

        with self.assertRaises(self.module.InternalSandboxComposeInputError):
            self.module.create_compose_inputs(
                **_call_arguments(Path("relative-input-root"))
            )

        invalid_tokens = (
            ("image_tag", "bad/tag"),
            ("image_tag", "bad:tag"),
            ("image_tag", "UPPERCASE"),
            ("bundle_dir_name", "../bundle"),
            ("bundle_dir_name", "bundle/name"),
            ("bundle_dir_name", ".hidden"),
        )
        for key, value in invalid_tokens:
            with self.subTest(key=key, value=value):
                with _private_root() as directory:
                    arguments = _call_arguments(Path(directory).resolve())
                    arguments[key] = value
                    with self.assertRaises(
                        self.module.InternalSandboxComposeInputError
                    ):
                        self.module.create_compose_inputs(**arguments)

    def test_rejects_duplicate_non_rfc1918_non_24_and_noncanonical_subnets(
        self,
    ) -> None:
        invalid_subnets = (
            ("oidc_subnet", SUBNETS["ingress_subnet"]),
            ("ingress_subnet", "203.0.113.0/24"),
            ("ingress_subnet", "172.16.227.0/25"),
            ("ingress_subnet", "172.16.227.1/24"),
            ("ingress_subnet", "fd00::/24"),
        )
        for key, value in invalid_subnets:
            with self.subTest(key=key, value=value):
                with _private_root() as directory:
                    arguments = _call_arguments(Path(directory).resolve())
                    arguments[key] = value
                    with self.assertRaises(
                        self.module.InternalSandboxComposeInputError
                    ):
                        self.module.create_compose_inputs(**arguments)

    def test_cli_parse_and_validation_failures_are_stable_and_non_reflective(
        self,
    ) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(
            self.module.main(
                ["create", "--input-root", "secret-looking-value"],
                stdout=stdout,
                stderr=stderr,
            ),
            78,
        )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), BLOCKED)
        self.assertNotIn("secret-looking-value", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
