"""TDD contract for offline INTERNAL_SANDBOX TLS fixture management."""

from __future__ import annotations

import importlib.util
import io
from contextlib import redirect_stderr
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "manage_internal_sandbox_tls.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("manage_internal_sandbox_tls", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("TLS fixture manager cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _memory_tls_handshake(*, root: Path, chain: Path, key: Path, hostname: str) -> None:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=chain, keyfile=key)
    # Explicit cafile loading is semantically identical to the official
    # Python container's SSL_CERT_FILE default path, while remaining portable
    # to the Apple system Python used by this repository's host-only tests.
    client_context = ssl.create_default_context(cafile=str(root))
    client_in = ssl.MemoryBIO()
    client_out = ssl.MemoryBIO()
    server_in = ssl.MemoryBIO()
    server_out = ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname=hostname,
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = False
    server_done = False
    for _attempt in range(32):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        request = client_out.read()
        if request:
            server_in.write(request)
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        response = server_out.read()
        if response:
            client_in.write(response)
        if client_done and server_done:
            return
    raise AssertionError("in-memory TLS handshake did not complete")


class InternalSandboxTlsFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_create_and_verify_emit_only_the_three_closed_assets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
            target = Path(directory).resolve() / "fixture"
            stdout = io.StringIO()
            self.assertEqual(
                self.module.main(
                    ["create", "--output-dir", str(target)],
                    stdout=stdout,
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_TLS_CREATED"}\n',
            )
            self.assertEqual(
                {path.name for path in target.iterdir()},
                {"root-ca.pem", "edge-tls-chain.pem", "edge-tls-key.pem"},
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((target / "edge-tls-key.pem").stat().st_mode),
                0o400,
            )
            self.assertEqual(
                stat.S_IMODE((target / "root-ca.pem").stat().st_mode),
                0o444,
            )
            self.assertEqual(
                stat.S_IMODE((target / "edge-tls-chain.pem").stat().st_mode),
                0o444,
            )
            self.assertNotIn(b"PRIVATE KEY", (target / "root-ca.pem").read_bytes())
            self.assertEqual(
                (target / "edge-tls-chain.pem").read_bytes().count(
                    b"-----BEGIN CERTIFICATE-----"
                ),
                2,
            )

            stdout = io.StringIO()
            self.assertEqual(
                self.module.main(
                    ["verify", "--input-dir", str(target)],
                    stdout=stdout,
                ),
                0,
            )
            self.assertEqual(
                stdout.getvalue(),
                '{"status":"INTERNAL_SANDBOX_TLS_VERIFIED"}\n',
            )

    def test_certificate_contract_is_exact_ca_chain_san_usage_and_key_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
            target = Path(directory).resolve() / "fixture"
            self.module.create_fixture(target)
            root = target / "root-ca.pem"
            chain = target / "edge-tls-chain.pem"
            leaf = target / "leaf.pem"
            leaf.write_bytes(chain.read_bytes().split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n")
            try:
                verify = subprocess.run(
                    ["openssl", "verify", "-CAfile", str(root), str(leaf)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
                text = subprocess.run(
                    ["openssl", "x509", "-in", str(leaf), "-noout", "-text"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertIn("DNS:identity.example.test", text)
                self.assertIn("DNS:pilot.example.test", text)
                self.assertEqual(text.count("DNS:"), 2)
                self.assertIn("TLS Web Server Authentication", text)
                self.assertIn("CA:FALSE", text)
                self.assertIn("Digital Signature", text)
                self.assertIn("Key Encipherment", text)
                root_text = subprocess.run(
                    ["openssl", "x509", "-in", str(root), "-noout", "-text"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertIn("CA:TRUE", root_text)
                self.assertIn("Certificate Sign", root_text)
                self.assertIn("CRL Sign", root_text)
                leaf_public = subprocess.run(
                    ["openssl", "x509", "-in", str(leaf), "-pubkey", "-noout"],
                    check=True,
                    capture_output=True,
                ).stdout
                key_public = subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-in",
                        str(target / "edge-tls-key.pem"),
                        "-pubout",
                    ],
                    check=True,
                    capture_output=True,
                ).stdout
                self.assertEqual(leaf_public, key_public)
                for cert in (root, leaf):
                    self.assertEqual(
                        subprocess.run(
                            ["openssl", "x509", "-checkend", "86400", "-noout", "-in", str(cert)],
                            check=False,
                            capture_output=True,
                        ).returncode,
                        0,
                    )
            finally:
                leaf.unlink(missing_ok=True)

    def test_api_default_ssl_context_trusts_only_the_two_leaf_hostnames(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
            target = Path(directory).resolve() / "fixture"
            self.module.create_fixture(target)
            facts = {
                "root": target / "root-ca.pem",
                "chain": target / "edge-tls-chain.pem",
                "key": target / "edge-tls-key.pem",
            }
            for hostname in ("identity.example.test", "pilot.example.test"):
                with self.subTest(hostname=hostname):
                    _memory_tls_handshake(hostname=hostname, **facts)
            with self.assertRaises(ssl.SSLCertVerificationError):
                _memory_tls_handshake(hostname="evil.example.test", **facts)

    def test_creation_is_atomic_non_overwriting_and_input_is_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
            target = Path(directory).resolve() / "fixture"
            target.mkdir()
            marker = target / "keep"
            marker.write_text("unchanged", encoding="ascii")
            with self.assertRaises(self.module.InternalSandboxTlsError):
                self.module.create_fixture(target)
            self.assertEqual(marker.read_text(encoding="ascii"), "unchanged")

            relative = Path("relative-fixture")
            with self.assertRaises(self.module.InternalSandboxTlsError):
                self.module.create_fixture(relative)
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.module.main(
                        [
                            "create",
                            "--output-dir",
                            str(Path(directory).resolve() / "x"),
                            "--hostname",
                            "evil.test",
                        ]
                    )

    def test_verify_rejects_extra_files_permission_drift_and_tampering(self) -> None:
        mutations = (
            lambda target: (target / "root-ca.key").write_text("forbidden", encoding="ascii"),
            lambda target: (target / "edge-tls-key.pem").chmod(0o440),
            lambda target: (
                (target / "edge-tls-chain.pem").chmod(0o644),
                (target / "edge-tls-chain.pem").write_bytes(b"not a certificate"),
            ),
            lambda target: (target / "root-ca.pem").unlink(),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
                    target = Path(directory).resolve() / "fixture"
                    self.module.create_fixture(target)
                    mutate(target)
                    with self.assertRaises(self.module.InternalSandboxTlsError):
                        self.module.verify_fixture(target)

    def test_cli_failure_is_non_reflective_and_does_not_print_private_material(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="desire-tls-test-") as directory:
            target = Path(directory).resolve() / "missing"
            result = self.module.main(
                ["verify", "--input-dir", str(target)],
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "ERROR: INTERNAL_SANDBOX_TLS_INVALID\n",
        )
        self.assertNotIn("PRIVATE", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
