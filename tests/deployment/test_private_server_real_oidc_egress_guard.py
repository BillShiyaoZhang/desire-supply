"""Static and mutation contracts for the real-OIDC namespace egress guard."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def _module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


guard = _module(
    "test_private_server_real_oidc_egress_guard_runtime",
    "deploy/private-server-real-oidc-egress-guard.py",
)
contract = _module(
    "test_private_server_real_oidc_egress_guard_contract",
    "scripts/private_server_real_oidc_compose_contract.py",
)


DB_IPV4 = "172.29.25.10"
OIDC_IPV4 = "8.8.8.8"
PROJECTION_SHA256 = (
    "db403c2c6ae304f328b9da6efd9349d7b710434b0b5aaa48b676a0b7fec7402e"
)


class PrivateServerRealOidcEgressGuardTests(unittest.TestCase):
    def test_projection_is_byte_exact_and_matches_compose_contract(self) -> None:
        projection = guard.canonical_projection(DB_IPV4, OIDC_IPV4)
        self.assertEqual(hashlib.sha256(projection).hexdigest(), PROJECTION_SHA256)
        self.assertEqual(
            guard.projection_sha256(DB_IPV4, OIDC_IPV4), PROJECTION_SHA256
        )
        self.assertEqual(
            contract.oidc_egress_projection_bytes(DB_IPV4, OIDC_IPV4),
            projection,
        )
        self.assertEqual(
            contract.oidc_egress_projection_sha256(DB_IPV4, OIDC_IPV4),
            PROJECTION_SHA256,
        )
        self.assertTrue(projection.endswith(b"\n"))
        self.assertNotIn(b" ", projection)

    def test_rules_default_drop_and_allow_only_exact_reviewed_destinations(self) -> None:
        rules = guard.canonical_rules(DB_IPV4, OIDC_IPV4).decode("ascii")
        self.assertTrue(rules.startswith("flush ruleset\n"))
        self.assertIn("type filter hook output priority filter; policy drop;", rules)
        self.assertIn("udp dport 53 reject", rules)
        self.assertIn("tcp dport 53 reject with tcp reset", rules)
        self.assertIn('oifname "lo" accept', rules)
        self.assertIn("ct state established,related accept", rules)
        self.assertIn(f"ip daddr {DB_IPV4} tcp dport 5432 accept", rules)
        self.assertIn(f"ip daddr {OIDC_IPV4} tcp dport 443 accept", rules)
        self.assertIn("meta nfproto ipv6 reject", rules)
        self.assertIn("meta nfproto ipv4 reject", rules)
        self.assertEqual(rules.count(PROJECTION_SHA256), 10)
        self.assertLess(rules.index("udp dport 53"), rules.index('oifname "lo"'))
        self.assertNotIn("accept\n", rules)

    def test_health_rejects_any_rule_added_after_sealed_baseline(self) -> None:
        baseline = guard.canonical_rules(DB_IPV4, OIDC_IPV4).split(b"\n", 1)[1]
        guard._validate_live_ruleset(
            baseline,
            DB_IPV4,
            OIDC_IPV4,
            PROJECTION_SHA256,
            baseline=baseline,
        )
        injected = baseline.replace(
            b"        reject comment",
            b"        ip daddr 1.1.1.1 accept\n        reject comment",
            1,
        )
        with self.assertRaises(guard.RealOidcEgressGuardError):
            guard._validate_live_ruleset(
                injected,
                DB_IPV4,
                OIDC_IPV4,
                PROJECTION_SHA256,
                baseline=baseline,
            )
        extra_table = baseline + b"table inet injected { chain output { type filter hook output priority -1; policy accept; } }\n"
        with self.assertRaises(guard.RealOidcEgressGuardError):
            guard._validate_live_ruleset(
                extra_table,
                DB_IPV4,
                OIDC_IPV4,
                PROJECTION_SHA256,
            )

    def test_private_database_and_public_provider_coordinates_are_closed(self) -> None:
        invalid_database = (
            "127.0.0.1",
            "169.254.169.254",
            "8.8.8.8",
            "192.0.2.1",
            "::1",
            "172.29.25.010",
            "172.29.25.10 ",
        )
        invalid_provider = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "008.008.008.008",
            "8.8.8.8 ",
        )
        for value in invalid_database:
            with self.subTest(database=value):
                with self.assertRaises(guard.RealOidcEgressGuardError):
                    guard.canonical_projection(value, OIDC_IPV4)
        for value in invalid_provider:
            with self.subTest(provider=value):
                with self.assertRaises(guard.RealOidcEgressGuardError):
                    guard.canonical_projection(DB_IPV4, value)

    def test_nft_invocation_is_absolute_bounded_and_has_no_proxy_or_retry(self) -> None:
        completed = subprocess.CompletedProcess(
            ["/usr/sbin/nft", "--check", "--file", "-"], 0, b"", b""
        )
        rules = guard.canonical_rules(DB_IPV4, OIDC_IPV4)
        with mock.patch.object(guard.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                guard._nft(("--check", "--file", "-"), stdin=rules), b""
            )
        run.assert_called_once()
        positional, keywords = run.call_args
        self.assertEqual(
            positional[0], ["/usr/sbin/nft", "--check", "--file", "-"]
        )
        self.assertEqual(keywords["input"], rules)
        self.assertEqual(keywords["timeout"], 5)
        self.assertFalse(keywords["check"])
        self.assertNotIn("HTTP_PROXY", keywords["env"])
        self.assertNotIn("HTTPS_PROXY", keywords["env"])
        self.assertNotIn("NO_PROXY", keywords["env"])

        with mock.patch.object(
            guard.subprocess, "run", return_value=completed
        ) as list_run:
            self.assertEqual(guard._live_ruleset(), b"")
        self.assertEqual(
            list_run.call_args.args[0],
            [
                "/usr/sbin/nft",
                "--numeric",
                "--numeric-priority",
                "list",
                "ruleset",
            ],
        )

    def test_failure_is_non_reflective(self) -> None:
        marker = "attacker-provider-token-MUST-NOT-REFLECT"
        environment = {
            "DESIRE_REAL_OIDC_DB_DATA_IPV4": marker,
            "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": OIDC_IPV4,
            "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": PROJECTION_SHA256,
        }
        output = io.StringIO()
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            sys, "stderr", output
        ):
            self.assertEqual(guard.main(("check",)), 78)
        self.assertNotIn(marker, output.getvalue())
        self.assertEqual(
            output.getvalue(),
            '{"code":"REAL_OIDC_EGRESS_GUARD_INVALID","status":"BLOCKED"}\n',
        )

    def test_static_topology_keeps_net_admin_and_guard_code_isolated(self) -> None:
        overlay = (
            ROOT / "deploy/private-server-real-oidc.compose.yaml"
        ).read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        guard_section = overlay.split("  oidc-egress-guard:\n", 1)[1].split(
            "\n  api:\n", 1
        )[0]
        api_section = overlay.split("\n  api:\n", 1)[1].split(
            "\n  edge:\n", 1
        )[0]
        image_section = dockerfile.split(
            "FROM ${PYTHON_IMAGE} AS oidc-egress-guard-runtime", 1
        )[1].split("FROM ${NODE_IMAGE} AS web-builder", 1)[0]
        self.assertEqual(overlay.count("- NET_ADMIN"), 1)
        self.assertIn("read_only: true", guard_section)
        self.assertIn("user: \"0:0\"", guard_section)
        self.assertIn(
            "entrypoint:\n      - /usr/local/bin/desire-real-oidc-egress-guard",
            guard_section,
        )
        self.assertNotIn("secrets:", guard_section)
        self.assertNotIn("configs:", guard_section)
        self.assertNotIn("volumes:", guard_section)
        self.assertIn("network_mode: service:oidc-egress-guard", api_section)
        self.assertIn("networks: !reset []", api_section)
        self.assertIn("db=${DESIRE_REAL_OIDC_DB_DATA_IPV4:?", api_section)
        self.assertIn("apt-get install --yes --no-install-recommends nftables", image_section)
        self.assertIn("private-server-real-oidc-egress-guard.py", image_section)
        self.assertNotIn("platform/src", image_section)
        self.assertNotIn("secrets/", image_section)


if __name__ == "__main__":
    unittest.main()
