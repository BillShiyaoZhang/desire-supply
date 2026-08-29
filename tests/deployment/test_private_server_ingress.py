"""Offline contracts for the opt-in private-server ingress boundary."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "preflight_private_server_ingress.py"
OVERLAY = ROOT / "deploy" / "private-server.compose.yaml"
RUNBOOK = ROOT / "docs" / "operations" / "private-server-internal-sandbox.md"

READY = '{"status":"PRIVATE_SERVER_INGRESS_PREFLIGHT_READY"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_INGRESS_PREFLIGHT_INVALID",'
    '"status":"BLOCKED"}\n'
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "preflight_private_server_ingress", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("private-server preflight cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrivateServerIngressContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _interface(
        self,
        address: str = "10.23.4.15",
        *,
        is_up: bool = True,
        is_loopback: bool = False,
    ):
        return self.module.InterfaceAddress(
            name="eth0",
            address=address,
            is_up=is_up,
            is_loopback=is_loopback,
        )

    def _listener(
        self,
        address: str,
        *,
        port: int = 443,
        state: str = "LISTEN",
    ):
        return self.module.Listener(
            local_address=address,
            port=port,
            state=state,
        )

    def test_pure_validator_accepts_exact_assigned_rfc1918_address(self) -> None:
        self.assertIsNone(
            self.module.validate_private_server_ingress(
                "10.23.4.15",
                interfaces=(self._interface(),),
                listeners=(
                    self._listener("10.23.4.16"),
                    self._listener("0.0.0.0", port=8443),
                ),
            )
        )

    def test_pure_validator_rejects_non_exact_private_or_unassigned_bind(self) -> None:
        hostile = (
            "8.8.8.8",
            "100.64.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.2",
            "224.0.0.1",
            "fd00::15",
            "::",
            "10.23.4.15/24",
            " 10.23.4.15",
            "not-an-ip",
        )
        for bind_ip in hostile:
            with self.subTest(bind_ip=bind_ip):
                with self.assertRaises(
                    self.module.PrivateServerIngressPreflightError
                ):
                    self.module.validate_private_server_ingress(
                        bind_ip,
                        interfaces=(self._interface(),),
                        listeners=(),
                    )

        rejected_interfaces = (
            (),
            (self._interface("10.23.4.16"),),
            (self._interface(is_up=False),),
            (self._interface(is_loopback=True),),
        )
        for interfaces in rejected_interfaces:
            with self.subTest(interfaces=interfaces):
                with self.assertRaises(
                    self.module.PrivateServerIngressPreflightError
                ):
                    self.module.validate_private_server_ingress(
                        "10.23.4.15",
                        interfaces=interfaces,
                        listeners=(),
                    )

    def test_pure_validator_rejects_target_and_both_wildcard_listeners(self) -> None:
        conflicting = (
            "10.23.4.15",
            "0.0.0.0",
            "::",
            "*",
            "127.0.0.1",
            "::ffff:10.23.4.15",
            "::ffff:a17:40f",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::ffff:0:0",
        )
        for address in conflicting:
            with self.subTest(address=address):
                with self.assertRaises(
                    self.module.PrivateServerIngressPreflightError
                ):
                    self.module.validate_private_server_ingress(
                        "10.23.4.15",
                        interfaces=(self._interface(),),
                        listeners=(self._listener(address),),
                    )

        self.assertIsNone(
            self.module.validate_private_server_ingress(
                "10.23.4.15",
                interfaces=(self._interface(),),
                listeners=(
                    self._listener("10.23.4.15", state="CLOSE-WAIT"),
                    self._listener("0.0.0.0", port=8443),
                ),
            )
        )

    def test_linux_cli_collects_injected_host_facts_and_prints_only_ready(self) -> None:
        calls = []

        def run_command(command):
            calls.append(tuple(command))
            if tuple(command) == ("ip", "-json", "address", "show", "up"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        '[{"ifname":"lo","flags":["LOOPBACK","UP"],'
                        '"addr_info":[{"family":"inet","local":"127.0.0.1"}]},'
                        '{"ifname":"eth0","flags":["BROADCAST","UP","LOWER_UP"],'
                        '"addr_info":[{"family":"inet","local":"10.23.4.15"}]}]'
                    ),
                    stderr="",
                )
            if tuple(command) == ("ss", "-H", "-ltn"):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="LISTEN 0 4096 10.23.4.16:443 0.0.0.0:*\n",
                    stderr="",
                )
            self.fail("unexpected command")

        stdout = io.StringIO()
        stderr = io.StringIO()
        self.assertEqual(
            self.module.main(
                ["--bind-ip", "10.23.4.15"],
                stdout=stdout,
                stderr=stderr,
                platform_name="linux",
                command_runner=run_command,
            ),
            0,
        )
        self.assertEqual(stdout.getvalue(), READY)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            calls,
            [
                ("ip", "-json", "address", "show", "up"),
                ("ss", "-H", "-ltn"),
            ],
        )

    def test_cli_is_linux_only_and_all_failures_are_non_reflective(self) -> None:
        secret_input = "hostile-input-must-not-be-reflected"

        def forbidden_runner(command):
            self.fail("command runner must not be called")

        cases = (
            ("darwin", ["--bind-ip", "10.23.4.15"], forbidden_runner),
            ("linux", ["--bind-ip", secret_input], forbidden_runner),
            ("linux", ["--unknown", secret_input], forbidden_runner),
        )
        for platform_name, argv, runner in cases:
            with self.subTest(platform_name=platform_name, argv=argv):
                stdout = io.StringIO()
                stderr = io.StringIO()
                self.assertEqual(
                    self.module.main(
                        argv,
                        stdout=stdout,
                        stderr=stderr,
                        platform_name=platform_name,
                        command_runner=runner,
                    ),
                    78,
                )
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), BLOCKED)

    def test_linux_cli_requires_success_empty_stderr_and_closed_shapes(self) -> None:
        good_interfaces = (
            '[{"ifname":"eth0","flags":["UP"],'
            '"addr_info":[{"family":"inet","local":"10.23.4.15"}]}]'
        )
        cases = (
            (1, "", good_interfaces, 0, "", ""),
            (0, "warning", good_interfaces, 0, "", ""),
            (0, "", "{}", 0, "", ""),
            (0, "", good_interfaces, 1, "", ""),
            (0, "", good_interfaces, 0, "warning", ""),
            (0, "", good_interfaces, 0, "", "LISTEN 0 4096 only-four-fields\n"),
        )
        for (
            ip_exit,
            ip_stderr,
            ip_stdout,
            ss_exit,
            ss_stderr,
            ss_stdout,
        ) in cases:
            with self.subTest(
                ip_exit=ip_exit,
                ip_stderr=ip_stderr,
                ip_stdout=ip_stdout,
                ss_exit=ss_exit,
                ss_stderr=ss_stderr,
                ss_stdout=ss_stdout,
            ):
                def run_command(command):
                    if command[0] == "ip":
                        return subprocess.CompletedProcess(
                            command, ip_exit, stdout=ip_stdout, stderr=ip_stderr
                        )
                    return subprocess.CompletedProcess(
                        command, ss_exit, stdout=ss_stdout, stderr=ss_stderr
                    )

                stdout = io.StringIO()
                stderr = io.StringIO()
                self.assertEqual(
                    self.module.main(
                        ["--bind-ip", "10.23.4.15"],
                        stdout=stdout,
                        stderr=stderr,
                        platform_name="linux",
                        command_runner=run_command,
                    ),
                    78,
                )
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), BLOCKED)

    def test_linux_cli_rejects_malformed_facts_and_listener_conflicts(self) -> None:
        fixtures = (
            ("not-json", ""),
            (
                '[{"ifname":"eth0","flags":["UP"],'
                '"addr_info":[{"family":"inet","local":"10.23.4.15"}]}]',
                "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n",
            ),
            (
                '[{"ifname":"eth0","flags":["UP"],'
                '"addr_info":[{"family":"inet","local":"10.23.4.15"}]}]',
                "LISTEN malformed\n",
            ),
        )
        for interface_output, listener_output in fixtures:
            with self.subTest(
                interface_output=interface_output,
                listener_output=listener_output,
            ):
                def run_command(command):
                    if command[0] == "ip":
                        return subprocess.CompletedProcess(
                            command, 0, stdout=interface_output, stderr=""
                        )
                    return subprocess.CompletedProcess(
                        command, 0, stdout=listener_output, stderr=""
                    )

                stdout = io.StringIO()
                stderr = io.StringIO()
                self.assertEqual(
                    self.module.main(
                        ["--bind-ip", "10.23.4.15"],
                        stdout=stdout,
                        stderr=stderr,
                        platform_name="linux",
                        command_runner=run_command,
                    ),
                    78,
                )
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), BLOCKED)

    def test_overlay_is_exactly_one_named_fail_closed_edge_bind(self) -> None:
        self.assertEqual(
            OVERLAY.read_text(encoding="utf-8"),
            "services:\n"
            "  edge:\n"
            "    ports:\n"
            "      - name: private-rfc1918-https\n"
            "        target: 443\n"
            '        published: "443"\n'
            '        host_ip: "${DESIRE_PRIVATE_INGRESS_IP:?DESIRE_PRIVATE_INGRESS_IP is required}"\n'
            "        protocol: tcp\n",
        )
        base = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn('host_ip: "127.0.0.1"', base)
        self.assertNotIn("DESIRE_PRIVATE_INGRESS_IP", base)

    def test_runbook_keeps_the_overlay_inactive_and_closed(self) -> None:
        runbook = RUNBOOK.read_text(encoding="utf-8")
        required = (
            "INACTIVE",
            "INTERNAL_SANDBOX",
            "G1 NO-GO",
            "G2 NO-GO",
            "不得使用任何 v13 project、tag、input、CIDR 或 evidence 坐标",
            "两个 `example.test` hostname",
            "测试 root CA",
            "主机防火墙",
            "云安全组",
            "exact Platform、Web、Edge 与 PostgreSQL 镜像",
            "--no-build --pull never",
            "新的、从未使用过的非 v13 坐标",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, runbook)
        for frozen_coordinate in (
            "desire-supply-e2e-ten-account-v13",
            "e2e-ten-account-v13-iam37-demand10-trust7",
            "172.16.227.0/24",
            "v13drill01",
        ):
            with self.subTest(frozen_coordinate=frozen_coordinate):
                self.assertNotIn(frozen_coordinate, runbook)


if __name__ == "__main__":
    unittest.main()
