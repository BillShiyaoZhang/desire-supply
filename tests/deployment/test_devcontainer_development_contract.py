"""Side-effect-free REDs for the reproducible development container."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE_DEV = ROOT / "compose.dev.yaml"
DEVCONTAINER = ROOT / ".devcontainer" / "devcontainer.json"
DOCS = ROOT / "docs" / "development" / "dev-container.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"
VERIFIER = ROOT / "scripts" / "verify_container_stack.py"
ENTRYPOINT = ROOT / "deploy" / "devcontainer-entrypoint.sh"
RUNTIME_CLOSURE = ROOT / "deploy" / "devcontainer-runtime-closure.sh"
TOOLCHAIN_CHECK = ROOT / "deploy" / "devcontainer-toolchain-check.sh"

POSTGRES_DEV_IMAGE = (
    "postgres:18.4-bookworm@sha256:"
    "1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296"
)
PYTHON_IMAGE = (
    "python:3.14.1-slim-bookworm@sha256:"
    "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff"
)
NODE_IMAGE = (
    "node:22.22.3-bookworm-slim@sha256:"
    "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752"
)
UV_IMAGE = (
    "ghcr.io/astral-sh/uv:0.9.15@sha256:"
    "4c1ad814fe658851f50ff95ecd6948673fffddb0d7994bdb019dcb58227abd52"
)
DEVCONTAINER_IPAM_DEFAULTS = {
    "DESIRE_DEVCONTAINER_APP_SUBNET": "172.16.221.0/24",
    "DESIRE_DEVCONTAINER_DATA_SUBNET": "172.16.222.0/24",
    "DESIRE_DEVCONTAINER_EGRESS_SUBNET": "172.16.223.0/24",
}
POSTGRES_PARENT_TMPFS = (
    "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"
)
DEVCONTAINER_EXECUTABLE_TMPFS = "/tmp:rw,exec,nosuid,nodev,size=64m"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "devcontainer_contract_verifier",
        VERIFIER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DevContainerDevelopmentContractTest(unittest.TestCase):
    def _runtime_closure_script(self) -> str:
        return RUNTIME_CLOSURE.read_text(encoding="utf-8")

    def test_tmpfs_exec_exception_is_devcontainer_only_and_fail_closed(self) -> None:
        overlay = COMPOSE_DEV.read_text(encoding="utf-8")
        production = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertEqual(overlay.count(DEVCONTAINER_EXECUTABLE_TMPFS), 1)
        self.assertNotIn(
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            overlay,
        )
        self.assertNotIn(DEVCONTAINER_EXECUTABLE_TMPFS, production)
        self.assertIn(
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            production,
        )

        verifier = _load_verifier()
        safe_service = {
            "tmpfs": [DEVCONTAINER_EXECUTABLE_TMPFS, POSTGRES_PARENT_TMPFS]
        }
        self.assertEqual(
            verifier._devcontainer_tmpfs_failures(safe_service),
            (),
        )
        for unsafe_tmpfs in (
            "/tmp:rw,nosuid,nodev,size=64m",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
        ):
            with self.subTest(unsafe_tmpfs=unsafe_tmpfs):
                unsafe_service = {
                    "tmpfs": [unsafe_tmpfs, POSTGRES_PARENT_TMPFS]
                }
                self.assertIn(
                    "devcontainer-tmpfs-exec-contract-open",
                    verifier._devcontainer_tmpfs_failures(unsafe_service),
                )

    def test_overlay_has_explicit_private_distinct_ipam_without_gateway(self) -> None:
        compose = COMPOSE_DEV.read_text(encoding="utf-8")
        defaults = []
        for variable, subnet in DEVCONTAINER_IPAM_DEFAULTS.items():
            self.assertEqual(
                compose.count(f"subnet: ${{{variable}:-{subnet}}}"),
                1,
            )
            parsed = ipaddress.ip_network(subnet, strict=True)
            self.assertEqual(parsed.version, 4)
            self.assertEqual(parsed.prefixlen, 24)
            self.assertTrue(
                any(
                    parsed.subnet_of(ipaddress.ip_network(private))
                    for private in (
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                    )
                )
            )
            defaults.append(parsed)
        self.assertEqual(len(set(defaults)), 3)
        self.assertNotIn("gateway:", compose)

        verifier = _load_verifier()
        resolved = {
            "networks": {
                "app": {
                    "internal": True,
                    "ipam": {"config": [{"subnet": "172.16.221.0/24"}]},
                },
                "data": {
                    "internal": True,
                    "ipam": {"config": [{"subnet": "172.16.222.0/24"}]},
                },
                "dev-egress": {
                    "ipam": {"config": [{"subnet": "172.16.223.0/24"}]},
                },
            }
        }
        expected_overlay = "\n".join(
            f"subnet: ${{{variable}:-{subnet}}}"
            for variable, subnet in DEVCONTAINER_IPAM_DEFAULTS.items()
        )
        self.assertEqual(
            verifier._devcontainer_ipam_failures(expected_overlay, resolved),
            (),
        )
        missing_ipam = json.loads(json.dumps(resolved))
        del missing_ipam["networks"]["data"]["ipam"]
        self.assertIn(
            "devcontainer-ipam-subnet-invalid:data",
            verifier._devcontainer_ipam_failures(expected_overlay, missing_ipam),
        )
        overlapping = json.loads(json.dumps(resolved))
        overlapping["networks"]["dev-egress"]["ipam"]["config"][0][
            "subnet"
        ] = "172.16.221.0/24"
        self.assertIn(
            "devcontainer-ipam-subnets-overlap",
            verifier._devcontainer_ipam_failures(expected_overlay, overlapping),
        )
        public_subnet = json.loads(json.dumps(resolved))
        public_subnet["networks"]["dev-egress"]["ipam"]["config"][0][
            "subnet"
        ] = "203.0.113.0/24"
        self.assertIn(
            "devcontainer-ipam-subnet-invalid:dev-egress",
            verifier._devcontainer_ipam_failures(expected_overlay, public_subnet),
        )
        broad_subnet = json.loads(json.dumps(resolved))
        broad_subnet["networks"]["data"]["ipam"]["config"][0]["subnet"] = (
            "172.16.224.0/20"
        )
        self.assertIn(
            "devcontainer-ipam-subnet-invalid:data",
            verifier._devcontainer_ipam_failures(expected_overlay, broad_subnet),
        )
        internal_egress = json.loads(json.dumps(resolved))
        internal_egress["networks"]["dev-egress"]["internal"] = True
        self.assertIn(
            "devcontainer-ipam-network-boundary-open",
            verifier._devcontainer_ipam_failures(expected_overlay, internal_egress),
        )
        explicit_gateway = expected_overlay + "\ngateway: 172.16.221.1\n"
        self.assertIn(
            "devcontainer-ipam-contract-open",
            verifier._devcontainer_ipam_failures(explicit_gateway, resolved),
        )

    def test_host_route_preflight_distinguishes_desktop_vm_bridge_conflicts(self) -> None:
        verifier = _load_verifier()
        candidates = (
            "172.16.233.0/24",
            "172.16.234.0/24",
            "172.16.235.0/24",
        )

        blocked, caveats = verifier._devcontainer_host_route_preflight(
            candidates,
            docker_cidrs=(),
            lan_direct_cidrs=(),
            host_vpn_routes=(
                "0.0.0.0/0",
                "0.0.0.0/1",
                "128.0.0.0/1",
            ),
        )
        self.assertEqual(blocked, ())
        self.assertEqual(
            caveats,
            tuple(
                "devcontainer-host-vpn-broad-route-caveat:"
                f"{candidate}:{route}"
                for candidate in candidates
                for route in ("0.0.0.0/0", "128.0.0.0/1")
            ),
        )

        blocked, caveats = verifier._devcontainer_host_route_preflight(
            candidates,
            docker_cidrs=("172.16.0.0/12",),
            lan_direct_cidrs=("172.16.234.0/23",),
            host_vpn_routes=(
                "172.16.233.0/24",
                "172.16.235.128/25",
                "128.0.0.0/1",
            ),
        )
        self.assertEqual(
            blocked,
            (
                "devcontainer-docker-cidr-overlap:"
                "172.16.233.0/24:172.16.0.0/12",
                "devcontainer-docker-cidr-overlap:"
                "172.16.234.0/24:172.16.0.0/12",
                "devcontainer-docker-cidr-overlap:"
                "172.16.235.0/24:172.16.0.0/12",
                "devcontainer-lan-direct-overlap:"
                "172.16.234.0/24:172.16.234.0/23",
                "devcontainer-lan-direct-overlap:"
                "172.16.235.0/24:172.16.234.0/23",
                "devcontainer-host-vpn-route-overlap:"
                "172.16.233.0/24:172.16.233.0/24",
                "devcontainer-host-vpn-route-overlap:"
                "172.16.235.0/24:172.16.235.128/25",
            ),
        )
        self.assertEqual(
            caveats,
            tuple(
                "devcontainer-host-vpn-broad-route-caveat:"
                f"{candidate}:128.0.0.0/1"
                for candidate in candidates
            ),
        )

    def test_editor_fails_closed_on_host_compose_project_environment(self) -> None:
        devcontainer = json.loads(DEVCONTAINER.read_text(encoding="utf-8"))
        command = devcontainer["initializeCommand"]
        self.assertEqual(
            command,
            'if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then '
            "printf '%s\\n' 'BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME' >&2; "
            "exit 64; fi; exit 0",
        )
        clean_environment = os.environ.copy()
        clean_environment.pop("COMPOSE_PROJECT_NAME", None)
        clean = subprocess.run(
            ["/bin/sh", "-c", command],
            env=clean_environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual((clean.returncode, clean.stdout, clean.stderr), (0, "", ""))
        blocked_environment = {
            **clean_environment,
            "COMPOSE_PROJECT_NAME": "must-not-be-disclosed",
        }
        blocked = subprocess.run(
            ["/bin/sh", "-c", command],
            env=blocked_environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(blocked.returncode, 64)
        self.assertEqual(
            blocked.stderr,
            "BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME\n",
        )
        self.assertNotIn("must-not-be-disclosed", blocked.stdout + blocked.stderr)

    def test_exact_python_node_uv_and_postgres18_toolchain_is_image_pinned(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
        self.assertTrue(RUNTIME_CLOSURE.is_file())
        self.assertTrue(TOOLCHAIN_CHECK.is_file())
        self.assertNotIn("\ndeploy\n", f"\n{dockerignore}\n")
        self.assertEqual(
            dockerfile.count(
                "COPY --chmod=0555 deploy/devcontainer-runtime-closure.sh "
                "/tmp/desire-runtime-closure"
            ),
            2,
        )
        self.assertIn(f"ARG PYTHON_IMAGE={PYTHON_IMAGE}", dockerfile)
        self.assertIn(f"ARG NODE_IMAGE={NODE_IMAGE}", dockerfile)
        self.assertIn(f"ARG UV_IMAGE={UV_IMAGE}", dockerfile)
        self.assertIn(f"ARG POSTGRES_DEV_IMAGE={POSTGRES_DEV_IMAGE}", dockerfile)
        self.assertIn("FROM ${NODE_IMAGE} AS devcontainer-node", dockerfile)
        self.assertIn("FROM ${PYTHON_IMAGE} AS devcontainer-python", dockerfile)
        self.assertIn("FROM ${POSTGRES_DEV_IMAGE} AS devcontainer", dockerfile)
        for closure_call in (
            "RUN /tmp/desire-runtime-closure "
            "/node-runtime-packages.txt /usr/local /usr/local/bin/node",
            "&& /tmp/desire-runtime-closure "
            "/python-runtime-packages.txt /usr/local",
            "/usr/local/bin/python3.14",
        ):
            self.assertIn(closure_call, dockerfile)

        stage = dockerfile[dockerfile.index("FROM ${POSTGRES_DEV_IMAGE} AS devcontainer") :]
        self.assertIn(
            "COPY --from=devcontainer-node /usr/local/ /usr/local/",
            stage,
        )
        self.assertIn(
            "COPY --from=devcontainer-python /usr/local/ /usr/local/",
            stage,
        )
        self.assertIn("COPY --from=uv-binaries /uv /uvx /usr/local/bin/", stage)
        self.assertIn(
            "COPY --from=devcontainer-python /python-runtime-packages.txt "
            "/tmp/python-runtime-packages.txt",
            stage,
        )
        self.assertIn(
            "COPY --from=devcontainer-node /node-runtime-packages.txt "
            "/tmp/node-runtime-packages.txt",
            stage,
        )
        self.assertEqual(
            stage.count(
                "xargs -r apt-get install --yes --no-install-recommends"
            ),
            2,
        )
        self.assertIn(
            "xargs -r apt-get install --yes --no-install-recommends",
            stage,
        )
        self.assertNotIn("xargs -r dpkg-query --search", dockerfile)
        closure_script = self._runtime_closure_script()
        self.assertNotIn("pipefail", closure_script)
        for fail_closed_fragment in (
            'if [ "$#" -lt 3 ]',
            'for runtime_binary_candidate in "$@"',
            'test -e "$runtime_binary_candidate"',
            'od -An -v -tx1 -N4 -- "$runtime_binary_candidate"',
            '$1 == "7f" && $2 == "45" && $3 == "4c" && $4 == "46"',
            "not found",
            'readlink -f -- "$runtime_dependency"',
            "for runtime_package_candidate in",
            'dpkg-query --search "$runtime_package_candidate"',
            'test -s "$runtime_packages_file"',
        ):
            self.assertIn(fail_closed_fragment, closure_script)
        self.assertNotIn("postgresql-client", stage)
        self.assertNotIn("        python3\n", stage)
        self.assertNotIn("        python3-pip\n", stage)
        self.assertNotIn("        python3-venv\n", stage)
        self.assertIn(
            'RUN test "$(id -u)" = "1000" \\\n'
            "    && /usr/local/bin/desire-devcontainer-toolchain-check",
            stage,
        )
        self.assertIn("USER node", stage)

    def test_node_runtime_closure_fails_closed_under_injected_faults(self) -> None:
        with tempfile.TemporaryDirectory(prefix="devcontainer-closure-") as raw_tmp:
            tmp = Path(raw_tmp)
            runtime_root = tmp / "runtime"
            (runtime_root / "bin").mkdir(parents=True)
            (runtime_root / "lib").mkdir()
            node_elf = runtime_root / "bin" / "node"
            node_elf.write_bytes(b"\x7fELFfixture")
            node_elf.chmod(0o755)
            python_config = runtime_root / "bin" / "python3.14-config"
            python_config.write_text(
                "#!/bin/sh\nprintf '%s\\n' config-script\n",
                encoding="utf-8",
            )
            python_config.chmod(0o755)
            dependency_one = tmp / "libfixture-one.so"
            dependency_two = tmp / "libfixture-two.so"
            dependency_one.write_bytes(b"one")
            dependency_two.write_bytes(b"two")
            canonical_lib = tmp / "usr" / "lib"
            canonical_lib.mkdir(parents=True)
            merged_dependency_canonical = canonical_lib / "libfixture-merged.so"
            merged_dependency_canonical.write_bytes(b"merged")
            raw_lib = tmp / "lib"
            raw_lib.symlink_to(canonical_lib, target_is_directory=True)
            merged_dependency_raw = raw_lib / "libfixture-merged.so"

            mock_bin = tmp / "bin"
            mock_bin.mkdir()
            ldd = mock_bin / "ldd"
            ldd.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  *-config) printf '%s\\n' "
                "'ldd received a config script' >&2; exit 91 ;;\n"
                "esac\n"
                "if [ \"${FAKE_LDD_MODE:-ok}\" = not-found ]; then\n"
                "  printf '%s\\n' 'libmissing.so => not found'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"${FAKE_LDD_MODE:-ok}\" = error ]; then\n"
                "  printf '%s\\n' 'fixture ldd failure' >&2\n"
                "  exit 7\n"
                "fi\n"
                "if [ \"${FAKE_LDD_MODE:-ok}\" = merged-only ]; then\n"
                "  printf 'libfixture-merged.so => %s (0x3)\\n' \"$FAKE_DEP_MERGED\"\n"
                "  exit 0\n"
                "fi\n"
                "printf 'libfixture-one.so => %s (0x1)\\n' \"$FAKE_DEP_ONE\"\n"
                "printf 'libfixture-two.so => %s (0x2)\\n' \"$FAKE_DEP_TWO\"\n",
                encoding="utf-8",
            )
            ldd.chmod(0o755)
            dpkg_query = mock_bin / "dpkg-query"
            dpkg_query.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = --search\n"
                "if [ \"${FAKE_DPKG_FAIL_RAW_PATH:-}\" = \"$2\" ] || "
                "[ \"${FAKE_DPKG_FAIL_CANONICAL_PATH:-}\" = \"$2\" ]; then\n"
                "  exit 1\n"
                "fi\n"
                "if [ \"$2\" = \"$FAKE_MERGED_CANONICAL\" ] && "
                "[ \"${FAKE_MERGED_OWNER_MODE:-raw}\" != canonical ]; then\n"
                "  exit 1\n"
                "fi\n"
                "if [ \"$2\" = \"$FAKE_MERGED_RAW\" ] && "
                "[ \"${FAKE_MERGED_OWNER_MODE:-raw}\" != raw ]; then\n"
                "  exit 1\n"
                "fi\n"
                "if [ \"$2\" = \"$FAKE_MERGED_RAW\" ] || "
                "[ \"$2\" = \"$FAKE_MERGED_CANONICAL\" ]; then\n"
                "  printf '%s: %s\\n' 'libfixture-merged:amd64' \"$2\"\n"
                "  exit 0\n"
                "fi\n"
                "case \"$2\" in\n"
                "  *one.so) package=libfixture-one:amd64 ;;\n"
                "  *two.so) package=libfixture-two:amd64 ;;\n"
                "  *) exit 1 ;;\n"
                "esac\n"
                "if [ \"$package\" = libfixture-one:amd64 ]; then\n"
                "  printf '%s, %s: %s\\n' \"$package\" "
                "'libfixture-alias:amd64' \"$2\"\n"
                "else\n"
                "  printf '%s: %s\\n' \"$package\" \"$2\"\n"
                "fi\n",
                encoding="utf-8",
            )
            dpkg_query.chmod(0o755)
            readlink = mock_bin / "readlink"
            readlink.write_text(
                "#!/bin/sh\n"
                "exec \"$FAKE_PYTHON\" -c "
                "'import os,sys; print(os.path.realpath(sys.argv[-1]))' \"$@\"\n",
                encoding="utf-8",
            )
            readlink.chmod(0o755)

            base_environment = {
                **os.environ,
                "PATH": f"{mock_bin}:/usr/bin:/bin",
                "FAKE_DEP_ONE": str(dependency_one),
                "FAKE_DEP_TWO": str(dependency_two),
                "FAKE_DEP_MERGED": str(merged_dependency_raw),
                "FAKE_MERGED_RAW": str(merged_dependency_raw),
                "FAKE_MERGED_CANONICAL": str(
                    merged_dependency_canonical.resolve()
                ),
                "FAKE_PYTHON": sys.executable,
            }

            for label, overrides, expected_packages, binary_candidate in (
                (
                    "node-complete-multi-owner",
                    {},
                    (
                        "libfixture-alias:amd64",
                        "libfixture-one:amd64",
                        "libfixture-two:amd64",
                    ),
                    node_elf,
                ),
                (
                    "node-merged-usr-raw-owner-only",
                    {
                        "FAKE_LDD_MODE": "merged-only",
                        "FAKE_MERGED_OWNER_MODE": "raw",
                    },
                    ("libfixture-merged:amd64",),
                    node_elf,
                ),
                (
                    "node-merged-usr-canonical-owner-only",
                    {
                        "FAKE_LDD_MODE": "merged-only",
                        "FAKE_MERGED_OWNER_MODE": "canonical",
                    },
                    ("libfixture-merged:amd64",),
                    node_elf,
                ),
                (
                    "node-ldd-not-found",
                    {"FAKE_LDD_MODE": "not-found"},
                    None,
                    node_elf,
                ),
                (
                    "node-ldd-nonzero",
                    {"FAKE_LDD_MODE": "error"},
                    None,
                    node_elf,
                ),
                (
                    "node-partial-dpkg-mapping",
                    {
                        "FAKE_DPKG_FAIL_RAW_PATH": str(dependency_two),
                        "FAKE_DPKG_FAIL_CANONICAL_PATH": str(
                            dependency_two.resolve()
                        ),
                    },
                    None,
                    node_elf,
                ),
                (
                    "node-non-elf-candidate",
                    {},
                    None,
                    python_config,
                ),
                (
                    "node-missing-candidate",
                    {},
                    None,
                    runtime_root / "bin" / "missing-node",
                ),
            ):
                with self.subTest(label=label):
                    packages_file = tmp / f"{label}.packages"
                    if expected_packages is None:
                        packages_file.write_text("stale-package\\n", encoding="utf-8")
                    completed = subprocess.run(
                        [
                            "/bin/sh",
                            str(RUNTIME_CLOSURE),
                            str(packages_file),
                            str(runtime_root),
                            str(binary_candidate),
                        ],
                        text=True,
                        capture_output=True,
                        env={**base_environment, **overrides},
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0 if expected_packages is not None else 1,
                    )
                    if expected_packages is not None:
                        self.assertEqual(completed.stdout, "")
                        self.assertEqual(completed.stderr, "")
                        self.assertEqual(
                            packages_file.read_text(encoding="utf-8").splitlines(),
                            list(expected_packages),
                        )
                    else:
                        self.assertEqual(completed.stdout, "")
                        self.assertEqual(
                            completed.stderr,
                            "BLOCKED:DEVCONTAINER_RUNTIME_CLOSURE\n",
                        )
                        self.assertFalse(packages_file.exists())

    def test_toolchain_guard_emits_one_stable_label_per_failure(self) -> None:
        self.assertIn(
            "export LC_ALL=C",
            TOOLCHAIN_CHECK.read_text(encoding="utf-8"),
        )
        labels = {
            "PYTHON_VERSION": "BLOCKED:DEVCONTAINER_PYTHON_VERSION",
            "PYTHON_IMPORT": "BLOCKED:DEVCONTAINER_PYTHON_IMPORT",
            "NODE_VERSION": "BLOCKED:DEVCONTAINER_NODE_VERSION",
            "NPM_VERSION": "BLOCKED:DEVCONTAINER_NPM_VERSION",
            "NPM_HELP_NO_USAGE": "BLOCKED:DEVCONTAINER_NPM_HELP",
            "NPM_CACHE": "BLOCKED:DEVCONTAINER_NPM_CACHE",
            "PSQL_VERSION": "BLOCKED:DEVCONTAINER_PSQL_VERSION",
            "PG_DUMP_VERSION": "BLOCKED:DEVCONTAINER_PG_DUMP_VERSION",
            "PG_RESTORE_VERSION": "BLOCKED:DEVCONTAINER_PG_RESTORE_VERSION",
            "UV_VERSION": "BLOCKED:DEVCONTAINER_UV_VERSION",
            "UID": "BLOCKED:DEVCONTAINER_UID",
            "USERNAME": "BLOCKED:DEVCONTAINER_USERNAME",
            "SHELL": "BLOCKED:DEVCONTAINER_SHELL",
            "SUDO": "BLOCKED:DEVCONTAINER_SUDO",
        }
        self.assertEqual(len(labels), 14)
        with tempfile.TemporaryDirectory(prefix="devcontainer-toolchain-") as raw_tmp:
            fixture_root = Path(raw_tmp)
            mock_bin = fixture_root / "bin"
            mock_bin.mkdir()
            fake_home = fixture_root / "home" / "node"
            fake_workspace = fixture_root / "workspace"
            dependency_roots = (
                fake_home / ".cache" / "uv",
                fake_home / ".npm",
                fake_workspace / "platform" / ".venv",
                fake_workspace / "mvp" / ".venv",
                fake_workspace / "web" / "node_modules",
            )
            for dependency_root in dependency_roots:
                dependency_root.mkdir(parents=True)
            fixture_check = fixture_root / "devcontainer-toolchain-check.sh"
            fixture_check.write_text(
                TOOLCHAIN_CHECK.read_text(encoding="utf-8")
                .replace("/home/node", str(fake_home))
                .replace("/workspace", str(fake_workspace)),
                encoding="utf-8",
            )
            dispatcher = mock_bin / "toolchain-fixture"
            dispatcher.write_text(
                "#!/bin/sh\n"
                "tool=${0##*/}\n"
                "failure=${FAKE_TOOLCHAIN_FAILURE:-}\n"
                "case \"$tool\" in\n"
                "  python)\n"
                "    if [ \"${1:-}\" = --version ]; then\n"
                "      [ \"$failure\" != PYTHON_VERSION ] || "
                "{ printf raw-python; printf raw-python-error >&2; exit 9; }\n"
                "      printf '%s\\n' 'Python 3.14.1'\n"
                "    else\n"
                "      [ \"$failure\" != PYTHON_IMPORT ] || "
                "{ printf raw-import; printf raw-import-error >&2; exit 9; }\n"
                "    fi ;;\n"
                "  node)\n"
                "    [ \"$failure\" != NODE_VERSION ] || "
                "{ printf raw-node; printf raw-node-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'v22.22.3' ;;\n"
                "  npm)\n"
                "    if [ \"${1:-}\" = config ]; then\n"
                "      [ \"$failure\" != NPM_CACHE ] || "
                "{ printf raw-cache; printf raw-cache-error >&2; exit 9; }\n"
                "      printf '%s\\n' \"${FAKE_NPM_CACHE:-/home/node/.npm}\"\n"
                "    elif [ \"${1:-}\" = --version ]; then\n"
                "      [ \"$failure\" != NPM_VERSION ] || "
                "{ printf raw-npm-version; "
                "printf raw-npm-version-error >&2; exit 9; }\n"
                "    else\n"
                "      case \"$failure\" in\n"
                "        NPM_HELP_NO_USAGE) "
                "printf raw-npm-help; printf raw-npm-help-error >&2; exit 1 ;;\n"
                "        NPM_HELP_STATUS_2) "
                "printf 'npm <command>\\n'; printf raw-help-error >&2; exit 2 ;;\n"
                "        NPM_HELP_EMPTY) exit 1 ;;\n"
                "      esac\n"
                "      printf '%s\\n' 'npm <command>'\n"
                "      exit 1\n"
                "    fi ;;\n"
                "  psql)\n"
                "    [ \"$failure\" != PSQL_VERSION ] || "
                "{ printf raw-psql; printf raw-psql-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'psql (PostgreSQL) 18.4 (fixture)' ;;\n"
                "  pg_dump)\n"
                "    [ \"$failure\" != PG_DUMP_VERSION ] || "
                "{ printf raw-dump; printf raw-dump-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'pg_dump (PostgreSQL) 18.4 (fixture)' ;;\n"
                "  pg_restore)\n"
                "    [ \"$failure\" != PG_RESTORE_VERSION ] || "
                "{ printf raw-restore; printf raw-restore-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'pg_restore (PostgreSQL) 18.4 (fixture)' ;;\n"
                "  uv)\n"
                "    [ \"$failure\" != UV_VERSION ] || "
                "{ printf raw-uv; printf raw-uv-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'uv 0.9.15' ;;\n"
                "  id)\n"
                "    if [ \"${1:-}\" = -u ]; then\n"
                "      [ \"$failure\" != UID ] || "
                "{ printf raw-uid; printf raw-uid-error >&2; exit 9; }\n"
                "      printf '%s\\n' \"${FAKE_TOOLCHAIN_UID:-1000}\"\n"
                "    else\n"
                "      [ \"$failure\" != USERNAME ] || "
                "{ printf raw-user; printf raw-user-error >&2; exit 9; }\n"
                "      printf '%s\\n' node\n"
                "    fi ;;\n"
                "  getent)\n"
                "    [ \"$failure\" != SHELL ] || "
                "{ printf raw-shell; printf raw-shell-error >&2; exit 9; }\n"
                "    printf '%s\\n' 'node:x:1000:1000::/home/node:/bin/bash' ;;\n"
                "  sudo)\n"
                "    [ \"$failure\" != SUDO ] || "
                "{ printf raw-sudo; printf raw-sudo-error >&2; exit 9; } ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            dispatcher.chmod(0o755)
            for command in (
                "python",
                "node",
                "npm",
                "psql",
                "pg_dump",
                "pg_restore",
                "uv",
                "id",
                "getent",
                "sudo",
            ):
                (mock_bin / command).symlink_to(dispatcher)

            environment = {
                **os.environ,
                "PATH": f"{mock_bin}:/usr/bin:/bin",
                "HOME": str(fake_home),
                "FAKE_NPM_CACHE": str(fake_home / ".npm"),
            }
            ready = subprocess.run(
                ["/bin/sh", str(fixture_check)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(ready.returncode, 0)
            self.assertEqual(ready.stdout, "READY:DEVCONTAINER_TOOLCHAIN\n")
            self.assertEqual(ready.stderr, "")

            remapped = subprocess.run(
                ["/bin/sh", str(fixture_check)],
                text=True,
                capture_output=True,
                env={**environment, "FAKE_TOOLCHAIN_UID": "1001"},
                check=False,
            )
            self.assertEqual(remapped.returncode, 0)
            self.assertEqual(
                remapped.stdout,
                "READY:DEVCONTAINER_TOOLCHAIN\n",
            )
            self.assertEqual(remapped.stderr, "")

            root_user = subprocess.run(
                ["/bin/sh", str(fixture_check)],
                text=True,
                capture_output=True,
                env={**environment, "FAKE_TOOLCHAIN_UID": "0"},
                check=False,
            )
            self.assertEqual(root_user.returncode, 1)
            self.assertEqual(root_user.stdout, "")
            self.assertEqual(
                root_user.stderr,
                "BLOCKED:DEVCONTAINER_UID\n",
            )

            for failure, label in labels.items():
                with self.subTest(failure=failure):
                    blocked = subprocess.run(
                        ["/bin/sh", str(fixture_check)],
                        text=True,
                        capture_output=True,
                        env={
                            **environment,
                            "FAKE_TOOLCHAIN_FAILURE": failure,
                        },
                        check=False,
                    )
                    self.assertEqual(blocked.returncode, 1)
                    self.assertEqual(blocked.stdout, "")
                    self.assertEqual(blocked.stderr, f"{label}\n")

            for failure in ("NPM_HELP_STATUS_2", "NPM_HELP_EMPTY"):
                with self.subTest(failure=failure):
                    blocked = subprocess.run(
                        ["/bin/sh", str(fixture_check)],
                        text=True,
                        capture_output=True,
                        env={
                            **environment,
                            "FAKE_TOOLCHAIN_FAILURE": failure,
                        },
                        check=False,
                    )
                    self.assertEqual(blocked.returncode, 1)
                    self.assertEqual(blocked.stdout, "")
                    self.assertEqual(
                        blocked.stderr,
                        "BLOCKED:DEVCONTAINER_NPM_HELP\n",
                    )

            wrong_home = subprocess.run(
                ["/bin/sh", str(fixture_check)],
                text=True,
                capture_output=True,
                env={**environment, "HOME": str(fixture_root / "wrong-home")},
                check=False,
            )
            self.assertEqual(wrong_home.returncode, 1)
            self.assertEqual(wrong_home.stdout, "")
            self.assertEqual(
                wrong_home.stderr,
                "BLOCKED:DEVCONTAINER_HOME\n",
            )

            dependency_roots[3].rmdir()
            missing_dependency = subprocess.run(
                ["/bin/sh", str(fixture_check)],
                text=True,
                capture_output=True,
                env=environment,
                check=False,
            )
            self.assertEqual(missing_dependency.returncode, 1)
            self.assertEqual(missing_dependency.stdout, "")
            self.assertEqual(
                missing_dependency.stderr,
                "BLOCKED:DEVCONTAINER_DEPENDENCY_ROOT\n",
            )

    def test_verifier_rejects_legacy_closure_and_unscoped_cleanup(self) -> None:
        verifier = _load_verifier()
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        runtime_closure = RUNTIME_CLOSURE.read_text(encoding="utf-8")
        toolchain_check = TOOLCHAIN_CHECK.read_text(encoding="utf-8")
        ci = CI.read_text(encoding="utf-8")
        docs = DOCS.read_text(encoding="utf-8")
        self.assertEqual(
            verifier._devcontainer_runtime_closure_failures(
                dockerfile,
                runtime_closure,
            ),
            (),
        )
        self.assertEqual(
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                toolchain_check,
                ci,
            ),
            (),
        )
        self.assertEqual(verifier._devcontainer_docs_failures(docs), ())

        legacy_closure = runtime_closure.replace(
            'dpkg-query --search "$runtime_package_candidate"',
            "xargs -r dpkg-query --search",
            1,
        )
        self.assertIn(
            "devcontainer-runtime-closure-pipeline-open",
            verifier._devcontainer_runtime_closure_failures(
                dockerfile,
                legacy_closure,
            ),
        )
        non_elf_open_closure = runtime_closure.replace(
            'od -An -v -tx1 -N4 -- "$runtime_binary_candidate"',
            'printf "7f 45 4c 46\\n"',
            1,
        )
        self.assertIn(
            "devcontainer-runtime-closure-pipeline-open",
            verifier._devcontainer_runtime_closure_failures(
                dockerfile,
                non_elf_open_closure,
            ),
        )
        node_closure_open = dockerfile.replace(
            "/usr/local /usr/local/bin/node",
            "/usr/local /usr/local/bin/npm",
            1,
        )
        self.assertIn(
            "devcontainer-node-runtime-closure-open",
            verifier._devcontainer_runtime_closure_failures(
                node_closure_open,
                runtime_closure,
            ),
        )
        mislabeled_toolchain = toolchain_check.replace(
            "DEVCONTAINER_NODE_VERSION",
            "DEVCONTAINER_NODE_UNKNOWN",
        )
        self.assertIn(
            "devcontainer-toolchain-label-contract-open",
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                mislabeled_toolchain,
                ci,
            ),
        )
        zero_only_help = toolchain_check.replace("0|1) ;;", "0) ;;", 1)
        self.assertIn(
            "devcontainer-toolchain-label-contract-open",
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                zero_only_help,
                ci,
            ),
        )
        fixed_runtime_uid = toolchain_check.replace(
            'if ! test "$toolchain_value" -gt 0 2>/dev/null',
            'if ! test "$toolchain_value" = 1000',
            1,
        )
        self.assertIn(
            "devcontainer-toolchain-label-contract-open",
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                fixed_runtime_uid,
                ci,
            ),
        )
        appended_fixed_runtime_uid = (
            toolchain_check + '\ntest "$toolchain_value" = "1000"\n'
        )
        self.assertIn(
            "devcontainer-toolchain-label-contract-open",
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                appended_fixed_runtime_uid,
                ci,
            ),
        )
        duplicated_ci_guard = ci + "\nnpm --version >/dev/null\n"
        self.assertIn(
            "devcontainer-toolchain-label-contract-open",
            verifier._devcontainer_toolchain_failures(
                dockerfile,
                toolchain_check,
                duplicated_ci_guard,
            ),
        )
        self.assertIn(
            "devcontainer-docs-legacy-project-name",
            verifier._devcontainer_docs_failures(
                docs + "\ndesire-supply-e2e-six-role\n"
            ),
        )
        unscoped_docs = docs.replace(
            verifier.DEVCONTAINER_AUDIT_DOWN,
            "docker compose -f compose.yaml -f compose.dev.yaml down "
            "--volumes --remove-orphans",
            1,
        )
        self.assertIn(
            "devcontainer-docs-unscoped-destroy",
            verifier._devcontainer_docs_failures(unscoped_docs),
        )
        compose_environment_scoped_docs = docs.replace(
            "--project-name desire-supply-devcontainer",
            '--project-name "${COMPOSE_PROJECT_NAME}"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-daily-project-open",
            verifier._devcontainer_docs_failures(
                compose_environment_scoped_docs,
            ),
        )

    def test_workspace_and_all_language_dependency_caches_are_nonroot(self) -> None:
        compose = COMPOSE_DEV.read_text(encoding="utf-8")
        base_compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        devcontainer = json.loads(DEVCONTAINER.read_text(encoding="utf-8"))
        entrypoint = ENTRYPOINT.read_text(encoding="utf-8")

        for mount in (
            ".:/workspace:cached",
            "platform-venv:/workspace/platform/.venv",
            "mvp-venv:/workspace/mvp/.venv",
            "web-node-modules:/workspace/web/node_modules",
            "uv-cache:/home/node/.cache/uv",
            "npm-cache:/home/node/.npm",
        ):
            self.assertIn(mount, compose)
        self.assertIn("  mvp-venv:", compose)
        self.assertIn("/workspace/mvp/.venv", dockerfile)
        self.assertEqual(base_compose.count(POSTGRES_PARENT_TMPFS), 1)
        self.assertEqual(compose.count(POSTGRES_PARENT_TMPFS), 1)
        self.assertNotIn("\n  db:\n", compose)
        self.assertIn("postgres-data:/var/lib/postgresql/data", base_compose)
        self.assertIn("PGDATA: /var/lib/postgresql/data/pgdata", base_compose)
        self.assertIn("install -d -o node -g node", dockerfile)
        self.assertIn("groupadd --gid 1000 node", dockerfile)
        self.assertIn(
            "useradd --uid 1000 --gid node --create-home "
            "--home-dir /home/node --shell /bin/bash node",
            dockerfile,
        )
        self.assertIn("node ALL=(root) NOPASSWD:ALL", dockerfile)
        self.assertIn("chmod 0440 /etc/sudoers.d/node", dockerfile)
        self.assertIn("/workspace \\", dockerfile)
        self.assertIn("HOME=/home/node", dockerfile)
        self.assertIn("NPM_CONFIG_CACHE=/home/node/.npm", dockerfile)
        self.assertNotIn("ENV DEBIAN_FRONTEND=noninteractive", dockerfile)

        self.assertEqual(devcontainer["workspaceFolder"], "/workspace")
        self.assertEqual(devcontainer["containerUser"], "node")
        self.assertEqual(devcontainer["remoteUser"], "node")
        self.assertIs(devcontainer["updateRemoteUserUID"], True)
        self.assertEqual(
            devcontainer["postCreateCommand"],
            "cd /workspace/mvp && uv sync --locked && "
            "/usr/local/bin/desire-devcontainer-post-create",
        )
        self.assertEqual(set(devcontainer["runServices"]), {"db", "devcontainer"})
        self.assertNotIn("docker.sock", json.dumps(devcontainer))
        self.assertNotIn("no-new-privileges", compose)
        self.assertNotIn("cap_drop", compose)
        self.assertNotIn("privileged:", compose)
        self.assertNotIn("%sudo", dockerfile)
        self.assertIn(
            "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m",
            compose,
        )

        dependency_loop = entrypoint.split(
            "for dependency_root in \\\n", 1
        )[1].split("\ndo\n", 1)[0]
        dependency_roots = tuple(
            line.strip().removesuffix(" \\")
            for line in dependency_loop.splitlines()
        )
        self.assertEqual(
            dependency_roots,
            (
                "/home/node/.cache/uv",
                "/home/node/.npm",
                "/workspace/platform/.venv",
                "/workspace/mvp/.venv",
                "/workspace/web/node_modules",
            ),
        )
        self.assertIn('runtime_owner="$(id -u):$(id -g)"', entrypoint)
        self.assertIn(
            'sudo -n chown -- "$runtime_owner" "$dependency_root"',
            entrypoint,
        )
        self.assertNotIn("chown -R", entrypoint)
        self.assertNotIn("chown --recursive", entrypoint)
        self.assertNotIn("\n    /workspace \\\n", entrypoint)

    def test_ci_docs_and_verifier_lock_the_same_development_contract(self) -> None:
        docs = DOCS.read_text(encoding="utf-8")
        ci = CI.read_text(encoding="utf-8")
        verifier = VERIFIER.read_text(encoding="utf-8")

        for version in ("Python 3.14.1", "Node 22.22.3", "PostgreSQL 18.4"):
            self.assertIn(version, docs)
        for evidence in (
            "隔离 v1",
            "隔离 v2",
            "隔离 v3 已通过",
            "不能仅凭该 build 日志判断是 version 还是 help 子命令失败",
            "各自留下的运行资源均为 0",
            "隔离 v4 的唯一 build 已 GREEN",
            "唯一 up",
            "默认地址池耗尽",
            "0 containers、0 volumes、2 networks",
            "永久保全",
            "隔离 v5 的唯一 build 与唯一 up 均 GREEN",
            "组合 smoke",
            "非合同变量未设置",
            "post-create 与三面 locked tests 均未",
            "2 containers、3 networks 与",
            "6 volumes",
            "desire-supply-devcontainer-audit-20260819-v6",
            "隔离 v6 的唯一 build 与唯一 up 均 GREEN",
            "额外恰好 1 个 anonymous local volume",
            "db target `/var/lib/postgresql`",
            "post-create 与 MVP/Platform/Web tests 均为 0",
            "v6 topology RED",
            "desire-supply-devcontainer-audit-20260819-v7",
            "v7 source/static 20/20",
            "`compose config --quiet` 精确 exit 0",
            "top-level rendered JSON network keys",
            "`app`、`data`、`dev-egress`",
            'project-specific 名称只在各 network 的 `name` 字段',
            "exit 1，且发生在 build 之前",
            "project/network/volume/tag 全部 absent",
            "build=0、up=0",
            "候选未被证伪",
            "不得重跑 v7",
            "desire-supply-devcontainer-audit-20260819-v8",
            "v8 的只读宿主",
            "128.0.0.0/1",
            "v8 project/network/volume/tag 全部 absent",
            "desire-supply-devcontainer-audit-20260824-v9",
            "172.16.224.0/24",
            "172.16.225.0/24",
            "172.16.226.0/24",
            "172.16.233.0/24",
            "172.16.234.0/24",
            "172.16.235.0/24",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v7"',
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v8"',
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v9"',
            "全部 Docker CIDR",
            "宿主直连路由",
            "更具体路由",
            "全隧道 VPN",
            "Linux VM 内",
            "LAN/direct CIDR 重叠",
            "只记录 caveat",
            "创建后端到端网络验证",
            "pg_isready -h db -p 5432",
            "https://pypi.org/simple/",
            "https://registry.npmjs.org/",
            "不是跨宿主机通用保证",
            "BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME",
        ):
            self.assertIn(evidence, docs)
        for variable, subnet in DEVCONTAINER_IPAM_DEFAULTS.items():
            self.assertIn(variable, docs)
            self.assertIn(subnet, docs)
        for npm_label in (
            "BLOCKED:DEVCONTAINER_NPM_VERSION",
            "BLOCKED:DEVCONTAINER_NPM_HELP",
        ):
            self.assertIn(npm_label, docs)
        self.assertNotIn("psql 15", docs)
        self.assertNotIn("desire-supply-e2e-six-role", docs)
        for daily_command in (
            "docker compose --project-name desire-supply-devcontainer "
            "-f compose.yaml -f compose.dev.yaml up -d db devcontainer",
            "docker compose --project-name desire-supply-devcontainer "
            "-f compose.yaml -f compose.dev.yaml exec devcontainer sh",
            "docker compose --project-name desire-supply-devcontainer "
            "-f compose.yaml -f compose.dev.yaml stop devcontainer db",
        ):
            self.assertIn(daily_command, docs)
        self.assertIn("COMPOSE_PROJECT_NAME", docs)
        self.assertNotIn(
            "docker compose -f compose.yaml -f compose.dev.yaml down",
            docs,
        )
        self.assertEqual(docs.count(" down --volumes --remove-orphans"), 1)
        self.assertIn(
            'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
            "-f compose.yaml -f compose.dev.yaml ps -a",
            docs,
        )
        exact_audit_guard = (
            'test "${DESIRE_DEV_AUDIT_PROJECT:-}" = '
            '"desire-supply-devcontainer-audit-20260824-v16"'
        )
        self.assertEqual(docs.count(exact_audit_guard), 2)
        self.assertNotIn(
            'case "${DESIRE_DEV_AUDIT_PROJECT:-}" in',
            docs,
        )
        self.assertIn(
            'index .Config.Labels "com.docker.compose.project"',
            docs,
        )
        self.assertIn(
            'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
            "-f compose.yaml -f compose.dev.yaml down --volumes "
            "--remove-orphans",
            docs,
        )
        self.assertIn(
            "cd /workspace/mvp && uv run --offline --locked python -m unittest",
            docs,
        )
        self.assertIn('PYTHON_VERSION: "3.14.1"', ci)
        self.assertIn('NODE_VERSION: "22.22.3"', ci)
        self.assertIn('UV_VERSION: "0.9.15"', ci)
        self.assertIn("docker build --target devcontainer", ci)
        self.assertIn(
            "sudo apt-get install --yes --no-install-recommends zsh",
            ci,
        )
        self.assertIn("docker run --rm --network none", ci)
        self.assertIn(
            "--tmpfs /var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m",
            ci,
        )
        self.assertIn("--entrypoint /bin/bash", ci)
        self.assertIn(
            "/usr/local/bin/desire-devcontainer-toolchain-check",
            ci,
        )
        self.assertIn("READY:DEVCONTAINER_TOOLCHAIN", ci)
        self.assertIn(
            "/bin/sh -n deploy/devcontainer-runtime-closure.sh",
            ci,
        )
        self.assertIn(
            "/bin/sh -n deploy/devcontainer-toolchain-check.sh",
            ci,
        )
        for runtime_smoke in (
            'test "$HOME" = "/home/node"',
            'test "$NPM_CONFIG_CACHE" = "/home/node/.npm"',
            'test "$(stat -c %U:%G /workspace)" = "node:node"',
            "test ! -e /var/run/docker.sock",
        ):
            self.assertIn(runtime_smoke, ci)

        for failure_code in (
            "devcontainer-python-image-not-pinned",
            "devcontainer-node-image-not-pinned",
            "devcontainer-postgres-client-image-not-pinned",
            "devcontainer-toolchain-guard-missing",
            "devcontainer-mvp-venv-not-cached",
            "devcontainer-mvp-install-not-locked",
            "devcontainer-user-contract-open",
            "devcontainer-sudo-contract-open",
            "devcontainer-privileged",
            "devcontainer-cache-contract-open",
            "devcontainer-runtime-closure-open",
            "devcontainer-node-runtime-closure-open",
            "devcontainer-cache-ownership-repair-open",
            "devcontainer-postgres-volume-not-ephemeral",
            "devcontainer-tmpfs-contract-open",
            "devcontainer-tmpfs-exec-contract-open",
            "devcontainer-home-contract-open",
            "devcontainer-runtime-closure-pipeline-open",
            "devcontainer-toolchain-label-contract-open",
            "devcontainer-docs-legacy-project-name",
            "devcontainer-docs-daily-stop-open",
            "devcontainer-docs-daily-project-open",
            "devcontainer-docs-unscoped-destroy",
            "devcontainer-docs-ipam-preflight-open",
            "devcontainer-docs-v9-evidence-open",
            "devcontainer-docs-v10-prebuild-evidence-open",
            "devcontainer-docs-v11-red-evidence-open",
            "devcontainer-docs-v12-prebuild-evidence-open",
            "devcontainer-docs-v13-dynamic-evidence-open",
            "devcontainer-docs-v14-red-evidence-open",
            "devcontainer-docs-v15-red-evidence-open",
            "devcontainer-docs-v16-coordinate-open",
            "devcontainer-docs-v16-direct-execution-open",
            "devcontainer-docs-v16-host-metadata-open",
            "devcontainer-docs-v16-runtime-smoke-open",
            "devcontainer-ipam-contract-open",
            "devcontainer-ipam-subnet-invalid",
            "devcontainer-ipam-network-boundary-open",
            "devcontainer-ipam-subnets-overlap",
            "devcontainer-docker-cidr-overlap",
            "devcontainer-lan-direct-overlap",
            "devcontainer-host-vpn-route-overlap",
            "devcontainer-host-vpn-broad-route-caveat",
            "devcontainer-editor-project-environment-open",
            "postgres-parent-tmpfs-open",
            "postgres-parent-volume-open",
            "postgres-child-volume-open",
        ):
            self.assertIn(failure_code, verifier)

    def test_v9_through_v15_evidence_and_v16_commands_are_one_shot_safe(
        self,
    ) -> None:
        docs = DOCS.read_text(encoding="utf-8")
        verifier = _load_verifier()

        for evidence in (
            "隔离 v9 的唯一 build 与唯一 up 均 GREEN",
            "v9 topology GREEN",
            "containers=2",
            "networks=3",
            "app=172.16.233.0/24 internal=true endpoints=1",
            "data=172.16.234.0/24 internal=true endpoints=2",
            "dev-egress=172.16.235.0/24 internal=false endpoints=1",
            "named/project-labeled volumes=6",
            "actual volume mounts=6",
            "anonymous volumes=0",
            "host port bindings=0",
            "privileged=0",
            "db parent `/var/lib/postgresql` 是 tmpfs",
            "child `/var/lib/postgresql/data` 是 named volume",
            "`sh: 7: 7: parameter not set`",
            "post-create=0",
            "MVP/Platform/Web locked tests=0",
            "候选不是 RED",
            "保持 running",
            "不得重试、stop、down、rm 或 prune",
            "v9 占用导致 172.16.233.0/24、172.16.234.0/24、172.16.235.0/24 均被阻断",
            "desire-supply-devcontainer-audit-20260824-v10",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v10"',
            "隔离 v10 的动态 preflight 全部 GREEN",
            "V8 operator wrapper",
            '`" Dockerfile".trim():`',
            "`SyntaxError: Unexpected token '.'`",
            "`0.0s`",
            "`nested exec=0`",
            "`candidate rehash=0`",
            "`build=0`、`up=0`",
            "project/network/volume/tag 仍全部 absent",
            "候选未被证伪",
            "不得复用 v10",
            "desire-supply-devcontainer-audit-20260824-v11",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v11"',
            "隔离 v11 的唯一 build 与唯一 up 均 GREEN",
            "v11 topology GREEN",
            "runtime smoke GREEN",
            "post-create GREEN",
            "MVP locked tests 134/134 GREEN",
            "Platform locked tests 1072",
            "1 failure + 16 errors",
            "IAM_0024_TEST_PYTHON_UNAVAILABLE",
            "Web tests/typecheck/lint=0",
            "v11 动态 RED",
            "不得复用 v11",
            "desire-supply-devcontainer-audit-20260824-v12",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v12"',
            "host preflight 只完成 hashes/static/initialize/secret stat",
            "这些已执行项全部 GREEN",
            "CIDR/route enumeration=0",
            "generic symlink check",
            "macOS 上不存在",
            "`/usr/bin/test`",
            "exit 127",
            "读取任何文件内容之前",
            "错误前 Docker command=0",
            "随后只执行 read-only preservation audit",
            "`build=0`、`up=0`、`Docker mutation=0`",
            "v12 project/network/volume/tag 全部 absent",
            "v11 保持 untouched",
            "operator harness-invalid",
            "不得重试或复用 v12",
            "desire-supply-devcontainer-audit-20260824-v13",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v13"',
            "隔离 v13 的唯一 build 与唯一 up 均 GREEN",
            "v13 topology GREEN",
            "v13 containers=2",
            "v13 networks=3",
            "app=172.16.242.0/24 internal=true endpoints=1",
            "data=172.16.243.0/24 internal=true endpoints=2",
            "dev-egress=172.16.244.0/24 internal=false endpoints=1",
            "v13 named/project-labeled volumes=6",
            "v13 actual volume mounts=6",
            "v13 anonymous volumes=0",
            "v13 host port bindings=0",
            "v13 privileged=0",
            "runtime smoke #1-#4 exit 0",
            "PyPI smoke #5",
            "exit 28",
            "20s",
            "11,463,474/45,294,663 bytes",
            "GET `/simple/`",
            "完整 large index",
            "smoke #6 execution=0",
            "post-create/toolchain/MVP/Platform/Web execution=0",
            "v13 保持 running/locked",
            "v13 不得重试、stop、down、rm 或 prune",
            "desire-supply-devcontainer-audit-20260824-v14",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v14"',
            "隔离 v14 的 fresh preflight、唯一 build、唯一 up",
            "v14 topology GREEN",
            "六项 runtime smoke",
            "唯一 post-create、工具链与 MVP locked tests",
            "134/134 均 GREEN",
            "Ran 1091 tests in 157.827s",
            "14 errors、0 failures",
            "7 个 setup",
            "MigrationConnectionLost",
            "3 个同类 setup error",
            "4 个 `taxonomy_migration_runner` password authentication error",
            "Web tests/typecheck/lint=0",
            "fixed roles 跨 test database",
            "VALID UNTIL '9999-01-01 00:00:00+00'",
            "所有时区偏移下仍可被 psycopg",
            "21/21 外部 harness 回归",
            "PostgreSQL 18/18",
            "online credentials 3/3",
            "session-drain contract 2/2",
            "v14 已按一次性规则锁定",
            "172.16.245.0/24",
            "172.16.246.0/24",
            "172.16.247.0/24",
            "保持 running",
            "down、rm、prune 或补跑 Web",
            "desire-supply-devcontainer-audit-20260824-v15",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v15"',
            "v15 topology GREEN",
            "2 containers、3 networks",
            "app=172.16.248.0/24 internal=true endpoints=1",
            "data=172.16.249.0/24 internal=true endpoints=2",
            "dev-egress=172.16.250.0/24 internal=false endpoints=1",
            "6 个 named/project-labeled volumes",
            "6 个 actual volume mounts",
            "0 anonymous volumes",
            "0 host port bindings",
            "0 privileged",
            "Ran 134 tests in 2.075s",
            "Ran 1096 tests in 176.405s",
            "Web `70/70`",
            "typecheck 与 lint 全部 GREEN",
            "for DESIRE_DEV_AUDIT_ID in $DESIRE_DEV_AUDIT_IDS",
            "zsh",
            "no such object",
            "down execution=0",
            "v15 cleanup RED",
            "v15 cleanup RED",
            "desire-supply-devcontainer-audit-20260824-v16",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"',
            "禁止任何自制 JavaScript、V8 或组合 wrapper",
            "逐条直接执行审定命令",
            "逐项记录退出码",
            "唯一 post-create 若非零，也必须立即锁定 v16",
            "禁止执行工具链和后续测试",
            "build 或 up 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。",
            "六项 runtime smoke 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。",
        ):
            self.assertIn(evidence, docs)

        fresh = docs.split("## Fresh project 动态验收", 1)[1]
        shell_check = (
            'test "$(getent passwd node | cut -d: -f7)" = "/bin/bash"'
        )
        self.assertEqual(fresh.count(shell_check), 1)
        self.assertIn(
            'export DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v16"',
            fresh,
        )
        self.assertIn(
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"',
            fresh,
        )
        self.assertNotIn(
            'export DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v14"',
            fresh,
        )
        self.assertNotIn(
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v14"',
            fresh,
        )
        self.assertNotIn(
            'export DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v15"',
            fresh,
        )
        self.assertNotIn(
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v15"',
            fresh,
        )
        exact_project_guard = (
            'test "${DESIRE_DEV_AUDIT_PROJECT:-}" = '
            '"desire-supply-devcontainer-audit-20260824-v16"'
        )
        exact_image_guard = (
            'test "${DESIRE_IMAGE_TAG:-}" = '
            '"devcontainer-audit-20260824-v16"'
        )
        self.assertEqual(fresh.count(exact_project_guard), 2)
        self.assertEqual(fresh.count(exact_image_guard), 1)
        self.assertNotIn("awk", fresh)
        self.assertNotIn("$7", fresh)
        self.assertNotIn("$SHELL", fresh)
        for variable, subnet in (
            ("DESIRE_DEVCONTAINER_APP_SUBNET", "172.16.251.0/24"),
            ("DESIRE_DEVCONTAINER_DATA_SUBNET", "172.16.252.0/24"),
            ("DESIRE_DEVCONTAINER_EGRESS_SUBNET", "172.16.253.0/24"),
        ):
            self.assertIn(f'export {variable}="{subnet}"', fresh)
        for stale_subnet in (
            "172.16.233.0/24",
            "172.16.234.0/24",
            "172.16.235.0/24",
            "172.16.236.0/24",
            "172.16.237.0/24",
            "172.16.238.0/24",
            "172.16.239.0/24",
            "172.16.240.0/24",
            "172.16.241.0/24",
            "172.16.242.0/24",
            "172.16.243.0/24",
            "172.16.244.0/24",
            "172.16.245.0/24",
            "172.16.246.0/24",
            "172.16.247.0/24",
            "172.16.248.0/24",
            "172.16.249.0/24",
            "172.16.250.0/24",
        ):
            self.assertNotIn(f'="{stale_subnet}"', fresh)
        portable_metadata_check = (
            "test ! -L secrets/db_superuser_password.txt"
        )
        regular_metadata_check = "test -f secrets/db_superuser_password.txt"
        self.assertEqual(fresh.count(portable_metadata_check), 1)
        self.assertEqual(fresh.count(regular_metadata_check), 1)
        self.assertNotIn("/usr/bin/test", fresh)
        self.assertIn(
            "install -m 0700 /bin/true "
            "/tmp/desire-devcontainer-tmp-exec-check",
            fresh,
        )
        self.assertIn(
            '"/tmp/desire-devcontainer-tmp-exec-check"',
            fresh,
        )
        self.assertEqual(
            fresh.count(
                "curl --head --fail --silent --show-error --location"
            ),
            2,
        )
        fresh_commands = verifier._bash_commands(fresh)
        self.assertEqual(
            sum(
                "--proto '=https' --proto-redir '=https'" in command
                for command in fresh_commands
            ),
            2,
        )
        self.assertIn("https://pypi.org/simple/", fresh)
        self.assertIn("https://registry.npmjs.org/", fresh)
        exact_container_count_guard = (
            'test "$(docker compose --project-name '
            '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml '
            "-f compose.dev.yaml ps --all --quiet | wc -l | "
            "tr -d '[:space:]')\" = \"2\""
        )
        self.assertEqual(fresh_commands.count(exact_container_count_guard), 1)
        self.assertEqual(len(fresh_commands), 37)
        for legacy_cleanup_shape in (
            "DESIRE_DEV_AUDIT_IDS",
            "for DESIRE_DEV_AUDIT_ID",
            "ps -aq",
            "xargs",
            "IFS=",
        ):
            self.assertNotIn(legacy_cleanup_shape, fresh)
        self.assertEqual(verifier._devcontainer_docs_failures(docs), ())

        weakened_v14_lock = docs.replace(
            "down、rm、prune 或补跑 Web",
            "或补跑 Web",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v14-red-evidence-open",
            verifier._devcontainer_docs_failures(weakened_v14_lock),
        )
        weakened_v14_running = docs.replace(
            "`172.16.247.0/24` 保持 running",
            "`172.16.247.0/24` 已被占用",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v14-red-evidence-open",
            verifier._devcontainer_docs_failures(weakened_v14_running),
        )
        weakened_v15_cleanup = docs.replace(
            "v15 cleanup RED",
            "v15 cleanup completed",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v15-red-evidence-open",
            verifier._devcontainer_docs_failures(weakened_v15_cleanup),
        )

        cleanup_mutations = (
            docs.replace(
                exact_container_count_guard,
                exact_container_count_guard.replace('= "2"', '= "1"'),
                1,
            ),
            docs.replace("ps -q db)\"", "ps -aq)\"", 1),
            docs.replace('test -n "$DESIRE_DEV_AUDIT_DB_ID"', "true", 1),
            docs.replace(
                'test "$DESIRE_DEV_AUDIT_DB_ID" != '
                '"$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"',
                "true",
                1,
            ),
            docs.replace(
                '"$DESIRE_DEV_AUDIT_DB_ID")" = '
                '"$DESIRE_DEV_AUDIT_PROJECT"',
                '"$DESIRE_DEV_AUDIT_DEVCONTAINER_ID")" = '
                '"$DESIRE_DEV_AUDIT_PROJECT"',
                1,
            ),
        )
        for cleanup_mutation in cleanup_mutations:
            with self.subTest(cleanup_mutation=cleanup_mutation[-160:]):
                self.assertIn(
                    "devcontainer-docs-v16-direct-execution-open",
                    verifier._devcontainer_docs_failures(cleanup_mutation),
                )

        legacy_multiline_loop = docs.replace(
            exact_container_count_guard,
            exact_container_count_guard
            + '\nDESIRE_DEV_AUDIT_IDS="$(docker compose --project-name '
            '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml '
            '-f compose.dev.yaml ps -aq)"\n'
            'for DESIRE_DEV_AUDIT_ID in $DESIRE_DEV_AUDIT_IDS; do\n'
            "  true\n"
            "done",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(legacy_multiline_loop),
        )

        nested_awk = docs.replace(
            shell_check,
            'test "$(getent passwd node | awk -F: \'{print $7}\')" '
            '= "/bin/bash"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-runtime-smoke-open",
            verifier._devcontainer_docs_failures(nested_awk),
        )
        environment_shell = docs.replace(
            shell_check,
            'test "$SHELL" = "/bin/bash"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-runtime-smoke-open",
            verifier._devcontainer_docs_failures(environment_shell),
        )
        stale_project = docs.replace(
            'export DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v16"',
            'export DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v15"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-coordinate-open",
            verifier._devcontainer_docs_failures(stale_project),
        )
        cleanup_prefix, cleanup_separator, cleanup_suffix = docs.rpartition(
            exact_project_guard
        )
        self.assertEqual(cleanup_separator, exact_project_guard)
        cleanup_drift = (
            cleanup_prefix
            + 'test "${DESIRE_DEV_AUDIT_PROJECT:-}" = '
            '"desire-supply-devcontainer-audit-20260824-v14"'
            + cleanup_suffix
        )
        cleanup_failures = verifier._devcontainer_docs_failures(cleanup_drift)
        self.assertIn("devcontainer-docs-unscoped-destroy", cleanup_failures)
        self.assertIn("devcontainer-docs-v16-coordinate-open", cleanup_failures)
        compensated_cleanup_drift = cleanup_drift.replace(
            exact_image_guard,
            exact_image_guard + "\n" + exact_project_guard,
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(compensated_cleanup_drift),
        )
        stale_image_tag = docs.replace(
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"',
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"\n'
            'export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v15"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-coordinate-open",
            verifier._devcontainer_docs_failures(stale_image_tag),
        )
        appended_project = (
            docs
            + '\n```bash\nexport DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v13"\n```\n'
        )
        self.assertIn(
            "devcontainer-docs-v16-coordinate-open",
            verifier._devcontainer_docs_failures(appended_project),
        )
        appended_image_tag = (
            docs
            + '\n```bash\nexport DESIRE_IMAGE_TAG='
            '"devcontainer-audit-20260824-v13"\n```\n'
        )
        self.assertIn(
            "devcontainer-docs-v16-coordinate-open",
            verifier._devcontainer_docs_failures(appended_image_tag),
        )
        for injected_state_change in (
            "unset DESIRE_IMAGE_TAG",
            'readonly DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v13"',
            'export    DESIRE_DEV_AUDIT_PROJECT="desire-supply-'
            'devcontainer-audit-20260824-v13"',
            ':; export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v13"',
        ):
            with self.subTest(injected_state_change=injected_state_change):
                mutated = docs.replace(
                    exact_image_guard,
                    exact_image_guard + "\n" + injected_state_change,
                    1,
                )
                self.assertIn(
                    "devcontainer-docs-v16-direct-execution-open",
                    verifier._devcontainer_docs_failures(mutated),
                )
        stale_cidr = docs.replace(
            'export DESIRE_DEVCONTAINER_APP_SUBNET="172.16.251.0/24"',
            'export DESIRE_DEVCONTAINER_APP_SUBNET="172.16.248.0/24"',
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-coordinate-open",
            verifier._devcontainer_docs_failures(stale_cidr),
        )
        wrapped_execution = docs.replace(
            "逐条直接执行审定命令",
            "交给 functions.exec 组合 wrapper 执行审定命令",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(wrapped_execution),
        )

        build_tail = "-f compose.yaml -f compose.dev.yaml build devcontainer"
        up_tail = (
            "-f compose.yaml -f compose.dev.yaml \\\n"
            "  up -d --wait --wait-timeout 120 db devcontainer"
        )
        reordered_execution = docs.replace(
            build_tail,
            "__DESIRE_V16_UP_TAIL__",
            1,
        ).replace(
            up_tail,
            build_tail,
            1,
        ).replace(
            "__DESIRE_V16_UP_TAIL__",
            up_tail,
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(reordered_execution),
        )
        combined_wrapper = (
            docs
            + "\n```bash\nsh -lc 'docker compose --project-name "
            '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml '
            "build devcontainer && docker compose --project-name "
            '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml '
            "up -d db devcontainer'\n```\n"
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(combined_wrapper),
        )
        weakened_build_stop = docs.replace(
            "build 或 up 任一非零都必须立即锁定 v16，"
            "禁止重试、补跑、清理或继续。",
            "build 或 up 非零时允许修正后重试。",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(weakened_build_stop),
        )
        weakened_smoke_stop = docs.replace(
            "六项 runtime smoke 任一非零都必须立即锁定 v16，"
            "禁止重试、补跑、清理或继续。",
            "runtime smoke 非零时仍继续 post-create。",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(weakened_smoke_stop),
        )

        missing_exec_smoke = docs.replace(
            "install -m 0700 /bin/true "
            "/tmp/desire-devcontainer-tmp-exec-check",
            "test -d /tmp",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-runtime-smoke-open",
            verifier._devcontainer_docs_failures(missing_exec_smoke),
        )

        nonportable_metadata = docs.replace(
            portable_metadata_check,
            "/usr/bin/test ! -L secrets/db_superuser_password.txt",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-host-metadata-open",
            verifier._devcontainer_docs_failures(nonportable_metadata),
        )
        missing_regular_metadata = docs.replace(
            regular_metadata_check,
            "test -e secrets/db_superuser_password.txt",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-host-metadata-open",
            verifier._devcontainer_docs_failures(missing_regular_metadata),
        )

        missing_post_create = docs.replace(
            "'cd /workspace/mvp && uv sync --locked && "
            "/usr/local/bin/desire-devcontainer-post-create'",
            "'true'",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(missing_post_create),
        )
        missing_post_create_stop = docs.replace(
            "唯一 post-create 若非零，也必须立即锁定 v16",
            "唯一 post-create 完成后继续",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-direct-execution-open",
            verifier._devcontainer_docs_failures(missing_post_create_stop),
        )

        body_downloading_probe = docs.replace(
            "curl --head --fail --silent --show-error --location",
            "curl --fail --silent --show-error --location",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-runtime-smoke-open",
            verifier._devcontainer_docs_failures(body_downloading_probe),
        )

        downgradeable_probe = docs.replace(
            "--proto '=https' --proto-redir '=https'",
            "--proto-redir all",
            1,
        )
        self.assertIn(
            "devcontainer-docs-v16-runtime-smoke-open",
            verifier._devcontainer_docs_failures(downgradeable_probe),
        )

    def test_v16_cleanup_executes_identically_in_sh_and_zsh(self) -> None:
        verifier = _load_verifier()
        docs = DOCS.read_text(encoding="utf-8")
        fresh = docs.split("## Fresh project 动态验收", 1)[1]
        commands = verifier._bash_commands(fresh)
        cleanup_start = max(
            index
            for index, command in enumerate(commands)
            if command == verifier.DEVCONTAINER_V16_PROJECT_GUARD
        )
        cleanup_end = commands.index(
            verifier.DEVCONTAINER_AUDIT_DOWN,
            cleanup_start,
        ) + 2
        cleanup_script = "\n".join(commands[cleanup_start:cleanup_end])

        shells = (Path("/bin/sh"), Path("/bin/zsh"))
        for shell in shells:
            self.assertTrue(
                shell.is_file(),
                f"required cleanup contract shell is missing: {shell}",
            )

        fake_docker = """#!/bin/sh
set -eu
scenario="${DESIRE_CLEANUP_SCENARIO:?}"
project="${DESIRE_DEV_AUDIT_PROJECT:?}"
sentinel="${DESIRE_CLEANUP_DOWN_SENTINEL:?}"
if [ "${1:-}" = "compose" ]; then
  command_line=" $* "
  case "$command_line" in
    *" ps --all --quiet "*)
      if [ "$scenario" = "bad_count" ]; then
        printf '%s\\n' db-id
      else
        printf '%s\\n' db-id devcontainer-id
      fi
      exit 0
      ;;
    *" ps -q db "*)
      case "$scenario" in
        empty_db) exit 0 ;;
        multi_db) printf '%s\\n' db-id extra-db-id ;;
        *) printf '%s\\n' db-id ;;
      esac
      exit 0
      ;;
    *" ps -q devcontainer "*)
      printf '%s\\n' devcontainer-id
      exit 0
      ;;
    *" ps -a "*)
      exit 0
      ;;
    *" down --volumes --remove-orphans "*)
      printf '%s\\n' down >> "$sentinel"
      exit 0
      ;;
  esac
fi
if [ "${1:-}" = "inspect" ]; then
  inspected=""
  for argument in "$@"; do
    inspected="$argument"
  done
  case "$inspected" in
    db-id) printf '%s\\n' "$project" ;;
    devcontainer-id)
      if [ "$scenario" = "bad_label" ]; then
        printf '%s\\n' wrong-project
      else
        printf '%s\\n' "$project"
      fi
      ;;
    *) exit 44 ;;
  esac
  exit 0
fi
exit 97
"""

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            docker_path = fake_bin / "docker"
            docker_path.write_text(fake_docker, encoding="utf-8")
            docker_path.chmod(0o700)

            for shell in shells:
                for scenario, expected_success in (
                    ("happy", True),
                    ("bad_count", False),
                    ("empty_db", False),
                    ("bad_label", False),
                    ("multi_db", False),
                ):
                    with self.subTest(shell=str(shell), scenario=scenario):
                        sentinel = temporary / (
                            f"{shell.name}-{scenario}-down.log"
                        )
                        environment = dict(os.environ)
                        environment.update(
                            {
                                "PATH": f"{fake_bin}:{environment['PATH']}",
                                "DESIRE_CLEANUP_SCENARIO": scenario,
                                "DESIRE_CLEANUP_DOWN_SENTINEL": str(sentinel),
                                "DESIRE_DEV_AUDIT_PROJECT": (
                                    verifier.DEVCONTAINER_V16_PROJECT
                                ),
                            }
                        )
                        result = subprocess.run(
                            [str(shell), "-f"],
                            input=f"set -eu\n{cleanup_script}\n",
                            text=True,
                            capture_output=True,
                            check=False,
                            env=environment,
                        )
                        down_lines = (
                            sentinel.read_text(encoding="utf-8").splitlines()
                            if sentinel.exists()
                            else []
                        )
                        if expected_success:
                            self.assertEqual(result.returncode, 0)
                            self.assertEqual(down_lines, ["down"])
                        else:
                            self.assertNotEqual(result.returncode, 0)
                            self.assertEqual(down_lines, [])


if __name__ == "__main__":
    unittest.main()
