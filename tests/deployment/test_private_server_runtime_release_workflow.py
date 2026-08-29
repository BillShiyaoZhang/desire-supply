"""Static, fail-closed contract for the runtime release GitHub workflow."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "private-server-runtime-release.yml"
RUNBOOK_PATH = ROOT / "docs" / "operations" / "private-server-runtime-release.md"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_BUILDX_SHA = "37fe631027851001ddb9b187196cc803df7f5f0e"
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
BUILDKIT_DIGEST = (
    "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)
SBOM_SCANNER_DIGEST = (
    "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
)


class PrivateServerRuntimeReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.lines = cls.raw.splitlines()
        cls.runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

    def test_trigger_is_manual_with_one_closed_architecture_choice(self) -> None:
        self.assertIn(
            "on:\n"
            "  workflow_dispatch:\n"
            "    inputs:\n"
            "      architecture:\n",
            self.raw,
        )
        self.assertEqual(self.raw.count("      architecture:\n"), 1)
        self.assertRegex(
            self.raw,
            re.compile(
                r"      architecture:\n"
                r"(?:        .*\n)+?"
                r"        options:\n"
                r"          - amd64\n"
                r"          - arm64\n\n",
            ),
        )
        for forbidden_trigger in (
            "  push:",
            "  pull_request:",
            "  schedule:",
            "  repository_dispatch:",
            "  workflow_call:",
        ):
            self.assertNotIn(forbidden_trigger, self.raw)

    def test_permissions_and_runner_are_closed_and_native(self) -> None:
        self.assertIn("permissions:\n  contents: read\n\n", self.raw)
        permission_block = self.raw.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(permission_block, "  contents: read")
        self.assertNotRegex(self.raw, re.compile(r"(?m)^\s+(?:id-token|packages|actions):"))
        self.assertIn(
            "runs-on: ${{ inputs.architecture == 'arm64' && "
            "'ubuntu-24.04-arm' || 'ubuntu-24.04' }}",
            self.raw,
        )
        self.assertIn('test "$native_architecture" = "$ARCHITECTURE"', self.raw)
        self.assertNotIn("matrix:", self.raw)
        self.assertNotIn("qemu", self.raw.casefold())

    def test_all_actions_are_immutable_and_exactly_pinned(self) -> None:
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", self.raw)
        self.assertEqual(
            uses,
            [
                f"actions/checkout@{CHECKOUT_SHA}",
                f"docker/setup-buildx-action@{SETUP_BUILDX_SHA}",
                f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}",
            ],
        )
        for value in uses:
            self.assertRegex(value.rsplit("@", 1)[1], r"^[0-9a-f]{40}$")
        self.assertIn("ref: ${{ github.sha }}", self.raw)
        self.assertIn("persist-credentials: false", self.raw)

    def test_buildx_version_and_digest_pinned_buildkit_scanner_are_exact(self) -> None:
        self.assertIn('BUILDX_NO_DEFAULT_ATTESTATIONS: "1"', self.raw)
        self.assertIn("BUILDX_VERSION: v0.36.1", self.raw)
        self.assertIn("version: v0.36.1", self.raw)
        self.assertIn(
            f"BUILDKIT_IMAGE: moby/buildkit:v0.32.2@{BUILDKIT_DIGEST}",
            self.raw,
        )
        self.assertIn(
            f"driver-opts: image=moby/buildkit:v0.32.2@{BUILDKIT_DIGEST}",
            self.raw,
        )
        self.assertIn("buildkitd-flags: --log-level=info", self.raw)
        self.assertIn("cache-binary: false", self.raw)
        self.assertIn(
            f"SBOM_SCANNER: docker.io/docker/buildkit-syft-scanner:1.11.0@{SBOM_SCANNER_DIGEST}",
            self.raw,
        )
        runbook = self.runbook.replace("\n", " ")
        self.assertIn("Buildx release asset 只做版本字符串核对", runbook)
        self.assertIn("不声明构建输入闭包或可复现构建", runbook)

    def test_server_runbook_closes_native_arch_and_loaded_config_digest(self) -> None:
        for required in (
            'DESIRE_RUNTIME_RELEASE_NATIVE_MACHINE="$(uname -m)"',
            "x86_64) DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE=amd64",
            "aarch64|arm64) DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE=arm64",
            'test "$DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE" =',
            '"image_config_digests"',
            "pre-existing runtime tag points to a different image ID",
            'test "$DESIRE_RUNTIME_RELEASE_ACTUAL_ID" =',
            "必须在第一次 image import/pull 前停止",
        ):
            self.assertIn(required, self.runbook)

        marker = 'DESIRE_RUNTIME_RELEASE_NATIVE_MACHINE="$(uname -m)"'
        marker_offset = self.runbook.index(marker)
        block_start = self.runbook.rfind("```bash\n", 0, marker_offset)
        block = self.runbook[block_start + len("```bash\n") :].split("\n```", 1)[0]
        checked = subprocess.run(
            ("/bin/bash", "-n"),
            input=block,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_source_snapshot_is_from_the_exact_checked_out_commit(self) -> None:
        readiness = "python -B scripts/check_private_server_source_readiness.py"
        current_head = "python -B scripts/verify_current_head_v27.py"
        self.assertIn(
            "- name: Verify the current-head v27 static contract",
            self.raw,
        )
        self.assertNotIn("python -B scripts/verify_current_head_v26.py", self.raw)
        self.assertNotIn("python -B scripts/verify_current_head_v25.py", self.raw)
        self.assertNotIn("python -B scripts/verify_current_head_v24.py", self.raw)
        self.assertNotIn("python -B scripts/verify_current_head_v23.py", self.raw)
        self.assertIn(
            "python -B scripts/private_server_runtime_release_source.py create",
            self.raw,
        )
        self.assertEqual(self.raw.count(readiness), 1)
        self.assertEqual(self.raw.count(current_head), 1)
        self.assertLess(self.raw.index(readiness), self.raw.index(current_head))
        self.assertLess(
            self.raw.index(current_head),
            self.raw.index("python -B scripts/private_server_runtime_release_source.py create"),
        )
        for marker in ("Trust11", "Trust9/Trust10", "不得把旧 bundle"):
            self.assertIn(marker, self.runbook)
        for required in (
            '--repository "$GITHUB_WORKSPACE"',
            '--commit "$GITHUB_SHA"',
            '--snapshot-output "$RELEASE_ROOT/source/source-snapshot.tar"',
            '--context-output "$RELEASE_ROOT/source/context"',
            '--dockerfile-set-output "$RELEASE_ROOT/source/dockerfile-digest-set.json"',
            '--facts-output "$RELEASE_ROOT/source/source-facts.json"',
        ):
            self.assertIn(required, self.raw)
        self.assertIn(
            "RELEASE_ROOT: ${{ runner.temp }}/private-server-runtime-release",
            self.raw,
        )

    def test_release_inputs_are_measured_and_verified_before_permanent_staging(self) -> None:
        section = self.runbook.split(
            "## 9. Release inputs、TLS 与 activation 是独立步骤",
            1,
        )[1]
        for marker in (
            "scripts/private_server_release_inputs.py measure",
            "PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY",
            "scripts/private_server_release_inputs.py verify --expected-tree-sha256",
            "authority=NOT_AUTHORITY",
            "execution_permitted=false",
            "production_authorized=false",
            "不创建 staging 或 attempt",
            "/usr/bin/python3 -I -B",
            "`.pyc` bytecode",
            "永久 staging 仍只能由 activator",
        ):
            self.assertIn(marker, section)
        self.assertLess(section.index(" measure"), section.index(" verify"))

    def test_four_fixed_application_oci_archives_have_modern_attestations(self) -> None:
        self.assertEqual(self.raw.count("docker buildx build \\"), 4)
        targets = re.findall(r"--target ([a-z0-9-]+) \\", self.raw)
        self.assertEqual(
            targets,
            [
                "platform-runtime",
                "web-runtime",
                "edge-runtime",
                "oidc-egress-guard-runtime",
            ],
        )
        self.assertEqual(self.raw.count('--platform "linux/${ARCHITECTURE}"'), 4)
        self.assertEqual(self.raw.count('--provenance "mode=min,version=v1"'), 4)
        self.assertEqual(self.raw.count('--sbom "generator=${SBOM_SCANNER}"'), 4)
        expected_outputs = {
            "platform": "desire-supply-platform",
            "web": "desire-supply-web",
            "edge": "desire-supply-edge",
            "oidc-egress-guard": "desire-supply-oidc-egress-guard",
        }
        for slot, repository in expected_outputs.items():
            self.assertIn(
                f"type=oci,dest=${{RELEASE_ROOT}}/images/{slot}.oci.tar,"
                f"name={repository}:${{IMAGE_TAG}},oci-mediatypes=true,"
                "oci-artifact=true,tar=true",
                self.raw,
            )
            self.assertIn(f'--tag "{repository}:${{IMAGE_TAG}}"', self.raw)
        self.assertEqual(self.raw.count("type=oci,dest="), 4)
        self.assertEqual(self.raw.count("oci-artifact=true"), 4)

    def test_tag_and_release_identity_are_derived_only_from_trusted_run_facts(self) -> None:
        self.assertIn(
            "IMAGE_TAG: sha-${{ github.sha }}-${{ inputs.architecture }}-"
            "r${{ github.run_id }}-a${{ github.run_attempt }}",
            self.raw,
        )
        self.assertIn(
            'test "$IMAGE_TAG" = "sha-${GITHUB_SHA}-${ARCHITECTURE}-'
            'r${GITHUB_RUN_ID}-a${GITHUB_RUN_ATTEMPT}"',
            self.raw,
        )
        self.assertIn('[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]', self.raw)
        self.assertIn('[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]]', self.raw)
        self.assertIn('[[ "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]', self.raw)
        self.assertIn(
            'test "$RELEASE_ROOT" = "$RUNNER_TEMP/private-server-runtime-release"',
            self.raw,
        )
        self.assertIn('test ! -e "$RELEASE_ROOT"', self.raw)
        self.assertEqual(self.raw.count("${{ inputs."), 5)
        self.assertNotIn("github.event.inputs", self.raw)

    def test_postgres_evidence_and_bundle_are_prepared_by_closed_helpers(self) -> None:
        self.assertIn(
            "python -B scripts/fetch_pinned_postgres_release_evidence.py",
            self.raw,
        )
        self.assertIn('--architecture "$ARCHITECTURE"', self.raw)
        self.assertIn('--output-dir "$RELEASE_ROOT/postgres"', self.raw)
        self.assertIn(
            "python -B scripts/prepare_private_server_runtime_release.py",
            self.raw,
        )
        for required in (
            '--commit "$GITHUB_SHA"',
            '--run-id "$GITHUB_RUN_ID"',
            '--run-attempt "$GITHUB_RUN_ATTEMPT"',
            '--source-snapshot "$RELEASE_ROOT/source/source-snapshot.tar"',
            '--source-dockerfile-set "$RELEASE_ROOT/source/dockerfile-digest-set.json"',
            '--source-facts "$RELEASE_ROOT/source/source-facts.json"',
            '--images-dir "$RELEASE_ROOT/images"',
            '--postgres-dir "$RELEASE_ROOT/postgres"',
            '--output "$bundle_path"',
        ):
            self.assertIn(required, self.raw)
        self.assertIn("sha256sum \"$bundle_path\"", self.raw)

    def test_exactly_one_unarchived_file_is_uploaded(self) -> None:
        self.assertEqual(self.raw.count("actions/upload-artifact@"), 1)
        upload_block = self.raw.split(
            f"uses: actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}", 1
        )[1].split("\n\n", 1)[0]
        self.assertIn("path: ${{ steps.bundle.outputs.path }}", upload_block)
        self.assertIn("archive: false", upload_block)
        self.assertIn("if-no-files-found: error", upload_block)
        self.assertNotIn("name:", upload_block)
        self.assertIn("LOCAL_BUNDLE_SHA256", self.raw)
        self.assertIn("GITHUB_ARTIFACT_DIGEST", self.raw)
        self.assertIn("reported as separate digest domains", self.raw)

    def test_workflow_cannot_publish_or_deploy(self) -> None:
        folded = self.raw.casefold()
        for forbidden in (
            "build-push-action",
            "login-action",
            "docker login",
            "--push",
            "push: true",
            "--load",
            "load: true",
            "--allow",
            "allow-insecure-entitlement",
            "security.insecure",
            "network.host",
            "docker.sock",
            "id-token: write",
            "packages: write",
            "environment:",
            "kubectl",
            "docker compose",
            "ssh ",
            "scp ",
        ):
            self.assertNotIn(forbidden, folded)
        self.assertIn("VALIDATED_RELEASE_ARTIFACT_NOT_AUTHORITY", self.raw)
        self.assertIn("production authorized: `false`", self.raw)
        self.assertIn("execution permitted: `false`", self.raw)


if __name__ == "__main__":
    unittest.main()
