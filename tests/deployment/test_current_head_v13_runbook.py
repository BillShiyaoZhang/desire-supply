"""Fail-closed static contract for the current-head v13 operator runbook."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK_PATH = ROOT / "docs" / "operations" / "run-and-check.md"
VERIFY_PATH = ROOT / "scripts" / "verify_container_stack.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_container_stack_v13_runbook", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()
RUNBOOK = RUNBOOK_PATH.read_text(encoding="utf-8")


def _replace_once(source: str, old: str, new: str) -> str:
    if old not in source:
        raise AssertionError(f"mutation target is missing: {old!r}")
    return source.replace(old, new, 1)


def _replace_restore_once(source: str, old: str, new: str) -> str:
    heading = "#### 4.8.2 当前头部隔离恢复与 replay"
    before, marker, restore_and_after = source.partition(heading)
    if marker != heading:
        raise AssertionError("current-head restore section is missing")
    if old not in restore_and_after:
        raise AssertionError(f"restore mutation target is missing: {old!r}")
    return before + marker + restore_and_after.replace(old, new, 1)


class CurrentHeadV13RunbookContractTest(unittest.TestCase):
    def assertBlocked(self, runbook: str, failure: str) -> None:
        self.assertIn(
            failure,
            VERIFIER._current_head_v13_runbook_failures(runbook),
        )

    def test_checked_in_runbook_is_closed(self) -> None:
        self.assertEqual(
            VERIFIER._current_head_v13_runbook_failures(RUNBOOK),
            (),
        )

    def test_markers_are_unique_and_ordered(self) -> None:
        for marker in (
            VERIFIER.CURRENT_HEAD_V13_FRESH_RUNBOOK_START,
            VERIFIER.CURRENT_HEAD_V13_FRESH_RUNBOOK_END,
            VERIFIER.CURRENT_HEAD_V13_JOURNEY_RESTART_START,
            VERIFIER.CURRENT_HEAD_V13_JOURNEY_RESTART_END,
        ):
            with self.subTest(marker=marker):
                self.assertBlocked(
                    _replace_once(
                        RUNBOOK,
                        marker,
                        marker.replace("CURRENT_HEAD", "DRIFTED_HEAD"),
                    ),
                    "current-head-v13-runbook-markers-open",
                )
        fresh_start = VERIFIER.CURRENT_HEAD_V13_FRESH_RUNBOOK_START
        fresh_end = VERIFIER.CURRENT_HEAD_V13_FRESH_RUNBOOK_END
        placeholder = "# TEMP CURRENT HEAD V13 MARKER"
        swapped = _replace_once(RUNBOOK, fresh_start, placeholder)
        swapped = _replace_once(swapped, fresh_end, fresh_start)
        swapped = _replace_once(swapped, placeholder, fresh_end)
        self.assertBlocked(
            swapped,
            "current-head-v13-runbook-markers-open",
        )

    def test_v13_coordinates_cidrs_and_evidence_paths_are_fixed(self) -> None:
        mutations = (
            (
                'export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v13"',
                'export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v14"',
            ),
            (
                'export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"',
                'export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust8"',
            ),
            (
                'export DESIRE_E2E_INGRESS_SUBNET="172.16.227.0/24"',
                'export DESIRE_E2E_INGRESS_SUBNET="172.16.226.0/24"',
            ),
            (
                'export DESIRE_E2E_OIDC_SUBNET="172.16.228.0/24"',
                'export DESIRE_E2E_OIDC_SUBNET="172.16.226.0/24"',
            ),
            (
                'export DESIRE_E2E_APP_SUBNET="172.16.229.0/24"',
                'export DESIRE_E2E_APP_SUBNET="172.16.226.0/24"',
            ),
            (
                'export DESIRE_E2E_DATA_SUBNET="172.16.231.0/24"',
                'export DESIRE_E2E_DATA_SUBNET="172.16.230.0/24"',
            ),
            (
                'export DESIRE_E2E_STATE="$DESIRE_E2E_EVIDENCE_DIR/state.json"',
                'export DESIRE_E2E_STATE="$DESIRE_E2E_EVIDENCE_DIR/state-2.json"',
            ),
            (
                'export DESIRE_E2E_RESTART_2_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-2-result.json"',
                'export DESIRE_E2E_RESTART_2_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-new.json"',
            ),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                self.assertBlocked(
                    _replace_once(RUNBOOK, old, new),
                    "current-head-v13-coordinate-open",
                )

    def test_preflight_requires_every_absence_proof_before_build(self) -> None:
        absence_proofs = (
            'test -z "${COMPOSE_PROJECT_NAME+x}"',
            'test -z "${COMPOSE_COMPATIBILITY+x}"',
            'test -z "${DESIRE_DB_PASSWORD_FILE+x}"',
            'test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"',
            'test ! -e "$DESIRE_E2E_INPUT_ROOT"',
            'DESIRE_E2E_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
            'test -z "$DESIRE_E2E_PROJECT_CONTAINER_IDS"',
            'DESIRE_E2E_PLATFORM_TAG_IDS="$(docker image ls --quiet "desire-supply-platform:$DESIRE_IMAGE_TAG")"',
            'test -z "$DESIRE_E2E_PLATFORM_TAG_IDS"',
            'if DESIRE_E2E_PORT_443_LISTENERS="$(lsof -nP -iTCP@127.0.0.1:443 -sTCP:LISTEN -t)"; then',
            'test -z "$DESIRE_E2E_PORT_443_LISTENERS"',
            'test ! -e "$DESIRE_E2E_STATE"',
            'test ! -e "$DESIRE_E2E_JOURNEY_RESULT"',
            'test ! -e "$DESIRE_E2E_RESTART_2_RESULT"',
        )
        for proof in absence_proofs:
            with self.subTest(proof=proof):
                self.assertBlocked(
                    _replace_once(RUNBOOK, proof, "# absence proof removed"),
                    "current-head-v13-preflight-open",
                )
        self.assertBlocked(
            _replace_once(RUNBOOK, "set -o pipefail", "# pipefail removed"),
            "current-head-v13-preflight-open",
        )
        self.assertBlocked(
            _replace_once(
                RUNBOOK,
                'test -z "${DESIRE_DB_PASSWORD_FILE+x}"',
                'test -z "${DESIRE_DB_PASSWORD_FILE:-}"',
            ),
            "current-head-v13-preflight-open",
        )
        self.assertBlocked(
            _replace_once(
                RUNBOOK,
                'DESIRE_E2E_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
                'test -z "$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
            ),
            "current-head-v13-preflight-open",
        )
        proof = 'test ! -e "$DESIRE_E2E_STATE"'
        reordered = _replace_once(RUNBOOK, proof, "# evidence check moved")
        reordered = _replace_once(
            reordered,
            "compose_v13 build api web edge",
            f"compose_v13 build api web edge\n{proof}",
        )
        self.assertBlocked(
            reordered,
            "current-head-v13-preflight-open",
        )

    def test_manifest_gate_is_once_before_every_v13_creation(self) -> None:
        gate = VERIFIER.CURRENT_HEAD_V13_DOCKER_HUB_PREFLIGHT_COMMAND
        build = "compose_v13 build api web edge"
        input_mkdir = 'mkdir -m 0700 -- "$DESIRE_E2E_INPUT_ROOT"'
        evidence_mkdir = 'mkdir -m 0700 -- "$DESIRE_E2E_EVIDENCE_DIR"'

        self.assertEqual(RUNBOOK.count(gate), 1)
        gate_position = RUNBOOK.index(gate)
        for creation in (
            input_mkdir,
            "scripts/prepare_internal_sandbox_inputs.py create",
            "scripts/manage_internal_sandbox_tls.py create",
            "desire_platform.deployment.internal_sandbox_bundle create",
            "scripts/prepare_internal_sandbox_compose_inputs.py create",
            evidence_mkdir,
            build,
        ):
            with self.subTest(creation=creation):
                self.assertLess(gate_position, RUNBOOK.index(creation))

        mutations = (
            _replace_once(RUNBOOK, gate, "# manifest gate removed"),
            _replace_once(RUNBOOK, gate, f"{gate}\n{gate}"),
            _replace_once(RUNBOOK, gate, f"{gate} || true"),
            _replace_once(RUNBOOK, gate, f"{gate}; true"),
            _replace_once(RUNBOOK, gate, f"timeout 60 {gate}"),
            _replace_once(RUNBOOK, gate, f"{gate} >/dev/null"),
            _replace_once(RUNBOOK, gate, f"mkdir -p /tmp/drift\n{gate}"),
        )
        for runbook in mutations:
            with self.subTest():
                self.assertBlocked(
                    runbook,
                    "current-head-v13-preflight-open",
                )

        for creation in (input_mkdir, evidence_mkdir, build):
            with self.subTest(moved_after=creation):
                moved = _replace_once(RUNBOOK, f"{gate}\n", "")
                moved = _replace_once(
                    moved,
                    creation,
                    f"{creation}\n{gate}",
                )
                self.assertBlocked(
                    moved,
                    "current-head-v13-preflight-open",
                )

    def test_fresh_build_and_same_container_replay_are_exact(self) -> None:
        build = "compose_v13 build api web edge"
        replay = 'docker start "$DESIRE_E2E_MIGRATE_ID"'
        mutations = (
            _replace_once(RUNBOOK, build, "# build omitted"),
            _replace_once(RUNBOOK, build, f"{build}\n{build}"),
            _replace_once(
                RUNBOOK,
                replay,
                "compose_v13 up -d --no-deps migrate",
            ),
        )
        for runbook in mutations:
            with self.subTest(mutation=runbook.count(build)):
                self.assertBlocked(
                    runbook,
                    "current-head-v13-fresh-flow-open",
                )

    def test_all_five_one_shots_and_exact_migration_evidence_are_required(self) -> None:
        identifier_assignments = (
            'DESIRE_E2E_MIGRATE_ID="$(compose_v13 ps --all --quiet migrate)"',
            'DESIRE_E2E_TAXONOMY_ID="$(compose_v13 ps --all --quiet taxonomy-seed)"',
            'DESIRE_E2E_RECONCILE_ID="$(compose_v13 ps --all --quiet online-credentials-reconcile)"',
            'DESIRE_E2E_CREDENTIAL_VERIFY_ID="$(compose_v13 ps --all --quiet online-credentials-verify)"',
            'DESIRE_E2E_IDENTITY_ID="$(compose_v13 ps --all --quiet identity-bootstrap)"',
        )
        for assignment in identifier_assignments:
            with self.subTest(assignment=assignment):
                self.assertBlocked(
                    _replace_once(RUNBOOK, assignment, "# identifier removed"),
                    "current-head-v13-one-shot-evidence-open",
                )

        self.assertBlocked(
            _replace_once(
                RUNBOOK,
                '"iam":{"applied_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37]',
                '"iam":{"applied_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]',
            ),
            "current-head-v13-one-shot-evidence-open",
        )

    def test_journey_and_each_restart_have_exclusive_result_outputs(self) -> None:
        result_arguments = (
            '--result-output "$DESIRE_E2E_JOURNEY_RESULT"',
            '--result-output "$DESIRE_E2E_RESTART_1_RESULT"',
            '--result-output "$DESIRE_E2E_RESTART_2_RESULT"',
        )
        for argument in result_arguments:
            with self.subTest(argument=argument):
                self.assertBlocked(
                    _replace_once(RUNBOOK, argument, "--result-output /tmp/drift.json"),
                    "current-head-v13-journey-restart-open",
                )
        self.assertBlocked(
            _replace_once(
                RUNBOOK,
                'umask "$original_umask"',
                "# original umask restored too early or omitted",
            ),
            "current-head-v13-journey-restart-open",
        )

    def test_two_restart_rounds_only_restart_persistent_services(self) -> None:
        mutations = (
            _replace_once(
                RUNBOOK,
                "compose_v13 stop db",
                "compose_v13 stop migrate",
            ),
            _replace_once(
                RUNBOOK,
                "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 db",
                "compose_v13 up -d --no-recreate --wait --wait-timeout 120 db",
            ),
            _replace_once(
                RUNBOOK,
                "\ncompose_v13 stop web\n",
                "\ncompose_v13 stop taxonomy-seed\n",
            ),
            _replace_once(
                RUNBOOK,
                "compose_v13 stop db",
                "compose_v13 stop db\ncompose_v13 restart migrate",
            ),
        )
        for runbook in mutations:
            with self.subTest():
                self.assertBlocked(
                    runbook,
                    "current-head-v13-journey-restart-open",
                )

    def test_preservation_snapshots_and_all_assertions_are_required(self) -> None:
        mutations = (
            _replace_once(
                RUNBOOK,
                '= "$DESIRE_E2E_MIGRATE_SNAPSHOT"',
                '= "$DESIRE_E2E_TAXONOMY_SNAPSHOT"',
            ),
            _replace_once(
                RUNBOOK,
                '= "$DESIRE_E2E_STATE_SHA"',
                '= "$DESIRE_E2E_STATE_STAT"',
            ),
            _replace_once(
                RUNBOOK,
                '"$DESIRE_E2E_DB_ID")" = "running|healthy|0"',
                '"$DESIRE_E2E_DB_ID")" = "running|healthy|1"',
            ),
            _replace_once(
                RUNBOOK,
                '"${DESIRE_E2E_PROJECT}_ingress")" = "$DESIRE_E2E_INGRESS_NETWORK_ID"',
                '"${DESIRE_E2E_PROJECT}_ingress")" = "$DESIRE_E2E_APP_NETWORK_ID"',
            ),
            _replace_once(
                RUNBOOK,
                '= "volume|$DESIRE_E2E_DATA_VOLUME"',
                '= "bind|$DESIRE_E2E_DATA_VOLUME"',
            ),
            _replace_once(
                RUNBOOK,
                'test "$(compose_v13 ps --all --quiet migrate)" = "$DESIRE_E2E_MIGRATE_ID"',
                "# one-shot compose identity removed",
            ),
            _replace_once(
                RUNBOOK,
                'test "$DESIRE_E2E_DB_NEXT_STARTED_AT" != "$DESIRE_E2E_DB_STARTED_AT"',
                'test "$DESIRE_E2E_DB_NEXT_STARTED_AT" = "$DESIRE_E2E_DB_STARTED_AT"',
            ),
            _replace_once(
                RUNBOOK,
                'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_IDENTITY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
                "# identity image proof removed",
            ),
            _replace_once(RUNBOOK, "\nassert_v13_preserved\n", "\n"),
        )
        for runbook in mutations:
            with self.subTest():
                self.assertBlocked(
                    runbook,
                    "current-head-v13-snapshot-open",
                )

    def test_destructive_commands_and_later_builds_are_rejected(self) -> None:
        build = "compose_v13 build api web edge"
        for command, failure in (
            ("compose_v13 down", "current-head-v13-destructive-command-open"),
            ("compose_v13 rm api", "current-head-v13-destructive-command-open"),
            (
                "compose_v13 run --rm api true",
                "current-head-v13-destructive-command-open",
            ),
            ("compose_v13 build api", "current-head-v13-fresh-flow-open"),
        ):
            with self.subTest(command=command):
                self.assertBlocked(
                    _replace_once(RUNBOOK, build, f"{build}\n{command}"),
                    failure,
                )
        later_build = _replace_once(
            RUNBOOK,
            "compose_v13 stop web",
            "compose_v13 build api\ncompose_v13 stop web",
        )
        self.assertBlocked(
            later_build,
            "current-head-v13-fresh-flow-open",
        )


class CurrentHeadV13RestoreRunbookContractTest(unittest.TestCase):
    def assertRestoreBlocked(self, runbook: str, failure: str) -> None:
        self.assertIn(
            failure,
            VERIFIER._current_head_restore_runbook_failures(runbook),
        )

    def test_checked_in_restore_runbook_is_closed(self) -> None:
        self.assertEqual(
            VERIFIER._current_head_restore_runbook_failures(RUNBOOK),
            (),
        )

    def test_restore_markers_are_unique_and_ordered(self) -> None:
        markers = (
            VERIFIER.CURRENT_HEAD_RESTORE_PREFLIGHT_START,
            VERIFIER.CURRENT_HEAD_RESTORE_PREFLIGHT_END,
            VERIFIER.CURRENT_HEAD_RESTORE_EXECUTION_START,
            VERIFIER.CURRENT_HEAD_RESTORE_EXECUTION_END,
            VERIFIER.CURRENT_HEAD_RESTORE_POSTRUN_START,
            VERIFIER.CURRENT_HEAD_RESTORE_POSTRUN_END,
            VERIFIER.CURRENT_HEAD_RESTORE_AUTHORITY_START,
            VERIFIER.CURRENT_HEAD_RESTORE_AUTHORITY_END,
        )
        self.assertEqual(
            tuple(RUNBOOK.count(marker) for marker in markers),
            (1,) * len(markers),
        )
        self.assertEqual(
            tuple(RUNBOOK.index(marker) for marker in markers),
            tuple(sorted(RUNBOOK.index(marker) for marker in markers)),
        )
        for marker in markers:
            with self.subTest(marker=marker):
                self.assertRestoreBlocked(
                    _replace_restore_once(
                        RUNBOOK,
                        marker,
                        marker.replace("CURRENT_HEAD", "DRIFTED_HEAD"),
                    ),
                    "database-restore-runbook-markers-open",
                )

    def test_restore_offsite_authority_closure_is_byte_sealed(self) -> None:
        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                "完整性记录，不是加密、签名或 MAC。",
                "完整性记录，可作为加密证明。",
            ),
            "database-restore-offsite-authority-open",
        )
        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                "<!-- END CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->\n\n"
                "2026-08-19 已完成一次 v9",
                "<!-- END CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->\n"
                "无需另行许可即可直接生成并上传备份。\n\n"
                "2026-08-19 已完成一次 v9",
            ),
            "database-restore-offsite-authority-open",
        )
        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                "加密离机备份仍等待有权操作者明确指定 recipient、KMS、tool 与 destination。",
                "加密离机备份仍等待有权操作者明确指定 recipient、KMS、tool 与 destination。"
                " 无需任何 authority，后续可以直接生成并宣称 encrypted/offsite backup。",
            ),
            "database-restore-offsite-authority-open",
        )

    def test_restore_coordinates_and_compatibility_mode_are_fixed(self) -> None:
        coordinate_mutations = (
            (
                'export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"',
                'export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v14"',
            ),
            (
                'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill01"',
                'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill02"',
            ),
            (
                'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"',
                'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.233.0/24"',
            ),
        )
        for old, new in coordinate_mutations:
            with self.subTest(coordinate=old):
                self.assertRestoreBlocked(
                    _replace_restore_once(RUNBOOK, old, new),
                    "database-restore-artifact-revalidation-runbook-open",
                )

        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                'test -z "${COMPOSE_COMPATIBILITY+x}"',
                'test -z "${COMPOSE_COMPATIBILITY:-}"',
            ),
            "database-restore-artifact-revalidation-runbook-open",
        )
        compatibility = _replace_restore_once(
            RUNBOOK,
            "compose_v13_restore() {\n  docker compose \\",
            "compose_v13_restore() {\n  docker compose --compatibility \\",
        )
        self.assertTrue(
            VERIFIER._current_head_restore_runbook_failures(compatibility),
            "literal --compatibility must be rejected",
        )

    def test_restore_execution_is_one_exact_no_build_flow(self) -> None:
        command = (
            "compose_v13_restore up -d --no-build --no-recreate "
            "database-restore-replay"
        )
        mutations = (
            _replace_restore_once(
                RUNBOOK,
                command,
                "compose_v13_restore up -d --no-recreate database-restore-replay",
            ),
            _replace_restore_once(
                RUNBOOK,
                command,
                f"{command}\ncompose_v13_restore build database-restore-replay",
            ),
            _replace_restore_once(
                RUNBOOK,
                'test "$(docker wait "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "0"',
                'compose_v13_restore wait database-restore-replay',
            ),
        )
        for mutation in mutations:
            with self.subTest():
                self.assertRestoreBlocked(
                    mutation,
                    "database-restore-execution-runbook-open",
                )

    def test_restore_postrun_requires_411_resources_and_source_image(self) -> None:
        mutations = (
            (
                'test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "4"',
                'test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "5"',
            ),
            (
                'test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
                'test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "2"',
            ),
            (
                'test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
                'test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "2"',
            ),
        )
        for old, new in mutations:
            with self.subTest(resource=old):
                self.assertRestoreBlocked(
                    _replace_restore_once(RUNBOOK, old, new),
                    "database-restore-postrun-resource-open",
                )

        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
                "# source API image proof removed",
            ),
            "database-restore-postrun-evidence-open",
        )

    def test_restore_requires_three_exact_logs_and_artifact_nlink(self) -> None:
        for log_name in ("BOOTSTRAP", "VERIFY", "REPLAY"):
            proof = (
                f'test "$DESIRE_DATABASE_RESTORE_{log_name}_LOG" = '
                f'"$DESIRE_DATABASE_RESTORE_EXPECTED_{log_name}"'
            )
            with self.subTest(log=log_name):
                self.assertRestoreBlocked(
                    _replace_restore_once(
                        RUNBOOK,
                        proof,
                        f"# exact {log_name.lower()} log proof removed",
                    ),
                    "database-restore-postrun-evidence-open",
                )

        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                'test "$(stat -f \'%Lp|%u|%g|%l\' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"',
                'test "$(stat -f \'%Lp|%u|%g\' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"',
            ),
            "database-restore-artifact-revalidation-runbook-open",
        )
        self.assertRestoreBlocked(
            _replace_restore_once(
                RUNBOOK,
                'DESIRE_DATABASE_RESTORE_DUMP_STAT="$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")"',
                'DESIRE_DATABASE_RESTORE_DUMP_STAT="$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")"',
            ),
            "database-restore-artifact-revalidation-runbook-open",
        )


if __name__ == "__main__":
    unittest.main()
