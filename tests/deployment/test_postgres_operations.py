"""Closed contracts for PostgreSQL backup and isolated restore verification."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
OPERATIONS_COMPOSE = "deploy/postgres-operations.compose.yaml"
OPERATIONS_SCRIPT = ROOT / "deploy" / "postgres-backup-restore.sh"
CORE_FACTS_SQL = ROOT / "deploy" / "postgres-core-facts.sql"
DEPLOYMENT_DOCS = ROOT / "docs" / "operations" / "container-deployment.md"
RUNBOOK_DOCS = ROOT / "docs" / "operations" / "run-and-check.md"
DEVCONTAINER_DOCS = ROOT / "docs" / "development" / "dev-container.md"
VERIFY_PATH = ROOT / "scripts" / "verify_container_stack.py"
GITIGNORE = ROOT / ".gitignore"
DOCKERIGNORE = ROOT / ".dockerignore"
BACKUP_ARTIFACT_RELATIVE = (
    "backups/internal-sandbox/v13drill01/"
    "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01.dump"
)
POSTGRES_PARENT_TMPFS = (
    "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"
)
POSTGRES_CHILD_DATA = "/var/lib/postgresql/data"
POSTGRES_CHILD_PGDATA = "/var/lib/postgresql/data/pgdata"
BOUNDED_LOCAL_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
OPERATIONS_SERVICES = (
    "database-backup",
    "database-restore-target",
    "database-restore-bootstrap",
    "database-restore-verify",
    "database-restore-replay",
)


def _compose_config(*, environment: dict[str, str] | None = None) -> dict:
    command_environment = os.environ.copy()
    if environment is not None:
        command_environment.update(environment)
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            OPERATIONS_COMPOSE,
            "--profile",
            "database-backup",
            "--profile",
            "database-restore-verify",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=command_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _load_current_head_v30_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_current_head_v30_operations", ROOT / "scripts/verify_current_head_v30.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("v30 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_container_stack_operations", VERIFY_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("container verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _depends_on(service: dict) -> dict[str, str]:
    return {
        name: value["condition"]
        for name, value in service.get("depends_on", {}).items()
    }


def _assert_exact_bounded_local_logging(
    test_case: unittest.TestCase,
    services: dict,
    service_names: tuple[str, ...],
) -> None:
    for service_name in service_names:
        with test_case.subTest(service=service_name):
            service = services[service_name]
            test_case.assertIn("logging", service)
            logging = service["logging"]
            test_case.assertEqual(logging, BOUNDED_LOCAL_LOGGING)
            for option_name in ("compress", "max-file", "max-size"):
                test_case.assertIs(type(logging["options"][option_name]), str)


class PostgresOperationsContractTest(unittest.TestCase):
    def test_resolved_operations_use_exact_bounded_local_logging(self) -> None:
        services = _compose_config()["services"]
        _assert_exact_bounded_local_logging(
            self,
            services,
            OPERATIONS_SERVICES,
        )

    def test_operations_artifacts_exist_and_have_closed_content(self) -> None:
        for path in (
            ROOT / OPERATIONS_COMPOSE,
            OPERATIONS_SCRIPT,
            CORE_FACTS_SQL,
        ):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())

        script = OPERATIONS_SCRIPT.read_text(encoding="utf-8")
        for fragment in (
            "pg_dump",
            "pg_restore",
            "--serializable-deferrable",
            "--single-transaction",
            "sha256sum",
            "cmp -s",
            "desire-restore-verify-",
            "18|48|48|5|5|16|16|24|24|11|11|2|2",
            "matching_continuity_counts",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        # Bind the unversioned alias to the fixed v30 release constants, then
        # independently verify those pins against the actual migration bytes.
        head = _load_current_head_v30_verifier()
        self.assertEqual(head.HEADS, "18|48|48|5|5|16|16|24|24|11|11|2|2")
        self.assertIn(f"EXPECTED_CONTRACTS='{head.EXPECTED_CONTRACTS}'", script)
        self.assertEqual(head._manifest_failures(ROOT), ())
        self.assertEqual(
            OPERATIONS_SCRIPT.read_bytes(),
            (ROOT / "deploy/postgres-backup-restore-v30.sh").read_bytes(),
        )
        self.assertNotIn("PGPASSWORD", script)
        self.assertNotIn("desire-supply-e2e", script)
        self.assertNotIn("docker volume", script)
        self.assertNotIn("18|36|36|3|3|8|8|3|3|2|2", script)

        empty_target = script.partition("_require_empty_restore_target() {")[2].partition(
            "\n}\n\n_restore_verify()"
        )[0]
        for relation in (
            "demand.demand_funding_markers",
            "demand.manual_funding_assignment_releases",
            "demand.manual_funding_findings",
        ):
            with self.subTest(empty_target_relation=relation):
                self.assertEqual(
                    empty_target.count(f"SELECT count(*) FROM {relation}"),
                    1,
                )

        facts = CORE_FACTS_SQL.read_text(encoding="utf-8")
        for relation in (
            "infra.iam_schema_compatibility",
            "profile.schema_compatibility",
            "demand.schema_compatibility",
            "trust.schema_compatibility",
            "taxonomy.schema_compatibility",
            "iam.users",
            "iam.access_invitations",
            "iam.memberships",
            "profile.creator_profiles",
            "profile.command_receipts",
            "demand.demands",
            "demand.demand_review_assignments",
            "demand.source_inbox",
            "demand.command_receipts",
            "demand.review_claim_receipts",
            "demand.manual_funding_review_cases",
            "demand.manual_funding_review_assignments",
            "demand.manual_funding_assignment_releases",
            "demand.manual_funding_findings",
            "demand.manual_funding_confirmations",
            "demand.manual_funding_receipts",
            "trust.cases",
            "trust.reports",
            "trust.case_assignments",
            "trust.case_assignment_releases",
            "trust.triage_drafts",
            "trust.triage_versions",
            "trust.command_receipts",
            "trust.appeal_receipt_key_policy",
            "trust.appeals",
            "trust.appeal_application_drafts",
            "trust.appeal_application_versions",
            "trust.appeal_review_assignments",
            "trust.appeal_assignment_releases",
            "trust.appeal_review_drafts",
            "trust.appeal_decision_versions",
            "trust.appeal_command_receipts",
            "trust.sealed_text_key_policy",
            "taxonomy.current_bundles",
            "taxonomy.consumer_inbox",
            "profile.taxonomy_projection_inbox",
            "audit.audit_events",
            "infra.outbox_events",
            "infra.consumer_inbox_events",
        ):
            with self.subTest(relation=relation):
                self.assertIn(relation, facts)

    def test_one_shot_profiles_are_pinned_isolated_and_not_published(self) -> None:
        config = _compose_config()
        services = config["services"]
        names = {
            "database-backup",
            "database-restore-target",
            "database-restore-bootstrap",
            "database-restore-verify",
            "database-restore-replay",
        }
        self.assertTrue(names.issubset(services))
        postgres_image = services["db"]["image"]

        backup = services["database-backup"]
        self.assertEqual(backup["profiles"], ["database-backup"])
        self.assertEqual(backup["image"], postgres_image)
        self.assertEqual(backup["entrypoint"], ["/bin/sh", "/run/desire-ops/postgres-backup-restore.sh"])
        self.assertEqual(backup["command"], ["backup"])
        self.assertEqual(set(backup["networks"]), {"data"})
        self.assertEqual(_depends_on(backup), {"db": "service_healthy"})
        self.assertNotIn("ports", backup)
        self.assertTrue(backup["read_only"])
        self.assertIn("ALL", backup["cap_drop"])
        self.assertIn("no-new-privileges=true", backup["security_opt"])
        self.assertEqual(
            [item["source"] for item in backup["secrets"]],
            ["db_superuser_password"],
        )
        backup_mount = backup["volumes"][0]
        self.assertEqual(backup_mount["type"], "bind")
        self.assertEqual(backup_mount["target"], "/var/lib/desire-backup")
        self.assertFalse(backup_mount.get("read_only", False))
        self.assertFalse(backup_mount["bind"]["create_host_path"])
        self.assertEqual(
            backup["tmpfs"],
            [
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                POSTGRES_PARENT_TMPFS,
            ],
        )

        target = services["database-restore-target"]
        self.assertEqual(target["profiles"], ["database-restore-verify"])
        self.assertEqual(target["image"], postgres_image)
        self.assertEqual(
            target["environment"]["POSTGRES_DB"], "desire_restore_verify"
        )
        self.assertNotIn("ports", target)
        self.assertEqual(
            target["networks"]["database-restore-verification"]["aliases"],
            ["db"],
        )
        self.assertEqual(
            target["volumes"][0]["source"],
            "postgres-restore-verification-data",
        )
        self.assertEqual(target["volumes"][0]["type"], "volume")
        self.assertEqual(target["volumes"][0]["target"], POSTGRES_CHILD_DATA)
        self.assertEqual(target["environment"]["PGDATA"], POSTGRES_CHILD_PGDATA)
        self.assertEqual(target["tmpfs"], [POSTGRES_PARENT_TMPFS])

        bootstrap = services["database-restore-bootstrap"]
        self.assertEqual(bootstrap["profiles"], ["database-restore-verify"])
        self.assertEqual(
            bootstrap["command"],
            ["python", "-m", "desire_platform.deployment"],
        )
        self.assertEqual(
            bootstrap["environment"]["DESIRE_DATABASE_NAME"],
            "desire_restore_verify",
        )
        self.assertEqual(
            _depends_on(bootstrap),
            {"database-restore-target": "service_healthy"},
        )

        verify = services["database-restore-verify"]
        self.assertEqual(verify["profiles"], ["database-restore-verify"])
        self.assertEqual(verify["image"], postgres_image)
        self.assertEqual(verify["command"], ["restore-verify"])
        self.assertEqual(
            verify["environment"]["DESIRE_DATABASE_NAME"],
            "desire_restore_verify",
        )
        self.assertEqual(
            _depends_on(verify),
            {"database-restore-bootstrap": "service_completed_successfully"},
        )
        self.assertEqual(
            verify["volumes"][0]["target"], "/var/lib/desire-backup"
        )
        self.assertTrue(verify["volumes"][0]["read_only"])
        self.assertNotIn("ports", verify)
        self.assertEqual(
            verify["tmpfs"],
            [
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                POSTGRES_PARENT_TMPFS,
            ],
        )

        replay = services["database-restore-replay"]
        self.assertEqual(replay["profiles"], ["database-restore-verify"])
        self.assertEqual(
            replay["command"],
            ["python", "-m", "desire_platform.deployment"],
        )
        self.assertEqual(
            replay["environment"],
            bootstrap["environment"],
        )
        self.assertEqual(
            [item["source"] for item in replay["secrets"]],
            ["db_superuser_password"],
        )
        self.assertEqual(
            _depends_on(replay),
            {"database-restore-verify": "service_completed_successfully"},
        )
        self.assertEqual(set(replay["networks"]), {"database-restore-verification"})
        self.assertNotIn("ports", replay)
        self.assertTrue(replay["read_only"])
        self.assertIn("ALL", replay["cap_drop"])
        self.assertIn("no-new-privileges=true", replay["security_opt"])
        self.assertEqual(replay["restart"], "no")
        self.assertEqual(replay["tmpfs"], ["/tmp:rw,noexec,nosuid,nodev,size=64m"])

        restore_network = config["networks"]["database-restore-verification"]
        self.assertTrue(restore_network["internal"])
        self.assertEqual(
            restore_network["ipam"]["config"],
            [{"subnet": "172.16.232.0/24"}],
        )
        self.assertNotIn("gateway", restore_network["ipam"]["config"][0])
        self.assertIn("postgres-restore-verification-data", config["volumes"])

        overridden = _compose_config(
            environment={"DESIRE_DATABASE_RESTORE_SUBNET": "10.251.232.0/24"}
        )
        self.assertEqual(
            overridden["networks"]["database-restore-verification"]["ipam"][
                "config"
            ],
            [{"subnet": "10.251.232.0/24"}],
        )

        raw_compose = (ROOT / OPERATIONS_COMPOSE).read_text(encoding="utf-8")
        raw_network = raw_compose.partition("\nnetworks:\n")[2].partition(
            "\nvolumes:\n"
        )[0]
        self.assertIn(
            "subnet: ${DESIRE_DATABASE_RESTORE_SUBNET:-172.16.232.0/24}",
            raw_network,
        )
        self.assertNotIn("gateway:", raw_network)
        self.assertNotIn("name:", raw_network)
        self.assertNotIn("external:", raw_network)

    def test_verifier_rejects_restore_p1_contract_mutations(self) -> None:
        verifier = _load_verifier()
        operations = _compose_config()
        raw_compose = (ROOT / OPERATIONS_COMPOSE).read_text(encoding="utf-8")
        script = OPERATIONS_SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(
            verifier._postgres_restore_closure_failures(
                operations, raw_compose, script
            ),
            (),
        )

        missing_table = script.replace(
            "(SELECT count(*) FROM demand.manual_funding_findings) +",
            "0 +",
            1,
        )
        self.assertIn(
            "database-restore-empty-target-open:demand.manual_funding_findings",
            verifier._postgres_restore_closure_failures(
                operations, raw_compose, missing_table
            ),
        )

        missing_ipam = json.loads(json.dumps(operations))
        del missing_ipam["networks"]["database-restore-verification"]["ipam"]
        self.assertIn(
            "database-restore-network-ipam-open",
            verifier._postgres_restore_closure_failures(
                missing_ipam, raw_compose, script
            ),
        )

        wrong_replay_order = json.loads(json.dumps(operations))
        wrong_replay_order["services"]["database-restore-replay"]["depends_on"] = {
            "database-restore-bootstrap": {
                "condition": "service_completed_successfully",
                "required": True,
            }
        }
        self.assertIn(
            "database-restore-replay-order-open",
            verifier._postgres_restore_closure_failures(
                wrong_replay_order, raw_compose, script
            ),
        )

    def test_docs_lock_parent_tmpfs_without_relaying_out_named_data(self) -> None:
        deployment = DEPLOYMENT_DOCS.read_text(encoding="utf-8")
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        development = DEVCONTAINER_DOCS.read_text(encoding="utf-8")

        for document in (deployment, runbook, development):
            for fragment in (
                "`/var/lib/postgresql`",
                "`/var/lib/postgresql/data`",
                "`PGDATA=/var/lib/postgresql/data/pgdata`",
                "`rw,nosuid,nodev,noexec,size=1m`",
                "匿名 parent volume",
            ):
                with self.subTest(document=document[:24], fragment=fragment):
                    self.assertIn(fragment, document)

        for document in (deployment, runbook):
            self.assertIn(
                "不得把 named volume 的 target 改到 `/var/lib/postgresql`",
                document,
            )

        for fragment in (
            "隔离 v6 的唯一 build 与唯一 up 均 GREEN",
            "额外恰好 1 个 anonymous local volume",
            "db target `/var/lib/postgresql`",
            "post-create 与 MVP/Platform/Web tests 均为 0",
            "v6 topology RED",
            "desire-supply-devcontainer-audit-20260819-v7",
            "v7 source/static 20/20",
            "`compose config --quiet` 精确 exit 0",
            "top-level rendered JSON network keys",
            "project/network/volume/tag 全部 absent",
            "build=0、up=0",
            "候选未被证伪",
            "不得重跑 v7",
            "desire-supply-devcontainer-audit-20260819-v8",
            'DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v8"',
        ):
            self.assertIn(fragment, development)

    def test_docs_close_restore_network_replay_and_artifact_boundaries(self) -> None:
        deployment = DEPLOYMENT_DOCS.read_text(encoding="utf-8")
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")

        for document in (deployment, runbook):
            for fragment in (
                "DESIRE_DATABASE_RESTORE_SUBNET",
                "172.16.232.0/24",
                "全部 Docker CIDR",
                "宿主直连路由",
                "更具体路由",
                "全隧道 VPN",
                "database-restore-replay",
                "SCHEMA_READY",
                "明文",
                "recipient/KMS/tool/destination authority",
            ):
                with self.subTest(document=document[:24], fragment=fragment):
                    self.assertIn(fragment, document)
            self.assertIn("未签名 SHA-256", " ".join(document.split()))

        for fragment in (
            "docker info --format '{{ json .DefaultAddressPools }}'",
            "docker network ls -q | xargs -r docker network inspect",
            "netstat -rn",
            "ip -4 route show table all",
            'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"',
            "up -d --no-build --no-recreate database-restore-replay",
            'docker wait "$DESIRE_DATABASE_RESTORE_REPLAY_ID"',
            "logs --no-color --no-log-prefix database-restore-verify",
            "logs --no-color --no-log-prefix database-restore-replay",
            "DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP=",
            "DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY=",
            "DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY=",
            '"applied_versions":[]',
            '"iam":{"applied_versions":[0,1,2,3,4,5,6,7,8,9,10',
            '"profile":{"applied_versions":[1,2,3]',
            '"demand":{"applied_versions":[1,2,3,4,5,6,7,8,9,10]',
            '"trust":{"applied_versions":[1,2,3,4,5,6,7]',
            '"taxonomy":{"applied_versions":[1,2]',
        ):
            with self.subTest(runbook_fragment=fragment):
                self.assertIn(fragment, runbook)
        self.assertNotIn("--exit-code-from", runbook)

    def test_current_head_restore_preflight_is_fail_closed_and_self_contained(
        self,
    ) -> None:
        deployment = DEPLOYMENT_DOCS.read_text(encoding="utf-8")
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        restore = runbook.partition(
            "#### 4.8.2 当前头部隔离恢复与 replay"
        )[2].partition("### 当前应能勾选")[0]
        preflight = restore.partition(
            "# BEGIN CURRENT_HEAD_RESTORE_PREFLIGHT"
        )[2].partition("# END CURRENT_HEAD_RESTORE_PREFLIGHT")[0]
        execution = restore.partition(
            "# BEGIN CURRENT_HEAD_RESTORE_EXECUTION"
        )[2].partition("# END CURRENT_HEAD_RESTORE_EXECUTION")[0]
        postrun = restore.partition(
            "# BEGIN CURRENT_HEAD_RESTORE_POSTRUN"
        )[2].partition("# END CURRENT_HEAD_RESTORE_POSTRUN")[0]
        self.assertTrue(restore)
        self.assertTrue(preflight)
        self.assertTrue(execution)
        self.assertTrue(postrun)

        for fragment in (
            "fresh project namespace",
            "project label",
            "name prefix",
            "0700",
            "0600",
            "current UID/GID",
        ):
            with self.subTest(deployment_fragment=fragment):
                self.assertIn(fragment, deployment)

        for fragment in (
            "set -eu",
            "set -o pipefail",
            'test -z "${COMPOSE_PROJECT_NAME+x}"',
            'test -z "${COMPOSE_COMPATIBILITY+x}"',
            'export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"',
            'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill01"',
            'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"',
            'export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"',
            'DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"',
            'DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"',
            "export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID",
            'test -d "$DESIRE_DATABASE_BACKUP_DIR"',
            'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"',
            'test "$(stat -f \'%Lp|%u|%g\' "$DESIRE_DATABASE_BACKUP_DIR")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.dump"',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.facts.json"',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.sha256"',
            'test -f "$restore_artifact_path"',
            'test ! -L "$restore_artifact_path"',
            'test -s "$restore_artifact_path"',
            'test "$(stat -f \'%Lp|%u|%g|%l\' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"',
            "DESIRE_DATABASE_RESTORE_DUMP_STAT=",
            "DESIRE_DATABASE_RESTORE_FACTS_STAT=",
            "DESIRE_DATABASE_RESTORE_MANIFEST_STAT=",
            "DESIRE_DATABASE_RESTORE_SOURCE_API_ID=",
            "DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID=",
            'test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
            'DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}-"',
            'DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}_"',
            "com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT",
            "docker container ls -a --format '{{.Names}}'",
            "docker network ls --format '{{.Name}}'",
            "docker volume ls --format '{{.Name}}'",
            'awk -v prefix="$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX"',
            'awk -v prefix="$DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX"',
            'test -z "$DESIRE_DATABASE_RESTORE_COMPOSE_CONTAINER_IDS"',
            'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS"',
            'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_NETWORK_IDS"',
            'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS"',
            'test -z "$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES"',
            'test -z "$DESIRE_DATABASE_RESTORE_NETWORK_PREFIX_MATCHES"',
            'test -z "$DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES"',
        ):
            with self.subTest(preflight_fragment=fragment):
                self.assertIn(fragment, preflight)

        self.assertEqual(
            [
                line
                for line in execution.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ],
            [
                'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
                "compose_v13_restore up -d --no-build --no-recreate database-restore-replay",
                'DESIRE_DATABASE_RESTORE_REPLAY_ID="$(compose_v13_restore ps --all --quiet database-restore-replay)"',
                'test -n "$DESIRE_DATABASE_RESTORE_REPLAY_ID"',
                'test "$(docker wait "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "0"',
            ],
        )
        for fragment in (
            'compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "4"',
            'label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "4"',
            'docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
            'docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
            'DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-bootstrap)"',
            'DESIRE_DATABASE_RESTORE_VERIFY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-verify)"',
            'DESIRE_DATABASE_RESTORE_REPLAY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-replay)"',
            'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
            'test "$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")" = "$DESIRE_DATABASE_RESTORE_DUMP_STAT"',
        ):
            with self.subTest(postrun_fragment=fragment):
                self.assertIn(fragment, postrun)

        self.assertNotIn("--compatibility", restore)
        for marker in (
            "# BEGIN CURRENT_HEAD_RESTORE_PREFLIGHT",
            "# END CURRENT_HEAD_RESTORE_PREFLIGHT",
            "# BEGIN CURRENT_HEAD_RESTORE_EXECUTION",
            "# END CURRENT_HEAD_RESTORE_EXECUTION",
            "# BEGIN CURRENT_HEAD_RESTORE_POSTRUN",
            "# END CURRENT_HEAD_RESTORE_POSTRUN",
        ):
            with self.subTest(marker=marker):
                self.assertEqual(restore.count(marker), 1)

        verifier = _load_verifier()
        self.assertEqual(
            verifier._current_head_restore_runbook_failures(runbook),
            (),
        )

    def test_verifier_rejects_current_head_restore_preflight_mutations(
        self,
    ) -> None:
        verifier = _load_verifier()
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        restore_start = "#### 4.8.2 当前头部隔离恢复与 replay"
        before, marker, restore_and_after = runbook.partition(restore_start)
        self.assertEqual(marker, restore_start)

        def mutate_restore(fragment: str, replacement: str = ":") -> str:
            self.assertIn(fragment, restore_and_after)
            return before + marker + restore_and_after.replace(
                fragment,
                replacement,
                1,
            )

        self.assertEqual(
            verifier._current_head_restore_runbook_failures(runbook),
            (),
        )
        namespace_mutations = {
            "label-container-not-asserted": mutate_restore(
                'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS"'
            ),
            "label-volume-list-not-assigned": mutate_restore(
                'DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS="$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"',
                'docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT"',
            ),
            "exact-container-prefix-not-asserted": mutate_restore(
                'test -z "$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES"'
            ),
            "exact-network-list-not-assigned": mutate_restore(
                'DESIRE_DATABASE_RESTORE_ALL_NETWORK_NAMES="$(docker network ls --format \'{{.Name}}\')"',
                "docker network ls --format '{{.Name}}'",
            ),
            "exact-volume-prefix-not-asserted": mutate_restore(
                'test -z "$DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES"'
            ),
        }
        for name, mutation in namespace_mutations.items():
            with self.subTest(namespace_mutation=name):
                self.assertIn(
                    "database-restore-fresh-namespace-runbook-open",
                    verifier._current_head_restore_runbook_failures(mutation),
                )

        artifact_mutations = {
            "fail-fast-absent": mutate_restore("set -eu"),
            "pipefail-absent": mutate_restore("set -o pipefail"),
            "compose-compatibility-unset-absent": mutate_restore(
                'test -z "${COMPOSE_COMPATIBILITY+x}"'
            ),
            "restore-uid-absent": mutate_restore(
                'DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"'
            ),
            "restore-gid-absent": mutate_restore(
                'DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"'
            ),
            "leaf-symlink-check-absent": mutate_restore(
                'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"'
            ),
            "leaf-owner-mode-check-absent": mutate_restore(
                'test "$(stat -f \'%Lp|%u|%g\' "$DESIRE_DATABASE_BACKUP_DIR")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"'
            ),
            "artifact-symlink-check-absent": mutate_restore(
                'test ! -L "$restore_artifact_path"'
            ),
            "artifact-owner-mode-check-absent": mutate_restore(
                'test "$(stat -f \'%Lp|%u|%g|%l\' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"'
            ),
            "artifact-nlink-snapshot-absent": mutate_restore(
                'DESIRE_DATABASE_RESTORE_DUMP_STAT="$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")"',
                'DESIRE_DATABASE_RESTORE_DUMP_STAT="$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")"',
            ),
            "restore-project-drifted": mutate_restore(
                'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill01"',
                'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill02"',
            ),
            "restore-subnet-drifted": mutate_restore(
                'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"',
                'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.233.0/24"',
            ),
        }
        for name, mutation in artifact_mutations.items():
            with self.subTest(artifact_mutation=name):
                self.assertIn(
                    "database-restore-artifact-revalidation-runbook-open",
                    verifier._current_head_restore_runbook_failures(mutation),
                )

    def test_verifier_rejects_current_head_restore_execution_and_postrun_mutations(
        self,
    ) -> None:
        verifier = _load_verifier()
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        restore_start = "#### 4.8.2 当前头部隔离恢复与 replay"
        before, marker, restore_and_after = runbook.partition(restore_start)
        self.assertEqual(marker, restore_start)

        def mutate_restore(fragment: str, replacement: str) -> str:
            self.assertIn(fragment, restore_and_after)
            return before + marker + restore_and_after.replace(
                fragment,
                replacement,
                1,
            )

        mutations = {
            "execution-marker": (
                mutate_restore(
                    "# BEGIN CURRENT_HEAD_RESTORE_EXECUTION",
                    "# BEGIN DRIFTED_HEAD_RESTORE_EXECUTION",
                ),
                "database-restore-runbook-markers-open",
            ),
            "build-allowed": (
                mutate_restore(
                    "compose_v13_restore up -d --no-build --no-recreate database-restore-replay",
                    "compose_v13_restore up -d --no-recreate database-restore-replay",
                ),
                "database-restore-execution-runbook-open",
            ),
            "source-api-image-unbound": (
                mutate_restore(
                    'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
                    "# source API image proof removed",
                ),
                "database-restore-postrun-evidence-open",
            ),
            "container-count-drifted": (
                mutate_restore(
                    'test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "4"',
                    'test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "5"',
                ),
                "database-restore-postrun-resource-open",
            ),
            "network-count-drifted": (
                mutate_restore(
                    'test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
                    'test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "2"',
                ),
                "database-restore-postrun-resource-open",
            ),
            "volume-count-drifted": (
                mutate_restore(
                    'test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
                    'test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "2"',
                ),
                "database-restore-postrun-resource-open",
            ),
            "bootstrap-log-not-exact": (
                mutate_restore(
                    'test "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP"',
                    'printf \'%s\n\' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG" | grep -F "$DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP"',
                ),
                "database-restore-postrun-evidence-open",
            ),
        }
        for name, (mutation, failure) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(
                    failure,
                    verifier._current_head_restore_runbook_failures(mutation),
                )

        compatibility = mutate_restore(
            "  docker compose \\\n",
            "  docker compose --compatibility \\\n",
        )
        self.assertTrue(
            verifier._current_head_restore_runbook_failures(compatibility),
            "literal --compatibility must invalidate the restore runbook",
        )

    def test_docs_close_current_head_v13_source_backup_runbook(self) -> None:
        deployment = DEPLOYMENT_DOCS.read_text(encoding="utf-8")
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        source_backup = runbook.partition(
            "#### 4.8.1 当前头部 v13 源侧备份（一次性）"
        )[2].partition(
            "#### 4.8.2 当前头部隔离恢复与 replay"
        )[0]
        self.assertTrue(source_backup)

        for fragment in (
            "desire-supply-e2e-ten-account-v13",
            "desire-supply-e2e-ten-account-v13_data",
            "secrets/e2e-ten-account-v13/compose.env",
            "secrets/e2e-ten-account-v13/compose.ipam.yaml",
            "deploy/postgres-operations.compose.yaml",
            "/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01",
            "--no-recreate",
            "DATABASE_BACKUP_READY",
            "零 recreation/空库",
            "/backups/",
            "VCS 或 Docker build context",
            "不是加密或 offsite 保护",
        ):
            with self.subTest(deployment_fragment=fragment):
                self.assertIn(fragment, deployment)

        for fragment in (
            "desire-supply-e2e-ten-account-v13",
            'secrets/e2e-ten-account-v13/compose.env',
            '-f "$PWD/compose.yaml"',
            'secrets/e2e-ten-account-v13/compose.ipam.yaml',
            'deploy/postgres-operations.compose.yaml',
            "desire-supply-e2e-ten-account-v13_data",
            "postgres-data",
            'DESIRE_DATABASE_BACKUP_PARENT="$PWD/backups"',
            'DESIRE_DATABASE_BACKUP_SANDBOX_PARENT="$PWD/backups/internal-sandbox"',
            "/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01",
            "# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN",
            "# END CURRENT_HEAD_BACKUP_PARENT_CHAIN",
            'if [ -e "$backup_parent_path" ] || [ -L "$backup_parent_path" ]; then',
            'mkdir -m 0700 -- "$backup_parent_path"',
            'test -d "$backup_parent_path"',
            'test ! -L "$backup_parent_path"',
            'stat -f \'%Lp|%u|%g\' "$backup_parent_path"',
            'test ! -e "$DESIRE_DATABASE_BACKUP_DIR"',
            'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"',
            "umask 077",
            'mkdir -m 0700 -- "$DESIRE_DATABASE_BACKUP_DIR"',
            'DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"',
            'DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"',
            "export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID",
            'stat -f \'%Lp|%u|%g\'',
            "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01",
            'com.docker.compose.project',
            'com.docker.compose.service',
            'com.docker.compose.network',
            'com.docker.compose.volume',
            '{{.State.Health.Status}}',
            'SOURCE_DB_STARTED_AT',
            'SOURCE_DB_RESTART_COUNT',
            'SOURCE_DATA_NETWORK_ID',
            'NetworkSettings.Networks',
            'SOURCE_DATA_VOLUME_CREATED_AT',
            'up -d --no-deps --no-build --no-recreate database-backup',
            'ps --all --quiet database-backup',
            'docker wait "$BACKUP_CONTAINER_ID"',
            '{{.State.ExitCode}}',
            '{{.RestartCount}}',
            'logs --no-color --no-log-prefix database-backup',
            'DATABASE_BACKUP_READY',
            'grep -Fo',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.dump"',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.facts.json"',
            '"$DESIRE_DATABASE_BACKUP_BASENAME.sha256"',
            'find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1',
            "从任一 backup parent 创建或 leaf 目录创建开始",
            '项目、basename 和三份 artifact 永久锁定',
            "VCS 或 Docker build context",
            "不是加密或 offsite 保护",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source_backup)

        verifier = _load_verifier()
        self.assertEqual(
            verifier._current_head_backup_runbook_failures(runbook),
            (),
        )
        wrong_source = runbook.replace(
            "desire-supply-e2e-ten-account-v13_data",
            "desire-restore-verify-currenthead_data",
            1,
        )
        self.assertIn(
            "database-backup-source-runbook-open",
            verifier._current_head_backup_runbook_failures(wrong_source),
        )
        recreating = runbook.replace(
            "up -d --no-deps --no-build --no-recreate database-backup",
            "up -d --no-deps --no-build database-backup",
            1,
        )
        self.assertIn(
            "database-backup-source-runbook-open",
            verifier._current_head_backup_runbook_failures(recreating),
        )

        for forbidden in (
            "mkdir -p",
            "chmod -R",
            "chown -R",
            "chmod --recursive",
            "chown --recursive",
        ):
            with self.subTest(forbidden_parent_operation=forbidden):
                self.assertNotIn(forbidden, source_backup)

        gitignore = GITIGNORE.read_text(encoding="utf-8")
        dockerignore = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertEqual(gitignore.splitlines().count("/backups/"), 1)
        self.assertEqual(dockerignore.splitlines().count("/backups/"), 1)
        self.assertEqual(
            verifier._backup_artifact_exclusion_failures(
                gitignore,
                dockerignore,
            ),
            (),
        )
        ignored = subprocess.run(
            [
                "git",
                "check-ignore",
                "--no-index",
                "--quiet",
                BACKUP_ARTIFACT_RELATIVE,
            ],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(ignored.returncode, 0)

    def test_verifier_rejects_backup_parent_chain_and_ignore_mutations(
        self,
    ) -> None:
        verifier = _load_verifier()
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        gitignore = GITIGNORE.read_text(encoding="utf-8")
        dockerignore = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertEqual(
            verifier._current_head_backup_runbook_failures(runbook),
            (),
        )
        self.assertEqual(
            verifier._backup_artifact_exclusion_failures(
                gitignore,
                dockerignore,
            ),
            (),
        )

        parent_chain_start = "# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN"
        parent_chain_end = "# END CURRENT_HEAD_BACKUP_PARENT_CHAIN"
        before, marker, remainder = runbook.partition(parent_chain_start)
        self.assertEqual(marker, parent_chain_start)
        _, marker, after = remainder.partition(parent_chain_end)
        self.assertEqual(marker, parent_chain_end)
        leaf_only = before + after
        parent_mutations = {
            "leaf-only": leaf_only,
            "missing-exists-or-symlink-check": runbook.replace(
                'if [ -e "$backup_parent_path" ] || [ -L "$backup_parent_path" ]; then',
                'if [ -e "$backup_parent_path" ]; then',
                1,
            ),
            "missing-symlink-check": runbook.replace(
                'test ! -L "$backup_parent_path"',
                ":",
            ),
            "missing-owner-mode-check": runbook.replace(
                'test "$(stat -f \'%Lp|%u|%g\' "$backup_parent_path")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"',
                ":",
                1,
            ),
        }
        for name, mutation in parent_mutations.items():
            with self.subTest(parent_mutation=name):
                self.assertIn(
                    "database-backup-source-runbook-open",
                    verifier._current_head_backup_runbook_failures(mutation),
                )

        ignore_mutations = {
            "git-absent": (gitignore.replace("/backups/\n", "", 1), dockerignore),
            "git-unanchored": (
                gitignore.replace("/backups/", "backups/", 1),
                dockerignore,
            ),
            "docker-absent": (
                gitignore,
                dockerignore.replace("/backups/\n", "", 1),
            ),
            "docker-unanchored": (
                gitignore,
                dockerignore.replace("/backups/", "backups/", 1),
            ),
        }
        for name, (git_mutation, docker_mutation) in ignore_mutations.items():
            with self.subTest(ignore_mutation=name):
                self.assertTrue(
                    verifier._backup_artifact_exclusion_failures(
                        git_mutation,
                        docker_mutation,
                    )
                )

    def test_verifier_rejects_current_head_backup_proof_weakening(
        self,
    ) -> None:
        verifier = _load_verifier()
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        self.assertEqual(
            verifier._current_head_backup_runbook_failures(runbook),
            (),
        )

        start_marker = "# BEGIN CURRENT_HEAD_V13_BACKUP"
        end_marker = "# END CURRENT_HEAD_V13_BACKUP"
        before, found_start, remainder = runbook.partition(start_marker)
        backup, found_end, after = remainder.partition(end_marker)
        self.assertEqual(found_start, start_marker)
        self.assertEqual(found_end, end_marker)

        def mutate_backup(old: str, new: str) -> str:
            self.assertEqual(
                backup.count(old),
                1,
                f"backup mutation target must be unique: {old}",
            )
            return (
                before
                + found_start
                + backup.replace(old, new, 1)
                + found_end
                + after
            )

        api_identity = (
            'test "$(docker inspect --format \'{{ index .Config.Labels '
            '"com.docker.compose.project" }}|{{ index .Config.Labels '
            '"com.docker.compose.service" }}\' "$SOURCE_API_CONTAINER_ID")" '
            '= "$DESIRE_DATABASE_SOURCE_PROJECT|api"'
        )
        api_image_capture = (
            'SOURCE_API_IMAGE_ID="$(docker inspect --format '
            "'{{.Image}}' \"$SOURCE_API_CONTAINER_ID\")\""
        )
        api_image_postcondition = (
            'test "$(docker inspect --format \'{{.Image}}\' '
            '"$SOURCE_API_CONTAINER_ID")" = "$SOURCE_API_IMAGE_ID"'
        )
        exact_backup_name = (
            'BACKUP_EXISTING_NAME_MATCHES="$(docker container ls -a '
            "--format '{{.Names}}' | awk -v "
            'expected="${DESIRE_DATABASE_SOURCE_PROJECT}-database-backup-1" '
            "'$0 == expected { print }')\""
        )
        exact_backup_log = (
            'test "$BACKUP_LOG" = '
            "'{\"artifact\":\"v13-iam37-profile3-demand10-trust7-taxonomy2-"
            "drill01\",\"status\":\"DATABASE_BACKUP_READY\"}'"
        )
        artifact_identity = (
            'test "$(stat -f \'%Lp|%u|%g|%l\' "$backup_artifact_path")" '
            '= "600|$DESIRE_DATABASE_OPERATIONS_UID|'
            '$DESIRE_DATABASE_OPERATIONS_GID|1"'
        )
        proof_mutations = {
            "pipefail-absent": mutate_backup("set -o pipefail", ":"),
            "literal-compose-compatibility": mutate_backup(
                "  docker compose \\\n",
                "  docker compose \\\n    --compatibility \\\n",
            ),
            "backup-name-match-is-not-exact": mutate_backup(
                exact_backup_name,
                exact_backup_name.replace("$0 == expected", "$0 ~ expected"),
            ),
            "source-api-label-identity-absent": mutate_backup(
                api_identity,
                'test -n "$SOURCE_API_CONTAINER_ID"',
            ),
            "source-api-compose-identity-absent": mutate_backup(
                'test "$(compose_v13_backup ps --all --quiet api)" '
                '= "$SOURCE_API_CONTAINER_ID"',
                'test -n "$SOURCE_API_CONTAINER_ID"',
            ),
            "source-api-image-captured-from-db": mutate_backup(
                api_image_capture,
                api_image_capture.replace(
                    "$SOURCE_API_CONTAINER_ID",
                    "$SOURCE_DB_CONTAINER_ID",
                ),
            ),
            "source-api-image-postcondition-absent": mutate_backup(
                api_image_postcondition,
                'test -n "$SOURCE_API_IMAGE_ID"',
            ),
            "backup-log-allows-extra-output": mutate_backup(
                exact_backup_log,
                'printf \'%s\\n\' "$BACKUP_LOG" | grep -F '
                "'\"status\":\"DATABASE_BACKUP_READY\"'",
            ),
            "artifact-hardlink-count-absent": mutate_backup(
                artifact_identity,
                artifact_identity.replace("%Lp|%u|%g|%l", "%Lp|%u|%g")
                .replace("$DESIRE_DATABASE_OPERATIONS_GID|1", "$DESIRE_DATABASE_OPERATIONS_GID"),
            ),
        }
        for name, mutation in proof_mutations.items():
            with self.subTest(proof_mutation=name):
                self.assertIn(
                    "database-backup-source-runbook-open",
                    verifier._current_head_backup_runbook_failures(mutation),
                )

        unset_variables = (
            "COMPOSE_COMPATIBILITY",
            "DESIRE_DB_PASSWORD_FILE",
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE",
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE",
            "DESIRE_IDENTITY_SOURCE_DIR",
            "DESIRE_INTERNAL_SANDBOX_TLS_DIR",
            "DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR",
        )
        for variable in unset_variables:
            mutation = mutate_backup(
                f'test -z "${{{variable}+x}}"',
                f'test -z "${{{variable}:-}}"',
            )
            with self.subTest(weakened_unset_guard=variable):
                self.assertIn(
                    "database-backup-source-runbook-open",
                    verifier._current_head_backup_runbook_failures(mutation),
                )

    def test_verifier_requires_current_head_source_backup_runbook(self) -> None:
        verifier = _load_verifier()
        runbook = RUNBOOK_DOCS.read_text(encoding="utf-8")
        self.assertEqual(
            verifier._current_head_backup_runbook_failures(runbook),
            (),
        )

    def test_devcontainer_has_no_docker_daemon_or_implicit_ops_profile(self) -> None:
        devcontainer = json.loads(
            (ROOT / ".devcontainer" / "devcontainer.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(devcontainer["runServices"]), {"db", "devcontainer"})
        self.assertNotIn("docker.sock", json.dumps(devcontainer))

        completed = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                "compose.yaml",
                "-f",
                "compose.dev.yaml",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        development = json.loads(completed.stdout)["services"]["devcontainer"]
        self.assertNotIn("docker.sock", json.dumps(development.get("volumes", [])))


if __name__ == "__main__":
    unittest.main()
