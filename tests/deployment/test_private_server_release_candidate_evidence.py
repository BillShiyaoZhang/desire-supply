"""Closed contracts for private-server release-candidate evidence v1."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "private_server_release_candidate_evidence.py"
SCHEMA_PATH = (
    ROOT / "deploy" / "private-server-release-candidate-evidence-v1.schema.json"
)
RUNBOOK_PATH = ROOT / "docs" / "operations" / "private-server-internal-sandbox.md"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "private_server_release_candidate_evidence",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("release-candidate evidence module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EVIDENCE = _load_module()
NOW = "2026-08-24T12:00:00Z"
SNAPSHOT = "a" * 64
EVIDENCE_SHA = "b" * 64
FROZEN_V13_ASSETS = {
    "IAM_MANIFEST": (
        ROOT
        / "tests/deployment/fixtures/current-head-v13/iam-manifest.json"
    ),
    "TRUST_MANIFEST": (
        ROOT
        / "tests/deployment/fixtures/current-head-v13/trust-manifest.json"
    ),
    "DEMAND_MANIFEST": (
        ROOT
        / "tests/deployment/fixtures/current-head-v13/demand-manifest.json"
    ),
    "TRUST_OPENAPI": (
        ROOT
        / "tests/deployment/fixtures/current-head-v13/trust-v1.openapi.yaml"
    ),
}


def _pending_document() -> dict:
    return {
        "schema_version": EVIDENCE.SCHEMA_VERSION,
        "candidate_id": "current-head-v13-rc-pending-example",
        "created_at": NOW,
        "candidate_scope": "RUN_CURRENT_HEAD_V13_ONCE",
        "environment": "INTERNAL_SANDBOX",
        "data_scope": "synthetic_only",
        "production_authorized": False,
        "approval_boundary": "SEPARATE_HUMAN_APPROVAL_ARTIFACT_REQUIRED",
        "source_snapshot": {
            "kind": "SOURCE_ARCHIVE_SHA256",
            "status": "PENDING",
            "snapshot_sha256": None,
            "verification_artifact_sha256": None,
            "verified_at": None,
        },
        "frozen_assets": [
            {
                "asset_id": asset_id,
                "path": path,
                "expected_sha256": expected,
                "observed_sha256": None,
                "source_snapshot_sha256": None,
                "status": "PENDING",
            }
            for asset_id, path, expected in EVIDENCE.FROZEN_ASSETS
        ],
        "docker_hub_manifest_gate": {
            "gate_id": "DOCKER_HUB_PRODUCTION_MANIFESTS_V1",
            "rounds_required": 3,
            "references_per_round": 5,
            "checks_required": 15,
            "checks_passed": 0,
            "references": list(EVIDENCE.DOCKER_REFERENCES),
            "status": "PENDING",
            "source_snapshot_sha256": None,
            "evidence_sha256": None,
            "completed_at": None,
        },
        "test_runs": [
            {
                "check_id": check_id,
                "status": "PENDING",
                "passed_count": None,
                "failed_count": None,
                "skipped_count": None,
                "source_snapshot_sha256": None,
                "evidence_sha256": None,
                "completed_at": None,
            }
            for check_id in EVIDENCE.TEST_RUN_IDS
        ],
        "quality_checks": [
            {
                "check_id": check_id,
                "status": "PENDING",
                "source_snapshot_sha256": None,
                "evidence_sha256": None,
                "completed_at": None,
            }
            for check_id in EVIDENCE.QUALITY_CHECK_IDS
        ],
        "trust8_applicant_discovery": {
            "implementation_status": "DEFERRED_NOT_IMPLEMENTED",
            "boundary": "FROZEN_TRUST7_BOUNDARY",
            "accepted_for_candidate_scope": False,
            "acceptance_record_sha256": None,
            "source_snapshot_sha256": None,
        },
        "one_shot_v13": {
            "claim": "NOT_VERIFIED",
            "checks": {
                check_id: "NOT_VERIFIED"
                for check_id in EVIDENCE.ONE_SHOT_CHECK_IDS
            },
            "source_snapshot_sha256": None,
            "verification_artifact_sha256": None,
            "verified_at": None,
        },
        "overall_status": "BLOCKED",
        "blocking_reasons": list(EVIDENCE.BLOCKING_REASONS),
    }


def _all_caller_claims_passed_document() -> dict:
    document = _pending_document()
    document["candidate_id"] = "current-head-v13-rc-all-claims-passed-example"
    document["source_snapshot"] = {
        "kind": "SOURCE_ARCHIVE_SHA256",
        "status": "VERIFIED",
        "snapshot_sha256": SNAPSHOT,
        "verification_artifact_sha256": EVIDENCE_SHA,
        "verified_at": NOW,
    }
    for item in document["frozen_assets"]:
        item["status"] = "VERIFIED"
        item["observed_sha256"] = item["expected_sha256"]
        item["source_snapshot_sha256"] = SNAPSHOT
    document["docker_hub_manifest_gate"].update(
        {
            "checks_passed": 15,
            "status": "PASSED",
            "source_snapshot_sha256": SNAPSHOT,
            "evidence_sha256": EVIDENCE_SHA,
            "completed_at": NOW,
        }
    )
    for index, run in enumerate(document["test_runs"], start=1):
        run.update(
            {
                "status": "PASSED",
                "passed_count": index,
                "failed_count": 0,
                "skipped_count": 0,
                "source_snapshot_sha256": SNAPSHOT,
                "evidence_sha256": EVIDENCE_SHA,
                "completed_at": NOW,
            }
        )
    for check in document["quality_checks"]:
        check.update(
            {
                "status": "PASSED",
                "source_snapshot_sha256": SNAPSHOT,
                "evidence_sha256": EVIDENCE_SHA,
                "completed_at": NOW,
            }
        )
    document["trust8_applicant_discovery"].update(
        {
            "accepted_for_candidate_scope": True,
            "acceptance_record_sha256": EVIDENCE_SHA,
            "source_snapshot_sha256": SNAPSHOT,
        }
    )
    document["one_shot_v13"] = {
        "claim": "UNCONSUMED_VERIFIED",
        "checks": {
            check_id: "ABSENT_VERIFIED"
            for check_id in EVIDENCE.ONE_SHOT_CHECK_IDS
        },
        "source_snapshot_sha256": SNAPSHOT,
        "verification_artifact_sha256": EVIDENCE_SHA,
        "verified_at": NOW,
    }
    document["overall_status"] = "BLOCKED"
    document["blocking_reasons"] = ["EVIDENCE_PROVENANCE_NOT_VERIFIED"]
    return document


def _write_input(path: Path, document: dict, *, canonical: bool = False) -> None:
    if canonical:
        raw = EVIDENCE._canonical_bytes(document)
    else:
        raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    path.chmod(0o600)


class PrivateServerReleaseCandidateEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.root.chmod(0o700)
        self.input_path = self.root / "candidate-input.json"
        self.output_path = self.root / "candidate-output.json"
        self.original_repository_root = EVIDENCE.REPOSITORY_ROOT
        self.v13_repository_root = self.root / "v13-source-snapshot"
        for asset_id, relative_path, _expected in EVIDENCE.FROZEN_ASSETS:
            source = FROZEN_V13_ASSETS.get(
                asset_id,
                ROOT / relative_path,
            )
            target = self.v13_repository_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        for relative_path in ("Dockerfile", "compose.yaml"):
            target = self.v13_repository_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative_path).read_bytes())
        EVIDENCE.REPOSITORY_ROOT = self.v13_repository_root

    def tearDown(self) -> None:
        EVIDENCE.REPOSITORY_ROOT = self.original_repository_root
        self.temporary.cleanup()

    def assertInvalid(self, document: dict) -> None:  # noqa: N802
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.validate_release_candidate_evidence(document)

    def test_schema_is_closed_and_cannot_represent_approval_or_production(self) -> None:
        schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
        script_text = SCRIPT_PATH.read_text(encoding="utf-8")
        schema = json.loads(schema_text)
        properties = schema["properties"]

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            properties["candidate_scope"]["const"],
            "RUN_CURRENT_HEAD_V13_ONCE",
        )
        self.assertEqual(properties["environment"]["const"], "INTERNAL_SANDBOX")
        self.assertEqual(properties["data_scope"]["const"], "synthetic_only")
        self.assertIs(properties["production_authorized"]["const"], False)
        self.assertEqual(properties["overall_status"]["const"], "BLOCKED")
        self.assertEqual(
            properties["blocking_reasons"]["contains"]["const"],
            "EVIDENCE_PROVENANCE_NOT_VERIFIED",
        )
        self.assertNotIn("approval", properties)
        self.assertNotIn('"APPROVED"', schema_text)
        self.assertNotIn("READY_FOR_HUMAN_APPROVAL", schema_text)
        self.assertNotIn("READY_FOR_HUMAN_APPROVAL", script_text)
        self.assertNotIn("APPROVED", script_text)
        self.assertEqual(len(schema["$defs"]["FrozenAssets"]["prefixItems"]), 7)
        self.assertEqual(len(schema["$defs"]["DockerReferences"]["prefixItems"]), 5)

    def test_runbook_keeps_candidate_and_private_activation_authority_separate(self) -> None:
        runbook = RUNBOOK_PATH.read_text(encoding="utf-8")

        for marker in (
            "RUN_CURRENT_HEAD_V13_ONCE",
            "production_authorized=false",
            '"claim":"NOT_VERIFIED"',
            '"overall_status":"BLOCKED"',
            "EVIDENCE_PROVENANCE_NOT_VERIFIED",
            "永久 fail-closed",
            "未验证的 caller claim",
            "任何下游都不得",
            "受保护 receipts",
            "live absence",
            "人工批准必须是独立 artifact",
            "不授权本页后续的非 v13 私服激活",
            "仓库当前不生成候选实例",
        ):
            self.assertIn(marker, runbook)

    def test_pending_example_is_valid_but_remains_blocked(self) -> None:
        document = _pending_document()

        self.assertEqual(
            EVIDENCE.validate_release_candidate_evidence(document),
            "BLOCKED",
        )

        legacy_ready = deepcopy(document)
        legacy_ready["overall_status"] = "READY_FOR_HUMAN_APPROVAL"
        legacy_ready["blocking_reasons"] = []
        self.assertInvalid(legacy_ready)

        _write_input(self.input_path, legacy_ready, canonical=True)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.verify_release_candidate_evidence(self.input_path)

    def test_all_caller_subclaims_passed_still_has_provenance_blocker(self) -> None:
        document = _all_caller_claims_passed_document()

        self.assertEqual(
            EVIDENCE.validate_release_candidate_evidence(document),
            "BLOCKED",
        )
        self.assertEqual(
            document["blocking_reasons"],
            ["EVIDENCE_PROVENANCE_NOT_VERIFIED"],
        )
        self.assertEqual(
            document["approval_boundary"],
            "SEPARATE_HUMAN_APPROVAL_ARTIFACT_REQUIRED",
        )
        self.assertNotIn("approval", document)

        missing_provenance = deepcopy(document)
        missing_provenance["blocking_reasons"] = []
        self.assertInvalid(missing_provenance)

    def test_v1_reports_current_appended_manifests_as_honest_mismatches(self) -> None:
        document = _all_caller_claims_passed_document()
        for item in document["frozen_assets"]:
            if item["asset_id"] not in FROZEN_V13_ASSETS:
                continue
            item["status"] = "MISMATCH"
            item["observed_sha256"] = hashlib.sha256(
                (ROOT / item["path"]).read_bytes()
            ).hexdigest()
        document["blocking_reasons"] = [
            "EVIDENCE_PROVENANCE_NOT_VERIFIED",
            "FROZEN_ASSET_NOT_VERIFIED",
        ]
        EVIDENCE.REPOSITORY_ROOT = ROOT
        try:
            self.assertEqual(
                EVIDENCE.validate_release_candidate_evidence(document),
                "BLOCKED",
            )
        finally:
            EVIDENCE.REPOSITORY_ROOT = self.v13_repository_root

    def test_every_pending_failed_mismatch_or_unaccepted_gate_adds_blocker(self) -> None:
        cases = []

        source = _all_caller_claims_passed_document()
        source["source_snapshot"]["status"] = "MISMATCH"
        cases.append((source, "SOURCE_SNAPSHOT_NOT_VERIFIED"))

        frozen = _all_caller_claims_passed_document()
        frozen["frozen_assets"][0].update(
            {"status": "PENDING", "observed_sha256": None, "source_snapshot_sha256": None}
        )
        cases.append((frozen, "FROZEN_ASSET_NOT_VERIFIED"))

        docker = _all_caller_claims_passed_document()
        docker["docker_hub_manifest_gate"]["status"] = "FAILED"
        docker["docker_hub_manifest_gate"]["checks_passed"] = 14
        cases.append((docker, "DOCKER_HUB_MANIFEST_GATE_NOT_PASSED"))

        test_run = _all_caller_claims_passed_document()
        test_run["test_runs"][0].update(
            {"status": "FAILED", "passed_count": 0, "failed_count": 1}
        )
        cases.append((test_run, "TEST_RUN_NOT_PASSED"))

        quality = _all_caller_claims_passed_document()
        quality["quality_checks"][0]["status"] = "MISMATCH"
        cases.append((quality, "QUALITY_CHECK_NOT_PASSED"))

        trust8 = _all_caller_claims_passed_document()
        trust8["trust8_applicant_discovery"].update(
            {
                "accepted_for_candidate_scope": False,
                "acceptance_record_sha256": None,
                "source_snapshot_sha256": None,
            }
        )
        cases.append((trust8, "TRUST8_DEFERRAL_NOT_ACCEPTED"))

        one_shot = _all_caller_claims_passed_document()
        one_shot["one_shot_v13"]["claim"] = "NOT_VERIFIED"
        one_shot["one_shot_v13"]["checks"]["input_root"] = "NOT_VERIFIED"
        cases.append((one_shot, "ONE_SHOT_V13_NOT_UNCONSUMED_VERIFIED"))

        for document, reason in cases:
            with self.subTest(reason=reason):
                document["blocking_reasons"] = [
                    "EVIDENCE_PROVENANCE_NOT_VERIFIED",
                    reason,
                ]
                self.assertEqual(
                    EVIDENCE.validate_release_candidate_evidence(document),
                    "BLOCKED",
                )

    def test_snapshot_bindings_frozen_bytes_and_pins_fail_closed(self) -> None:
        binding = _all_caller_claims_passed_document()
        binding["quality_checks"][0]["source_snapshot_sha256"] = "c" * 64
        self.assertInvalid(binding)

        frozen = _all_caller_claims_passed_document()
        frozen["frozen_assets"][0]["observed_sha256"] = "c" * 64
        self.assertInvalid(frozen)

        pin = _all_caller_claims_passed_document()
        pin["docker_hub_manifest_gate"]["references"][0] = (
            pin["docker_hub_manifest_gate"]["references"][0][:-1] + "0"
        )
        self.assertInvalid(pin)

        extra = _all_caller_claims_passed_document()
        extra["approval"] = {"status": "APPROVED"}
        self.assertInvalid(extra)

    def test_partial_one_shot_absence_stays_not_verified_and_needs_evidence(self) -> None:
        document = _pending_document()
        document["source_snapshot"] = {
            "kind": "SOURCE_ARCHIVE_SHA256",
            "status": "VERIFIED",
            "snapshot_sha256": SNAPSHOT,
            "verification_artifact_sha256": EVIDENCE_SHA,
            "verified_at": NOW,
        }
        document["one_shot_v13"]["checks"][
            "primary_project_namespace"
        ] = "ABSENT_VERIFIED"
        document["one_shot_v13"].update(
            {
                "source_snapshot_sha256": SNAPSHOT,
                "verification_artifact_sha256": EVIDENCE_SHA,
                "verified_at": NOW,
            }
        )
        document["blocking_reasons"].remove("SOURCE_SNAPSHOT_NOT_VERIFIED")

        self.assertEqual(
            EVIDENCE.validate_release_candidate_evidence(document),
            "BLOCKED",
        )
        document["one_shot_v13"]["claim"] = "UNCONSUMED_VERIFIED"
        self.assertInvalid(document)

    def test_generate_writes_new_canonical_0600_file_and_verify_is_read_only(self) -> None:
        _write_input(self.input_path, _pending_document())

        overall = EVIDENCE.generate_release_candidate_evidence(
            self.input_path,
            self.output_path,
        )

        self.assertEqual(overall, "BLOCKED")
        output_stat = self.output_path.stat()
        self.assertEqual(stat.S_IMODE(output_stat.st_mode), 0o600)
        self.assertEqual(output_stat.st_nlink, 1)
        self.assertEqual(
            self.output_path.read_bytes(),
            EVIDENCE._canonical_bytes(_pending_document()),
        )
        before = self.output_path.stat()
        self.assertEqual(
            EVIDENCE.verify_release_candidate_evidence(self.output_path),
            "BLOCKED",
        )
        after = self.output_path.stat()
        self.assertEqual(
            (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ino),
            (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ino),
        )

    def test_no_overwrite_no_symlink_no_hardlink_and_safe_parent(self) -> None:
        _write_input(self.input_path, _pending_document())

        self.output_path.write_bytes(b"preserve\n")
        self.output_path.chmod(0o600)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.generate_release_candidate_evidence(
                self.input_path,
                self.output_path,
            )
        self.assertEqual(self.output_path.read_bytes(), b"preserve\n")

        self.output_path.unlink()
        target = self.root / "target.json"
        target.write_bytes(b"preserve target\n")
        target.chmod(0o600)
        self.output_path.symlink_to(target)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.generate_release_candidate_evidence(
                self.input_path,
                self.output_path,
            )
        self.assertEqual(target.read_bytes(), b"preserve target\n")

        self.output_path.unlink()
        linked_input = self.root / "linked-input.json"
        os.link(self.input_path, linked_input)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.generate_release_candidate_evidence(
                linked_input,
                self.output_path,
            )

        linked_input.unlink()
        self.root.chmod(0o755)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.generate_release_candidate_evidence(
                self.input_path,
                self.output_path,
            )
        self.assertFalse(self.output_path.exists())

    def test_verify_rejects_noncanonical_or_duplicate_json(self) -> None:
        _write_input(self.input_path, _pending_document(), canonical=False)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.verify_release_candidate_evidence(self.input_path)

        duplicate = EVIDENCE._canonical_bytes(_pending_document()).replace(
            b'{"approval_boundary":',
            b'{"schema_version":"duplicate","approval_boundary":',
            1,
        )
        self.input_path.write_bytes(duplicate)
        self.input_path.chmod(0o600)
        with self.assertRaises(EVIDENCE.ReleaseCandidateEvidenceError):
            EVIDENCE.verify_release_candidate_evidence(self.input_path)

    def test_cli_is_stable_and_never_reports_approved(self) -> None:
        _write_input(self.input_path, _pending_document())
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = EVIDENCE.main(
                (
                    "generate",
                    "--input",
                    str(self.input_path),
                    "--output",
                    str(self.output_path),
                )
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "overall_status": "BLOCKED",
                "status": EVIDENCE.WRITTEN_STATUS,
            },
        )
        self.assertNotIn("APPROVED", stdout.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = EVIDENCE.main(("generate", "--output", "secret"))
        self.assertEqual(exit_code, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {"code": EVIDENCE.ERROR_CODE, "status": "BLOCKED"},
        )
        self.assertNotIn("secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
