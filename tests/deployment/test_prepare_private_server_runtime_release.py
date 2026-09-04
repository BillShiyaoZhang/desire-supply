"""Offline tests for the closed private-server runtime release bundle."""

from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tests.deployment import test_fetch_pinned_postgres_release_evidence as FETCH_TEST
from tests.deployment import test_private_server_runtime_release as RELEASE_TEST


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "prepare_private_server_runtime_release.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "test_prepare_private_server_runtime_release_contract", SCRIPT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("bundle helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PREPARE = _load_module()

COMMIT = "a" * 40
RUN_ID = "424242"
RUN_ATTEMPT = "3"
ARCHITECTURE = "amd64"
IMAGE_TAG = f"sha-{COMMIT}-{ARCHITECTURE}-r{RUN_ID}-a{RUN_ATTEMPT}"


def _write(path: Path, raw: bytes, mode: int) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def _app_archive(slot: str) -> bytes:
    materials = RELEASE_TEST.APP_MATERIALS[slot]
    wrapper = json.loads(materials["layout_index"])
    wrapper["manifests"][0]["annotations"] = {
        "io.containerd.image.name": (
            f"docker.io/library/{PREPARE.REPOSITORIES[slot]}:{IMAGE_TAG}"
        ),
        "org.opencontainers.image.ref.name": IMAGE_TAG,
    }
    return RELEASE_TEST._rewrite_oci_archive(
        materials["archive"],
        {"index.json": RELEASE_TEST._canonical(wrapper)},
    )


def _source_facts(snapshot: bytes, dockerfile_set: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:") as archive:
        member_count = len(archive.getmembers())
    return RELEASE_TEST._canonical(
        {
            "commit": COMMIT,
            "dockerfile_digest_set": {
                "sha256": hashlib.sha256(dockerfile_set).hexdigest(),
                "size": len(dockerfile_set),
            },
            "format": PREPARE.SOURCE_FACTS_FORMAT,
            "snapshot": {
                "member_count": member_count,
                "sha256": hashlib.sha256(snapshot).hexdigest(),
                "size": len(snapshot),
            },
            "tree_sha256": "b" * 64,
        }
    )


class _Inputs:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / "source"
        self.images = self.root / "images"
        self.outputs = self.root / "outputs"
        for directory in (self.source, self.images, self.outputs):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self.snapshot = _write(
            self.source / "source-snapshot.tar",
            RELEASE_TEST.SOURCE_SNAPSHOT,
            0o400,
        )
        self.dockerfile_set = _write(
            self.source / "dockerfile-digest-set.json",
            RELEASE_TEST.DOCKERFILE_DIGEST_SET,
            0o400,
        )
        self.facts = _write(
            self.source / "source-facts.json",
            _source_facts(
                RELEASE_TEST.SOURCE_SNAPSHOT,
                RELEASE_TEST.DOCKERFILE_DIGEST_SET,
            ),
            0o600,
        )
        for slot, name in PREPARE.APP_ARCHIVE_FILES.items():
            _write(self.images / name, _app_archive(slot), 0o400)

        self.postgres_fixture = FETCH_TEST._Fixture()
        registry = FETCH_TEST._Registry(self.postgres_fixture)
        self.postgres = self.root / "postgres"
        with (
            patch.object(
                FETCH_TEST.FETCHER,
                "ROOT_INDEX_DIGEST",
                self.postgres_fixture.root_digest,
            ),
            patch.object(
                FETCH_TEST.FETCHER,
                "PINNED_PLATFORM_GRAPHS",
                self.postgres_fixture.graphs,
            ),
            patch.object(
                FETCH_TEST.FETCHER,
                "DockerHubEvidenceTransport",
                return_value=registry,
            ),
        ):
            FETCH_TEST.FETCHER.fetch_pinned_postgres_release_evidence(
                ARCHITECTURE, self.postgres
            )

    def contract(self) -> ExitStack:
        stack = ExitStack()
        root_digest = self.postgres_fixture.root_digest
        stack.enter_context(patch.object(PREPARE, "POSTGRES_ROOT_DIGEST", root_digest))
        stack.enter_context(
            patch.object(PREPARE.RELEASE, "POSTGRES_ROOT_INDEX_DIGEST", root_digest)
        )
        stack.enter_context(
            patch.object(
                PREPARE.RELEASE,
                "POSTGRES_REFERENCE",
                f"postgres:18.4-alpine@{root_digest}",
            )
        )
        return stack

    def output(self, name: str = "release.tar") -> Path:
        directory = self.outputs / name.removesuffix(".tar")
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        return directory / name

    def prepare(self, output: Path):
        return PREPARE.prepare_runtime_release(
            architecture=ARCHITECTURE,
            commit=COMMIT,
            run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT,
            source_snapshot=self.snapshot,
            source_dockerfile_set=self.dockerfile_set,
            source_facts=self.facts,
            images_directory=self.images,
            postgres_directory=self.postgres,
            output=output,
        )

    def close(self) -> None:
        self.temporary.cleanup()


def _repack(
    raw: bytes,
    *,
    mutate_name: str | None = None,
    mutate_content=None,
    mutate_mode: int | None = None,
    extra: bool = False,
    duplicate: bool = False,
    tar_format: int = tarfile.USTAR_FORMAT,
) -> bytes:
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        for member in source.getmembers():
            content = None
            if member.isfile():
                stream = source.extractfile(member)
                if stream is None:
                    raise AssertionError("fixture member unreadable")
                content = stream.read()
                if member.name == mutate_name and mutate_content is not None:
                    content = mutate_content(content)
            clone = tarfile.TarInfo(member.name)
            clone.type = member.type
            clone.mode = (
                mutate_mode
                if member.name == mutate_name and mutate_mode is not None
                else member.mode
            )
            clone.uid = member.uid
            clone.gid = member.gid
            clone.uname = member.uname
            clone.gname = member.gname
            clone.mtime = member.mtime
            clone.devmajor = member.devmajor
            clone.devminor = member.devminor
            clone.size = 0 if content is None else len(content)
            entries.append((clone, content))
    if duplicate:
        original, content = entries[-1]
        clone = tarfile.TarInfo(original.name)
        clone.type = original.type
        clone.mode = original.mode
        clone.uid = clone.gid = clone.mtime = 0
        clone.size = 0 if content is None else len(content)
        entries.append((clone, content))
    if extra:
        info = tarfile.TarInfo("unexpected.txt")
        info.mode = 0o400
        info.uid = info.gid = info.mtime = 0
        info.size = 1
        entries.append((info, b"x"))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tar_format) as archive:
        for info, content in entries:
            archive.addfile(info, None if content is None else io.BytesIO(content))
    return output.getvalue()


class PreparePrivateServerRuntimeReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs = _Inputs()

    def tearDown(self) -> None:
        self.inputs.close()

    def test_success_is_closed_canonical_and_fully_verifiable(self) -> None:
        output = self.inputs.output()
        with self.inputs.contract():
            result = self.inputs.prepare(output)
            verified = PREPARE.verify_bundle(output)
        self.assertEqual(result, verified)
        self.assertEqual(result.release_id, f"runtime-release-{IMAGE_TAG}")
        self.assertEqual(result.image_tag, IMAGE_TAG)
        self.assertEqual(result.architecture, ARCHITECTURE)
        self.assertEqual(
            dict(result.image_config_digests),
            {
                slot: RELEASE_TEST.APP_MATERIALS[slot]["config_digest"]
                for slot in PREPARE.APP_SLOTS
            },
        )
        self.assertFalse(result.execution_permitted)
        self.assertFalse(result.production_authorized)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o400)
        self.assertEqual(result.bundle_sha256, hashlib.sha256(output.read_bytes()).hexdigest())
        with tarfile.open(output, mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual(
                tuple(item.name for item in members), PREPARE.EXPECTED_MEMBERS
            )
            for member in members:
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.mtime, 0)
                self.assertEqual(
                    member.mode,
                    0o700 if member.name in PREPARE.DIRECTORY_MEMBERS else 0o400,
                )
            self.assertNotIn("source/source-facts.json", archive.getnames())
            self.assertNotIn("postgres/evidence.json", archive.getnames())
            release_stream = archive.extractfile("release.json")
            self.assertIsNotNone(release_stream)
            schema_heads = json.loads(release_stream.read())["schema_heads"]
            self.assertEqual(schema_heads["iam"], 46)
            self.assertEqual(schema_heads["profile"], 5)
            self.assertEqual(schema_heads["demand"], 15)
            self.assertEqual(schema_heads["trust"], 22)
            self.assertEqual(schema_heads["matching"], 9)
            for slot in PREPARE.APP_SLOTS:
                for kind in ("sbom", "provenance"):
                    member = archive.getmember(
                        f"attestations/{slot}/{kind}.intoto.json"
                    )
                    stream = archive.extractfile(member)
                    self.assertIsNotNone(stream)
                    self.assertEqual(
                        stream.read(), RELEASE_TEST.APP_MATERIALS[slot][kind]
                    )

    def test_same_inputs_produce_identical_ustar_bytes(self) -> None:
        first = self.inputs.output("first.tar")
        second = self.inputs.output("second.tar")
        with self.inputs.contract():
            first_result = self.inputs.prepare(first)
            second_result = self.inputs.prepare(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result.bundle_sha256, second_result.bundle_sha256)

    def test_prepare_rejects_nonterminal_inner_oci_archive_bytes(self) -> None:
        archive = self.inputs.images / PREPARE.APP_ARCHIVE_FILES["platform"]
        original = archive.read_bytes()
        mutations = {
            "concatenated-second-tar": original + original,
            "nonzero-after-terminal": original + b"nonzero" + b"\x00" * 505,
            "nonzero-member-padding": RELEASE_TEST._nonzero_member_padding(
                original, "oci-layout"
            ),
        }
        for index, (name, raw) in enumerate(mutations.items()):
            archive.chmod(0o600)
            archive.write_bytes(raw)
            archive.chmod(0o400)
            with (
                self.subTest(name=name),
                self.inputs.contract(),
                self.assertRaisesRegex(
                    PREPARE.RuntimeReleaseBundleError,
                    f"^{PREPARE.ERROR_CODE}$",
                ),
            ):
                self.inputs.prepare(self.inputs.output(f"bad-inner-{index}.tar"))
        archive.chmod(0o600)
        archive.write_bytes(original)
        archive.chmod(0o400)

    def test_bundle_rejects_content_extra_duplicate_mode_and_trailing_tamper(self) -> None:
        original = self.inputs.output("original.tar")
        with self.inputs.contract():
            self.inputs.prepare(original)
        mutations = {
            "content": _repack(
                original.read_bytes(),
                mutate_name="README.txt",
                mutate_content=lambda raw: raw + b"tampered\n",
            ),
            "bound-image": _repack(
                original.read_bytes(),
                mutate_name="images/platform.oci.tar",
                mutate_content=lambda raw: raw + b"tampered",
            ),
            "extra": _repack(original.read_bytes(), extra=True),
            "duplicate": _repack(original.read_bytes(), duplicate=True),
            "mode": _repack(
                original.read_bytes(), mutate_name="README.txt", mutate_mode=0o444
            ),
            "trailing": original.read_bytes() + b"not-zero" + b"\x00" * 504,
            "concatenated": original.read_bytes() + original.read_bytes(),
            "hidden-gnu-offset": (
                RELEASE_TEST._gnu_long_name_prefix("README.txt")
                + original.read_bytes()
            ),
            "nonzero-member-padding": RELEASE_TEST._nonzero_member_padding(
                original.read_bytes(), "README.txt"
            ),
            "gnu-format": _repack(
                original.read_bytes(), tar_format=tarfile.GNU_FORMAT
            ),
        }
        for name, raw in mutations.items():
            with self.subTest(name=name):
                path = self.inputs.output(f"{name}.tar")
                _write(path, raw, 0o400)
                with self.inputs.contract(), self.assertRaises(
                    PREPARE.RuntimeReleaseBundleError
                ):
                    PREPARE.verify_bundle(path)

    def test_facts_are_cross_checked_and_never_trusted(self) -> None:
        facts = json.loads(self.inputs.facts.read_bytes())
        facts["snapshot"]["member_count"] += 1
        _write(self.inputs.facts, RELEASE_TEST._canonical(facts), 0o600)
        with self.inputs.contract(), self.assertRaises(
            PREPARE.RuntimeReleaseBundleError
        ):
            self.inputs.prepare(self.inputs.output())

    def test_owner_only_modes_absolute_paths_and_closed_directories_are_required(self) -> None:
        self.inputs.facts.chmod(0o400)
        with self.inputs.contract(), self.assertRaises(
            PREPARE.RuntimeReleaseBundleError
        ):
            self.inputs.prepare(self.inputs.output("bad-mode.tar"))
        self.inputs.facts.chmod(0o600)
        extra = self.inputs.images / "extra.oci.tar"
        _write(extra, b"x", 0o400)
        with self.inputs.contract(), self.assertRaises(
            PREPARE.RuntimeReleaseBundleError
        ):
            self.inputs.prepare(self.inputs.output("extra-input.tar"))
        extra.unlink()
        relative = Path("relative.tar")
        with self.inputs.contract(), self.assertRaises(
            PREPARE.RuntimeReleaseBundleError
        ):
            PREPARE.verify_bundle(relative)

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.inputs.output()
        with self.inputs.contract():
            self.inputs.prepare(output)
            original = output.read_bytes()
            with self.assertRaises(PREPARE.RuntimeReleaseBundleError):
                self.inputs.prepare(output)
        self.assertEqual(output.read_bytes(), original)

    def test_output_created_in_publish_window_is_never_overwritten(self) -> None:
        output = self.inputs.output()
        original_rename = PREPARE._rename_no_replace

        def insert_output(source, target, directory_descriptor):
            _write(output, b"must survive", 0o400)
            return original_rename(source, target, directory_descriptor)

        with (
            self.inputs.contract(),
            patch.object(
                PREPARE,
                "_rename_no_replace",
                side_effect=insert_output,
            ),
            self.assertRaises(PREPARE.RuntimeReleaseBundleError),
        ):
            self.inputs.prepare(output)
        self.assertEqual(output.read_bytes(), b"must survive")

    def test_input_replacement_is_detected_and_failed_output_is_never_published(self) -> None:
        output = self.inputs.output()
        original_parser = PREPARE._parse_app_archive
        replaced = False

        def replace_after_parse(slot, archive_file, **keywords):
            nonlocal replaced
            result = original_parser(slot, archive_file, **keywords)
            if not replaced:
                replaced = True
                raw = archive_file.path.read_bytes()
                displaced = archive_file.path.with_name(archive_file.path.name + ".old")
                archive_file.path.rename(displaced)
                _write(archive_file.path, raw, 0o400)
            return result

        with (
            self.inputs.contract(),
            patch.object(PREPARE, "_parse_app_archive", side_effect=replace_after_parse),
            self.assertRaises(PREPARE.RuntimeReleaseBundleError),
        ):
            self.inputs.prepare(output)
        self.assertFalse(output.exists())
        (self.inputs.images / "platform.oci.tar.old").unlink()

        clean_output = self.inputs.output("verify-failure.tar")
        with (
            self.inputs.contract(),
            patch.object(
                PREPARE,
                "verify_bundle",
                side_effect=PREPARE.RuntimeReleaseBundleError(),
            ),
            self.assertRaises(PREPARE.RuntimeReleaseBundleError),
        ):
            self.inputs.prepare(clean_output)
        self.assertFalse(clean_output.exists())
        residual = list(clean_output.parent.iterdir())
        self.assertEqual(len(residual), 1)
        self.assertTrue(residual[0].name.startswith("create-verify-failure.tar-"))
        self.assertEqual(stat.S_IMODE(residual[0].stat().st_mode), 0o400)

    def test_atomic_no_replace_has_no_overwriting_platform_fallback(self) -> None:
        parent = self.inputs.root / "rename-contract"
        parent.mkdir(mode=0o700)
        parent.chmod(0o700)
        source = parent / "source"
        source.mkdir(mode=0o700)
        descriptor = os.open(parent, os.O_RDONLY)
        try:
            with (
                patch.object(PREPARE.sys, "platform", "unsupported"),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE._rename_no_replace("source", "destination", descriptor)
            with (
                patch.object(PREPARE.sys, "platform", "linux"),
                patch.object(PREPARE.ctypes, "CDLL", return_value=object()),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE._rename_no_replace("source", "destination", descriptor)
        finally:
            os.close(descriptor)
        self.assertTrue(source.is_dir())
        self.assertFalse((parent / "destination").exists())

    def test_stage_bundle_atomically_exposes_only_a_fully_verified_private_tree(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stages"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_open = PREPARE._open_file
        opened_bundle_paths = []

        def record_open(path, **keywords):
            if path == output:
                opened_bundle_paths.append(path)
            return original_open(path, **keywords)

        with self.inputs.contract(), patch.object(
            PREPARE, "_open_file", side_effect=record_open
        ):
            created = self.inputs.prepare(output)
            opened_bundle_paths.clear()
            staged = PREPARE.stage_bundle(output, destination)
        self.assertEqual(staged, created)
        self.assertTrue(destination.is_dir())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        actual = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
        }
        self.assertEqual(actual, set(PREPARE.EXPECTED_MEMBERS))
        for name in PREPARE.DIRECTORY_MEMBERS:
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o700)
        for name in PREPARE.FILE_MEMBERS:
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o400)
        self.assertEqual(
            {
                path.name
                for path in (destination / "images").iterdir()
            },
            set(PREPARE.APP_ARCHIVE_FILES.values()),
        )
        self.assertEqual(
            [item.name for item in stage_parent.iterdir()], [destination.name]
        )
        self.assertEqual(opened_bundle_paths, [output])

    def test_stage_rejects_existing_destination_and_retains_private_failed_staging(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stages"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        existing = stage_parent / "existing"
        existing.mkdir(mode=0o700)
        with self.inputs.contract():
            self.inputs.prepare(output)
            with self.assertRaises(PREPARE.RuntimeReleaseBundleError):
                PREPARE.stage_bundle(output, existing)
        self.assertTrue(existing.is_dir())
        tampered = self.inputs.output("tampered-stage.tar")
        _write(
            tampered,
            _repack(
                output.read_bytes(),
                mutate_name="README.txt",
                mutate_content=lambda raw: raw + b"tampered",
            ),
            0o400,
        )
        destination = stage_parent / "must-not-exist"
        with self.inputs.contract(), self.assertRaises(
            PREPARE.RuntimeReleaseBundleError
        ):
            PREPARE.stage_bundle(tampered, destination)
        self.assertFalse(destination.exists())
        residual = [item for item in stage_parent.iterdir() if item != existing]
        self.assertEqual(len(residual), 1)
        self.assertTrue(residual[0].name.startswith(f".{destination.name}.stage-"))
        self.assertEqual(stat.S_IMODE(residual[0].stat().st_mode), 0o700)

    def test_stage_no_replace_rejects_destination_created_in_publish_window(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-no-replace"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_rename = PREPARE._rename_no_replace

        def insert_destination(source, target, directory_descriptor):
            destination.mkdir(mode=0o700)
            destination.chmod(0o700)
            _write(destination / "sentinel", b"must survive", 0o400)
            return original_rename(source, target, directory_descriptor)

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_rename_no_replace",
                    side_effect=insert_destination,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertEqual((destination / "sentinel").read_bytes(), b"must survive")
        residual = [item for item in stage_parent.iterdir() if item != destination]
        self.assertEqual(len(residual), 1)
        self.assertTrue(residual[0].name.startswith(f".{destination.name}.stage-"))

    def test_stage_root_replacement_is_rejected_without_deleting_replacement(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-root-replacement"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_extract = PREPARE._extract_opened_bundle
        replaced_roots = []

        def replace_root(opened, root, bundle_sha256, created_identities=None):
            result = original_extract(
                opened,
                root,
                bundle_sha256,
                created_identities,
            )
            displaced = root.with_name(root.name + ".displaced")
            root.rename(displaced)
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            _write(root / "sentinel", b"replacement root", 0o400)
            replaced_roots.append((root, displaced))
            return result

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_extract_opened_bundle",
                    side_effect=replace_root,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        replacement, displaced = replaced_roots[0]
        self.assertFalse(destination.exists())
        self.assertEqual((replacement / "sentinel").read_bytes(), b"replacement root")
        self.assertTrue(displaced.is_dir())

    def test_stage_destination_replacement_is_rejected_and_preserved(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-destination-replacement"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        displaced = stage_parent / "published.displaced"
        original_rename = PREPARE._rename_no_replace

        def replace_after_publish(source, target, directory_descriptor):
            original_rename(source, target, directory_descriptor)
            destination.rename(displaced)
            destination.mkdir(mode=0o700)
            destination.chmod(0o700)
            _write(destination / "sentinel", b"replacement destination", 0o400)

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_rename_no_replace",
                    side_effect=replace_after_publish,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertEqual(
            (destination / "sentinel").read_bytes(),
            b"replacement destination",
        )
        self.assertTrue(displaced.is_dir())

    def test_stage_child_replacement_is_preserved_on_failure(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-child-replacement"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_extract = PREPARE._extract_opened_bundle
        replaced_roots = []

        def replace_child(opened, root, bundle_sha256, created_identities=None):
            result = original_extract(
                opened,
                root,
                bundle_sha256,
                created_identities,
            )
            target = root / "README.txt"
            target.unlink()
            _write(target, b"replacement child", 0o400)
            replaced_roots.append(root)
            return result

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_extract_opened_bundle",
                    side_effect=replace_child,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(
            (replaced_roots[0] / "README.txt").read_bytes(),
            b"replacement child",
        )

    def test_stage_rejects_an_extra_child_inserted_after_validation(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-extra-child"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_extract = PREPARE._extract_opened_bundle
        staged_roots = []

        def insert_extra(opened, root, bundle_sha256, created_identities=None):
            result = original_extract(
                opened,
                root,
                bundle_sha256,
                created_identities,
            )
            _write(root / "unlisted", b"not in the release", 0o400)
            staged_roots.append(root)
            return result

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_extract_opened_bundle",
                    side_effect=insert_extra,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(
            (staged_roots[0] / "unlisted").read_bytes(),
            b"not in the release",
        )

    def test_stage_final_visible_check_rejects_late_destination_replacement(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-final-visible"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        displaced = stage_parent / "validated.displaced"
        original_recheck = PREPARE._recheck_created_tree
        rechecks = 0

        def replace_after_second_recheck(root_descriptor, created_identities):
            nonlocal rechecks
            original_recheck(root_descriptor, created_identities)
            rechecks += 1
            if rechecks == 2:
                destination.rename(displaced)
                destination.mkdir(mode=0o700)
                destination.chmod(0o700)
                _write(destination / "sentinel", b"late replacement", 0o400)

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_recheck_created_tree",
                    side_effect=replace_after_second_recheck,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertEqual(rechecks, 2)
        self.assertEqual(
            (destination / "sentinel").read_bytes(),
            b"late replacement",
        )
        self.assertTrue(displaced.is_dir())

    def test_stage_final_visible_check_rejects_a_late_extra_child(self) -> None:
        output = self.inputs.output()
        stage_parent = self.inputs.root / "stage-late-extra"
        stage_parent.mkdir(mode=0o700)
        stage_parent.chmod(0o700)
        destination = stage_parent / "runtime-release"
        original_recheck = PREPARE._recheck_created_tree
        rechecks = 0

        def insert_after_second_recheck(root_descriptor, created_identities):
            nonlocal rechecks
            original_recheck(root_descriptor, created_identities)
            rechecks += 1
            if rechecks == 2:
                _write(destination / "late-extra", b"must be rejected", 0o400)

        with self.inputs.contract():
            self.inputs.prepare(output)
            with (
                patch.object(
                    PREPARE,
                    "_recheck_created_tree",
                    side_effect=insert_after_second_recheck,
                ),
                self.assertRaises(PREPARE.RuntimeReleaseBundleError),
            ):
                PREPARE.stage_bundle(output, destination)
        self.assertEqual(rechecks, 2)
        self.assertEqual(
            (destination / "late-extra").read_bytes(),
            b"must be rejected",
        )

    def test_cli_is_closed_non_authoritative_and_non_reflective(self) -> None:
        output = self.inputs.output()
        arguments = (
            "--architecture",
            ARCHITECTURE,
            "--commit",
            COMMIT,
            "--run-id",
            RUN_ID,
            "--run-attempt",
            RUN_ATTEMPT,
            "--source-snapshot",
            str(self.inputs.snapshot),
            "--source-dockerfile-set",
            str(self.inputs.dockerfile_set),
            "--source-facts",
            str(self.inputs.facts),
            "--images-dir",
            str(self.inputs.images),
            "--postgres-dir",
            str(self.inputs.postgres),
            "--output",
            str(output),
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with self.inputs.contract(), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(PREPARE.main(arguments), 0)
            self.assertEqual(
                PREPARE.main(("verify-bundle", "--bundle", str(output))), 0
            )
            stage_parent = self.inputs.root / "cli-stage"
            stage_parent.mkdir(mode=0o700)
            stage_parent.chmod(0o700)
            destination = stage_parent / "release"
            self.assertEqual(
                PREPARE.main(
                    (
                        "stage-bundle",
                        "--bundle",
                        str(output),
                        "--destination",
                        str(destination),
                    )
                ),
                0,
            )
        records = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(
            [item["status"] for item in records],
            [
                "BUNDLE_CREATED_VALIDATED_NOT_AUTHORITY",
                "BUNDLE_VALIDATED_NOT_AUTHORITY",
                "BUNDLE_STAGED_VALIDATED_NOT_AUTHORITY",
            ],
        )
        for item in records:
            self.assertEqual(item["authority"], PREPARE.AUTHORITY)
            self.assertFalse(item["execution_permitted"])
            self.assertFalse(item["production_authorized"])
            self.assertEqual(
                item["image_config_digests"],
                {
                    slot: RELEASE_TEST.APP_MATERIALS[slot]["config_digest"]
                    for slot in PREPARE.APP_SLOTS
                },
            )
        self.assertEqual(stderr.getvalue(), "")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(PREPARE.main(("verify-bundle", "--bundle", "secret")), 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("secret", stderr.getvalue())
        self.assertEqual(json.loads(stderr.getvalue())["status"], "BLOCKED")

    def test_module_has_no_network_docker_execution_or_deployment_capability(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {
                    "socket",
                    "ssl",
                    "http",
                    "urllib",
                    "requests",
                    "subprocess",
                    "docker",
                }
            )
        )
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(calls.isdisjoint({"system", "popen", "exec", "spawn"}))
        self.assertTrue(
            calls.isdisjoint({"remove", "removedirs", "rmdir", "unlink"})
        )
        self.assertNotIn("docker.sock", source.casefold())
        self.assertNotIn("os.rename", source)
        self.assertNotIn("TemporaryDirectory", source)
        self.assertNotIn("production_authorized=True", source)
        self.assertNotIn("execution_permitted=True", source)


if __name__ == "__main__":
    unittest.main()
