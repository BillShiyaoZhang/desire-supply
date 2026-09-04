"""Offline and fail-closed tests for the private-server runtime release."""

from __future__ import annotations

import ast
import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "private_server_runtime_release.py"
SCHEMA_PATH = ROOT / "deploy" / "private-server-runtime-release-v1.schema.json"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "test_private_server_runtime_release_contract", SCRIPT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime release module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RELEASE = _load_module()


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("ascii")
    return hashlib.sha256(value).hexdigest()


def _artifact(value: bytes) -> dict[str, object]:
    return {"sha256": _digest(value), "size": len(value)}


IMAGE_TAG = "release-v1"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


DOCKERFILE_CONTENT = b"FROM scratch\n"
DOCKERFILE_BYTES = {
    slot: DOCKERFILE_CONTENT for slot in RELEASE.OCI_IMAGE_SLOTS
}
DOCKERFILE_DIGEST_SET = _canonical(
    {
        slot: {
            "dockerfile_sha256": _digest(content),
            "target": RELEASE.DOCKERFILE_TARGETS[slot],
        }
        for slot, content in DOCKERFILE_BYTES.items()
    }
)
DOCKERFILE_SHA256 = _digest(DOCKERFILE_DIGEST_SET)


def _source_snapshot(
    dockerfile_content: bytes = DOCKERFILE_CONTENT,
    link_target: str = "src/desire_platform/contracts",
) -> bytes:
    regular_files = {
        "Dockerfile": (dockerfile_content, 0o644),
        "platform/src/desire_platform/contracts/schema.txt": (b"contract\n", 0o644),
        "scripts/release-helper": (b"#!/bin/sh\nexit 0\n", 0o755),
        "web/app/v1/app/[...path]/route.ts": (b"export {}\n", 0o644),
    }
    directories = {
        "deploy",
        "platform",
        "platform/src",
        "platform/src/desire_platform",
        "platform/src/desire_platform/contracts",
        "scripts",
        "web",
        "web/app",
        "web/app/v1",
        "web/app/v1/app",
        "web/app/v1/app/[...path]",
    }
    links = {"platform/contracts": link_target}
    output = io.BytesIO()
    names = sorted((*directories, *regular_files, *links), key=lambda item: item.encode("utf-8"))
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            info = tarfile.TarInfo(name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            if name in directories:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif name in links:
                info.type = tarfile.SYMTYPE
                info.mode = 0o777
                info.linkname = links[name]
                archive.addfile(info)
            else:
                content, mode = regular_files[name]
                info.mode = mode
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


SOURCE_SNAPSHOT = _source_snapshot()
SOURCE_SHA256 = _digest(SOURCE_SNAPSHOT)


def _statement(
    slot: str, kind: str, platform_manifest_digest: str
) -> bytes:
    subject = [
        {
            "name": slot + (f"-{index}" if slot == "postgres" else ""),
            "digest": {
                "sha256": platform_manifest_digest.removeprefix("sha256:")
            },
        }
        for index in range(13 if slot == "postgres" else 1)
    ]
    if kind == "sbom":
        predicate_type = "https://spdx.dev/Document"
        predicate = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3" if slot == "postgres" else "SPDX-2.2",
            "dataLicense": "CC0-1.0",
            "name": slot + "-sbom",
            "documentNamespace": "urn:example:" + slot,
            "creationInfo": {
                "created": "2026-08-25T00:00:00Z",
                "creators": ["Tool: test-fixture"],
            },
            "packages": [{"SPDXID": "SPDXRef-Package", "name": slot}],
            "relationships": [],
            "files": [{"SPDXID": "SPDXRef-File", "fileName": "/app"}],
            "documentDescribes": ["SPDXRef-Package"],
        }
    else:
        dependencies = [
            {
                "uri": "https://github.com/example/" + slot,
                "digest": (
                    {"sha1": _digest(slot + ":build-material")[:40]}
                    if slot == "postgres"
                    else {"sha256": _digest(slot + ":build-material")}
                ),
            }
        ]
        if slot == "postgres":
            predicate_type = "https://slsa.dev/provenance/v0.2"
            predicate = {
                "builder": {"id": "github.com/docker-library/postgres"},
                "buildType": "https://mobyproject.org/buildkit@v1",
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/docker-library/postgres",
                        "entryPoint": "Dockerfile",
                    },
                    "environment": {},
                    "parameters": {
                        "frontend": "dockerfile.v0",
                        "args": {},
                        "secrets": [],
                    },
                },
                "buildConfig": {},
                "metadata": {},
                "materials": dependencies,
            }
        else:
            predicate_type = "https://slsa.dev/provenance/v1"
            predicate = {
                "buildDefinition": {
                    "buildType": (
                        "https://github.com/moby/buildkit/blob/master/docs/"
                        "attestations/slsa-definitions.md"
                    ),
                    "externalParameters": {
                        "configSource": {"path": "Dockerfile"},
                        "request": {
                            "frontend": "dockerfile.v0",
                            "args": {"target": RELEASE.DOCKERFILE_TARGETS[slot]},
                            "locals": [
                                {"name": "context"},
                                {"name": "dockerfile"},
                            ],
                            "compatibilityVersion": 30,
                        },
                    },
                    "internalParameters": {"builderPlatform": "linux/amd64"},
                    "resolvedDependencies": dependencies,
                },
                "runDetails": {
                    "builder": {"id": ""},
                    "metadata": {"buildkit_metadata": {}},
                },
            }
    return _canonical(
        {
            "_type": (
                "https://in-toto.io/Statement/v0.1"
                if slot == "postgres"
                else "https://in-toto.io/Statement/v1"
            ),
            "subject": subject,
            "predicateType": predicate_type,
            "predicate": predicate,
        }
    )


def _image_materials(slot: str, *, include_archive: bool) -> dict[str, object]:
    layer = (slot + ":runnable-layer\n").encode("ascii")
    config = _canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {
                "type": "layers",
                "diff_ids": ["sha256:" + _digest(layer)],
            },
        }
    )
    config_digest = "sha256:" + _digest(config)
    target_manifest = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + _digest(layer),
                    "size": len(layer),
                }
            ],
        }
    )
    platform_digest = "sha256:" + _digest(target_manifest)
    sbom = _statement(slot, "sbom", platform_digest)
    provenance = _statement(slot, "provenance", platform_digest)
    provenance_type = (
        "https://slsa.dev/provenance/v1"
        if include_archive
        else "https://slsa.dev/provenance/v0.2"
    )
    layers = [
        {
            "mediaType": "application/vnd.in-toto+json",
            "digest": "sha256:" + _digest(sbom),
            "size": len(sbom),
            "annotations": {
                "in-toto.io/predicate-type": "https://spdx.dev/Document"
            },
        },
        {
            "mediaType": "application/vnd.in-toto+json",
            "digest": "sha256:" + _digest(provenance),
            "size": len(provenance),
            "annotations": {"in-toto.io/predicate-type": provenance_type},
        },
    ]
    if include_archive:
        attestation_config = b"{}"
        attestation_document = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.docker.attestation.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:" + _digest(attestation_config),
                "size": len(attestation_config),
                "data": base64.b64encode(attestation_config).decode("ascii"),
            },
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": platform_digest,
                "size": len(target_manifest),
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            "layers": layers,
        }
    else:
        attestation_config = _canonical(
            {
                "architecture": "unknown",
                "os": "unknown",
                "config": {},
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [
                        "sha256:" + _digest(sbom),
                        "sha256:" + _digest(provenance),
                    ],
                },
            }
        )
        attestation_document = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:" + _digest(attestation_config),
                "size": len(attestation_config),
            },
            "layers": layers,
        }
    attestation_manifest = _canonical(attestation_document)
    result: dict[str, object] = {
        "platform_manifest": target_manifest,
        "platform_manifest_digest": platform_digest,
        "config": config,
        "config_digest": config_digest,
        "layer": layer,
        "sbom": sbom,
        "provenance": provenance,
        "attestation_manifest": attestation_manifest,
        "attestation_config": attestation_config,
    }
    if not include_archive:
        return result
    index = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": platform_digest,
                    "size": len(target_manifest),
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + _digest(attestation_manifest),
                    "size": len(attestation_manifest),
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest",
                        "vnd.docker.reference.digest": platform_digest,
                    },
                },
            ],
        }
    )
    root_index_digest = "sha256:" + _digest(index)
    layout_index = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": root_index_digest,
                    "size": len(index),
                    "annotations": {
                        "io.containerd.image.name": (
                            f"docker.io/library/desire-supply-{slot}:{IMAGE_TAG}"
                        ),
                        "org.opencontainers.image.ref.name": IMAGE_TAG,
                    },
                }
            ],
        }
    )
    blobs = {
        root_index_digest.removeprefix("sha256:"): index,
        platform_digest.removeprefix("sha256:"): target_manifest,
        config_digest.removeprefix("sha256:"): config,
        _digest(layer): layer,
        _digest(attestation_manifest): attestation_manifest,
        _digest(sbom): sbom,
        _digest(provenance): provenance,
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("blobs", "blobs/sha256"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o555
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info)
        for name, content in (
            ("oci-layout", _canonical({"imageLayoutVersion": "1.0.0"})),
            ("index.json", layout_index),
            *(("blobs/sha256/" + name, content) for name, content in blobs.items()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    result["index"] = index
    result["layout_index"] = layout_index
    result["root_index_digest"] = root_index_digest
    result["archive"] = buffer.getvalue()
    return result


APP_MATERIALS = {
    slot: _image_materials(slot, include_archive=True)
    for slot in RELEASE.OCI_IMAGE_SLOTS
}
POSTGRES_MATERIALS = _image_materials("postgres", include_archive=False)


def _document() -> dict[str, object]:
    images: dict[str, object] = {}
    for slot in RELEASE.OCI_IMAGE_SLOTS:
        materials = APP_MATERIALS[slot]
        root_digest = materials["root_index_digest"]
        images[slot] = {
            "delivery_kind": "OCI_ARCHIVE",
            "reference": f"desire-supply-{slot}:{IMAGE_TAG}@{root_digest}",
            "root_index_digest": root_digest,
            "platform_manifest_digest": materials["platform_manifest_digest"],
            "config_digest": materials["config_digest"],
            "oci_archive": _artifact(materials["archive"]),
            "sbom": _artifact(materials["sbom"]),
            "provenance": _artifact(materials["provenance"]),
        }
    postgres = POSTGRES_MATERIALS
    images["postgres"] = {
        "delivery_kind": "PINNED_REGISTRY",
        "reference": RELEASE.POSTGRES_REFERENCE,
        "root_index_digest": RELEASE.POSTGRES_ROOT_INDEX_DIGEST,
        "platform_manifest_digest": postgres["platform_manifest_digest"],
        "config_digest": postgres["config_digest"],
        "registry_index": {
            "sha256": RELEASE.POSTGRES_ROOT_INDEX_DIGEST.removeprefix("sha256:"),
            "size": 4096,
        },
        "platform_manifest": _artifact(postgres["platform_manifest"]),
        "image_config": _artifact(postgres["config"]),
        "attestation_manifest": _artifact(postgres["attestation_manifest"]),
        "attestation_config": _artifact(postgres["attestation_config"]),
        "sbom": _artifact(postgres["sbom"]),
        "provenance": _artifact(postgres["provenance"]),
    }
    return {
        "format": RELEASE.FORMAT,
        "status": RELEASE.STATUS,
        "authority": RELEASE.AUTHORITY,
        "execution_permitted": False,
        "production_authorized": False,
        "release_id": "runtime-release-example-v1",
        "image_tag": IMAGE_TAG,
        "source": {
            "snapshot_kind": RELEASE.SOURCE_SNAPSHOT_KIND,
            "source_snapshot": _artifact(SOURCE_SNAPSHOT),
            "dockerfile_kind": RELEASE.DOCKERFILE_KIND,
            "dockerfiles": json.loads(DOCKERFILE_DIGEST_SET),
            "dockerfile_digest_set": _artifact(DOCKERFILE_DIGEST_SET),
        },
        "target_platform": {"os": "linux", "architecture": "amd64"},
        "schema_heads": dict(RELEASE.SCHEMA_HEADS),
        "images": images,
}


def _write_file(directory: Path, name: str, content: bytes, mode: int) -> Path:
    value = directory / name
    value.write_bytes(content)
    value.chmod(mode)
    return value


def _rewrite_oci_archive(
    raw: bytes,
    replacements: dict[str, bytes],
    renames: dict[str, str] | None = None,
) -> bytes:
    renames = {} if renames is None else renames
    source = io.BytesIO(raw)
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(fileobj=source, mode="r:") as archive:
        for member in archive.getmembers():
            if member.isdir():
                entries.append((member, None))
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise AssertionError("fixture member is unreadable")
            content = stream.read()
            entries.append((member, replacements.get(member.name, content)))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for original, content in entries:
            info = tarfile.TarInfo(renames.get(original.name, original.name))
            info.mode = original.mode
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            if content is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _tar_data_end(raw: bytes) -> int:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
    if not members:
        raise AssertionError("fixture archive has no members")
    member = members[-1]
    return member.offset_data + ((member.size + 511) // 512) * 512


def _gnu_long_name_prefix(name: str) -> bytes:
    payload = name.encode("ascii") + b"\x00"
    info = tarfile.TarInfo("././@LongLink")
    info.type = tarfile.GNUTYPE_LONGNAME
    info.size = len(payload)
    return (
        info.tobuf(format=tarfile.GNU_FORMAT)
        + payload
        + b"\x00" * (-len(payload) % 512)
    )


def _nonzero_member_padding(raw: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        member = archive.getmember(name)
    padding_start = member.offset_data + member.size
    padding_end = member.offset_data + ((member.size + 511) // 512) * 512
    if padding_start >= padding_end or raw[padding_start] != 0:
        raise AssertionError("fixture member has no zero padding to mutate")
    changed = bytearray(raw)
    changed[padding_start] = 0x53
    return bytes(changed)


class RuntimeReleaseTest(unittest.TestCase):
    def assert_invalid_document(self, document: object) -> None:
        with self.assertRaises(RELEASE.RuntimeReleaseContractError):
            RELEASE.validate_runtime_release_manifest(_canonical(document))

    def private_directory(self):
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name).resolve()
        directory.chmod(0o700)
        return temporary, directory

    def test_schema_closes_exactly_five_images_and_postgres_delivery(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            dict(RELEASE.SCHEMA_HEADS),
            {
                "postgresql": 18,
                "iam": 47,
                "profile": 5,
                "demand": 15,
                "trust": 23,
                "matching": 10,
                "taxonomy": 2,
            },
        )
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["format"]["const"], RELEASE.FORMAT)
        self.assertEqual(schema["properties"]["status"]["const"], RELEASE.STATUS)
        self.assertEqual(
            schema["properties"]["authority"]["const"], RELEASE.AUTHORITY
        )
        self.assertIs(
            schema["properties"]["execution_permitted"]["const"], False
        )
        self.assertIs(
            schema["properties"]["production_authorized"]["const"], False
        )
        for name, expected in RELEASE.SCHEMA_HEADS.items():
            self.assertEqual(
                schema["properties"]["schema_heads"]["properties"][name]["const"],
                expected,
            )
        images = schema["properties"]["images"]
        self.assertFalse(images["additionalProperties"])
        self.assertEqual(set(images["required"]), set(RELEASE.IMAGE_SLOTS))
        self.assertEqual(set(images["properties"]), set(RELEASE.IMAGE_SLOTS))
        postgres = schema["$defs"]["postgresImage"]
        self.assertFalse(postgres["additionalProperties"])
        self.assertEqual(
            postgres["properties"]["delivery_kind"]["const"], "PINNED_REGISTRY"
        )
        self.assertEqual(
            postgres["properties"]["reference"]["const"],
            RELEASE.POSTGRES_REFERENCE,
        )
        self.assertNotIn("oci_archive", postgres["properties"])
        self.assertNotIn("oci_archive", postgres["required"])
        for definition in ("ociImageBase", "postgresImage", "ociArchive", "sbom", "provenance"):
            self.assertFalse(schema["$defs"][definition]["additionalProperties"])

    def test_create_is_canonical_deterministic_and_validate_projects_all_bindings(self) -> None:
        document = _document()
        reversed_document = dict(reversed(tuple(document.items())))
        raw = RELEASE.create_manifest(document)
        self.assertEqual(raw, _canonical(document))
        self.assertEqual(raw, RELEASE.create_manifest(reversed_document))
        self.assertTrue(raw.endswith(b"\n"))
        manifest = RELEASE.validate(raw)
        self.assertEqual(manifest.raw, raw)
        self.assertEqual(manifest.sha256, _digest(raw))
        self.assertEqual(manifest.target_os, "linux")
        self.assertEqual(manifest.target_architecture, "amd64")
        self.assertEqual(dict(manifest.schema_heads), dict(RELEASE.SCHEMA_HEADS))
        self.assertEqual(tuple(item.slot for item in manifest.images), RELEASE.IMAGE_SLOTS)
        self.assertEqual(manifest.images[-1].delivery_kind, "PINNED_REGISTRY")
        self.assertEqual(
            tuple(item.kind for item in manifest.images[-1].artifacts),
            (
                "registry_index",
                "platform_manifest",
                "image_config",
                "attestation_manifest",
                "attestation_config",
                "sbom",
                "provenance",
            ),
        )
        self.assertFalse(manifest.execution_permitted)
        self.assertFalse(manifest.production_authorized)
        self.assertEqual(manifest.authority, "NOT_AUTHORITY")
        with self.assertRaises(FrozenInstanceError):
            manifest.authority = "AUTHORITY"

    def test_duplicate_noncanonical_number_and_unknown_inputs_fail_closed(self) -> None:
        raw = RELEASE.create_manifest(_document())
        duplicate = raw.replace(
            b'"authority":"NOT_AUTHORITY"',
            b'"authority":"NOT_AUTHORITY","authority":"NOT_AUTHORITY"',
            1,
        )
        with self.assertRaises(RELEASE.RuntimeReleaseContractError):
            RELEASE.validate(duplicate)
        with self.assertRaises(RELEASE.RuntimeReleaseContractError):
            RELEASE.validate(json.dumps(_document(), indent=2).encode("utf-8"))
        for numeric in (b'{"value":1.5}\n', b'{"value":NaN}\n'):
            with self.subTest(numeric=numeric):
                with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                    RELEASE.validate(numeric)
        for field_name in (
            "extra",
            "secret",
            "path",
            "socket",
            "command",
            "argv",
            "env",
        ):
            mutated = _document()
            mutated[field_name] = "forbidden"
            with self.subTest(field_name=field_name):
                self.assert_invalid_document(mutated)

    def test_constants_cross_bindings_and_digest_shapes_reject_mutation(self) -> None:
        mutations = []

        def add(change):
            value = _document()
            change(value)
            mutations.append(value)

        add(lambda value: value.__setitem__("format", "other"))
        add(lambda value: value.__setitem__("status", "READY"))
        add(lambda value: value.__setitem__("authority", "DEPLOY"))
        add(lambda value: value.__setitem__("execution_permitted", True))
        add(lambda value: value.__setitem__("production_authorized", True))
        add(lambda value: value["target_platform"].__setitem__("os", "darwin"))
        add(lambda value: value["target_platform"].__setitem__("architecture", "x86"))
        add(lambda value: value["schema_heads"].__setitem__("iam", 39))
        add(lambda value: value["schema_heads"].__setitem__("trust", 12))
        add(
            lambda value: value["source"]["dockerfile_digest_set"].__setitem__(
                "sha256", "a" * 63
            )
        )
        add(
            lambda value: value["source"]["dockerfiles"]["platform"].__setitem__(
                "target", "web-runtime"
            )
        )
        add(
            lambda value: value["images"]["platform"].__setitem__(
                "delivery_kind", "PINNED_REGISTRY"
            )
        )
        add(
            lambda value: value["images"]["platform"].__setitem__(
                "root_index_digest", "sha256:" + "1" * 64
            )
        )
        add(lambda value: value["images"]["platform"].__setitem__("config_digest", "1" * 64))
        add(
            lambda value: value["images"]["web"].__setitem__(
                "reference", value["images"]["platform"]["reference"]
            )
        )
        add(lambda value: value["images"]["edge"]["oci_archive"].__setitem__("size", 0))
        add(lambda value: value["images"]["edge"]["sbom"].__setitem__("sha256", "z" * 64))
        add(
            lambda value: value["images"]["edge"]["provenance"].__setitem__(
                "size", RELEASE.MAX_PROVENANCE_BYTES + 1
            )
        )
        for index, value in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_invalid_document(value)

    def test_every_semantic_binding_changes_the_manifest_identity(self) -> None:
        original = _document()
        original_manifest = RELEASE.validate(RELEASE.create_manifest(original))
        locations = (
            ("source", "source_snapshot", "sha256"),
            ("source", "source_snapshot", "size"),
            ("images", "platform", "config_digest"),
            ("images", "web", "oci_archive", "sha256"),
            ("images", "edge", "sbom", "sha256"),
            ("images", "oidc-egress-guard", "provenance", "sha256"),
            ("images", "postgres", "attestation_manifest", "size"),
            ("images", "postgres", "sbom", "sha256"),
            ("images", "postgres", "provenance", "sha256"),
        )
        for index, location in enumerate(locations):
            mutated = deepcopy(original)
            target = mutated
            for name in location[:-1]:
                target = target[name]
            old = target[location[-1]]
            if isinstance(old, int):
                replacement = old + 1
            elif isinstance(old, str) and old.startswith("sha256:"):
                replacement = "sha256:" + _digest(f"replacement:{index}")
            else:
                replacement = _digest(f"replacement:{index}")
            target[location[-1]] = replacement
            changed = RELEASE.validate(RELEASE.create_manifest(mutated))
            with self.subTest(location=location):
                self.assertNotEqual(changed.sha256, original_manifest.sha256)

    def test_postgres_is_exactly_pinned_and_can_never_claim_an_archive(self) -> None:
        mutations = []
        for name, value in (
            ("delivery_kind", "OCI_ARCHIVE"),
            ("reference", "postgres:18.4-alpine@sha256:" + "0" * 64),
            ("root_index_digest", "sha256:" + "0" * 64),
        ):
            document = _document()
            document["images"]["postgres"][name] = value
            mutations.append(document)
        document = _document()
        document["images"]["postgres"]["oci_archive"] = _artifact(b"not allowed")
        mutations.append(document)
        document = _document()
        del document["images"]["platform"]["oci_archive"]
        mutations.append(document)
        for index, value in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_invalid_document(value)
        manifest = RELEASE.validate(RELEASE.create_manifest(_document()))
        with self.assertRaises(RELEASE.RuntimeReleaseContractError):
            RELEASE.verify_artifact(
                manifest,
                slot="postgres",
                artifact_kind="oci_archive",
                artifact_file=Path("/unreachable"),
            )

    def test_create_validate_and_cli_use_owner_only_files_without_overwrite(self) -> None:
        temporary, directory = self.private_directory()
        try:
            source = _write_file(
                directory,
                "candidate.json",
                json.dumps(_document(), indent=2).encode("ascii"),
                0o600,
            )
            output = directory / "release.json"
            manifest = RELEASE.create_runtime_release_manifest_file(source, output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o400)
            self.assertEqual(RELEASE.validate_runtime_release_manifest_file(output), manifest)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.create_runtime_release_manifest_file(source, output)

            cli_output = directory / "release-cli.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = RELEASE.main(
                    (
                        "create-manifest",
                        "--input",
                        str(source),
                        "--output",
                        str(cli_output),
                    )
                )
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(
                json.loads(stdout.getvalue())["status"],
                "MANIFEST_CREATED_NOT_AUTHORITY",
            )
            self.assertEqual(cli_output.stat().st_mode & 0o777, 0o400)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = RELEASE.main(("validate", "--manifest", str(output)))
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["status"], "MANIFEST_VALIDATED_NOT_AUTHORITY")
            self.assertEqual(report["authority"], "NOT_AUTHORITY")
            self.assertFalse(report["execution_permitted"])
            self.assertFalse(report["production_authorized"])
        finally:
            temporary.cleanup()

    def test_relative_parent_permission_symlink_hardlink_and_file_modes_reject(self) -> None:
        temporary, directory = self.private_directory()
        try:
            manifest_raw = RELEASE.create_manifest(_document())
            manifest_file = _write_file(directory, "release.json", manifest_raw, 0o400)
            artifact = _write_file(
                directory,
                "platform-sbom.json",
                APP_MATERIALS["platform"]["sbom"],
                0o400,
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.validate_runtime_release_manifest_file(Path("release.json"))

            manifest_file.chmod(0o600)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.validate_runtime_release_manifest_file(manifest_file)
            manifest_file.chmod(0o400)

            directory.chmod(0o755)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.validate_runtime_release_manifest_file(manifest_file)
            directory.chmod(0o700)

            symlink = directory / "linked.json"
            symlink.symlink_to(manifest_file.name)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.validate_runtime_release_manifest_file(symlink)

            hardlink = directory / "hardlinked.json"
            os.link(manifest_file, hardlink)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.validate_runtime_release_manifest_file(manifest_file)
            hardlink.unlink()

            artifact.chmod(0o600)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    manifest_raw,
                    slot="platform",
                    artifact_kind="sbom",
                    artifact_file=artifact,
                )
        finally:
            temporary.cleanup()

    def test_source_artifacts_verify_symlinks_routes_targets_and_cross_binding(self) -> None:
        raw = RELEASE.create_manifest(_document())
        temporary, directory = self.private_directory()
        try:
            snapshot = _write_file(
                directory, "source-snapshot.tar", SOURCE_SNAPSHOT, 0o400
            )
            digest_set = _write_file(
                directory,
                "dockerfile-digest-set.json",
                DOCKERFILE_DIGEST_SET,
                0o400,
            )
            snapshot_result = RELEASE.verify_source_artifact(
                raw,
                artifact_kind="source_snapshot",
                artifact_file=snapshot,
            )
            digest_result = RELEASE.verify_source_artifact(
                raw,
                artifact_kind="dockerfile_digest_set",
                artifact_file=digest_set,
            )
            self.assertEqual(snapshot_result.slot, "source")
            self.assertEqual(digest_result.sha256, DOCKERFILE_SHA256)

            manifest_file = _write_file(directory, "release.json", raw, 0o400)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = RELEASE.main(
                    (
                        "verify-source-artifact",
                        "--manifest",
                        str(manifest_file),
                        "--kind",
                        "source_snapshot",
                        "--artifact",
                        str(snapshot),
                    )
                )
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(stdout.getvalue())["slot"], "source")

            inconsistent = _source_snapshot(b"FROM busybox\n")
            changed = _document()
            changed["source"]["source_snapshot"] = _artifact(inconsistent)
            changed_raw = RELEASE.create_manifest(changed)
            inconsistent_file = _write_file(
                directory, "inconsistent-source.tar", inconsistent, 0o400
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_source_artifact(
                    changed_raw,
                    artifact_kind="source_snapshot",
                    artifact_file=inconsistent_file,
                )

            escaping = _source_snapshot(link_target="../../../outside")
            escaping_document = _document()
            escaping_document["source"]["source_snapshot"] = _artifact(escaping)
            escaping_raw = RELEASE.create_manifest(escaping_document)
            escaping_file = _write_file(
                directory, "escaping-source.tar", escaping, 0o400
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_source_artifact(
                    escaping_raw,
                    artifact_kind="source_snapshot",
                    artifact_file=escaping_file,
                )

            padded = _nonzero_member_padding(SOURCE_SNAPSHOT, "Dockerfile")
            padded_document = _document()
            padded_document["source"]["source_snapshot"] = _artifact(padded)
            padded_file = _write_file(
                directory, "nonzero-source-padding.tar", padded, 0o400
            )
            with self.assertRaisesRegex(
                RELEASE.RuntimeReleaseContractError,
                f"^{RELEASE.ERROR_CODE}$",
            ):
                RELEASE.verify_source_artifact(
                    RELEASE.create_manifest(padded_document),
                    artifact_kind="source_snapshot",
                    artifact_file=padded_file,
                )
        finally:
            temporary.cleanup()

    def test_artifact_verification_detects_content_size_kind_and_manifest_tampering(self) -> None:
        temporary, directory = self.private_directory()
        try:
            raw = RELEASE.create_manifest(_document())
            artifact = _write_file(
                directory,
                "platform-archive.oci",
                APP_MATERIALS["platform"]["archive"],
                0o400,
            )
            result = RELEASE.verify_artifact(
                raw,
                slot="platform",
                artifact_kind="oci_archive",
                artifact_file=artifact,
            )
            self.assertEqual(
                result.status,
                "CONTENT_VALIDATED_UNSIGNED_UNTRUSTED_NOT_AUTHORITY",
            )
            self.assertEqual(result.authority, "NOT_AUTHORITY")
            self.assertEqual(
                result.sha256, _digest(APP_MATERIALS["platform"]["archive"])
            )

            artifact.chmod(0o600)
            artifact.write_bytes(
                b"X" * len(APP_MATERIALS["platform"]["archive"])
            )
            artifact.chmod(0o400)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="platform",
                    artifact_kind="oci_archive",
                    artifact_file=artifact,
                )
            artifact.chmod(0o600)
            artifact.write_bytes(b"wrong size")
            artifact.chmod(0o400)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="platform",
                    artifact_kind="oci_archive",
                    artifact_file=artifact,
                )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="missing",
                    artifact_kind="sbom",
                    artifact_file=artifact,
                )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="platform",
                    artifact_kind="layer",
                    artifact_file=artifact,
                )

            manifest = RELEASE.validate(raw)
            object.__setattr__(manifest, "sha256", "0" * 64)
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    manifest,
                    slot="platform",
                    artifact_kind="oci_archive",
                    artifact_file=artifact,
                )
        finally:
            temporary.cleanup()

    def test_oci_semantics_reject_wrong_target_even_when_transport_hash_matches(self) -> None:
        document = _document()
        index = json.loads(APP_MATERIALS["platform"]["index"])
        index["manifests"][0]["platform"]["architecture"] = "arm64"
        changed_index = _canonical(index)
        root_digest = "sha256:" + _digest(changed_index)
        layout_index = json.loads(APP_MATERIALS["platform"]["layout_index"])
        layout_index["manifests"][0]["digest"] = root_digest
        layout_index["manifests"][0]["size"] = len(changed_index)
        changed_layout_index = _canonical(layout_index)
        old_root_name = (
            "blobs/sha256/"
            + APP_MATERIALS["platform"]["root_index_digest"].removeprefix(
                "sha256:"
            )
        )
        new_root_name = "blobs/sha256/" + root_digest.removeprefix("sha256:")
        changed_archive = _rewrite_oci_archive(
            APP_MATERIALS["platform"]["archive"],
            {
                "index.json": changed_layout_index,
                old_root_name: changed_index,
            },
            {old_root_name: new_root_name},
        )
        image = document["images"]["platform"]
        image["root_index_digest"] = root_digest
        image["reference"] = (
            f"desire-supply-platform:{IMAGE_TAG}@{root_digest}"
        )
        image["oci_archive"] = _artifact(changed_archive)
        manifest = RELEASE.create_manifest(document)

        temporary, directory = self.private_directory()
        try:
            artifact = _write_file(
                directory, "wrong-platform.oci", changed_archive, 0o400
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    manifest,
                    slot="platform",
                    artifact_kind="oci_archive",
                    artifact_file=artifact,
                )
        finally:
            temporary.cleanup()

    def test_oci_archive_requires_contiguous_members_and_zero_terminal_blocks(self) -> None:
        original = APP_MATERIALS["platform"]["archive"]
        data_end = _tar_data_end(original)
        self.assertGreaterEqual(len(original) - data_end, 1024)
        self.assertEqual((len(original) - data_end) % 512, 0)
        self.assertEqual(original[data_end:], b"\x00" * (len(original) - data_end))

        nonzero_trailer = bytearray(original)
        nonzero_trailer[data_end] = 1
        mutations = {
            "nonzero-terminal-block": bytes(nonzero_trailer),
            "nonzero-after-existing-terminal": (
                original + b"\x01" + b"\x00" * 511
            ),
            "only-one-terminal-block": original[: data_end + 512],
            "unaligned-zero-trailer": original + b"\x00",
            "concatenated-second-tar": original + original,
            "hidden-gnu-offset-record": _gnu_long_name_prefix("blobs") + original,
            "nonzero-member-padding": _nonzero_member_padding(
                original, "oci-layout"
            ),
            "truncated-last-member": original[: data_end - 512] + b"\x00" * 1536,
        }

        temporary, directory = self.private_directory()
        try:
            minimum_terminal = original[: data_end + 1024]
            valid_document = _document()
            valid_document["images"]["platform"]["oci_archive"] = _artifact(
                minimum_terminal
            )
            valid_artifact = _write_file(
                directory, "minimum-terminal.oci", minimum_terminal, 0o400
            )
            verified = RELEASE.verify_artifact(
                RELEASE.create_manifest(valid_document),
                slot="platform",
                artifact_kind="oci_archive",
                artifact_file=valid_artifact,
            )
            self.assertEqual(verified.size, len(minimum_terminal))

            for index, (name, archive_raw) in enumerate(mutations.items()):
                document = _document()
                document["images"]["platform"]["oci_archive"] = _artifact(
                    archive_raw
                )
                manifest = RELEASE.create_manifest(document)
                artifact = _write_file(
                    directory, f"bad-terminal-{index}.oci", archive_raw, 0o400
                )
                with self.subTest(name=name):
                    with self.assertRaisesRegex(
                        RELEASE.RuntimeReleaseContractError,
                        f"^{RELEASE.ERROR_CODE}$",
                    ):
                        RELEASE.verify_artifact(
                            manifest,
                            slot="platform",
                            artifact_kind="oci_archive",
                            artifact_file=artifact,
                        )
        finally:
            temporary.cleanup()

    def test_oci_layout_reference_annotations_bind_the_exact_tag_and_name(self) -> None:
        original = json.loads(APP_MATERIALS["platform"]["layout_index"])
        annotations = original["manifests"][0]["annotations"]
        mutations: list[tuple[str, dict[str, object]]] = []
        for key in (
            "io.containerd.image.name",
            "org.opencontainers.image.ref.name",
        ):
            missing = deepcopy(original)
            del missing["manifests"][0]["annotations"][key]
            mutations.append(("missing-" + key, missing))
        wrong_name = deepcopy(original)
        wrong_name["manifests"][0]["annotations"][
            "io.containerd.image.name"
        ] = "docker.io/library/other:release-v1"
        mutations.append(("wrong-image-name", wrong_name))
        wrong_tag = deepcopy(original)
        wrong_tag["manifests"][0]["annotations"][
            "org.opencontainers.image.ref.name"
        ] = "other-tag"
        mutations.append(("wrong-ref-name", wrong_tag))
        self.assertEqual(
            annotations["io.containerd.image.name"],
            f"docker.io/library/desire-supply-platform:{IMAGE_TAG}",
        )

        temporary, directory = self.private_directory()
        try:
            for index, (name, layout) in enumerate(mutations):
                archive = _rewrite_oci_archive(
                    APP_MATERIALS["platform"]["archive"],
                    {"index.json": _canonical(layout)},
                )
                document = _document()
                document["images"]["platform"]["oci_archive"] = _artifact(
                    archive
                )
                manifest = RELEASE.create_manifest(document)
                artifact = _write_file(
                    directory, f"bad-layout-{index}.oci", archive, 0o400
                )
                with self.subTest(name=name):
                    with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                        RELEASE.verify_artifact(
                            manifest,
                            slot="platform",
                            artifact_kind="oci_archive",
                            artifact_file=artifact,
                        )
        finally:
            temporary.cleanup()

    def test_external_statement_keeps_original_bytes_but_is_exactly_layer_bound(self) -> None:
        statement = json.loads(APP_MATERIALS["platform"]["sbom"])
        noncanonical = json.dumps(statement, indent=2).encode("utf-8")
        document = _document()
        document["images"]["platform"]["sbom"] = _artifact(noncanonical)
        raw = RELEASE.create_manifest(document)

        temporary, directory = self.private_directory()
        try:
            sbom_file = _write_file(
                directory, "platform-sbom.json", noncanonical, 0o400
            )
            result = RELEASE.verify_artifact(
                raw,
                slot="platform",
                artifact_kind="sbom",
                artifact_file=sbom_file,
            )
            self.assertEqual(result.sha256, _digest(noncanonical))
            archive_file = _write_file(
                directory,
                "platform.oci",
                APP_MATERIALS["platform"]["archive"],
                0o400,
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="platform",
                    artifact_kind="oci_archive",
                    artifact_file=archive_file,
                )

            for mutation in ("subject", "unknown", "duplicate"):
                value = deepcopy(statement)
                if mutation == "subject":
                    value["subject"][0]["digest"]["sha256"] = "0" * 64
                    content = _canonical(value)
                elif mutation == "unknown":
                    value["unexpected"] = True
                    content = _canonical(value)
                else:
                    content = APP_MATERIALS["platform"]["sbom"].replace(
                        b'"_type":', b'"_type":"duplicate","_type":', 1
                    )
                changed = _document()
                changed["images"]["platform"]["sbom"] = _artifact(content)
                changed_raw = RELEASE.create_manifest(changed)
                changed_file = _write_file(
                    directory, f"bad-{mutation}.json", content, 0o400
                )
                with self.subTest(mutation=mutation):
                    with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                        RELEASE.verify_artifact(
                            changed_raw,
                            slot="platform",
                            artifact_kind="sbom",
                            artifact_file=changed_file,
                        )
        finally:
            temporary.cleanup()

    def test_app_provenance_must_prove_v1_min_without_rich_build_inputs(self) -> None:
        original = json.loads(APP_MATERIALS["platform"]["provenance"])
        mutations: list[tuple[str, dict[str, object]]] = []

        build_config = deepcopy(original)
        build_config["predicate"]["buildDefinition"]["internalParameters"][
            "buildConfig"
        ] = {"llbDefinition": []}
        mutations.append(("build-config", build_config))

        secret_identity = deepcopy(original)
        secret_identity["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["secrets"] = [{"id": "production"}]
        mutations.append(("secret-identity", secret_identity))

        build_argument = deepcopy(original)
        build_argument["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["args"]["build-arg:TOKEN"] = "value"
        mutations.append(("build-argument", build_argument))

        wrong_target = deepcopy(original)
        wrong_target["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["args"]["target"] = RELEASE.DOCKERFILE_TARGETS["web"]
        mutations.append(("wrong-target", wrong_target))

        missing_target = deepcopy(original)
        missing_target["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["args"].pop("target")
        mutations.append(("missing-target", missing_target))

        missing_request = deepcopy(original)
        missing_request["predicate"]["buildDefinition"]["externalParameters"].pop(
            "request"
        )
        mutations.append(("missing-request", missing_request))

        wrong_config_source = deepcopy(original)
        wrong_config_source["predicate"]["buildDefinition"]["externalParameters"][
            "configSource"
        ]["path"] = "deploy/alternate.Dockerfile"
        mutations.append(("wrong-config-source", wrong_config_source))

        wrong_compatibility = deepcopy(original)
        wrong_compatibility["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["compatibilityVersion"] = 20
        mutations.append(("wrong-compatibility", wrong_compatibility))

        extra_local = deepcopy(original)
        extra_local["predicate"]["buildDefinition"]["externalParameters"][
            "request"
        ]["locals"].append({"name": "unreviewed"})
        mutations.append(("extra-local", extra_local))

        rich_source = deepcopy(original)
        rich_source["predicate"]["runDetails"]["metadata"][
            "buildkit_metadata"
        ]["source"] = {"infos": [{"filename": "Dockerfile"}]}
        mutations.append(("rich-source", rich_source))

        downgraded = deepcopy(original)
        downgraded["_type"] = "https://in-toto.io/Statement/v0.1"
        mutations.append(("statement-downgrade", downgraded))

        temporary, directory = self.private_directory()
        try:
            for index, (name, value) in enumerate(mutations):
                content = _canonical(value)
                document = _document()
                document["images"]["platform"]["provenance"] = _artifact(
                    content
                )
                manifest = RELEASE.create_manifest(document)
                artifact = _write_file(
                    directory, f"bad-provenance-{index}.json", content, 0o400
                )
                with self.subTest(name=name):
                    with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                        RELEASE.verify_artifact(
                            manifest,
                            slot="platform",
                            artifact_kind="provenance",
                            artifact_file=artifact,
                        )
        finally:
            temporary.cleanup()

    def test_postgres_raw_supply_chain_blobs_are_required_and_cross_checked(self) -> None:
        raw = RELEASE.create_manifest(_document())
        successful = {
            "platform_manifest": POSTGRES_MATERIALS["platform_manifest"],
            "image_config": POSTGRES_MATERIALS["config"],
            "attestation_manifest": POSTGRES_MATERIALS["attestation_manifest"],
            "attestation_config": POSTGRES_MATERIALS["attestation_config"],
            "sbom": POSTGRES_MATERIALS["sbom"],
            "provenance": POSTGRES_MATERIALS["provenance"],
        }
        temporary, directory = self.private_directory()
        try:
            for kind, content in successful.items():
                artifact = _write_file(
                    directory, "postgres-" + kind + ".json", content, 0o400
                )
                with self.subTest(kind=kind):
                    result = RELEASE.verify_artifact(
                        raw,
                        slot="postgres",
                        artifact_kind=kind,
                        artifact_file=artifact,
                    )
                    self.assertEqual(result.sha256, _digest(content))

            missing_upstream_index = _write_file(
                directory, "postgres-registry-index.json", b"x" * 4096, 0o400
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    raw,
                    slot="postgres",
                    artifact_kind="registry_index",
                    artifact_file=missing_upstream_index,
                )

            bad_attestation = json.loads(
                POSTGRES_MATERIALS["attestation_manifest"]
            )
            bad_attestation["subject"] = {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": POSTGRES_MATERIALS["platform_manifest_digest"],
                "size": len(POSTGRES_MATERIALS["platform_manifest"]),
            }
            bad_content = _canonical(bad_attestation)
            changed = _document()
            changed["images"]["postgres"]["attestation_manifest"] = _artifact(
                bad_content
            )
            changed_raw = RELEASE.create_manifest(changed)
            bad_file = _write_file(
                directory, "postgres-bad-attestation.json", bad_content, 0o400
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    changed_raw,
                    slot="postgres",
                    artifact_kind="attestation_manifest",
                    artifact_file=bad_file,
                )

            mismatched = json.loads(
                POSTGRES_MATERIALS["attestation_manifest"]
            )
            mismatched["layers"][1]["annotations"][
                "in-toto.io/predicate-type"
            ] = "https://slsa.dev/provenance/v1"
            mismatched_content = _canonical(mismatched)
            mismatched_document = _document()
            mismatched_document["images"]["postgres"][
                "attestation_manifest"
            ] = _artifact(mismatched_content)
            mismatched_raw = RELEASE.create_manifest(mismatched_document)
            mismatched_file = _write_file(
                directory,
                "postgres-mismatched-predicate.json",
                mismatched_content,
                0o400,
            )
            with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                RELEASE.verify_artifact(
                    mismatched_raw,
                    slot="postgres",
                    artifact_kind="attestation_manifest",
                    artifact_file=mismatched_file,
                )
        finally:
            temporary.cleanup()

    def test_verify_artifact_cli_is_offline_and_non_authoritative(self) -> None:
        temporary, directory = self.private_directory()
        try:
            raw = RELEASE.create_manifest(_document())
            manifest = _write_file(directory, "release.json", raw, 0o400)
            artifact = _write_file(
                directory,
                "postgres-sbom.json",
                POSTGRES_MATERIALS["sbom"],
                0o400,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = RELEASE.main(
                    (
                        "verify-artifact",
                        "--manifest",
                        str(manifest),
                        "--slot",
                        "postgres",
                        "--kind",
                        "sbom",
                        "--artifact",
                        str(artifact),
                    )
                )
            self.assertEqual(result, 0)
            self.assertEqual(stderr.getvalue(), "")
            report = json.loads(stdout.getvalue())
            self.assertEqual(
                report["status"],
                "CONTENT_VALIDATED_UNSIGNED_UNTRUSTED_NOT_AUTHORITY",
            )
            self.assertEqual(report["authority"], "NOT_AUTHORITY")
            self.assertNotIn("reference", report)
            self.assertNotIn("file", report)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = RELEASE.main(("deploy",))
            self.assertEqual(result, 78)
            self.assertEqual(stdout.getvalue(), "")
            failure = json.loads(stderr.getvalue())
            self.assertEqual(failure["status"], "BLOCKED")
            self.assertEqual(failure["authority"], "NOT_AUTHORITY")
        finally:
            temporary.cleanup()

    def test_descriptor_identity_rejects_leaf_replacement_during_hash(self) -> None:
        temporary, directory = self.private_directory()
        try:
            raw = RELEASE.create_manifest(_document())
            content = APP_MATERIALS["platform"]["sbom"]
            artifact = _write_file(directory, "platform-sbom.json", content, 0o400)
            replacement = _write_file(directory, "replacement.json", content, 0o400)
            original_read = RELEASE.os.read
            swapped = False

            def replace_after_read(descriptor: int, count: int) -> bytes:
                nonlocal swapped
                result = original_read(descriptor, count)
                if not swapped:
                    swapped = True
                    os.replace(replacement, artifact)
                return result

            with mock.patch.object(RELEASE.os, "read", side_effect=replace_after_read):
                with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                    RELEASE.verify_artifact(
                        raw,
                        slot="platform",
                        artifact_kind="sbom",
                        artifact_file=artifact,
                    )
            self.assertTrue(swapped)
        finally:
            temporary.cleanup()

    def test_document_and_artifact_large_file_boundaries_reject_before_reading(self) -> None:
        with self.assertRaises(RELEASE.RuntimeReleaseContractError):
            RELEASE.validate(b"x" * (RELEASE.MAX_DOCUMENT_BYTES + 1))
        document = _document()
        document["images"]["platform"]["oci_archive"]["size"] = (
            RELEASE.MAX_OCI_ARCHIVE_BYTES + 1
        )
        self.assert_invalid_document(document)

        temporary, directory = self.private_directory()
        try:
            raw = RELEASE.create_manifest(_document())
            oversized = directory / "oversized-sbom.json"
            with oversized.open("wb") as stream:
                stream.truncate(RELEASE.MAX_SBOM_BYTES + 1)
            oversized.chmod(0o400)
            with mock.patch.object(
                RELEASE.os,
                "read",
                side_effect=AssertionError("oversized artifact must not be read"),
            ):
                with self.assertRaises(RELEASE.RuntimeReleaseContractError):
                    RELEASE.verify_artifact(
                        raw,
                        slot="platform",
                        artifact_kind="sbom",
                        artifact_file=oversized,
                    )
        finally:
            temporary.cleanup()

    def test_no_execution_network_registry_or_authority_capability_exists(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        forbidden_calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "exec",
                    "eval",
                    "compile",
                }:
                    forbidden_calls.append(node.func.id)
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and (
                        node.func.attr in {"system", "popen", "fork", "forkpty"}
                        or node.func.attr.startswith("spawn")
                        or node.func.attr.startswith("exec")
                    )
                ):
                    forbidden_calls.append("os." + node.func.attr)
        self.assertTrue(
            {"subprocess", "socket", "urllib", "http", "requests", "docker"}.isdisjoint(
                imported_roots
            )
        )
        self.assertEqual(forbidden_calls, [])
        self.assertNotIn("/var/run/docker.sock", source)
        self.assertNotIn("docker.from_env", source)
        forbidden_fields = {
            "secret",
            "path",
            "socket",
            "command",
            "argv",
            "env",
        }
        for projected_type in (
            RELEASE.ArtifactBinding,
            RELEASE.RuntimeImageBinding,
            RELEASE.RuntimeReleaseManifest,
            RELEASE.VerifiedRuntimeArtifact,
        ):
            self.assertTrue(
                forbidden_fields.isdisjoint(item.name for item in fields(projected_type))
            )


if __name__ == "__main__":
    unittest.main()
