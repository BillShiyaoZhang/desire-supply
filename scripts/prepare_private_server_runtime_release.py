#!/usr/bin/env python3
"""Assemble and verify one closed private-server runtime release bundle.

This helper is content-only.  It has no network, Docker, container lifecycle,
deployment, credential, or production-authority capability.  Both creation and
verification fail closed around owner-only files and canonical release data.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import types
from typing import Any, Mapping, NoReturn, Sequence


ERROR_CODE = "PRIVATE_SERVER_RUNTIME_RELEASE_BUNDLE_INVALID"
STATUS = "VALIDATED_RELEASE_BUNDLE_NOT_AUTHORITY"
AUTHORITY = "NOT_AUTHORITY"

MAX_BUNDLE_BYTES = 64 * 1024 * 1024 * 1024
MAX_OCI_ARCHIVE_BYTES = 32 * 1024 * 1024 * 1024
MAX_SOURCE_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 128 * 1024 * 1024
MAX_PROVENANCE_BYTES = 32 * 1024 * 1024
MAX_TOOL_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 128

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
IN_TOTO = "application/vnd.in-toto+json"
ATTESTATION_ARTIFACT = "application/vnd.docker.attestation.manifest.v1+json"
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_V1_PREDICATE = "https://slsa.dev/provenance/v1"
SLSA_V02_PREDICATE = "https://slsa.dev/provenance/v0.2"

SOURCE_FACTS_FORMAT = "desire-private-server-runtime-release-source-facts-v1"
POSTGRES_EVIDENCE_FORMAT = "desire-pinned-postgres-release-evidence-v1"
POSTGRES_EVIDENCE_STATUS = "CONTENT_FETCHED_UNSIGNED_UNTRUSTED"
POSTGRES_EVIDENCE_AUTHORITY = "NOT_EXECUTION_AUTHORITY"
POSTGRES_ROOT_DIGEST = (
    "sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)

APP_SLOTS = ("platform", "web", "edge", "oidc-egress-guard")
REPOSITORIES = {
    "platform": "desire-supply-platform",
    "web": "desire-supply-web",
    "edge": "desire-supply-edge",
    "oidc-egress-guard": "desire-supply-oidc-egress-guard",
}
TARGETS = {
    "platform": "platform-runtime",
    "web": "web-runtime",
    "edge": "edge-runtime",
    "oidc-egress-guard": "oidc-egress-guard-runtime",
}
APP_ARCHIVE_FILES = {
    slot: f"{slot}.oci.tar" for slot in APP_SLOTS
}
POSTGRES_FILES = {
    "registry_index": "registry-index.json",
    "platform_manifest": "platform-manifest.json",
    "image_config": "image-config.json",
    "attestation_manifest": "attestation-manifest.json",
    "attestation_config": "attestation-config.json",
    "sbom": "sbom.intoto.json",
    "provenance": "provenance.intoto.json",
}
POSTGRES_EVIDENCE_KINDS = {
    kind: "root_index" if kind == "registry_index" else kind
    for kind in POSTGRES_FILES
}

DIRECTORY_MEMBERS = (
    "attestations",
    *(f"attestations/{slot}" for slot in APP_SLOTS),
    "contracts",
    "images",
    "postgres",
    "source",
    "tools",
)
FILE_MEMBERS = (
    "README.txt",
    *(f"attestations/{slot}/provenance.intoto.json" for slot in APP_SLOTS),
    *(f"attestations/{slot}/sbom.intoto.json" for slot in APP_SLOTS),
    "contracts/private-server-runtime-release-v1.schema.json",
    *(f"images/{APP_ARCHIVE_FILES[slot]}" for slot in APP_SLOTS),
    *(f"postgres/{name}" for name in POSTGRES_FILES.values()),
    "release.json",
    "source/dockerfile-digest-set.json",
    "source/source-snapshot.tar",
    "tools/prepare_private_server_runtime_release.py",
    "tools/private_server_runtime_release.py",
)
EXPECTED_MEMBERS = tuple(
    sorted((*DIRECTORY_MEMBERS, *FILE_MEMBERS), key=lambda value: value.encode("ascii"))
)
EXPECTED_CHILDREN = {
    parent: frozenset(
        name.rpartition("/")[2]
        for name in EXPECTED_MEMBERS
        if name.rpartition("/")[0] == parent
    )
    for parent in ("", *DIRECTORY_MEMBERS)
}

README = b"""Desire Supply private-server runtime release bundle

This deterministic bundle contains validated, unsigned and untrusted release
content. It is not execution authority, deployment authority, production
approval, or proof that an attestation signer is authentic.

The member contract defines no dedicated secret input, but source and
attestation bytes are untrusted evidence and are not DLP-scanned. Protect the
bundle as sensitive release evidence. Final artifact digests are closed; build
inputs are not claimed to be dependency-closed or reproducible.

Validate it offline with a separately trusted copy of:
  python prepare_private_server_runtime_release.py verify-bundle \
    --bundle /absolute/path/to/bundle.tar

Safe creation and staging require an atomic no-replace rename primitive
(Linux renameat2/RENAME_NOREPLACE or Darwin renameatx_np/RENAME_EXCL). An
unsupported host is rejected; there is no overwriting rename fallback.

The helper deliberately performs no path-based deletion. Every verify-bundle
run retains its private randomized 0700 extraction tree beside the bundle; a
private randomized 0400 file or another 0700 staging tree can also remain.
Retry failures with a fresh output or destination and leave cleanup to
separately authorized administration.

The validator performs no network, Docker, container, or deployment action.
"""

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]{0,19}\Z")
_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}\Z")


class RuntimeReleaseBundleError(RuntimeError):
    """Stable, deliberately non-reflective bundle failure."""

    def __init__(self) -> None:
        super().__init__(ERROR_CODE)


def _invalid() -> NoReturn:
    raise RuntimeReleaseBundleError() from None


def _trusted_locations() -> tuple[Path, Path, Path]:
    prepare = Path(__file__).resolve()
    if prepare.parent.name == "scripts":
        release = prepare.parent / "private_server_runtime_release.py"
        schema = prepare.parent.parent / "deploy" / "private-server-runtime-release-v1.schema.json"
    else:
        release = prepare.parent / "private_server_runtime_release.py"
        schema = (
            prepare.parent.parent
            / "contracts"
            / "private-server-runtime-release-v1.schema.json"
        )
    return prepare, release, schema


PREPARE_PATH, RELEASE_PATH, SCHEMA_PATH = _trusted_locations()


def _bootstrap_source(path: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 < before.st_size <= MAX_TOOL_BYTES
            or _identity_bootstrap(before) != _identity_bootstrap(visible)
        ):
            _invalid()
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        if _identity_bootstrap(os.fstat(descriptor)) != _identity_bootstrap(before):
            _invalid()
        return b"".join(chunks)
    except RuntimeReleaseBundleError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _identity_bootstrap(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


PREPARE_SOURCE_RAW = _bootstrap_source(PREPARE_PATH)
RELEASE_SOURCE_RAW = _bootstrap_source(RELEASE_PATH)
SCHEMA_SOURCE_RAW = _bootstrap_source(SCHEMA_PATH)


def _load_release_module(raw: bytes) -> Any:
    name = "desire_private_server_runtime_release_bundle_contract"
    module = types.ModuleType(name)
    module.__file__ = str(RELEASE_PATH)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(raw, str(RELEASE_PATH), "exec")
        exec(code, module.__dict__)
    except Exception:
        _invalid()
    return module


RELEASE = _load_release_module(RELEASE_SOURCE_RAW)


def _canonical(value: Any) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeError):
        _invalid()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if type(key) is not str or key in result:
            _invalid()
        result[key] = value
    return result


def _reject_number(_value: str) -> NoReturn:
    _invalid()


def _json(raw: bytes, *, maximum: int, canonical: bool = False) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if not isinstance(value, dict) or (canonical and _canonical(value) != raw):
            _invalid()
        return value
    except RuntimeReleaseBundleError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _invalid()


def _closed(value: Any, keys: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _allowed(
    value: Any, *, required: Sequence[str], allowed: Sequence[str]
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not frozenset(required).issubset(value)
        or not frozenset(value).issubset(allowed)
    ):
        _invalid()
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        _invalid()
    return value


def _size(value: Any, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        _invalid()
    return value


def _descriptor(value: Any, maximum: int) -> dict[str, Any]:
    item = _allowed(
        value,
        required=("mediaType", "digest", "size"),
        allowed=(
            "mediaType",
            "digest",
            "size",
            "platform",
            "annotations",
            "artifactType",
            "urls",
            "data",
        ),
    )
    if type(item["mediaType"]) is not str or not item["mediaType"]:
        _invalid()
    _digest(item["digest"])
    _size(item["size"], maximum)
    if "platform" in item and not isinstance(item["platform"], dict):
        _invalid()
    if "annotations" in item and not isinstance(item["annotations"], dict):
        _invalid()
    if "artifactType" in item and type(item["artifactType"]) is not str:
        _invalid()
    if "urls" in item and not isinstance(item["urls"], list):
        _invalid()
    if "data" in item and type(item["data"]) is not str:
        _invalid()
    return item


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _safe_absolute(value: Path, *, leaf: bool) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        _invalid()
    if leaf and _LEAF.fullmatch(value.name) is None:
        _invalid()
    try:
        parent = value.parent.resolve(strict=True) if leaf else value.resolve(strict=True)
    except (OSError, RuntimeError):
        _invalid()
    if (leaf and parent != value.parent) or (not leaf and parent != value):
        _invalid()
    return value


@dataclass
class _OpenedFile:
    path: Path
    descriptor: int
    parent_descriptor: int
    identity: tuple[int, ...]
    parent_identity: tuple[int, ...]
    maximum: int

    @property
    def size(self) -> int:
        return self.identity[6]

    def recheck(self) -> None:
        try:
            opened = os.fstat(self.descriptor)
            visible = os.stat(
                self.path.name,
                dir_fd=self.parent_descriptor,
                follow_symlinks=False,
            )
            parent = os.fstat(self.parent_descriptor)
            parent_visible = os.stat(self.path.parent, follow_symlinks=False)
        except OSError:
            _invalid()
        if (
            _identity(opened) != self.identity
            or _identity(visible) != self.identity
            or _directory_identity(parent) != self.parent_identity
            or _directory_identity(parent_visible) != self.parent_identity
        ):
            _invalid()

    def read(self) -> bytes:
        self.recheck()
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            remaining = self.size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(self.descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    _invalid()
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(self.descriptor, 1):
                _invalid()
            os.lseek(self.descriptor, 0, os.SEEK_SET)
        except OSError:
            _invalid()
        self.recheck()
        return b"".join(chunks)

    def sha256(self) -> str:
        self.recheck()
        digest = hashlib.sha256()
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            remaining = self.size
            while remaining:
                chunk = os.read(self.descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    _invalid()
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(self.descriptor, 1):
                _invalid()
            os.lseek(self.descriptor, 0, os.SEEK_SET)
        except OSError:
            _invalid()
        self.recheck()
        return digest.hexdigest()

    def stream(self) -> io.BufferedReader:
        self.recheck()
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            return os.fdopen(os.dup(self.descriptor), "rb", closefd=True)
        except OSError:
            _invalid()

    def close(self) -> None:
        for descriptor in (self.descriptor, self.parent_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.descriptor = -1
        self.parent_descriptor = -1


def _open_file(value: Path, *, mode: int, maximum: int) -> _OpenedFile:
    path = _safe_absolute(value, leaf=True)
    parent_descriptor = -1
    descriptor = -1
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_descriptor = os.open(path.parent, flags)
        parent = os.fstat(parent_descriptor)
        parent_visible = os.stat(path.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
            or _directory_identity(parent) != _directory_identity(parent_visible)
        ):
            _invalid()
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        visible = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != mode
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= maximum
            or _identity(opened) != _identity(visible)
        ):
            _invalid()
        return _OpenedFile(
            path=path,
            descriptor=descriptor,
            parent_descriptor=parent_descriptor,
            identity=_identity(opened),
            parent_identity=_directory_identity(parent),
            maximum=maximum,
        )
    except RuntimeReleaseBundleError:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        _invalid()


def _safe_directory(value: Path, expected_names: set[str]) -> Path:
    path = _safe_absolute(value, leaf=False)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
        names = os.listdir(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_uid != os.geteuid()
            or _directory_identity(opened) != _directory_identity(visible)
            or len(names) != len(set(names))
            or set(names) != expected_names
        ):
            _invalid()
        return path
    except RuntimeReleaseBundleError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _artifact(raw: bytes | _OpenedFile) -> dict[str, Any]:
    if isinstance(raw, _OpenedFile):
        return {"sha256": raw.sha256(), "size": raw.size}
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


@dataclass(frozen=True)
class _AppEvidence:
    slot: str
    archive: _OpenedFile
    root_index_digest: str
    platform_manifest_digest: str
    config_digest: str
    sbom: bytes
    provenance: bytes


def _tar_blob(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    descriptor: Mapping[str, Any],
    *,
    maximum: int,
) -> bytes:
    digest = _digest(descriptor.get("digest"))
    size = _size(descriptor.get("size"), maximum)
    member = members.get("blobs/sha256/" + digest.removeprefix("sha256:"))
    if member is None or not member.isfile() or member.size != size:
        _invalid()
    extracted = archive.extractfile(member)
    if extracted is None:
        _invalid()
    try:
        raw = extracted.read(maximum + 1)
        if extracted.read(1):
            _invalid()
    except (OSError, tarfile.TarError):
        _invalid()
    finally:
        extracted.close()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
        _invalid()
    return raw


def _platform_matches(value: Any, architecture: str) -> bool:
    return (
        isinstance(value, dict)
        and value.get("os") == "linux"
        and value.get("architecture") == architecture
    )


def _parse_app_archive(
    slot: str, archive_file: _OpenedFile, *, architecture: str, image_tag: str
) -> _AppEvidence:
    stream = archive_file.stream()
    try:
        with stream, tarfile.open(fileobj=stream, mode="r:") as archive:
            raw_members = archive.getmembers()
            if not 3 <= len(raw_members) <= 1024:
                _invalid()
            members: dict[str, tarfile.TarInfo] = {}
            for member in raw_members:
                if member.name in members or member.pax_headers or member.issparse():
                    _invalid()
                members[member.name] = member
            layout_member = members.get("index.json")
            if (
                layout_member is None
                or not layout_member.isfile()
                or layout_member.size > MAX_DOCUMENT_BYTES
            ):
                _invalid()
            layout_stream = archive.extractfile(layout_member)
            if layout_stream is None:
                _invalid()
            try:
                layout_raw = layout_stream.read(MAX_DOCUMENT_BYTES + 1)
            finally:
                layout_stream.close()
            layout = _allowed(
                _json(layout_raw, maximum=MAX_DOCUMENT_BYTES),
                required=("schemaVersion", "mediaType", "manifests"),
                allowed=("schemaVersion", "mediaType", "manifests", "annotations"),
            )
            if layout["schemaVersion"] != 2 or layout["mediaType"] != OCI_INDEX:
                _invalid()
            if not isinstance(layout["manifests"], list) or len(layout["manifests"]) != 1:
                _invalid()
            root_descriptor = _descriptor(layout["manifests"][0], MAX_DOCUMENT_BYTES)
            annotations = root_descriptor.get("annotations")
            if (
                root_descriptor["mediaType"] != OCI_INDEX
                or "platform" in root_descriptor
                or not isinstance(annotations, dict)
                or annotations.get("io.containerd.image.name")
                != f"docker.io/library/{REPOSITORIES[slot]}:{image_tag}"
                or annotations.get("org.opencontainers.image.ref.name") != image_tag
            ):
                _invalid()
            root_raw = _tar_blob(
                archive, members, root_descriptor, maximum=MAX_DOCUMENT_BYTES
            )
            root = _allowed(
                _json(root_raw, maximum=MAX_DOCUMENT_BYTES),
                required=("schemaVersion", "mediaType", "manifests"),
                allowed=("schemaVersion", "mediaType", "manifests", "annotations"),
            )
            if (
                root["schemaVersion"] != 2
                or root["mediaType"] != OCI_INDEX
                or not isinstance(root["manifests"], list)
                or len(root["manifests"]) != 2
            ):
                _invalid()
            target: dict[str, Any] | None = None
            attestation: dict[str, Any] | None = None
            for raw_descriptor in root["manifests"]:
                descriptor = _descriptor(raw_descriptor, MAX_DOCUMENT_BYTES)
                platform = descriptor.get("platform")
                annotations = descriptor.get("annotations", {})
                if _platform_matches(platform, architecture):
                    if target is not None:
                        _invalid()
                    target = descriptor
                elif (
                    isinstance(platform, dict)
                    and platform.get("os") == "unknown"
                    and platform.get("architecture") == "unknown"
                    and isinstance(annotations, dict)
                    and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
                ):
                    if attestation is not None:
                        _invalid()
                    attestation = descriptor
                else:
                    _invalid()
            if target is None or attestation is None:
                _invalid()
            if (
                target["mediaType"] != OCI_MANIFEST
                or attestation["mediaType"] != OCI_MANIFEST
                or attestation.get("annotations", {}).get("vnd.docker.reference.digest")
                != target["digest"]
            ):
                _invalid()
            target_raw = _tar_blob(archive, members, target, maximum=MAX_DOCUMENT_BYTES)
            target_manifest = _allowed(
                _json(target_raw, maximum=MAX_DOCUMENT_BYTES),
                required=("schemaVersion", "mediaType", "config", "layers"),
                allowed=("schemaVersion", "mediaType", "config", "layers", "annotations"),
            )
            if (
                target_manifest["schemaVersion"] != 2
                or target_manifest["mediaType"] != OCI_MANIFEST
            ):
                _invalid()
            config = _descriptor(target_manifest["config"], MAX_DOCUMENT_BYTES)
            if config["mediaType"] != OCI_CONFIG:
                _invalid()
            _tar_blob(archive, members, config, maximum=MAX_DOCUMENT_BYTES)
            attestation_raw = _tar_blob(
                archive, members, attestation, maximum=MAX_DOCUMENT_BYTES
            )
            attestation_manifest = _allowed(
                _json(attestation_raw, maximum=MAX_DOCUMENT_BYTES),
                required=(
                    "schemaVersion",
                    "mediaType",
                    "artifactType",
                    "config",
                    "subject",
                    "layers",
                ),
                allowed=(
                    "schemaVersion",
                    "mediaType",
                    "artifactType",
                    "config",
                    "subject",
                    "layers",
                    "annotations",
                ),
            )
            subject = _descriptor(attestation_manifest["subject"], MAX_DOCUMENT_BYTES)
            if (
                attestation_manifest["schemaVersion"] != 2
                or attestation_manifest["mediaType"] != OCI_MANIFEST
                or attestation_manifest["artifactType"] != ATTESTATION_ARTIFACT
                or subject["digest"] != target["digest"]
                or subject["size"] != target["size"]
                or not isinstance(attestation_manifest["layers"], list)
                or len(attestation_manifest["layers"]) != 2
            ):
                _invalid()
            statements: dict[str, bytes] = {}
            for raw_layer in attestation_manifest["layers"]:
                layer = _descriptor(raw_layer, max(MAX_SBOM_BYTES, MAX_PROVENANCE_BYTES))
                annotations = layer.get("annotations")
                if layer["mediaType"] != IN_TOTO or not isinstance(annotations, dict):
                    _invalid()
                predicate = annotations.get("in-toto.io/predicate-type")
                if predicate == SPDX_PREDICATE:
                    kind, maximum = "sbom", MAX_SBOM_BYTES
                elif predicate == SLSA_V1_PREDICATE:
                    kind, maximum = "provenance", MAX_PROVENANCE_BYTES
                else:
                    _invalid()
                if kind in statements:
                    _invalid()
                statements[kind] = _tar_blob(archive, members, layer, maximum=maximum)
            if frozenset(statements) != frozenset(("sbom", "provenance")):
                _invalid()
            result = _AppEvidence(
                slot=slot,
                archive=archive_file,
                root_index_digest=root_descriptor["digest"],
                platform_manifest_digest=target["digest"],
                config_digest=config["digest"],
                sbom=statements["sbom"],
                provenance=statements["provenance"],
            )
    except RuntimeReleaseBundleError:
        raise
    except (OSError, ValueError, tarfile.TarError, EOFError):
        _invalid()
    archive_file.recheck()
    return result


@dataclass(frozen=True)
class _PostgresEvidence:
    files: Mapping[str, _OpenedFile]
    raw: Mapping[str, bytes]
    platform_manifest_digest: str
    config_digest: str


def _postgres_platform(architecture: str) -> dict[str, str]:
    if architecture == "amd64":
        return {"architecture": "amd64", "os": "linux"}
    return {"architecture": "arm64", "os": "linux", "variant": "v8"}


def _parse_postgres_evidence(
    directory: Path, *, architecture: str
) -> _PostgresEvidence:
    _safe_directory(directory, {*POSTGRES_FILES.values(), "evidence.json"})
    opened: dict[str, _OpenedFile] = {}
    try:
        limits = {
            "registry_index": MAX_DOCUMENT_BYTES,
            "platform_manifest": MAX_DOCUMENT_BYTES,
            "image_config": MAX_DOCUMENT_BYTES,
            "attestation_manifest": MAX_DOCUMENT_BYTES,
            "attestation_config": MAX_DOCUMENT_BYTES,
            "sbom": MAX_SBOM_BYTES,
            "provenance": MAX_PROVENANCE_BYTES,
        }
        for kind, name in POSTGRES_FILES.items():
            opened[kind] = _open_file(directory / name, mode=0o400, maximum=limits[kind])
        evidence_file = _open_file(
            directory / "evidence.json", mode=0o400, maximum=MAX_DOCUMENT_BYTES
        )
        opened["evidence"] = evidence_file
        raw = {kind: item.read() for kind, item in opened.items() if kind != "evidence"}
        root_digest = "sha256:" + hashlib.sha256(raw["registry_index"]).hexdigest()
        if root_digest != POSTGRES_ROOT_DIGEST:
            _invalid()
        root = _json(raw["registry_index"], maximum=MAX_DOCUMENT_BYTES)
        manifests = root.get("manifests")
        if (
            root.get("schemaVersion") != 2
            or root.get("mediaType") != OCI_INDEX
            or not isinstance(manifests, list)
        ):
            _invalid()
        target: dict[str, Any] | None = None
        attestations: list[dict[str, Any]] = []
        for value in manifests:
            descriptor = _descriptor(value, MAX_DOCUMENT_BYTES)
            platform = descriptor.get("platform")
            annotations = descriptor.get("annotations", {})
            if _platform_matches(platform, architecture):
                if target is not None:
                    _invalid()
                target = descriptor
            elif (
                isinstance(platform, dict)
                and platform.get("os") == "unknown"
                and platform.get("architecture") == "unknown"
                and isinstance(annotations, dict)
                and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
            ):
                attestations.append(descriptor)
        if target is None:
            _invalid()
        matching_attestations = [
            item
            for item in attestations
            if item.get("annotations", {}).get("vnd.docker.reference.digest")
            == target["digest"]
        ]
        if len(matching_attestations) != 1:
            _invalid()
        attestation = matching_attestations[0]
        if (
            target["digest"] != "sha256:" + hashlib.sha256(raw["platform_manifest"]).hexdigest()
            or target["size"] != len(raw["platform_manifest"])
            or attestation["digest"]
            != "sha256:" + hashlib.sha256(raw["attestation_manifest"]).hexdigest()
            or attestation["size"] != len(raw["attestation_manifest"])
            or attestation.get("annotations", {}).get("vnd.docker.reference.digest")
            != target["digest"]
        ):
            _invalid()
        platform_manifest = _json(raw["platform_manifest"], maximum=MAX_DOCUMENT_BYTES)
        config = _descriptor(platform_manifest.get("config"), MAX_DOCUMENT_BYTES)
        if (
            config["digest"] != "sha256:" + hashlib.sha256(raw["image_config"]).hexdigest()
            or config["size"] != len(raw["image_config"])
        ):
            _invalid()
        attestation_manifest = _json(raw["attestation_manifest"], maximum=MAX_DOCUMENT_BYTES)
        attestation_config = _descriptor(attestation_manifest.get("config"), MAX_DOCUMENT_BYTES)
        if (
            attestation_config["digest"]
            != "sha256:" + hashlib.sha256(raw["attestation_config"]).hexdigest()
            or attestation_config["size"] != len(raw["attestation_config"])
        ):
            _invalid()
        layers = attestation_manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != 2:
            _invalid()
        found: dict[str, dict[str, Any]] = {}
        for value in layers:
            layer = _descriptor(value, max(MAX_SBOM_BYTES, MAX_PROVENANCE_BYTES))
            annotations = layer.get("annotations")
            if layer["mediaType"] != IN_TOTO or not isinstance(annotations, dict):
                _invalid()
            predicate = annotations.get("in-toto.io/predicate-type")
            if predicate == SPDX_PREDICATE:
                kind = "sbom"
            elif predicate == SLSA_V02_PREDICATE:
                kind = "provenance"
            else:
                _invalid()
            if kind in found:
                _invalid()
            found[kind] = layer
        if frozenset(found) != frozenset(("sbom", "provenance")):
            _invalid()
        for kind in ("sbom", "provenance"):
            if (
                found[kind]["digest"] != "sha256:" + hashlib.sha256(raw[kind]).hexdigest()
                or found[kind]["size"] != len(raw[kind])
            ):
                _invalid()
        artifact_order = tuple(POSTGRES_FILES)
        expected_evidence = {
            "architecture": architecture,
            "artifacts": [
                {
                    "kind": POSTGRES_EVIDENCE_KINDS[kind],
                    "name": POSTGRES_FILES[kind],
                    "sha256": hashlib.sha256(raw[kind]).hexdigest(),
                    "size": len(raw[kind]),
                }
                for kind in artifact_order
            ],
            "attestation_manifest_digest": attestation["digest"],
            "authenticity_verified": False,
            "authority": POSTGRES_EVIDENCE_AUTHORITY,
            "config_digest": config["digest"],
            "execution_permitted": False,
            "format": POSTGRES_EVIDENCE_FORMAT,
            "platform_manifest_digest": target["digest"],
            "production_authorized": False,
            "reference": f"docker.io/library/postgres:18.4-alpine@{POSTGRES_ROOT_DIGEST}",
            "repository": "library/postgres",
            "root_index_digest": POSTGRES_ROOT_DIGEST,
            "signature_verified": False,
            "status": POSTGRES_EVIDENCE_STATUS,
            "target_platform": _postgres_platform(architecture),
        }
        evidence_raw = evidence_file.read()
        evidence = _json(evidence_raw, maximum=MAX_DOCUMENT_BYTES, canonical=True)
        if evidence != expected_evidence:
            _invalid()
        evidence_file.close()
        del opened["evidence"]
        return _PostgresEvidence(
            files={kind: opened[kind] for kind in POSTGRES_FILES},
            raw=raw,
            platform_manifest_digest=target["digest"],
            config_digest=config["digest"],
        )
    except Exception:
        for item in opened.values():
            item.close()
        raise


@dataclass(frozen=True)
class _SourceEvidence:
    snapshot: _OpenedFile
    dockerfile_set: _OpenedFile
    facts: _OpenedFile
    dockerfiles: Mapping[str, Any]


def _snapshot_member_count(snapshot: _OpenedFile) -> int:
    stream = snapshot.stream()
    try:
        with stream, tarfile.open(fileobj=stream, mode="r:") as archive:
            members = archive.getmembers()
            if not 0 < len(members) <= 200_000:
                _invalid()
            return len(members)
    except RuntimeReleaseBundleError:
        raise
    except (OSError, ValueError, tarfile.TarError, EOFError):
        _invalid()


def _parse_source_evidence(
    snapshot_path: Path,
    dockerfile_set_path: Path,
    facts_path: Path,
    *,
    commit: str,
) -> _SourceEvidence:
    opened: list[_OpenedFile] = []
    try:
        snapshot = _open_file(snapshot_path, mode=0o400, maximum=MAX_SOURCE_SNAPSHOT_BYTES)
        opened.append(snapshot)
        dockerfile_set = _open_file(dockerfile_set_path, mode=0o400, maximum=MAX_DOCUMENT_BYTES)
        opened.append(dockerfile_set)
        facts = _open_file(facts_path, mode=0o600, maximum=MAX_DOCUMENT_BYTES)
        opened.append(facts)
        dockerfile_raw = dockerfile_set.read()
        dockerfiles = _closed(
            _json(dockerfile_raw, maximum=MAX_DOCUMENT_BYTES, canonical=True), APP_SLOTS
        )
        for slot in APP_SLOTS:
            item = _closed(dockerfiles[slot], ("dockerfile_sha256", "target"))
            if (
                type(item["dockerfile_sha256"]) is not str
                or _SHA256.fullmatch(item["dockerfile_sha256"]) is None
            ):
                _invalid()
            if item["target"] != TARGETS[slot]:
                _invalid()
        facts_document = _closed(
            _json(facts.read(), maximum=MAX_DOCUMENT_BYTES, canonical=True),
            ("commit", "dockerfile_digest_set", "format", "snapshot", "tree_sha256"),
        )
        if facts_document["format"] != SOURCE_FACTS_FORMAT or facts_document["commit"] != commit:
            _invalid()
        tree_sha256 = facts_document["tree_sha256"]
        if type(tree_sha256) is not str or _SHA256.fullmatch(tree_sha256) is None:
            _invalid()
        dockerfile_fact = _closed(facts_document["dockerfile_digest_set"], ("sha256", "size"))
        snapshot_fact = _closed(facts_document["snapshot"], ("member_count", "sha256", "size"))
        actual_dockerfile = _artifact(dockerfile_raw)
        actual_snapshot = _artifact(snapshot)
        if (
            dockerfile_fact != actual_dockerfile
            or snapshot_fact.get("sha256") != actual_snapshot["sha256"]
            or snapshot_fact.get("size") != actual_snapshot["size"]
            or snapshot_fact.get("member_count") != _snapshot_member_count(snapshot)
        ):
            _invalid()
        return _SourceEvidence(
            snapshot=snapshot,
            dockerfile_set=dockerfile_set,
            facts=facts,
            dockerfiles=dockerfiles,
        )
    except Exception:
        for item in opened:
            item.close()
        raise


def _write_private_file(path: Path, raw: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        os.fchmod(descriptor, 0o400)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _invalid()
            view = view[written:]
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != len(raw)
        ):
            _invalid()
    except RuntimeReleaseBundleError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_all_artifacts(
    manifest: Any,
    source: _SourceEvidence,
    apps: Mapping[str, _AppEvidence],
    postgres: _PostgresEvidence,
) -> None:
    RELEASE.verify_runtime_release_source_artifact(
        manifest, artifact_kind="source_snapshot", artifact_file=source.snapshot.path
    )
    RELEASE.verify_runtime_release_source_artifact(
        manifest,
        artifact_kind="dockerfile_digest_set",
        artifact_file=source.dockerfile_set.path,
    )
    directory = Path(
        tempfile.mkdtemp(prefix="desire-runtime-statements-")
    ).resolve()
    directory.chmod(0o700)
    for slot in APP_SLOTS:
        app = apps[slot]
        RELEASE.verify_runtime_release_artifact(
            manifest,
            slot=slot,
            artifact_kind="oci_archive",
            artifact_file=app.archive.path,
        )
        for kind, raw in (("sbom", app.sbom), ("provenance", app.provenance)):
            path = directory / f"{slot}-{kind}.json"
            _write_private_file(path, raw)
            RELEASE.verify_runtime_release_artifact(
                manifest, slot=slot, artifact_kind=kind, artifact_file=path
            )
    for kind in POSTGRES_FILES:
        RELEASE.verify_runtime_release_artifact(
            manifest,
            slot="postgres",
            artifact_kind=kind,
            artifact_file=postgres.files[kind].path,
        )


@dataclass(frozen=True)
class BundleVerification:
    bundle_sha256: str
    release_id: str
    image_tag: str
    architecture: str
    manifest_sha256: str
    image_config_digests: tuple[tuple[str, str], ...]
    status: str = STATUS
    authority: str = AUTHORITY
    execution_permitted: bool = False
    production_authorized: bool = False


@dataclass(frozen=True)
class _BundleEntry:
    name: str
    directory: bool
    content: bytes | _OpenedFile | None


def _tar_info(entry: _BundleEntry) -> tarfile.TarInfo:
    info = tarfile.TarInfo(entry.name)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.devmajor = 0
    info.devminor = 0
    info.pax_headers = {}
    if entry.directory:
        info.type = tarfile.DIRTYPE
        info.mode = 0o700
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = 0o400
        if isinstance(entry.content, _OpenedFile):
            info.size = entry.content.size
        elif isinstance(entry.content, bytes):
            info.size = len(entry.content)
        else:
            _invalid()
    return info


def _output_parent(path: Path) -> tuple[int, tuple[int, ...]]:
    candidate = _safe_absolute(path, leaf=True)
    descriptor = -1
    try:
        descriptor = os.open(
            candidate.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        visible = os.stat(candidate.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_uid != os.geteuid()
            or _directory_identity(opened) != _directory_identity(visible)
        ):
            _invalid()
        try:
            os.stat(candidate.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _invalid()
        return descriptor, _directory_identity(opened)
    except RuntimeReleaseBundleError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _invalid()


def _write_bundle(
    path: Path, entries: Sequence[_BundleEntry]
) -> BundleVerification:
    if tuple(entry.name for entry in entries) != EXPECTED_MEMBERS:
        _invalid()
    parent_descriptor, parent_identity = _output_parent(path)
    descriptor = -1
    staging: Path | None = None
    staging_identity: tuple[int, ...] | None = None
    try:
        descriptor, staging_raw = tempfile.mkstemp(
            prefix=f"create-{path.name}-",
            dir=path.parent,
        )
        staging = Path(staging_raw).resolve()
        if staging.parent != path.parent:
            _invalid()
        os.fchmod(descriptor, 0o400)
        created = os.fstat(descriptor)
        visible_created = os.stat(
            staging.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        staging_identity = _identity(created)
        if (
            not stat.S_ISREG(created.st_mode)
            or stat.S_IMODE(created.st_mode) != 0o400
            or created.st_uid != os.geteuid()
            or created.st_nlink != 1
            or _identity(visible_created) != staging_identity
        ):
            _invalid()
        with os.fdopen(os.dup(descriptor), "wb", closefd=True) as stream:
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for entry in entries:
                    info = _tar_info(entry)
                    if entry.directory:
                        archive.addfile(info)
                    elif isinstance(entry.content, _OpenedFile):
                        entry.content.recheck()
                        with entry.content.stream() as source:
                            archive.addfile(info, source)
                        entry.content.recheck()
                    elif isinstance(entry.content, bytes):
                        archive.addfile(info, io.BytesIO(entry.content))
                    else:
                        _invalid()
            stream.flush()
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        visible = os.stat(
            staging.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        staging_identity = _identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= MAX_BUNDLE_BYTES
            or _identity(visible) != staging_identity
            or _directory_identity(os.fstat(parent_descriptor)) != parent_identity
        ):
            _invalid()
        verification = verify_bundle(staging)
        visible_verified = os.stat(
            staging.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _identity(os.fstat(descriptor)) != staging_identity
            or _identity(visible_verified) != staging_identity
        ):
            _invalid()
        _rename_no_replace(staging.name, path.name, parent_descriptor)
        os.fsync(parent_descriptor)
        published = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published_opened = os.fstat(descriptor)
        if (
            (published_opened.st_dev, published_opened.st_ino)
            != (staging_identity[0], staging_identity[1])
            or _identity(published) != _identity(published_opened)
            or _directory_identity(os.fstat(parent_descriptor)) != parent_identity
        ):
            _invalid()
        return verification
    except RuntimeReleaseBundleError:
        raise
    except Exception:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _manifest_document(
    *,
    release_id: str,
    image_tag: str,
    architecture: str,
    source: _SourceEvidence,
    apps: Mapping[str, _AppEvidence],
    postgres: _PostgresEvidence,
) -> dict[str, Any]:
    images: dict[str, Any] = {}
    for slot in APP_SLOTS:
        app = apps[slot]
        images[slot] = {
            "delivery_kind": "OCI_ARCHIVE",
            "reference": f"{REPOSITORIES[slot]}:{image_tag}@{app.root_index_digest}",
            "root_index_digest": app.root_index_digest,
            "platform_manifest_digest": app.platform_manifest_digest,
            "config_digest": app.config_digest,
            "oci_archive": _artifact(app.archive),
            "sbom": _artifact(app.sbom),
            "provenance": _artifact(app.provenance),
        }
    raw = postgres.raw
    images["postgres"] = {
        "delivery_kind": "PINNED_REGISTRY",
        "reference": RELEASE.POSTGRES_REFERENCE,
        "root_index_digest": RELEASE.POSTGRES_ROOT_INDEX_DIGEST,
        "platform_manifest_digest": postgres.platform_manifest_digest,
        "config_digest": postgres.config_digest,
        **{kind: _artifact(raw[kind]) for kind in POSTGRES_FILES},
    }
    return {
        "format": RELEASE.FORMAT,
        "status": RELEASE.STATUS,
        "authority": RELEASE.AUTHORITY,
        "execution_permitted": False,
        "production_authorized": False,
        "release_id": release_id,
        "image_tag": image_tag,
        "source": {
            "snapshot_kind": RELEASE.SOURCE_SNAPSHOT_KIND,
            "source_snapshot": _artifact(source.snapshot),
            "dockerfile_kind": RELEASE.DOCKERFILE_KIND,
            "dockerfiles": source.dockerfiles,
            "dockerfile_digest_set": _artifact(source.dockerfile_set),
        },
        "target_platform": {"os": "linux", "architecture": architecture},
        "schema_heads": dict(RELEASE.SCHEMA_HEADS),
        "images": images,
    }


def _bundle_entries(
    manifest_raw: bytes,
    source: _SourceEvidence,
    apps: Mapping[str, _AppEvidence],
    postgres: _PostgresEvidence,
) -> tuple[_BundleEntry, ...]:
    content: dict[str, bytes | _OpenedFile] = {
        "README.txt": README,
        "contracts/private-server-runtime-release-v1.schema.json": SCHEMA_SOURCE_RAW,
        "release.json": manifest_raw,
        "source/dockerfile-digest-set.json": source.dockerfile_set,
        "source/source-snapshot.tar": source.snapshot,
        "tools/prepare_private_server_runtime_release.py": PREPARE_SOURCE_RAW,
        "tools/private_server_runtime_release.py": RELEASE_SOURCE_RAW,
    }
    for slot in APP_SLOTS:
        content[f"images/{APP_ARCHIVE_FILES[slot]}"] = apps[slot].archive
        content[f"attestations/{slot}/sbom.intoto.json"] = apps[slot].sbom
        content[f"attestations/{slot}/provenance.intoto.json"] = apps[slot].provenance
    for kind, name in POSTGRES_FILES.items():
        content[f"postgres/{name}"] = postgres.raw[kind]
    if frozenset(content) != frozenset(FILE_MEMBERS):
        _invalid()
    return tuple(
        _BundleEntry(
            name=name,
            directory=name in DIRECTORY_MEMBERS,
            content=None if name in DIRECTORY_MEMBERS else content[name],
        )
        for name in EXPECTED_MEMBERS
    )


def _member_metadata(member: tarfile.TarInfo, *, directory: bool) -> None:
    if (
        member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != 0
        or member.devmajor != 0
        or member.devminor != 0
        or member.linkname
        or member.pax_headers
        or member.issparse()
    ):
        _invalid()
    if directory:
        if not member.isdir() or member.mode != 0o700 or member.size != 0:
            _invalid()
    elif not member.isfile() or member.mode != 0o400 or not 0 < member.size <= MAX_BUNDLE_BYTES:
        _invalid()


def _extract_file(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    path: Path,
    created_identities: dict[str, tuple[int, ...]] | None,
) -> None:
    stream = archive.extractfile(member)
    if stream is None:
        _invalid()
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        os.fchmod(descriptor, 0o400)
        remaining = member.size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                _invalid()
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _invalid()
                view = view[written:]
            remaining -= len(chunk)
        if stream.read(1):
            _invalid()
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != member.size
        ):
            _invalid()
    except RuntimeReleaseBundleError:
        raise
    except (OSError, tarfile.TarError):
        _invalid()
    finally:
        stream.close()
        if descriptor >= 0:
            if created_identities is not None:
                try:
                    opened = os.fstat(descriptor)
                    if (
                        stat.S_ISREG(opened.st_mode)
                        and stat.S_IMODE(opened.st_mode) == 0o400
                        and opened.st_uid == os.geteuid()
                        and opened.st_nlink == 1
                    ):
                        created_identities[member.name] = _identity(opened)
                except OSError:
                    pass
            os.close(descriptor)


def _verify_extracted(root: Path, bundle_sha256: str) -> BundleVerification:
    if (root / "README.txt").read_bytes() != README:
        _invalid()
    if (
        root / "contracts/private-server-runtime-release-v1.schema.json"
    ).read_bytes() != SCHEMA_SOURCE_RAW:
        _invalid()
    if (
        root / "tools/private_server_runtime_release.py"
    ).read_bytes() != RELEASE_SOURCE_RAW:
        _invalid()
    if (
        root / "tools/prepare_private_server_runtime_release.py"
    ).read_bytes() != PREPARE_SOURCE_RAW:
        _invalid()
    manifest_path = root / "release.json"
    manifest = RELEASE.validate_runtime_release_manifest_file(manifest_path)
    RELEASE.verify_runtime_release_source_artifact_file(
        manifest_path,
        artifact_kind="source_snapshot",
        artifact_file=root / "source/source-snapshot.tar",
    )
    RELEASE.verify_runtime_release_source_artifact_file(
        manifest_path,
        artifact_kind="dockerfile_digest_set",
        artifact_file=root / "source/dockerfile-digest-set.json",
    )
    for slot in APP_SLOTS:
        RELEASE.verify_runtime_release_artifact_file(
            manifest_path,
            slot=slot,
            artifact_kind="oci_archive",
            artifact_file=root / f"images/{APP_ARCHIVE_FILES[slot]}",
        )
        for kind in ("sbom", "provenance"):
            RELEASE.verify_runtime_release_artifact_file(
                manifest_path,
                slot=slot,
                artifact_kind=kind,
                artifact_file=root / f"attestations/{slot}/{kind}.intoto.json",
            )
    for kind, name in POSTGRES_FILES.items():
        RELEASE.verify_runtime_release_artifact_file(
            manifest_path,
            slot="postgres",
            artifact_kind=kind,
            artifact_file=root / f"postgres/{name}",
        )
    image_config_digests = {image.slot: image.config_digest for image in manifest.images}
    if set(image_config_digests) != {*APP_SLOTS, "postgres"}:
        _invalid()
    return BundleVerification(
        bundle_sha256=bundle_sha256,
        release_id=manifest.release_id,
        image_tag=manifest.image_tag,
        architecture=manifest.target_architecture,
        manifest_sha256=manifest.sha256,
        image_config_digests=tuple(
            (slot, image_config_digests[slot]) for slot in APP_SLOTS
        ),
    )


def _extract_opened_bundle(
    opened: _OpenedFile,
    root: Path,
    bundle_sha256: str,
    created_identities: dict[str, tuple[int, ...]] | None = None,
) -> BundleVerification:
    try:
        visible_root = os.stat(root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(visible_root.st_mode)
            or stat.S_IMODE(visible_root.st_mode) != 0o700
            or visible_root.st_uid != os.geteuid()
            or any(root.iterdir())
        ):
            _invalid()
        stream = opened.stream()
        with stream, tarfile.open(fileobj=stream, mode="r:") as archive:
            members = archive.getmembers()
            names = tuple(member.name for member in members)
            if (
                not 0 < len(members) <= MAX_MEMBERS
                or len(names) != len(set(names))
                or names != EXPECTED_MEMBERS
            ):
                _invalid()
            expected_offset = 0
            for member in members:
                if (
                    type(member.offset) is not int
                    or type(member.offset_data) is not int
                    or type(member.size) is not int
                    or member.size < 0
                    or member.offset != expected_offset
                    or member.offset_data != member.offset + 512
                    or os.pread(
                        opened.descriptor, 8, member.offset + 257
                    )
                    != b"ustar\x0000"
                ):
                    _invalid()
                is_directory = member.name in DIRECTORY_MEMBERS
                _member_metadata(member, directory=is_directory)
                next_offset = member.offset_data + (
                    (member.size + 511) // 512
                ) * 512
                if next_offset > opened.size:
                    _invalid()
                padding_start = member.offset_data + member.size
                padding_size = next_offset - padding_start
                if padding_size:
                    padding = os.pread(
                        opened.descriptor, padding_size, padding_start
                    )
                    if len(padding) != padding_size or any(padding):
                        _invalid()
                destination = root / member.name
                if is_directory:
                    destination.mkdir(mode=0o700)
                    destination.chmod(0o700)
                    visible = os.stat(destination, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(visible.st_mode)
                        or stat.S_IMODE(visible.st_mode) != 0o700
                        or visible.st_uid != os.geteuid()
                    ):
                        _invalid()
                    if created_identities is not None:
                        created_identities[member.name] = _directory_identity(visible)
                else:
                    _extract_file(
                        archive,
                        member,
                        destination,
                        created_identities,
                    )
                expected_offset = next_offset
        trailing = opened.size - expected_offset
        if trailing < 1024 or trailing % 512 != 0:
            _invalid()
        position = expected_offset
        while position < opened.size:
            chunk = os.pread(
                opened.descriptor,
                min(1024 * 1024, opened.size - position),
                position,
            )
            if not chunk or any(chunk):
                _invalid()
            position += len(chunk)
    except RuntimeReleaseBundleError:
        raise
    except (OSError, RuntimeError, ValueError, tarfile.TarError, EOFError):
        _invalid()
    opened.recheck()
    try:
        return _verify_extracted(root, bundle_sha256)
    except RuntimeReleaseBundleError:
        raise
    except Exception:
        _invalid()


def verify_bundle(bundle: Path) -> BundleVerification:
    """Validate one immutable bundle without network, execution, or deployment."""

    opened = _open_file(bundle, mode=0o400, maximum=MAX_BUNDLE_BYTES)
    try:
        bundle_sha256 = opened.sha256()
        root = Path(
            tempfile.mkdtemp(
                prefix=f".{opened.path.name}.verify-",
                dir=opened.path.parent,
            )
        ).resolve()
        if root.parent != opened.path.parent:
            _invalid()
        root.chmod(0o700)
        return _extract_opened_bundle(opened, root, bundle_sha256)
    finally:
        opened.close()


def _stage_parent(destination: Path) -> tuple[int, tuple[int, ...]]:
    if (
        not isinstance(destination, Path)
        or not destination.is_absolute()
        or ".." in destination.parts
        or _LEAF.fullmatch(destination.name) is None
    ):
        _invalid()
    descriptor = -1
    try:
        if destination.parent.resolve(strict=True) != destination.parent:
            _invalid()
        descriptor = os.open(
            destination.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        visible = os.stat(destination.parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_uid != os.geteuid()
            or _directory_identity(opened) != _directory_identity(visible)
        ):
            os.close(descriptor)
            _invalid()
        try:
            os.stat(destination.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            os.close(descriptor)
            _invalid()
        return descriptor, _directory_identity(opened)
    except RuntimeReleaseBundleError:
        raise
    except (OSError, RuntimeError):
        if descriptor >= 0:
            os.close(descriptor)
        _invalid()


def _open_relative_directory(
    root_descriptor: int,
    components: Sequence[str],
    *,
    expected_identities: Mapping[str, tuple[int, ...]] | None = None,
) -> int:
    descriptor = -1
    traversed: list[str] = []
    try:
        descriptor = os.dup(root_descriptor)
        for component in components:
            parent_descriptor = descriptor
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(next_descriptor)
            visible = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            traversed.append(component)
            expected = (
                None
                if expected_identities is None
                else expected_identities.get("/".join(traversed))
            )
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o700
                or opened.st_uid != os.geteuid()
                or _directory_identity(opened) != _directory_identity(visible)
                or (
                    expected_identities is not None
                    and (
                        expected is None
                        or _directory_identity(opened) != expected
                    )
                )
            ):
                os.close(next_descriptor)
                os.close(parent_descriptor)
                _invalid()
            os.close(parent_descriptor)
            descriptor = next_descriptor
        return descriptor
    except FileNotFoundError:
        if descriptor >= 0:
            os.close(descriptor)
        _invalid()
    except RuntimeReleaseBundleError:
        raise
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _invalid()


def _recheck_created_tree(
    root_descriptor: int,
    created_identities: Mapping[str, tuple[int, ...]],
) -> None:
    if frozenset(created_identities) != frozenset(EXPECTED_MEMBERS):
        _invalid()
    try:
        if frozenset(os.listdir(root_descriptor)) != EXPECTED_CHILDREN[""]:
            _invalid()
    except RuntimeReleaseBundleError:
        raise
    except OSError:
        _invalid()
    for name in DIRECTORY_MEMBERS:
        descriptor = _open_relative_directory(
            root_descriptor,
            name.split("/"),
            expected_identities=created_identities,
        )
        try:
            if frozenset(os.listdir(descriptor)) != EXPECTED_CHILDREN[name]:
                _invalid()
        finally:
            os.close(descriptor)
    for name in FILE_MEMBERS:
        components = name.split("/")
        directory_descriptor = _open_relative_directory(
            root_descriptor,
            components[:-1],
            expected_identities=created_identities,
        )
        descriptor = -1
        try:
            descriptor = os.open(
                components[-1],
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            opened = os.fstat(descriptor)
            visible = os.stat(
                components[-1],
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o400
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or _identity(opened) != created_identities[name]
                or _identity(visible) != created_identities[name]
            ):
                _invalid()
        except RuntimeReleaseBundleError:
            raise
        except OSError:
            _invalid()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_descriptor)


def _rename_no_replace(source: str, destination: str, directory_descriptor: int) -> None:
    """Atomically rename a directory only when the destination is absent."""

    try:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            function = library.renameat2
            flag = 1  # RENAME_NOREPLACE
        elif sys.platform == "darwin":
            function = library.renameatx_np
            flag = 0x00000004  # RENAME_EXCL
        else:
            _invalid()
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        function.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = function(
            directory_descriptor,
            os.fsencode(source),
            directory_descriptor,
            os.fsencode(destination),
            flag,
        )
    except RuntimeReleaseBundleError:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        _invalid()
    if result != 0:
        _invalid()


def stage_bundle(bundle: Path, destination: Path) -> BundleVerification:
    """Validate once, then atomically expose a private staged release directory."""

    opened = _open_file(bundle, mode=0o400, maximum=MAX_BUNDLE_BYTES)
    parent_descriptor = -1
    staging_descriptor = -1
    staging: Path | None = None
    staging_identity: tuple[int, ...] | None = None
    created_identities: dict[str, tuple[int, ...]] = {}
    try:
        bundle_sha256 = opened.sha256()
        parent_descriptor, parent_identity = _stage_parent(destination)
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.stage-",
                dir=destination.parent,
            )
        ).resolve()
        if staging.parent != destination.parent:
            _invalid()
        staging_descriptor = os.open(
            staging.name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        os.fchmod(staging_descriptor, 0o700)
        opened_staging = os.fstat(staging_descriptor)
        visible_staging = os.stat(
            staging.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        staging_identity = _directory_identity(opened_staging)
        if (
            not stat.S_ISDIR(opened_staging.st_mode)
            or stat.S_IMODE(opened_staging.st_mode) != 0o700
            or opened_staging.st_uid != os.geteuid()
            or _directory_identity(visible_staging) != staging_identity
        ):
            _invalid()
        result = _extract_opened_bundle(
            opened,
            staging,
            bundle_sha256,
            created_identities,
        )
        opened.recheck()
        _recheck_created_tree(staging_descriptor, created_identities)
        visible_staging = os.stat(
            staging.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            _directory_identity(os.fstat(parent_descriptor)) != parent_identity
            or _directory_identity(os.fstat(staging_descriptor)) != staging_identity
            or _directory_identity(visible_staging) != staging_identity
        ):
            _invalid()
        _rename_no_replace(
            staging.name,
            destination.name,
            parent_descriptor,
        )
        os.fsync(parent_descriptor)
        visible = os.stat(destination.name, dir_fd=parent_descriptor, follow_symlinks=False)
        published_opened = os.fstat(staging_descriptor)
        published_identity = _identity(published_opened)
        if (
            not stat.S_ISDIR(visible.st_mode)
            or stat.S_IMODE(visible.st_mode) != 0o700
            or visible.st_uid != os.geteuid()
            or _directory_identity(visible) != staging_identity
            or _directory_identity(published_opened) != staging_identity
            or _identity(visible) != published_identity
        ):
            _invalid()
        _recheck_created_tree(staging_descriptor, created_identities)
        final_visible = os.stat(
            destination.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        final_opened = os.fstat(staging_descriptor)
        if (
            _identity(final_visible) != published_identity
            or _identity(final_opened) != published_identity
            or _directory_identity(os.fstat(parent_descriptor)) != parent_identity
        ):
            _invalid()
        return result
    except RuntimeReleaseBundleError:
        raise
    except (OSError, RuntimeError):
        _invalid()
    finally:
        opened.close()
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def prepare_runtime_release(
    *,
    architecture: str,
    commit: str,
    run_id: str,
    run_attempt: str,
    source_snapshot: Path,
    source_dockerfile_set: Path,
    source_facts: Path,
    images_directory: Path,
    postgres_directory: Path,
    output: Path,
) -> BundleVerification:
    """Create one deterministic, closed, validated, non-authority USTAR bundle."""

    if (
        architecture not in ("amd64", "arm64")
        or _SHA40.fullmatch(commit) is None
        or _POSITIVE_INTEGER.fullmatch(run_id) is None
        or _POSITIVE_INTEGER.fullmatch(run_attempt) is None
    ):
        _invalid()
    image_tag = f"sha-{commit}-{architecture}-r{run_id}-a{run_attempt}"
    release_id = "runtime-release-" + image_tag
    source: _SourceEvidence | None = None
    apps: dict[str, _AppEvidence] = {}
    postgres: _PostgresEvidence | None = None
    try:
        source = _parse_source_evidence(
            source_snapshot,
            source_dockerfile_set,
            source_facts,
            commit=commit,
        )
        images_directory = _safe_directory(
            images_directory, set(APP_ARCHIVE_FILES.values())
        )
        for slot, name in APP_ARCHIVE_FILES.items():
            archive = _open_file(
                images_directory / name,
                mode=0o400,
                maximum=MAX_OCI_ARCHIVE_BYTES,
            )
            try:
                apps[slot] = _parse_app_archive(
                    slot, archive, architecture=architecture, image_tag=image_tag
                )
            except Exception:
                archive.close()
                raise
        postgres = _parse_postgres_evidence(
            postgres_directory, architecture=architecture
        )
        document = _manifest_document(
            release_id=release_id,
            image_tag=image_tag,
            architecture=architecture,
            source=source,
            apps=apps,
            postgres=postgres,
        )
        manifest_raw = RELEASE.create_runtime_release_manifest(document)
        manifest = RELEASE.validate_runtime_release_manifest(manifest_raw)
        _verify_all_artifacts(manifest, source, apps, postgres)
        result = _write_bundle(
            output,
            _bundle_entries(manifest_raw, source, apps, postgres),
        )
        if result.release_id != release_id or result.image_tag != image_tag:
            _invalid()
        return result
    except RuntimeReleaseBundleError:
        raise
    except Exception:
        _invalid()
    finally:
        if source is not None:
            source.snapshot.close()
            source.dockerfile_set.close()
            source.facts.close()
        for app in apps.values():
            app.archive.close()
        if postgres is not None:
            for item in postgres.files.values():
                item.close()


def _emit(stream: Any, value: Mapping[str, Any]) -> None:
    stream.write(_canonical(value).decode("ascii"))


def _failure() -> int:
    _emit(
        sys.stderr,
        {
            "authority": AUTHORITY,
            "code": ERROR_CODE,
            "execution_permitted": False,
            "production_authorized": False,
            "status": "BLOCKED",
        },
    )
    return 78


def main(arguments: Sequence[str] | None = None) -> int:
    values = tuple(sys.argv[1:] if arguments is None else arguments)
    try:
        if (
            len(values) == 5
            and values[0] == "stage-bundle"
            and values[1] == "--bundle"
            and values[3] == "--destination"
        ):
            result = stage_bundle(Path(values[2]), Path(values[4]))
            _emit(
                sys.stdout,
                {
                    "authority": result.authority,
                    "bundle_sha256": result.bundle_sha256,
                    "execution_permitted": result.execution_permitted,
                    "image_config_digests": dict(result.image_config_digests),
                    "manifest_sha256": result.manifest_sha256,
                    "production_authorized": result.production_authorized,
                    "release_id": result.release_id,
                    "status": "BUNDLE_STAGED_VALIDATED_NOT_AUTHORITY",
                },
            )
            return 0
        if (
            len(values) == 3
            and values[0] == "verify-bundle"
            and values[1] == "--bundle"
        ):
            result = verify_bundle(Path(values[2]))
            _emit(
                sys.stdout,
                {
                    "authority": result.authority,
                    "bundle_sha256": result.bundle_sha256,
                    "execution_permitted": result.execution_permitted,
                    "image_config_digests": dict(result.image_config_digests),
                    "manifest_sha256": result.manifest_sha256,
                    "production_authorized": result.production_authorized,
                    "release_id": result.release_id,
                    "status": "BUNDLE_VALIDATED_NOT_AUTHORITY",
                },
            )
            return 0
        expected = (
            "--architecture",
            "--commit",
            "--run-id",
            "--run-attempt",
            "--source-snapshot",
            "--source-dockerfile-set",
            "--source-facts",
            "--images-dir",
            "--postgres-dir",
            "--output",
        )
        if len(values) == 20 and tuple(values[index] for index in range(0, 20, 2)) == expected:
            result = prepare_runtime_release(
                architecture=values[1],
                commit=values[3],
                run_id=values[5],
                run_attempt=values[7],
                source_snapshot=Path(values[9]),
                source_dockerfile_set=Path(values[11]),
                source_facts=Path(values[13]),
                images_directory=Path(values[15]),
                postgres_directory=Path(values[17]),
                output=Path(values[19]),
            )
            _emit(
                sys.stdout,
                {
                    "authority": result.authority,
                    "bundle_sha256": result.bundle_sha256,
                    "execution_permitted": result.execution_permitted,
                    "image_config_digests": dict(result.image_config_digests),
                    "manifest_sha256": result.manifest_sha256,
                    "production_authorized": result.production_authorized,
                    "release_id": result.release_id,
                    "status": "BUNDLE_CREATED_VALIDATED_NOT_AUTHORITY",
                },
            )
            return 0
        return _failure()
    except Exception:
        return _failure()


if __name__ == "__main__":
    raise SystemExit(main())
