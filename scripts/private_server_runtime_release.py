#!/usr/bin/env python3
"""Closed, offline bindings for a private-server runtime release.

The contract binds immutable release content and nothing else.  It cannot
start containers, contact a registry, deploy a release, or grant production
authority.  All filesystem entry points require owner-only, descriptor-safe
files beneath an owner-only directory.  Content validation is deliberately
unsigned and untrusted: it never proves attestation authenticity.
"""

from __future__ import annotations

import base64
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
import unicodedata
from types import MappingProxyType
from typing import Any, Mapping, NoReturn, Sequence


FORMAT = "desire-private-server-runtime-release-v1"
STATUS = "VALIDATED_RELEASE_ARTIFACT_NOT_AUTHORITY"
AUTHORITY = "NOT_AUTHORITY"
ERROR_CODE = "PRIVATE_SERVER_RUNTIME_RELEASE_INVALID"

MAX_DOCUMENT_BYTES = 256 * 1024
MAX_OCI_ARCHIVE_BYTES = 32 * 1024 * 1024 * 1024
MAX_SBOM_BYTES = 64 * 1024 * 1024
MAX_PROVENANCE_BYTES = 16 * 1024 * 1024
MAX_REGISTRY_METADATA_BYTES = 16 * 1024 * 1024
MAX_OCI_JSON_BYTES = 16 * 1024 * 1024
MAX_OCI_MEMBERS = 1024
MAX_SOURCE_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
MAX_SOURCE_MEMBERS = 200000
MAX_DOCKERFILE_DIGEST_SET_BYTES = 256 * 1024

SOURCE_SNAPSHOT_KIND = "NORMALIZED_SOURCE_SNAPSHOT_TAR_V1"
DOCKERFILE_KIND = "CANONICAL_DOCKERFILE_DIGEST_SET_V1"
SOURCE_SNAPSHOT_DEFINITION = (
    "SHA-256 of the complete uncompressed POSIX ustar source snapshot: every "
    "build-context directory, regular file, and safe internal relative symlink exactly "
    "once; NFC UTF-8 portable names and link targets sorted bytewise; links remain "
    "inside the snapshot and are acyclic; no PAX records, devices, or VCS metadata; "
    "uid, gid, and mtime zero; uname and gname empty; regular files use mode 0644 or "
    "0755 according to the Git executable bit, directories use 0755, and symlinks use "
    "0777; terminal 512-byte blocks contain only zeroes"
)
DOCKERFILE_DIGEST_DEFINITION = (
    "SHA-256 of newline-terminated canonical JSON mapping each OCI application slot "
    "to the exact Dockerfile SHA-256 and fixed BuildKit target name"
)

IMAGE_SLOTS = (
    "platform",
    "web",
    "edge",
    "oidc-egress-guard",
    "postgres",
)
OCI_IMAGE_SLOTS = IMAGE_SLOTS[:-1]
_IMAGE_REPOSITORIES = MappingProxyType(
    {
        "platform": "desire-supply-platform",
        "web": "desire-supply-web",
        "edge": "desire-supply-edge",
        "oidc-egress-guard": "desire-supply-oidc-egress-guard",
    }
)
DOCKERFILE_TARGETS = MappingProxyType(
    {
        "platform": "platform-runtime",
        "web": "web-runtime",
        "edge": "edge-runtime",
        "oidc-egress-guard": "oidc-egress-guard-runtime",
    }
)
DOCKERFILE_SNAPSHOT_MEMBER = "Dockerfile"
SCHEMA_HEADS = MappingProxyType(
    {
        "postgresql": 18,
        "iam": 46,
        "profile": 5,
        "demand": 15,
        "trust": 22,
        "matching": 3,
        "taxonomy": 2,
    }
)
POSTGRES_ROOT_INDEX_DIGEST = (
    "sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
POSTGRES_REFERENCE = "postgres:18.4-alpine@" + POSTGRES_ROOT_INDEX_DIGEST

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELEASE_ID = re.compile(r"^runtime-release-[a-z0-9][a-z0-9._-]{0,95}$")
_IMAGE_TAG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}$")
_LEAF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_FORBIDDEN_FIELD_NAMES = frozenset(
    (
        "arg",
        "args",
        "argument",
        "arguments",
        "argv",
        "command",
        "commands",
        "cwd",
        "docker_socket",
        "endpoint",
        "env",
        "environment",
        "path",
        "paths",
        "secret",
        "secrets",
        "socket",
        "socket_path",
        "working_directory",
    )
)
_ARTIFACT_MAXIMUMS = MappingProxyType(
    {
        "oci_archive": MAX_OCI_ARCHIVE_BYTES,
        "registry_index": MAX_REGISTRY_METADATA_BYTES,
        "platform_manifest": MAX_REGISTRY_METADATA_BYTES,
        "image_config": MAX_REGISTRY_METADATA_BYTES,
        "attestation_manifest": MAX_REGISTRY_METADATA_BYTES,
        "attestation_config": MAX_REGISTRY_METADATA_BYTES,
        "sbom": MAX_SBOM_BYTES,
        "provenance": MAX_PROVENANCE_BYTES,
        "source_snapshot": MAX_SOURCE_SNAPSHOT_BYTES,
        "dockerfile_digest_set": MAX_DOCKERFILE_DIGEST_SET_BYTES,
    }
)
_OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
_OCI_LAYER_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
    )
)
_IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
_SPDX_PREDICATE = "https://spdx.dev/Document"
_SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
_ATTESTATION_ARTIFACT_TYPE = (
    "application/vnd.docker.attestation.manifest.v1+json"
)
_OCI_EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"
_OCI_EMPTY_CONFIG_DIGEST = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)


class RuntimeReleaseContractError(RuntimeError):
    """Stable, non-reflective failure for invalid release input."""

    def __init__(self) -> None:
        super().__init__(ERROR_CODE)


@dataclass(frozen=True, repr=False)
class ArtifactBinding:
    """One immutable, size-bounded release artifact."""

    kind: str
    sha256: str
    size: int


@dataclass(frozen=True, repr=False)
class RuntimeImageBinding:
    """Safe immutable projection of one validated image binding."""

    slot: str
    delivery_kind: str
    reference: str
    root_index_digest: str
    platform_manifest_digest: str
    config_digest: str
    artifacts: tuple[ArtifactBinding, ...]


@dataclass(frozen=True, repr=False)
class RuntimeReleaseManifest:
    """Safe immutable projection of a canonical non-authority manifest."""

    raw: bytes
    sha256: str
    release_id: str
    image_tag: str
    source_snapshot_sha256: str
    dockerfile_sha256: str
    dockerfiles: tuple[tuple[str, str, str], ...]
    source_artifacts: tuple[ArtifactBinding, ...]
    target_os: str
    target_architecture: str
    schema_heads: tuple[tuple[str, int], ...]
    images: tuple[RuntimeImageBinding, ...]
    status: str
    authority: str
    execution_permitted: bool
    production_authorized: bool


@dataclass(frozen=True, repr=False)
class VerifiedRuntimeArtifact:
    """Digest result which remains explicitly non-authoritative."""

    slot: str
    artifact_kind: str
    sha256: str
    size: int
    status: str
    authority: str


def _invalid() -> NoReturn:
    raise RuntimeReleaseContractError()


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if not isinstance(key, str) or key in result:
            _invalid()
        result[key] = value
    return result


def _reject_number(_value: str) -> NoReturn:
    _invalid()


def _canonical(value: Any) -> bytes:
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return (serialized + "\n").encode("ascii")
    except RuntimeReleaseContractError:
        raise
    except (TypeError, ValueError, UnicodeError):
        _invalid()


def _parse(raw: bytes, *, require_canonical: bool) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_DOCUMENT_BYTES:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if not isinstance(value, dict):
            _invalid()
        if require_canonical and _canonical(value) != raw:
            _invalid()
        return value
    except RuntimeReleaseContractError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _invalid()


def _closed(value: Any, keys: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _scan_forbidden_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_FIELD_NAMES:
                _invalid()
            _scan_forbidden_fields(item)
    elif isinstance(value, list):
        for item in value:
            _scan_forbidden_fields(item)


def _constant(value: Any, expected: Any) -> None:
    if type(value) is not type(expected) or value != expected:
        _invalid()


def _validated_string(value: Any, expression: re.Pattern[str]) -> str:
    if not isinstance(value, str) or expression.fullmatch(value) is None:
        _invalid()
    return value


def _validated_sha256(value: Any) -> str:
    return _validated_string(value, _SHA256)


def _validated_image_digest(value: Any) -> str:
    return _validated_string(value, _IMAGE_DIGEST)


def _validated_size(value: Any, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        _invalid()
    return value


def _artifact_binding(value: Any, kind: str) -> ArtifactBinding:
    item = _closed(value, ("sha256", "size"))
    maximum = _ARTIFACT_MAXIMUMS.get(kind)
    if maximum is None:
        _invalid()
    binding = ArtifactBinding(
        kind=kind,
        sha256=_validated_sha256(item["sha256"]),
        size=_validated_size(item["size"], maximum),
    )
    if kind == "source_snapshot" and binding.size < 1024:
        _invalid()
    return binding


def _validate_document(document: Any, raw: bytes) -> RuntimeReleaseManifest:
    _scan_forbidden_fields(document)
    root = _closed(
        document,
        (
            "format",
            "status",
            "authority",
            "execution_permitted",
            "production_authorized",
            "release_id",
            "image_tag",
            "source",
            "target_platform",
            "schema_heads",
            "images",
        ),
    )
    _constant(root["format"], FORMAT)
    _constant(root["status"], STATUS)
    _constant(root["authority"], AUTHORITY)
    _constant(root["execution_permitted"], False)
    _constant(root["production_authorized"], False)
    release_id = _validated_string(root["release_id"], _RELEASE_ID)
    image_tag = _validated_string(root["image_tag"], _IMAGE_TAG)

    source = _closed(
        root["source"],
        (
            "snapshot_kind",
            "source_snapshot",
            "dockerfile_kind",
            "dockerfiles",
            "dockerfile_digest_set",
        ),
    )
    _constant(source["snapshot_kind"], SOURCE_SNAPSHOT_KIND)
    _constant(source["dockerfile_kind"], DOCKERFILE_KIND)
    source_snapshot_binding = _artifact_binding(
        source["source_snapshot"], "source_snapshot"
    )
    dockerfile_binding = _artifact_binding(
        source["dockerfile_digest_set"], "dockerfile_digest_set"
    )
    dockerfile_documents = _closed(source["dockerfiles"], OCI_IMAGE_SLOTS)
    dockerfiles: list[tuple[str, str, str]] = []
    for slot in OCI_IMAGE_SLOTS:
        dockerfile = _closed(
            dockerfile_documents[slot], ("dockerfile_sha256", "target")
        )
        digest = _validated_sha256(dockerfile["dockerfile_sha256"])
        _constant(dockerfile["target"], DOCKERFILE_TARGETS[slot])
        dockerfiles.append((slot, digest, dockerfile["target"]))
    if len({item[1] for item in dockerfiles}) != 1:
        _invalid()
    canonical_dockerfiles = _canonical(dockerfile_documents)
    _constant(dockerfile_binding.sha256, hashlib.sha256(canonical_dockerfiles).hexdigest())
    _constant(dockerfile_binding.size, len(canonical_dockerfiles))
    source_snapshot_sha256 = source_snapshot_binding.sha256
    dockerfile_sha256 = dockerfile_binding.sha256

    target = _closed(root["target_platform"], ("os", "architecture"))
    _constant(target["os"], "linux")
    if target["architecture"] not in ("amd64", "arm64"):
        _invalid()
    target_architecture = target["architecture"]

    heads = _closed(root["schema_heads"], tuple(SCHEMA_HEADS))
    for name, expected in SCHEMA_HEADS.items():
        _constant(heads[name], expected)

    image_documents = _closed(root["images"], IMAGE_SLOTS)
    image_bindings: list[RuntimeImageBinding] = []
    for slot in OCI_IMAGE_SLOTS:
        image = _closed(
            image_documents[slot],
            (
                "delivery_kind",
                "reference",
                "root_index_digest",
                "platform_manifest_digest",
                "config_digest",
                "oci_archive",
                "sbom",
                "provenance",
            ),
        )
        _constant(image["delivery_kind"], "OCI_ARCHIVE")
        root_index_digest = _validated_image_digest(image["root_index_digest"])
        platform_manifest_digest = _validated_image_digest(
            image["platform_manifest_digest"]
        )
        config_digest = _validated_image_digest(image["config_digest"])
        expected_reference = (
            f"{_IMAGE_REPOSITORIES[slot]}:{image_tag}@{root_index_digest}"
        )
        _constant(image["reference"], expected_reference)
        image_bindings.append(
            RuntimeImageBinding(
                slot=slot,
                delivery_kind="OCI_ARCHIVE",
                reference=expected_reference,
                root_index_digest=root_index_digest,
                platform_manifest_digest=platform_manifest_digest,
                config_digest=config_digest,
                artifacts=(
                    _artifact_binding(image["oci_archive"], "oci_archive"),
                    _artifact_binding(image["sbom"], "sbom"),
                    _artifact_binding(image["provenance"], "provenance"),
                ),
            )
        )

    postgres = _closed(
        image_documents["postgres"],
        (
            "delivery_kind",
            "reference",
            "root_index_digest",
            "platform_manifest_digest",
            "config_digest",
            "registry_index",
            "platform_manifest",
            "image_config",
            "attestation_manifest",
            "attestation_config",
            "sbom",
            "provenance",
        ),
    )
    _constant(postgres["delivery_kind"], "PINNED_REGISTRY")
    _constant(postgres["reference"], POSTGRES_REFERENCE)
    _constant(postgres["root_index_digest"], POSTGRES_ROOT_INDEX_DIGEST)
    postgres_platform_manifest_digest = _validated_image_digest(
        postgres["platform_manifest_digest"]
    )
    postgres_config_digest = _validated_image_digest(postgres["config_digest"])
    postgres_registry_index = _artifact_binding(
        postgres["registry_index"], "registry_index"
    )
    postgres_platform_manifest = _artifact_binding(
        postgres["platform_manifest"], "platform_manifest"
    )
    postgres_image_config = _artifact_binding(
        postgres["image_config"], "image_config"
    )
    postgres_attestation_manifest = _artifact_binding(
        postgres["attestation_manifest"], "attestation_manifest"
    )
    postgres_attestation_config = _artifact_binding(
        postgres["attestation_config"], "attestation_config"
    )
    _constant(
        postgres_registry_index.sha256,
        POSTGRES_ROOT_INDEX_DIGEST.removeprefix("sha256:"),
    )
    _constant(
        postgres_platform_manifest.sha256,
        postgres_platform_manifest_digest.removeprefix("sha256:"),
    )
    _constant(
        postgres_image_config.sha256,
        postgres_config_digest.removeprefix("sha256:"),
    )
    image_bindings.append(
        RuntimeImageBinding(
            slot="postgres",
            delivery_kind="PINNED_REGISTRY",
            reference=POSTGRES_REFERENCE,
            root_index_digest=POSTGRES_ROOT_INDEX_DIGEST,
            platform_manifest_digest=postgres_platform_manifest_digest,
            config_digest=postgres_config_digest,
            artifacts=(
                postgres_registry_index,
                postgres_platform_manifest,
                postgres_image_config,
                postgres_attestation_manifest,
                postgres_attestation_config,
                _artifact_binding(postgres["sbom"], "sbom"),
                _artifact_binding(postgres["provenance"], "provenance"),
            ),
        )
    )

    return RuntimeReleaseManifest(
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        release_id=release_id,
        image_tag=image_tag,
        source_snapshot_sha256=source_snapshot_sha256,
        dockerfile_sha256=dockerfile_sha256,
        dockerfiles=tuple(dockerfiles),
        source_artifacts=(source_snapshot_binding, dockerfile_binding),
        target_os="linux",
        target_architecture=target_architecture,
        schema_heads=tuple((name, heads[name]) for name in SCHEMA_HEADS),
        images=tuple(image_bindings),
        status=STATUS,
        authority=AUTHORITY,
        execution_permitted=False,
        production_authorized=False,
    )


def create_runtime_release_manifest(document: Mapping[str, Any]) -> bytes:
    """Return the canonical bytes for one valid non-authority manifest."""

    if type(document) is not dict:
        _invalid()
    raw = _canonical(document)
    _validate_document(_parse(raw, require_canonical=True), raw)
    return raw


def validate_runtime_release_manifest(raw: bytes) -> RuntimeReleaseManifest:
    """Validate canonical manifest bytes without external effects."""

    document = _parse(raw, require_canonical=True)
    return _validate_document(document, raw)


# Short API names are deliberately content-only; none grants execution authority.
create_manifest = create_runtime_release_manifest
validate = validate_runtime_release_manifest


def _stable_identity(value: os.stat_result) -> tuple[int, ...]:
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
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _safe_absolute_file(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        _invalid()
    if _LEAF_NAME.fullmatch(value.name) is None:
        _invalid()
    try:
        resolved_parent = value.parent.resolve(strict=True)
    except OSError:
        _invalid()
    if resolved_parent != value.parent:
        _invalid()
    return value


def _open_parent(value: Path) -> tuple[Path, int, tuple[int, ...]]:
    candidate = _safe_absolute_file(value)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(candidate.parent, flags)
        opened = os.fstat(descriptor)
        visible = os.stat(candidate.parent, follow_symlinks=False)
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _invalid()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_uid != os.geteuid()
        or _stable_identity(opened) != _stable_identity(visible)
    ):
        os.close(descriptor)
        _invalid()
    return candidate, descriptor, _directory_identity(opened)


def _verify_parent(
    candidate: Path, descriptor: int, identity: tuple[int, ...]
) -> None:
    try:
        opened = os.fstat(descriptor)
        visible = os.stat(candidate.parent, follow_symlinks=False)
    except OSError:
        _invalid()
    if (
        _directory_identity(opened) != identity
        or _directory_identity(visible) != identity
    ):
        _invalid()


def _opened_regular_file(
    descriptor: int,
    visible: os.stat_result,
    *,
    expected_mode: int,
    maximum: int,
) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
    except OSError:
        _invalid()
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != expected_mode
        or opened.st_uid != os.geteuid()
        or opened.st_nlink != 1
        or not 0 < opened.st_size <= maximum
        or _stable_identity(opened) != _stable_identity(visible)
    ):
        _invalid()
    return opened


def _read_document_file(value: Path, *, expected_mode: int) -> bytes:
    candidate, parent_descriptor, parent_identity = _open_parent(value)
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        visible_before = os.stat(
            candidate.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_before = _opened_regular_file(
            descriptor,
            visible_before,
            expected_mode=expected_mode,
            maximum=MAX_DOCUMENT_BYTES,
        )
        chunks: list[bytes] = []
        remaining = opened_before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        visible_after = os.stat(
            candidate.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_after = os.fstat(descriptor)
        if (
            _stable_identity(opened_after) != _stable_identity(opened_before)
            or _stable_identity(visible_after) != _stable_identity(opened_before)
        ):
            _invalid()
        _verify_parent(candidate, parent_descriptor, parent_identity)
        return b"".join(chunks)
    except RuntimeReleaseContractError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _write_new_manifest(value: Path, raw: bytes) -> None:
    candidate, parent_descriptor, parent_identity = _open_parent(value)
    descriptor = -1
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(candidate.name, flags, 0o400, dir_fd=parent_descriptor)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        visible = os.stat(
            candidate.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != len(raw)
            or _stable_identity(opened) != _stable_identity(visible)
        ):
            _invalid()
        _verify_parent(candidate, parent_descriptor, parent_identity)
    except RuntimeReleaseContractError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def create_runtime_release_manifest_file(
    input_file: Path, output_file: Path
) -> RuntimeReleaseManifest:
    """Canonicalize one owner-only 0600 input into a new owner-only 0400 file."""

    source_raw = _read_document_file(input_file, expected_mode=0o600)
    source_document = _parse(source_raw, require_canonical=False)
    canonical = create_runtime_release_manifest(source_document)
    _write_new_manifest(output_file, canonical)
    return validate_runtime_release_manifest(canonical)


def validate_runtime_release_manifest_file(value: Path) -> RuntimeReleaseManifest:
    """Read and validate one immutable owner-only 0400 manifest file."""

    raw = _read_document_file(value, expected_mode=0o400)
    return validate_runtime_release_manifest(raw)


def _manifest_projection(
    value: RuntimeReleaseManifest | bytes,
) -> RuntimeReleaseManifest:
    if type(value) is bytes:
        return validate_runtime_release_manifest(value)
    if not isinstance(value, RuntimeReleaseManifest):
        _invalid()
    validated = validate_runtime_release_manifest(value.raw)
    if validated != value:
        _invalid()
    return validated


def _image_binding(
    manifest: RuntimeReleaseManifest, slot: str
) -> RuntimeImageBinding:
    if slot not in IMAGE_SLOTS:
        _invalid()
    for image in manifest.images:
        if image.slot == slot:
            return image
    _invalid()


def _artifact_for(
    image: RuntimeImageBinding, artifact_kind: str
) -> ArtifactBinding:
    if artifact_kind not in _ARTIFACT_MAXIMUMS:
        _invalid()
    for artifact in image.artifacts:
        if artifact.kind == artifact_kind:
            return artifact
    _invalid()


def _allowed_object(
    value: Any, *, required: Sequence[str], allowed: Sequence[str]
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not frozenset(required).issubset(value)
        or not frozenset(value).issubset(allowed)
    ):
        _invalid()
    return value


def _parse_content_json(raw: bytes, *, maximum: int) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if not isinstance(value, dict):
            _invalid()
        return value
    except RuntimeReleaseContractError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _invalid()


def _annotations(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 64:
        _invalid()
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not 0 < len(key) <= 256
            or len(item) > 1024
        ):
            _invalid()
    return value


def _descriptor(
    value: Any, *, maximum: int, allow_data: bool = False
) -> dict[str, Any]:
    descriptor = _allowed_object(
        value,
        required=("mediaType", "digest", "size"),
        allowed=(
            "mediaType",
            "digest",
            "size",
            "platform",
            "annotations",
            "urls",
            "artifactType",
            *(("data",) if allow_data else ()),
        ),
    )
    if not isinstance(descriptor["mediaType"], str) or not descriptor["mediaType"]:
        _invalid()
    _validated_image_digest(descriptor["digest"])
    _validated_size(descriptor["size"], maximum)
    if "annotations" in descriptor:
        _annotations(descriptor["annotations"])
    if "urls" in descriptor and (
        not isinstance(descriptor["urls"], list)
        or len(descriptor["urls"]) > 32
        or not all(isinstance(item, str) for item in descriptor["urls"])
    ):
        _invalid()
    if "artifactType" in descriptor and not isinstance(
        descriptor["artifactType"], str
    ):
        _invalid()
    if "data" in descriptor:
        if not isinstance(descriptor["data"], str):
            _invalid()
        try:
            inline = base64.b64decode(descriptor["data"], validate=True)
        except (ValueError, TypeError):
            _invalid()
        if (
            len(inline) != descriptor["size"]
            or hashlib.sha256(inline).hexdigest()
            != descriptor["digest"].removeprefix("sha256:")
        ):
            _invalid()
    if "platform" in descriptor:
        platform = _allowed_object(
            descriptor["platform"],
            required=("os", "architecture"),
            allowed=("os", "architecture", "variant"),
        )
        if not isinstance(platform["os"], str) or not isinstance(
            platform["architecture"], str
        ):
            _invalid()
        if "variant" in platform and not isinstance(platform["variant"], str):
            _invalid()
    return descriptor


def _is_target_platform(value: Any, architecture: str) -> bool:
    return (
        isinstance(value, dict)
        and value.get("os") == "linux"
        and value.get("architecture") == architecture
    )


def _root_index_bindings(
    raw: bytes,
    *,
    image: RuntimeImageBinding,
    architecture: str,
    allow_other_platforms: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if hashlib.sha256(raw).hexdigest() != image.root_index_digest.removeprefix(
        "sha256:"
    ):
        _invalid()
    index = _allowed_object(
        _parse_content_json(raw, maximum=MAX_OCI_JSON_BYTES),
        required=("schemaVersion", "mediaType", "manifests"),
        allowed=("schemaVersion", "mediaType", "manifests", "annotations"),
    )
    _constant(index["schemaVersion"], 2)
    _constant(index["mediaType"], _OCI_INDEX_MEDIA_TYPE)
    if "annotations" in index:
        _annotations(index["annotations"])
    if not isinstance(index["manifests"], list) or not 2 <= len(
        index["manifests"]
    ) <= 256:
        _invalid()
    targets: list[dict[str, Any]] = []
    attestations: list[dict[str, Any]] = []
    for raw_descriptor in index["manifests"]:
        descriptor = _descriptor(raw_descriptor, maximum=MAX_OCI_JSON_BYTES)
        _constant(descriptor["mediaType"], _OCI_MANIFEST_MEDIA_TYPE)
        platform = descriptor.get("platform")
        annotations = descriptor.get("annotations", {})
        if _is_target_platform(platform, architecture):
            if descriptor["digest"] != image.platform_manifest_digest:
                _invalid()
            targets.append(descriptor)
            continue
        if (
            isinstance(platform, dict)
            and platform.get("os") == "unknown"
            and platform.get("architecture") == "unknown"
            and annotations.get("vnd.docker.reference.type")
            == "attestation-manifest"
            and annotations.get("vnd.docker.reference.digest")
            == image.platform_manifest_digest
        ):
            attestations.append(descriptor)
            continue
        if not allow_other_platforms:
            _invalid()
    if len(targets) != 1 or len(attestations) != 1:
        _invalid()
    return targets[0], attestations[0]


def _layout_root_descriptor(
    raw: bytes, *, image: RuntimeImageBinding, image_tag: str
) -> dict[str, Any]:
    layout_index = _allowed_object(
        _parse_content_json(raw, maximum=MAX_OCI_JSON_BYTES),
        required=("schemaVersion", "mediaType", "manifests"),
        allowed=("schemaVersion", "mediaType", "manifests", "annotations"),
    )
    _constant(layout_index["schemaVersion"], 2)
    _constant(layout_index["mediaType"], _OCI_INDEX_MEDIA_TYPE)
    if "annotations" in layout_index:
        _annotations(layout_index["annotations"])
    if not isinstance(layout_index["manifests"], list) or len(
        layout_index["manifests"]
    ) != 1:
        _invalid()
    root = _descriptor(
        layout_index["manifests"][0], maximum=MAX_OCI_JSON_BYTES
    )
    _constant(root["mediaType"], _OCI_INDEX_MEDIA_TYPE)
    _constant(root["digest"], image.root_index_digest)
    if "platform" in root:
        _invalid()
    annotations = root.get("annotations")
    if not isinstance(annotations, dict):
        _invalid()
    _constant(
        annotations.get("io.containerd.image.name"),
        f"docker.io/library/{_IMAGE_REPOSITORIES[image.slot]}:{image_tag}",
    )
    _constant(
        annotations.get("org.opencontainers.image.ref.name"), image_tag
    )
    return root


def _manifest_bindings(
    raw: bytes,
    *,
    expected_digest: str,
    expected_size: int,
    runnable: bool,
    expected_config_digest: str | None = None,
    expected_subject_digest: str | None = None,
    expected_subject_size: int | None = None,
    architecture: str | None = None,
    attestation_profile: str | None = None,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    if (
        len(raw) != expected_size
        or hashlib.sha256(raw).hexdigest()
        != expected_digest.removeprefix("sha256:")
    ):
        _invalid()
    manifest = _allowed_object(
        _parse_content_json(raw, maximum=MAX_OCI_JSON_BYTES),
        required=("schemaVersion", "mediaType", "config", "layers"),
        allowed=(
            "schemaVersion",
            "mediaType",
            "config",
            "layers",
            "annotations",
            "artifactType",
            "subject",
        ),
    )
    _constant(manifest["schemaVersion"], 2)
    _constant(manifest["mediaType"], _OCI_MANIFEST_MEDIA_TYPE)
    if "annotations" in manifest:
        _annotations(manifest["annotations"])
    config = _descriptor(
        manifest["config"], maximum=MAX_OCI_JSON_BYTES, allow_data=True
    )
    if runnable:
        if attestation_profile is not None or "artifactType" in manifest or "subject" in manifest:
            _invalid()
        _constant(config["mediaType"], _OCI_CONFIG_MEDIA_TYPE)
        if expected_config_digest is None:
            _invalid()
        _constant(config["digest"], expected_config_digest)
    else:
        if attestation_profile == "modern":
            if (
                expected_subject_digest is None
                or expected_subject_size is None
                or architecture is None
                or "subject" not in manifest
                or "artifactType" not in manifest
            ):
                _invalid()
            subject = _descriptor(manifest["subject"], maximum=MAX_OCI_JSON_BYTES)
            _constant(subject["mediaType"], _OCI_MANIFEST_MEDIA_TYPE)
            _constant(subject["digest"], expected_subject_digest)
            _constant(subject["size"], expected_subject_size)
            if "platform" in subject and not _is_target_platform(
                subject["platform"], architecture
            ):
                _invalid()
            _constant(manifest["artifactType"], _ATTESTATION_ARTIFACT_TYPE)
            _constant(config["mediaType"], _OCI_EMPTY_CONFIG_MEDIA_TYPE)
            _constant(config["digest"], _OCI_EMPTY_CONFIG_DIGEST)
            _constant(config["size"], 2)
        elif attestation_profile == "postgres_legacy":
            if (
                "subject" in manifest
                or "artifactType" in manifest
                or "annotations" in manifest
            ):
                _invalid()
            _constant(config["mediaType"], _OCI_CONFIG_MEDIA_TYPE)
        else:
            _invalid()
    if not isinstance(manifest["layers"], list) or not 1 <= len(
        manifest["layers"]
    ) <= 256:
        _invalid()
    layers = tuple(
        _descriptor(item, maximum=MAX_OCI_ARCHIVE_BYTES)
        for item in manifest["layers"]
    )
    if runnable:
        for layer in layers:
            if layer["mediaType"] not in _OCI_LAYER_MEDIA_TYPES:
                _invalid()
    return config, layers


def _content_binding(image: RuntimeImageBinding, kind: str) -> ArtifactBinding:
    return _artifact_for(image, kind)


def _attestation_layers(
    layers: Sequence[dict[str, Any]], image: RuntimeImageBinding
) -> tuple[dict[str, Any], dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for layer in layers:
        _constant(layer["mediaType"], "application/vnd.in-toto+json")
        annotations = layer.get("annotations")
        if not isinstance(annotations, dict):
            _invalid()
        predicate_type = annotations.get("in-toto.io/predicate-type")
        if predicate_type == _SPDX_PREDICATE:
            kind = "sbom"
        elif predicate_type == (
            _SLSA_PROVENANCE
            if image.slot in OCI_IMAGE_SLOTS
            else "https://slsa.dev/provenance/v0.2"
        ):
            kind = "provenance"
        else:
            _invalid()
        if kind in found:
            _invalid()
        binding = _content_binding(image, kind)
        _constant(layer["digest"], "sha256:" + binding.sha256)
        _constant(layer["size"], binding.size)
        found[kind] = layer
    if frozenset(found) != frozenset(("sbom", "provenance")):
        _invalid()
    return found["sbom"], found["provenance"]


def _legacy_attestation_config(raw: bytes, image: RuntimeImageBinding) -> None:
    config = _closed(
        _parse_content_json(raw, maximum=MAX_OCI_JSON_BYTES),
        ("architecture", "os", "config", "rootfs"),
    )
    _constant(config["architecture"], "unknown")
    _constant(config["os"], "unknown")
    _constant(config["config"], {})
    rootfs = _closed(config["rootfs"], ("type", "diff_ids"))
    _constant(rootfs["type"], "layers")
    _constant(
        rootfs["diff_ids"],
        [
            "sha256:" + _content_binding(image, "sbom").sha256,
            "sha256:" + _content_binding(image, "provenance").sha256,
        ],
    )


def _image_config(
    raw: bytes,
    *,
    image: RuntimeImageBinding,
    architecture: str,
    expected_layer_count: int | None = None,
) -> None:
    if hashlib.sha256(raw).hexdigest() != image.config_digest.removeprefix("sha256:"):
        _invalid()
    config = _allowed_object(
        _parse_content_json(raw, maximum=MAX_OCI_JSON_BYTES),
        required=("architecture", "os", "config", "rootfs"),
        allowed=(
            "architecture",
            "os",
            "config",
            "rootfs",
            "created",
            "author",
            "history",
            "variant",
            "os.version",
            "os.features",
        ),
    )
    _constant(config["architecture"], architecture)
    _constant(config["os"], "linux")
    if not isinstance(config["config"], dict):
        _invalid()
    rootfs = _closed(config["rootfs"], ("type", "diff_ids"))
    _constant(rootfs["type"], "layers")
    if not isinstance(rootfs["diff_ids"], list):
        _invalid()
    if (
        expected_layer_count is not None
        and len(rootfs["diff_ids"]) != expected_layer_count
    ):
        _invalid()
    for digest in rootfs["diff_ids"]:
        _validated_image_digest(digest)


def _digest_mapping(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 8:
        _invalid()
    normalized: list[tuple[str, str]] = []
    for algorithm, encoded in value.items():
        if (
            not isinstance(algorithm, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._+-]{0,31}", algorithm) is None
            or not isinstance(encoded, str)
            or re.fullmatch(r"[0-9a-f]{32,128}", encoded) is None
        ):
            _invalid()
        normalized.append((algorithm, encoded))
    return tuple(sorted(normalized))


def _resource_descriptors(
    value: Any,
) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    if not isinstance(value, list) or len(value) > 4096:
        _invalid()
    result: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for raw_item in value:
        item = _allowed_object(
            raw_item,
            required=("uri", "digest"),
            allowed=(
                "uri",
                "digest",
                "name",
                "downloadLocation",
                "mediaType",
                "content",
                "annotations",
            ),
        )
        if not isinstance(item["uri"], str) or not 0 < len(item["uri"]) <= 2048:
            _invalid()
        for optional_string in ("name", "downloadLocation", "mediaType", "content"):
            if optional_string in item and not isinstance(
                item[optional_string], str
            ):
                _invalid()
        if "annotations" in item and not isinstance(item["annotations"], dict):
            _invalid()
        result.append((item["uri"], _digest_mapping(item["digest"])))
    if len(set(result)) != len(result):
        _invalid()
    return tuple(result)


def _statement_content(
    raw: bytes,
    *,
    kind: str,
    manifest: RuntimeReleaseManifest,
    image: RuntimeImageBinding,
) -> None:
    statement = _closed(
        _parse_content_json(raw, maximum=_ARTIFACT_MAXIMUMS[kind]),
        ("_type", "subject", "predicateType", "predicate"),
    )
    if statement["_type"] not in (
        _IN_TOTO_STATEMENT,
        "https://in-toto.io/Statement/v0.1",
    ):
        _invalid()
    if (
        not isinstance(statement["subject"], list)
        or not 1 <= len(statement["subject"]) <= 64
    ):
        _invalid()
    expected_subject = image.platform_manifest_digest.removeprefix("sha256:")
    for raw_subject in statement["subject"]:
        subject = _closed(raw_subject, ("name", "digest"))
        if not isinstance(subject["name"], str) or len(subject["name"]) > 2048:
            _invalid()
        digest = _closed(subject["digest"], ("sha256",))
        _constant(_validated_sha256(digest["sha256"]), expected_subject)
    predicate = statement["predicate"]
    if kind == "sbom":
        _constant(statement["predicateType"], _SPDX_PREDICATE)
        spdx = _allowed_object(
            predicate,
            required=(
                "SPDXID",
                "spdxVersion",
                "dataLicense",
                "name",
                "documentNamespace",
                "creationInfo",
                "packages",
            ),
            allowed=(
                "SPDXID",
                "spdxVersion",
                "dataLicense",
                "name",
                "documentNamespace",
                "creationInfo",
                "packages",
                "relationships",
                "files",
                "documentDescribes",
                "externalDocumentRefs",
                "hasExtractedLicensingInfos",
                "annotations",
                "revieweds",
                "snippets",
                "comment",
                "reviews",
            ),
        )
        _constant(spdx["SPDXID"], "SPDXRef-DOCUMENT")
        if spdx["spdxVersion"] not in ("SPDX-2.2", "SPDX-2.3"):
            _invalid()
        _constant(spdx["dataLicense"], "CC0-1.0")
        if (
            not isinstance(spdx["name"], str)
            or not isinstance(spdx["documentNamespace"], str)
            or not isinstance(spdx["packages"], list)
            or len(spdx["packages"]) > 100000
        ):
            _invalid()
        for list_name in (
            "relationships",
            "files",
            "documentDescribes",
            "externalDocumentRefs",
            "hasExtractedLicensingInfos",
            "annotations",
            "revieweds",
            "snippets",
            "reviews",
        ):
            if list_name in spdx and not isinstance(spdx[list_name], list):
                _invalid()
        if "comment" in spdx and not isinstance(spdx["comment"], str):
            _invalid()
        creation = _allowed_object(
            spdx["creationInfo"],
            required=("created", "creators"),
            allowed=("created", "creators", "licenseListVersion", "comment"),
        )
        if (
            not isinstance(creation["created"], str)
            or not isinstance(creation["creators"], list)
            or not creation["creators"]
            or not all(isinstance(item, str) for item in creation["creators"])
        ):
            _invalid()
        if not all(isinstance(item, dict) for item in spdx["packages"]):
            _invalid()
        if "relationships" in spdx and not all(
            isinstance(item, dict) for item in spdx["relationships"]
        ):
            _invalid()
        return
    if kind != "provenance":
        _invalid()
    expected_provenance_type = (
        _SLSA_PROVENANCE
        if image.slot in OCI_IMAGE_SLOTS
        else "https://slsa.dev/provenance/v0.2"
    )
    _constant(statement["predicateType"], expected_provenance_type)
    if statement["predicateType"] == _SLSA_PROVENANCE:
        _constant(statement["_type"], _IN_TOTO_STATEMENT)
        slsa = _closed(predicate, ("buildDefinition", "runDetails"))
        definition = _closed(
            slsa["buildDefinition"],
            (
                "buildType",
                "externalParameters",
                "internalParameters",
                "resolvedDependencies",
            ),
        )
        _constant(
            definition["buildType"],
            "https://github.com/moby/buildkit/blob/master/docs/attestations/"
            "slsa-definitions.md",
        )
        external_parameters = _allowed_object(
            definition["externalParameters"],
            required=("configSource", "request"),
            allowed=("configSource", "request"),
        )
        config_source = _closed(external_parameters["configSource"], ("path",))
        _constant(config_source["path"], "Dockerfile")
        internal_parameters = _closed(
            definition["internalParameters"], ("builderPlatform",)
        )
        _constant(
            internal_parameters["builderPlatform"],
            f"linux/{manifest.target_architecture}",
        )
        request = _closed(
            external_parameters["request"],
            ("frontend", "args", "locals", "compatibilityVersion"),
        )
        _constant(request["frontend"], "dockerfile.v0")
        _constant(request["compatibilityVersion"], 30)
        request_args = request["args"]
        if not isinstance(request_args, dict) or not set(request_args).issubset(
            {"target", "filename", "platform"}
        ):
            _invalid()
        _constant(request_args.get("target"), DOCKERFILE_TARGETS[image.slot])
        if "filename" in request_args:
            _constant(request_args["filename"], "Dockerfile")
        if "platform" in request_args:
            _constant(
                request_args["platform"],
                f"linux/{manifest.target_architecture}",
            )
        locals_value = request["locals"]
        if not isinstance(locals_value, list) or len(locals_value) != 2:
            _invalid()
        local_names = []
        for local in locals_value:
            value = _closed(local, ("name",))
            if not isinstance(value["name"], str):
                _invalid()
            local_names.append(value["name"])
        if frozenset(local_names) != frozenset(("context", "dockerfile")):
            _invalid()
        _resource_descriptors(definition["resolvedDependencies"])
        details = _allowed_object(
            slsa["runDetails"],
            required=("builder", "metadata"),
            allowed=("builder", "metadata", "byproducts"),
        )
        builder = _allowed_object(
            details["builder"],
            required=("id",),
            allowed=("id", "builderDependencies", "version"),
        )
        if (
            not isinstance(builder["id"], str)
            or not isinstance(details["metadata"], dict)
        ):
            _invalid()
        buildkit_metadata = details["metadata"].get("buildkit_metadata")
        if buildkit_metadata is not None:
            if not isinstance(buildkit_metadata, dict) or (
                "source" in buildkit_metadata
                or "layers" in buildkit_metadata
            ):
                _invalid()
        if "byproducts" in details and not isinstance(details["byproducts"], list):
            _invalid()
    elif statement["predicateType"] == "https://slsa.dev/provenance/v0.2":
        slsa = _allowed_object(
            predicate,
            required=(
                "builder",
                "buildType",
                "invocation",
                "metadata",
                "materials",
            ),
            allowed=(
                "builder",
                "buildType",
                "invocation",
                "buildConfig",
                "metadata",
                "materials",
            ),
        )
        builder = _allowed_object(
            slsa["builder"],
            required=("id",),
            allowed=("id", "builderDependencies", "version"),
        )
        if (
            not isinstance(builder["id"], str)
            or not isinstance(slsa["buildType"], str)
            or not isinstance(slsa["invocation"], dict)
            or not isinstance(slsa["metadata"], dict)
        ):
            _invalid()
        if "buildConfig" in slsa and not isinstance(slsa["buildConfig"], dict):
            _invalid()
        invocation = slsa["invocation"]
        config_source = invocation.get("configSource")
        if config_source is not None:
            config_source = _allowed_object(
                config_source,
                required=(),
                allowed=("uri", "digest", "entryPoint"),
            )
            if "uri" in config_source and not isinstance(config_source["uri"], str):
                _invalid()
            if "entryPoint" in config_source and not isinstance(
                config_source["entryPoint"], str
            ):
                _invalid()
            if "digest" in config_source:
                _digest_mapping(config_source["digest"])
        parameters = invocation.get("parameters")
        if parameters is not None:
            if not isinstance(parameters, dict):
                _invalid()
            if "frontend" in parameters and (
                not isinstance(parameters["frontend"], str)
                or not parameters["frontend"]
            ):
                _invalid()
        _resource_descriptors(slsa["materials"])
    else:
        _invalid()


def _tar_member_content(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    maximum: int,
    expected_digest: str | None = None,
    expected_size: int | None = None,
    retain: bool,
) -> bytes:
    if (
        not member.isfile()
        or not 0 < member.size <= maximum
        or (expected_size is not None and member.size != expected_size)
    ):
        _invalid()
    extracted = archive.extractfile(member)
    if extracted is None:
        _invalid()
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    remaining = member.size
    try:
        while remaining:
            chunk = extracted.read(min(remaining, 1024 * 1024))
            if not chunk:
                _invalid()
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
            remaining -= len(chunk)
        if extracted.read(1):
            _invalid()
    except (OSError, tarfile.TarError):
        _invalid()
    finally:
        extracted.close()
    if expected_digest is not None and digest.hexdigest() != expected_digest:
        _invalid()
    return b"".join(chunks)


def _blob_member(
    members: Mapping[str, tarfile.TarInfo], digest: str
) -> tuple[str, tarfile.TarInfo]:
    _validated_image_digest(digest)
    name = "blobs/sha256/" + digest.removeprefix("sha256:")
    member = members.get(name)
    if member is None:
        _invalid()
    return name, member


def _inline_descriptor_content(descriptor: Mapping[str, Any]) -> bytes | None:
    encoded = descriptor.get("data")
    if encoded is None:
        return None
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        _invalid()


def _tar_descriptor_content(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    used: set[str],
    descriptor: Mapping[str, Any],
    *,
    maximum: int,
) -> bytes:
    inline = _inline_descriptor_content(descriptor)
    name = "blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")
    member = members.get(name)
    if member is None:
        if inline is None:
            _invalid()
        return inline
    used.add(name)
    raw = _tar_member_content(
        archive,
        member,
        maximum=maximum,
        expected_digest=descriptor["digest"].removeprefix("sha256:"),
        expected_size=descriptor["size"],
        retain=True,
    )
    if inline is not None and raw != inline:
        _invalid()
    return raw


def _verify_tar_terminal(
    descriptor: int, members: Sequence[tarfile.TarInfo]
) -> None:
    """Require one contiguous tar stream followed only by complete zero blocks."""

    try:
        size = os.fstat(descriptor).st_size
        expected_offset = 0
        for member in members:
            if (
                type(member.offset) is not int
                or type(member.offset_data) is not int
                or type(member.size) is not int
                or member.size < 0
                or member.offset != expected_offset
                or member.offset_data != member.offset + 512
            ):
                _invalid()
            expected_offset = member.offset_data + (
                (member.size + 511) // 512
            ) * 512
            if expected_offset > size:
                _invalid()
            padding_start = member.offset_data + member.size
            padding_size = expected_offset - padding_start
            if padding_size:
                padding = os.pread(descriptor, padding_size, padding_start)
                if len(padding) != padding_size or any(padding):
                    _invalid()
        trailing = size - expected_offset
        if trailing < 1024 or trailing % 512 != 0:
            _invalid()
        position = expected_offset
        while position < size:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, size - position),
                position,
            )
            if not chunk or any(chunk):
                _invalid()
            position += len(chunk)
    except RuntimeReleaseContractError:
        raise
    except OSError:
        _invalid()


def _verify_oci_archive(
    descriptor: int,
    *,
    manifest: RuntimeReleaseManifest,
    image: RuntimeImageBinding,
) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                raw_members: list[tarfile.TarInfo] = []
                for member in archive:
                    raw_members.append(member)
                    if len(raw_members) > MAX_OCI_MEMBERS:
                        _invalid()
                if not 3 <= len(raw_members) <= MAX_OCI_MEMBERS:
                    _invalid()
                _verify_tar_terminal(descriptor, raw_members)
                members: dict[str, tarfile.TarInfo] = {}
                directories: set[str] = set()
                for member in raw_members:
                    if member.name in ("blobs", "blobs/sha256"):
                        if (
                            not member.isdir()
                            or member.name in directories
                            or member.pax_headers
                        ):
                            _invalid()
                        directories.add(member.name)
                        continue
                    if (
                        member.name in members
                        or member.name not in ("oci-layout", "index.json")
                        and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name)
                        is None
                        or not member.isfile()
                        or member.issparse()
                        or member.pax_headers
                    ):
                        _invalid()
                    members[member.name] = member
                used = {"oci-layout", "index.json", *directories}
                layout_member = members.get("oci-layout")
                index_member = members.get("index.json")
                if layout_member is None or index_member is None:
                    _invalid()
                layout_raw = _tar_member_content(
                    archive, layout_member, maximum=4096, retain=True
                )
                layout = _closed(
                    _parse_content_json(layout_raw, maximum=4096),
                    ("imageLayoutVersion",),
                )
                _constant(layout["imageLayoutVersion"], "1.0.0")
                layout_index_raw = _tar_member_content(
                    archive,
                    index_member,
                    maximum=MAX_OCI_JSON_BYTES,
                    retain=True,
                )
                root_descriptor = _layout_root_descriptor(
                    layout_index_raw,
                    image=image,
                    image_tag=manifest.image_tag,
                )
                root_name, root_member = _blob_member(
                    members, root_descriptor["digest"]
                )
                used.add(root_name)
                root_raw = _tar_member_content(
                    archive,
                    root_member,
                    maximum=MAX_OCI_JSON_BYTES,
                    expected_digest=root_descriptor["digest"].removeprefix(
                        "sha256:"
                    ),
                    expected_size=root_descriptor["size"],
                    retain=True,
                )
                target, attestation = _root_index_bindings(
                    root_raw,
                    image=image,
                    architecture=manifest.target_architecture,
                    allow_other_platforms=False,
                )

                target_name, target_member = _blob_member(
                    members, target["digest"]
                )
                used.add(target_name)
                target_raw = _tar_member_content(
                    archive,
                    target_member,
                    maximum=MAX_OCI_JSON_BYTES,
                    expected_digest=target["digest"].removeprefix("sha256:"),
                    expected_size=target["size"],
                    retain=True,
                )
                config, layers = _manifest_bindings(
                    target_raw,
                    expected_digest=image.platform_manifest_digest,
                    expected_size=target["size"],
                    runnable=True,
                    expected_config_digest=image.config_digest,
                )
                config_raw = _tar_descriptor_content(
                    archive,
                    members,
                    used,
                    config,
                    maximum=MAX_OCI_JSON_BYTES,
                )
                _image_config(
                    config_raw,
                    image=image,
                    architecture=manifest.target_architecture,
                    expected_layer_count=len(layers),
                )
                for layer in layers:
                    layer_name, layer_member = _blob_member(
                        members, layer["digest"]
                    )
                    used.add(layer_name)
                    _tar_member_content(
                        archive,
                        layer_member,
                        maximum=MAX_OCI_ARCHIVE_BYTES,
                        expected_digest=layer["digest"].removeprefix("sha256:"),
                        expected_size=layer["size"],
                        retain=False,
                    )

                attest_name, attest_member = _blob_member(
                    members, attestation["digest"]
                )
                used.add(attest_name)
                attest_raw = _tar_member_content(
                    archive,
                    attest_member,
                    maximum=MAX_OCI_JSON_BYTES,
                    expected_digest=attestation["digest"].removeprefix("sha256:"),
                    expected_size=attestation["size"],
                    retain=True,
                )
                attest_config, attest_layers = _manifest_bindings(
                    attest_raw,
                    expected_digest=attestation["digest"],
                    expected_size=attestation["size"],
                    runnable=False,
                    expected_subject_digest=image.platform_manifest_digest,
                    expected_subject_size=target["size"],
                    architecture=manifest.target_architecture,
                    attestation_profile="modern",
                )
                sbom_layer, provenance_layer = _attestation_layers(
                    attest_layers, image
                )
                attest_config_raw = _tar_descriptor_content(
                    archive,
                    members,
                    used,
                    attest_config,
                    maximum=MAX_OCI_JSON_BYTES,
                )
                _parse_content_json(
                    attest_config_raw, maximum=MAX_OCI_JSON_BYTES
                )
                for kind, layer in (
                    ("sbom", sbom_layer),
                    ("provenance", provenance_layer),
                ):
                    layer_name, layer_member = _blob_member(
                        members, layer["digest"]
                    )
                    used.add(layer_name)
                    raw = _tar_member_content(
                        archive,
                        layer_member,
                        maximum=_ARTIFACT_MAXIMUMS[kind],
                        expected_digest=layer["digest"].removeprefix("sha256:"),
                        expected_size=layer["size"],
                        retain=True,
                    )
                    _statement_content(
                        raw, kind=kind, manifest=manifest, image=image
                    )
                if frozenset((*members, *directories)) != frozenset(used):
                    _invalid()
    except RuntimeReleaseContractError:
        raise
    except (OSError, ValueError, tarfile.TarError, EOFError):
        _invalid()


def _portable_snapshot_name(value: str) -> tuple[str, ...]:
    if (
        not isinstance(value, str)
        or not value
        or unicodedata.normalize("NFC", value) != value
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _invalid()
    parts = tuple(value.rstrip("/").split("/"))
    if (
        not parts
        or any(part in ("", ".", "..") for part in parts)
        or any(part in (".git", ".hg", ".svn") for part in parts)
        or len(value.rstrip("/").encode("utf-8")) > 255
        or any(not 0 < len(part.encode("utf-8")) <= 100 for part in parts)
    ):
        _invalid()
    return parts


def _resolved_link_target(name: str, linkname: str) -> str:
    if (
        not isinstance(linkname, str)
        or not linkname
        or unicodedata.normalize("NFC", linkname) != linkname
        or linkname.startswith("/")
        or "\\" in linkname
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in linkname
        )
    ):
        _invalid()
    resolved = list(_portable_snapshot_name(name)[:-1])
    for part in linkname.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                _invalid()
            resolved.pop()
            continue
        if (
            part in (".git", ".hg", ".svn")
            or not 0 < len(part.encode("utf-8")) <= 100
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in part
            )
        ):
            _invalid()
        resolved.append(part)
    if not resolved:
        _invalid()
    return "/".join(resolved)


def _verify_source_snapshot(
    descriptor: int, size: int, manifest: RuntimeReleaseManifest
) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        entries: dict[str, str] = {}
        links: dict[str, str] = {}
        names: list[str] = []
        dockerfile_digest: str | None = None
        expected_offset = 0
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                for count, member in enumerate(archive, start=1):
                    if count > MAX_SOURCE_MEMBERS:
                        _invalid()
                    name = member.name.rstrip("/")
                    _portable_snapshot_name(name)
                    if name in entries or member.pax_headers or member.issparse():
                        _invalid()
                    if member.offset != expected_offset or member.offset_data != (
                        member.offset + 512
                    ):
                        _invalid()
                    if os.pread(descriptor, 8, member.offset + 257) != b"ustar\x0000":
                        _invalid()
                    if (
                        member.uid != 0
                        or member.gid != 0
                        or member.mtime != 0
                        or member.uname not in (None, "")
                        or member.gname not in (None, "")
                    ):
                        _invalid()
                    if member.isfile():
                        if member.mode not in (0o644, 0o755) or member.linkname:
                            _invalid()
                        kind = "file"
                        if name == DOCKERFILE_SNAPSHOT_MEMBER:
                            digest = hashlib.sha256()
                            remaining = member.size
                            position = member.offset_data
                            while remaining:
                                chunk = os.pread(
                                    descriptor,
                                    min(1024 * 1024, remaining),
                                    position,
                                )
                                if not chunk:
                                    _invalid()
                                digest.update(chunk)
                                remaining -= len(chunk)
                                position += len(chunk)
                            dockerfile_digest = digest.hexdigest()
                    elif member.isdir():
                        if (
                            member.mode != 0o755
                            or member.size != 0
                            or member.linkname
                        ):
                            _invalid()
                        kind = "directory"
                    elif member.issym():
                        if member.mode != 0o777 or member.size != 0:
                            _invalid()
                        kind = "symlink"
                        links[name] = _resolved_link_target(name, member.linkname)
                    else:
                        _invalid()
                    entries[name] = kind
                    names.append(name)
                    next_offset = member.offset_data + (
                        (member.size + 511) // 512
                    ) * 512
                    padding_start = member.offset_data + member.size
                    padding_size = next_offset - padding_start
                    if padding_size:
                        padding = os.pread(
                            descriptor, padding_size, padding_start
                        )
                        if len(padding) != padding_size or any(padding):
                            _invalid()
                    expected_offset = next_offset
        if not entries or names != sorted(names, key=lambda item: item.encode("utf-8")):
            _invalid()
        for name in entries:
            parts = name.split("/")
            for index in range(1, len(parts)):
                if entries.get("/".join(parts[:index])) != "directory":
                    _invalid()
        for name, target in links.items():
            if target not in entries:
                _invalid()
            seen = {name}
            current = target
            while current in links:
                if current in seen:
                    _invalid()
                seen.add(current)
                current = links[current]
            if current not in entries:
                _invalid()
        if dockerfile_digest is None or {
            item[1] for item in manifest.dockerfiles
        } != {dockerfile_digest}:
            _invalid()
        trailing = size - expected_offset
        if trailing < 1024 or trailing % 512 != 0:
            _invalid()
        position = expected_offset
        while position < size:
            chunk = os.pread(descriptor, min(1024 * 1024, size - position), position)
            if not chunk or any(chunk):
                _invalid()
            position += len(chunk)
    except RuntimeReleaseContractError:
        raise
    except (OSError, ValueError, tarfile.TarError, EOFError, UnicodeError):
        _invalid()


def _verify_dockerfile_digest_set(
    raw: bytes, manifest: RuntimeReleaseManifest
) -> None:
    document = _closed(
        _parse_content_json(raw, maximum=MAX_DOCKERFILE_DIGEST_SET_BYTES),
        OCI_IMAGE_SLOTS,
    )
    for slot in OCI_IMAGE_SLOTS:
        binding = _closed(document[slot], ("dockerfile_sha256", "target"))
        _validated_sha256(binding["dockerfile_sha256"])
        _constant(binding["target"], DOCKERFILE_TARGETS[slot])
    expected = {
        slot: {"dockerfile_sha256": digest, "target": target}
        for slot, digest, target in manifest.dockerfiles
    }
    _constant(document, expected)
    if _canonical(document) != raw:
        _invalid()


def _semantic_content(
    descriptor: int,
    raw: bytes | None,
    *,
    binding: ArtifactBinding,
    manifest: RuntimeReleaseManifest,
    image: RuntimeImageBinding | None,
) -> None:
    if binding.kind == "source_snapshot":
        _verify_source_snapshot(descriptor, binding.size, manifest)
        return
    if binding.kind == "dockerfile_digest_set":
        if raw is None:
            _invalid()
        _verify_dockerfile_digest_set(raw, manifest)
        return
    if image is None:
        _invalid()
    if binding.kind == "oci_archive":
        _verify_oci_archive(descriptor, manifest=manifest, image=image)
        return
    if raw is None:
        _invalid()
    if binding.kind == "registry_index":
        target, attestation = _root_index_bindings(
            raw,
            image=image,
            architecture=manifest.target_architecture,
            allow_other_platforms=True,
        )
        platform_binding = _content_binding(image, "platform_manifest")
        attestation_binding = _content_binding(image, "attestation_manifest")
        _constant(target["size"], platform_binding.size)
        _constant(attestation["digest"], "sha256:" + attestation_binding.sha256)
        _constant(attestation["size"], attestation_binding.size)
        return
    if binding.kind == "platform_manifest":
        config, _layers = _manifest_bindings(
            raw,
            expected_digest=image.platform_manifest_digest,
            expected_size=binding.size,
            runnable=True,
            expected_config_digest=image.config_digest,
        )
        _constant(config["size"], _content_binding(image, "image_config").size)
        return
    if binding.kind == "image_config":
        _image_config(
            raw, image=image, architecture=manifest.target_architecture
        )
        return
    if binding.kind == "attestation_manifest":
        platform_binding = _content_binding(image, "platform_manifest")
        config, layers = _manifest_bindings(
            raw,
            expected_digest="sha256:" + binding.sha256,
            expected_size=binding.size,
            runnable=False,
            expected_subject_digest=image.platform_manifest_digest,
            expected_subject_size=platform_binding.size,
            architecture=manifest.target_architecture,
            attestation_profile="postgres_legacy",
        )
        _constant(
            config["digest"],
            "sha256:" + _content_binding(image, "attestation_config").sha256,
        )
        _constant(config["size"], _content_binding(image, "attestation_config").size)
        _attestation_layers(layers, image)
        return
    if binding.kind == "attestation_config":
        _legacy_attestation_config(raw, image)
        return
    if binding.kind in ("sbom", "provenance"):
        _statement_content(raw, kind=binding.kind, manifest=manifest, image=image)
        return
    _invalid()


def _hash_artifact_file(
    value: Path,
    binding: ArtifactBinding,
    *,
    manifest: RuntimeReleaseManifest,
    image: RuntimeImageBinding | None,
) -> None:
    candidate, parent_descriptor, parent_identity = _open_parent(value)
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    maximum = _ARTIFACT_MAXIMUMS[binding.kind]
    try:
        descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        visible_before = os.stat(
            candidate.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_before = _opened_regular_file(
            descriptor,
            visible_before,
            expected_mode=0o400,
            maximum=maximum,
        )
        if opened_before.st_size != binding.size:
            _invalid()
        digest = hashlib.sha256()
        retained: list[bytes] = []
        remaining = binding.size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                _invalid()
            digest.update(chunk)
            if binding.kind not in ("oci_archive", "source_snapshot"):
                retained.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or digest.hexdigest() != binding.sha256:
            _invalid()
        _semantic_content(
            descriptor,
            (
                None
                if binding.kind in ("oci_archive", "source_snapshot")
                else b"".join(retained)
            ),
            binding=binding,
            manifest=manifest,
            image=image,
        )
        visible_after = os.stat(
            candidate.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        opened_after = os.fstat(descriptor)
        if (
            _stable_identity(opened_after) != _stable_identity(opened_before)
            or _stable_identity(visible_after) != _stable_identity(opened_before)
        ):
            _invalid()
        _verify_parent(candidate, parent_descriptor, parent_identity)
    except RuntimeReleaseContractError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def verify_runtime_release_artifact(
    manifest: RuntimeReleaseManifest | bytes,
    *,
    slot: str,
    artifact_kind: str,
    artifact_file: Path,
) -> VerifiedRuntimeArtifact:
    """Verify one bound file without loading, executing, or publishing it."""

    validated = _manifest_projection(manifest)
    image = _image_binding(validated, slot)
    binding = _artifact_for(image, artifact_kind)
    _hash_artifact_file(
        artifact_file,
        binding,
        manifest=validated,
        image=image,
    )
    return VerifiedRuntimeArtifact(
        slot=slot,
        artifact_kind=artifact_kind,
        sha256=binding.sha256,
        size=binding.size,
        status="CONTENT_VALIDATED_UNSIGNED_UNTRUSTED_NOT_AUTHORITY",
        authority=AUTHORITY,
    )


verify_artifact = verify_runtime_release_artifact


def verify_runtime_release_source_artifact(
    manifest: RuntimeReleaseManifest | bytes,
    *,
    artifact_kind: str,
    artifact_file: Path,
) -> VerifiedRuntimeArtifact:
    """Verify one bound source artifact as unsigned, untrusted content."""

    validated = _manifest_projection(manifest)
    binding = next(
        (
            item
            for item in validated.source_artifacts
            if item.kind == artifact_kind
        ),
        None,
    )
    if binding is None:
        _invalid()
    _hash_artifact_file(
        artifact_file,
        binding,
        manifest=validated,
        image=None,
    )
    return VerifiedRuntimeArtifact(
        slot="source",
        artifact_kind=artifact_kind,
        sha256=binding.sha256,
        size=binding.size,
        status="CONTENT_VALIDATED_UNSIGNED_UNTRUSTED_NOT_AUTHORITY",
        authority=AUTHORITY,
    )


verify_source_artifact = verify_runtime_release_source_artifact


def verify_runtime_release_artifact_file(
    manifest_file: Path,
    *,
    slot: str,
    artifact_kind: str,
    artifact_file: Path,
) -> VerifiedRuntimeArtifact:
    """Validate a 0400 manifest and verify one 0400 bound artifact."""

    manifest = validate_runtime_release_manifest_file(manifest_file)
    return verify_runtime_release_artifact(
        manifest,
        slot=slot,
        artifact_kind=artifact_kind,
        artifact_file=artifact_file,
    )


def verify_runtime_release_source_artifact_file(
    manifest_file: Path,
    *,
    artifact_kind: str,
    artifact_file: Path,
) -> VerifiedRuntimeArtifact:
    """Validate a 0400 manifest and one 0400 bound source artifact."""

    manifest = validate_runtime_release_manifest_file(manifest_file)
    return verify_runtime_release_source_artifact(
        manifest,
        artifact_kind=artifact_kind,
        artifact_file=artifact_file,
    )


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
    """Run a fixed, offline CLI with no lifecycle or network capability."""

    values = tuple(sys.argv[1:] if arguments is None else arguments)
    try:
        if (
            len(values) == 5
            and values[0] == "create-manifest"
            and values[1] == "--input"
            and values[3] == "--output"
        ):
            result = create_runtime_release_manifest_file(
                Path(values[2]), Path(values[4])
            )
            _emit(
                sys.stdout,
                {
                    "authority": result.authority,
                    "execution_permitted": result.execution_permitted,
                    "manifest_sha256": result.sha256,
                    "production_authorized": result.production_authorized,
                    "status": "MANIFEST_CREATED_NOT_AUTHORITY",
                },
            )
            return 0
        if (
            len(values) == 3
            and values[0] == "validate"
            and values[1] == "--manifest"
        ):
            result = validate_runtime_release_manifest_file(Path(values[2]))
            _emit(
                sys.stdout,
                {
                    "authority": result.authority,
                    "execution_permitted": result.execution_permitted,
                    "manifest_sha256": result.sha256,
                    "production_authorized": result.production_authorized,
                    "status": "MANIFEST_VALIDATED_NOT_AUTHORITY",
                },
            )
            return 0
        if (
            len(values) == 7
            and values[0] == "verify-source-artifact"
            and values[1] == "--manifest"
            and values[3] == "--kind"
            and values[5] == "--artifact"
        ):
            result = verify_runtime_release_source_artifact_file(
                Path(values[2]),
                artifact_kind=values[4],
                artifact_file=Path(values[6]),
            )
            _emit(
                sys.stdout,
                {
                    "artifact_kind": result.artifact_kind,
                    "authority": result.authority,
                    "sha256": result.sha256,
                    "size": result.size,
                    "slot": result.slot,
                    "status": result.status,
                },
            )
            return 0
        if (
            len(values) == 9
            and values[0] == "verify-artifact"
            and values[1] == "--manifest"
            and values[3] == "--slot"
            and values[5] == "--kind"
            and values[7] == "--artifact"
        ):
            result = verify_runtime_release_artifact_file(
                Path(values[2]),
                slot=values[4],
                artifact_kind=values[6],
                artifact_file=Path(values[8]),
            )
            _emit(
                sys.stdout,
                {
                    "artifact_kind": result.artifact_kind,
                    "authority": result.authority,
                    "sha256": result.sha256,
                    "size": result.size,
                    "slot": result.slot,
                    "status": result.status,
                },
            )
            return 0
        return _failure()
    except RuntimeReleaseContractError:
        return _failure()


if __name__ == "__main__":
    raise SystemExit(main())
