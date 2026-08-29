#!/usr/bin/env python3
"""Fetch the fixed PostgreSQL runtime evidence without granting authority.

This is the repository's deliberately narrow online evidence collector.  It
can fetch one of two platform projections from one immutable Docker Hub root
index.  It preserves every registry object byte-for-byte and records content
bindings; it does not verify a signature, establish provenance authenticity,
or authorize execution or deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from types import MappingProxyType
from typing import Any, Callable, NoReturn, Sequence
from urllib.parse import urlsplit, urlunsplit


ERROR_CODE = "PINNED_POSTGRES_RELEASE_EVIDENCE_INVALID"
FORMAT = "desire-pinned-postgres-release-evidence-v1"
STATUS = "CONTENT_FETCHED_UNSIGNED_UNTRUSTED"
AUTHORITY = "NOT_EXECUTION_AUTHORITY"

AUTH_HOST = "auth.docker.io"
REGISTRY_HOST = "registry-1.docker.io"
BLOB_REDIRECT_HOST = "production.cloudfront.docker.com"
REPOSITORY = "library/postgres"
TAG = "18.4-alpine"
ROOT_INDEX_DIGEST = (
    "sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
TOKEN_TARGET = (
    "/token?service=registry.docker.io&"
    "scope=repository%3Alibrary%2Fpostgres%3Apull"
)

REQUEST_TIMEOUT_SECONDS = 30
USER_AGENT = "desire-supply-pinned-postgres-evidence/1"
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
    )
)
BLOB_ACCEPT = "application/octet-stream"

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
IN_TOTO_LAYER = "application/vnd.in-toto+json"
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_V02_PREDICATE = "https://slsa.dev/provenance/v0.2"
STATEMENT_V01 = "https://in-toto.io/Statement/v0.1"

MAX_TOKEN_BYTES = 128 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 128 * 1024 * 1024
MAX_PROVENANCE_BYTES = 32 * 1024 * 1024
MAX_REDIRECT_BYTES = 8 * 1024
MAX_DESCRIPTOR_BYTES = 128 * 1024 * 1024

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRY_TARGET = re.compile(
    r"/v2/library/postgres/(?:manifests|blobs)/sha256:[0-9a-f]{64}\Z"
)
_OUTPUT_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_ARTIFACT_FILES = {
    "root_index": "registry-index.json",
    "platform_manifest": "platform-manifest.json",
    "image_config": "image-config.json",
    "attestation_manifest": "attestation-manifest.json",
    "attestation_config": "attestation-config.json",
    "sbom": "sbom.intoto.json",
    "provenance": "provenance.intoto.json",
}


class PinnedPostgresReleaseEvidenceError(RuntimeError):
    """A stable, deliberately non-reflective collection failure."""

    def __init__(self) -> None:
        super().__init__(ERROR_CODE)


def _invalid() -> NoReturn:
    raise PinnedPostgresReleaseEvidenceError() from None


@dataclass(frozen=True)
class RawArtifact:
    """One exact upstream object retained by the evidence bundle."""

    kind: str
    filename: str
    raw: bytes
    sha256: str
    size: int


@dataclass(frozen=True)
class EvidenceResult:
    """Non-authoritative public result; deliberately contains no token or URL."""

    architecture: str
    root_index_digest: str
    platform_manifest_digest: str
    config_digest: str
    attestation_manifest_digest: str
    status: str = STATUS
    authority: str = AUTHORITY


@dataclass(frozen=True)
class PinnedPlatformGraph:
    """The complete fixed descriptor graph for one supported upstream platform."""

    platform_manifest_digest: str
    platform_manifest_size: int
    config_digest: str
    config_size: int
    attestation_manifest_digest: str
    attestation_manifest_size: int
    attestation_config_digest: str
    attestation_config_size: int
    sbom_digest: str
    sbom_size: int
    provenance_digest: str
    provenance_size: int


PINNED_PLATFORM_GRAPHS = MappingProxyType({
    "amd64": PinnedPlatformGraph(
        platform_manifest_digest=(
            "sha256:b6a16ed0eb96e2c362811f7eeb951eac8b459e7b40be4149ea5444aa7c65569b"
        ),
        platform_manifest_size=2678,
        config_digest=(
            "sha256:bd1890816ae0b8ad4644f05728570d4be774e1f1490d7232f5084b52ea335183"
        ),
        config_size=8509,
        attestation_manifest_digest=(
            "sha256:d47cbb6b172896421df55c9a7afd3727a92a7ff05a17c5d910175dc7ff11cedf"
        ),
        attestation_manifest_size=840,
        attestation_config_digest=(
            "sha256:8eac90f8e0d28c3c0058be8dce6df773a71f50c2df7c289e8ff435ebffff3ed8"
        ),
        attestation_config_size=241,
        sbom_digest=(
            "sha256:32a5a1abaaf0428efca7ce410da748c62bd9b40d464d5056bf23c5cf276f7077"
        ),
        sbom_size=617266,
        provenance_digest=(
            "sha256:71608f5c0921ef359a3f846d6ad12ae74f82eb68be4c0227c59a4a128e778f1f"
        ),
        provenance_size=41048,
    ),
    "arm64": PinnedPlatformGraph(
        platform_manifest_digest=(
            "sha256:122c9942437efcbbb8d595fc578dee7d26ee1543c2a8634d183adfa4a1e55b4d"
        ),
        platform_manifest_size=2680,
        config_digest=(
            "sha256:db676a0ed906c00f55020fb8999e4fb30c598bf5c3b5c188630aef2812d3f11d"
        ),
        config_size=8523,
        attestation_manifest_digest=(
            "sha256:337172f3d66e8a9298a194cb848d1758e905e3b00d21aec6f1e88e57bf06097b"
        ),
        attestation_manifest_size=840,
        attestation_config_digest=(
            "sha256:ee4c7f901212ee3d1bc83d0fbc9d5035e940552f190c43db998dd3b40aca558a"
        ),
        attestation_config_size=241,
        sbom_digest=(
            "sha256:071cfbe442f0a554a67398a207788a4d31f27101e7385d707cacf29668b19ae0"
        ),
        sbom_size=616696,
        provenance_digest=(
            "sha256:063e7a583f48258c2edd38cd65871659878a61fa39539b78ef58031b3451542e"
        ),
        provenance_size=41266,
    ),
})


class _NetworkResponse:
    """Tie a one-shot HTTP response to its connection."""

    def __init__(self, response: object, connection: object) -> None:
        self._response = response
        self._connection = connection
        self.status = getattr(response, "status", None)
        self.headers = getattr(response, "headers", None)

    def read(self, amount: int) -> bytes:
        return self._response.read(amount)  # type: ignore[attr-defined]

    def close(self) -> None:
        try:
            self._response.close()  # type: ignore[attr-defined]
        finally:
            self._connection.close()  # type: ignore[attr-defined]


class DockerHubEvidenceTransport:
    """Direct three-host HTTPS transport with no proxy, netrc, retry, or cookie jar."""

    def __init__(
        self,
        *,
        connection_factory: Callable[..., object] = HTTPSConnection,
    ) -> None:
        if not callable(connection_factory):
            _invalid()
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if (
            not context.check_hostname
            or context.verify_mode != ssl.CERT_REQUIRED
            or context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            _invalid()
        self._connection_factory = connection_factory
        self._context = context
        self._closed = False
        self._connections: list[object] = []

    def request(
        self,
        *,
        host: str,
        target: str,
        headers: dict[str, str],
        timeout: int,
        cloudfront_redirect: bool = False,
    ) -> object:
        """Issue one GET after independently enforcing the fixed network boundary."""

        if (
            self._closed
            or type(host) is not str
            or type(target) is not str
            or type(timeout) is not int
            or not 1 <= timeout <= 60
            or type(cloudfront_redirect) is not bool
            or not isinstance(headers, dict)
        ):
            _invalid()
        if any(
            type(key) is not str or type(value) is not str
            for key, value in headers.items()
        ):
            _invalid()
        lowered = {key.lower(): value for key, value in headers.items()}
        if (
            len(lowered) != len(headers)
            or lowered.get("accept-encoding") != "identity"
            or lowered.get("user-agent") != USER_AGENT
            or any(
                forbidden in lowered
                for forbidden in (
                    "host",
                    "connection",
                    "proxy-authorization",
                    "cookie",
                    "referer",
                )
            )
        ):
            _invalid()

        if host == AUTH_HOST:
            if cloudfront_redirect or target != TOKEN_TARGET or "authorization" in lowered:
                _invalid()
        elif host == REGISTRY_HOST:
            if cloudfront_redirect or _REGISTRY_TARGET.fullmatch(target) is None:
                _invalid()
            authorization = lowered.get("authorization")
            if (
                authorization is None
                or re.fullmatch(r"Bearer [^\x00-\x20\x7f]{1,16384}", authorization) is None
            ):
                _invalid()
        elif host == BLOB_REDIRECT_HOST:
            if (
                not cloudfront_redirect
                or "authorization" in lowered
                or not target.startswith("/")
                or len(target) > MAX_REDIRECT_BYTES
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in target)
            ):
                _invalid()
        else:
            _invalid()

        try:
            connection = self._connection_factory(
                host,
                443,
                timeout=timeout,
                context=self._context,
            )
            self._connections.append(connection)
            connection.request("GET", target, headers=headers)  # type: ignore[attr-defined]
            response = connection.getresponse()  # type: ignore[attr-defined]
            return _NetworkResponse(response, connection)
        except PinnedPostgresReleaseEvidenceError:
            raise
        except Exception:
            _invalid()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for connection in self._connections:
            try:
                connection.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        self._connections.clear()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if type(key) is not str or key in result:
            _invalid()
        result[key] = value
    return result


def _reject_number(_value: str) -> NoReturn:
    _invalid()


def _json_object(raw: bytes, *, maximum: int) -> dict[str, Any]:
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
    except PinnedPostgresReleaseEvidenceError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        _invalid()


def _closed(value: Any, keys: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        _invalid()
    return value


def _allowed(
    value: Any,
    *,
    required: Sequence[str],
    allowed: Sequence[str],
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


def _size(value: Any, *, maximum: int = MAX_DESCRIPTOR_BYTES) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        _invalid()
    return value


def _annotations(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 64:
        _invalid()
    for key, item in value.items():
        if (
            type(key) is not str
            or type(item) is not str
            or not 0 < len(key) <= 256
            or len(item) > 2048
        ):
            _invalid()
    return value


def _platform(value: Any) -> dict[str, Any]:
    platform = _allowed(
        value,
        required=("architecture", "os"),
        allowed=(
            "architecture",
            "os",
            "variant",
            "features",
            "os.version",
            "os.features",
        ),
    )
    if (
        type(platform["architecture"]) is not str
        or type(platform["os"]) is not str
        or not platform["architecture"]
        or not platform["os"]
    ):
        _invalid()
    if "variant" in platform and type(platform["variant"]) is not str:
        _invalid()
    for name in ("features", "os.features"):
        if name in platform and (
            not isinstance(platform[name], list)
            or len(platform[name]) > 64
            or not all(type(item) is str for item in platform[name])
        ):
            _invalid()
    if "os.version" in platform and type(platform["os.version"]) is not str:
        _invalid()
    return platform


def _descriptor(value: Any, *, maximum: int) -> dict[str, Any]:
    descriptor = _allowed(
        value,
        required=("mediaType", "digest", "size"),
        allowed=("mediaType", "digest", "size", "platform", "annotations"),
    )
    if type(descriptor["mediaType"]) is not str or not descriptor["mediaType"]:
        _invalid()
    _digest(descriptor["digest"])
    _size(descriptor["size"], maximum=maximum)
    if "platform" in descriptor:
        _platform(descriptor["platform"])
    if "annotations" in descriptor:
        _annotations(descriptor["annotations"])
    return descriptor


def _one_header(headers: Any, name: str, *, required: bool = False) -> str | None:
    try:
        values = headers.get_all(name) if headers is not None else None
    except Exception:
        _invalid()
    if values is None:
        if required:
            _invalid()
        return None
    if not isinstance(values, list) or len(values) != 1 or type(values[0]) is not str:
        _invalid()
    return values[0]


def _response_bytes(response: object, *, maximum: int, expected_status: int = 200) -> bytes:
    try:
        if getattr(response, "status", None) != expected_status:
            _invalid()
        headers = getattr(response, "headers", None)
        encoding = _one_header(headers, "Content-Encoding")
        if encoding is not None and encoding.lower() != "identity":
            _invalid()
        content_length = _one_header(headers, "Content-Length")
        if content_length is not None:
            if re.fullmatch(r"0|[1-9][0-9]{0,9}", content_length) is None:
                _invalid()
            declared = int(content_length)
            if declared > maximum:
                _invalid()
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = response.read(  # type: ignore[attr-defined]
                min(1024 * 1024, maximum + 1 - total)
            )
            if type(chunk) is not bytes:
                _invalid()
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum:
            _invalid()
        raw = b"".join(chunks)
        if content_length is not None and len(raw) != int(content_length):
            _invalid()
        return raw
    finally:
        try:
            response.close()  # type: ignore[attr-defined]
        except Exception:
            pass


def _base_headers(*, accept: str, token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": accept,
        "Accept-Encoding": "identity",
        "User-Agent": USER_AGENT,
    }
    if token is not None:
        if type(token) is not str or re.fullmatch(r"[^\x00-\x20\x7f]{1,16384}", token) is None:
            _invalid()
        headers["Authorization"] = "Bearer " + token
    return headers


def _fetch_token(transport: object) -> str:
    response = transport.request(  # type: ignore[attr-defined]
        host=AUTH_HOST,
        target=TOKEN_TARGET,
        headers=_base_headers(accept="application/json"),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    raw = _response_bytes(response, maximum=MAX_TOKEN_BYTES)
    token_document = _allowed(
        _json_object(raw, maximum=MAX_TOKEN_BYTES),
        required=("token",),
        allowed=("token", "access_token", "expires_in", "issued_at"),
    )
    token = token_document["token"]
    if type(token) is not str or re.fullmatch(r"[^\x00-\x20\x7f]{1,16384}", token) is None:
        _invalid()
    if "access_token" in token_document and token_document["access_token"] != token:
        _invalid()
    if "expires_in" in token_document and (
        type(token_document["expires_in"]) is not int
        or token_document["expires_in"] <= 0
    ):
        _invalid()
    if "issued_at" in token_document and type(token_document["issued_at"]) is not str:
        _invalid()
    return token


def _manifest_target(digest: str) -> str:
    return f"/v2/{REPOSITORY}/manifests/{_digest(digest)}"


def _blob_target(digest: str) -> str:
    return f"/v2/{REPOSITORY}/blobs/{_digest(digest)}"


def _fetch_manifest(
    transport: object,
    *,
    token: str,
    digest: str,
    expected_size: int | None,
    maximum: int,
) -> bytes:
    response = transport.request(  # type: ignore[attr-defined]
        host=REGISTRY_HOST,
        target=_manifest_target(digest),
        headers=_base_headers(accept=MANIFEST_ACCEPT, token=token),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    headers = getattr(response, "headers", None)
    raw = _response_bytes(response, maximum=maximum)
    content_digest = _one_header(headers, "Docker-Content-Digest", required=True)
    if (
        content_digest != digest
        or (expected_size is not None and len(raw) != expected_size)
        or hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:")
    ):
        _invalid()
    return raw


def _redirect_selector(response: object) -> str:
    location = _one_header(getattr(response, "headers", None), "Location", required=True)
    try:
        parsed = urlsplit(location)
        port = parsed.port
    except (TypeError, ValueError):
        _invalid()
    if (
        parsed.scheme != "https"
        or parsed.hostname != BLOB_REDIRECT_HOST
        or parsed.netloc != BLOB_REDIRECT_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or len(location) > MAX_REDIRECT_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in location)
    ):
        _invalid()
    return urlunsplit(("", "", parsed.path, parsed.query, ""))


def _fetch_blob(
    transport: object,
    *,
    token: str,
    descriptor: dict[str, Any],
    maximum: int,
) -> bytes:
    digest = _digest(descriptor["digest"])
    expected_size = _size(descriptor["size"], maximum=maximum)
    response = transport.request(  # type: ignore[attr-defined]
        host=REGISTRY_HOST,
        target=_blob_target(digest),
        headers=_base_headers(accept=BLOB_ACCEPT, token=token),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    status_code = getattr(response, "status", None)
    if status_code == 307:
        try:
            selector = _redirect_selector(response)
        finally:
            try:
                response.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        response = transport.request(  # type: ignore[attr-defined]
            host=BLOB_REDIRECT_HOST,
            target=selector,
            headers=_base_headers(accept=BLOB_ACCEPT),
            timeout=REQUEST_TIMEOUT_SECONDS,
            cloudfront_redirect=True,
        )
    raw = _response_bytes(response, maximum=maximum)
    if (
        len(raw) != expected_size
        or hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:")
    ):
        _invalid()
    return raw


def _target_platform(architecture: str) -> dict[str, str]:
    if architecture == "amd64":
        return {"architecture": "amd64", "os": "linux"}
    if architecture == "arm64":
        return {"architecture": "arm64", "os": "linux", "variant": "v8"}
    _invalid()


def _pinned_graph(architecture: str) -> PinnedPlatformGraph:
    graph = PINNED_PLATFORM_GRAPHS.get(architecture)
    if not isinstance(graph, PinnedPlatformGraph):
        _invalid()
    for digest in (
        graph.platform_manifest_digest,
        graph.config_digest,
        graph.attestation_manifest_digest,
        graph.attestation_config_digest,
        graph.sbom_digest,
        graph.provenance_digest,
    ):
        _digest(digest)
    for size in (
        graph.platform_manifest_size,
        graph.config_size,
        graph.attestation_manifest_size,
        graph.attestation_config_size,
        graph.sbom_size,
        graph.provenance_size,
    ):
        _size(size, maximum=MAX_DESCRIPTOR_BYTES)
    return graph


def _same_platform(value: Any, expected: dict[str, str]) -> bool:
    if not isinstance(value, dict):
        return False
    actual = {key: value.get(key) for key in ("architecture", "os", "variant") if key in value}
    return actual == expected


def _root_bindings(
    raw: bytes,
    *,
    architecture: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if hashlib.sha256(raw).hexdigest() != ROOT_INDEX_DIGEST.removeprefix("sha256:"):
        _invalid()
    index = _allowed(
        _json_object(raw, maximum=MAX_INDEX_BYTES),
        required=("schemaVersion", "mediaType", "manifests"),
        allowed=("schemaVersion", "mediaType", "manifests", "annotations"),
    )
    if index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX:
        _invalid()
    if "annotations" in index:
        _annotations(index["annotations"])
    if not isinstance(index["manifests"], list) or not 4 <= len(index["manifests"]) <= 256:
        _invalid()
    descriptors = tuple(
        _descriptor(item, maximum=MAX_MANIFEST_BYTES)
        for item in index["manifests"]
    )
    if len({item["digest"] for item in descriptors}) != len(descriptors):
        _invalid()

    fixed_platforms = {
        "amd64": {"architecture": "amd64", "os": "linux"},
        "arm64": {"architecture": "arm64", "os": "linux", "variant": "v8"},
    }
    runnable_by_arch: dict[str, dict[str, Any]] = {}
    for name, expected in fixed_platforms.items():
        matches = [
            item
            for item in descriptors
            if item["mediaType"] == OCI_MANIFEST and _same_platform(item.get("platform"), expected)
        ]
        if len(matches) != 1:
            _invalid()
        runnable_by_arch[name] = matches[0]

    attestation_by_digest: dict[str, list[dict[str, Any]]] = {}
    for item in descriptors:
        platform = item.get("platform")
        annotations = item.get("annotations", {})
        if (
            isinstance(platform, dict)
            and platform.get("os") == "unknown"
            and platform.get("architecture") == "unknown"
        ):
            if (
                item["mediaType"] != OCI_MANIFEST
                or set(annotations) != {
                    "vnd.docker.reference.digest",
                    "vnd.docker.reference.type",
                }
                or annotations.get("vnd.docker.reference.type") != "attestation-manifest"
            ):
                _invalid()
            reference_digest = _digest(annotations.get("vnd.docker.reference.digest"))
            attestation_by_digest.setdefault(reference_digest, []).append(item)

    for runnable in runnable_by_arch.values():
        if len(attestation_by_digest.get(runnable["digest"], ())) != 1:
            _invalid()
    for name, runnable in runnable_by_arch.items():
        graph = _pinned_graph(name)
        attestation = attestation_by_digest[runnable["digest"]][0]
        if (
            runnable["digest"] != graph.platform_manifest_digest
            or runnable["size"] != graph.platform_manifest_size
            or attestation["digest"] != graph.attestation_manifest_digest
            or attestation["size"] != graph.attestation_manifest_size
        ):
            _invalid()
    selected = runnable_by_arch[architecture]
    return selected, attestation_by_digest[selected["digest"]][0]


def _manifest(
    raw: bytes,
    *,
    expected_digest: str,
    expected_size: int,
    legacy_attestation: bool,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    if (
        len(raw) != expected_size
        or hashlib.sha256(raw).hexdigest() != expected_digest.removeprefix("sha256:")
    ):
        _invalid()
    manifest = _closed(
        _json_object(raw, maximum=MAX_MANIFEST_BYTES),
        ("schemaVersion", "mediaType", "config", "layers"),
    )
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST:
        _invalid()
    config = _descriptor(manifest["config"], maximum=MAX_CONFIG_BYTES)
    if config["mediaType"] != OCI_CONFIG or "platform" in config or "annotations" in config:
        _invalid()
    layers_value = manifest["layers"]
    if not isinstance(layers_value, list):
        _invalid()
    if legacy_attestation:
        if len(layers_value) != 2:
            _invalid()
    elif not 1 <= len(layers_value) <= 256:
        _invalid()
    layers = tuple(
        _descriptor(item, maximum=MAX_DESCRIPTOR_BYTES)
        for item in layers_value
    )
    if legacy_attestation:
        for layer in layers:
            if layer["mediaType"] != IN_TOTO_LAYER or "platform" in layer:
                _invalid()
    else:
        allowed_layers = {
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
        }
        if any(layer["mediaType"] not in allowed_layers for layer in layers):
            _invalid()
    return config, layers


def _image_config(
    raw: bytes,
    *,
    descriptor: dict[str, Any],
    architecture: str,
    layer_count: int,
) -> None:
    if (
        len(raw) != descriptor["size"]
        or hashlib.sha256(raw).hexdigest() != descriptor["digest"].removeprefix("sha256:")
    ):
        _invalid()
    config = _allowed(
        _json_object(raw, maximum=MAX_CONFIG_BYTES),
        required=("architecture", "os", "config", "rootfs"),
        allowed=(
            "architecture",
            "os",
            "variant",
            "config",
            "rootfs",
            "created",
            "author",
            "history",
            "os.version",
            "os.features",
        ),
    )
    expected = _target_platform(architecture)
    if config["architecture"] != expected["architecture"] or config["os"] != "linux":
        _invalid()
    if expected.get("variant") is not None and config.get("variant") not in (
        None,
        expected["variant"],
    ):
        _invalid()
    if not isinstance(config["config"], dict):
        _invalid()
    rootfs = _closed(config["rootfs"], ("type", "diff_ids"))
    if rootfs["type"] != "layers" or not isinstance(rootfs["diff_ids"], list):
        _invalid()
    if len(rootfs["diff_ids"]) != layer_count:
        _invalid()
    for digest in rootfs["diff_ids"]:
        _digest(digest)
    if "history" in config and (
        not isinstance(config["history"], list)
        or len(config["history"]) > 4096
        or not all(isinstance(item, dict) for item in config["history"])
    ):
        _invalid()


def _attestation_layers(layers: Sequence[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    expected = {
        SPDX_PREDICATE: "sbom",
        SLSA_V02_PREDICATE: "provenance",
    }
    for layer in layers:
        annotations = layer.get("annotations")
        if not isinstance(annotations, dict) or set(annotations) != {"in-toto.io/predicate-type"}:
            _invalid()
        kind = expected.get(annotations["in-toto.io/predicate-type"])
        if kind is None or kind in found:
            _invalid()
        found[kind] = layer
    if set(found) != {"sbom", "provenance"}:
        _invalid()
    return found["sbom"], found["provenance"]


def _legacy_attestation_config(
    raw: bytes,
    *,
    descriptor: dict[str, Any],
    layers: Sequence[dict[str, Any]],
) -> None:
    if (
        len(raw) != descriptor["size"]
        or hashlib.sha256(raw).hexdigest() != descriptor["digest"].removeprefix("sha256:")
    ):
        _invalid()
    config = _closed(
        _json_object(raw, maximum=MAX_CONFIG_BYTES),
        ("architecture", "os", "config", "rootfs"),
    )
    if config["architecture"] != "unknown" or config["os"] != "unknown" or config["config"] != {}:
        _invalid()
    rootfs = _closed(config["rootfs"], ("type", "diff_ids"))
    if rootfs["type"] != "layers" or rootfs["diff_ids"] != [item["digest"] for item in layers]:
        _invalid()


def _statement_subjects(statement: dict[str, Any], *, platform_digest: str) -> None:
    subjects = statement["subject"]
    if not isinstance(subjects, list) or len(subjects) != 13:
        _invalid()
    expected = platform_digest.removeprefix("sha256:")
    for value in subjects:
        subject = _closed(value, ("name", "digest"))
        if type(subject["name"]) is not str or len(subject["name"]) > 2048:
            _invalid()
        digest = _closed(subject["digest"], ("sha256",))
        if digest["sha256"] != expected:
            _invalid()


def _spdx_predicate(value: Any) -> None:
    spdx = _allowed(
        value,
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
    if (
        spdx["SPDXID"] != "SPDXRef-DOCUMENT"
        or spdx["spdxVersion"] != "SPDX-2.3"
        or spdx["dataLicense"] != "CC0-1.0"
        or type(spdx["name"]) is not str
        or type(spdx["documentNamespace"]) is not str
        or not isinstance(spdx["packages"], list)
        or len(spdx["packages"]) > 100000
        or not all(isinstance(item, dict) for item in spdx["packages"])
    ):
        _invalid()
    creation = _allowed(
        spdx["creationInfo"],
        required=("created", "creators"),
        allowed=("created", "creators", "licenseListVersion", "comment"),
    )
    if (
        type(creation["created"]) is not str
        or not isinstance(creation["creators"], list)
        or not creation["creators"]
        or not all(type(item) is str for item in creation["creators"])
    ):
        _invalid()
    for name in (
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
        if name in spdx and not isinstance(spdx[name], list):
            _invalid()
    if "comment" in spdx and type(spdx["comment"]) is not str:
        _invalid()


def _digest_mapping(value: Any) -> None:
    if not isinstance(value, dict) or set(value) not in ({"sha1"}, {"sha256"}):
        _invalid()
    algorithm = next(iter(value))
    encoded = value[algorithm]
    if type(encoded) is not str or (
        algorithm == "sha1" and _HEX40.fullmatch(encoded) is None
    ) or (
        algorithm == "sha256" and _HEX64.fullmatch(encoded) is None
    ):
        _invalid()


def _provenance_predicate(value: Any) -> None:
    predicate = _allowed(
        value,
        required=("builder", "buildType", "invocation", "metadata", "materials"),
        allowed=("builder", "buildType", "invocation", "buildConfig", "metadata", "materials"),
    )
    builder = _allowed(
        predicate["builder"],
        required=("id",),
        allowed=("id", "builderDependencies", "version"),
    )
    if (
        type(builder["id"]) is not str
        or "github.com/docker-library" not in builder["id"]
        or type(predicate["buildType"]) is not str
        or not predicate["buildType"]
        or not isinstance(predicate["metadata"], dict)
    ):
        _invalid()
    if "buildConfig" in predicate and not isinstance(predicate["buildConfig"], dict):
        _invalid()
    invocation = _closed(predicate["invocation"], ("configSource", "environment", "parameters"))
    config_source = _allowed(
        invocation["configSource"],
        required=(),
        allowed=("uri", "entryPoint"),
    )
    if "uri" in config_source and type(config_source["uri"]) is not str:
        _invalid()
    if "entryPoint" in config_source and type(config_source["entryPoint"]) is not str:
        _invalid()
    if not isinstance(invocation["environment"], dict):
        _invalid()
    parameters = _allowed(
        invocation["parameters"],
        required=("args", "frontend", "secrets"),
        allowed=("args", "frontend", "secrets", "locals", "ssh"),
    )
    if (
        not isinstance(parameters["args"], dict)
        or type(parameters["frontend"]) is not str
        or not parameters["frontend"]
        or not isinstance(parameters["secrets"], list)
    ):
        _invalid()
    for optional in ("locals", "ssh"):
        if optional in parameters and not isinstance(parameters[optional], list):
            _invalid()
    materials = predicate["materials"]
    if not isinstance(materials, list) or len(materials) > 4096:
        _invalid()
    for material in materials:
        item = _closed(material, ("uri", "digest"))
        if type(item["uri"]) is not str or not 0 < len(item["uri"]) <= 4096:
            _invalid()
        _digest_mapping(item["digest"])


def _statement(raw: bytes, *, kind: str, platform_digest: str) -> None:
    maximum = MAX_SBOM_BYTES if kind == "sbom" else MAX_PROVENANCE_BYTES
    statement = _closed(
        _json_object(raw, maximum=maximum),
        ("_type", "subject", "predicateType", "predicate"),
    )
    if statement["_type"] != STATEMENT_V01:
        _invalid()
    _statement_subjects(statement, platform_digest=platform_digest)
    if kind == "sbom":
        if statement["predicateType"] != SPDX_PREDICATE:
            _invalid()
        _spdx_predicate(statement["predicate"])
    elif kind == "provenance":
        if statement["predicateType"] != SLSA_V02_PREDICATE:
            _invalid()
        _provenance_predicate(statement["predicate"])
    else:
        _invalid()


def _raw_artifact(kind: str, raw: bytes) -> RawArtifact:
    filename = _ARTIFACT_FILES.get(kind)
    if filename is None or type(raw) is not bytes:
        _invalid()
    return RawArtifact(
        kind=kind,
        filename=filename,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )


def _collect(
    transport: object,
    *,
    architecture: str,
) -> tuple[tuple[RawArtifact, ...], EvidenceResult]:
    _target_platform(architecture)
    graph = _pinned_graph(architecture)
    token = _fetch_token(transport)
    root_raw = _fetch_manifest(
        transport,
        token=token,
        digest=ROOT_INDEX_DIGEST,
        expected_size=None,
        maximum=MAX_INDEX_BYTES,
    )
    platform_descriptor, attestation_descriptor = _root_bindings(
        root_raw,
        architecture=architecture,
    )

    platform_raw = _fetch_manifest(
        transport,
        token=token,
        digest=platform_descriptor["digest"],
        expected_size=platform_descriptor["size"],
        maximum=MAX_MANIFEST_BYTES,
    )
    image_config_descriptor, platform_layers = _manifest(
        platform_raw,
        expected_digest=platform_descriptor["digest"],
        expected_size=platform_descriptor["size"],
        legacy_attestation=False,
    )
    if (
        image_config_descriptor["digest"] != graph.config_digest
        or image_config_descriptor["size"] != graph.config_size
    ):
        _invalid()
    image_config_raw = _fetch_blob(
        transport,
        token=token,
        descriptor=image_config_descriptor,
        maximum=MAX_CONFIG_BYTES,
    )
    _image_config(
        image_config_raw,
        descriptor=image_config_descriptor,
        architecture=architecture,
        layer_count=len(platform_layers),
    )

    attestation_raw = _fetch_manifest(
        transport,
        token=token,
        digest=attestation_descriptor["digest"],
        expected_size=attestation_descriptor["size"],
        maximum=MAX_MANIFEST_BYTES,
    )
    attestation_config_descriptor, attestation_layers = _manifest(
        attestation_raw,
        expected_digest=attestation_descriptor["digest"],
        expected_size=attestation_descriptor["size"],
        legacy_attestation=True,
    )
    sbom_descriptor, provenance_descriptor = _attestation_layers(attestation_layers)
    if (
        attestation_config_descriptor["digest"] != graph.attestation_config_digest
        or attestation_config_descriptor["size"] != graph.attestation_config_size
        or sbom_descriptor["digest"] != graph.sbom_digest
        or sbom_descriptor["size"] != graph.sbom_size
        or provenance_descriptor["digest"] != graph.provenance_digest
        or provenance_descriptor["size"] != graph.provenance_size
    ):
        _invalid()
    attestation_config_raw = _fetch_blob(
        transport,
        token=token,
        descriptor=attestation_config_descriptor,
        maximum=MAX_CONFIG_BYTES,
    )
    _legacy_attestation_config(
        attestation_config_raw,
        descriptor=attestation_config_descriptor,
        layers=attestation_layers,
    )
    sbom_raw = _fetch_blob(
        transport,
        token=token,
        descriptor=sbom_descriptor,
        maximum=MAX_SBOM_BYTES,
    )
    provenance_raw = _fetch_blob(
        transport,
        token=token,
        descriptor=provenance_descriptor,
        maximum=MAX_PROVENANCE_BYTES,
    )
    _statement(sbom_raw, kind="sbom", platform_digest=platform_descriptor["digest"])
    _statement(provenance_raw, kind="provenance", platform_digest=platform_descriptor["digest"])

    artifacts = (
        _raw_artifact("root_index", root_raw),
        _raw_artifact("platform_manifest", platform_raw),
        _raw_artifact("image_config", image_config_raw),
        _raw_artifact("attestation_manifest", attestation_raw),
        _raw_artifact("attestation_config", attestation_config_raw),
        _raw_artifact("sbom", sbom_raw),
        _raw_artifact("provenance", provenance_raw),
    )
    result = EvidenceResult(
        architecture=architecture,
        root_index_digest=ROOT_INDEX_DIGEST,
        platform_manifest_digest=platform_descriptor["digest"],
        config_digest=image_config_descriptor["digest"],
        attestation_manifest_digest=attestation_descriptor["digest"],
    )
    return artifacts, result


@dataclass
class _OutputDestination:
    parent_descriptor: int
    parent_device: int
    parent_inode: int
    leaf: str

    def close(self) -> None:
        try:
            os.close(self.parent_descriptor)
        except OSError:
            pass


def _prepare_output(value: str | os.PathLike[str]) -> _OutputDestination:
    try:
        encoded = os.fspath(value)
        if type(encoded) is not str or "\x00" in encoded:
            _invalid()
        path = Path(encoded)
        if not path.is_absolute() or ".." in path.parts or path.name in ("", ".", ".."):
            _invalid()
        if _OUTPUT_LEAF.fullmatch(path.name) is None:
            _invalid()
        parent = path.parent
        unresolved_parent = os.stat(parent, follow_symlinks=False)
        if stat.S_ISLNK(unresolved_parent.st_mode):
            _invalid()
        # macOS commonly exposes /var as an absolute alias of /private/var.
        # Resolve ancestor aliases once, then bind all operations to the
        # resulting directory descriptor.  A symlink as the immediate parent
        # remains forbidden.
        parent = parent.resolve(strict=True)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = os.open(parent, flags)
        parent_stat = os.fstat(parent_descriptor)
        visible_stat = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or (parent_stat.st_dev, parent_stat.st_ino)
            != (visible_stat.st_dev, visible_stat.st_ino)
        ):
            os.close(parent_descriptor)
            _invalid()
        try:
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            os.close(parent_descriptor)
            _invalid()
        return _OutputDestination(
            parent_descriptor=parent_descriptor,
            parent_device=parent_stat.st_dev,
            parent_inode=parent_stat.st_ino,
            leaf=path.name,
        )
    except PinnedPostgresReleaseEvidenceError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _invalid()


def _canonical(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _invalid()


def _evidence_document(artifacts: Sequence[RawArtifact], result: EvidenceResult) -> bytes:
    expected_order = tuple(_ARTIFACT_FILES)
    if tuple(item.kind for item in artifacts) != expected_order:
        _invalid()
    for item in artifacts:
        if (
            item.filename != _ARTIFACT_FILES[item.kind]
            or item.size != len(item.raw)
            or item.sha256 != hashlib.sha256(item.raw).hexdigest()
        ):
            _invalid()
    by_kind = {item.kind: item for item in artifacts}
    if (
        result.root_index_digest != "sha256:" + by_kind["root_index"].sha256
        or result.platform_manifest_digest
        != "sha256:" + by_kind["platform_manifest"].sha256
        or result.config_digest != "sha256:" + by_kind["image_config"].sha256
        or result.attestation_manifest_digest
        != "sha256:" + by_kind["attestation_manifest"].sha256
    ):
        _invalid()
    platform = _target_platform(result.architecture)
    return _canonical(
        {
            "architecture": result.architecture,
            "artifacts": [
                {
                    "kind": item.kind,
                    "name": item.filename,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in artifacts
            ],
            "attestation_manifest_digest": result.attestation_manifest_digest,
            "authenticity_verified": False,
            "authority": AUTHORITY,
            "config_digest": result.config_digest,
            "execution_permitted": False,
            "format": FORMAT,
            "platform_manifest_digest": result.platform_manifest_digest,
            "production_authorized": False,
            "reference": f"docker.io/{REPOSITORY}:{TAG}@{ROOT_INDEX_DIGEST}",
            "repository": REPOSITORY,
            "root_index_digest": ROOT_INDEX_DIGEST,
            "signature_verified": False,
            "status": STATUS,
            "target_platform": platform,
        }
    )


@dataclass(frozen=True)
class _DirectoryIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class _CreatedFile:
    name: str
    device: int
    inode: int
    size: int
    sha256: str


def _same_identity(metadata: os.stat_result, *, device: int, inode: int) -> bool:
    return (metadata.st_dev, metadata.st_ino) == (device, inode)


def _visible_directory_matches(
    destination: _OutputDestination,
    identity: _DirectoryIdentity,
) -> bool:
    try:
        visible = os.stat(
            destination.leaf,
            dir_fd=destination.parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        stat.S_ISDIR(visible.st_mode)
        and stat.S_IMODE(visible.st_mode) == 0o700
        and visible.st_uid == os.geteuid()
        and _same_identity(
            visible,
            device=identity.device,
            inode=identity.inode,
        )
    )


def _write_file(
    directory_descriptor: int,
    name: str,
    raw: bytes,
    created_files: list[_CreatedFile],
) -> None:
    if (
        name not in {*_ARTIFACT_FILES.values(), "evidence.json"}
        or type(raw) is not bytes
        or not isinstance(created_files, list)
        or any(item.name == name for item in created_files)
    ):
        _invalid()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
        ):
            _invalid()
        record = _CreatedFile(
            name=name,
            device=opened.st_dev,
            inode=opened.st_ino,
            size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )
        created_files.append(record)
        os.fchmod(descriptor, 0o400)
        secured = os.fstat(descriptor)
        if (
            not _same_identity(
                secured,
                device=record.device,
                inode=record.inode,
            )
            or not stat.S_ISREG(secured.st_mode)
            or stat.S_IMODE(secured.st_mode) != 0o400
            or secured.st_uid != os.geteuid()
            or secured.st_nlink != 1
        ):
            _invalid()
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _invalid()
            view = view[written:]
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        if (
            not _same_identity(
                completed,
                device=record.device,
                inode=record.inode,
            )
            or completed.st_size != record.size
            or stat.S_IMODE(completed.st_mode) != 0o400
            or completed.st_uid != os.geteuid()
            or completed.st_nlink != 1
        ):
            _invalid()
    except PinnedPostgresReleaseEvidenceError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_visible_file(
    directory_descriptor: int,
    record: _CreatedFile,
    raw: bytes,
) -> None:
    if (
        type(raw) is not bytes
        or record.size != len(raw)
        or record.sha256 != hashlib.sha256(raw).hexdigest()
    ):
        _invalid()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(record.name, flags, dir_fd=directory_descriptor)
        opened = os.fstat(descriptor)
        visible = os.stat(
            record.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        for metadata in (opened, visible):
            if (
                not _same_identity(
                    metadata,
                    device=record.device,
                    inode=record.inode,
                )
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_size != record.size
            ):
                _invalid()
        digest = hashlib.sha256()
        offset = 0
        while offset < len(raw):
            chunk = os.read(descriptor, min(1024 * 1024, len(raw) - offset))
            if not chunk or chunk != raw[offset : offset + len(chunk)]:
                _invalid()
            digest.update(chunk)
            offset += len(chunk)
        if os.read(descriptor, 1) or digest.hexdigest() != record.sha256:
            _invalid()
        completed = os.fstat(descriptor)
        visible_after = os.stat(
            record.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        for metadata in (completed, visible_after):
            if (
                not _same_identity(
                    metadata,
                    device=record.device,
                    inode=record.inode,
                )
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_size != record.size
            ):
                _invalid()
    except PinnedPostgresReleaseEvidenceError:
        raise
    except OSError:
        _invalid()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_committed_bundle(
    destination: _OutputDestination,
    directory_descriptor: int,
    identity: _DirectoryIdentity,
    payloads: Sequence[tuple[str, bytes]],
    created_files: Sequence[_CreatedFile],
) -> None:
    if not _visible_directory_matches(destination, identity):
        _invalid()
    parent = os.fstat(destination.parent_descriptor)
    directory = os.fstat(directory_descriptor)
    if (
        not _same_identity(
            parent,
            device=destination.parent_device,
            inode=destination.parent_inode,
        )
        or not stat.S_ISDIR(directory.st_mode)
        or stat.S_IMODE(directory.st_mode) != 0o700
        or directory.st_uid != os.geteuid()
        or not _same_identity(
            directory,
            device=identity.device,
            inode=identity.inode,
        )
    ):
        _invalid()
    expected_names = {name for name, _raw in payloads}
    records = {item.name: item for item in created_files}
    if (
        len(payloads) != 8
        or len(expected_names) != 8
        or len(created_files) != 8
        or len(records) != 8
        or set(records) != expected_names
        or set(os.listdir(directory_descriptor)) != expected_names
    ):
        _invalid()
    for name, raw in payloads:
        _verify_visible_file(directory_descriptor, records[name], raw)
    if (
        set(os.listdir(directory_descriptor)) != expected_names
        or not _visible_directory_matches(destination, identity)
    ):
        _invalid()


def _cleanup_partial_bundle(
    destination: _OutputDestination,
    directory_descriptor: int,
    identity: _DirectoryIdentity | None,
    created_files: Sequence[_CreatedFile],
) -> None:
    """Retain every failed output object for non-destructive disposition.

    Neither ``unlink`` nor ``rmdir`` can target an already-open descriptor on
    every supported host.  Checking an inode and then deleting its pathname
    would therefore reopen a same-UID replacement race.  The fail-closed
    outcome is to leave the private 0700 partial tree untouched, return the
    contract error, and require a fresh absolute output path for any retry.
    """

    del destination, directory_descriptor, identity, created_files


def _write_bundle(
    destination: _OutputDestination,
    artifacts: Sequence[RawArtifact],
    result: EvidenceResult,
) -> None:
    evidence_raw = _evidence_document(artifacts, result)
    payloads = tuple(
        (artifact.filename, artifact.raw) for artifact in artifacts
    ) + (("evidence.json", evidence_raw),)
    directory_descriptor = -1
    identity: _DirectoryIdentity | None = None
    created_files: list[_CreatedFile] = []
    try:
        parent_stat = os.fstat(destination.parent_descriptor)
        if (
            not _same_identity(
                parent_stat,
                device=destination.parent_device,
                inode=destination.parent_inode,
            )
            or parent_stat.st_uid != os.geteuid()
        ):
            _invalid()
        os.mkdir(destination.leaf, 0o700, dir_fd=destination.parent_descriptor)
        created_stat = os.stat(
            destination.leaf,
            dir_fd=destination.parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(created_stat.st_mode) or created_stat.st_uid != os.geteuid():
            _invalid()
        identity = _DirectoryIdentity(
            device=created_stat.st_dev,
            inode=created_stat.st_ino,
        )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_descriptor = os.open(
            destination.leaf,
            flags,
            dir_fd=destination.parent_descriptor,
        )
        os.fchmod(directory_descriptor, 0o700)
        directory_stat = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
            or directory_stat.st_uid != os.geteuid()
            or not _same_identity(
                directory_stat,
                device=identity.device,
                inode=identity.inode,
            )
            or not _visible_directory_matches(destination, identity)
        ):
            _invalid()
        for name, raw in payloads:
            _write_file(
                directory_descriptor,
                name,
                raw,
                created_files,
            )
        os.fsync(directory_descriptor)
        _verify_committed_bundle(
            destination,
            directory_descriptor,
            identity,
            payloads,
            created_files,
        )
    except PinnedPostgresReleaseEvidenceError:
        _cleanup_partial_bundle(
            destination,
            directory_descriptor,
            identity,
            created_files,
        )
        raise
    except Exception:
        _cleanup_partial_bundle(
            destination,
            directory_descriptor,
            identity,
            created_files,
        )
        _invalid()
    finally:
        if directory_descriptor >= 0:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def fetch_pinned_postgres_release_evidence(
    architecture: str,
    output_directory: str | os.PathLike[str],
) -> EvidenceResult:
    """Fetch and retain one fixed platform projection as unsigned content evidence."""

    destination: _OutputDestination | None = None
    transport: object | None = None
    try:
        if architecture not in ("amd64", "arm64"):
            _invalid()
        destination = _prepare_output(output_directory)
        transport = DockerHubEvidenceTransport()
        artifacts, result = _collect(transport, architecture=architecture)
        _write_bundle(destination, artifacts, result)
        return result
    except PinnedPostgresReleaseEvidenceError:
        raise
    except Exception:
        _invalid()
    finally:
        if transport is not None:
            try:
                transport.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        if destination is not None:
            destination.close()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if (
            len(arguments) != 4
            or arguments[0] != "--architecture"
            or arguments[2] != "--output-dir"
        ):
            _invalid()
        result = fetch_pinned_postgres_release_evidence(
            arguments[1],
            arguments[3],
        )
        sys.stdout.write(
            _canonical(
                {
                    "architecture": result.architecture,
                    "authority": result.authority,
                    "status": result.status,
                }
            ).decode("utf-8")
        )
        return 0
    except PinnedPostgresReleaseEvidenceError:
        sys.stderr.write(
            '{"code":"PINNED_POSTGRES_RELEASE_EVIDENCE_INVALID","status":"BLOCKED"}\n'
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
