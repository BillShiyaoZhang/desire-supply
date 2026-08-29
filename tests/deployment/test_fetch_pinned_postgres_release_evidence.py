"""Pure-mock tests for the pinned PostgreSQL upstream evidence collector."""

from __future__ import annotations

from email.message import Message
import hashlib
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "fetch_pinned_postgres_release_evidence.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "fetch_pinned_postgres_release_evidence",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("evidence collector cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FETCHER = _load_module()


def _raw(value) -> bytes:
    # Deliberately preserve insertion order: upstream JSON is raw evidence and
    # is not required to use the collector's canonical output ordering.
    return json.dumps(value, separators=(",", ":"), sort_keys=False).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _descriptor(media_type: str, raw: bytes, **extra):
    return {
        "mediaType": media_type,
        "digest": _digest(raw),
        "size": len(raw),
        **extra,
    }


def _subjects(platform_digest: str):
    return [
        {
            "name": f"pkg:docker/postgres/component-{index}@18.4",
            "digest": {"sha256": platform_digest.removeprefix("sha256:")},
        }
        for index in range(13)
    ]


class _Fixture:
    def __init__(self, mutator=None) -> None:
        self.mutator = mutator or (lambda _kind, _arch, _value: None)
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}
        self.by_arch: dict[str, dict[str, object]] = {}
        root_descriptors = []
        for architecture in ("amd64", "arm64"):
            projection = self._projection(architecture)
            self.by_arch[architecture] = projection
            root_descriptors.extend(
                (projection["platform_descriptor"], projection["attestation_descriptor"])
            )
        self.graphs = {
            architecture: FETCHER.PinnedPlatformGraph(
                platform_manifest_digest=projection["platform_descriptor"]["digest"],
                platform_manifest_size=projection["platform_descriptor"]["size"],
                config_digest=projection["image_config_descriptor"]["digest"],
                config_size=projection["image_config_descriptor"]["size"],
                attestation_manifest_digest=projection["attestation_descriptor"]["digest"],
                attestation_manifest_size=projection["attestation_descriptor"]["size"],
                attestation_config_digest=projection["attestation_config_descriptor"]["digest"],
                attestation_config_size=projection["attestation_config_descriptor"]["size"],
                sbom_digest=projection["sbom_descriptor"]["digest"],
                sbom_size=projection["sbom_descriptor"]["size"],
                provenance_digest=projection["provenance_descriptor"]["digest"],
                provenance_size=projection["provenance_descriptor"]["size"],
            )
            for architecture, projection in self.by_arch.items()
        }
        root = {
            "schemaVersion": 2,
            "mediaType": FETCHER.OCI_INDEX,
            "manifests": root_descriptors,
        }
        self.mutator("root_index", "all", root)
        self.root_raw = _raw(root)
        self.root_digest = _digest(self.root_raw)
        self.manifests[self.root_digest] = self.root_raw

    def _projection(self, architecture: str):
        platform = {"architecture": architecture, "os": "linux"}
        if architecture == "arm64":
            platform["variant"] = "v8"

        layer_raw = ("fixed-postgres-layer-" + architecture).encode("ascii")
        layer_descriptor = _descriptor(
            "application/vnd.oci.image.layer.v1.tar+gzip",
            layer_raw,
        )
        image_config = {
            "architecture": architecture,
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [_digest(layer_raw)]},
            "history": [{"created_by": "COPY postgres"}],
        }
        if architecture == "arm64":
            image_config["variant"] = "v8"
        self.mutator("image_config", architecture, image_config)
        image_config_raw = _raw(image_config)
        image_config_descriptor = _descriptor(FETCHER.OCI_CONFIG, image_config_raw)
        platform_manifest = {
            "schemaVersion": 2,
            "mediaType": FETCHER.OCI_MANIFEST,
            "config": image_config_descriptor,
            "layers": [layer_descriptor],
        }
        self.mutator("platform_manifest", architecture, platform_manifest)
        platform_raw = _raw(platform_manifest)
        platform_descriptor = _descriptor(
            FETCHER.OCI_MANIFEST,
            platform_raw,
            platform=platform,
        )

        sbom_statement = {
            "_type": FETCHER.STATEMENT_V01,
            "subject": _subjects(platform_descriptor["digest"]),
            "predicateType": FETCHER.SPDX_PREDICATE,
            "predicate": {
                "SPDXID": "SPDXRef-DOCUMENT",
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "name": f"postgres-{architecture}",
                "documentNamespace": f"https://example.invalid/spdx/{architecture}",
                "creationInfo": {
                    "created": "2026-08-25T00:00:00Z",
                    "creators": ["Tool: docker/buildkit"],
                },
                "packages": [{"SPDXID": "SPDXRef-Package-postgres"}],
                "files": [{"SPDXID": "SPDXRef-File-postgres"}],
            },
        }
        self.mutator("sbom", architecture, sbom_statement)
        sbom_raw = _raw(sbom_statement)

        provenance_statement = {
            "_type": FETCHER.STATEMENT_V01,
            "subject": _subjects(platform_descriptor["digest"]),
            "predicateType": FETCHER.SLSA_V02_PREDICATE,
            "predicate": {
                "builder": {
                    "id": "https://github.com/docker-library/postgres.git"
                },
                "buildType": "https://mobyproject.org/buildkit@v1",
                "invocation": {
                    "configSource": {
                        "uri": "https://github.com/docker-library/postgres.git",
                        "entryPoint": "18/alpine3.23/Dockerfile",
                    },
                    "environment": {"platform": f"linux/{architecture}"},
                    "parameters": {
                        "args": {"POSTGRES_VERSION": "18.4"},
                        "frontend": "dockerfile.v0",
                        "secrets": [{"id": "GIT_AUTH_TOKEN"}],
                        "locals": [{"name": "context"}],
                    },
                },
                "buildConfig": {"steps": []},
                "metadata": {"completeness": {"parameters": True}},
                "materials": [
                    {
                        "uri": "git+https://github.com/docker-library/postgres.git",
                        "digest": {"sha1": "1" * 40},
                    },
                    {
                        "uri": "pkg:docker/alpine@3.23",
                        "digest": {"sha256": "2" * 64},
                    },
                ],
            },
        }
        self.mutator("provenance", architecture, provenance_statement)
        provenance_raw = _raw(provenance_statement)

        sbom_descriptor = _descriptor(
            FETCHER.IN_TOTO_LAYER,
            sbom_raw,
            annotations={"in-toto.io/predicate-type": FETCHER.SPDX_PREDICATE},
        )
        provenance_descriptor = _descriptor(
            FETCHER.IN_TOTO_LAYER,
            provenance_raw,
            annotations={
                "in-toto.io/predicate-type": FETCHER.SLSA_V02_PREDICATE
            },
        )
        attestation_config = {
            "architecture": "unknown",
            "os": "unknown",
            "config": {},
            "rootfs": {
                "type": "layers",
                "diff_ids": [
                    sbom_descriptor["digest"],
                    provenance_descriptor["digest"],
                ],
            },
        }
        self.mutator("attestation_config", architecture, attestation_config)
        attestation_config_raw = _raw(attestation_config)
        attestation_config_descriptor = _descriptor(
            FETCHER.OCI_CONFIG,
            attestation_config_raw,
        )
        attestation_manifest = {
            "schemaVersion": 2,
            "mediaType": FETCHER.OCI_MANIFEST,
            "config": attestation_config_descriptor,
            "layers": [sbom_descriptor, provenance_descriptor],
        }
        self.mutator("attestation_manifest", architecture, attestation_manifest)
        attestation_raw = _raw(attestation_manifest)
        attestation_descriptor = _descriptor(
            FETCHER.OCI_MANIFEST,
            attestation_raw,
            platform={"architecture": "unknown", "os": "unknown"},
            annotations={
                "vnd.docker.reference.digest": platform_descriptor["digest"],
                "vnd.docker.reference.type": "attestation-manifest",
            },
        )

        self.manifests[_digest(platform_raw)] = platform_raw
        self.manifests[_digest(attestation_raw)] = attestation_raw
        for blob in (
            image_config_raw,
            attestation_config_raw,
            sbom_raw,
            provenance_raw,
        ):
            self.blobs[_digest(blob)] = blob
        return {
            "platform_descriptor": platform_descriptor,
            "attestation_descriptor": attestation_descriptor,
            "image_config_descriptor": image_config_descriptor,
            "attestation_config_descriptor": attestation_config_descriptor,
            "sbom_descriptor": sbom_descriptor,
            "provenance_descriptor": provenance_descriptor,
            "platform_raw": platform_raw,
            "image_config_raw": image_config_raw,
            "attestation_raw": attestation_raw,
            "attestation_config_raw": attestation_config_raw,
            "sbom_raw": sbom_raw,
            "provenance_raw": provenance_raw,
        }


class _Response:
    def __init__(self, *, status=200, body=b"", headers=()) -> None:
        self.status = status
        self.body = body
        self.position = 0
        self.closed = False
        self.headers = Message()
        header_items = headers.items() if isinstance(headers, dict) else headers
        for name, value in header_items:
            self.headers[name] = value

    def read(self, amount: int) -> bytes:
        result = self.body[self.position : self.position + amount]
        self.position += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class _Registry:
    TOKEN = "anonymous-secret-token-never-persist-this"

    def __init__(self, fixture: _Fixture) -> None:
        self.fixture = fixture
        self.requests = []
        self.responses = []
        self.closed = False
        self.token_status = 200
        self.token_body = _raw(
            {
                "token": self.TOKEN,
                "access_token": self.TOKEN,
                "expires_in": 300,
                "issued_at": "2026-08-25T00:00:00Z",
            }
        )
        self.manifest_redirect_digest = None
        self.redirect_blob_digests: set[str] = set()
        self.redirect_status = 307
        self.redirect_host = FETCHER.BLOB_REDIRECT_HOST
        self.cloudfront_status = 200
        self.tamper_digest = None
        self.encoded_digest = None
        self.duplicate_length_digest = None
        self.redirect_map: dict[str, bytes] = {}

    def request(self, **request):
        self.requests.append(request)
        host = request["host"]
        target = request["target"]
        if host == FETCHER.AUTH_HOST:
            response = _Response(status=self.token_status, body=self.token_body)
            self.responses.append(response)
            return response
        if host == FETCHER.BLOB_REDIRECT_HOST:
            body = self.redirect_map.get(target, b"")
            response = _Response(
                status=self.cloudfront_status,
                body=body,
                headers={"Content-Length": str(len(body))},
            )
            self.responses.append(response)
            return response
        if host != FETCHER.REGISTRY_HOST:
            raise AssertionError("unexpected host")
        digest = target.rsplit("/", 1)[-1]
        if "/manifests/" in target:
            body = self.fixture.manifests[digest]
            if digest == self.manifest_redirect_digest:
                response = _Response(
                    status=307,
                    headers={
                        "Location": (
                            f"https://{FETCHER.BLOB_REDIRECT_HOST}/forbidden-manifest"
                        )
                    },
                )
            else:
                response = _Response(
                    body=body,
                    headers={
                        "Content-Length": str(len(body)),
                        "Docker-Content-Digest": digest,
                    },
                )
            self.responses.append(response)
            return response
        body = self.fixture.blobs[digest]
        if digest in self.redirect_blob_digests:
            selector = f"/registry-v2/blobs/{digest}/data?X-Amz-Signature=opaque"
            self.redirect_map[selector] = body
            response = _Response(
                status=self.redirect_status,
                headers={
                    "Location": f"https://{self.redirect_host}{selector}"
                },
            )
        else:
            if digest == self.tamper_digest:
                body += b"tampered"
            headers = [("Content-Length", str(len(body)))]
            if digest == self.encoded_digest:
                headers.append(("Content-Encoding", "gzip"))
            if digest == self.duplicate_length_digest:
                headers.append(("Content-Length", str(len(body))))
            response = _Response(body=body, headers=headers)
        self.responses.append(response)
        return response

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, host, port, *, timeout, context) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.calls = []
        self.closed = False

    def request(self, method, target, *, headers) -> None:
        self.calls.append((method, target, dict(headers)))

    def getresponse(self):
        return _Response(body=b"{}")

    def close(self) -> None:
        self.closed = True


class FetchPinnedPostgresReleaseEvidenceTests(unittest.TestCase):
    def test_fixed_contract_and_success_for_both_platforms(self):
        self.assertEqual(
            FETCHER.ROOT_INDEX_DIGEST,
            "sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
        )
        self.assertEqual(FETCHER.REPOSITORY, "library/postgres")
        self.assertEqual(FETCHER.TAG, "18.4-alpine")
        expected_graphs = {
            "amd64": (
                "sha256:b6a16ed0eb96e2c362811f7eeb951eac8b459e7b40be4149ea5444aa7c65569b",
                2678,
                "sha256:bd1890816ae0b8ad4644f05728570d4be774e1f1490d7232f5084b52ea335183",
                8509,
                "sha256:d47cbb6b172896421df55c9a7afd3727a92a7ff05a17c5d910175dc7ff11cedf",
                840,
                "sha256:8eac90f8e0d28c3c0058be8dce6df773a71f50c2df7c289e8ff435ebffff3ed8",
                241,
                "sha256:32a5a1abaaf0428efca7ce410da748c62bd9b40d464d5056bf23c5cf276f7077",
                617266,
                "sha256:71608f5c0921ef359a3f846d6ad12ae74f82eb68be4c0227c59a4a128e778f1f",
                41048,
            ),
            "arm64": (
                "sha256:122c9942437efcbbb8d595fc578dee7d26ee1543c2a8634d183adfa4a1e55b4d",
                2680,
                "sha256:db676a0ed906c00f55020fb8999e4fb30c598bf5c3b5c188630aef2812d3f11d",
                8523,
                "sha256:337172f3d66e8a9298a194cb848d1758e905e3b00d21aec6f1e88e57bf06097b",
                840,
                "sha256:ee4c7f901212ee3d1bc83d0fbc9d5035e940552f190c43db998dd3b40aca558a",
                241,
                "sha256:071cfbe442f0a554a67398a207788a4d31f27101e7385d707cacf29668b19ae0",
                616696,
                "sha256:063e7a583f48258c2edd38cd65871659878a61fa39539b78ef58031b3451542e",
                41266,
            ),
        }
        for architecture, expected in expected_graphs.items():
            graph = FETCHER.PINNED_PLATFORM_GRAPHS[architecture]
            self.assertEqual(
                (
                    graph.platform_manifest_digest,
                    graph.platform_manifest_size,
                    graph.config_digest,
                    graph.config_size,
                    graph.attestation_manifest_digest,
                    graph.attestation_manifest_size,
                    graph.attestation_config_digest,
                    graph.attestation_config_size,
                    graph.sbom_digest,
                    graph.sbom_size,
                    graph.provenance_digest,
                    graph.provenance_size,
                ),
                expected,
            )
        for architecture in ("amd64", "arm64"):
            with self.subTest(architecture=architecture), TemporaryDirectory() as temporary:
                fixture = _Fixture()
                registry = _Registry(fixture)
                output = Path(temporary) / f"evidence-{architecture}"
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(
                        FETCHER,
                        "DockerHubEvidenceTransport",
                        return_value=registry,
                    ),
                ):
                    result = FETCHER.fetch_pinned_postgres_release_evidence(
                        architecture,
                        output,
                    )
                projection = fixture.by_arch[architecture]
                self.assertEqual(result.status, FETCHER.STATUS)
                self.assertEqual(result.authority, FETCHER.AUTHORITY)
                self.assertEqual(
                    result.platform_manifest_digest,
                    projection["platform_descriptor"]["digest"],
                )
                expected_files = {
                    "registry-index.json": fixture.root_raw,
                    "platform-manifest.json": projection["platform_raw"],
                    "image-config.json": projection["image_config_raw"],
                    "attestation-manifest.json": projection["attestation_raw"],
                    "attestation-config.json": projection["attestation_config_raw"],
                    "sbom.intoto.json": projection["sbom_raw"],
                    "provenance.intoto.json": projection["provenance_raw"],
                }
                self.assertEqual(
                    {item.name for item in output.iterdir()},
                    {*expected_files, "evidence.json"},
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for name, expected_raw in expected_files.items():
                    path = output / name
                    self.assertEqual(path.read_bytes(), expected_raw)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                evidence_path = output / "evidence.json"
                evidence_raw = evidence_path.read_bytes()
                self.assertEqual(stat.S_IMODE(evidence_path.stat().st_mode), 0o400)
                evidence = json.loads(evidence_raw)
                self.assertEqual(
                    evidence_raw,
                    FETCHER._canonical(evidence),
                )
                self.assertEqual(evidence["status"], FETCHER.STATUS)
                self.assertEqual(evidence["authority"], FETCHER.AUTHORITY)
                self.assertFalse(evidence["authenticity_verified"])
                self.assertFalse(evidence["signature_verified"])
                self.assertFalse(evidence["execution_permitted"])
                self.assertFalse(evidence["production_authorized"])
                self.assertEqual(
                    [item["name"] for item in evidence["artifacts"]],
                    list(expected_files),
                )
                for binding in evidence["artifacts"]:
                    raw = expected_files[binding["name"]]
                    self.assertEqual(binding["size"], len(raw))
                    self.assertEqual(binding["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertTrue(registry.closed)
                self.assertNotIn(_Registry.TOKEN.encode(), evidence_raw)
                self.assertTrue(
                    all("/referrers/" not in request["target"] for request in registry.requests)
                )
                self.assertEqual(
                    {request["host"] for request in registry.requests},
                    {FETCHER.AUTH_HOST, FETCHER.REGISTRY_HOST},
                )
                for request in registry.requests:
                    headers = {key.lower(): value for key, value in request["headers"].items()}
                    self.assertEqual(headers["accept-encoding"], "identity")
                    self.assertNotIn("cookie", headers)
                    self.assertNotIn("referer", headers)
                    if request["host"] == FETCHER.REGISTRY_HOST:
                        self.assertEqual(headers["authorization"], "Bearer " + _Registry.TOKEN)
                    else:
                        self.assertNotIn("authorization", headers)

    def test_one_307_blob_redirect_is_byte_exact_and_credential_free(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        digest = fixture.by_arch["amd64"]["sbom_descriptor"]["digest"]
        registry.redirect_blob_digests.add(digest)
        with (
            TemporaryDirectory() as temporary,
            patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
            patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
            patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
        ):
            output = Path(temporary) / "evidence"
            FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)
            self.assertEqual(
                (output / "sbom.intoto.json").read_bytes(),
                fixture.by_arch["amd64"]["sbom_raw"],
            )
        cloudfront = [
            request
            for request in registry.requests
            if request["host"] == FETCHER.BLOB_REDIRECT_HOST
        ]
        self.assertEqual(len(cloudfront), 1)
        self.assertIs(cloudfront[0]["cloudfront_redirect"], True)
        headers = {key.lower(): value for key, value in cloudfront[0]["headers"].items()}
        self.assertNotIn("authorization", headers)
        self.assertNotIn("cookie", headers)
        self.assertNotIn("referer", headers)
        self.assertNotIn(_Registry.TOKEN, repr(cloudfront[0]))

    def test_token_and_manifest_redirects_are_never_followed(self):
        for failure in ("token", "root_manifest", "platform_manifest"):
            with self.subTest(failure=failure), TemporaryDirectory() as temporary:
                fixture = _Fixture()
                registry = _Registry(fixture)
                if failure == "token":
                    registry.token_status = 302
                elif failure == "root_manifest":
                    registry.manifest_redirect_digest = fixture.root_digest
                else:
                    registry.manifest_redirect_digest = fixture.by_arch["amd64"][
                        "platform_descriptor"
                    ]["digest"]
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )
                self.assertFalse(
                    any(
                        request["host"] == FETCHER.BLOB_REDIRECT_HOST
                        for request in registry.requests
                    )
                )

    def test_blob_redirect_is_exactly_one_307_to_fixed_https_host(self):
        cases = (
            ("wrong_status", 302, FETCHER.BLOB_REDIRECT_HOST, 200),
            ("wrong_host", 307, "example.invalid", 200),
            ("second_redirect", 307, FETCHER.BLOB_REDIRECT_HOST, 307),
        )
        for name, first_status, host, final_status in cases:
            with self.subTest(name=name), TemporaryDirectory() as temporary:
                fixture = _Fixture()
                registry = _Registry(fixture)
                digest = fixture.by_arch["amd64"]["sbom_descriptor"]["digest"]
                registry.redirect_blob_digests.add(digest)
                registry.redirect_status = first_status
                registry.redirect_host = host
                registry.cloudfront_status = final_status
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_raw_digest_size_encoding_and_duplicate_headers_fail_closed(self):
        for failure in ("tamper", "encoding", "duplicate_length"):
            with self.subTest(failure=failure), TemporaryDirectory() as temporary:
                fixture = _Fixture()
                registry = _Registry(fixture)
                digest = fixture.by_arch["amd64"]["sbom_descriptor"]["digest"]
                attribute = {
                    "tamper": "tamper_digest",
                    "encoding": "encoded_digest",
                    "duplicate_length": "duplicate_length_digest",
                }[failure]
                setattr(registry, attribute, digest)
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_duplicate_and_unknown_token_json_fail_closed_without_reflection(self):
        bad_documents = (
            b'{"token":"first","token":"second"}',
            b'{"token":"secret-token-value","unexpected":true}',
        )
        for token_body in bad_documents:
            with self.subTest(token_body=token_body), TemporaryDirectory() as temporary:
                fixture = _Fixture()
                registry = _Registry(fixture)
                registry.token_body = token_body
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError) as raised,
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )
                self.assertEqual(str(raised.exception), FETCHER.ERROR_CODE)
                self.assertNotIn("secret", str(raised.exception))
                self.assertNotIn("http", str(raised.exception))

    def test_root_requires_unique_amd64_arm64_and_inline_attestations(self):
        def duplicate(_kind, _arch, value):
            if _kind == "root_index":
                value["manifests"].append(dict(value["manifests"][0]))

        def omit_arm(_kind, _arch, value):
            if _kind == "root_index":
                value["manifests"] = value["manifests"][:2]

        def detach(_kind, _arch, value):
            if _kind == "root_index":
                value["manifests"][1]["annotations"][
                    "vnd.docker.reference.digest"
                ] = "sha256:" + "0" * 64

        for mutator in (duplicate, omit_arm, detach):
            with self.subTest(mutator=mutator.__name__), TemporaryDirectory() as temporary:
                fixture = _Fixture(mutator)
                registry = _Registry(fixture)
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_every_selected_descriptor_must_equal_the_fixed_platform_graph(self):
        fixture = _Fixture()
        original = fixture.graphs["amd64"]
        for field in (
            "platform_manifest_size",
            "config_size",
            "attestation_manifest_size",
            "attestation_config_size",
            "sbom_size",
            "provenance_size",
        ):
            with self.subTest(field=field), TemporaryDirectory() as temporary:
                wrong_graphs = dict(fixture.graphs)
                wrong_graphs["amd64"] = FETCHER.PinnedPlatformGraph(
                    **{
                        **original.__dict__,
                        field: getattr(original, field) + 1,
                    }
                )
                registry = _Registry(fixture)
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", wrong_graphs),
                    patch.object(
                        FETCHER,
                        "DockerHubEvidenceTransport",
                        return_value=registry,
                    ),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_legacy_attestation_profile_is_closed(self):
        mutations = (
            lambda value: value.update({"subject": {}}),
            lambda value: value.update({"artifactType": "application/vnd.in-toto+json"}),
            lambda value: value["layers"].reverse(),
        )
        for mutation in mutations:
            def mutate(kind, arch, value, mutation=mutation):
                if kind == "attestation_manifest" and arch == "amd64":
                    mutation(value)

            with self.subTest(mutation=repr(mutation)), TemporaryDirectory() as temporary:
                fixture = _Fixture(mutate)
                registry = _Registry(fixture)
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_statement_subject_and_predicate_annotation_are_cross_bound(self):
        def wrong_subject(kind, arch, value):
            if kind == "sbom" and arch == "amd64":
                value["subject"][0]["digest"]["sha256"] = "0" * 64

        def wrong_predicate(kind, arch, value):
            if kind == "attestation_manifest" and arch == "amd64":
                value["layers"][1]["annotations"][
                    "in-toto.io/predicate-type"
                ] = "https://slsa.dev/provenance/v1"

        for mutator in (wrong_subject, wrong_predicate):
            with self.subTest(mutator=mutator.__name__), TemporaryDirectory() as temporary:
                fixture = _Fixture(mutator)
                registry = _Registry(fixture)
                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64", Path(temporary) / "evidence"
                    )

    def test_only_absolute_new_owner_directory_is_accepted(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            existing = parent / "existing"
            existing.mkdir()
            sentinel = existing / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            relative = Path("relative-evidence")
            symlink_parent = parent / "symlink-parent"
            symlink_parent.symlink_to(parent, target_is_directory=True)
            for output in (relative, existing, symlink_parent / "evidence"):
                with (
                    self.subTest(output=str(output)),
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                    patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_output_creation_race_does_not_overwrite(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        original_collect = FETCHER._collect
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"

            def raced_collect(transport, *, architecture):
                result = original_collect(transport, architecture=architecture)
                output.mkdir(mode=0o700)
                (output / "sentinel").write_text("race-winner", encoding="utf-8")
                return result

            with (
                patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                patch.object(FETCHER, "DockerHubEvidenceTransport", return_value=registry),
                patch.object(FETCHER, "_collect", side_effect=raced_collect),
                self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
            ):
                FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)
            self.assertEqual(
                (output / "sentinel").read_text(encoding="utf-8"),
                "race-winner",
            )
            self.assertEqual({path.name for path in output.iterdir()}, {"sentinel"})

    def test_network_failure_leaves_no_output_directory(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        registry.token_status = 503
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            with (
                patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                patch.object(
                    FETCHER,
                    "DockerHubEvidenceTransport",
                    return_value=registry,
                ),
                self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
            ):
                FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)
            self.assertFalse(output.exists())
            self.assertTrue(registry.closed)

    def test_failure_after_each_created_file_retains_the_private_partial_tree(self):
        fixture = _Fixture()
        original_write = FETCHER._write_file
        for fail_at in range(1, 9):
            with self.subTest(fail_at=fail_at), TemporaryDirectory() as temporary:
                output = Path(temporary) / "evidence"
                registry = _Registry(fixture)
                calls = 0

                def failing_write(
                    directory_descriptor,
                    name,
                    raw,
                    created_files,
                ):
                    nonlocal calls
                    calls += 1
                    original_write(
                        directory_descriptor,
                        name,
                        raw,
                        created_files,
                    )
                    if calls == fail_at:
                        if fail_at == 4:
                            raise RuntimeError("injected non-contract write failure")
                        raise FETCHER.PinnedPostgresReleaseEvidenceError()

                with (
                    patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                    patch.object(
                        FETCHER,
                        "PINNED_PLATFORM_GRAPHS",
                        fixture.graphs,
                    ),
                    patch.object(
                        FETCHER,
                        "DockerHubEvidenceTransport",
                        return_value=registry,
                    ),
                    patch.object(FETCHER, "_write_file", side_effect=failing_write),
                    self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
                ):
                    FETCHER.fetch_pinned_postgres_release_evidence(
                        "amd64",
                        output,
                    )
                self.assertEqual(calls, fail_at)
                self.assertTrue(output.is_dir())
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                retained = tuple(output.iterdir())
                self.assertEqual(len(retained), fail_at)
                for path in retained:
                    self.assertTrue(path.is_file())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                if fail_at == 8:
                    # A retry must use a new absolute path; the helper never
                    # destroys or reuses a failed evidence tree.
                    retry_output = Path(temporary) / "retry-evidence"
                    retry_registry = _Registry(fixture)
                    with (
                        patch.object(
                            FETCHER,
                            "ROOT_INDEX_DIGEST",
                            fixture.root_digest,
                        ),
                        patch.object(
                            FETCHER,
                            "PINNED_PLATFORM_GRAPHS",
                            fixture.graphs,
                        ),
                        patch.object(
                            FETCHER,
                            "DockerHubEvidenceTransport",
                            return_value=retry_registry,
                        ),
                    ):
                        FETCHER.fetch_pinned_postgres_release_evidence(
                            "amd64",
                            retry_output,
                        )
                    self.assertTrue((retry_output / "evidence.json").is_file())

    def test_final_content_tamper_is_detected_and_partial_tree_is_retained(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        original_write = FETCHER._write_file
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"

            def tampering_write(
                directory_descriptor,
                name,
                raw,
                created_files,
            ):
                original_write(
                    directory_descriptor,
                    name,
                    raw,
                    created_files,
                )
                if name != "evidence.json":
                    return
                target = "platform-manifest.json"
                os.chmod(
                    target,
                    0o600,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
                try:
                    size = next(
                        item.size
                        for item in created_files
                        if item.name == target
                    )
                    os.write(descriptor, b"x" * size)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, 0o400)
                finally:
                    os.close(descriptor)

            with (
                patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                patch.object(
                    FETCHER,
                    "DockerHubEvidenceTransport",
                    return_value=registry,
                ),
                patch.object(FETCHER, "_write_file", side_effect=tampering_write),
                self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
            ):
                FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)
            self.assertTrue(output.is_dir())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(len(tuple(output.iterdir())), 8)

    def test_same_uid_directory_replacement_is_rejected_and_never_deleted(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        original_write = FETCHER._write_file
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "evidence"
            renamed = parent / "renamed-original"

            def replacing_write(
                directory_descriptor,
                name,
                raw,
                created_files,
            ):
                original_write(
                    directory_descriptor,
                    name,
                    raw,
                    created_files,
                )
                if name != "evidence.json":
                    return
                output.rename(renamed)
                output.mkdir(mode=0o700)
                sentinel = output / "replacement-sentinel"
                sentinel.write_bytes(b"same-uid replacement must survive")
                sentinel.chmod(0o400)

            with (
                patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                patch.object(
                    FETCHER,
                    "DockerHubEvidenceTransport",
                    return_value=registry,
                ),
                patch.object(FETCHER, "_write_file", side_effect=replacing_write),
                self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
            ):
                FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)

            self.assertEqual(
                (output / "replacement-sentinel").read_bytes(),
                b"same-uid replacement must survive",
            )
            self.assertEqual(
                {item.name for item in output.iterdir()},
                {"replacement-sentinel"},
            )
            self.assertEqual(
                {item.name for item in renamed.iterdir()},
                {
                    "registry-index.json",
                    "platform-manifest.json",
                    "image-config.json",
                    "attestation-manifest.json",
                    "attestation-config.json",
                    "sbom.intoto.json",
                    "provenance.intoto.json",
                    "evidence.json",
                },
            )

    def test_same_uid_file_replacement_is_rejected_and_never_deleted(self):
        fixture = _Fixture()
        registry = _Registry(fixture)
        original_write = FETCHER._write_file
        replacement = b"same-uid replacement file must survive"
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"

            def replacing_write(
                directory_descriptor,
                name,
                raw,
                created_files,
            ):
                original_write(
                    directory_descriptor,
                    name,
                    raw,
                    created_files,
                )
                if name != "evidence.json":
                    return
                target = "platform-manifest.json"
                os.unlink(target, dir_fd=directory_descriptor)
                descriptor = os.open(
                    target,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o400,
                    dir_fd=directory_descriptor,
                )
                try:
                    os.write(descriptor, replacement)
                    os.fsync(descriptor)
                    os.fchmod(descriptor, 0o400)
                finally:
                    os.close(descriptor)

            with (
                patch.object(FETCHER, "ROOT_INDEX_DIGEST", fixture.root_digest),
                patch.object(FETCHER, "PINNED_PLATFORM_GRAPHS", fixture.graphs),
                patch.object(
                    FETCHER,
                    "DockerHubEvidenceTransport",
                    return_value=registry,
                ),
                patch.object(FETCHER, "_write_file", side_effect=replacing_write),
                self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError),
            ):
                FETCHER.fetch_pinned_postgres_release_evidence("amd64", output)

            self.assertEqual(
                {item.name for item in output.iterdir()},
                {
                    "registry-index.json",
                    "platform-manifest.json",
                    "image-config.json",
                    "attestation-manifest.json",
                    "attestation-config.json",
                    "sbom.intoto.json",
                    "provenance.intoto.json",
                    "evidence.json",
                },
            )
            self.assertEqual(
                (output / "platform-manifest.json").read_bytes(),
                replacement,
            )

    def test_direct_transport_has_fixed_hosts_and_no_ambient_credentials(self):
        connections = []

        def factory(*args, **kwargs):
            connection = _Connection(*args, **kwargs)
            connections.append(connection)
            return connection

        transport = FETCHER.DockerHubEvidenceTransport(connection_factory=factory)
        response = transport.request(
            host=FETCHER.AUTH_HOST,
            target=FETCHER.TOKEN_TARGET,
            headers=FETCHER._base_headers(accept="application/json"),
            timeout=10,
        )
        response.close()
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].host, FETCHER.AUTH_HOST)
        self.assertEqual(connections[0].port, 443)
        self.assertTrue(connections[0].context.check_hostname)
        self.assertEqual(connections[0].context.verify_mode, 2)
        for bad_request in (
            {
                "host": "example.invalid",
                "target": "/",
                "headers": FETCHER._base_headers(accept="application/json"),
            },
            {
                "host": FETCHER.BLOB_REDIRECT_HOST,
                "target": "/unsigned",
                "headers": FETCHER._base_headers(accept=FETCHER.BLOB_ACCEPT),
            },
            {
                "host": FETCHER.BLOB_REDIRECT_HOST,
                "target": "/signed",
                "headers": FETCHER._base_headers(
                    accept=FETCHER.BLOB_ACCEPT,
                    token="must-not-cross-origin",
                ),
                "cloudfront_redirect": True,
            },
        ):
            with self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError):
                transport.request(timeout=10, **bad_request)
        transport.close()

    def test_response_size_boundary_is_fail_closed(self):
        for length, accepted in ((8, True), (9, False)):
            response = _Response(
                body=b"x" * length,
                headers={"Content-Length": str(length)},
            )
            if accepted:
                self.assertEqual(
                    FETCHER._response_bytes(response, maximum=8),
                    b"x" * length,
                )
            else:
                with self.assertRaises(FETCHER.PinnedPostgresReleaseEvidenceError):
                    FETCHER._response_bytes(response, maximum=8)
            self.assertTrue(response.closed)

    def test_cli_has_two_fixed_flags_and_never_reflects_sensitive_failure(self):
        for arguments in (
            (),
            ("--architecture", "amd64"),
            ("amd64", "/absolute/output"),
            ("--architecture", "s390x", "--output-dir", "/absolute/output"),
            ("--output-dir", "/absolute/output", "--architecture", "amd64"),
        ):
            stdout = StringIO()
            stderr = StringIO()
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(FETCHER.main(arguments), 78)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(
                stderr.getvalue(),
                '{"code":"PINNED_POSTGRES_RELEASE_EVIDENCE_INVALID","status":"BLOCKED"}\n',
            )
            self.assertNotIn("output", stderr.getvalue())

        result = FETCHER.EvidenceResult(
            architecture="amd64",
            root_index_digest="sha256:" + "1" * 64,
            platform_manifest_digest="sha256:" + "2" * 64,
            config_digest="sha256:" + "3" * 64,
            attestation_manifest_digest="sha256:" + "4" * 64,
        )
        stdout = StringIO()
        stderr = StringIO()
        with (
            patch.object(sys, "stdout", stdout),
            patch.object(sys, "stderr", stderr),
            patch.object(
                FETCHER,
                "fetch_pinned_postgres_release_evidence",
                return_value=result,
            ) as collect,
        ):
            self.assertEqual(
                FETCHER.main(
                    (
                        "--architecture",
                        "amd64",
                        "--output-dir",
                        "/absolute/new-output",
                    )
                ),
                0,
            )
        collect.assert_called_once_with("amd64", "/absolute/new-output")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "architecture": "amd64",
                "authority": FETCHER.AUTHORITY,
                "status": FETCHER.STATUS,
            },
        )

    def test_source_has_no_referrers_proxy_netrc_subprocess_or_rewrite_path(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertNotIn("/referrers/", lowered)
        self.assertNotIn("import requests", lowered)
        self.assertNotIn("urllib.request", lowered)
        self.assertNotIn("getproxies", lowered)
        self.assertNotIn("netrc", lowered.replace("no proxy, netrc", ""))
        self.assertNotIn("subprocess", lowered)
        self.assertNotIn("docker run", lowered)
        self.assertNotIn("docker build", lowered)
        self.assertNotIn("os.environ", lowered)
        self.assertNotIn("http_proxy", lowered)
        self.assertIn("production.cloudfront.docker.com", source)
        self.assertIn("Accept-Encoding\": \"identity", source)


if __name__ == "__main__":
    unittest.main()
