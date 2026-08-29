"""Offline tests for the Docker Hub production-manifest preflight."""

from __future__ import annotations

from email.message import Message
import hashlib
import importlib.util
from io import StringIO
import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlparse
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "preflight_docker_hub_manifests.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "preflight_docker_hub_manifests",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Docker Hub manifest preflight cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # The wider deployment-suite command also exposes ``platform/tests`` on
    # PYTHONPATH, where a test package named ``http`` would otherwise shadow
    # the Python standard library required by urllib.request.
    platform_tests = (ROOT / "platform" / "tests").resolve()
    original_path = list(sys.path)
    try:
        sys.path[:] = [
            entry
            for entry in sys.path
            if Path(entry or ".").resolve() != platform_tests
        ]
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = original_path
    return module


PREFLIGHT = _load_module()


class _Response:
    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b"",
        headers=None,
    ) -> None:
        self.status = status
        self.body = body
        self.read_count = 0
        self.closed = False
        self.headers = Message()
        header_items = (
            headers.items() if isinstance(headers, dict) else (headers or ())
        )
        for name, value in header_items:
            self.headers[name] = value

    def read(self, amount: int) -> bytes:
        self.read_count += 1
        return self.body[:amount]

    def close(self) -> None:
        self.closed = True


class _RegistryDouble:
    def __init__(
        self,
        *,
        fail_token_at: int | None = None,
        fail_head_at: int | None = None,
        mismatch_head_at: int | None = None,
        missing_digest_head_at: int | None = None,
        duplicate_digest_head_at: int | None = None,
        conflicting_digest_head_at: int | None = None,
        redirect_token_at: int | None = None,
        oversized_token_at: int | None = None,
    ) -> None:
        self.fail_token_at = fail_token_at
        self.fail_head_at = fail_head_at
        self.mismatch_head_at = mismatch_head_at
        self.missing_digest_head_at = missing_digest_head_at
        self.duplicate_digest_head_at = duplicate_digest_head_at
        self.conflicting_digest_head_at = conflicting_digest_head_at
        self.redirect_token_at = redirect_token_at
        self.oversized_token_at = oversized_token_at
        self.requests = []
        self.responses: list[_Response] = []
        self.token_count = 0
        self.head_count = 0
        self.close_count = 0

    def open(self, request, *, timeout: int):
        self.requests.append((request, timeout))
        if request.get_method() == "GET":
            self.token_count += 1
            if self.token_count == self.fail_token_at:
                response = _Response(status=503)
            elif self.token_count == self.redirect_token_at:
                response = _Response(
                    status=302,
                    headers={"Location": "https://example.invalid/token"},
                )
            elif self.token_count == self.oversized_token_at:
                response = _Response(
                    body=b"x" * (PREFLIGHT._MAX_TOKEN_RESPONSE_BYTES + 1)
                )
            else:
                response = _Response(
                    body=json.dumps(
                        {"token": f"anonymous-token-{self.token_count}"}
                    ).encode("utf-8")
                )
            self.responses.append(response)
            return response

        if request.get_method() != "HEAD":
            raise AssertionError("unexpected HTTP method")
        self.head_count += 1
        digest = request.full_url.rsplit("/", 1)[-1]
        if self.head_count == self.fail_head_at:
            response = _Response(status=503)
        elif self.head_count == self.missing_digest_head_at:
            response = _Response()
        elif self.head_count == self.mismatch_head_at:
            response = _Response(
                headers={"Docker-Content-Digest": f"sha256:{'0' * 64}"}
            )
        elif self.head_count == self.duplicate_digest_head_at:
            response = _Response(
                headers=(
                    ("Docker-Content-Digest", digest),
                    ("Docker-Content-Digest", digest),
                )
            )
        elif self.head_count == self.conflicting_digest_head_at:
            response = _Response(
                headers=(
                    ("Docker-Content-Digest", digest),
                    (
                        "Docker-Content-Digest",
                        f"sha256:{'0' * 64}",
                    ),
                )
            )
        else:
            response = _Response(
                headers={"Docker-Content-Digest": digest}
            )
        self.responses.append(response)
        return response

    def close(self) -> None:
        self.close_count += 1

    @property
    def token_repositories(self) -> list[str]:
        repositories = []
        for request, _timeout in self.requests:
            if request.get_method() != "GET":
                continue
            query = parse_qs(urlparse(request.full_url).query)
            scope = query["scope"]
            if len(scope) != 1:
                raise AssertionError("unexpected token scope")
            prefix = "repository:"
            suffix = ":pull"
            if not scope[0].startswith(prefix) or not scope[0].endswith(suffix):
                raise AssertionError("unexpected token scope")
            repositories.append(scope[0][len(prefix) : -len(suffix)])
        return repositories

    @property
    def head_repositories(self) -> list[str]:
        repositories = []
        for request, _timeout in self.requests:
            if request.get_method() != "HEAD":
                continue
            path = urlparse(request.full_url).path
            prefix = "/v2/"
            suffix = f"/manifests/{path.rsplit('/', 1)[-1]}"
            repositories.append(path[len(prefix) : -len(suffix)])
        return repositories

    @property
    def ordered_operations(self) -> list[tuple[str, str]]:
        operations = []
        token_repositories = iter(self.token_repositories)
        head_repositories = iter(self.head_repositories)
        for request, _timeout in self.requests:
            method = request.get_method()
            repository = (
                next(token_repositories)
                if method == "GET"
                else next(head_repositories)
            )
            operations.append((method, repository))
        return operations


class _ConnectionDouble:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        context: ssl.SSLContext,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.sock = None
        self.requests = []
        self.responses: list[_Response] = []
        self.closed = False

    def request(self, method, selector, *, headers) -> None:
        self.requests.append((method, selector, headers))
        self.responses.append(_Response())

    def getresponse(self) -> _Response:
        return self.responses[-1]

    def close(self) -> None:
        self.closed = True


class _ConnectionFactoryDouble:
    def __init__(self) -> None:
        self.connections: list[_ConnectionDouble] = []

    def __call__(self, host, port, *, timeout, context):
        connection = _ConnectionDouble(
            host,
            port,
            timeout=timeout,
            context=context,
        )
        self.connections.append(connection)
        return connection


class DockerHubHTTPSessionTransportTest(unittest.TestCase):
    def test_reuses_one_verified_tls_connection_per_exact_host_and_closes(self) -> None:
        factory = _ConnectionFactoryDouble()
        transport = PREFLIGHT.DockerHubHTTPSessionTransport(
            connection_factory=factory,
        )
        requests = (
            PREFLIGHT.Request(
                "https://auth.docker.io/token?scope=repository%3Aa%3Apull",
                method="GET",
            ),
            PREFLIGHT.Request(
                "https://registry-1.docker.io/v2/a/manifests/sha256:one",
                headers={"Authorization": "Bearer opaque-one"},
                method="HEAD",
            ),
            PREFLIGHT.Request(
                "https://auth.docker.io/token?scope=repository%3Ab%3Apull",
                method="GET",
            ),
            PREFLIGHT.Request(
                "https://registry-1.docker.io/v2/b/manifests/sha256:two",
                headers={"Authorization": "Bearer opaque-two"},
                method="HEAD",
            ),
        )

        responses = []
        for request in requests:
            response = transport.open(request, timeout=11)
            response.close()
            responses.append(response)
        transport.close()

        self.assertEqual(
            [connection.host for connection in factory.connections],
            ["auth.docker.io", "registry-1.docker.io"],
        )
        self.assertEqual(
            [len(connection.requests) for connection in factory.connections],
            [2, 2],
        )
        self.assertTrue(
            all(connection.port == 443 for connection in factory.connections)
        )
        self.assertTrue(
            all(connection.timeout == 11 for connection in factory.connections)
        )
        self.assertTrue(all(connection.closed for connection in factory.connections))
        self.assertTrue(all(response.closed for response in responses))
        contexts = [connection.context for connection in factory.connections]
        self.assertIs(contexts[0], contexts[1])
        self.assertTrue(contexts[0].check_hostname)
        self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(
            contexts[0].minimum_version,
            ssl.TLSVersion.TLSv1_2,
        )

    def test_rejects_non_exact_tls_origins_and_methods_before_connecting(self) -> None:
        factory = _ConnectionFactoryDouble()
        transport = PREFLIGHT.DockerHubHTTPSessionTransport(
            connection_factory=factory,
        )
        invalid_requests = (
            PREFLIGHT.Request("http://auth.docker.io/token", method="GET"),
            PREFLIGHT.Request("https://example.invalid/token", method="GET"),
            PREFLIGHT.Request("https://auth.docker.io:443/token", method="GET"),
            PREFLIGHT.Request("https://auth.docker.io/token", method="HEAD"),
            PREFLIGHT.Request(
                "https://registry-1.docker.io/v2/a/manifests/x",
                method="GET",
            ),
        )

        for request in invalid_requests:
            with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
                transport.open(request, timeout=11)
        transport.close()

        self.assertEqual(factory.connections, [])


class DockerHubManifestPreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.references = PREFLIGHT.load_production_image_references(ROOT)

    def _assert_repository_mutation_rejected(
        self,
        *,
        dockerfile: str | bytes | None = None,
        compose: str | bytes | None = None,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            dockerfile_bytes = (
                dockerfile.encode("utf-8")
                if isinstance(dockerfile, str)
                else dockerfile
            )
            compose_bytes = (
                compose.encode("utf-8")
                if isinstance(compose, str)
                else compose
            )
            (root / "Dockerfile").write_bytes(
                dockerfile_bytes
                if dockerfile_bytes is not None
                else (ROOT / "Dockerfile").read_bytes()
            )
            (root / "compose.yaml").write_bytes(
                compose_bytes
                if compose_bytes is not None
                else (ROOT / "compose.yaml").read_bytes()
            )

            real_load = PREFLIGHT.load_production_image_references
            stdout = StringIO()
            stderr = StringIO()
            with patch.object(
                PREFLIGHT,
                "load_production_image_references",
                side_effect=lambda _root: real_load(root),
            ), patch.object(
                PREFLIGHT,
                "verify_docker_hub_manifests",
            ) as verify:
                result = PREFLIGHT.main((), stdout=stdout, stderr=stderr)

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), PREFLIGHT.BLOCKED)
            verify.assert_not_called()

    def _assert_dockerfile_semantics_rejected(self, dockerfile: str) -> None:
        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT._validate_dockerfile_semantics(dockerfile)

    def test_reads_exact_five_current_production_references(self) -> None:
        expected = (
                "docker.io/docker/dockerfile:1.12@sha256:"
                "93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25",
                "docker.io/library/python:3.14.1-slim-bookworm@sha256:"
                "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff",
                "docker.io/library/node:22.22.3-bookworm-slim@sha256:"
                "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752",
                "docker.io/library/caddy:2.10.2-alpine@sha256:"
                "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
                "docker.io/library/postgres:18.4-alpine@sha256:"
                "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
        )
        self.assertEqual(PREFLIGHT.EXPECTED_PRODUCTION_IMAGE_REFERENCES, expected)
        self.assertEqual(
            tuple(reference.canonical for reference in self.references),
            expected,
        )

    def test_current_build_sources_match_the_closed_byte_digests(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_bytes()
        compose = (ROOT / "compose.yaml").read_bytes()
        self.assertEqual(
            PREFLIGHT.EXPECTED_DOCKERFILE_SHA256,
            "6d16a0a7179dcf62fe7cdf2b2a76b39b1d1db8c450ea2d1df35ed0ec84b14677",
        )
        self.assertEqual(
            PREFLIGHT.EXPECTED_COMPOSE_SHA256,
            "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd",
        )
        self.assertEqual(
            hashlib.sha256(dockerfile).hexdigest(),
            PREFLIGHT.EXPECTED_DOCKERFILE_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(compose).hexdigest(),
            PREFLIGHT.EXPECTED_COMPOSE_SHA256,
        )

    def test_rejects_first_middle_and_last_byte_mutations_before_network(self) -> None:
        for filename in ("Dockerfile", "compose.yaml"):
            approved = (ROOT / filename).read_bytes()
            for position in (0, len(approved) // 2, len(approved) - 1):
                mutated = bytearray(approved)
                mutated[position] ^= 1
                with self.subTest(filename=filename, position=position):
                    if filename == "Dockerfile":
                        self._assert_repository_mutation_rejected(
                            dockerfile=bytes(mutated)
                        )
                    else:
                        self._assert_repository_mutation_rejected(
                            compose=bytes(mutated)
                        )

    def test_rejects_any_change_to_the_five_hard_coded_pins(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        for _slot, _repository, expected_line, _value in (
            PREFLIGHT._EXPECTED_DOCKERFILE_BINDINGS
        ):
            replacement = expected_line[:-1] + (
                "0" if expected_line[-1] != "0" else "1"
            )
            with self.subTest(line=expected_line.split("@", 1)[0]):
                self._assert_repository_mutation_rejected(
                    dockerfile=dockerfile.replace(expected_line, replacement, 1)
                )
        expected_image_line = (
            f"    image: {PREFLIGHT._EXPECTED_COMPOSE_DB_IMAGE}"
        )
        replacement = expected_image_line[:-1] + (
            "0" if expected_image_line[-1] != "0" else "1"
        )
        self._assert_repository_mutation_rejected(
            compose=compose.replace(expected_image_line, replacement, 1)
        )

    def test_rejects_dockerfile_semantic_rebindings_and_stage_redirects(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        syntax_line = PREFLIGHT._EXPECTED_DOCKERFILE_BINDINGS[0][2]
        python_arg = PREFLIGHT._EXPECTED_DOCKERFILE_BINDINGS[1][2]
        platform_builder = PREFLIGHT._EXPECTED_PRODUCTION_FROM_LINES[
            "platform-builder"
        ]
        mutations = (
            dockerfile.replace(
                syntax_line,
                syntax_line + "\n# SYNTAX =docker/dockerfile:evil",
                1,
            ),
            dockerfile.replace(
                python_arg,
                python_arg + "\n arg  PYTHON_IMAGE=python:evil",
                1,
            ),
            dockerfile.replace(
                python_arg,
                "ARG \\\n    PYTHON_IMAGE=python:evil",
                1,
            ),
            dockerfile.replace(
                platform_builder,
                "from ${PYTHON_IMAGE} as PLATFORM-BUILDER",
                1,
            ),
            dockerfile.replace(
                platform_builder,
                "FROM evil.invalid/image AS platform-builder\n"
                + platform_builder,
                1,
            ),
            dockerfile.replace(
                platform_builder,
                "FROM evil.invalid/image AS \\\n  platform-builder",
                1,
            ),
        )
        mutations += (
            dockerfile.replace(
                platform_builder,
                "FROM evil.invalid/bootstrap AS untrusted-bootstrap\n"
                + platform_builder,
                1,
            ),
            dockerfile.replace(
                platform_builder,
                platform_builder
                + "\nCOPY --from=untrusted-bootstrap /payload /payload",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_repository_mutation_rejected(dockerfile=mutation)

    def test_edge_runtime_is_a_scratch_metadata_allowlist(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        PREFLIGHT._validate_dockerfile_semantics(dockerfile)
        self.assertEqual(
            PREFLIGHT._dockerfile_stage_logical_instructions(
                dockerfile.splitlines(), "edge-runtime"
            ),
            PREFLIGHT._EXPECTED_EDGE_RUNTIME_LOGICAL_INSTRUCTIONS,
        )

        final_from = "FROM scratch AS edge-runtime"
        final_expose = "EXPOSE 443 8080"
        final_copy = "COPY --from=edge-runtime-filesystem / /"
        final_cmd = (
            'CMD ["/usr/bin/caddy", "run", "--config", '
            '"/etc/caddy/Caddyfile", "--adapter", "caddyfile"]'
        )
        mutations = (
            dockerfile.replace(
                final_from,
                "FROM ${CADDY_IMAGE} AS edge-runtime",
                1,
            ),
            dockerfile.replace(final_expose, "EXPOSE 443 8080 2019", 1),
            dockerfile.replace(
                final_expose,
                final_expose + "\nVOLUME [\"/data\"]",
                1,
            ),
            dockerfile.replace(
                final_copy,
                final_copy + "\nENTRYPOINT [\"/usr/bin/caddy\"]",
                1,
            ),
            dockerfile.replace(
                "WORKDIR /srv",
                "WORKDIR /\nSTOPSIGNAL SIGQUIT",
                1,
            ),
            dockerfile.replace(
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\",
                "PATH=/usr/bin:/bin \\",
                1,
            ),
            dockerfile.replace(final_cmd, final_cmd.replace("/usr/bin/caddy", "caddy"), 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutation, dockerfile)
                self._assert_dockerfile_semantics_rejected(mutation)

    def test_rejects_compose_db_image_alternatives_and_duplicates(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        expected_line = f"    image: {PREFLIGHT._EXPECTED_COMPOSE_DB_IMAGE}"
        mutations = (
            compose.replace(
                expected_line,
                expected_line + "\n    image: postgres:evil",
                1,
            ),
            compose.replace(
                expected_line,
                expected_line + '\n    "image": "postgres:evil"',
                1,
            ),
            compose.replace(
                expected_line,
                expected_line + "\n    ? image\n    : postgres:evil",
                1,
            ),
            compose.replace(
                expected_line,
                expected_line + "\n    image : postgres:evil",
                1,
            ),
            compose.replace(
                expected_line,
                f'    "image": "{PREFLIGHT._EXPECTED_COMPOSE_DB_IMAGE}"',
                1,
            ),
            compose.replace(
                "  migrate:",
                '  "db":\n    image: postgres:evil\n\n  migrate:',
                1,
            ),
            compose.replace(
                expected_line,
                expected_line + "\n    <<: *untrusted-image",
                1,
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_repository_mutation_rejected(compose=mutation)

    def test_rejects_compose_build_arg_and_context_overrides_before_network(self) -> None:
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        service_build_arguments = {
            "migrate": "PYTHON_IMAGE",
            "api": "PYTHON_IMAGE",
            "web": "NODE_IMAGE",
            "edge": "CADDY_IMAGE",
        }

        def insert_in_build(service: str, addition: str) -> str:
            service_marker = f"  {service}:"
            prefix, service_and_remainder = compose.split(service_marker, 1)
            build_marker = "    build:\n"
            before_build, after_build = service_and_remainder.split(
                build_marker,
                1,
            )
            return (
                prefix
                + service_marker
                + before_build
                + build_marker
                + addition
                + after_build
            )

        for service, argument in service_build_arguments.items():
            mutations = (
                insert_in_build(
                    service,
                    "      args:\n"
                    f"        {argument}: evil.invalid/image@sha256:"
                    + "0" * 64
                    + "\n",
                ),
                insert_in_build(
                    service,
                    "      context: https://evil.invalid/context.git\n",
                ),
            )
            for kind, mutation in zip(("args", "context"), mutations):
                with self.subTest(service=service, kind=kind):
                    self._assert_repository_mutation_rejected(compose=mutation)

    def test_success_uses_anonymous_auth_and_head_metadata_only(self) -> None:
        registry = _RegistryDouble()

        PREFLIGHT.verify_docker_hub_manifests(
            self.references,
            transport_factory=lambda: registry,
        )

        self.assertEqual(registry.token_count, 5)
        self.assertEqual(registry.head_count, 15)
        self.assertEqual(len(registry.requests), 20)
        self.assertEqual(registry.close_count, 1)
        self.assertTrue(all(response.closed for response in registry.responses))
        ordered_repositories = [
            reference.repository for reference in self.references
        ]
        self.assertEqual(registry.token_repositories, ordered_repositories)
        self.assertEqual(
            registry.head_repositories,
            ordered_repositories * 3,
        )
        expected_operations = []
        for repository in ordered_repositories:
            expected_operations.extend((("GET", repository), ("HEAD", repository)))
        expected_operations.extend(
            ("HEAD", repository)
            for repository in ordered_repositories * 2
        )
        self.assertEqual(registry.ordered_operations, expected_operations)
        expected_authorization = {
            repository: f"Bearer anonymous-token-{index}"
            for index, repository in enumerate(ordered_repositories, start=1)
        }
        head_repositories = iter(registry.head_repositories)
        for (request, timeout), response in zip(
            registry.requests,
            registry.responses,
        ):
            self.assertEqual(timeout, PREFLIGHT.REQUEST_TIMEOUT_SECONDS)
            self.assertEqual(
                request.get_header("User-agent"),
                PREFLIGHT.USER_AGENT,
            )
            if request.get_method() == "GET":
                self.assertIsNone(request.get_header("Authorization"))
                self.assertEqual(request.get_header("Accept"), "application/json")
                self.assertEqual(response.read_count, 1)
            else:
                repository = next(head_repositories)
                self.assertEqual(
                    request.get_header("Accept"),
                    PREFLIGHT.MANIFEST_ACCEPT,
                )
                self.assertEqual(
                    request.get_header("Authorization"),
                    expected_authorization[repository],
                )
                self.assertEqual(response.read_count, 0)

    def test_digest_mismatch_fails_closed(self) -> None:
        registry = _RegistryDouble(mismatch_head_at=1)

        with self.assertRaises(
            PREFLIGHT.DockerHubManifestPreflightError
        ) as raised:
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 1)
        self.assertEqual(registry.close_count, 1)
        self.assertNotIn("anonymous-token", str(raised.exception))

    def test_duplicate_digest_headers_fail_even_when_one_or_both_match(self) -> None:
        for field, registry in (
            (
                "duplicate-correct",
                _RegistryDouble(duplicate_digest_head_at=1),
            ),
            (
                "correct-and-conflicting",
                _RegistryDouble(conflicting_digest_head_at=1),
            ),
        ):
            with self.subTest(field=field):
                with self.assertRaises(
                    PREFLIGHT.DockerHubManifestPreflightError
                ):
                    PREFLIGHT.verify_docker_hub_manifests(
                        self.references,
                        transport_factory=lambda registry=registry: registry,
                    )
                self.assertEqual(registry.token_count, 1)
                self.assertEqual(registry.head_count, 1)
                self.assertEqual(registry.close_count, 1)

    def test_manifest_http_failure_fails_closed(self) -> None:
        registry = _RegistryDouble(fail_head_at=1)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 1)
        self.assertEqual(registry.close_count, 1)

    def test_token_failure_stops_before_manifest_request(self) -> None:
        registry = _RegistryDouble(fail_token_at=1)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 0)
        self.assertEqual(registry.close_count, 1)

    def test_token_redirect_is_rejected_without_following(self) -> None:
        registry = _RegistryDouble(redirect_token_at=1)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 0)
        self.assertEqual(len(registry.requests), 1)
        self.assertEqual(registry.close_count, 1)

    def test_oversized_token_response_fails_closed(self) -> None:
        registry = _RegistryDouble(oversized_token_at=1)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 0)
        self.assertEqual(registry.close_count, 1)
        self.assertTrue(all(response.closed for response in registry.responses))

    def test_missing_digest_header_fails_closed(self) -> None:
        registry = _RegistryDouble(missing_digest_head_at=1)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        self.assertEqual(registry.token_count, 1)
        self.assertEqual(registry.head_count, 1)
        self.assertEqual(registry.close_count, 1)

    def test_three_round_order_stops_at_first_failure_without_retry(self) -> None:
        registry = _RegistryDouble(fail_head_at=7)

        with self.assertRaises(PREFLIGHT.DockerHubManifestPreflightError):
            PREFLIGHT.verify_docker_hub_manifests(
                self.references,
                transport_factory=lambda: registry,
            )

        ordered_repositories = [
            reference.repository for reference in self.references
        ]
        expected_before_failure = ordered_repositories + ordered_repositories[:2]
        self.assertEqual(registry.token_repositories, ordered_repositories)
        self.assertEqual(registry.head_repositories, expected_before_failure)
        self.assertEqual(registry.token_count, 5)
        self.assertEqual(registry.head_count, 7)
        self.assertEqual(len(registry.requests), 12)
        self.assertEqual(registry.close_count, 1)

    def test_main_loads_then_verifies_before_printing_ready(self) -> None:
        events = []

        def load(_root):
            events.append("load")
            return self.references

        def verify(references):
            self.assertEqual(references, self.references)
            events.append("verify")

        stdout = StringIO()
        stderr = StringIO()
        with patch.object(
            PREFLIGHT,
            "load_production_image_references",
            side_effect=load,
        ), patch.object(
            PREFLIGHT,
            "verify_docker_hub_manifests",
            side_effect=verify,
        ):
            result = PREFLIGHT.main((), stdout=stdout, stderr=stderr)

        self.assertEqual(events, ["load", "verify"])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), PREFLIGHT.READY)
        self.assertEqual(stderr.getvalue(), "")

    def test_main_never_prints_ready_when_load_or_verification_fails(self) -> None:
        for failure in ("load", "verify"):
            events = []

            def load(_root):
                events.append("load")
                if failure == "load":
                    raise PREFLIGHT.DockerHubManifestPreflightError()
                return self.references

            def verify(_references):
                events.append("verify")
                raise PREFLIGHT.DockerHubManifestPreflightError()

            stdout = StringIO()
            stderr = StringIO()
            with self.subTest(failure=failure), patch.object(
                PREFLIGHT,
                "load_production_image_references",
                side_effect=load,
            ), patch.object(
                PREFLIGHT,
                "verify_docker_hub_manifests",
                side_effect=verify,
            ):
                result = PREFLIGHT.main((), stdout=stdout, stderr=stderr)

            self.assertEqual(
                events,
                ["load"] if failure == "load" else ["load", "verify"],
            )
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), PREFLIGHT.BLOCKED)


if __name__ == "__main__":
    unittest.main()
