#!/usr/bin/env python3
"""Verify that every pinned production image manifest is present on Docker Hub.

The preflight reads the five production image slots from the repository, obtains
anonymous pull tokens, and issues HEAD requests for manifest metadata only.  It
never downloads image layers and deliberately has no retry path: one failed
check invalidates the whole three-round observation.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
from http.client import HTTPSConnection
import json
from pathlib import Path
import re
import ssl
import sys
from typing import Callable, NoReturn, Optional, Sequence, TextIO
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request


READY = (
    '{"checks":15,"refs":5,"rounds":3,'
    '"status":"DOCKER_HUB_MANIFEST_PREFLIGHT_READY"}\n'
)
BLOCKED = (
    '{"code":"DOCKER_HUB_MANIFEST_PREFLIGHT_INVALID",'
    '"status":"BLOCKED"}\n'
)
DEFAULT_ROUNDS = 3
EXPECTED_REFERENCE_COUNT = 5
EXPECTED_DOCKERFILE_SHA256 = (
    "6d16a0a7179dcf62fe7cdf2b2a76b39b1d1db8c450ea2d1df35ed0ec84b14677"
)
EXPECTED_COMPOSE_SHA256 = (
    "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd"
)
REQUEST_TIMEOUT_SECONDS = 15
TOKEN_ENDPOINT = "https://auth.docker.io/token"
REGISTRY_ENDPOINT = "https://registry-1.docker.io"
_AUTH_HOST = "auth.docker.io"
_REGISTRY_HOST = "registry-1.docker.io"
USER_AGENT = "desire-supply-docker-hub-manifest-preflight/1"
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
_MAX_TOKEN_RESPONSE_BYTES = 128 * 1024
_MAX_TOKEN_BYTES = 16 * 1024
_REFERENCE = re.compile(
    r"^(?P<name>[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r":(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})"
    r"@(?P<digest>sha256:[0-9a-f]{64})$"
)
EXPECTED_PRODUCTION_IMAGE_REFERENCES = (
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
_EXPECTED_DOCKERFILE_BINDINGS = (
    (
        "dockerfile",
        "docker/dockerfile",
        "# syntax=docker/dockerfile:1.12@sha256:"
        "93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25",
        "docker/dockerfile:1.12@sha256:"
        "93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25",
    ),
    (
        "python",
        "library/python",
        "ARG PYTHON_IMAGE=python:3.14.1-slim-bookworm@sha256:"
        "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff",
        "python:3.14.1-slim-bookworm@sha256:"
        "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff",
    ),
    (
        "node",
        "library/node",
        "ARG NODE_IMAGE=node:22.22.3-bookworm-slim@sha256:"
        "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752",
        "node:22.22.3-bookworm-slim@sha256:"
        "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752",
    ),
    (
        "caddy",
        "library/caddy",
        "ARG CADDY_IMAGE=caddy:2.10.2-alpine@sha256:"
        "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
        "caddy:2.10.2-alpine@sha256:"
        "4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d",
    ),
)
_EXPECTED_COMPOSE_DB_IMAGE = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
_EXPECTED_SLOT_REPOSITORIES = (
    ("dockerfile", "docker/dockerfile"),
    ("python", "library/python"),
    ("node", "library/node"),
    ("caddy", "library/caddy"),
    ("postgres", "library/postgres"),
)
_TARGET_BUILD_ARGUMENTS = {
    "PYTHON_IMAGE": _EXPECTED_DOCKERFILE_BINDINGS[1][2],
    "NODE_IMAGE": _EXPECTED_DOCKERFILE_BINDINGS[2][2],
    "CADDY_IMAGE": _EXPECTED_DOCKERFILE_BINDINGS[3][2],
}
_EXPECTED_PRODUCTION_FROM_LINES = {
    "platform-builder": "FROM ${PYTHON_IMAGE} AS platform-builder",
    "platform-runtime": "FROM ${PYTHON_IMAGE} AS platform-runtime",
    "web-builder": "FROM ${NODE_IMAGE} AS web-builder",
    "web-runtime": "FROM ${NODE_IMAGE} AS web-runtime",
    "edge-runtime-filesystem": (
        "FROM ${CADDY_IMAGE} AS edge-runtime-filesystem"
    ),
    "edge-runtime": "FROM scratch AS edge-runtime",
}
_EXPECTED_EDGE_RUNTIME_LOGICAL_INSTRUCTIONS = (
    "FROM scratch AS edge-runtime",
    (
        "ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "
        "XDG_CONFIG_HOME=/tmp/caddy-config XDG_DATA_HOME=/tmp/caddy-data"
    ),
    "COPY --from=edge-runtime-filesystem / /",
    "WORKDIR /srv",
    "USER 10001:10001",
    "EXPOSE 443 8080",
    (
        'CMD ["/usr/bin/caddy", "run", "--config", '
        '"/etc/caddy/Caddyfile", "--adapter", "caddyfile"]'
    ),
)
_DOCKERFILE_INSTRUCTION = re.compile(
    r"^[ \t]*(?P<instruction>[A-Za-z]+)(?=$|[ \t])"
)
_PARSER_DIRECTIVE = re.compile(
    r"^[ \t]*#[ \t]*(?P<name>[A-Za-z]+)[ \t]*="
)
_FROM_STAGE = re.compile(
    r"(?:^|[ \t])AS[ \t]+(?P<stage>[A-Za-z0-9_.-]+)(?:$|[ \t])",
    re.IGNORECASE,
)


class DockerHubManifestPreflightError(RuntimeError):
    """Stable, non-reflective failure for the remote manifest gate."""

    def __init__(self) -> None:
        super().__init__("DOCKER_HUB_MANIFEST_PREFLIGHT_INVALID")


@dataclass(frozen=True)
class ProductionImageReference:
    """One closed repository slot and its digest-pinned Docker Hub reference."""

    slot: str
    repository: str
    tag: str
    digest: str

    @property
    def canonical(self) -> str:
        return f"docker.io/{self.repository}:{self.tag}@{self.digest}"


class DockerHubHTTPSessionTransport:
    """Two-host, persistent HTTPS transport with no redirect or retry path."""

    def __init__(
        self,
        *,
        connection_factory: Callable[..., object] = HTTPSConnection,
    ) -> None:
        if not callable(connection_factory):
            _invalid()
        tls_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        if (
            not tls_context.check_hostname
            or tls_context.verify_mode != ssl.CERT_REQUIRED
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            _invalid()
        self._connection_factory = connection_factory
        self._tls_context = tls_context
        self._connections: dict[str, object] = {}
        self._closed = False

    def open(self, request: Request, *, timeout: int) -> object:
        """Issue exactly one request and return its bounded-use response."""

        if (
            self._closed
            or not isinstance(request, Request)
            or type(timeout) is not int
            or not 1 <= timeout <= 60
        ):
            _invalid()
        try:
            parsed = urlsplit(request.full_url)
            port = parsed.port
        except (TypeError, ValueError):
            _invalid()
        host = parsed.hostname
        method = request.get_method()
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port is not None
            or parsed.netloc != host
            or (host, method)
            not in ((_AUTH_HOST, "GET"), (_REGISTRY_HOST, "HEAD"))
            or request.has_header("Host")
            or request.has_header("Connection")
            or (
                host == _AUTH_HOST
                and request.has_header("Authorization")
            )
        ):
            _invalid()
        selector = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection = self._connections.get(host)
        if connection is None:
            try:
                connection = self._connection_factory(
                    host,
                    443,
                    timeout=timeout,
                    context=self._tls_context,
                )
            except DockerHubManifestPreflightError:
                raise
            except Exception as error:
                raise DockerHubManifestPreflightError() from error
            self._connections[host] = connection
        try:
            network_socket = getattr(connection, "sock", None)
            if network_socket is not None:
                network_socket.settimeout(timeout)
            connection.request(
                method,
                selector,
                headers=dict(request.header_items()),
            )
            return connection.getresponse()
        except DockerHubManifestPreflightError:
            raise
        except Exception as error:
            raise DockerHubManifestPreflightError() from error

    def close(self) -> None:
        """Close both host connections, including after fail-fast exits."""

        if self._closed:
            return
        self._closed = True
        close_error: Optional[Exception] = None
        for connection in self._connections.values():
            try:
                connection.close()
            except Exception as error:
                if close_error is None:
                    close_error = error
        self._connections.clear()
        if close_error is not None:
            raise DockerHubManifestPreflightError() from close_error


def load_production_image_references(
    repository_root: Path,
) -> tuple[ProductionImageReference, ...]:
    """Read the exact five production image slots from checked-in artifacts."""

    if not isinstance(repository_root, Path):
        _invalid()
    dockerfile = _read_closed_text(
        repository_root / "Dockerfile",
        expected_sha256=EXPECTED_DOCKERFILE_SHA256,
    )
    compose = _read_closed_text(
        repository_root / "compose.yaml",
        expected_sha256=EXPECTED_COMPOSE_SHA256,
    )

    _validate_dockerfile_semantics(dockerfile)
    references = []
    for slot, expected_repository, expected_line, expected_value in (
        _EXPECTED_DOCKERFILE_BINDINGS
    ):
        if dockerfile.splitlines().count(expected_line) != 1:
            _invalid()
        references.append(
            _parse_reference(slot, expected_repository, expected_value)
        )

    postgres_reference = _extract_compose_service_image(compose, "db")
    references.append(
        _parse_reference("postgres", "library/postgres", postgres_reference)
    )
    if (
        len(references) != EXPECTED_REFERENCE_COUNT
        or len({reference.slot for reference in references})
        != EXPECTED_REFERENCE_COUNT
        or len({reference.canonical for reference in references})
        != EXPECTED_REFERENCE_COUNT
        or tuple(reference.canonical for reference in references)
        != EXPECTED_PRODUCTION_IMAGE_REFERENCES
    ):
        _invalid()
    return tuple(references)


def verify_docker_hub_manifests(
    references: Sequence[ProductionImageReference],
    *,
    rounds: int = DEFAULT_ROUNDS,
    transport_factory: Callable[..., object] = DockerHubHTTPSessionTransport,
    timeout_seconds: int = REQUEST_TIMEOUT_SECONDS,
) -> None:
    """Run three complete, ordered rounds with no retries or stitched results."""

    if (
        rounds != DEFAULT_ROUNDS
        or type(rounds) is not int
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 60
        or not callable(transport_factory)
        or isinstance(references, (str, bytes))
    ):
        _invalid()
    try:
        closed_references = tuple(references)
    except (TypeError, ValueError):
        _invalid()
    if (
        len(closed_references) != EXPECTED_REFERENCE_COUNT
        or any(
            not isinstance(reference, ProductionImageReference)
            for reference in closed_references
        )
        or len({reference.slot for reference in closed_references})
        != EXPECTED_REFERENCE_COUNT
        or len({reference.canonical for reference in closed_references})
        != EXPECTED_REFERENCE_COUNT
        or tuple(
            (reference.slot, reference.repository)
            for reference in closed_references
        )
        != _EXPECTED_SLOT_REPOSITORIES
        or tuple(
            reference.canonical for reference in closed_references
        )
        != EXPECTED_PRODUCTION_IMAGE_REFERENCES
        or any(
            _REFERENCE.fullmatch(
                f"{reference.repository}:{reference.tag}@{reference.digest}"
            )
            is None
            for reference in closed_references
        )
    ):
        _invalid()

    try:
        transport = transport_factory()
        open_url = getattr(transport, "open", None)
        close_transport = getattr(transport, "close", None)
        if not callable(open_url) or not callable(close_transport):
            _invalid()
        with closing(transport):
            tokens: dict[str, str] = {}
            for _round_number in range(1, rounds + 1):
                for reference in closed_references:
                    token = tokens.get(reference.repository)
                    if token is None:
                        token = _fetch_anonymous_token(
                            reference,
                            open_url=open_url,
                            timeout_seconds=timeout_seconds,
                        )
                        tokens[reference.repository] = token
                    _head_manifest(
                        reference,
                        token=token,
                        open_url=open_url,
                        timeout_seconds=timeout_seconds,
                    )
    except DockerHubManifestPreflightError:
        raise
    except Exception as error:
        raise DockerHubManifestPreflightError() from error


def _read_closed_text(path: Path, *, expected_sha256: str) -> str:
    try:
        if (
            not path.is_file()
            or path.is_symlink()
            or not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            _invalid()
        raw = path.read_bytes()
    except DockerHubManifestPreflightError:
        raise
    except OSError:
        _invalid()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        _invalid()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        _invalid()
    if not raw or b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        _invalid()
    return text


def _validate_dockerfile_semantics(dockerfile: str) -> None:
    """Close instruction spellings that could redirect a pinned build slot."""

    lines = dockerfile.splitlines()
    syntax_lines = []
    target_argument_lines: dict[str, list[str]] = {
        name: [] for name in _TARGET_BUILD_ARGUMENTS
    }
    production_stage_lines: dict[str, list[str]] = {
        name: [] for name in _EXPECTED_PRODUCTION_FROM_LINES
    }

    for line_number, line in enumerate(lines):
        directive = _PARSER_DIRECTIVE.match(line)
        if directive is not None:
            directive_name = directive.group("name").lower()
            if directive_name == "syntax":
                syntax_lines.append((line_number, line))
            elif directive_name == "escape":
                _invalid()

        instruction_match = _DOCKERFILE_INSTRUCTION.match(line)
        if instruction_match is None:
            continue
        instruction = instruction_match.group("instruction").upper()
        if instruction not in ("ARG", "FROM"):
            continue
        logical_instruction, physical_lines = _dockerfile_logical_instruction(
            lines,
            line_number,
        )
        if instruction == "ARG":
            folded_instruction = logical_instruction.upper()
            for argument_name in _TARGET_BUILD_ARGUMENTS:
                if re.search(
                    rf"(?<![A-Z0-9_]){re.escape(argument_name)}"
                    rf"(?![A-Z0-9_])",
                    folded_instruction,
                ):
                    if len(physical_lines) != 1:
                        _invalid()
                    target_argument_lines[argument_name].append(line)
            continue

        stage_match = _FROM_STAGE.search(logical_instruction)
        if stage_match is None:
            continue
        stage = stage_match.group("stage").lower()
        if stage in production_stage_lines:
            if len(physical_lines) != 1:
                _invalid()
            production_stage_lines[stage].append(line)

    expected_syntax_line = _EXPECTED_DOCKERFILE_BINDINGS[0][2]
    if syntax_lines != [(0, expected_syntax_line)]:
        _invalid()
    if any(
        lines_for_argument != [_TARGET_BUILD_ARGUMENTS[argument_name]]
        for argument_name, lines_for_argument in target_argument_lines.items()
    ):
        _invalid()
    if any(
        lines_for_stage != [_EXPECTED_PRODUCTION_FROM_LINES[stage]]
        for stage, lines_for_stage in production_stage_lines.items()
    ):
        _invalid()
    if (
        _dockerfile_stage_logical_instructions(lines, "edge-runtime")
        != _EXPECTED_EDGE_RUNTIME_LOGICAL_INSTRUCTIONS
    ):
        _invalid()


def _dockerfile_logical_instruction(
    lines: Sequence[str],
    start_index: int,
) -> tuple[str, tuple[str, ...]]:
    physical_lines = []
    index = start_index
    while True:
        if index >= len(lines):
            _invalid()
        line = lines[index]
        physical_lines.append(line)
        without_trailing_space = line.rstrip(" \t")
        if not without_trailing_space.endswith("\\"):
            break
        index += 1
    logical_parts = []
    for line_index, physical_line in enumerate(physical_lines):
        part = physical_line.strip(" \t")
        if line_index < len(physical_lines) - 1:
            part = part.rstrip(" \t")[:-1].rstrip(" \t")
        logical_parts.append(part)
    return " ".join(logical_parts), tuple(physical_lines)


def _dockerfile_stage_logical_instructions(
    lines: Sequence[str], stage_name: str
) -> tuple[str, ...]:
    if not isinstance(stage_name, str) or not stage_name:
        _invalid()
    current_stage = None
    selected = []
    index = 0
    while index < len(lines):
        instruction_match = _DOCKERFILE_INSTRUCTION.match(lines[index])
        if instruction_match is None:
            index += 1
            continue
        logical_instruction, physical_lines = _dockerfile_logical_instruction(
            lines, index
        )
        instruction = instruction_match.group("instruction").upper()
        if instruction == "FROM":
            stage_match = _FROM_STAGE.search(logical_instruction)
            current_stage = (
                stage_match.group("stage").lower()
                if stage_match is not None
                else None
            )
        if current_stage == stage_name:
            selected.append(logical_instruction)
        index += len(physical_lines)
    return tuple(selected)


def _extract_compose_service_image(compose: str, service: str) -> str:
    if service != "db" or "\t" in compose:
        _invalid()
    lines = compose.splitlines()
    services_indexes = [
        index for index, line in enumerate(lines) if line == "services:"
    ]
    if len(services_indexes) != 1:
        _invalid()
    services_index = services_indexes[0]
    services_end = len(lines)
    for index, line in enumerate(lines[services_index + 1 :], services_index + 1):
        if line and not line.startswith(" ") and not line.startswith("#"):
            services_end = index
            break

    for line in lines:
        stripped = line.lstrip(" ")
        if stripped.startswith("?") and re.search(
            r"(?:^|[ \"'])services(?:$|[ \"':])",
            stripped[1:].lstrip(" "),
        ):
            _invalid()
        if re.match(r"^[ \t]*[\"']services[\"'][ \t]*:", line):
            _invalid()

    service_header = f"  {service}:"
    service_indexes = [
        index
        for index, line in enumerate(
            lines[services_index + 1 : services_end],
            services_index + 1,
        )
        if line == service_header
    ]
    if len(service_indexes) != 1:
        _invalid()

    for line in lines[services_index + 1 : services_end]:
        if line == service_header:
            continue
        if re.match(r"^  [\"']db[\"'][ ]*:", line):
            _invalid()
        if re.match(r"^  db[ ]+:", line):
            _invalid()
        if re.match(r"^  \?[ ]+(?:db|[\"']db[\"'])(?:[ ]|:|$)", line):
            _invalid()

    service_start = service_indexes[0]
    service_end = services_end
    for index, line in enumerate(lines[service_start + 1 : services_end], service_start + 1):
        if line.startswith("  ") and not line.startswith("    "):
            service_end = index
            break
        if line and not line.startswith(" "):
            service_end = index
            break

    image_lines = []
    for line in lines[service_start + 1 : service_end]:
        if line.startswith("    <<"):
            _invalid()
        if re.match(r"^    [\"']", line) or re.match(r"^    \?", line):
            _invalid()
        if re.match(r"^    image[ ]*:", line):
            image_lines.append(line)
        elif re.match(r"^    image(?:[ ]|$)", line):
            _invalid()
    expected_image_line = f"    image: {_EXPECTED_COMPOSE_DB_IMAGE}"
    if image_lines != [expected_image_line]:
        _invalid()
    return _EXPECTED_COMPOSE_DB_IMAGE


def _parse_reference(
    slot: str,
    expected_repository: str,
    value: str,
) -> ProductionImageReference:
    if not isinstance(value, str) or value != value.strip():
        _invalid()
    match = _REFERENCE.fullmatch(value)
    if match is None:
        _invalid()
    name = match.group("name")
    repository = name if "/" in name else f"library/{name}"
    if repository != expected_repository:
        _invalid()
    return ProductionImageReference(
        slot=slot,
        repository=repository,
        tag=match.group("tag"),
        digest=match.group("digest"),
    )


def _fetch_anonymous_token(
    reference: ProductionImageReference,
    *,
    open_url: Callable[..., object],
    timeout_seconds: int,
) -> str:
    query = urlencode(
        (
            ("service", "registry.docker.io"),
            ("scope", f"repository:{reference.repository}:pull"),
        )
    )
    request = Request(
        f"{TOKEN_ENDPOINT}?{query}",
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with closing(open_url(request, timeout=timeout_seconds)) as response:
            if _response_status(response) != 200:
                _invalid()
            body = response.read(_MAX_TOKEN_RESPONSE_BYTES + 1)
    except DockerHubManifestPreflightError:
        raise
    except Exception as error:
        raise DockerHubManifestPreflightError() from error
    if not isinstance(body, bytes) or len(body) > _MAX_TOKEN_RESPONSE_BYTES:
        _invalid()
    try:
        document = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError):
        _invalid()
    if not isinstance(document, dict):
        _invalid()
    token = document.get("token")
    access_token = document.get("access_token")
    if token is None:
        token = access_token
    elif access_token is not None and access_token != token:
        _invalid()
    if (
        not isinstance(token, str)
        or not 1 <= len(token.encode("ascii", errors="ignore")) <= _MAX_TOKEN_BYTES
        or token.encode("ascii", errors="ignore").decode("ascii") != token
        or token != token.strip()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
    ):
        _invalid()
    return token


def _head_manifest(
    reference: ProductionImageReference,
    *,
    token: str,
    open_url: Callable[..., object],
    timeout_seconds: int,
) -> None:
    request = Request(
        f"{REGISTRY_ENDPOINT}/v2/{reference.repository}/manifests/"
        f"{reference.digest}",
        headers={
            "Accept": MANIFEST_ACCEPT,
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
        },
        method="HEAD",
    )
    try:
        with closing(open_url(request, timeout=timeout_seconds)) as response:
            if _response_status(response) != 200:
                _invalid()
            headers = getattr(response, "headers", None)
            if headers is None:
                _invalid()
            get_all = getattr(headers, "get_all", None)
            if not callable(get_all):
                _invalid()
            observed_digests = get_all("Docker-Content-Digest")
            if (
                not isinstance(observed_digests, list)
                or observed_digests != [reference.digest]
            ):
                _invalid()
    except DockerHubManifestPreflightError:
        raise
    except Exception as error:
        raise DockerHubManifestPreflightError() from error


def _response_status(response: object) -> int:
    status = getattr(response, "status", None)
    if type(status) is not int:
        _invalid()
    return status


def _invalid() -> NoReturn:
    raise DockerHubManifestPreflightError()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if arguments:
            _invalid()
        repository_root = Path(__file__).resolve().parents[1]
        references = load_production_image_references(repository_root)
        verify_docker_hub_manifests(references)
    except DockerHubManifestPreflightError:
        stderr.write(BLOCKED)
        return 1
    stdout.write(READY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
