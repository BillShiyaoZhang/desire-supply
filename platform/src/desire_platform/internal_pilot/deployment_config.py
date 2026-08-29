"""Closed non-secret deployment bundle for the internal sandbox API process."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple
import unicodedata
from urllib.parse import urlsplit
from uuid import UUID

from .postgres_pool import PostgresEndpointSettings


_MAXIMUM_CONFIG_BYTES = 256 * 1024
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_DNS_NAME = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_REVIEWED_ALGORITHMS = frozenset(("ES256", "RS256"))
OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC = "SYSTEM_DNS_SYNTHETIC"
OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP = "PINNED_PUBLIC_IP"
DEPLOYMENT_CONFIG_POINTER_ENV = (
    "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"
)


class InternalSandboxDeploymentConfigError(ValueError):
    def __init__(self) -> None:
        self.code = "INVALID_INTERNAL_SANDBOX_DEPLOYMENT_CONFIGURATION"
        super().__init__(self.code)


class _InvalidConfiguration(Exception):
    pass


def _invalid(*_facts: Any) -> Any:
    raise _InvalidConfiguration


def _string(value: Any, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or any(unicodedata.category(character) == "Cs" for character in value)
    ):
        _invalid()
    return value


def _integer(value: Any, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _invalid()
    return value


def _closed_object(value: Any, required: Iterable[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(required):
        _invalid()
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _canonical_path(value: Any) -> str:
    candidate = _string(value)
    try:
        path = PurePosixPath(candidate)
    except (TypeError, ValueError):
        _invalid()
    if (
        not path.is_absolute()
        or candidate == "/"
        or candidate.endswith("/")
        or str(path) != candidate
        or any(part in (".", "..") for part in path.parts)
    ):
        _invalid()
    return candidate


def _https_url(value: Any, *, callback: bool) -> str:
    candidate = _string(value, maximum=512)
    if not candidate.isascii():
        _invalid()
    try:
        split = urlsplit(candidate)
        port = split.port
    except ValueError:
        _invalid()
    if (
        split.scheme != "https"
        or split.username is not None
        or split.password is not None
        or not split.hostname
        or split.hostname != split.hostname.lower()
        or _DNS_NAME.fullmatch(split.hostname) is None
        or port is not None
        or split.netloc != split.hostname
        or split.query
        or split.fragment
        or any(token in split.path for token in ("%", "\\", "//", "/./", "/../"))
    ):
        _invalid()
    if callback:
        if split.path != "/v1/auth/oidc/callback":
            _invalid()
    elif candidate.endswith("/"):
        _invalid()
    return candidate


def _canonical_global_public_ipv4(value: Any) -> str:
    candidate = _string(value, maximum=15)
    if not candidate.isascii():
        _invalid()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        _invalid()
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or str(address) != candidate
        or not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        _invalid()
    return candidate


def _real_oidc_hostname(value: str) -> None:
    if (
        _DNS_NAME.fullmatch(value) is None
        or "." not in value
        or not any(character.isalpha() for character in value.rsplit(".", 1)[-1])
        or value.endswith((".test", ".localhost", ".local", ".invalid"))
    ):
        _invalid()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    _invalid()


@dataclass(frozen=True)
class InternalSandboxOidcNetworkBinding:
    mode: str
    pinned_public_ipv4: Optional[str]

    def __post_init__(self) -> None:
        try:
            mode = _string(self.mode, maximum=32)
            if mode == OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC:
                if self.pinned_public_ipv4 is not None:
                    _invalid()
            elif mode == OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP:
                _canonical_global_public_ipv4(self.pinned_public_ipv4)
            else:
                _invalid()
        except _InvalidConfiguration:
            raise ValueError(
                "internal sandbox OIDC network binding is invalid"
            ) from None


@dataclass(frozen=True)
class InternalSandboxOidcSettings:
    issuer: str
    client_id: str
    client_secret_key_id: str
    redirect_uri: str
    allowed_signing_algorithms: Tuple[str, ...]
    metadata_ttl_seconds: int
    request_timeout_seconds: int
    maximum_response_bytes: int
    clock_skew_seconds: int
    subject_digest_key_id: str
    network_binding: InternalSandboxOidcNetworkBinding

    def __post_init__(self) -> None:
        try:
            _https_url(self.issuer, callback=False)
            _https_url(self.redirect_uri, callback=True)
            if _OPAQUE.fullmatch(_string(self.client_id, maximum=128)) is None:
                _invalid()
            for key_id in (self.client_secret_key_id, self.subject_digest_key_id):
                if _KEY_ID.fullmatch(_string(key_id, maximum=63)) is None:
                    _invalid()
            if self.client_secret_key_id == self.subject_digest_key_id:
                _invalid()
            algorithms = self.allowed_signing_algorithms
            if (
                not isinstance(algorithms, tuple)
                or not 1 <= len(algorithms) <= 2
                or len(set(algorithms)) != len(algorithms)
                or any(value not in _REVIEWED_ALGORITHMS for value in algorithms)
                or tuple(sorted(algorithms)) != algorithms
            ):
                _invalid()
            _integer(self.metadata_ttl_seconds, minimum=60, maximum=3_600)
            _integer(self.request_timeout_seconds, minimum=1, maximum=10)
            _integer(
                self.maximum_response_bytes,
                minimum=65_536,
                maximum=1_048_576,
            )
            _integer(self.clock_skew_seconds, minimum=0, maximum=300)
            if not isinstance(
                self.network_binding, InternalSandboxOidcNetworkBinding
            ):
                _invalid()
            issuer_hostname = urlsplit(self.issuer).hostname
            if not isinstance(issuer_hostname, str):
                _invalid()
            is_synthetic_test_issuer = issuer_hostname.endswith(".test")
            if self.network_binding.mode == OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC:
                if not is_synthetic_test_issuer:
                    _invalid()
            elif self.network_binding.mode == OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP:
                if is_synthetic_test_issuer:
                    _invalid()
                _real_oidc_hostname(issuer_hostname)
            else:
                _invalid()
        except _InvalidConfiguration:
            raise ValueError("internal sandbox OIDC settings are invalid") from None


@dataclass(frozen=True)
class InternalSandboxBindSettings:
    host: str
    port: int

    def __post_init__(self) -> None:
        # The Docker BFF authority is deliberately frozen to api:8000.  A
        # configurable listener could otherwise pass readiness while being
        # unreachable from that one reviewed internal hop.
        if self.host != "0.0.0.0" or self.port != 8_000:
            raise ValueError("internal sandbox bind authority is invalid")


@dataclass(frozen=True)
class InternalSandboxDeploymentConfiguration:
    schema_name: str
    deployment_mode: str
    external_participants_enabled: bool
    internal_bff_origin: str
    runtime_config_path: str
    secret_manifest_path: str
    secret_root: str
    postgres: PostgresEndpointSettings
    oidc: InternalSandboxOidcSettings
    system_actor_id: UUID
    bind: InternalSandboxBindSettings

    def __post_init__(self) -> None:
        try:
            if (
                self.schema_name != "desire-internal-sandbox-deployment-v1"
                or self.deployment_mode != "INTERNAL_SANDBOX"
                or self.external_participants_enabled is not False
                or self.internal_bff_origin != "http://api:8000"
            ):
                _invalid()
            runtime_path = _canonical_path(self.runtime_config_path)
            manifest_path = _canonical_path(self.secret_manifest_path)
            secret_root = _canonical_path(self.secret_root)
            root = PurePosixPath(secret_root)
            if (
                runtime_path == manifest_path
                or root in PurePosixPath(runtime_path).parents
                or root in PurePosixPath(manifest_path).parents
            ):
                _invalid()
            if not isinstance(self.postgres, PostgresEndpointSettings):
                _invalid()
            if not isinstance(self.oidc, InternalSandboxOidcSettings):
                _invalid()
            if (
                not isinstance(self.system_actor_id, UUID)
                or self.system_actor_id.int == 0
            ):
                _invalid()
            if not isinstance(self.bind, InternalSandboxBindSettings):
                _invalid()
        except _InvalidConfiguration:
            raise ValueError("internal sandbox deployment facts are invalid") from None


def _uuid(value: Any) -> UUID:
    candidate = _string(value, maximum=36)
    try:
        parsed = UUID(candidate)
    except (ValueError, AttributeError):
        _invalid()
    if parsed.int == 0 or str(parsed) != candidate:
        _invalid()
    return parsed


def parse_internal_sandbox_deployment_config(
    raw: bytes,
) -> InternalSandboxDeploymentConfiguration:
    """Parse explicit UTF-8 bytes without consulting environment or cwd."""

    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAXIMUM_CONFIG_BYTES:
            _invalid()
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=_invalid,
            parse_constant=_invalid,
        )
        root = _closed_object(
            document,
            (
                "schema_name",
                "deployment_mode",
                "external_participants_enabled",
                "internal_bff_origin",
                "runtime_config_path",
                "secret_manifest_path",
                "secret_root",
                "postgres",
                "oidc",
                "system_actor_id",
                "bind",
            ),
        )
        postgres = _closed_object(
            root["postgres"],
            ("host", "port", "database", "transport_security"),
        )
        oidc = _closed_object(
            root["oidc"],
            (
                "issuer",
                "client_id",
                "client_secret_key_id",
                "redirect_uri",
                "allowed_signing_algorithms",
                "metadata_ttl_seconds",
                "request_timeout_seconds",
                "maximum_response_bytes",
                "clock_skew_seconds",
                "subject_digest_key_id",
                "network_binding",
            ),
        )
        network_binding = _closed_object(
            oidc["network_binding"],
            ("mode", "pinned_public_ipv4"),
        )
        algorithms = oidc["allowed_signing_algorithms"]
        if not isinstance(algorithms, list):
            _invalid()
        bind = _closed_object(root["bind"], ("host", "port"))
        return InternalSandboxDeploymentConfiguration(
            schema_name=root["schema_name"],
            deployment_mode=root["deployment_mode"],
            external_participants_enabled=root["external_participants_enabled"],
            internal_bff_origin=root["internal_bff_origin"],
            runtime_config_path=_canonical_path(root["runtime_config_path"]),
            secret_manifest_path=_canonical_path(root["secret_manifest_path"]),
            secret_root=_canonical_path(root["secret_root"]),
            postgres=PostgresEndpointSettings(
                host=postgres["host"],
                port=postgres["port"],
                database=postgres["database"],
                transport_security=postgres["transport_security"],
            ),
            oidc=InternalSandboxOidcSettings(
                issuer=oidc["issuer"],
                client_id=oidc["client_id"],
                client_secret_key_id=oidc["client_secret_key_id"],
                redirect_uri=oidc["redirect_uri"],
                allowed_signing_algorithms=tuple(algorithms),
                metadata_ttl_seconds=oidc["metadata_ttl_seconds"],
                request_timeout_seconds=oidc["request_timeout_seconds"],
                maximum_response_bytes=oidc["maximum_response_bytes"],
                clock_skew_seconds=oidc["clock_skew_seconds"],
                subject_digest_key_id=oidc["subject_digest_key_id"],
                network_binding=InternalSandboxOidcNetworkBinding(
                    mode=network_binding["mode"],
                    pinned_public_ipv4=network_binding["pinned_public_ipv4"],
                ),
            ),
            system_actor_id=_uuid(root["system_actor_id"]),
            bind=InternalSandboxBindSettings(
                host=bind["host"],
                port=bind["port"],
            ),
        )
    except _InvalidConfiguration:
        raise InternalSandboxDeploymentConfigError() from None
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise InternalSandboxDeploymentConfigError() from None


def _read_regular_config_file(path: str) -> bytes:
    try:
        candidate = Path(path)
        if str(candidate.resolve(strict=True)) != path:
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= _MAXIMUM_CONFIG_BYTES
            ):
                raise OSError
            chunks = []
            remaining = _MAXIMUM_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) != metadata.st_size:
                raise OSError
            return raw
        finally:
            os.close(descriptor)
    except OSError:
        raise InternalSandboxDeploymentConfigError() from None


def load_internal_sandbox_deployment_config_pointer(
    *,
    environment: Mapping[str, str],
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> InternalSandboxDeploymentConfiguration:
    """Load through the process's one allowed ``DESIRE_*`` environment fact."""

    try:
        if not isinstance(environment, Mapping):
            _invalid()
        desire_keys = tuple(
            sorted(
                key
                for key in environment
                if isinstance(key, str) and key.startswith("DESIRE_")
            )
        )
        if desire_keys != (DEPLOYMENT_CONFIG_POINTER_ENV,):
            _invalid()
        path = _canonical_path(environment.get(DEPLOYMENT_CONFIG_POINTER_ENV))
        pointer = PurePosixPath(path)
        if PurePosixPath("/run/secrets") in pointer.parents:
            _invalid()
        reader = _read_regular_config_file if read_bytes is None else read_bytes
        if not callable(reader):
            _invalid()
        raw = reader(path)
        if type(raw) is not bytes:
            _invalid()
        config = parse_internal_sandbox_deployment_config(raw)
        if PurePosixPath(config.secret_root) in pointer.parents:
            _invalid()
        return config
    except InternalSandboxDeploymentConfigError:
        raise
    except _InvalidConfiguration:
        raise InternalSandboxDeploymentConfigError() from None
    except BaseException:
        raise InternalSandboxDeploymentConfigError() from None


__all__ = [
    "DEPLOYMENT_CONFIG_POINTER_ENV",
    "InternalSandboxBindSettings",
    "InternalSandboxDeploymentConfigError",
    "InternalSandboxDeploymentConfiguration",
    "InternalSandboxOidcSettings",
    "InternalSandboxOidcNetworkBinding",
    "OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP",
    "OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC",
    "load_internal_sandbox_deployment_config_pointer",
    "parse_internal_sandbox_deployment_config",
]
