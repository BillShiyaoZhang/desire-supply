#!/usr/bin/env python3
"""Fail-closed static contract for the private-server real-OIDC overlay.

This validator does not activate a deployment.  It closes one fully resolved
Compose JSON document against separately reviewed, non-secret deployment
facts and the external input paths that produced that document.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Dict, Iterable, Mapping, NoReturn, Optional, Sequence, Tuple
from urllib.parse import urlsplit


_MAX_COMPOSE_BYTES = 4 * 1024 * 1024
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_SECRET_BYTES = 4 * 1024
_MAX_TLS_BYTES = 1024 * 1024
_TEMPLATE_SHA256 = (
    "b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942"
)
_SYSTEM_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
_EGRESS_GUARD_ENTRYPOINT = "/usr/local/bin/desire-real-oidc-egress-guard"
_EGRESS_PROJECTION_SCHEMA = "desire-real-oidc-egress-projection-v1"
_POSTGRES_IMAGE = (
    "postgres:18.4-alpine@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
_BOUNDED_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_PROJECT = re.compile(
    r"desire-real-oidc-(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,38}[a-z0-9])\Z"
)
_DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z"
)
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IMAGE_TAG = re.compile(
    r"sha-[0-9a-f]{40}-(?:amd64|arm64)-r[1-9][0-9]*-a[1-9][0-9]*\Z"
)
_SERVICE_NAMES = frozenset(
    (
        "api",
        "db",
        "edge",
        "identity-bootstrap",
        "matching-runtime",
        "migrate",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "oidc-egress-guard",
        "taxonomy-seed",
        "web",
    )
)
_NETWORK_NAMES = frozenset(("app", "data", "ingress", "oidc-egress"))
_CONFIG_NAMES = frozenset(
    (
        "internal-sandbox-deployment",
        "internal-sandbox-identity-template",
        "internal-sandbox-runtime-config",
        "internal-sandbox-secret-manifest",
        "internal-sandbox-matching-deployment",
        "internal-sandbox-matching-runtime-config",
        "internal-sandbox-matching-secret-manifest",
        "internal-sandbox-online-credentials-deployment",
        "internal-sandbox-online-credentials-runtime-config",
        "internal-sandbox-online-credentials-secret-manifest",
        "real-oidc-caddyfile",
        "real-oidc-edge-tls-chain",
    )
)
_API_SECRET_ORDER = (
        "db-demand-finance-v1",
        "db-demand-review-v1",
        "db-demand-self-v1",
        "db-iam-app-v1",
        "db-iam-onboarding-v1",
        "db-iam-session-authenticator-v1",
        "db-matching-creator-v1",
        "db-matching-selector-v1",
        "db-matching-assignment-v1",
        "db-matching-review-v1",
        "db-profile-app-v1",
        "db-trust-appeal-v1",
        "db-trust-decision-v1",
        "db-trust-officer-v1",
        "db-trust-self-v1",
        "key-access-invitation-token-v1",
        "key-csrf-v1",
        "key-demand-client-reference-v1",
        "key-demand-idempotency-retained-2025-12",
        "key-demand-idempotency-v1",
        "key-demand-payload-hash-v1",
        "key-demand-payload-retained-2025-12",
        "key-editor-id-derivation-v1",
        "key-iam-read-cursor-v1",
        "key-iam-receipt-idempotency-hmac-2026-01",
        "key-iam-receipt-payload-hmac-2026-01",
        "key-matching-idempotency-v1",
        "key-matching-payload-v1",
        "key-matching-read-cursor-v1",
        "key-oidc-browser-binding-v1",
        "key-oidc-client-secret-v1",
        "key-oidc-nonce-v1",
        "key-oidc-protocol-aead-v1",
        "key-oidc-recipient-binding-v1",
        "key-oidc-state-v1",
        "key-oidc-subject-digest-v1",
        "key-profile-idempotency-v1",
        "key-profile-payload-hash-v1",
        "key-session-handle-v1",
        "key-trust-idempotency-v1",
        "key-trust-payload-hash-v1",
        "key-trust-sealed-note-v1",
        "key-trust-report-cursor-v1",
)
_MATCHING_RUNTIME_SECRET_ORDER = (
    "db-demand-matching-v1",
    "db-profile-matcher-v1",
    "db-trust-decision-v1",
    "db-matching-worker-v1",
    "db-matching-coordinator-v1",
    "key-matching-worker-idempotency-v1",
    "key-matching-worker-payload-hash-v1",
    "key-matching-worker-lease-digest-v1",
    "key-matching-coordinator-idempotency-v1",
    "key-matching-coordinator-payload-hash-v1",
    "key-matching-coordinator-lease-digest-v1",
)
_BUNDLE_SECRET_ORDER = tuple(
    sorted(set(_API_SECRET_ORDER) | set(_MATCHING_RUNTIME_SECRET_ORDER))
)
_BUNDLE_SECRET_NAMES = frozenset(_BUNDLE_SECRET_ORDER)
_SECRET_NAMES = _BUNDLE_SECRET_NAMES | frozenset(
    (
        "db_superuser_password",
        "edge-tls-key",
        "taxonomy_seed_receipt_hmac_key",
        "taxonomy_seed_workload_credential",
    )
)
_IDENTITY_SOURCE_NAMES = frozenset(
    name
    for slug in (
        "access_admin_01",
        "appeal_reviewer_01",
        "creator_01",
        "demand_owner_01",
        "finance_operator_01",
        "finance_operator_02",
        "operations_reviewer_01",
        "org_admin_01",
        "trust_officer_01",
        "trust_officer_02",
    )
    for name in (slug + ".subject", slug + ".email")
)
_ADMIN_ENVIRONMENT = {
    "DESIRE_DATABASE_ADMIN_USER": "postgres",
    "DESIRE_DATABASE_HOST": "db",
    "DESIRE_DATABASE_NAME": "desire",
    "DESIRE_DATABASE_PASSWORD_FILE": "/run/secrets/db_superuser_password",
    "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
    "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
}
_RUNTIME_CONFIG_ATTACHMENTS = (
    ("internal-sandbox-deployment", "/run/desire/deployment.json", "0444"),
    ("internal-sandbox-runtime-config", "/run/desire/runtime-config.json", "0444"),
    ("internal-sandbox-secret-manifest", "/run/desire/secret-manifest.json", "0444"),
)
_MATCHING_RUNTIME_CONFIG_ATTACHMENTS = (
    (
        "internal-sandbox-matching-deployment",
        "/run/desire/matching-deployment.json",
        "0444",
    ),
    (
        "internal-sandbox-matching-runtime-config",
        "/run/desire/matching-runtime-config.json",
        "0444",
    ),
    (
        "internal-sandbox-matching-secret-manifest",
        "/run/desire/matching-secret-manifest.json",
        "0444",
    ),
)
_ONLINE_CREDENTIAL_CONFIG_ATTACHMENTS = (
    (
        "internal-sandbox-online-credentials-deployment",
        "/run/desire/online-credentials-deployment.json",
        "0444",
    ),
    (
        "internal-sandbox-online-credentials-runtime-config",
        "/run/desire/online-credentials-runtime-config.json",
        "0444",
    ),
    (
        "internal-sandbox-online-credentials-secret-manifest",
        "/run/desire/online-credentials-secret-manifest.json",
        "0444",
    ),
)
_EXPECTED_CADDYFILE = b'''{
\tadmin off
\tauto_https disable_redirects
\tpersist_config off
}

:8080 {
\t@edge_health path /_edge/health
\trespond @edge_health `{ "status": "LIVE" }` 200
}

https://{$DESIRE_REAL_OIDC_PILOT_HOSTNAME} {
\ttls /run/desire-tls/edge-tls-chain.pem /run/secrets/edge-tls-key.pem

\theader {
\t\t-Server
\t\tX-Content-Type-Options "nosniff"
\t\tReferrer-Policy "same-origin"
\t\tX-Frame-Options "DENY"
\t\tStrict-Transport-Security "max-age=31536000"
\t\tPermissions-Policy "camera=(), geolocation=(), microphone=()"
\t}

\treverse_proxy web:3000 {
\t\theader_up -Forwarded
\t\theader_up Host {$DESIRE_REAL_OIDC_PILOT_HOSTNAME}
\t\theader_up X-Forwarded-Host {$DESIRE_REAL_OIDC_PILOT_HOSTNAME}
\t\theader_up X-Forwarded-Proto https
\t}
}
'''


class PrivateServerRealOidcComposeContractError(RuntimeError):
    """Stable, non-reflective validation failure."""

    def __init__(self) -> None:
        self.code = "PRIVATE_SERVER_REAL_OIDC_COMPOSE_INVALID"
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class ReviewedRealOidcInputs:
    project_name: str
    pilot_hostname: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_pinned_public_ipv4: str
    db_data_ipv4: str
    image_tag: str
    bundle_dir: str
    identity_source_dir: str
    tls_dir: str
    ingress_ip: str


def _invalid() -> NoReturn:
    raise PrivateServerRealOidcComposeContractError()


def _pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            _invalid()
        result[key] = value
    return result


def _parse_json(raw: bytes, *, maximum: int) -> Mapping[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= maximum:
            _invalid()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: _invalid(),
            parse_constant=lambda _value: _invalid(),
        )
    except PrivateServerRealOidcComposeContractError:
        raise
    except BaseException:
        _invalid()
    if not isinstance(value, dict):
        _invalid()
    return value


def _closed(value: Any, keys: Iterable[str]) -> Mapping[str, Any]:
    expected = frozenset(keys)
    if not isinstance(value, dict) or frozenset(value) != expected:
        _invalid()
    return value


def _dns_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or value != value.strip()
        or len(value) > 253
        or _DNS_NAME.fullmatch(value) is None
        or not any(character.isalpha() for character in value.rsplit(".", 1)[-1])
        or value.endswith((".test", ".localhost", ".local", ".invalid"))
    ):
        _invalid()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _invalid()
    return value


def _issuer(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii() or len(value) > 512:
        _invalid()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        _invalid()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or parsed.netloc != parsed.hostname
        or port is not None
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
        or any(token in parsed.path for token in ("%", "\\", "//", "/./", "/../"))
    ):
        _invalid()
    _dns_name(parsed.hostname)
    return value


def _global_public_ipv4(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        _invalid()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _invalid()
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_global
        or str(address) != value
    ):
        _invalid()
    return value


def _rfc1918_ipv4(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        _invalid()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _invalid()
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or str(address) != value
        or not any(address in network for network in _RFC1918)
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    ):
        _invalid()
    return value


def oidc_egress_projection_bytes(
    db_data_ipv4: Any, oidc_pinned_public_ipv4: Any
) -> bytes:
    """Return the byte-exact non-secret namespace-firewall descriptor."""

    database = _rfc1918_ipv4(db_data_ipv4)
    provider = _global_public_ipv4(oidc_pinned_public_ipv4)
    descriptor = {
        "database": {"ipv4": database, "port": 5432, "verdict": "ALLOW"},
        "dns": {"tcp_port": 53, "udp_port": 53, "verdict": "REJECT"},
        "established_related": "ALLOW",
        "ipv4_other": "REJECT",
        "ipv6": "REJECT",
        "loopback": "ALLOW",
        "oidc": {"ipv4": provider, "port": 443, "verdict": "ALLOW"},
        "output_policy": "DROP",
        "schema": _EGRESS_PROJECTION_SCHEMA,
    }
    return (
        json.dumps(
            descriptor,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def oidc_egress_projection_sha256(
    db_data_ipv4: Any, oidc_pinned_public_ipv4: Any
) -> str:
    return hashlib.sha256(
        oidc_egress_projection_bytes(db_data_ipv4, oidc_pinned_public_ipv4)
    ).hexdigest()


def _canonical_existing_path(
    value: Any, *, directory: bool, maximum_bytes: Optional[int] = None
) -> Path:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not 1 <= len(value) <= 4096
        or value != value.strip()
        or "\x00" in value
    ):
        _invalid()
    path = Path(value)
    if not path.is_absolute() or str(path) != value or value == "/":
        _invalid()
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except (OSError, RuntimeError):
        _invalid()
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        _invalid()
    if directory:
        if not stat.S_ISDIR(metadata.st_mode):
            _invalid()
    else:
        if not stat.S_ISREG(metadata.st_mode):
            _invalid()
        if (
            metadata.st_nlink != 1
            or maximum_bytes is None
            or not 0 < metadata.st_size <= maximum_bytes
        ):
            _invalid()
    return path


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _closed_directory(path: Path, *, expected_mode: Optional[int] = None) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        _invalid()
    if (
        path.resolve(strict=True) != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
        or (
            expected_mode is not None
            and stat.S_IMODE(metadata.st_mode) != expected_mode
        )
    ):
        _invalid()


def _closed_descendant_ancestry(path: Path, *, root: Path) -> None:
    if not _within(path, root) or path == root:
        _invalid()
    current = path.parent
    while True:
        _closed_directory(current, expected_mode=0o555)
        if current == root:
            return
        if current == current.parent or not _within(current, root):
            _invalid()
        current = current.parent


def _require_distinct_files(paths: Iterable[Path]) -> None:
    observed_paths = []
    observed_inodes = []
    for path in paths:
        try:
            metadata = path.stat()
        except OSError:
            _invalid()
        observed_paths.append(str(path))
        observed_inodes.append((metadata.st_dev, metadata.st_ino))
    if (
        len(observed_paths) != len(set(observed_paths))
        or len(observed_inodes) != len(set(observed_inodes))
    ):
        _invalid()


def _require_exact_directory_entries(path: Path, names: Iterable[str]) -> None:
    try:
        entries = tuple(os.scandir(str(path)))
    except OSError:
        _invalid()
    if frozenset(entry.name for entry in entries) != frozenset(names):
        _invalid()
    if any(entry.is_symlink() for entry in entries):
        _invalid()


def _require_external_directory(value: str, *, repository: Path) -> Path:
    path = _canonical_existing_path(value, directory=True)
    _closed_directory(path, expected_mode=0o555)
    _closed_directory(path.parent, expected_mode=0o700)
    if _within(path, repository) or _within(repository, path):
        _invalid()
    return path


def _logical_file(
    value: Any,
    *,
    project: str,
    logical_name: str,
    expected_path: Path,
    maximum_bytes: int,
    mounted_mode: Optional[int] = None,
) -> None:
    item = _closed(value, ("name", "file"))
    if item["name"] != project + "_" + logical_name:
        _invalid()
    observed = _canonical_existing_path(
        item["file"], directory=False, maximum_bytes=maximum_bytes
    )
    if observed != expected_path:
        _invalid()
    if (
        mounted_mode is not None
        and stat.S_IMODE(observed.stat().st_mode) != mounted_mode
    ):
        _invalid()


def _inventory_identity_sources(root: Path) -> None:
    try:
        root_metadata = root.stat()
        parent_metadata = root.parent.stat()
    except OSError:
        _invalid()
    try:
        entries = tuple(os.scandir(str(root)))
    except OSError:
        _invalid()
    if (
        stat.S_IMODE(root_metadata.st_mode) != 0o555
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or frozenset(entry.name for entry in entries) != _IDENTITY_SOURCE_NAMES
    ):
        _invalid()
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError:
            _invalid()
        if (
            entry.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= 512
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or Path(entry.path).resolve(strict=True) != Path(entry.path)
        ):
            _invalid()


def _validate_deployment(
    raw: bytes,
    *,
    reviewed: ReviewedRealOidcInputs,
    expected_runtime_config_path: str,
    expected_secret_manifest_path: str,
) -> None:
    root = _closed(
        _parse_json(raw, maximum=256 * 1024),
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
    postgres = _closed(
        root["postgres"], ("host", "port", "database", "transport_security")
    )
    bind = _closed(root["bind"], ("host", "port"))
    oidc = _closed(
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
    network_binding = _closed(
        oidc["network_binding"], ("mode", "pinned_public_ipv4")
    )
    expected_redirect = (
        "https://" + reviewed.pilot_hostname + "/v1/auth/oidc/callback"
    )
    algorithms = oidc["allowed_signing_algorithms"]
    if (
        root["schema_name"] != "desire-internal-sandbox-deployment-v1"
        or root["deployment_mode"] != "INTERNAL_SANDBOX"
        or root["external_participants_enabled"] is not False
        or root["internal_bff_origin"] != "http://api:8000"
        or root["runtime_config_path"] != expected_runtime_config_path
        or root["secret_manifest_path"] != expected_secret_manifest_path
        or root["secret_root"] != "/run/secrets"
        or root["system_actor_id"]
        != "10000000-0000-4000-8000-000000000001"
        or postgres
        != {
            "host": "db",
            "port": 5432,
            "database": "desire",
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        }
        or bind != {"host": "0.0.0.0", "port": 8000}
        or oidc["issuer"] != reviewed.oidc_issuer
        or oidc["client_id"] != reviewed.oidc_client_id
        or oidc["client_secret_key_id"] != "oidc-client-secret-v1"
        or oidc["redirect_uri"] != expected_redirect
        or oidc["subject_digest_key_id"] != "oidc-subject-digest-v1"
        or network_binding
        != {
            "mode": "PINNED_PUBLIC_IP",
            "pinned_public_ipv4": reviewed.oidc_pinned_public_ipv4,
        }
        or not isinstance(algorithms, list)
        or not 1 <= len(algorithms) <= 2
        or algorithms != sorted(set(algorithms))
        or not set(algorithms).issubset({"ES256", "RS256"})
        or type(oidc["metadata_ttl_seconds"]) is not int
        or not 60 <= oidc["metadata_ttl_seconds"] <= 3600
        or type(oidc["request_timeout_seconds"]) is not int
        or not 1 <= oidc["request_timeout_seconds"] <= 10
        or type(oidc["maximum_response_bytes"]) is not int
        or not 65536 <= oidc["maximum_response_bytes"] <= 1048576
        or type(oidc["clock_skew_seconds"]) is not int
        or not 0 <= oidc["clock_skew_seconds"] <= 300
    ):
        _invalid()
    if urlsplit(reviewed.oidc_issuer).hostname == reviewed.pilot_hostname:
        _invalid()


def _environment(service: Mapping[str, Any], expected: Mapping[str, str]) -> None:
    if service.get("environment") != dict(expected):
        _invalid()


def _attachments(value: Any) -> Tuple[Tuple[str, str, str], ...]:
    if not isinstance(value, list):
        _invalid()
    result = []
    for item in value:
        closed = _closed(item, ("source", "target", "mode"))
        if not all(isinstance(closed[key], str) for key in closed):
            _invalid()
        result.append((closed["source"], closed["target"], closed["mode"]))
    return tuple(result)


def _secret_sources(value: Any) -> frozenset:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        _invalid()
    sources = []
    for item in value:
        if not isinstance(item, dict):
            _invalid()
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            _invalid()
        sources.append(source)
    if len(sources) != len(set(sources)):
        _invalid()
    return frozenset(sources)


def _secret_map(value: Any) -> Mapping[str, Mapping[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, list):
        _invalid()
    result: Dict[str, Mapping[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            _invalid()
        source = item.get("source")
        target = item.get("target")
        if (
            not isinstance(source, str)
            or not isinstance(target, str)
            or source in result
            or frozenset(item)
            - frozenset(("source", "target", "uid", "gid", "mode"))
        ):
            _invalid()
        result[source] = item
    return result


def _plain_secret(source: str, target: str) -> Mapping[str, Any]:
    return {"source": source, "target": target}


def _named_secret_map(names: Iterable[str]) -> Mapping[str, Mapping[str, Any]]:
    return {name: _plain_secret(name, name) for name in names}


def _networks(service: Mapping[str, Any]) -> frozenset:
    value = service.get("networks")
    if not isinstance(value, dict) or any(item not in (None, {}) for item in value.values()):
        _invalid()
    return frozenset(value)


def _network_bindings(service: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    value = service.get("networks")
    if value is None:
        return {}
    if not isinstance(value, dict):
        _invalid()
    result = {}
    for name, item in value.items():
        if item is None or item == {}:
            result[name] = {}
        elif isinstance(item, dict):
            result[name] = item
        else:
            _invalid()
    return result


def _depends(service: Mapping[str, Any]) -> Dict[str, str]:
    value = service.get("depends_on")
    if value is None:
        return {}
    if not isinstance(value, dict):
        _invalid()
    result = {}
    for name, item in value.items():
        if not isinstance(item, dict) or item.get("required") is not True:
            _invalid()
        if frozenset(item) != frozenset(("condition", "required")):
            _invalid()
        condition = item.get("condition")
        if not isinstance(condition, str):
            _invalid()
        result[name] = condition
    return result


def _validate_networks(
    value: Any,
    *,
    db_data_ipv4: ipaddress.IPv4Address,
    ingress_ip: ipaddress.IPv4Address,
    project_name: str,
) -> None:
    if not isinstance(value, dict) or frozenset(value) != _NETWORK_NAMES:
        _invalid()
    subnets = []
    for name, network in value.items():
        if not isinstance(network, dict):
            _invalid()
        expected_keys = {"name", "ipam"}
        if name in ("app", "data"):
            expected_keys.add("internal")
        if frozenset(network) != frozenset(expected_keys):
            _invalid()
        if network.get("name") != project_name + "_" + name:
            _invalid()
        if network.get("internal", False) is not (name in ("app", "data")):
            _invalid()
        ipam = network.get("ipam")
        if not isinstance(ipam, dict) or frozenset(ipam) != frozenset(("config",)):
            _invalid()
        configs = ipam["config"]
        if not isinstance(configs, list) or len(configs) != 1:
            _invalid()
        item = _closed(configs[0], ("subnet",))
        try:
            subnet = ipaddress.ip_network(item["subnet"], strict=True)
        except (TypeError, ValueError):
            _invalid()
        if (
            not isinstance(subnet, ipaddress.IPv4Network)
            or subnet.prefixlen != 24
            or not any(subnet.subnet_of(parent) for parent in _RFC1918)
        ):
            _invalid()
        subnets.append((name, subnet))
    if any(left.overlaps(right) for index, (_, left) in enumerate(subnets) for _, right in subnets[index + 1 :]):
        _invalid()
    if any(ingress_ip in subnet for _, subnet in subnets):
        _invalid()
    data_subnet = dict(subnets)["data"]
    if (
        db_data_ipv4 not in data_subnet
        or db_data_ipv4 == data_subnet.network_address
        or db_data_ipv4 == data_subnet.network_address + 1
        or db_data_ipv4 == data_subnet.broadcast_address
    ):
        _invalid()


def _validate_unsafe_features(
    services: Mapping[str, Mapping[str, Any]], *, db_data_ipv4: str
) -> None:
    for name, service in services.items():
        expected_cap_add = ["NET_ADMIN"] if name == "oidc-egress-guard" else None
        expected_network_mode = (
            "service:oidc-egress-guard" if name == "api" else None
        )
        expected_extra_hosts = ["db=" + db_data_ipv4] if name == "api" else None
        if (
            service.get("privileged", False) is not False
            or service.get("cap_add") != expected_cap_add
            or service.get("devices") not in (None, [])
            or service.get("device_cgroup_rules") not in (None, [])
            or service.get("network_mode") != expected_network_mode
            or service.get("pid") not in (None, "")
            or service.get("ipc") not in (None, "")
            or service.get("uts") not in (None, "")
            or service.get("extra_hosts") != expected_extra_hosts
            or service.get("userns_mode") not in (None, "")
            or service.get("labels") not in (None, {})
            or service.get("annotations") not in (None, {})
            or service.get("env_file") not in (None, [])
            or service.get("links") not in (None, [])
            or service.get("external_links") not in (None, [])
        ):
            _invalid()
        ports = service.get("ports")
        if name != "edge" and ports not in (None, []):
            _invalid()
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            _invalid()
        for volume in volumes:
            if not isinstance(volume, dict):
                _invalid()
            source = volume.get("source", "")
            target = volume.get("target", "")
            combined = str(source) + "\x00" + str(target)
            if "docker.sock" in combined or "/dev/" in combined:
                _invalid()


def _validate_hardening(services: Mapping[str, Mapping[str, Any]]) -> None:
    ordinary_tmpfs = ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
    for name, service in services.items():
        if name == "db":
            if (
                service.get("restart") != "unless-stopped"
                or service.get("tmpfs")
                != ["/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"]
            ):
                _invalid()
            continue
        expected_tmpfs = list(ordinary_tmpfs)
        if name == "oidc-egress-guard":
            expected_tmpfs = [
                "/run/desire-oidc-egress:rw,noexec,nosuid,nodev,size=64k,mode=0700"
            ]
        if name == "identity-bootstrap":
            expected_tmpfs.append(
                "/run/identity-bootstrap:rw,noexec,nosuid,nodev,size=1m,"
                "uid=10001,gid=10001,mode=0700"
            )
        if name == "matching-runtime":
            expected_tmpfs.append(
                "/run/matching-runtime:rw,noexec,nosuid,nodev,size=64k,"
                "uid=10001,gid=10001,mode=0700"
            )
        expected_restart = (
            "unless-stopped" if name == "matching-runtime" else "no"
        )
        if (
            service.get("read_only") is not True
            or service.get("init") is not True
            or service.get("restart") != expected_restart
            or service.get("cap_drop") != ["ALL"]
            or service.get("security_opt") != ["no-new-privileges=true"]
            or service.get("tmpfs") != expected_tmpfs
        ):
            _invalid()


def _validate_volumes(
    services: Mapping[str, Mapping[str, Any]], *, identity_source: Path
) -> None:
    expected_identity = [
        {
            "type": "bind",
            "source": str(identity_source),
            "target": "/run/identity-sources",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    expected_db = [
        {
            "type": "volume",
            "source": "postgres-data",
            "target": "/var/lib/postgresql/data",
            "volume": {},
        }
    ]
    for name, service in services.items():
        observed = service.get("volumes")
        if name == "identity-bootstrap":
            if observed != expected_identity:
                _invalid()
        elif name == "db":
            if observed != expected_db:
                _invalid()
        elif observed not in (None, []):
            _invalid()


def _validate_secret_attachments(
    services: Mapping[str, Mapping[str, Any]]
) -> None:
    runtime = _named_secret_map(_API_SECRET_ORDER)
    matching_runtime = _named_secret_map(_MATCHING_RUNTIME_SECRET_ORDER)
    online_databases = {
        name: _plain_secret(name, name)
        for name in _BUNDLE_SECRET_ORDER
        if name.startswith("db-")
    }
    online_databases["db_superuser_password"] = _plain_secret(
        "db_superuser_password", "db_superuser_password"
    )
    db_admin = {
        "db_superuser_password": _plain_secret(
            "db_superuser_password", "/run/secrets/db_superuser_password"
        )
    }
    taxonomy = dict(db_admin)
    taxonomy.update(
        {
            "taxonomy_seed_receipt_hmac_key": _plain_secret(
                "taxonomy_seed_receipt_hmac_key",
                "/run/secrets/taxonomy_seed_receipt_hmac_key",
            ),
            "taxonomy_seed_workload_credential": _plain_secret(
                "taxonomy_seed_workload_credential",
                "/run/secrets/taxonomy_seed_workload_credential",
            ),
        }
    )
    identity = {
        "db_superuser_password": _plain_secret(
            "db_superuser_password", "db_superuser_password"
        ),
        "key-oidc-subject-digest-v1": _plain_secret(
            "key-oidc-subject-digest-v1", "key-oidc-subject-digest-v1"
        ),
        "key-oidc-recipient-binding-v1": _plain_secret(
            "key-oidc-recipient-binding-v1", "key-oidc-recipient-binding-v1"
        ),
    }
    edge = {
        "edge-tls-key": {
            "source": "edge-tls-key",
            "target": "/run/secrets/edge-tls-key.pem",
            "uid": "10001",
            "gid": "10001",
            "mode": "0400",
        }
    }
    expected = {
        "api": runtime,
        "db": db_admin,
        "edge": edge,
        "identity-bootstrap": identity,
        "migrate": db_admin,
        "matching-runtime": matching_runtime,
        "online-credentials-reconcile": online_databases,
        "online-credentials-verify": online_databases,
        "oidc-egress-guard": {},
        "taxonomy-seed": taxonomy,
        "web": {},
    }
    observed = {
        name: _secret_map(service.get("secrets"))
        for name, service in services.items()
    }
    if observed != expected:
        _invalid()


def _validate_services(
    value: Any,
    *,
    reviewed: ReviewedRealOidcInputs,
    identity_source: Path,
    ingress_ip: ipaddress.IPv4Address,
) -> None:
    if not isinstance(value, dict) or frozenset(value) != _SERVICE_NAMES:
        _invalid()
    services = value
    if not all(isinstance(service, dict) for service in services.values()):
        _invalid()
    expected_service_keys = {
        "api": frozenset(("build", "cap_drop", "command", "configs", "depends_on", "entrypoint", "environment", "extra_hosts", "healthcheck", "image", "init", "network_mode", "read_only", "restart", "secrets", "security_opt", "stop_grace_period", "tmpfs")),
        "db": frozenset(("command", "entrypoint", "environment", "healthcheck", "image", "networks", "restart", "secrets", "shm_size", "stop_grace_period", "tmpfs", "volumes")),
        "edge": frozenset(("build", "cap_drop", "command", "configs", "entrypoint", "environment", "healthcheck", "image", "init", "networks", "ports", "read_only", "restart", "secrets", "security_opt", "sysctls", "tmpfs")),
        "identity-bootstrap": frozenset(("cap_drop", "command", "configs", "depends_on", "entrypoint", "environment", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "tmpfs", "volumes")),
        "migrate": frozenset(("build", "cap_drop", "command", "depends_on", "entrypoint", "environment", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "tmpfs")),
        "matching-runtime": frozenset(("cap_drop", "command", "configs", "depends_on", "entrypoint", "environment", "healthcheck", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "stop_grace_period", "tmpfs")),
        "online-credentials-reconcile": frozenset(("cap_drop", "command", "configs", "depends_on", "entrypoint", "environment", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "tmpfs")),
        "online-credentials-verify": frozenset(("cap_drop", "command", "configs", "depends_on", "entrypoint", "environment", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "tmpfs")),
        "oidc-egress-guard": frozenset(("build", "cap_add", "cap_drop", "command", "entrypoint", "environment", "healthcheck", "image", "init", "networks", "read_only", "restart", "security_opt", "tmpfs", "user")),
        "taxonomy-seed": frozenset(("cap_drop", "command", "depends_on", "entrypoint", "environment", "image", "init", "networks", "read_only", "restart", "secrets", "security_opt", "tmpfs")),
        "web": frozenset(("build", "cap_drop", "command", "depends_on", "entrypoint", "environment", "healthcheck", "image", "init", "networks", "read_only", "restart", "security_opt", "tmpfs")),
    }
    expected_service_keys = {
        name: keys | frozenset(("logging",))
        for name, keys in expected_service_keys.items()
    }
    if {name: frozenset(service) for name, service in services.items()} != expected_service_keys:
        _invalid()
    if any(service.get("logging") != _BOUNDED_LOGGING for service in services.values()):
        _invalid()
    if any(
        service.get("entrypoint") is not None
        for name, service in services.items()
        if name != "oidc-egress-guard"
    ) or services["oidc-egress-guard"].get("entrypoint") != [
        _EGRESS_GUARD_ENTRYPOINT
    ]:
        _invalid()
    _validate_unsafe_features(services, db_data_ipv4=reviewed.db_data_ipv4)
    _validate_hardening(services)
    _validate_volumes(services, identity_source=identity_source)
    _validate_secret_attachments(services)
    expected_networks = {
        "api": {},
        "db": {"data": {"ipv4_address": reviewed.db_data_ipv4}},
        "edge": {"app": {}, "ingress": {}},
        "identity-bootstrap": {"data": {}},
        "migrate": {"data": {}},
        "matching-runtime": {"data": {}},
        "online-credentials-reconcile": {"data": {}},
        "online-credentials-verify": {"data": {}},
        "oidc-egress-guard": {
            "app": {"aliases": ["api"]},
            "data": {},
            "oidc-egress": {},
        },
        "taxonomy-seed": {"data": {}},
        "web": {"app": {}},
    }
    if {
        name: _network_bindings(service) for name, service in services.items()
    } != expected_networks:
        _invalid()
    expected_dependencies = {
        "api": {
            "identity-bootstrap": "service_completed_successfully",
            "oidc-egress-guard": "service_healthy",
        },
        "db": {},
        "edge": {},
        "identity-bootstrap": {"online-credentials-verify": "service_completed_successfully"},
        "migrate": {"db": "service_healthy"},
        "matching-runtime": {
            "identity-bootstrap": "service_completed_successfully"
        },
        "online-credentials-reconcile": {"taxonomy-seed": "service_completed_successfully"},
        "online-credentials-verify": {"online-credentials-reconcile": "service_completed_successfully"},
        "oidc-egress-guard": {},
        "taxonomy-seed": {"migrate": "service_completed_successfully"},
        "web": {"api": "service_healthy"},
    }
    if {name: _depends(service) for name, service in services.items()} != expected_dependencies:
        _invalid()

    admin = dict(_ADMIN_ENVIRONMENT)
    _environment(services["migrate"], admin)
    taxonomy_environment = dict(admin)
    taxonomy_environment.update(
        {
            "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE": "/run/secrets/taxonomy_seed_receipt_hmac_key",
            "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE": "/run/secrets/taxonomy_seed_workload_credential",
        }
    )
    _environment(services["taxonomy-seed"], taxonomy_environment)
    online_environment = dict(admin)
    online_environment["DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"] = "/run/desire/online-credentials-deployment.json"
    _environment(services["online-credentials-reconcile"], online_environment)
    _environment(services["online-credentials-verify"], online_environment)
    identity_environment = dict(admin)
    identity_environment["DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE"] = "/run/desire/deployment.json"
    identity_environment.update(
        {
            "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_OUTPUT_FILE": "/run/identity-bootstrap/manifest.json",
            "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_SOURCE_ROOT": "/run/identity-sources",
            "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_TEMPLATE_FILE": "/run/desire/identity-bootstrap-template.json",
            "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256": _TEMPLATE_SHA256,
        }
    )
    _environment(services["identity-bootstrap"], identity_environment)
    _environment(
        services["matching-runtime"],
        {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
                "/run/desire/matching-deployment.json"
            ),
            "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
                "/run/matching-runtime/healthy"
            ),
        },
    )
    _environment(
        services["api"],
        {
            "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": "/run/desire/deployment.json",
            "SSL_CERT_FILE": _SYSTEM_CA_FILE,
        },
    )
    _environment(
        services["oidc-egress-guard"],
        {
            "DESIRE_REAL_OIDC_DB_DATA_IPV4": reviewed.db_data_ipv4,
            "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256": (
                oidc_egress_projection_sha256(
                    reviewed.db_data_ipv4,
                    reviewed.oidc_pinned_public_ipv4,
                )
            ),
            "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4": (
                reviewed.oidc_pinned_public_ipv4
            ),
        },
    )
    _environment(
        services["web"],
        {"DESIRE_LOOPBACK_BASE_URL": "http://api:8000", "NODE_ENV": "production"},
    )
    _environment(
        services["edge"],
        {"DESIRE_REAL_OIDC_PILOT_HOSTNAME": reviewed.pilot_hostname},
    )
    _environment(
        services["db"],
        {
            "PGDATA": "/var/lib/postgresql/data/pgdata",
            "POSTGRES_DB": "desire",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/db_superuser_password",
            "POSTGRES_USER": "postgres",
        },
    )

    expected_commands = {
        "api": ["python", "-m", "desire_platform.internal_pilot.api_server"],
        "db": None,
        "edge": None,
        "identity-bootstrap": ["python", "-m", "desire_platform.deployment.preprovisioned_identity_bootstrap_orchestrator", "run"],
        "migrate": ["python", "-m", "desire_platform.deployment"],
        "matching-runtime": ["python", "-m", "desire_platform.matching.runtime_process"],
        "online-credentials-reconcile": ["python", "-m", "desire_platform.deployment.online_credentials", "reconcile"],
        "online-credentials-verify": ["python", "-m", "desire_platform.deployment.online_credentials", "verify"],
        "oidc-egress-guard": None,
        "taxonomy-seed": ["python", "-m", "desire_platform.deployment.synthetic_taxonomy_seed", "apply"],
        "web": None,
    }
    if {name: service.get("command") for name, service in services.items()} != expected_commands:
        _invalid()
    expected_builds = {
        "api": {"context": str(repository := Path(__file__).resolve(strict=True).parent.parent), "dockerfile": "Dockerfile", "target": "platform-runtime"},
        "migrate": {"context": str(repository), "dockerfile": "Dockerfile", "target": "platform-runtime"},
        "oidc-egress-guard": {"context": str(repository), "dockerfile": "Dockerfile", "target": "oidc-egress-guard-runtime"},
        "web": {"context": str(repository), "dockerfile": "Dockerfile", "target": "web-runtime"},
        "edge": {"context": str(repository), "dockerfile": "Dockerfile", "target": "edge-runtime"},
    }
    if any(services[name].get("build") != build for name, build in expected_builds.items()):
        _invalid()
    platform_image = "desire-supply-platform:" + reviewed.image_tag
    expected_images = {
        "api": platform_image,
        "db": _POSTGRES_IMAGE,
        "edge": "desire-supply-edge:" + reviewed.image_tag,
        "identity-bootstrap": platform_image,
        "migrate": platform_image,
        "matching-runtime": platform_image,
        "online-credentials-reconcile": platform_image,
        "online-credentials-verify": platform_image,
        "oidc-egress-guard": "desire-supply-oidc-egress-guard:" + reviewed.image_tag,
        "taxonomy-seed": platform_image,
        "web": "desire-supply-web:" + reviewed.image_tag,
    }
    if {name: service.get("image") for name, service in services.items()} != expected_images:
        _invalid()
    identity_configs = _attachments(services["identity-bootstrap"].get("configs"))
    if identity_configs != _RUNTIME_CONFIG_ATTACHMENTS + (
        ("internal-sandbox-identity-template", "/run/desire/identity-bootstrap-template.json", "0444"),
    ):
        _invalid()
    if _attachments(services["api"].get("configs")) != _RUNTIME_CONFIG_ATTACHMENTS:
        _invalid()
    if (
        _attachments(services["matching-runtime"].get("configs"))
        != _MATCHING_RUNTIME_CONFIG_ATTACHMENTS
    ):
        _invalid()
    if any(
        _attachments(services[name].get("configs"))
        != _ONLINE_CREDENTIAL_CONFIG_ATTACHMENTS
        for name in (
            "online-credentials-reconcile",
            "online-credentials-verify",
        )
    ):
        _invalid()
    if _attachments(services["edge"].get("configs")) != (
        ("real-oidc-caddyfile", "/etc/caddy/Caddyfile", "0444"),
        ("real-oidc-edge-tls-chain", "/run/desire-tls/edge-tls-chain.pem", "0444"),
    ):
        _invalid()
    identity_secrets = _secret_sources(services["identity-bootstrap"].get("secrets"))
    if identity_secrets != frozenset(
        (
            "db_superuser_password",
            "key-oidc-subject-digest-v1",
            "key-oidc-recipient-binding-v1",
        )
    ):
        _invalid()
    if "key-oidc-client-secret-v1" in identity_secrets:
        _invalid()
    expected_healthchecks = {
        "db": {"test": ["CMD-SHELL", "pg_isready -U postgres -d desire || exit 1"], "timeout": "3s", "interval": "5s", "retries": 20, "start_period": "10s"},
        "api": {"test": ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"], "timeout": "3s", "interval": "10s", "retries": 6, "start_period": "20s"},
        "matching-runtime": {"test": ["CMD", "python", "-c", "from pathlib import Path; import time; p=Path('/run/matching-runtime/healthy'); raise SystemExit(0 if p.is_file() and time.time()-p.stat().st_mtime < 30 else 1)"], "timeout": "3s", "interval": "10s", "retries": 3, "start_period": "20s"},
        "web": {"test": ["CMD", "node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"], "timeout": "3s", "interval": "10s", "retries": 10, "start_period": "15s"},
        "edge": {"test": ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://127.0.0.1:8080/_edge/health"], "timeout": "3s", "interval": "10s", "retries": 10, "start_period": "5s"},
        "oidc-egress-guard": {"test": ["CMD", _EGRESS_GUARD_ENTRYPOINT, "check"], "timeout": "3s", "interval": "5s", "retries": 3, "start_period": "1s"},
    }
    if any(services[name].get("healthcheck") != healthcheck for name, healthcheck in expected_healthchecks.items()):
        _invalid()
    if (
        services["db"].get("shm_size") != "134217728"
        or services["db"].get("stop_grace_period") != "1m0s"
        or services["api"].get("stop_grace_period") != "20s"
        or services["matching-runtime"].get("stop_grace_period") != "30s"
        or services["oidc-egress-guard"].get("user") != "0:0"
        or services["edge"].get("sysctls")
        != {"net.ipv4.ip_unprivileged_port_start": "0"}
    ):
        _invalid()
    edge_ports = services["edge"].get("ports")
    if not isinstance(edge_ports, list) or len(edge_ports) != 2:
        _invalid()
    normalized_ports = set()
    for port in edge_ports:
        if not isinstance(port, dict):
            _invalid()
        expected_port_keys = {
            "mode",
            "host_ip",
            "target",
            "published",
            "protocol",
        }
        if port.get("name") is not None:
            expected_port_keys.add("name")
        if frozenset(port) != frozenset(expected_port_keys):
            _invalid()
        normalized_ports.add(
            (
                port.get("name"),
                port.get("host_ip"),
                port.get("target"),
                port.get("published"),
                port.get("protocol"),
                port.get("mode"),
            )
        )
    if normalized_ports != {
        (None, "127.0.0.1", 443, "443", "tcp", "ingress"),
        ("private-rfc1918-https", str(ingress_ip), 443, "443", "tcp", "ingress"),
    }:
        _invalid()


def _validate_filesystem_inputs(
    document: Mapping[str, Any],
    *,
    reviewed: ReviewedRealOidcInputs,
    repository: Path,
) -> Tuple[Path, Path, Path]:
    bundle = _require_external_directory(reviewed.bundle_dir, repository=repository)
    identity = _require_external_directory(reviewed.identity_source_dir, repository=repository)
    tls = _require_external_directory(reviewed.tls_dir, repository=repository)
    roots = (bundle, identity, tls)
    staging_root = bundle.parent
    if identity.parent != staging_root or tls.parent != staging_root:
        _invalid()
    if any(
        _within(left, right) or _within(right, left)
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        _invalid()
    _require_exact_directory_entries(bundle, ("config", "runtime-secrets"))
    _require_exact_directory_entries(
        bundle / "config",
        (
            "deployment.json",
            "runtime-config.json",
            "secret-manifest.json",
            "matching-deployment.json",
            "matching-runtime-config.json",
            "matching-secret-manifest.json",
            "online-credentials-deployment.json",
            "online-credentials-runtime-config.json",
            "online-credentials-secret-manifest.json",
            "identity-bootstrap-template.json",
            "Caddyfile.real-oidc",
        ),
    )
    _require_exact_directory_entries(
        bundle / "runtime-secrets", _BUNDLE_SECRET_NAMES
    )
    _require_exact_directory_entries(
        tls, ("edge-tls-chain.pem", "edge-tls-key.pem")
    )
    _inventory_identity_sources(identity)

    configs = document.get("configs")
    if not isinstance(configs, dict) or frozenset(configs) != _CONFIG_NAMES:
        _invalid()
    expected_configs = {
        "internal-sandbox-deployment": bundle / "config/deployment.json",
        "internal-sandbox-runtime-config": bundle / "config/runtime-config.json",
        "internal-sandbox-secret-manifest": bundle / "config/secret-manifest.json",
        "internal-sandbox-matching-deployment": bundle / "config/matching-deployment.json",
        "internal-sandbox-matching-runtime-config": bundle / "config/matching-runtime-config.json",
        "internal-sandbox-matching-secret-manifest": bundle / "config/matching-secret-manifest.json",
        "internal-sandbox-online-credentials-deployment": bundle / "config/online-credentials-deployment.json",
        "internal-sandbox-online-credentials-runtime-config": bundle / "config/online-credentials-runtime-config.json",
        "internal-sandbox-online-credentials-secret-manifest": bundle / "config/online-credentials-secret-manifest.json",
        "internal-sandbox-identity-template": bundle / "config/identity-bootstrap-template.json",
        "real-oidc-caddyfile": bundle / "config/Caddyfile.real-oidc",
        "real-oidc-edge-tls-chain": tls / "edge-tls-chain.pem",
    }
    for logical, path in expected_configs.items():
        if _within(path, bundle):
            _closed_descendant_ancestry(path, root=bundle)
        elif logical == "real-oidc-edge-tls-chain":
            _closed_descendant_ancestry(path, root=tls)
        maximum = _MAX_TLS_BYTES if logical == "real-oidc-edge-tls-chain" else _MAX_CONFIG_BYTES
        _logical_file(
            configs[logical],
            project=reviewed.project_name,
            logical_name=logical,
            expected_path=path,
            maximum_bytes=maximum,
            mounted_mode=0o444,
        )

    secrets = document.get("secrets")
    if not isinstance(secrets, dict) or frozenset(secrets) != _SECRET_NAMES:
        _invalid()
    bundle_secret_paths = []
    for logical in _BUNDLE_SECRET_NAMES:
        secret_path = bundle / ("runtime-secrets/" + logical)
        _closed_descendant_ancestry(secret_path, root=bundle)
        _logical_file(
            secrets[logical],
            project=reviewed.project_name,
            logical_name=logical,
            expected_path=secret_path,
            maximum_bytes=_MAX_SECRET_BYTES,
            mounted_mode=0o444,
        )
        bundle_secret_paths.append(secret_path)
    tls_key_path = tls / "edge-tls-key.pem"
    _closed_descendant_ancestry(tls_key_path, root=tls)
    _logical_file(
        secrets["edge-tls-key"],
        project=reviewed.project_name,
        logical_name="edge-tls-key",
        expected_path=tls_key_path,
        maximum_bytes=_MAX_TLS_BYTES,
        mounted_mode=0o444,
    )
    standalone_secret_paths = []
    for logical in (
        "db_superuser_password",
        "taxonomy_seed_receipt_hmac_key",
        "taxonomy_seed_workload_credential",
    ):
        item = _closed(secrets[logical], ("name", "file"))
        if item["name"] != reviewed.project_name + "_" + logical:
            _invalid()
        source = _canonical_existing_path(
            item["file"], directory=False, maximum_bytes=_MAX_SECRET_BYTES
        )
        _closed_directory(source.parent, expected_mode=0o700)
        if (
            source.parent != staging_root
            or _within(source, repository)
            or _within(source, bundle)
            or _within(source, identity)
            or _within(source, tls)
            or stat.S_IMODE(source.stat().st_mode) != 0o444
        ):
            _invalid()
        standalone_secret_paths.append(source)

    all_input_files = (
        list(expected_configs.values())
        + bundle_secret_paths
        + [tls_key_path]
        + standalone_secret_paths
        + [identity / name for name in _IDENTITY_SOURCE_NAMES]
    )
    _require_distinct_files(all_input_files)

    for deployment_name, runtime_path, manifest_path in (
        (
            "deployment.json",
            "/run/desire/runtime-config.json",
            "/run/desire/secret-manifest.json",
        ),
        (
            "matching-deployment.json",
            "/run/desire/matching-runtime-config.json",
            "/run/desire/matching-secret-manifest.json",
        ),
        (
            "online-credentials-deployment.json",
            "/run/desire/online-credentials-runtime-config.json",
            "/run/desire/online-credentials-secret-manifest.json",
        ),
    ):
        try:
            deployment_raw = (bundle / "config" / deployment_name).read_bytes()
        except OSError:
            _invalid()
        _validate_deployment(
            deployment_raw,
            reviewed=reviewed,
            expected_runtime_config_path=runtime_path,
            expected_secret_manifest_path=manifest_path,
        )
    repository_template_path = _canonical_existing_path(
        str(
            repository
            / "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"
        ),
        directory=False,
        maximum_bytes=_MAX_CONFIG_BYTES,
    )
    repository_caddy_path = _canonical_existing_path(
        str(repository / "deploy/Caddyfile.real-oidc"),
        directory=False,
        maximum_bytes=_MAX_CONFIG_BYTES,
    )
    try:
        template_raw = expected_configs["internal-sandbox-identity-template"].read_bytes()
        caddy_raw = expected_configs["real-oidc-caddyfile"].read_bytes()
        repository_template_raw = repository_template_path.read_bytes()
        repository_caddy_raw = repository_caddy_path.read_bytes()
    except OSError:
        _invalid()
    if (
        template_raw != repository_template_raw
        or hashlib.sha256(template_raw).hexdigest() != _TEMPLATE_SHA256
    ):
        _invalid()
    if caddy_raw != repository_caddy_raw or caddy_raw != _EXPECTED_CADDYFILE:
        _invalid()
    return bundle, identity, tls


def _validate_extensions(document: Mapping[str, Any]) -> None:
    expected_runtime_configs = [
        {"mode": 292, "source": source, "target": target}
        for source, target, _mode in _RUNTIME_CONFIG_ATTACHMENTS
    ]
    expected_identity_configs = list(expected_runtime_configs)
    expected_identity_configs.append(
        {
            "mode": 292,
            "source": "internal-sandbox-identity-template",
            "target": "/run/desire/identity-bootstrap-template.json",
        }
    )
    expected_matching_configs = [
        {"mode": 292, "source": source, "target": target}
        for source, target, _mode in _MATCHING_RUNTIME_CONFIG_ATTACHMENTS
    ]
    expected_online_configs = [
        {"mode": 292, "source": source, "target": target}
        for source, target, _mode in _ONLINE_CREDENTIAL_CONFIG_ATTACHMENTS
    ]
    runtime_secrets = _named_secret_map(_API_SECRET_ORDER)
    matching_secrets = _named_secret_map(_MATCHING_RUNTIME_SECRET_ORDER)
    online_secrets = {
        name: _plain_secret(name, name)
        for name in _BUNDLE_SECRET_ORDER
        if name.startswith("db-")
    }
    online_secrets["db_superuser_password"] = _plain_secret(
        "db_superuser_password", "db_superuser_password"
    )
    identity_secrets = {
        "db_superuser_password": _plain_secret(
            "db_superuser_password", "db_superuser_password"
        ),
        "key-oidc-subject-digest-v1": _plain_secret(
            "key-oidc-subject-digest-v1", "key-oidc-subject-digest-v1"
        ),
        "key-oidc-recipient-binding-v1": _plain_secret(
            "key-oidc-recipient-binding-v1",
            "key-oidc-recipient-binding-v1",
        ),
    }
    if (
        document.get("x-deployment-admin") != _ADMIN_ENVIRONMENT
        or document.get("x-hardened")
        != {
            "cap_drop": ["ALL"],
            "init": True,
            "logging": _BOUNDED_LOGGING,
            "read_only": True,
            "restart": "no",
            "security_opt": ["no-new-privileges=true"],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
        }
        or document.get("x-runtime-configs") != expected_runtime_configs
        or document.get("x-identity-configs") != expected_identity_configs
        or document.get("x-matching-runtime-configs")
        != expected_matching_configs
        or document.get("x-online-credential-configs")
        != expected_online_configs
        or _secret_map(document.get("x-runtime-secrets")) != runtime_secrets
        or _secret_map(document.get("x-matching-runtime-secrets"))
        != matching_secrets
        or _secret_map(document.get("x-online-database-secrets"))
        != online_secrets
        or _secret_map(document.get("x-identity-bootstrap-secrets"))
        != identity_secrets
    ):
        _invalid()


def validate_private_server_real_oidc_compose(
    raw_compose_json: bytes,
    *,
    reviewed: ReviewedRealOidcInputs,
    repository_root: Optional[str] = None,
) -> None:
    """Validate one resolved four-layer document without reflecting inputs."""

    try:
        if not isinstance(reviewed, ReviewedRealOidcInputs):
            _invalid()
        if _PROJECT.fullmatch(reviewed.project_name) is None:
            _invalid()
        pilot = _dns_name(reviewed.pilot_hostname)
        issuer = _issuer(reviewed.oidc_issuer)
        pinned_public_ipv4 = _global_public_ipv4(
            reviewed.oidc_pinned_public_ipv4
        )
        db_data_ipv4 = _rfc1918_ipv4(reviewed.db_data_ipv4)
        if pilot != reviewed.pilot_hostname or issuer != reviewed.oidc_issuer:
            _invalid()
        if pinned_public_ipv4 != reviewed.oidc_pinned_public_ipv4:
            _invalid()
        if db_data_ipv4 != reviewed.db_data_ipv4:
            _invalid()
        if (
            not isinstance(reviewed.oidc_client_id, str)
            or _CLIENT_ID.fullmatch(reviewed.oidc_client_id) is None
            or reviewed.oidc_client_id == "desire-internal-sandbox"
        ):
            _invalid()
        if (
            not isinstance(reviewed.image_tag, str)
            or _IMAGE_TAG.fullmatch(reviewed.image_tag) is None
        ):
            _invalid()
        try:
            ingress_ip = ipaddress.ip_address(reviewed.ingress_ip)
        except ValueError:
            _invalid()
        if (
            not isinstance(ingress_ip, ipaddress.IPv4Address)
            or not any(ingress_ip in network for network in _RFC1918)
            or ingress_ip.is_loopback
            or str(ingress_ip) != reviewed.ingress_ip
        ):
            _invalid()
        if repository_root is None:
            repository = Path(__file__).resolve(strict=True).parent.parent
        else:
            repository = _canonical_existing_path(repository_root, directory=True)
        document = _closed(
            _parse_json(raw_compose_json, maximum=_MAX_COMPOSE_BYTES),
            (
                "name",
                "networks",
                "services",
                "volumes",
                "configs",
                "secrets",
                "x-deployment-admin",
                "x-hardened",
                "x-identity-configs",
                "x-identity-bootstrap-secrets",
                "x-matching-runtime-configs",
                "x-matching-runtime-secrets",
                "x-online-credential-configs",
                "x-online-database-secrets",
                "x-runtime-configs",
                "x-runtime-secrets",
            ),
        )
        if document["name"] != reviewed.project_name:
            _invalid()
        _validate_extensions(document)
        _, identity, _ = _validate_filesystem_inputs(
            document, reviewed=reviewed, repository=repository
        )
        _validate_networks(
            document["networks"],
            db_data_ipv4=ipaddress.IPv4Address(db_data_ipv4),
            ingress_ip=ingress_ip,
            project_name=reviewed.project_name,
        )
        _validate_services(
            document["services"],
            reviewed=reviewed,
            identity_source=identity,
            ingress_ip=ingress_ip,
        )
        volumes = document["volumes"]
        if (
            not isinstance(volumes, dict)
            or volumes
            != {
                "postgres-data": {
                    "name": reviewed.project_name + "_postgres-data"
                }
            }
        ):
            _invalid()
        serialized = json.dumps(document, ensure_ascii=True, separators=(",", ":"))
        for forbidden in (
            "synthetic-oidc",
            "identity.example.test",
            "oidc-backend",
            "internal-sandbox-root-ca",
            "/run/desire-tls/root-ca.pem",
            "host-gateway",
            "/var/run/docker.sock",
            "/run/docker.sock",
            "provider_refresh_token",
            "provider_access_token",
            "provider_id_token",
            "provider_authorization_code",
            "oidc_authorization_code",
        ):
            if forbidden in serialized:
                _invalid()
    except PrivateServerRealOidcComposeContractError:
        raise
    except BaseException:
        _invalid()


def check_repository_static_profile(*, repository_root: Optional[str] = None) -> None:
    """Check source-level invariants without Docker or deployment inputs."""

    try:
        if repository_root is None:
            repository = Path(__file__).resolve(strict=True).parent.parent
        else:
            repository = _canonical_existing_path(repository_root, directory=True)
        caddy = (repository / "deploy/Caddyfile.real-oidc").read_bytes()
        overlay = (repository / "deploy/private-server-real-oidc.compose.yaml").read_text(
            encoding="utf-8"
        )
        workflow = (repository / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        dockerfile = (repository / "Dockerfile").read_text(encoding="utf-8")
        guard = (
            repository / "deploy/private-server-real-oidc-egress-guard.py"
        ).read_text(encoding="utf-8")
        adapter = (
            repository
            / "platform/src/desire_platform/identity_access/adapters/oidc.py"
        ).read_text(encoding="utf-8")
        production_plan = (
            repository
            / "platform/src/desire_platform/internal_pilot/production_plan.py"
        ).read_text(encoding="utf-8")
        template = (
            repository
            / "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json"
        ).read_bytes()
        required_overlay = (
            "DESIRE_REAL_OIDC_PROJECT_NAME:?",
            "synthetic-oidc: !reset null",
            "depends_on: !override {}",
            "depends_on: !override\n      identity-bootstrap:",
            "oidc-backend: !reset null",
            "oidc-egress: {}",
            "configs: !override",
            "networks: !override",
            "networks: !reset []",
            "network_mode: service:oidc-egress-guard",
            "oidc-egress-guard:",
            "target: oidc-egress-guard-runtime",
            "cap_add:\n      - NET_ADMIN",
            "aliases:\n          - api",
            "DESIRE_REAL_OIDC_DB_DATA_IPV4:?",
            "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4:?",
            "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256:?",
            "DESIRE_REAL_OIDC_PILOT_HOSTNAME:?",
            "DESIRE_REAL_OIDC_BUNDLE_DIR:?",
            "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR:?",
            "DESIRE_REAL_OIDC_TLS_DIR:?",
            "DESIRE_REAL_OIDC_DB_PASSWORD_FILE:?",
            "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE:?",
            "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE:?",
            "/config/identity-bootstrap-template.json",
            "/config/Caddyfile.real-oidc",
            "SSL_CERT_FILE: " + _SYSTEM_CA_FILE,
            "preprovisioned_identity_bootstrap_orchestrator",
            "key-trust-report-cursor-v1",
        )
        if (
            caddy != _EXPECTED_CADDYFILE
            or hashlib.sha256(template).hexdigest() != _TEMPLATE_SHA256
            or any(token not in overlay for token in required_overlay)
            or "DESIRE_REAL_OIDC_BUNDLE_DIR:-" in overlay
            or "DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR:-" in overlay
            or "DESIRE_REAL_OIDC_TLS_DIR:-" in overlay
            or "DESIRE_REAL_OIDC_DB_PASSWORD_FILE:-" in overlay
            or "DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE:-"
            in overlay
            or "DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE:-"
            in overlay
            or "Verify the Platform runtime public CA bundle" not in workflow
            or "p='/etc/ssl/certs/ca-certificates.crt'" not in workflow
            or "os.path.isfile(p)" not in workflow
            or "os.path.getsize(p) > 0" not in workflow
            or "os.access(p, os.R_OK)" not in workflow
            or "Build the exact real OIDC egress guard image" not in workflow
            or "AS oidc-egress-guard-runtime" not in dockerfile
            or "apt-get install --yes --no-install-recommends nftables" not in dockerfile
            or "private-server-real-oidc-egress-guard.py" not in dockerfile
            or "policy drop" not in guard
            or "udp dport 53 reject" not in guard
            or "tcp dport 53 reject with tcp reset" not in guard
            or "meta nfproto ipv6 reject" not in guard
            or "tcp dport 5432 accept" not in guard
            or "tcp dport 443 accept" not in guard
            or "def projection_sha256(" not in guard
            or "ProxyHandler({})," not in adapter
            or "PinnedPublicIpOidcJsonTransport(" not in production_plan
            or "network_binding.pinned_public_ipv4" not in production_plan
        ):
            _invalid()
    except PrivateServerRealOidcComposeContractError:
        raise
    except BaseException:
        _invalid()


def _options(argv: Sequence[str]) -> Mapping[str, str]:
    names = frozenset(
        (
            "--project-name",
            "--pilot-hostname",
            "--oidc-issuer",
            "--oidc-client-id",
            "--oidc-pinned-public-ipv4",
            "--db-data-ipv4",
            "--image-tag",
            "--bundle-dir",
            "--identity-source-dir",
            "--tls-dir",
            "--ingress-ip",
        )
    )
    if len(argv) != 2 * len(names):
        _invalid()
    result = {}
    for index in range(0, len(argv), 2):
        name = argv[index]
        value = argv[index + 1]
        if name not in names or name in result or not isinstance(value, str):
            _invalid()
        result[name] = value
    if frozenset(result) != names:
        _invalid()
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if arguments == ("--check-static",):
            check_repository_static_profile()
            sys.stdout.write('{"status":"REAL_OIDC_STATIC_PROFILE_OK"}\n')
            return 0
        options = _options(arguments)
        raw = sys.stdin.buffer.read(_MAX_COMPOSE_BYTES + 1)
        reviewed = ReviewedRealOidcInputs(
            project_name=options["--project-name"],
            pilot_hostname=options["--pilot-hostname"],
            oidc_issuer=options["--oidc-issuer"],
            oidc_client_id=options["--oidc-client-id"],
            oidc_pinned_public_ipv4=options["--oidc-pinned-public-ipv4"],
            db_data_ipv4=options["--db-data-ipv4"],
            image_tag=options["--image-tag"],
            bundle_dir=options["--bundle-dir"],
            identity_source_dir=options["--identity-source-dir"],
            tls_dir=options["--tls-dir"],
            ingress_ip=options["--ingress-ip"],
        )
        validate_private_server_real_oidc_compose(raw, reviewed=reviewed)
    except PrivateServerRealOidcComposeContractError:
        sys.stderr.write(
            '{"code":"PRIVATE_SERVER_REAL_OIDC_COMPOSE_INVALID","status":"BLOCKED"}\n'
        )
        return 78
    except BaseException:
        sys.stderr.write(
            '{"code":"PRIVATE_SERVER_REAL_OIDC_COMPOSE_INVALID","status":"BLOCKED"}\n'
        )
        return 78
    sys.stdout.write('{"status":"PRIVATE_SERVER_REAL_OIDC_COMPOSE_VERIFIED"}\n')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "PrivateServerRealOidcComposeContractError",
    "ReviewedRealOidcInputs",
    "check_repository_static_profile",
    "main",
    "oidc_egress_projection_bytes",
    "oidc_egress_projection_sha256",
    "validate_private_server_real_oidc_compose",
)
