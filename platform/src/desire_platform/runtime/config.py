"""Closed, side-effect-free runtime configuration parser."""

import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Tuple


_MAX_CONFIG_BYTES = 256 * 1024
_PROCESS_KINDS = frozenset(
    {
        "web-api",
        "webhook-ingress",
        "outbox-delivery",
        "domain-process",
        "migration",
        "audit-recovery",
    }
)
_CAPABILITY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_APPLICATION_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SECRET_REF_PATTERN = re.compile(
    r"^secret://[a-z0-9][a-z0-9_-]{0,62}/"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}#"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"
)


@dataclass(frozen=True)
class RuntimeIdentity:
    environment_id: str
    deployment_id: str
    release_id: str
    region: str
    instance_id: str


@dataclass(frozen=True)
class ProcessConfiguration:
    kind: str
    capability_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArtifactRequirement:
    artifact_id: str
    sha256: str


@dataclass(frozen=True)
class DatabaseProfile:
    capability_id: str
    online_role: str
    credential_ref: str = field(repr=False)
    application_name: str
    max_pool_size: int
    checkout_timeout_ms: int
    statement_timeout_ms: int
    lock_timeout_ms: int
    idle_in_transaction_timeout_ms: int


@dataclass(frozen=True)
class KeyRequirement:
    purpose: str
    active_key_id: str
    retained_key_ids: Tuple[str, ...]


@dataclass(frozen=True)
class RuntimeBudgets:
    startup_timeout_ms: int
    readiness_timeout_ms: int
    shutdown_timeout_ms: int


@dataclass(frozen=True)
class RuntimeConfiguration:
    schema_name: str
    identity: RuntimeIdentity
    process: ProcessConfiguration
    artifacts: Tuple[ArtifactRequirement, ...]
    database_profiles: Tuple[DatabaseProfile, ...]
    key_requirements: Tuple[KeyRequirement, ...]
    budgets: RuntimeBudgets


class RuntimeConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _InvalidConfiguration(Exception):
    pass


def _invalid() -> None:
    raise _InvalidConfiguration


def _closed_object(
    value: Any,
    *,
    required: Iterable[str],
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _invalid()
    required_keys = frozenset(required)
    if frozenset(value) != required_keys:
        _invalid()
    return value


def _array(value: Any, *, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _invalid()
    return value


def _string(value: Any, *, minimum: int = 1, maximum: int = 64) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _invalid()
    if value != value.strip() or unicodedata.normalize("NFC", value) != value:
        _invalid()
    if any(unicodedata.category(character) == "Cs" for character in value):
        _invalid()
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        _invalid()
    return value


def _matching_string(value: Any, pattern: re.Pattern[str]) -> str:
    candidate = _string(value)
    if pattern.fullmatch(candidate) is None:
        _invalid()
    return candidate


def _integer(value: Any, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _invalid()
    return value


def _unique(values: Iterable[str]) -> None:
    materialized = tuple(values)
    if len(materialized) != len(frozenset(materialized)):
        _invalid()


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _reject_json_number(_: str) -> Any:
    _invalid()


def _decode_json(raw: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_CONFIG_BYTES:
        _invalid()
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except _InvalidConfiguration:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _invalid()
    if not isinstance(value, dict):
        _invalid()
    return value


def _parse_identity(value: Any) -> RuntimeIdentity:
    item = _closed_object(
        value,
        required=(
            "environment_id",
            "deployment_id",
            "release_id",
            "region",
            "instance_id",
        ),
    )
    return RuntimeIdentity(
        environment_id=_string(item["environment_id"]),
        deployment_id=_string(item["deployment_id"]),
        release_id=_string(item["release_id"]),
        region=_string(item["region"]),
        instance_id=_string(item["instance_id"]),
    )


def _parse_process(value: Any) -> ProcessConfiguration:
    item = _closed_object(value, required=("kind", "capability_ids"))
    kind = _string(item["kind"])
    if kind not in _PROCESS_KINDS:
        _invalid()
    raw_capabilities = _array(item["capability_ids"], minimum=1, maximum=64)
    capabilities = tuple(
        _matching_string(candidate, _CAPABILITY_PATTERN)
        for candidate in raw_capabilities
    )
    _unique(capabilities)
    return ProcessConfiguration(kind=kind, capability_ids=capabilities)


def _parse_artifacts(value: Any) -> Tuple[ArtifactRequirement, ...]:
    artifacts = []
    for raw_artifact in _array(value, minimum=1, maximum=128):
        item = _closed_object(raw_artifact, required=("artifact_id", "sha256"))
        artifacts.append(
            ArtifactRequirement(
                artifact_id=_string(item["artifact_id"]),
                sha256=_matching_string(item["sha256"], _DIGEST_PATTERN),
            )
        )
    _unique(artifact.artifact_id for artifact in artifacts)
    return tuple(artifacts)


def _parse_database_profiles(
    value: Any,
    process: ProcessConfiguration,
) -> Tuple[DatabaseProfile, ...]:
    profiles = []
    for raw_profile in _array(value, minimum=0, maximum=64):
        item = _closed_object(
            raw_profile,
            required=(
                "capability_id",
                "online_role",
                "credential_ref",
                "application_name",
                "max_pool_size",
                "checkout_timeout_ms",
                "statement_timeout_ms",
                "lock_timeout_ms",
                "idle_in_transaction_timeout_ms",
            ),
        )
        capability_id = _matching_string(
            item["capability_id"],
            _CAPABILITY_PATTERN,
        )
        if capability_id not in process.capability_ids:
            _invalid()
        profiles.append(
            DatabaseProfile(
                capability_id=capability_id,
                online_role=_matching_string(item["online_role"], _ROLE_PATTERN),
                credential_ref=_matching_string(
                    item["credential_ref"],
                    _SECRET_REF_PATTERN,
                ),
                application_name=_matching_string(
                    item["application_name"],
                    _APPLICATION_PATTERN,
                ),
                max_pool_size=_integer(
                    item["max_pool_size"], minimum=1, maximum=64
                ),
                checkout_timeout_ms=_integer(
                    item["checkout_timeout_ms"], minimum=50, maximum=30000
                ),
                statement_timeout_ms=_integer(
                    item["statement_timeout_ms"], minimum=50, maximum=120000
                ),
                lock_timeout_ms=_integer(
                    item["lock_timeout_ms"], minimum=10, maximum=30000
                ),
                idle_in_transaction_timeout_ms=_integer(
                    item["idle_in_transaction_timeout_ms"],
                    minimum=100,
                    maximum=120000,
                ),
            )
        )
    _unique(profile.capability_id for profile in profiles)
    _unique(profile.credential_ref for profile in profiles)
    _unique(profile.application_name for profile in profiles)
    return tuple(profiles)


def _parse_key_requirements(value: Any) -> Tuple[KeyRequirement, ...]:
    requirements = []
    for raw_requirement in _array(value, minimum=0, maximum=128):
        item = _closed_object(
            raw_requirement,
            required=("purpose", "active_key_id", "retained_key_ids"),
        )
        retained_ids = tuple(
            _string(key_id)
            for key_id in _array(
                item["retained_key_ids"],
                minimum=1,
                maximum=32,
            )
        )
        _unique(retained_ids)
        active_key_id = _string(item["active_key_id"])
        if active_key_id not in retained_ids:
            _invalid()
        requirements.append(
            KeyRequirement(
                purpose=_matching_string(item["purpose"], _CAPABILITY_PATTERN),
                active_key_id=active_key_id,
                retained_key_ids=retained_ids,
            )
        )
    _unique(requirement.purpose for requirement in requirements)
    return tuple(requirements)


def _parse_budgets(value: Any) -> RuntimeBudgets:
    item = _closed_object(
        value,
        required=(
            "startup_timeout_ms",
            "readiness_timeout_ms",
            "shutdown_timeout_ms",
        ),
    )
    return RuntimeBudgets(
        startup_timeout_ms=_integer(
            item["startup_timeout_ms"], minimum=100, maximum=300000
        ),
        readiness_timeout_ms=_integer(
            item["readiness_timeout_ms"], minimum=50, maximum=30000
        ),
        shutdown_timeout_ms=_integer(
            item["shutdown_timeout_ms"], minimum=100, maximum=300000
        ),
    )


def parse_runtime_config(raw: bytes) -> RuntimeConfiguration:
    """Parse one closed document without reading ambient process state."""

    try:
        root = _closed_object(
            _decode_json(raw),
            required=(
                "schema_name",
                "identity",
                "process",
                "artifacts",
                "database_profiles",
                "key_requirements",
                "budgets",
            ),
        )
        schema_name = _string(root["schema_name"])
        if schema_name != "desire-runtime-config-v1":
            _invalid()
        process = _parse_process(root["process"])
        return RuntimeConfiguration(
            schema_name=schema_name,
            identity=_parse_identity(root["identity"]),
            process=process,
            artifacts=_parse_artifacts(root["artifacts"]),
            database_profiles=_parse_database_profiles(
                root["database_profiles"],
                process,
            ),
            key_requirements=_parse_key_requirements(root["key_requirements"]),
            budgets=_parse_budgets(root["budgets"]),
        )
    except _InvalidConfiguration:
        raise RuntimeConfigurationError("INVALID_RUNTIME_CONFIGURATION") from None


def _validate_runtime_configuration_instance(
    config: RuntimeConfiguration,
) -> None:
    """Apply the byte-parser invariants to an already-constructed value.

    Composition roots accept the immutable value type publicly, so this prevents a
    caller from bypassing the only supported parser by directly instantiating the
    dataclasses with open or malformed facts.
    """

    try:
        if type(config) is not RuntimeConfiguration:
            _invalid()
        document = {
            "schema_name": config.schema_name,
            "identity": {
                "environment_id": config.identity.environment_id,
                "deployment_id": config.identity.deployment_id,
                "release_id": config.identity.release_id,
                "region": config.identity.region,
                "instance_id": config.identity.instance_id,
            },
            "process": {
                "kind": config.process.kind,
                "capability_ids": list(config.process.capability_ids),
            },
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "sha256": artifact.sha256,
                }
                for artifact in config.artifacts
            ],
            "database_profiles": [
                {
                    "capability_id": profile.capability_id,
                    "online_role": profile.online_role,
                    "credential_ref": profile.credential_ref,
                    "application_name": profile.application_name,
                    "max_pool_size": profile.max_pool_size,
                    "checkout_timeout_ms": profile.checkout_timeout_ms,
                    "statement_timeout_ms": profile.statement_timeout_ms,
                    "lock_timeout_ms": profile.lock_timeout_ms,
                    "idle_in_transaction_timeout_ms": (
                        profile.idle_in_transaction_timeout_ms
                    ),
                }
                for profile in config.database_profiles
            ],
            "key_requirements": [
                {
                    "purpose": requirement.purpose,
                    "active_key_id": requirement.active_key_id,
                    "retained_key_ids": list(requirement.retained_key_ids),
                }
                for requirement in config.key_requirements
            ],
            "budgets": {
                "startup_timeout_ms": config.budgets.startup_timeout_ms,
                "readiness_timeout_ms": config.budgets.readiness_timeout_ms,
                "shutdown_timeout_ms": config.budgets.shutdown_timeout_ms,
            },
        }
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        if parse_runtime_config(encoded) != config:
            _invalid()
    except RuntimeConfigurationError:
        raise
    except BaseException:
        raise RuntimeConfigurationError("INVALID_RUNTIME_CONFIGURATION") from None
