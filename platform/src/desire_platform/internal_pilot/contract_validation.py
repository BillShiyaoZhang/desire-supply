"""Digest-pinned package contract validators for PostgreSQL command UoWs."""

from __future__ import annotations

from datetime import datetime
import hashlib
import hmac
from importlib import resources
import json
import math
import re
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple


_MAXIMUM_RESOURCE_BYTES = 2 * 1024 * 1024
_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_RFC3339_DATETIME = re.compile(
    r"^(?P<whole>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?"
    r"(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_RESOURCE_FACTS = {
    ("iam", "event"): (
        "events/iam-v1.schema.json",
        bytes.fromhex(
            "6af7e75f738bfeef9aeed0ac8e84da7"
            "82485c1a42e1c937c9d51e66884bad934"
        ),
    ),
    ("iam", "api"): (
        "api/iam-v1.openapi.yaml",
        bytes.fromhex(
            "26ffd8243c0baa2580d21e8878897ed0"
            "f13aa61fd9ba468cca8edf1fe277477c"
        ),
    ),
    ("profile", "event"): (
        "events/profile-v1.schema.json",
        bytes.fromhex(
            "9dd6287bf3bef84c550dffad9d49d580"
            "ea8b0d7ff718702ead49f3f94c518ac8"
        ),
    ),
    ("profile", "api"): (
        "api/profile-v1.openapi.yaml",
        bytes.fromhex(
            "f3ef514855c26d6fa058da6c776124b"
            "089ac2d7d662fedf2503c82e7800537e8"
        ),
    ),
    ("demand", "event"): (
        "events/demand-v1.schema.json",
        bytes.fromhex(
            "46631be37cb70aea771d2103e1fe39dc3"
            "9f3f4303239ae1dc6e55fa946d1059c"
        ),
    ),
    ("demand", "api"): (
        "api/demand-v1.openapi.yaml",
        bytes.fromhex(
            "046561ae51d147e8df3b8fcf0b61f1d"
            "d922efe452175e63f128a937e8f11c4ff"
        ),
    ),
}
_PROFILE_EVENT_SCHEMAS = frozenset(
    (
        "CreatorProfileCreatedEvent",
        "CreatorProfilePublishedEvent",
        "CreatorProfilePausedEvent",
        "CreatorProfileResumedEvent",
        "CreatorProfileArchivedEvent",
    )
)
_SCHEMA_KEYS = frozenset(
    (
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "oneOf",
        "allOf",
        "if",
        "then",
        "properties",
        "required",
        "additionalProperties",
        "minProperties",
        "maxProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
    )
)


class PostgresContractConfigurationError(RuntimeError):
    def __init__(self) -> None:
        self.code = "CONTRACT_CONFIGURATION_UNAVAILABLE"
        super().__init__(self.code)


class PostgresContractValidationError(ValueError):
    def __init__(self) -> None:
        self.code = "CONTRACT_VALIDATION_FAILED"
        super().__init__(self.code)


class _InvalidSchema(Exception):
    pass


class _InvalidValue(Exception):
    pass


def _default_resource_loader(relative_path: str) -> bytes:
    try:
        candidate = resources.files("desire_platform.contracts")
        for segment in relative_path.split("/"):
            candidate = candidate.joinpath(segment)
        return candidate.read_bytes()
    except (ImportError, ModuleNotFoundError, OSError, TypeError, ValueError):
        raise PostgresContractConfigurationError() from None


def _load_reviewed_resource(
    *,
    component: str,
    kind: str,
    loader: Callable[[str], bytes],
) -> bytes:
    try:
        relative_path, expected_sha256 = _RESOURCE_FACTS[(component, kind)]
        raw = loader(relative_path)
    except PostgresContractConfigurationError:
        raise
    except BaseException:
        raise PostgresContractConfigurationError() from None
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= _MAXIMUM_RESOURCE_BYTES
        or not hmac.compare_digest(hashlib.sha256(raw).digest(), expected_sha256)
    ):
        raise PostgresContractConfigurationError()
    return raw


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidSchema
        result[key] = value
    return result


def _parse_event_schema(raw: bytes) -> Mapping[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(_InvalidSchema()),
            parse_constant=lambda _value: (_ for _ in ()).throw(_InvalidSchema()),
        )
    except _InvalidSchema:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        raise _InvalidSchema from None
    if not isinstance(document, Mapping) or document.get("$schema") != _DIALECT:
        raise _InvalidSchema
    return document


def _parse_openapi(raw: bytes) -> Mapping[str, Any]:
    try:
        import yaml
    except (ImportError, ModuleNotFoundError):
        raise _InvalidSchema from None

    class _UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> Any:
        loader.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise _InvalidSchema
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    _UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    try:
        text = raw.decode("utf-8", errors="strict")
        document = yaml.load(text, Loader=_UniqueSafeLoader)
    except _InvalidSchema:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError, TypeError, ValueError):
        raise _InvalidSchema from None
    if (
        not isinstance(document, Mapping)
        or document.get("openapi") != "3.1.0"
        or document.get("jsonSchemaDialect") != _DIALECT
        or not isinstance(document.get("components"), Mapping)
        or not isinstance(document["components"].get("schemas"), Mapping)
    ):
        raise _InvalidSchema
    return document


class _PackagedPostgresContractValidator:
    def __init__(
        self,
        *,
        component: str,
        resource_loader: Callable[[str], bytes],
    ) -> None:
        if component not in {"iam", "profile", "demand"} or not callable(resource_loader):
            raise PostgresContractConfigurationError()
        try:
            self._event_document = _parse_event_schema(
                _load_reviewed_resource(
                    component=component,
                    kind="event",
                    loader=resource_loader,
                )
            )
            self._api_document = _parse_openapi(
                _load_reviewed_resource(
                    component=component,
                    kind="api",
                    loader=resource_loader,
                )
            )
            self._component = component
            self._response_schema = _response_schema(component)
            _audit_schema(self._event_document, self._event_document, set(), 0)
            _audit_schema(self._response_schema, self._api_document, set(), 0)
            self._iam_response_schemas = None
            if component == "iam":
                self._iam_response_schemas = {
                    name: {"$ref": f"#/components/schemas/{name}"}
                    for name in (
                        "PlatformUserAdminDto",
                        "PolicyRequirementStatusDto",
                        "AccessInvitationAdminDto",
                        "MembershipAdminDto",
                        "AccessInvitationAcceptanceDto",
                        "OrganizationSummaryDto",
                    )
                }
                for schema in self._iam_response_schemas.values():
                    _audit_schema(schema, self._api_document, set(), 0)
        except PostgresContractConfigurationError:
            raise
        except BaseException:
            raise PostgresContractConfigurationError() from None

    def validate(
        self,
        value: Mapping[str, Any],
        schema_name: Optional[str] = None,
    ) -> None:
        if not isinstance(value, Mapping) or (
            schema_name is not None and not isinstance(schema_name, str)
        ):
            raise PostgresContractValidationError()
        try:
            schema, document = self._select_schema(schema_name)
            _validate_schema(value, schema, document, 0)
        except _InvalidValue:
            raise PostgresContractValidationError() from None
        except _InvalidSchema:
            raise PostgresContractConfigurationError() from None
        return None

    def _select_schema(
        self,
        schema_name: Optional[str],
    ) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
        if self._component == "iam":
            if schema_name is None:
                return self._event_document, self._event_document
            if self._iam_response_schemas is not None:
                schema = self._iam_response_schemas.get(schema_name)
                if schema is not None:
                    return schema, self._api_document
        elif self._component == "profile":
            if schema_name in _PROFILE_EVENT_SCHEMAS:
                definitions = self._event_document.get("$defs")
                if not isinstance(definitions, Mapping):
                    raise _InvalidSchema
                schema = definitions.get(schema_name)
                if not isinstance(schema, Mapping):
                    raise _InvalidSchema
                return schema, self._event_document
            if schema_name == "CreatorProfileCommandResponse":
                return self._response_schema, self._api_document
        elif schema_name == "demand-v1":
            return self._event_document, self._event_document
        elif schema_name == "DemandDto":
            return self._response_schema, self._api_document
        raise _InvalidValue

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(component={self._component!r}, "
            "resources=<digest-pinned>)"
        )


class ProfilePostgresContractValidator(_PackagedPostgresContractValidator):
    def __init__(
        self,
        *,
        resource_loader: Callable[[str], bytes] = _default_resource_loader,
    ) -> None:
        super().__init__(component="profile", resource_loader=resource_loader)


class DemandPostgresContractValidator(_PackagedPostgresContractValidator):
    def __init__(
        self,
        *,
        resource_loader: Callable[[str], bytes] = _default_resource_loader,
    ) -> None:
        super().__init__(component="demand", resource_loader=resource_loader)


class IamPostgresContractValidator(_PackagedPostgresContractValidator):
    def __init__(
        self,
        *,
        resource_loader: Callable[[str], bytes] = _default_resource_loader,
    ) -> None:
        super().__init__(component="iam", resource_loader=resource_loader)


def _response_schema(component: str) -> Mapping[str, Any]:
    if component == "iam":
        return {"$ref": "#/components/schemas/PlatformUserAdminDto"}
    if component == "profile":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["profile_id", "aggregate_version", "status"],
            "properties": {
                "profile_id": {"$ref": "#/components/schemas/OpaqueId"},
                "aggregate_version": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2_147_483_647,
                },
                "status": {
                    "$ref": "#/components/schemas/CreatorProfileStatus"
                },
            },
        }
    if component == "demand":
        return {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "aggregate_version",
                "demand_id",
                "demand_version_id",
                "status",
            ],
            "properties": {
                "aggregate_version": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2_147_483_647,
                },
                "demand_id": {"$ref": "#/components/schemas/OpaqueId"},
                "demand_version_id": {
                    "$ref": "#/components/schemas/OpaqueId"
                },
                "status": {"$ref": "#/components/schemas/DemandStatus"},
            },
        }
    raise _InvalidSchema


def _audit_schema(
    schema: Any,
    document: Mapping[str, Any],
    seen: set[int],
    depth: int,
) -> None:
    if depth > 64 or not isinstance(schema, Mapping):
        raise _InvalidSchema
    identity = id(schema)
    if identity in seen:
        return
    seen.add(identity)
    if set(schema).difference(_SCHEMA_KEYS):
        raise _InvalidSchema
    if "$schema" in schema and schema["$schema"] != _DIALECT:
        raise _InvalidSchema
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise _InvalidSchema
        _audit_schema(
            _resolve_reference(document, reference),
            document,
            seen,
            depth + 1,
        )
    for keyword in ("$defs", "properties"):
        if keyword in schema:
            values = schema[keyword]
            if not isinstance(values, Mapping) or any(
                not isinstance(name, str) for name in values
            ):
                raise _InvalidSchema
            for child in values.values():
                _audit_schema(child, document, seen, depth + 1)
    for keyword in ("oneOf", "allOf"):
        if keyword in schema:
            values = schema[keyword]
            if (
                not isinstance(values, Sequence)
                or isinstance(values, (str, bytes))
                or not values
            ):
                raise _InvalidSchema
            for child in values:
                _audit_schema(child, document, seen, depth + 1)
    if "items" in schema:
        _audit_schema(schema["items"], document, seen, depth + 1)
    for keyword in ("if", "then"):
        if keyword in schema:
            _audit_schema(schema[keyword], document, seen, depth + 1)
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        _audit_schema(additional, document, seen, depth + 1)
    _audit_scalar_keywords(schema)


def _audit_scalar_keywords(schema: Mapping[str, Any]) -> None:
    if "type" in schema and schema["type"] not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        raise _InvalidSchema
    if "required" in schema and (
        not isinstance(schema["required"], list)
        or len(set(schema["required"])) != len(schema["required"])
        or any(not isinstance(item, str) for item in schema["required"])
    ):
        raise _InvalidSchema
    if "enum" in schema and (
        not isinstance(schema["enum"], list) or not schema["enum"]
    ):
        raise _InvalidSchema
    for name in (
        "minProperties",
        "maxProperties",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
    ):
        if name in schema and (
            type(schema[name]) is not int or schema[name] < 0
        ):
            raise _InvalidSchema
    for name in ("minimum", "maximum"):
        if name in schema and (
            isinstance(schema[name], bool)
            or not isinstance(schema[name], (int, float))
            or not math.isfinite(schema[name])
        ):
            raise _InvalidSchema
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise _InvalidSchema
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise _InvalidSchema
        try:
            re.compile(schema["pattern"])
        except re.error:
            raise _InvalidSchema from None
    if "format" in schema and schema["format"] not in {"date-time", "uuid"}:
        raise _InvalidSchema


def _resolve_reference(document: Mapping[str, Any], reference: str) -> Any:
    value: Any = document
    try:
        for raw_segment in reference[2:].split("/"):
            segment = raw_segment.replace("~1", "/").replace("~0", "~")
            if not isinstance(value, Mapping) or segment not in value:
                raise _InvalidSchema
            value = value[segment]
    except (KeyError, TypeError):
        raise _InvalidSchema from None
    if not isinstance(value, Mapping):
        raise _InvalidSchema
    return value


def _validate_schema(
    value: Any,
    schema: Mapping[str, Any],
    document: Mapping[str, Any],
    depth: int,
) -> None:
    if depth > 64:
        raise _InvalidValue
    if "$ref" in schema:
        _validate_schema(
            value,
            _resolve_reference(document, schema["$ref"]),
            document,
            depth + 1,
        )
    if "allOf" in schema:
        for child in schema["allOf"]:
            _validate_schema(value, child, document, depth + 1)
    if "oneOf" in schema:
        matches = 0
        for child in schema["oneOf"]:
            try:
                _validate_schema(value, child, document, depth + 1)
            except _InvalidValue:
                continue
            matches += 1
        if matches != 1:
            raise _InvalidValue
    if "if" in schema:
        try:
            _validate_schema(value, schema["if"], document, depth + 1)
        except _InvalidValue:
            pass
        else:
            if "then" in schema:
                _validate_schema(value, schema["then"], document, depth + 1)
    if "type" in schema and not _matches_type(value, schema["type"]):
        raise _InvalidValue
    if "const" in schema and not _json_equal(value, schema["const"]):
        raise _InvalidValue
    if "enum" in schema and not any(
        _json_equal(value, candidate) for candidate in schema["enum"]
    ):
        raise _InvalidValue

    if isinstance(value, Mapping):
        _validate_object(value, schema, document, depth)
    if isinstance(value, (list, tuple)):
        _validate_array(value, schema, document, depth)
    if isinstance(value, str):
        _validate_string(value, schema)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise _InvalidValue
        if "minimum" in schema and value < schema["minimum"]:
            raise _InvalidValue
        if "maximum" in schema and value > schema["maximum"]:
            raise _InvalidValue


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, (list, tuple)),
        "string": isinstance(value, str),
        "integer": type(value) is int,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }[expected]


def _validate_object(
    value: Mapping[Any, Any],
    schema: Mapping[str, Any],
    document: Mapping[str, Any],
    depth: int,
) -> None:
    if any(not isinstance(key, str) for key in value):
        raise _InvalidValue
    if "minProperties" in schema and len(value) < schema["minProperties"]:
        raise _InvalidValue
    if "maxProperties" in schema and len(value) > schema["maxProperties"]:
        raise _InvalidValue
    required = schema.get("required", ())
    if any(name not in value for name in required):
        raise _InvalidValue
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        raise _InvalidSchema
    additional = schema.get("additionalProperties", True)
    for name, item in value.items():
        child = properties.get(name)
        if child is not None:
            _validate_schema(item, child, document, depth + 1)
        elif additional is False:
            raise _InvalidValue
        elif isinstance(additional, Mapping):
            _validate_schema(item, additional, document, depth + 1)


def _validate_array(
    value: Sequence[Any],
    schema: Mapping[str, Any],
    document: Mapping[str, Any],
    depth: int,
) -> None:
    if "minItems" in schema and len(value) < schema["minItems"]:
        raise _InvalidValue
    if "maxItems" in schema and len(value) > schema["maxItems"]:
        raise _InvalidValue
    if schema.get("uniqueItems") is True:
        for index, item in enumerate(value):
            if any(_json_equal(item, prior) for prior in value[:index]):
                raise _InvalidValue
    if "items" in schema:
        for item in value:
            _validate_schema(item, schema["items"], document, depth + 1)


def _validate_string(value: str, schema: Mapping[str, Any]) -> None:
    if "minLength" in schema and len(value) < schema["minLength"]:
        raise _InvalidValue
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        raise _InvalidValue
    if "pattern" in schema and re.search(schema["pattern"], value) is None:
        raise _InvalidValue
    if schema.get("format") == "date-time":
        match = _RFC3339_DATETIME.fullmatch(value)
        if match is None or match.group("zone") == "-00:00":
            raise _InvalidValue
        encoded = match.group("whole")
        fraction = match.group("fraction")
        if fraction is not None:
            # RFC 3339 permits arbitrary secfrac precision.  Normalize only
            # the parser probe so Python 3.9 can validate every legal width.
            encoded += "." + fraction[:6].ljust(6, "0")
        zone = match.group("zone")
        encoded += "+00:00" if zone == "Z" else zone
        try:
            parsed = datetime.fromisoformat(encoded)
        except ValueError:
            raise _InvalidValue from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise _InvalidValue
    elif schema.get("format") == "uuid":
        from uuid import UUID

        try:
            parsed_uuid = UUID(value)
        except ValueError:
            raise _InvalidValue from None
        if str(parsed_uuid) != value:
            raise _InvalidValue


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if left is None or right is None:
        return left is right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return math.isfinite(left) and math.isfinite(right) and left == right
    return type(left) is type(right) and left == right


__all__ = [
    "DemandPostgresContractValidator",
    "IamPostgresContractValidator",
    "PostgresContractConfigurationError",
    "PostgresContractValidationError",
    "ProfilePostgresContractValidator",
]
