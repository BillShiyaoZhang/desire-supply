"""Reviewed, synthetic-only seed plan for ``INTERNAL_SANDBOX``.

The manifest is a command plan, never a table fixture.  It identifies the
authoritative Taxonomy/Demand versions and the public command interfaces that
must be used.  Missing production provisioning/projection ports remain named
blockers; this module does not turn them into owner SQL or direct ``ACTIVE``
facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from importlib import resources
import json
import re
from typing import Any, Dict, Mapping, Tuple
import unicodedata
from uuid import UUID

from ..demand.ports.commands import DemandRuleRequirement
from ..taxonomy.domain import ValidatedTaxonomyRelease
from .synthetic_taxonomy import build_internal_sandbox_taxonomy_release


_MAXIMUM_MANIFEST_BYTES = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")

INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256 = bytes.fromhex(
    "418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d"
)

_OPERATION_SEQUENCE = (
    "PublishTaxonomyBundle",
    "CaptureTaxonomyConsumerRelease",
    "ApplyTaxonomyBundleToConsumer",
    "PublishPolicyBundle",
    "IssueAccessInvitation",
    "AcceptAccessInvitation",
    "CreateCreatorProfile",
    "CreateDemand",
)
_PROVISIONING_COMMANDS = (
    "PublishPolicyBundle",
    "IssueAccessInvitation",
    "AcceptAccessInvitation",
)
_RUNTIME_INPUTS = (
    "TAXONOMY_WORKLOAD_CREDENTIAL",
    "TAXONOMY_RECEIPT_HMAC_KEY",
    "IAM_POLICY_PUBLICATION_EVIDENCE",
    "INVITATION_TOKEN_MATERIAL",
    "OIDC_SANDBOX_BINDING",
    "COMMAND_IDEMPOTENCY_KEYS",
)
_BLOCKERS: Tuple[str, ...] = ()


class InternalSandboxSyntheticSeedError(RuntimeError):
    """Closed, non-sensitive manifest or orchestration failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _InvalidManifest(Exception):
    pass


@dataclass(frozen=True)
class SyntheticAccountSlot:
    slot_code: str
    role_codes: Tuple[str, ...]
    invitation_purpose: str
    provisioning_commands: Tuple[str, ...]


@dataclass(frozen=True)
class SyntheticBusinessDraft:
    resource_kind: str
    owner_slot_code: str
    create_command: str
    taxonomy_bundle_id: str
    funds_amount_minor: int
    contains_real_data: bool


@dataclass(frozen=True)
class InternalSandboxSyntheticSeedPlan:
    fixture_id: str
    manifest_sha256: str
    taxonomy_bundle_id: str
    taxonomy_family_code: str
    taxonomy_semantic_version: str
    taxonomy_consumer_codes: Tuple[str, ...]
    taxonomy_release: ValidatedTaxonomyRelease = field(repr=False)
    taxonomy_workload_principal_id: str
    taxonomy_workload_attestation_sha256: str = field(repr=False)
    taxonomy_authority_valid_until: datetime
    taxonomy_credential_binding_mode: str
    taxonomy_profile_consumer_code: str
    taxonomy_profile_consumer_job_id: str
    taxonomy_consumer_authorization_digest: str = field(repr=False)
    rule_requirement: DemandRuleRequirement = field(repr=False)
    account_slots: Tuple[SyntheticAccountSlot, ...]
    business_drafts: Tuple[SyntheticBusinessDraft, ...] = field(repr=False)
    operation_sequence: Tuple[str, ...]
    required_runtime_inputs: Tuple[str, ...] = field(repr=False)
    blockers: Tuple[str, ...]

    @property
    def account_slot_codes(self) -> Tuple[str, ...]:
        return tuple(item.slot_code for item in self.account_slots)

    @property
    def business_resource_kinds(self) -> Tuple[str, ...]:
        return tuple(item.resource_kind for item in self.business_drafts)

    @property
    def is_executable(self) -> bool:
        return not self.blockers

    def validate_rule_requirement(self, value: Any) -> None:
        if not isinstance(value, DemandRuleRequirement) or value != self.rule_requirement:
            raise InternalSandboxSyntheticSeedError(
                "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED"
            ) from None
        return None

    def require_executable(self) -> None:
        if not self.is_executable:
            raise InternalSandboxSyntheticSeedError(
                "INTERNAL_SANDBOX_SYNTHETIC_SEED_BLOCKED"
            ) from None
        return None

    def __repr__(self) -> str:
        return (
            "InternalSandboxSyntheticSeedPlan("
            f"fixture_id={self.fixture_id!r}, "
            f"taxonomy_bundle_id={self.taxonomy_bundle_id!r}, "
            f"account_slots={self.account_slot_codes!r}, "
            f"business_resources={self.business_resource_kinds!r}, "
            f"blockers={self.blockers!r})"
        )


def parse_internal_sandbox_synthetic_seed(
    raw: bytes,
    *,
    expected_sha256: bytes = INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256,
) -> InternalSandboxSyntheticSeedPlan:
    """Parse exact canonical bytes against an explicit reviewed digest."""

    try:
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= _MAXIMUM_MANIFEST_BYTES
            or not isinstance(expected_sha256, bytes)
            or len(expected_sha256) != 32
            or not hmac.compare_digest(hashlib.sha256(raw).digest(), expected_sha256)
            or not raw.endswith(b"\n")
            or raw.endswith(b"\n\n")
            or b"\r" in raw
            or b"\x00" in raw
            or raw.startswith(b"\xef\xbb\xbf")
        ):
            raise _InvalidManifest
        document = json.loads(
            raw.decode("ascii", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_float=_invalid,
            parse_constant=_invalid,
        )
        canonical = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        if not hmac.compare_digest(canonical, raw):
            raise _InvalidManifest
        root = _closed(
            document,
            (
                "account_slots",
                "blockers",
                "business_drafts",
                "demand_rule_requirement",
                "deployment_mode",
                "external_side_effects_enabled",
                "fixture_id",
                "operation_sequence",
                "real_funds",
                "real_person_data",
                "required_runtime_inputs",
                "schema_name",
                "synthetic",
                "taxonomy",
                "taxonomy_seed_authority",
            ),
        )
        if (
            root["schema_name"] != "desire-internal-sandbox-synthetic-seed-v1"
            or root["fixture_id"] != "internal-sandbox-g1-synthetic-v1"
            or root["deployment_mode"] != "INTERNAL_SANDBOX"
            or root["synthetic"] is not True
            or root["real_person_data"] is not False
            or root["real_funds"] is not False
            or root["external_side_effects_enabled"] is not False
        ):
            raise _InvalidManifest
        _canonical_text(root["fixture_id"])
        operation_sequence = _exact_strings(
            root["operation_sequence"], _OPERATION_SEQUENCE
        )
        runtime_inputs = _exact_strings(
            root["required_runtime_inputs"], _RUNTIME_INPUTS
        )
        blockers = _exact_strings(root["blockers"], _BLOCKERS)
        taxonomy = _taxonomy(root["taxonomy"])
        authority = _taxonomy_seed_authority(root["taxonomy_seed_authority"])
        release = build_internal_sandbox_taxonomy_release()
        if (
            release.candidate.manifest.bundle_id != taxonomy[0]
            or release.candidate.manifest.family_code != taxonomy[1]
            or release.candidate.manifest.semantic_version != taxonomy[2]
            or release.release_manifest_sha256 != taxonomy[4]
            or release.selector_digest != taxonomy[5]
        ):
            raise _InvalidManifest
        requirement = _rule_requirement(root["demand_rule_requirement"])
        if requirement.taxonomy_bundle_id != taxonomy[0]:
            raise _InvalidManifest
        accounts = _account_slots(root["account_slots"])
        drafts = _business_drafts(root["business_drafts"], taxonomy[0])
        return InternalSandboxSyntheticSeedPlan(
            fixture_id=root["fixture_id"],
            manifest_sha256=hashlib.sha256(raw).hexdigest(),
            taxonomy_bundle_id=taxonomy[0],
            taxonomy_family_code=taxonomy[1],
            taxonomy_semantic_version=taxonomy[2],
            taxonomy_consumer_codes=taxonomy[3],
            taxonomy_release=release,
            taxonomy_workload_principal_id=authority[0],
            taxonomy_workload_attestation_sha256=authority[1],
            taxonomy_authority_valid_until=authority[2],
            taxonomy_credential_binding_mode=authority[3],
            taxonomy_profile_consumer_code=authority[4],
            taxonomy_profile_consumer_job_id=authority[5],
            taxonomy_consumer_authorization_digest=authority[6],
            rule_requirement=requirement,
            account_slots=accounts,
            business_drafts=drafts,
            operation_sequence=operation_sequence,
            required_runtime_inputs=runtime_inputs,
            blockers=blockers,
        )
    except InternalSandboxSyntheticSeedError:
        raise
    except BaseException:
        raise InternalSandboxSyntheticSeedError(
            "INVALID_INTERNAL_SANDBOX_SYNTHETIC_SEED"
        ) from None


def load_internal_sandbox_synthetic_seed() -> InternalSandboxSyntheticSeedPlan:
    """Load the one reviewed package resource; never search cwd/environment."""

    try:
        raw = (
            resources.files("desire_platform.internal_pilot.fixtures")
            .joinpath("internal_sandbox_seed_v1.json")
            .read_bytes()
        )
    except BaseException:
        raise InternalSandboxSyntheticSeedError(
            "INVALID_INTERNAL_SANDBOX_SYNTHETIC_SEED"
        ) from None
    return parse_internal_sandbox_synthetic_seed(raw)


def _taxonomy(
    value: Any,
) -> Tuple[str, str, str, Tuple[str, ...], str, str]:
    document = _closed(
        value,
        (
            "bundle_id",
            "consumer_codes",
            "family_code",
            "release_manifest_sha256",
            "selector_digest",
            "semantic_version",
        ),
    )
    bundle_id = _uuid(document["bundle_id"])
    family = _canonical_text(document["family_code"])
    semantic_version = _canonical_text(document["semantic_version"])
    consumers = _exact_strings(
        document["consumer_codes"], ("DEMAND", "MATCHING", "PROFILE")
    )
    release_manifest_sha256 = _canonical_text(
        document["release_manifest_sha256"]
    )
    selector_digest = _canonical_text(document["selector_digest"])
    if family != "PLATFORM_WORK_V1" or _SEMVER.fullmatch(semantic_version) is None:
        raise _InvalidManifest
    if (
        semantic_version != "1.0.0"
        or _SHA256.fullmatch(release_manifest_sha256) is None
        or _SHA256.fullmatch(selector_digest) is None
        or not any(bytes.fromhex(release_manifest_sha256))
        or not any(bytes.fromhex(selector_digest))
    ):
        raise _InvalidManifest
    return (
        bundle_id,
        family,
        semantic_version,
        consumers,
        release_manifest_sha256,
        selector_digest,
    )


def _taxonomy_seed_authority(
    value: Any,
) -> Tuple[str, str, datetime, str, str, str, str]:
    document = _closed(
        value,
        (
            "authority_valid_until",
            "consumer_authorization_digest",
            "consumer_code",
            "consumer_job_id",
            "credential_binding_mode",
            "workload_attestation_sha256",
            "workload_principal_id",
        ),
    )
    principal = _canonical_text(document["workload_principal_id"])
    attestation = _canonical_text(document["workload_attestation_sha256"])
    valid_until = _timestamp(document["authority_valid_until"])
    binding_mode = _canonical_text(document["credential_binding_mode"])
    consumer_code = _canonical_text(document["consumer_code"])
    consumer_job_id = _canonical_text(document["consumer_job_id"])
    authorization = _canonical_text(document["consumer_authorization_digest"])
    if (
        principal != "internal_sandbox_taxonomy_seed_v1"
        or attestation
        != "997cd36982083be3fd8f38e0069c2c20b342b1e89ba8e1225ce402fdfd46e501"
        or valid_until != datetime(2100, 1, 1, tzinfo=timezone.utc)
        or binding_mode != "RUNTIME_SHA256"
        or consumer_code != "PROFILE"
        or consumer_job_id != "internal_sandbox_profile_seed_job_v1"
        or authorization
        != "b1fc57d727ca30377601e05afd5eccdb787b59f82072a027a203934696496d33"
        or _SHA256.fullmatch(attestation) is None
        or _SHA256.fullmatch(authorization) is None
    ):
        raise _InvalidManifest
    return (
        principal,
        attestation,
        valid_until,
        binding_mode,
        consumer_code,
        consumer_job_id,
        authorization,
    )


def _rule_requirement(value: Any) -> DemandRuleRequirement:
    document = _closed(
        value,
        (
            "budget_rule_bundle_id",
            "composite_rule_requirement_id",
            "effective_at",
            "effective_until",
            "matching_rule_bundle_id",
            "reason_code_bundle_id",
            "requirement_sha256",
            "risk_rule_bundle_id",
            "taxonomy_bundle_id",
        ),
    )
    identifiers = (
        _uuid(document["taxonomy_bundle_id"]),
        _uuid(document["budget_rule_bundle_id"]),
        _uuid(document["risk_rule_bundle_id"]),
        _uuid(document["matching_rule_bundle_id"]),
        _uuid(document["reason_code_bundle_id"]),
        _uuid(document["composite_rule_requirement_id"]),
    )
    digest = _canonical_text(document["requirement_sha256"])
    effective_at = _timestamp(document["effective_at"])
    effective_until = _timestamp(document["effective_until"])
    if (
        len(set(identifiers)) != len(identifiers)
        or _SHA256.fullmatch(digest) is None
        or not any(bytes.fromhex(digest))
        or effective_at >= effective_until
    ):
        raise _InvalidManifest
    return DemandRuleRequirement(
        taxonomy_bundle_id=identifiers[0],
        budget_rule_bundle_id=identifiers[1],
        risk_rule_bundle_id=identifiers[2],
        matching_rule_bundle_id=identifiers[3],
        reason_code_bundle_id=identifiers[4],
        composite_rule_requirement_id=identifiers[5],
        effective_at=effective_at,
        effective_until=effective_until,
        requirement_sha256=digest,
    )


def _account_slots(value: Any) -> Tuple[SyntheticAccountSlot, ...]:
    if not isinstance(value, list) or len(value) != 2:
        raise _InvalidManifest
    expected = (
        ("CREATOR", ("CREATOR",), "CREATOR_ENROLLMENT"),
        ("DEMAND_OWNER", ("DEMAND_OWNER",), "ORGANIZATION_MEMBERSHIP"),
    )
    result = []
    for candidate, (slot_code, roles, purpose) in zip(value, expected):
        item = _closed(
            candidate,
            (
                "invitation_purpose",
                "provisioning_commands",
                "role_codes",
                "slot_code",
            ),
        )
        if (
            item["slot_code"] != slot_code
            or item["invitation_purpose"] != purpose
            or _exact_strings(item["role_codes"], roles) != roles
            or _exact_strings(
                item["provisioning_commands"], _PROVISIONING_COMMANDS
            )
            != _PROVISIONING_COMMANDS
        ):
            raise _InvalidManifest
        result.append(
            SyntheticAccountSlot(
                slot_code=slot_code,
                role_codes=roles,
                invitation_purpose=purpose,
                provisioning_commands=_PROVISIONING_COMMANDS,
            )
        )
    return tuple(result)


def _business_drafts(
    value: Any, taxonomy_bundle_id: str
) -> Tuple[SyntheticBusinessDraft, ...]:
    if not isinstance(value, list) or len(value) != 2:
        raise _InvalidManifest
    expected = (
        ("CREATOR_PROFILE", "CREATOR", "CreateCreatorProfile"),
        ("DEMAND", "DEMAND_OWNER", "CreateDemand"),
    )
    result = []
    for candidate, (kind, owner, command) in zip(value, expected):
        item = _closed(
            candidate,
            (
                "contains_real_data",
                "create_command",
                "funds_amount_minor",
                "owner_slot_code",
                "resource_kind",
                "taxonomy_bundle_id",
            ),
        )
        if (
            item["resource_kind"] != kind
            or item["owner_slot_code"] != owner
            or item["create_command"] != command
            or _uuid(item["taxonomy_bundle_id"]) != taxonomy_bundle_id
            or type(item["funds_amount_minor"]) is not int
            or item["funds_amount_minor"] != 0
            or item["contains_real_data"] is not False
        ):
            raise _InvalidManifest
        result.append(
            SyntheticBusinessDraft(
                resource_kind=kind,
                owner_slot_code=owner,
                create_command=command,
                taxonomy_bundle_id=taxonomy_bundle_id,
                funds_amount_minor=0,
                contains_real_data=False,
            )
        )
    return tuple(result)


def _closed(value: Any, keys: Tuple[str, ...]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != frozenset(keys):
        raise _InvalidManifest
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise _InvalidManifest
        result[key] = value
    return result


def _invalid(*_values: Any) -> Any:
    raise _InvalidManifest


def _canonical_text(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _InvalidManifest
    return value


def _uuid(value: Any) -> str:
    candidate = _canonical_text(value)
    try:
        result = UUID(candidate)
    except (AttributeError, TypeError, ValueError):
        raise _InvalidManifest from None
    if result.int == 0 or str(result) != candidate:
        raise _InvalidManifest
    return candidate


def _timestamp(value: Any) -> datetime:
    candidate = _canonical_text(value)
    try:
        result = datetime.strptime(candidate, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise _InvalidManifest from None
    if result.isoformat().replace("+00:00", "Z") != candidate:
        raise _InvalidManifest
    return result


def _exact_strings(value: Any, expected: Tuple[str, ...]) -> Tuple[str, ...]:
    if not isinstance(value, list) or tuple(value) != expected:
        raise _InvalidManifest
    for item in value:
        _canonical_text(item)
    return tuple(value)


__all__ = [
    "INTERNAL_SANDBOX_SYNTHETIC_SEED_SHA256",
    "InternalSandboxSyntheticSeedError",
    "InternalSandboxSyntheticSeedPlan",
    "SyntheticAccountSlot",
    "SyntheticBusinessDraft",
    "load_internal_sandbox_synthetic_seed",
    "parse_internal_sandbox_synthetic_seed",
]
