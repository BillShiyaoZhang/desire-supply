"""Generate a digest-only manifest for reviewed, real OIDC identities.

This deployment-only boundary is deliberately separate from the fictional
INTERNAL_SANDBOX generator.  It accepts only the subject and provider-verified
email for each account in the pinned ten-account template.  User IDs, roles,
grants, and source-file bindings remain exclusively template-owned.

Raw identity values are read from a directory-FD-anchored regular-file snapshot
and reduced with the same active keys and byte domains as the online OIDC
adapters.  Every mutable input or derived buffer is zeroed before control
returns; immutable interpreter temporaries are never retained, returned, or
logged.  The resulting document is the existing digest-only identity bootstrap
manifest consumed by the normal parse/apply/verify closure.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import (
    Any,
    Callable,
    Dict,
    Mapping,
    NoReturn,
    Optional,
    Sequence,
    TextIO,
    Tuple,
)
import unicodedata
from urllib.parse import urlsplit

from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
    _read_regular_config_file,
    load_internal_sandbox_deployment_config_pointer,
)
from desire_platform.internal_pilot.secrets import (
    FileSecretCarrier,
    FilesystemSecretProvider,
    parse_file_secret_manifest,
)
from desire_platform.runtime.config import parse_runtime_config

from .identity_bootstrap import (
    IDENTITY_BOOTSTRAP_SCHEMA,
    parse_internal_sandbox_identity_manifest,
)
from .identity_bootstrap_manifest import (
    IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA,
    IdentityBootstrapManifestGenerationError,
    _ACCOUNT_KEYS,
    _TEMPLATE_CONTACT_KEYS,
    _TEMPLATE_IDENTITY_KEYS,
    _absolute_path,
    _atomic_write,
    _canonical,
    _closed_object,
    _output_path,
    _parse_template,
    _read_source_descriptor,
    _source_name,
    _source_metadata_fingerprint,
    _source_root,
    _zero,
)


PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV = (
    "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_TEMPLATE_FILE"
)
PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV = (
    "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256"
)
PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV = (
    "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_SOURCE_ROOT"
)
PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV = (
    "DESIRE_PREPROVISIONED_OIDC_IDENTITY_BOOTSTRAP_OUTPUT_FILE"
)

_SUBJECT_PURPOSE = "OIDC_SUBJECT_DIGEST"
_RECIPIENT_PURPOSE = "OIDC_RECIPIENT_BINDING"
_RECIPIENT_DOMAIN = b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
_DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
_ALLOWED_ENVIRONMENT = frozenset(
    (
        DEPLOYMENT_CONFIG_POINTER_ENV,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
        PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    )
)


class PreprovisionedIdentityBootstrapManifestGenerationError(RuntimeError):
    """Stable, non-reflective failure at the real-identity generation edge."""

    def __init__(
        self,
        code: str = "PREPROVISIONED_IDENTITY_BOOTSTRAP_MANIFEST_INVALID",
    ) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, repr=False)
class GeneratedPreprovisionedIdentityBootstrapManifest:
    canonical_bytes: bytes = field(repr=False)
    manifest_sha256: str
    revision: int
    account_count: int

    def __repr__(self) -> str:
        return (
            "GeneratedPreprovisionedIdentityBootstrapManifest("
            "manifest_sha256=%r, revision=%r, account_count=%r)"
            % (self.manifest_sha256, self.revision, self.account_count)
        )


def generate_preprovisioned_identity_bootstrap_manifest(
    *,
    template_bytes: bytes,
    expected_template_sha256: str,
    issuer: str,
    subject_digest_key_id: str,
    subject_digest_key: bytearray,
    recipient_binding_key_id: str,
    recipient_binding_key: bytearray,
    read_source: Callable[[str], bytearray],
) -> GeneratedPreprovisionedIdentityBootstrapManifest:
    """Reduce reviewed real-provider identities to the existing manifest.

    Ownership of each ``bytearray`` returned by ``read_source`` transfers to
    this function.  Every transferred source and derived mutable buffer is
    zeroed on both success and failure.  Key buffers remain caller-owned.
    """

    sensitive_buffers: list[bytearray] = []
    try:
        _require_key(
            subject_digest_key_id,
            subject_digest_key,
            maximum_size=4_096,
        )
        _require_key(
            recipient_binding_key_id,
            recipient_binding_key,
            maximum_size=64,
        )
        _require_issuer(issuer)
        if not callable(read_source):
            _invalid()
        template = _parse_template(
            template_bytes,
            expected_template_sha256=expected_template_sha256,
        )

        account_inputs: list[tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], str, str]] = []
        source_names: list[str] = []
        for value in template["accounts"]:
            account = _closed_object(value, _ACCOUNT_KEYS)
            identity = _closed_object(
                account["external_identity"], _TEMPLATE_IDENTITY_KEYS
            )
            contact = _closed_object(
                account["contact_point"], _TEMPLATE_CONTACT_KEYS
            )
            subject_file = _source_name(
                identity["subject_file_name"], ".subject"
            )
            email_file = _source_name(
                contact["verified_email_file_name"], ".email"
            )
            source_names.extend((subject_file, email_file))
            account_inputs.append(
                (account, identity, contact, subject_file, email_file)
            )
        if len(source_names) != 20 or len(set(source_names)) != 20:
            _invalid()

        generated_accounts: list[Dict[str, Any]] = []
        subject_digests: set[str] = set()
        recipient_digests: set[str] = set()
        for account, identity, contact, subject_file, email_file in account_inputs:
            subject = _take_source(read_source, subject_file, sensitive_buffers)
            email = _take_source(read_source, email_file, sensitive_buffers)

            _decode_identity_text(subject)
            email_text = _decode_identity_text(email)
            normalized_email_text = unicodedata.normalize(
                "NFC", email_text.strip().casefold()
            )
            if not _valid_identity_text(normalized_email_text):
                _invalid()
            try:
                normalized_email = bytearray(
                    normalized_email_text.encode("utf-8", errors="strict")
                )
            except (UnicodeEncodeError, UnicodeError):
                _invalid()
            sensitive_buffers.append(normalized_email)
            if not 1 <= len(normalized_email) <= 512:
                _invalid()

            subject_digest = hmac.new(
                subject_digest_key, digestmod=hashlib.sha256
            )
            subject_digest.update(b"oidc-subject-v1\x00")
            subject_digest.update(issuer.encode("utf-8", errors="strict"))
            subject_digest.update(b"\x00")
            # The provider's opaque subject is deliberately not normalized.
            # Strict UTF-8 validation above guarantees these are exactly the
            # bytes encoded by the online adapter for the same claim string.
            subject_digest.update(subject)

            recipient_digest = hmac.new(
                recipient_binding_key, digestmod=hashlib.sha256
            )
            recipient_digest.update(_RECIPIENT_DOMAIN)
            recipient_digest.update(normalized_email)
            subject_hex = subject_digest.hexdigest()
            recipient_hex = recipient_digest.hexdigest()
            if (
                subject_hex in subject_digests
                or recipient_hex in recipient_digests
            ):
                _invalid()
            subject_digests.add(subject_hex)
            recipient_digests.add(recipient_hex)

            transformed = dict(account)
            transformed["external_identity"] = {
                "id": identity["id"],
                "subject_digest_key_id": subject_digest_key_id,
                "subject_digest_sha256": subject_hex,
            }
            transformed["contact_point"] = {
                "id": contact["id"],
                "recipient_binding_digest_key_id": recipient_binding_key_id,
                "recipient_binding_digest_sha256": recipient_hex,
            }
            generated_accounts.append(transformed)

        output_document = dict(template)
        output_document["accounts"] = generated_accounts
        output_document["issuer"] = issuer
        output_document["schema_name"] = IDENTITY_BOOTSTRAP_SCHEMA
        canonical = _canonical(output_document)
        digest = hashlib.sha256(canonical).hexdigest()
        parsed = parse_internal_sandbox_identity_manifest(
            canonical,
            expected_sha256=digest,
            expected_issuer=issuer,
        )
        return GeneratedPreprovisionedIdentityBootstrapManifest(
            canonical_bytes=canonical,
            manifest_sha256=digest,
            revision=parsed.revision,
            account_count=len(parsed.accounts),
        )
    except PreprovisionedIdentityBootstrapManifestGenerationError:
        raise
    except BaseException:
        _invalid()
    finally:
        for material in sensitive_buffers:
            _zero(material)


def generate_preprovisioned_identity_bootstrap_manifest_file(
    *,
    environment: Mapping[str, str],
    now: datetime,
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> GeneratedPreprovisionedIdentityBootstrapManifest:
    """Resolve active online keys and atomically write one digest manifest."""

    carriers: list[FileSecretCarrier] = []
    source_snapshot: Dict[str, bytearray] = {}
    try:
        if (
            not isinstance(environment, Mapping)
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            _invalid()
        desire_keys = frozenset(
            key
            for key in environment
            if isinstance(key, str) and key.startswith("DESIRE_")
        )
        if desire_keys != _ALLOWED_ENVIRONMENT:
            _invalid()
        reader = _read_regular_config_file if read_bytes is None else read_bytes
        if not callable(reader):
            _invalid()
        deployment = load_internal_sandbox_deployment_config_pointer(
            environment={
                DEPLOYMENT_CONFIG_POINTER_ENV: environment[
                    DEPLOYMENT_CONFIG_POINTER_ENV
                ]
            },
            read_bytes=reader,
        )
        runtime = parse_runtime_config(reader(deployment.runtime_config_path))
        if runtime.identity.environment_id != "internal-sandbox":
            _invalid()

        deployment_path = Path(
            _absolute_path(environment[DEPLOYMENT_CONFIG_POINTER_ENV])
        )
        runtime_path = Path(_absolute_path(deployment.runtime_config_path))
        secret_manifest_path = Path(
            _absolute_path(deployment.secret_manifest_path)
        )
        template_path = Path(
            _absolute_path(
                environment[PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV]
            )
        )
        source_root = _source_root(
            environment[PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV]
        )
        secret_root = Path(deployment.secret_root).resolve(strict=True)
        output_path = _output_path(
            environment[PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV],
            forbidden_roots=(source_root, secret_root),
        )
        _require_isolated_paths(
            template_path=template_path,
            source_root=source_root,
            secret_root=secret_root,
            output_path=output_path,
            forbidden_paths=(
                deployment_path,
                runtime_path,
                secret_manifest_path,
            ),
        )

        requirements = {item.purpose: item for item in runtime.key_requirements}
        if frozenset((_SUBJECT_PURPOSE, _RECIPIENT_PURPOSE)) - frozenset(
            requirements
        ):
            _invalid()
        subject_requirement = requirements[_SUBJECT_PURPOSE]
        recipient_requirement = requirements[_RECIPIENT_PURPOSE]
        if (
            subject_requirement.active_key_id
            != deployment.oidc.subject_digest_key_id
        ):
            _invalid()
        entries = parse_file_secret_manifest(reader(deployment.secret_manifest_path))
        provider = FilesystemSecretProvider(
            allowed_root=secret_root,
            entries=entries,
        )
        subject_carrier = provider.resolve_key(
            _SUBJECT_PURPOSE,
            subject_requirement.active_key_id,
        )
        carriers.append(subject_carrier)
        recipient_carrier = provider.resolve_key(
            _RECIPIENT_PURPOSE,
            recipient_requirement.active_key_id,
        )
        carriers.append(recipient_carrier)
        for carrier in carriers:
            if (
                carrier.status != "ACTIVE"
                or carrier.not_before > now
                or now >= carrier.not_after
            ):
                _invalid()

        template_bytes = reader(str(template_path))
        template_sha256 = environment[
            PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV
        ]
        expected_source_names = _template_source_names(
            template_bytes,
            expected_template_sha256=template_sha256,
        )
        source_snapshot = _read_exact_source_snapshot(
            source_root,
            expected_source_names,
        )
        result = generate_preprovisioned_identity_bootstrap_manifest(
            template_bytes=template_bytes,
            expected_template_sha256=template_sha256,
            issuer=deployment.oidc.issuer,
            subject_digest_key_id=subject_carrier.key_id,
            subject_digest_key=subject_carrier.material,
            recipient_binding_key_id=recipient_carrier.key_id,
            recipient_binding_key=recipient_carrier.material,
            read_source=lambda file_name: source_snapshot.pop(file_name),
        )
        _atomic_write(output_path, result.canonical_bytes)
        return result
    except PreprovisionedIdentityBootstrapManifestGenerationError:
        raise
    except BaseException:
        _invalid()
    finally:
        for material in source_snapshot.values():
            _zero(material)
        for carrier in reversed(carriers):
            carrier.destroy()


def _take_source(
    read_source: Callable[[str], bytearray],
    file_name: str,
    sensitive_buffers: list[bytearray],
) -> bytearray:
    material = read_source(file_name)
    if type(material) is not bytearray:
        _invalid()
    sensitive_buffers.append(material)
    if not 1 <= len(material) <= 512:
        _invalid()
    return material


def _template_source_names(
    template_bytes: bytes,
    *,
    expected_template_sha256: str,
) -> frozenset[str]:
    template = _parse_template(
        template_bytes,
        expected_template_sha256=expected_template_sha256,
    )
    names: list[str] = []
    for value in template["accounts"]:
        account = _closed_object(value, _ACCOUNT_KEYS)
        identity = _closed_object(
            account["external_identity"], _TEMPLATE_IDENTITY_KEYS
        )
        contact = _closed_object(
            account["contact_point"], _TEMPLATE_CONTACT_KEYS
        )
        names.extend(
            (
                _source_name(identity["subject_file_name"], ".subject"),
                _source_name(contact["verified_email_file_name"], ".email"),
            )
        )
    if len(names) != 20 or len(set(names)) != 20:
        _invalid()
    return frozenset(names)


def _read_exact_source_snapshot(
    root: Path,
    expected_names: frozenset[str],
) -> Dict[str, bytearray]:
    if not isinstance(expected_names, frozenset) or len(expected_names) != 20:
        _invalid()
    directory_descriptor = None
    descriptors: Dict[str, int] = {}
    fingerprints: Dict[str, Tuple[int, ...]] = {}
    materials: Dict[str, bytearray] = {}
    transferred = False
    try:
        path_metadata = os.stat(root, follow_symlinks=False)
        directory_descriptor = os.open(
            str(root),
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_metadata = os.fstat(directory_descriptor)
        directory_fingerprint = _source_metadata_fingerprint(
            directory_metadata
        )
        if (
            _source_metadata_fingerprint(path_metadata)
            != directory_fingerprint
            or not stat.S_ISDIR(directory_metadata.st_mode)
        ):
            _invalid()
        try:
            filesystem_read_only = bool(
                os.fstatvfs(directory_descriptor).f_flag
                & getattr(os, "ST_RDONLY", 1)
            )
        except (AttributeError, OSError):
            filesystem_read_only = False
        _require_non_writable_source_metadata(
            directory_metadata,
            filesystem_read_only=filesystem_read_only,
            directory=True,
        )
        _require_snapshot_names(directory_descriptor, expected_names)

        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for name in sorted(expected_names):
            metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            _require_non_writable_source_metadata(
                metadata,
                filesystem_read_only=filesystem_read_only,
                directory=False,
            )
            fingerprint = _source_metadata_fingerprint(metadata)
            descriptor = os.open(
                name,
                flags,
                dir_fd=directory_descriptor,
            )
            if (
                _source_metadata_fingerprint(os.fstat(descriptor))
                != fingerprint
            ):
                os.close(descriptor)
                _invalid()
            descriptors[name] = descriptor
            fingerprints[name] = fingerprint

        _require_snapshot_unchanged(
            root=root,
            directory_descriptor=directory_descriptor,
            directory_fingerprint=directory_fingerprint,
            expected_names=expected_names,
            source_fingerprints=fingerprints,
        )
        for name in sorted(expected_names):
            materials[name] = _read_source_descriptor(
                descriptors[name],
                expected_fingerprint=fingerprints[name],
            )
        _require_snapshot_unchanged(
            root=root,
            directory_descriptor=directory_descriptor,
            directory_fingerprint=directory_fingerprint,
            expected_names=expected_names,
            source_fingerprints=fingerprints,
        )
        transferred = True
        return materials
    except PreprovisionedIdentityBootstrapManifestGenerationError:
        raise
    except IdentityBootstrapManifestGenerationError:
        _invalid()
    except BaseException:
        _invalid()
    finally:
        if not transferred:
            for material in materials.values():
                _zero(material)
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if directory_descriptor is not None:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def _require_snapshot_names(
    directory_descriptor: int,
    expected_names: frozenset[str],
) -> None:
    actual_names: set[str] = set()
    for name in os.listdir(directory_descriptor):
        if name.endswith(".subject"):
            _source_name(name, ".subject")
        elif name.endswith(".email"):
            _source_name(name, ".email")
        else:
            _invalid()
        if name in actual_names:
            _invalid()
        actual_names.add(name)
    if actual_names != expected_names:
        _invalid()


def _require_snapshot_unchanged(
    *,
    root: Path,
    directory_descriptor: int,
    directory_fingerprint: Tuple[int, ...],
    expected_names: frozenset[str],
    source_fingerprints: Mapping[str, Tuple[int, ...]],
) -> None:
    if (
        _source_metadata_fingerprint(os.fstat(directory_descriptor))
        != directory_fingerprint
        or _source_metadata_fingerprint(os.stat(root, follow_symlinks=False))
        != directory_fingerprint
    ):
        _invalid()
    _require_snapshot_names(directory_descriptor, expected_names)
    if frozenset(source_fingerprints) != expected_names:
        _invalid()
    for name in sorted(expected_names):
        if (
            _source_metadata_fingerprint(
                os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            )
            != source_fingerprints[name]
        ):
            _invalid()


def _require_non_writable_source_metadata(
    metadata: os.stat_result,
    *,
    filesystem_read_only: bool,
    directory: bool,
) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or (not directory and not 1 <= metadata.st_size <= 512)
        or (not directory and metadata.st_nlink != 1)
        or (
            not filesystem_read_only
            and stat.S_IMODE(metadata.st_mode) & 0o222
        )
    ):
        _invalid()


def _decode_identity_text(material: bytearray) -> str:
    try:
        value = material.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, UnicodeError):
        _invalid()
    if not _valid_identity_text(value):
        _invalid()
    return value


def _valid_identity_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            for character in value
        )
    )


def _require_key(
    key_id: Any,
    material: Any,
    *,
    maximum_size: int,
) -> None:
    if (
        not isinstance(key_id, str)
        or _KEY_ID.fullmatch(key_id) is None
        or type(material) is not bytearray
        or not 32 <= len(material) <= maximum_size
        or not any(material)
    ):
        _invalid()


def _require_issuer(value: Any) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or not value.isascii()
        or value != value.strip()
        or value.endswith("/")
        or not _valid_identity_text(value)
    ):
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
        or not parsed.hostname
        or parsed.hostname != parsed.hostname.lower()
        or _DNS_NAME.fullmatch(parsed.hostname) is None
        or port is not None
        or parsed.netloc != parsed.hostname
        or parsed.query
        or parsed.fragment
        or any(token in parsed.path for token in ("%", "\\", "//", "/./", "/../"))
    ):
        _invalid()


def _require_isolated_paths(
    *,
    template_path: Path,
    source_root: Path,
    secret_root: Path,
    output_path: Path,
    forbidden_paths: Tuple[Path, ...],
) -> None:
    output_root = output_path.parent
    if (
        not isinstance(forbidden_paths, tuple)
        or len(forbidden_paths) != 3
        or _overlap(source_root, secret_root)
        or _overlap(source_root, output_root)
        or _overlap(secret_root, output_root)
        or source_root in template_path.parents
        or secret_root in template_path.parents
        or _path_aliases(output_path, template_path)
        or any(_path_aliases(output_path, path) for path in forbidden_paths)
    ):
        _invalid()


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _path_aliases(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        _invalid()


def _invalid() -> NoReturn:
    raise PreprovisionedIdentityBootstrapManifestGenerationError()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> int:
    parser = argparse.ArgumentParser(
        prog=(
            "python -m desire_platform.deployment."
            "preprovisioned_identity_bootstrap_manifest"
        )
    )
    parser.add_argument("action", choices=("generate",))
    parser.parse_args(argv)
    values = os.environ if environment is None else environment
    try:
        generated = generate_preprovisioned_identity_bootstrap_manifest_file(
            environment=values,
            now=clock(),
        )
    except PreprovisionedIdentityBootstrapManifestGenerationError as error:
        stderr.write(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 78
    except BaseException:
        stderr.write(
            '{"code":"PREPROVISIONED_IDENTITY_BOOTSTRAP_MANIFEST_INVALID",'
            '"status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(
        json.dumps(
            {
                "account_count": generated.account_count,
                "manifest_sha256": generated.manifest_sha256,
                "revision": generated.revision,
                "status": "PREPROVISIONED_IDENTITY_BOOTSTRAP_MANIFEST_READY",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "GeneratedPreprovisionedIdentityBootstrapManifest",
    "IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV",
    "PREPROVISIONED_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV",
    "PreprovisionedIdentityBootstrapManifestGenerationError",
    "generate_preprovisioned_identity_bootstrap_manifest",
    "generate_preprovisioned_identity_bootstrap_manifest_file",
    "main",
)
