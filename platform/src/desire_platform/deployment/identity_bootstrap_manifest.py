"""Generate a digest-only INTERNAL_SANDBOX identity bootstrap manifest.

This deployment-only program deliberately reads the same active OIDC subject
and recipient-binding keys as the online OIDC adapter.  Raw fictional provider
subjects and verified email values are accepted only from direct, regular files,
are reduced to keyed digests, and are zeroed before the operation returns.
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
import tempfile
from typing import Any, Callable, Dict, Mapping, NoReturn, Optional, Sequence, TextIO, Tuple

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
    IdentityBootstrapConfigurationError,
    parse_internal_sandbox_identity_manifest,
)


IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA = (
    "desire-internal-sandbox-identity-bootstrap-template-v1"
)
IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_TEMPLATE_FILE"
)
IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256"
)
IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_SOURCE_ROOT"
)
IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV = (
    "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_OUTPUT_FILE"
)

_SUBJECT_PURPOSE = "OIDC_SUBJECT_DIGEST"
_RECIPIENT_PURPOSE = "OIDC_RECIPIENT_BINDING"
_RECIPIENT_DOMAIN = b"desire:iam:recipient-binding:v1\x00EMAIL\x00"
_SOURCE_FILE = re.compile(r"[a-z][a-z0-9_]{2,31}\.(?:subject|email)\Z")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_TEMPLATE_ROOT_KEYS = frozenset(
    (
        "accounts",
        "bootstrap_id",
        "environment_id",
        "policy",
        "previous_manifest_sha256",
        "revision",
        "schema_name",
    )
)
_ACCOUNT_KEYS = frozenset(
    (
        "account_code",
        "activation_event_id",
        "contact_point",
        "creator_grant",
        "demand_owner_grant",
        "external_identity",
        "organization_grant",
        "platform_duty_grants",
        "revocation_event_id",
        "user_id",
    )
)
_TEMPLATE_IDENTITY_KEYS = frozenset(("id", "subject_file_name"))
_TEMPLATE_CONTACT_KEYS = frozenset(("id", "verified_email_file_name"))
_ALLOWED_ENVIRONMENT = frozenset(
    (
        DEPLOYMENT_CONFIG_POINTER_ENV,
        IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV,
        IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV,
        IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV,
        IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV,
    )
)


class IdentityBootstrapManifestGenerationError(RuntimeError):
    """Stable, non-reflective failure for the deployment generator."""

    def __init__(
        self,
        code: str = "IDENTITY_BOOTSTRAP_MANIFEST_GENERATION_INVALID",
    ) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, repr=False)
class GeneratedIdentityBootstrapManifest:
    canonical_bytes: bytes = field(repr=False)
    manifest_sha256: str
    revision: int
    account_count: int

    def __repr__(self) -> str:
        return (
            "GeneratedIdentityBootstrapManifest("
            "manifest_sha256=%r, revision=%r, account_count=%r)"
            % (self.manifest_sha256, self.revision, self.account_count)
        )


def generate_internal_sandbox_identity_manifest(
    *,
    template_bytes: bytes,
    expected_template_sha256: str,
    issuer: str,
    subject_digest_key_id: str,
    subject_digest_key: bytearray,
    recipient_binding_key_id: str,
    recipient_binding_key: bytearray,
    read_source: Callable[[str], bytearray],
) -> GeneratedIdentityBootstrapManifest:
    """Transform one pinned template and fixed fictional inputs to digests.

    Ownership of every ``bytearray`` returned by ``read_source`` transfers to
    this function; every such buffer is zeroed on success and failure.  Key
    buffers remain caller-owned so one managed carrier can serve the operation.
    """

    raw_sources = []  # type: list[bytearray]
    try:
        _require_key(subject_digest_key_id, subject_digest_key)
        _require_key(recipient_binding_key_id, recipient_binding_key)
        if not callable(read_source):
            _invalid()
        template = _parse_template(
            template_bytes,
            expected_template_sha256=expected_template_sha256,
        )
        accounts = template["accounts"]
        source_names = []
        generated_accounts = []
        for value in accounts:
            account = _closed_object(value, _ACCOUNT_KEYS)
            account_code = account["account_code"]
            if (
                not isinstance(account_code, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{2,31}", account_code) is None
            ):
                _invalid()
            identity = _closed_object(
                account["external_identity"], _TEMPLATE_IDENTITY_KEYS
            )
            contact = _closed_object(
                account["contact_point"], _TEMPLATE_CONTACT_KEYS
            )
            subject_file = _source_name(identity["subject_file_name"], ".subject")
            email_file = _source_name(
                contact["verified_email_file_name"], ".email"
            )
            source_names.extend((subject_file, email_file))
            subject = read_source(subject_file)
            if not isinstance(subject, bytearray):
                _invalid()
            raw_sources.append(subject)
            email = read_source(email_file)
            if not isinstance(email, bytearray):
                _invalid()
            raw_sources.append(email)
            expected_slug = account_code.replace("_", "-").encode("ascii")
            if not hmac.compare_digest(subject, b"sandbox:" + expected_slug):
                _invalid()
            if not hmac.compare_digest(
                email,
                b"sandbox-" + expected_slug + b"@example.test",
            ):
                _invalid()

            subject_digest = hmac.new(
                subject_digest_key, digestmod=hashlib.sha256
            )
            subject_digest.update(b"oidc-subject-v1\x00")
            subject_digest.update(issuer.encode("utf-8", errors="strict"))
            subject_digest.update(b"\x00")
            subject_digest.update(subject)
            recipient_digest = hmac.new(
                recipient_binding_key, digestmod=hashlib.sha256
            )
            recipient_digest.update(_RECIPIENT_DOMAIN)
            recipient_digest.update(email)

            transformed = dict(account)
            transformed["external_identity"] = {
                "id": identity["id"],
                "subject_digest_key_id": subject_digest_key_id,
                "subject_digest_sha256": subject_digest.hexdigest(),
            }
            transformed["contact_point"] = {
                "id": contact["id"],
                "recipient_binding_digest_key_id": recipient_binding_key_id,
                "recipient_binding_digest_sha256": recipient_digest.hexdigest(),
            }
            generated_accounts.append(transformed)
        if len(source_names) != len(set(source_names)):
            _invalid()

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
        return GeneratedIdentityBootstrapManifest(
            canonical_bytes=canonical,
            manifest_sha256=digest,
            revision=parsed.revision,
            account_count=len(parsed.accounts),
        )
    except IdentityBootstrapManifestGenerationError:
        raise
    except (IdentityBootstrapConfigurationError, KeyError, TypeError, ValueError):
        _invalid()
    finally:
        for material in raw_sources:
            _zero(material)


def generate_identity_bootstrap_manifest_file(
    *,
    environment: Mapping[str, str],
    now: datetime,
    read_bytes: Optional[Callable[[str], bytes]] = None,
) -> GeneratedIdentityBootstrapManifest:
    """Resolve the two active runtime keys and atomically write the manifest."""

    carriers = []  # type: list[FileSecretCarrier]
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
            allowed_root=Path(deployment.secret_root),
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

        template_path = _absolute_path(
            environment[IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV]
        )
        source_root = _source_root(
            environment[IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV]
        )
        if source_root == Path(deployment.secret_root).resolve(strict=True):
            _invalid()
        result = generate_internal_sandbox_identity_manifest(
            template_bytes=reader(template_path),
            expected_template_sha256=environment[
                IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV
            ],
            issuer=deployment.oidc.issuer,
            subject_digest_key_id=subject_carrier.key_id,
            subject_digest_key=subject_carrier.material,
            recipient_binding_key_id=recipient_carrier.key_id,
            recipient_binding_key=recipient_carrier.material,
            read_source=lambda file_name: _read_source(source_root, file_name),
        )
        output_path = _output_path(
            environment[IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV],
            forbidden_roots=(
                source_root,
                Path(deployment.secret_root).resolve(strict=True),
            ),
        )
        _atomic_write(output_path, result.canonical_bytes)
        return result
    except IdentityBootstrapManifestGenerationError:
        raise
    except BaseException:
        _invalid()
    finally:
        for carrier in reversed(carriers):
            carrier.destroy()


def _parse_template(raw: bytes, *, expected_template_sha256: str) -> Dict[str, Any]:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= 131_072
        or not isinstance(expected_template_sha256, str)
        or _SHA256_HEX.fullmatch(expected_template_sha256) is None
        or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), expected_template_sha256
        )
    ):
        _invalid()
    canonical_input = raw[:-1] if raw.endswith(b"\n") else raw
    if b"\r" in raw or canonical_input.endswith(b"\n"):
        _invalid()
    try:
        document = json.loads(
            canonical_input.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _invalid()
    root = _closed_object(document, _TEMPLATE_ROOT_KEYS)
    if (
        root["schema_name"] != IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA
        or root["environment_id"] != "internal-sandbox"
        or not hmac.compare_digest(canonical_input, _canonical(root))
        or type(root["accounts"]) is not list
        or len(root["accounts"]) != 10
    ):
        _invalid()
    return root


def _closed_object(value: Any, keys: frozenset[str]) -> Dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        _invalid()
    return value


def _unique_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result = {}  # type: Dict[str, Any]
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _reject_number(_value: str) -> NoReturn:
    _invalid()


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _require_key(key_id: Any, material: Any) -> None:
    if (
        not isinstance(key_id, str)
        or _KEY_ID.fullmatch(key_id) is None
        or not isinstance(material, bytearray)
        or not 32 <= len(material) <= 4_096
        or not any(material)
    ):
        _invalid()


def _source_name(value: Any, suffix: str) -> str:
    if (
        not isinstance(value, str)
        or _SOURCE_FILE.fullmatch(value) is None
        or not value.endswith(suffix)
    ):
        _invalid()
    return value


def _absolute_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        _invalid()
    try:
        resolved = Path(value).resolve(strict=True)
    except OSError:
        _invalid()
    if str(resolved) != value or not resolved.is_file() or resolved.is_symlink():
        _invalid()
    return value


def _source_root(value: Any) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        _invalid()
    try:
        root = Path(value)
        resolved = root.resolve(strict=True)
    except OSError:
        _invalid()
    if str(resolved) != value or root.is_symlink() or not resolved.is_dir():
        _invalid()
    return resolved


def _read_source(root: Path, file_name: str) -> bytearray:
    _source_name(
        file_name,
        ".subject" if file_name.endswith(".subject") else ".email",
    )
    candidate = root / file_name
    descriptor = None
    material = None  # type: Optional[bytearray]
    transferred = False
    try:
        descriptor = os.open(
            str(candidate),
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        material = _read_source_descriptor(descriptor)
        os.close(descriptor)
        descriptor = None
        transferred = True
        return material
    except IdentityBootstrapManifestGenerationError:
        raise
    except BaseException:
        _invalid()
    finally:
        if material is not None and not transferred:
            _zero(material)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_source_descriptor(
    descriptor: int,
    *,
    expected_fingerprint: Optional[Tuple[int, ...]] = None,
) -> bytearray:
    """Read one already-open regular source and transfer one mutable buffer.

    The caller owns the returned buffer.  Until that return completes, this
    function owns the allocation and destroys it on every failure, including a
    partial ``readv`` followed by an operating-system exception.
    """

    raw = None  # type: Optional[bytearray]
    transferred = False
    try:
        if type(descriptor) is not int or descriptor < 0:
            _invalid()
        metadata = os.fstat(descriptor)
        fingerprint = _source_metadata_fingerprint(metadata)
        if (
            expected_fingerprint is not None
            and fingerprint != expected_fingerprint
        ):
            _invalid()
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= 512:
            _invalid()
        raw = bytearray(metadata.st_size)
        offset = 0
        while offset < len(raw):
            read_count = os.readv(descriptor, [memoryview(raw)[offset:]])
            if read_count <= 0:
                break
            offset += read_count
        if offset != metadata.st_size:
            _invalid()
        if _source_metadata_fingerprint(os.fstat(descriptor)) != fingerprint:
            _invalid()
        if raw.endswith(b"\r\n"):
            del raw[-2:]
        elif raw.endswith(b"\n"):
            del raw[-1:]
        if not raw or b"\x00" in raw or b"\r" in raw or b"\n" in raw:
            _invalid()
        transferred = True
        return raw
    except IdentityBootstrapManifestGenerationError:
        raise
    except BaseException:
        _invalid()
    finally:
        if raw is not None and not transferred:
            _zero(raw)


def _source_metadata_fingerprint(metadata: os.stat_result) -> Tuple[int, ...]:
    try:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    except (AttributeError, TypeError, ValueError):
        _invalid()


def _output_path(value: Any, *, forbidden_roots: Tuple[Path, ...]) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        _invalid()
    candidate = Path(value)
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError:
        _invalid()
    if (
        str(parent) != str(candidate.parent)
        or not parent.is_dir()
        or candidate.name in ("", ".", "..")
    ):
        _invalid()
    for root in forbidden_roots:
        if parent == root or root in parent.parents:
            _invalid()
    if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
        _invalid()
    return candidate


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor = None
    temporary = None  # type: Optional[str]
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".identity-bootstrap-",
            dir=str(path.parent),
        )
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, str(path))
        temporary = None
        directory = os.open(
            str(path.parent),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        _invalid()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _zero(material: bytearray) -> None:
    for index in range(len(material)):
        material[index] = 0


def _invalid() -> NoReturn:
    raise IdentityBootstrapManifestGenerationError()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environment: Optional[Mapping[str, str]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m desire_platform.deployment.identity_bootstrap_manifest"
    )
    parser.add_argument("action", choices=("generate",))
    parser.parse_args(argv)
    values = os.environ if environment is None else environment
    try:
        generated = generate_identity_bootstrap_manifest_file(
            environment=values,
            now=clock(),
        )
    except IdentityBootstrapManifestGenerationError as error:
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
            '{"code":"IDENTITY_BOOTSTRAP_MANIFEST_GENERATION_INVALID",'
            '"status":"BLOCKED"}\n'
        )
        return 78
    stdout.write(
        json.dumps(
            {
                "account_count": generated.account_count,
                "manifest_sha256": generated.manifest_sha256,
                "revision": generated.revision,
                "status": "IDENTITY_BOOTSTRAP_MANIFEST_READY",
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
    "GeneratedIdentityBootstrapManifest",
    "IDENTITY_BOOTSTRAP_OUTPUT_FILE_ENV",
    "IDENTITY_BOOTSTRAP_SOURCE_ROOT_ENV",
    "IDENTITY_BOOTSTRAP_TEMPLATE_FILE_ENV",
    "IDENTITY_BOOTSTRAP_TEMPLATE_SCHEMA",
    "IDENTITY_BOOTSTRAP_TEMPLATE_SHA256_ENV",
    "IdentityBootstrapManifestGenerationError",
    "generate_identity_bootstrap_manifest_file",
    "generate_internal_sandbox_identity_manifest",
    "main",
)
