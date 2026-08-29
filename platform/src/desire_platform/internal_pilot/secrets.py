"""Purpose-separated file secret provider for container deployments."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import threading
from typing import Any, Optional, Tuple

from desire_platform.runtime.config import DatabaseProfile


_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_PURPOSE = re.compile(r"^[A-Z][A-Z0-9_:]{0,127}$")
_CREDENTIAL_REF = re.compile(
    r"^secret://[a-z0-9][a-z0-9_-]{0,62}/"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}#"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"
)
_KINDS = frozenset(("DATABASE_CREDENTIAL", "KEY"))
_STATUSES = frozenset(("ACTIVE", "VERIFY_ONLY"))
_MAXIMUM_MANIFEST_BYTES = 256 * 1024
_UTC_SECOND = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


class SecretProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SecretManifestError(ValueError):
    def __init__(self) -> None:
        self.code = "INVALID_SECRET_MANIFEST"
        super().__init__(self.code)


class _InvalidManifest(Exception):
    pass


def _invalid_manifest(*_facts: Any) -> Any:
    raise _InvalidManifest


def _manifest_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid_manifest()
        result[key] = value
    return result


def _manifest_object(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != expected:
        _invalid_manifest()
    return value


def _manifest_utc(value: Any) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND.fullmatch(value) is None:
        _invalid_manifest()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _invalid_manifest()
    return parsed.replace(tzinfo=timezone.utc)


def parse_file_secret_manifest(raw: bytes) -> Tuple["FileSecretManifestEntry", ...]:
    """Parse one closed, secret-free manifest from explicit UTF-8 bytes."""

    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAXIMUM_MANIFEST_BYTES:
            _invalid_manifest()
        decoded = raw.decode("utf-8", errors="strict")
        document = json.loads(
            decoded,
            object_pairs_hook=_manifest_pairs,
            parse_float=_invalid_manifest,
            parse_constant=_invalid_manifest,
        )
        root = _manifest_object(
            document,
            frozenset(("schema_name", "entries")),
        )
        if root["schema_name"] != "desire-file-secret-manifest-v1":
            _invalid_manifest()
        raw_entries = root["entries"]
        if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= 256:
            _invalid_manifest()
        expected_entry_fields = frozenset(
            (
                "kind",
                "file_name",
                "credential_ref",
                "purpose",
                "key_id",
                "not_before",
                "not_after",
                "status",
            )
        )
        entries = tuple(
            FileSecretManifestEntry(
                kind=item["kind"],
                file_name=item["file_name"],
                credential_ref=item["credential_ref"],
                purpose=item["purpose"],
                key_id=item["key_id"],
                not_before=_manifest_utc(item["not_before"]),
                not_after=_manifest_utc(item["not_after"]),
                status=item["status"],
            )
            for item in (
                _manifest_object(value, expected_entry_fields)
                for value in raw_entries
            )
        )
        file_names = tuple(entry.file_name for entry in entries)
        identities = tuple(
            (
                ("credential", entry.credential_ref)
                if entry.kind == "DATABASE_CREDENTIAL"
                else (entry.purpose, entry.key_id)
            )
            for entry in entries
        )
        if (
            len(set(file_names)) != len(file_names)
            or len(set(identities)) != len(identities)
        ):
            _invalid_manifest()
        return entries
    except _InvalidManifest:
        raise SecretManifestError() from None
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise SecretManifestError() from None


@dataclass(frozen=True)
class FileSecretManifestEntry:
    kind: str
    file_name: str
    credential_ref: Optional[str]
    purpose: str
    key_id: str
    not_before: datetime
    not_after: datetime
    status: str

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError("secret kind is not closed")
        if not isinstance(self.file_name, str) or _FILE_NAME.fullmatch(self.file_name) is None:
            raise ValueError("secret file name is invalid")
        if not isinstance(self.purpose, str) or _PURPOSE.fullmatch(self.purpose) is None:
            raise ValueError("secret purpose is invalid")
        if not isinstance(self.key_id, str) or _KEY_ID.fullmatch(self.key_id) is None:
            raise ValueError("secret key ID is invalid")
        if self.status not in _STATUSES:
            raise ValueError("secret status is not closed")
        _require_utc(self.not_before)
        _require_utc(self.not_after)
        if self.not_before >= self.not_after:
            raise ValueError("secret validity window is invalid")
        if self.kind == "DATABASE_CREDENTIAL":
            if (
                not isinstance(self.credential_ref, str)
                or _CREDENTIAL_REF.fullmatch(self.credential_ref) is None
                or self.credential_ref.rsplit("#", 1)[1] != self.key_id
                or not self.purpose.startswith("DATABASE_CREDENTIAL:")
                or self.status != "ACTIVE"
            ):
                raise ValueError("database credential manifest is invalid")
        elif self.credential_ref is not None or self.purpose.startswith(
            "DATABASE_CREDENTIAL:"
        ):
            raise ValueError("key manifest is invalid")


@dataclass(repr=False)
class FileSecretCarrier:
    purpose: str
    key_id: str
    not_before: datetime
    not_after: datetime
    status: str
    material: bytearray = field(repr=False)
    binding_sha256: Optional[bytes] = field(default=None, repr=False)
    _destroyed: bool = field(default=False, init=False, repr=False)
    _lock: Any = field(default_factory=threading.Lock, init=False, repr=False)

    def destroy(self) -> None:
        with self._lock:
            if self._destroyed:
                return
            for index in range(len(self.material)):
                self.material[index] = 0
            self._destroyed = True

    def __repr__(self) -> str:
        return (
            "FileSecretCarrier("
            f"purpose={self.purpose!r}, key_id={self.key_id!r}, "
            f"status={self.status!r}, material=<redacted>, "
            f"destroyed={self._destroyed})"
        )


class ManagedRuntimeSecrets:
    """Own resolved carriers until all dependent runtime resources are closed."""

    def __init__(
        self,
        *,
        carriers: Tuple[FileSecretCarrier, ...],
        clock: Any,
    ) -> None:
        if (
            not isinstance(carriers, tuple)
            or not carriers
            or any(not isinstance(item, FileSecretCarrier) for item in carriers)
            or len({id(item) for item in carriers}) != len(carriers)
            or len({(item.purpose, item.key_id) for item in carriers})
            != len(carriers)
            or not callable(clock)
        ):
            raise ValueError("managed runtime secret registry is invalid")
        self._carriers = carriers
        self._clock = clock
        self._closed = False
        self._lock = threading.RLock()

    @property
    def carriers(self) -> Tuple[FileSecretCarrier, ...]:
        return self._carriers

    def check_readiness(self, *, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30_000:
            raise SecretProviderError("SECRET_UNAVAILABLE")
        try:
            now = self._clock()
            _require_utc(now)
        except BaseException:
            raise SecretProviderError("SECRET_UNAVAILABLE") from None
        with self._lock:
            if self._closed:
                raise SecretProviderError("SECRET_UNAVAILABLE")
            for carrier in self._carriers:
                if (
                    carrier._destroyed
                    or carrier.status not in _STATUSES
                    or carrier.not_before > now
                    or now >= carrier.not_after
                    or not carrier.material
                    or not any(carrier.material)
                ):
                    raise SecretProviderError("SECRET_UNAVAILABLE")
        return None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for carrier in reversed(self._carriers):
                carrier.destroy()

    def __repr__(self) -> str:
        with self._lock:
            return (
                "ManagedRuntimeSecrets("
                f"carrier_count={len(self._carriers)}, closed={self._closed}, "
                "material=<redacted>)"
            )


class FilesystemSecretProvider:
    """Resolve only manifest-listed direct children of one trusted directory."""

    def __init__(
        self,
        *,
        allowed_root: Path,
        entries: Tuple[FileSecretManifestEntry, ...],
    ) -> None:
        if not isinstance(allowed_root, Path):
            raise TypeError("secret root is unavailable")
        try:
            resolved_root = allowed_root.resolve(strict=True)
        except OSError:
            raise ValueError("secret root is unavailable") from None
        if not resolved_root.is_dir() or allowed_root.is_symlink():
            raise ValueError("secret root is unavailable")
        if (
            not isinstance(entries, tuple)
            or not entries
            or any(not isinstance(entry, FileSecretManifestEntry) for entry in entries)
        ):
            raise ValueError("secret manifest is unavailable")
        file_names = tuple(entry.file_name for entry in entries)
        identities = tuple(
            (
                ("credential", entry.credential_ref)
                if entry.kind == "DATABASE_CREDENTIAL"
                else (entry.purpose, entry.key_id)
            )
            for entry in entries
        )
        if (
            len(set(file_names)) != len(file_names)
            or len(set(identities)) != len(identities)
        ):
            raise ValueError("secret manifest contains aliases")
        self._root = resolved_root
        self._credential_entries = {
            entry.credential_ref: entry
            for entry in entries
            if entry.kind == "DATABASE_CREDENTIAL"
        }
        self._key_entries = {
            (entry.purpose, entry.key_id): entry
            for entry in entries
            if entry.kind == "KEY"
        }
        self._issued: set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def resolve_credential(self, profile: DatabaseProfile) -> FileSecretCarrier:
        if not isinstance(profile, DatabaseProfile):
            raise SecretProviderError("SECRET_UNAVAILABLE")
        entry = self._credential_entries.get(profile.credential_ref)
        if (
            entry is None
            or entry.purpose != f"DATABASE_CREDENTIAL:{profile.capability_id}"
            or entry.key_id != profile.credential_ref.rsplit("#", 1)[1]
        ):
            raise SecretProviderError("SECRET_UNAVAILABLE")
        carrier = self._resolve(entry)
        carrier.binding_sha256 = _credential_binding(profile)
        return carrier

    def resolve_key(self, purpose: str, key_id: str) -> FileSecretCarrier:
        if not isinstance(purpose, str) or not isinstance(key_id, str):
            raise SecretProviderError("SECRET_UNAVAILABLE")
        entry = self._key_entries.get((purpose, key_id))
        if entry is None:
            raise SecretProviderError("SECRET_UNAVAILABLE")
        return self._resolve(entry)

    def _resolve(self, entry: FileSecretManifestEntry) -> FileSecretCarrier:
        identity = (entry.kind, entry.credential_ref or f"{entry.purpose}:{entry.key_id}")
        with self._lock:
            if identity in self._issued:
                raise SecretProviderError("SECRET_ALREADY_RESOLVED")
            material = _read_material(self._root, entry)
            self._issued.add(identity)
        return FileSecretCarrier(
            purpose=entry.purpose,
            key_id=entry.key_id,
            not_before=entry.not_before,
            not_after=entry.not_after,
            status=entry.status,
            material=bytearray(material),
        )

    def __repr__(self) -> str:
        return (
            "FilesystemSecretProvider("
            f"credential_count={len(self._credential_entries)}, "
            f"key_count={len(self._key_entries)}, root=<redacted>)"
        )


def _read_material(root: Path, entry: FileSecretManifestEntry) -> bytes:
    candidate = root / entry.file_name
    if candidate.is_symlink():
        raise SecretProviderError("SECRET_INVALID")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
        if resolved.parent != root or not stat.S_ISREG(metadata.st_mode):
            raise OSError
        raw = resolved.read_bytes()
    except OSError:
        raise SecretProviderError("SECRET_UNAVAILABLE") from None
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    minimum = 24 if entry.kind == "DATABASE_CREDENTIAL" else 32
    if (
        not minimum <= len(raw) <= 4_096
        or b"\x00" in raw
        or b"\r" in raw
        or b"\n" in raw
    ):
        raise SecretProviderError("SECRET_INVALID")
    return raw


def _credential_binding(profile: DatabaseProfile) -> bytes:
    return hashlib.sha256(
        b"runtime-db-credential-v1\x00"
        + profile.capability_id.encode("utf-8")
        + b"\x00"
        + profile.online_role.encode("utf-8")
        + b"\x00"
        + profile.credential_ref.encode("utf-8")
    ).digest()


def _require_utc(value: Any) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("secret validity time must be aware UTC")
    try:
        offset = value.utcoffset()
    except BaseException:
        raise TypeError("secret validity time must be aware UTC") from None
    if offset != timedelta(0):
        raise ValueError("secret validity time must be UTC")


__all__ = [
    "FileSecretCarrier",
    "FileSecretManifestEntry",
    "FilesystemSecretProvider",
    "ManagedRuntimeSecrets",
    "SecretManifestError",
    "SecretProviderError",
    "parse_file_secret_manifest",
]
