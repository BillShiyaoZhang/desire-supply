"""Fail-closed verification for immutable resources shipped in the platform package."""

import hashlib
import hmac
import importlib.resources
import re
from dataclasses import dataclass
from typing import Dict, Tuple

from .config import ArtifactRequirement


_ARTIFACT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAXIMUM_ARTIFACT_BYTES = 64 * 1024 * 1024


class PackageArtifactVerificationError(RuntimeError):
    """Stable public failure without resource names or digest material."""

    def __init__(self) -> None:
        self.code = "ARTIFACT_VERIFICATION_FAILED"
        super().__init__(self.code)


@dataclass(frozen=True)
class PackageArtifactLocation:
    """Closed registry entry for one packaged artifact."""

    artifact_id: str
    package: str
    resource_path: str
    maximum_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.artifact_id) is not str
            or _ARTIFACT_ID_PATTERN.fullmatch(self.artifact_id) is None
        ):
            raise ValueError("artifact_id is invalid")
        if (
            type(self.package) is not str
            or _PACKAGE_PATTERN.fullmatch(self.package) is None
        ):
            raise ValueError("package is invalid")
        if not _safe_resource_path(self.resource_path):
            raise ValueError("resource_path is invalid")
        if (
            type(self.maximum_bytes) is not int
            or not 1 <= self.maximum_bytes <= _MAXIMUM_ARTIFACT_BYTES
        ):
            raise ValueError("maximum_bytes is invalid")


def _safe_resource_path(value: object) -> bool:
    if type(value) is not str or not value or value.startswith("/"):
        return False
    if "\\" in value or value.endswith("/"):
        return False
    segments = value.split("/")
    return all(segment not in ("", ".", "..") for segment in segments)


class PackageArtifactVerifier:
    """Resolve only registered package resources and compare their exact digest."""

    def __init__(self, *, locations: Tuple[PackageArtifactLocation, ...]) -> None:
        if type(locations) is not tuple:
            raise TypeError("locations must be a tuple")
        registry: Dict[str, PackageArtifactLocation] = {}
        for location in locations:
            if not isinstance(location, PackageArtifactLocation):
                raise TypeError("locations contain an invalid entry")
            if location.artifact_id in registry:
                raise ValueError("duplicate artifact_id")
            registry[location.artifact_id] = location
        self._locations = registry

    def verify(self, requirement: ArtifactRequirement) -> None:
        try:
            if not isinstance(requirement, ArtifactRequirement):
                raise TypeError
            if (
                type(requirement.artifact_id) is not str
                or _ARTIFACT_ID_PATTERN.fullmatch(requirement.artifact_id) is None
                or type(requirement.sha256) is not str
                or _DIGEST_PATTERN.fullmatch(requirement.sha256) is None
            ):
                raise ValueError
            location = self._locations[requirement.artifact_id]
            resource = importlib.resources.files(location.package)
            for segment in location.resource_path.split("/"):
                resource = resource.joinpath(segment)
            if not resource.is_file():
                raise FileNotFoundError
            with resource.open("rb") as stream:
                payload = stream.read(location.maximum_bytes + 1)
            if type(payload) is not bytes or len(payload) > location.maximum_bytes:
                raise ValueError
            actual = hashlib.sha256(payload).hexdigest()
            if not hmac.compare_digest(actual, requirement.sha256):
                raise ValueError
        except PackageArtifactVerificationError:
            raise
        except BaseException:
            raise PackageArtifactVerificationError() from None

    def __repr__(self) -> str:
        return "PackageArtifactVerifier(resources=<redacted>)"
