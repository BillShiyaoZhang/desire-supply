"""Local-only synthetic multi-role workflow service."""

from .service import (
    FIXTURE_ID,
    OPERATION_IDS,
    PERSONAS,
    LocalSyntheticError,
    LocalSyntheticService,
)

__all__ = [
    "FIXTURE_ID",
    "LocalSyntheticError",
    "LocalSyntheticService",
    "OPERATION_IDS",
    "PERSONAS",
]
