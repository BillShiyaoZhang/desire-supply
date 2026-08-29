"""Enforce the reviewed editor choices at every content write boundary."""

from __future__ import annotations

import re
from typing import Any, Iterator, Mapping, Optional, Sequence, Tuple

from ..synthetic_taxonomy import INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID
from .choices import build_internal_sandbox_editor_choices
from .contracts import (
    EditorChoiceFieldDto,
    EditorChoicesDto,
    EditorServiceError,
)


_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def internal_sandbox_editor_choices() -> EditorChoicesDto:
    """Return the one code-native catalog accepted by internal-pilot writes."""

    return build_internal_sandbox_editor_choices(
        bundle_id=INTERNAL_SANDBOX_TAXONOMY_BUNDLE_ID
    )


def normalize_editor_choice_path(path: str) -> str:
    """Normalize concrete JSON array indexes to editor-choice wildcards."""

    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("editor choice content path is invalid")
    segments = path[1:].split("/")
    if not segments or any(not segment for segment in segments):
        raise ValueError("editor choice content path is invalid")
    return "/" + "/".join(
        "*" if _ARRAY_INDEX.fullmatch(segment) is not None else segment
        for segment in segments
    )


def validate_editor_choice_membership(
    *,
    resource_type: str,
    content: Mapping[str, Any],
    choices: Optional[EditorChoicesDto] = None,
) -> None:
    """Reject present values that are outside the exact reviewed catalog.

    Missing fields and malformed container shapes remain the responsibility of
    the existing Profile/Demand domain validators.  For fields that are
    present, every concrete array item is checked and reported with its exact
    numeric JSON Pointer.  An unavailable wildcard therefore accepts an absent
    or empty array, but never a non-empty one.
    """

    if resource_type not in {"CREATOR_PROFILE", "DEMAND"}:
        raise ValueError("editor choice resource type is invalid")
    if not isinstance(content, Mapping):
        raise ValueError("editor choice content is invalid")
    catalog = choices or internal_sandbox_editor_choices()
    if not isinstance(catalog, EditorChoicesDto):
        raise TypeError("editor choices are invalid")

    for field in catalog.fields:
        if field.resource_type != resource_type:
            continue
        allowed_values = tuple(option.value for option in field.options)
        for path, value in _values_at_field(content, field):
            if (
                normalize_editor_choice_path(path) != field.path_template
                or field.status == "UNAVAILABLE"
                or not isinstance(value, str)
                or value not in allowed_values
            ):
                raise EditorServiceError(
                    status=422,
                    code="EDITOR_CHOICE_UNAVAILABLE",
                    path="/content" + path,
                )


def _values_at_field(
    content: Mapping[str, Any],
    field: EditorChoiceFieldDto,
) -> Iterator[Tuple[str, Any]]:
    segments = tuple(field.path_template[1:].split("/"))
    yield from _walk(content, segments, ())


def _walk(
    value: Any,
    remaining: Tuple[str, ...],
    actual: Tuple[str, ...],
) -> Iterator[Tuple[str, Any]]:
    if not remaining:
        yield "/" + "/".join(actual), value
        return
    segment, tail = remaining[0], remaining[1:]
    if segment == "*":
        if not _is_json_array(value):
            return
        for index, child in enumerate(value):
            yield from _walk(child, tail, actual + (str(index),))
        return
    if not isinstance(value, Mapping) or segment not in value:
        return
    yield from _walk(value[segment], tail, actual + (segment,))


def _is_json_array(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


__all__ = [
    "internal_sandbox_editor_choices",
    "normalize_editor_choice_path",
    "validate_editor_choice_membership",
]
