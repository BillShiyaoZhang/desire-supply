"""Stable, non-reflective IAM domain errors."""

import re


_ENTITY_TAG = re.compile(r'^"v[1-9][0-9]*"$')


class IamError(Exception):
    """A closed IAM rejection identified by a stable, safe code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class IamPreconditionFailed(IamError):
    """A stale aggregate decision carrying its current strong entity tag."""

    def __init__(self, entity_tag: str) -> None:
        if not isinstance(entity_tag, str) or _ENTITY_TAG.fullmatch(entity_tag) is None:
            raise ValueError("precondition entity_tag is invalid")
        self.entity_tag = entity_tag
        super().__init__("PRECONDITION_FAILED")
