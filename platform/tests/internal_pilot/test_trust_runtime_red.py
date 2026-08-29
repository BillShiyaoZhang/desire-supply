"""Managed Trust runtime projection-port contracts."""

from types import SimpleNamespace

import pytest

from desire_platform.internal_pilot.trust_runtime import (
    InternalSandboxTrustPostgresRuntime,
)


def test_completed_assignment_projection_is_open_checked_and_delegated() -> None:
    calls = []
    projections = SimpleNamespace(
        list_my_completed_case_assignments=lambda **values: (
            calls.append(values),
            "completed-projection",
        )[1]
    )
    runtime = object.__new__(InternalSandboxTrustPostgresRuntime)
    runtime._projections = projections
    runtime._closed = False

    result = runtime.list_my_completed_case_assignments(
        actor="synthetic-officer",
        limit=100,
    )

    assert result == "completed-projection"
    assert calls == [{"actor": "synthetic-officer", "limit": 100}]

    runtime._closed = True
    with pytest.raises(RuntimeError, match="TRUST_RUNTIME_NOT_READY"):
        runtime.list_my_completed_case_assignments(
            actor="synthetic-officer",
            limit=100,
        )
