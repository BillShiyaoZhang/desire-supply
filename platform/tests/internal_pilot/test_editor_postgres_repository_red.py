"""TDD contract for the internal-pilot PostgreSQL composition repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import inspect
from types import SimpleNamespace
from uuid import UUID

import pytest

from desire_platform.creator_profile.adapters.postgres.migrations import (
    PROFILE_SCHEMA_HEAD_VERSION,
)
from desire_platform.creator_profile.adapters.postgres import (
    CreatorProfilePostgresOperation,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_SCHEMA_HEAD_VERSION,
)
from desire_platform.demand.adapters.postgres import DemandPostgresOperation
from desire_platform.internal_pilot.editor.contracts import EditorPrincipal
import desire_platform.internal_pilot.editor.postgres as editor_postgres
from desire_platform.internal_pilot.editor.postgres import (
    EditorPostgresConfigurationError,
    ProfileCompletedLifecycleReplayError,
    ProfileCompletedLifecycleReplayProbeRequest,
    ProfileReadAuthority,
    PsycopgProfileCompletedLifecycleReceiptProbe,
    PsycopgEditorRepository,
    _owner_demand_findings,
)


@dataclass(frozen=True)
class _Command:
    operation: object


class _ProfileUow:
    def __init__(self) -> None:
        self.calls = []

    def execute_create(self, command):
        self.calls.append(("create", command))
        return "profile-created"


class _DemandUow:
    def __init__(self) -> None:
        self.calls = []

    def execute_submit(self, command):
        self.calls.append(("submit", command))
        return "demand-submitted"


class _Row:
    def __init__(self, value) -> None:
        self._value = value

    def fetchone(self):
        return self._value


class _Rows(_Row):
    def fetchmany(self, size):
        assert size == 2
        return list(self._value[:size])


class _AllRows(_Row):
    def fetchall(self):
        return list(self._value)


class _ProjectionConnection:
    def __init__(self, *, role: str, component: str, schema_head: int) -> None:
        self.role = role
        self.component = component
        self.schema_head = schema_head

    def execute(self, statement, parameters=None):
        del parameters
        if "session_user,current_user" in statement:
            return _Row((self.role, self.role, 18))
        if f"FROM {self.component}.schema_compatibility" in statement:
            return _Row((self.component,) + (self.schema_head,) * 4)
        if "NULLIF(current_setting('app.scope_kind'" in statement:
            return _Row((None,) * 6)
        return _Row(None)


class _ProjectionSource:
    def __init__(self, connection: _ProjectionConnection) -> None:
        self.connection = connection
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection) -> None:
        self.released.append(connection)

    def discard(self, connection) -> None:
        self.discarded.append(connection)


class _ProfileCurrentProjectionConnection(_ProjectionConnection):
    def __init__(self, *, status: str) -> None:
        super().__init__(
            role="profile_app",
            component="profile",
            schema_head=PROFILE_SCHEMA_HEAD_VERSION,
        )
        self.status = status
        self.marker = hashlib.sha256(b"profile-current-projection").digest()
        self.draft_id = UUID("41000000-0000-4000-8000-000000000001")
        self.published_id = UUID("42000000-0000-4000-8000-000000000001")

    def execute(self, statement, parameters=None):
        if "pg_catalog.set_config" in statement:
            return _Row(None)
        if "iam_api.lock_creator_profile_self_v1" in statement:
            return _Row((self.marker, True))
        if "FROM profile.creator_profiles" in statement:
            return _Row(
                (
                    _PROFILE_ID,
                    _PROFILE_ACTOR_ID,
                    self.status,
                    5,
                    self.draft_id,
                    self.published_id,
                )
            )
        if "FROM profile.profile_versions" in statement:
            taxonomy_id = UUID("43000000-0000-4000-8000-000000000001")
            return _AllRows(
                (
                    (
                        self.published_id,
                        1,
                        None,
                        "PUBLISHED",
                        {"content": {"identity": {"headline": "published"}}},
                        hashlib.sha256(b"published").digest(),
                        taxonomy_id,
                        _PROFILE_NOW - timedelta(days=2),
                    ),
                    (
                        self.draft_id,
                        2,
                        self.published_id,
                        "DRAFT",
                        {"content": {"identity": {"headline": "draft"}}},
                        hashlib.sha256(b"draft").digest(),
                        taxonomy_id,
                        _PROFILE_NOW - timedelta(days=1),
                    ),
                )
            )
        return super().execute(statement, parameters)


_PROFILE_ACTOR_ID = UUID("10000000-0000-4000-8000-000000000001")
_PROFILE_SESSION_ID = UUID("20000000-0000-4000-8000-000000000001")
_PROFILE_COMMAND_ID = UUID("30000000-0000-4000-8000-000000000001")
_PROFILE_ID = UUID("40000000-0000-4000-8000-000000000001")
_PROFILE_GRANT_ID = UUID("50000000-0000-4000-8000-000000000001")
_PROFILE_BUNDLE_ID = UUID("60000000-0000-4000-8000-000000000001")
_PROFILE_MARKER = hashlib.sha256(b"profile-lifecycle-authority").digest()
_PROFILE_NOW = datetime(2026, 8, 24, 8, tzinfo=timezone.utc)
_PROFILE_EXPECTED_VERSION = 3
_PROFILE_IDEMPOTENCY_KEY = "profile-lifecycle-replay-0001"
_PROFILE_CANONICAL_PAYLOAD = b'{"operation":"PauseCreatorProfile"}'
_PROFILE_IDEMPOTENCY_KEYS = (
    ("profile-idempotency-2026-02", b"a" * 32),
    ("profile-idempotency-2026-01", b"c" * 32),
)
_PROFILE_PAYLOAD_KEYS = (
    ("profile-payload-2026-02", b"b" * 32),
    ("profile-payload-2026-01", b"d" * 32),
)
_DEFAULT_PROFILE_AUTHORITY = object()


def _profile_digest(key: bytes, material: bytes) -> bytes:
    return hmac.new(key, material, hashlib.sha256).digest()


def _profile_replay_request() -> ProfileCompletedLifecycleReplayProbeRequest:
    return ProfileCompletedLifecycleReplayProbeRequest(
        actor_user_id=_PROFILE_ACTOR_ID,
        session_id=_PROFILE_SESSION_ID,
        command_id=_PROFILE_COMMAND_ID,
        profile_id=_PROFILE_ID,
        operation=CreatorProfilePostgresOperation.PAUSE,
        expected_version=_PROFILE_EXPECTED_VERSION,
        expected_authority_marker_sha256=_PROFILE_MARKER,
        idempotency_key=_PROFILE_IDEMPOTENCY_KEY,
        canonical_payload=_PROFILE_CANONICAL_PAYLOAD,
    )


def _profile_receipt_row(**overrides):
    identity_key_id, identity_key = _PROFILE_IDEMPOTENCY_KEYS[1]
    payload_key_id, payload_key = _PROFILE_PAYLOAD_KEYS[1]
    completed_at = _PROFILE_NOW - timedelta(minutes=1)
    row = [
        _PROFILE_COMMAND_ID,
        "USER",
        _PROFILE_ACTOR_ID,
        CreatorProfilePostgresOperation.PAUSE.value,
        1,
        identity_key_id,
        _profile_digest(
            identity_key,
            _PROFILE_IDEMPOTENCY_KEY.encode("utf-8"),
        ),
        payload_key_id,
        "profile-command-json-v1",
        _profile_digest(payload_key, _PROFILE_CANONICAL_PAYLOAD),
        _PROFILE_ID,
        _PROFILE_EXPECTED_VERSION,
        "COMPLETED",
        {
            "profile_id": str(_PROFILE_ID),
            "aggregate_version": _PROFILE_EXPECTED_VERSION + 1,
            "status": "PAUSED",
        },
        1,
        _PROFILE_EXPECTED_VERSION + 1,
        completed_at,
        _PROFILE_NOW + timedelta(days=7),
        completed_at,
        _PROFILE_NOW,
    ]
    indexes = {
        "receipt_id": 0,
        "principal_kind": 1,
        "principal_id": 2,
        "command_name": 3,
        "command_version": 4,
        "identity_key_id": 5,
        "identity_digest": 6,
        "payload_key_id": 7,
        "canonicalization_version": 8,
        "payload_hash": 9,
        "profile_id": 10,
        "expected_version": 11,
        "status": 12,
        "safe_response": 13,
        "response_schema_version": 14,
        "completed_version": 15,
        "created_at": 16,
        "retain_until": 17,
        "completed_at": 18,
        "database_now": 19,
    }
    for name, value in overrides.items():
        row[indexes[name]] = value
    return tuple(row)


def _profile_receipt_identity() -> tuple[str, bytes]:
    key_id, key = _PROFILE_IDEMPOTENCY_KEYS[1]
    return (
        key_id,
        _profile_digest(key, _PROFILE_IDEMPOTENCY_KEY.encode("utf-8")),
    )


class _ProfileReceiptConnection(_ProjectionConnection):
    def __init__(
        self,
        *,
        receipt_rows=None,
        authority_row=_DEFAULT_PROFILE_AUTHORITY,
    ) -> None:
        super().__init__(
            role="profile_app",
            component="profile",
            schema_head=PROFILE_SCHEMA_HEAD_VERSION,
        )
        self.receipt_rows = {} if receipt_rows is None else receipt_rows
        self.authority_row = (
            (
                _PROFILE_ACTOR_ID,
                _PROFILE_GRANT_ID,
                _PROFILE_BUNDLE_ID,
                _PROFILE_MARKER,
                True,
            )
            if authority_row is _DEFAULT_PROFILE_AUTHORITY
            else authority_row
        )
        self.calls = []
        self.local_settings = {}

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if "pg_catalog.set_config" in statement:
            name, value = parameters
            self.local_settings[name] = value
            return _Row(None)
        if "iam_api.lock_creator_profile_self_v1" in statement:
            return _Row(self.authority_row)
        if "FROM profile.command_receipts" in statement:
            key_id = parameters[2]
            digest = parameters[3]
            return _Rows(self.receipt_rows.get((key_id, digest), []))
        return super().execute(statement, parameters)


def _profile_receipt_probe(
    *, rows=None, authority_row=_DEFAULT_PROFILE_AUTHORITY
):
    connection = _ProfileReceiptConnection(
        receipt_rows={} if rows is None else rows,
        authority_row=authority_row,
    )
    source = _ProjectionSource(connection)
    probe = PsycopgProfileCompletedLifecycleReceiptProbe(
        connections=source,
        idempotency_keys=_PROFILE_IDEMPOTENCY_KEYS,
        payload_hash_keys=_PROFILE_PAYLOAD_KEYS,
    )
    return probe, connection, source


def test_editor_projection_schema_guards_have_no_numeric_head_copies() -> None:
    source = inspect.getsource(editor_postgres._run_projection)

    assert '("demand", 7, 7, 7, 7)' not in source
    assert '("profile", 3, 3, 3, 3)' not in source
    assert "DEMAND_SCHEMA_HEAD_VERSION" in source
    assert "PROFILE_SCHEMA_HEAD_VERSION" in source


@pytest.mark.parametrize(
    ("component", "constant_name", "catalog_head"),
    (
        ("demand", "DEMAND_SCHEMA_HEAD_VERSION", DEMAND_SCHEMA_HEAD_VERSION),
        ("profile", "PROFILE_SCHEMA_HEAD_VERSION", PROFILE_SCHEMA_HEAD_VERSION),
    ),
)
def test_editor_projection_schema_guard_follows_component_head_constant(
    monkeypatch,
    component,
    constant_name,
    catalog_head,
) -> None:
    schema_head = catalog_head + 100
    monkeypatch.setattr(
        editor_postgres,
        constant_name,
        schema_head,
        raising=False,
    )
    role = f"{component}_reader"
    connection = _ProjectionConnection(
        role=role,
        component=component,
        schema_head=schema_head,
    )
    source = _ProjectionSource(connection)

    result = editor_postgres._run_projection(
        source=source,
        expected_role=role,
        expected_component=component,
        work=lambda candidate: candidate,
    )

    assert result is connection
    assert source.released == [connection]
    assert source.discarded == []


@pytest.mark.parametrize(
    ("status", "operation", "current_status"),
    (
        ("PAUSED", CreatorProfilePostgresOperation.PAUSE, "PUBLISHED"),
        ("ACTIVE", CreatorProfilePostgresOperation.RESUME, "DRAFT"),
    ),
)
def test_profile_projection_uses_published_while_paused_and_draft_after_resume(
    status,
    operation,
    current_status,
) -> None:
    connection = _ProfileCurrentProjectionConnection(status=status)
    source = _ProjectionSource(connection)
    repository = PsycopgEditorRepository(
        profile_uow=SimpleNamespace(),
        demand_uows={},
        profile_reads=source,
    )
    principal = EditorPrincipal(
        user_id=str(_PROFILE_ACTOR_ID),
        session_id=str(_PROFILE_SESSION_ID),
        organization_id=None,
        role_codes=("CREATOR",),
    )

    projected = repository.get_profile(
        principal=principal,
        profile_id=str(_PROFILE_ID),
        authority=ProfileReadAuthority(connection.marker, operation),
    )

    assert projected.current_version is not None
    assert projected.current_version.status == current_status
    assert {version.status for version in projected.versions} == {
        "DRAFT",
        "PUBLISHED",
    }
    if status == "PAUSED":
        assert projected.capabilities == ("RESUME", "ARCHIVE")
        assert projected.editable_paths == ()
    else:
        assert "SAVE_DRAFT" in projected.capabilities
        assert "PUBLISH" in projected.capabilities
    assert source.released == [connection]
    assert source.discarded == []


def test_profile_completed_lifecycle_probe_hits_retained_receipt_and_misses_cleanly(
) -> None:
    identity = _profile_receipt_identity()
    probe, connection, source = _profile_receipt_probe(
        rows={identity: [_profile_receipt_row()]},
    )

    result = probe.read_completed(_profile_replay_request())

    assert result is not None
    assert (
        result.profile_id,
        result.operation,
        result.aggregate_version,
        result.status,
    ) == (
        _PROFILE_ID,
        CreatorProfilePostgresOperation.PAUSE,
        _PROFILE_EXPECTED_VERSION + 1,
        "PAUSED",
    )
    assert connection.local_settings == {
        "TimeZone": "UTC",
        "lock_timeout": "2000ms",
        "statement_timeout": "10000ms",
        "idle_in_transaction_session_timeout": "15000ms",
        "app.scope_kind": "PROFILE_SELF",
        "app.operation": "PAUSE_PROFILE",
        "app.actor_user_id": str(_PROFILE_ACTOR_ID),
        "app.session_id": str(_PROFILE_SESSION_ID),
        "app.profile_id": str(_PROFILE_ID),
        "app.command_id": str(_PROFILE_COMMAND_ID),
        "app.command_name": CreatorProfilePostgresOperation.PAUSE.value,
        "app.command_version": "1",
        "app.expected_aggregate_version": str(_PROFILE_EXPECTED_VERSION),
        "app.idempotency_key_digest_key_id": identity[0],
        "app.idempotency_key_digest": identity[1].hex(),
    }
    statements = [statement for statement, _parameters in connection.calls]
    assert next(
        index
        for index, statement in enumerate(statements)
        if "iam_api.lock_creator_profile_self_v1" in statement
    ) < next(
        index
        for index, statement in enumerate(statements)
        if "FROM profile.command_receipts" in statement
    )
    assert source.released == [connection]
    assert source.discarded == []

    miss, miss_connection, miss_source = _profile_receipt_probe()
    assert miss.read_completed(_profile_replay_request()) is None
    assert sum(
        "FROM profile.command_receipts" in statement
        for statement, _parameters in miss_connection.calls
    ) == len(_PROFILE_IDEMPOTENCY_KEYS)
    assert miss_source.released == [miss_connection]
    assert miss_source.discarded == []


@pytest.mark.parametrize(
    ("row", "expected_code"),
    (
        (
            _profile_receipt_row(
                payload_hash=_profile_digest(
                    _PROFILE_PAYLOAD_KEYS[1][1],
                    b"changed-profile-lifecycle-payload",
                )
            ),
            "IDEMPOTENCY_KEY_REUSED",
        ),
        (
            _profile_receipt_row(
                status="IN_PROGRESS",
                safe_response=None,
                response_schema_version=None,
                completed_version=None,
                completed_at=None,
            ),
            "COMMAND_OUTCOME_UNKNOWN",
        ),
        (
            _profile_receipt_row(
                payload_key_id="profile-payload-retired-without-material"
            ),
            "SERVICE_UNAVAILABLE",
        ),
        (
            _profile_receipt_row(
                status="IN_PROGRESS",
                retain_until=_PROFILE_NOW - timedelta(seconds=1),
                safe_response=None,
                response_schema_version=None,
                completed_version=None,
                completed_at=None,
            ),
            "SERVICE_UNAVAILABLE",
        ),
        (
            _profile_receipt_row(
                status="IN_PROGRESS",
                completed_version=None,
                completed_at=None,
            ),
            "SERVICE_UNAVAILABLE",
        ),
    ),
)
def test_profile_completed_lifecycle_probe_preserves_conflict_and_unknown_codes(
    row,
    expected_code,
) -> None:
    identity = _profile_receipt_identity()
    probe, connection, source = _profile_receipt_probe(rows={identity: [row]})

    with pytest.raises(ProfileCompletedLifecycleReplayError) as raised:
        probe.read_completed(_profile_replay_request())

    assert raised.value.code == expected_code
    assert source.released == [connection]
    assert source.discarded == []


@pytest.mark.parametrize(
    "row",
    (
        _profile_receipt_row(
            receipt_id=UUID("30000000-0000-4000-8000-000000000099")
        ),
        _profile_receipt_row(canonicalization_version="profile-command-json-v0"),
        _profile_receipt_row(
            safe_response={
                "profile_id": str(_PROFILE_ID),
                "aggregate_version": _PROFILE_EXPECTED_VERSION + 1,
                "status": "ACTIVE",
            }
        ),
        _profile_receipt_row(response_schema_version=2),
        _profile_receipt_row(completed_version=_PROFILE_EXPECTED_VERSION + 2),
        _profile_receipt_row(profile_id=UUID(int=_PROFILE_ID.int + 1)),
    ),
)
def test_profile_completed_lifecycle_probe_rejects_corrupt_receipt_projection(
    row,
) -> None:
    identity = _profile_receipt_identity()
    probe, connection, source = _profile_receipt_probe(rows={identity: [row]})

    with pytest.raises(ProfileCompletedLifecycleReplayError) as raised:
        probe.read_completed(_profile_replay_request())

    assert raised.value.code == "SERVICE_UNAVAILABLE"
    assert source.released == [connection]
    assert source.discarded == []


def test_profile_completed_lifecycle_probe_rejects_expired_or_duplicate_receipt(
) -> None:
    identity = _profile_receipt_identity()
    expired = _profile_receipt_row(
        retain_until=_PROFILE_NOW - timedelta(seconds=1),
    )
    cases = ([expired], [_profile_receipt_row(), _profile_receipt_row()])

    for rows in cases:
        probe, connection, source = _profile_receipt_probe(
            rows={identity: rows}
        )
        with pytest.raises(ProfileCompletedLifecycleReplayError) as raised:
            probe.read_completed(_profile_replay_request())
        assert raised.value.code == "SERVICE_UNAVAILABLE"
        assert source.released == [connection]
        assert source.discarded == []


@pytest.mark.parametrize(
    ("authority_row", "expected_code"),
    (
        (None, "RESOURCE_NOT_FOUND"),
        ((), "SERVICE_UNAVAILABLE"),
        (
            (
                _PROFILE_ACTOR_ID,
                _PROFILE_GRANT_ID,
                _PROFILE_BUNDLE_ID,
                hashlib.sha256(b"wrong-profile-authority").digest(),
                True,
            ),
            "SERVICE_UNAVAILABLE",
        ),
        (
            (
                _PROFILE_ACTOR_ID,
                _PROFILE_GRANT_ID,
                _PROFILE_BUNDLE_ID,
                _PROFILE_MARKER,
                False,
            ),
            "SERVICE_UNAVAILABLE",
        ),
    ),
)
def test_profile_completed_lifecycle_probe_fails_closed_on_authority_marker(
    authority_row,
    expected_code,
) -> None:
    probe, connection, source = _profile_receipt_probe(
        authority_row=authority_row,
    )

    with pytest.raises(ProfileCompletedLifecycleReplayError) as raised:
        probe.read_completed(_profile_replay_request())

    assert raised.value.code == expected_code
    assert not any(
        "FROM profile.command_receipts" in statement
        for statement, _parameters in connection.calls
    )
    assert source.released == [connection]
    assert source.discarded == []


def test_closed_dispatch_delegates_writes_to_the_canonical_fixed_uows() -> None:
    profile = _ProfileUow()
    demand = _DemandUow()
    repository = PsycopgEditorRepository(
        profile_uow=profile,
        demand_uows={DemandPostgresOperation.SUBMIT: demand},
    )
    profile_command = _Command(CreatorProfilePostgresOperation.CREATE)
    demand_command = _Command(DemandPostgresOperation.SUBMIT)

    assert repository.execute_profile(profile_command) == "profile-created"
    assert repository.execute_demand(demand_command) == "demand-submitted"
    assert profile.calls == [("create", profile_command)]
    assert demand.calls == [("submit", demand_command)]


def test_dispatch_is_default_deny_for_unknown_or_unbound_programs() -> None:
    repository = PsycopgEditorRepository(
        profile_uow=SimpleNamespace(),
        demand_uows={},
    )

    with pytest.raises(ValueError, match="closed Creator Profile command"):
        repository.execute_profile(_Command("CREATE"))
    with pytest.raises(EditorPostgresConfigurationError, match="not configured"):
        repository.execute_demand(_Command(DemandPostgresOperation.CREATE))


def test_owner_findings_projection_rejects_open_or_malformed_database_rows() -> None:
    reviewed_at = datetime(2026, 8, 16, 8, tzinfo=timezone.utc)
    first = (
        UUID("71000000-0000-4000-8000-000000000001"),
        UUID("72000000-0000-4000-8000-000000000001"),
        UUID("73000000-0000-4000-8000-000000000001"),
        "NEEDS_CHANGES",
        ["SCOPE_UNCLEAR"],
        ["SCOPE"],
        reviewed_at,
    )
    second = (
        UUID("71000000-0000-4000-8000-000000000002"),
        UUID("72000000-0000-4000-8000-000000000002"),
        UUID("73000000-0000-4000-8000-000000000002"),
        "VERIFIED",
        [],
        [],
        reviewed_at + timedelta(seconds=1),
    )
    projected = _owner_demand_findings((first, second))
    assert tuple(item.result for item in projected) == (
        "NEEDS_CHANGES",
        "VERIFIED",
    )
    assert projected[0].required_field_paths == ("/scope",)

    unsorted_operations = (
        first[0],
        first[1],
        first[2],
        "NEEDS_CHANGES",
        ["SCOPE_UNCLEAR", "CONTENT_INCOMPLETE"],
        ["SCOPE", "BUDGET"],
        reviewed_at,
    )
    assert _owner_demand_findings((unsorted_operations,))[0].required_field_paths == (
        "/scope",
        "/budget",
    )

    finance = (
        UUID("71000000-0000-4000-8000-000000000003"),
        UUID("72000000-0000-4000-8000-000000000003"),
        None,
        "REJECTED",
        ["BUDGET_PLAN_UNACCEPTABLE"],
        ["BUDGET", "SCOPE"],
        reviewed_at + timedelta(seconds=2),
    )
    finance_projection = _owner_demand_findings((finance,))[0]
    assert finance_projection.assignment_id is None
    assert finance_projection.required_field_paths == ("/budget", "/scope")

    malformed = (
        (first[:-1],),
        ((first[0], *first[1:]), (first[0], *second[1:])),
        ((first[0], first[1], first[2], "ALLOW", [], [], reviewed_at),),
        ((first[0], first[1], first[2], "NEEDS_CHANGES", [], ["SCOPE"], reviewed_at),),
        ((first[0], first[1], first[2], "VERIFIED", ["SCOPE_UNCLEAR"], [], reviewed_at),),
        ((first[0], first[1], first[2], "NEEDS_CHANGES", ("SCOPE_UNCLEAR",), ["SCOPE"], reviewed_at),),
        ((first[0], first[1], None, "REJECTED", ["SCOPE_UNCLEAR"], ["SCOPE"], reviewed_at),),
        ((first[0], first[1], None, "REJECTED", ["BUDGET_PLAN_UNACCEPTABLE"], ["UNKNOWN"], reviewed_at),),
        ((first[0], first[1], first[2], "NEEDS_CHANGES", ["SCOPE_UNCLEAR"], ["SCOPE"], reviewed_at.replace(tzinfo=None)),),
        (second, first),
    )
    for rows in malformed:
        with pytest.raises(EditorPostgresConfigurationError):
            _owner_demand_findings(rows)
