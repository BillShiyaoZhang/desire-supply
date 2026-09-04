"""Explicit, exact-target SYSTEM handoff from secured funding to Matching.

This operator command is intentionally separate from the API and Matching
worker. It authenticates as demand_system, reads one RLS-scoped Demand, obtains
current rule/Trust evidence, and invokes the canonical Demand14 command. It
does not discover tenants, accept candidate inputs, or write business SQL.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import stat
from typing import Any, Optional, Sequence, Union
from uuid import UUID

import psycopg

from desire_platform.demand.adapters.postgres import (
    DemandPostgresCommand, DemandPostgresCommitOutcomeUnknownError, DemandPostgresDatabaseResult,
    DemandPostgresExecutionScope, DemandPostgresHoldEvidence,
    DemandPostgresOperation, DemandPostgresReceiptMaterial,
    DemandPostgresRuleRequirement, PsycopgDemandRuleCatalog,
    PsycopgDemandUnitOfWorkFactory,
)
from desire_platform.demand.adapters.postgres.uow import _preflight_writer
from desire_platform.demand.ports.commands import DemandHoldDecision
from desire_platform.internal_pilot.contract_validation import DemandPostgresContractValidator
from desire_platform.trust_safety.adapters.postgres import PsycopgTrustDemandSafetyHoldProvider


SYSTEM_WORKLOAD_ID = UUID("48000000-0000-4000-8000-000000000001")
SYSTEM_AUTHORITY_MARKER = bytes.fromhex(
    "d48c8643a2b65b291f98db043ceb9804a825901027e8a13be1cf88a83ea3f789"
)
_OPERATION = DemandPostgresOperation.REQUEST_MATCHING_SYSTEM
_CREDENTIAL_FILES = (
    "db-demand-system-v1", "db-demand-self-v1", "db-trust-decision-v1",
    "key-demand-idempotency-v1", "key-demand-payload-hash-v1",
)


class MatchingWorkflowError(RuntimeError):
    """A closed error code; never a database, configuration or secret dump."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MatchingWorkflowTarget:
    organization_id: UUID
    demand_id: UUID
    expected_version: int
    request_id: UUID

    def __post_init__(self) -> None:
        if any(not isinstance(value, UUID) or value.int == 0 for value in (
            self.organization_id, self.demand_id, self.request_id
        )) or type(self.expected_version) is not int or self.expected_version < 1:
            raise ValueError("invalid exact Matching workflow target")


@dataclass(frozen=True)
class MatchingWorkflowSnapshot:
    demand_version_id: UUID
    content_sha256: bytes = field(repr=False)
    funding_source_event_id: UUID
    original_actor_user_id: UUID


class PsycopgMatchingWorkflowTargetReader:
    """Only one exact scoped root/version/SECURED marker, never a work queue."""

    def __init__(self, *, connections: Any) -> None:
        self._connections = connections

    def read(self, target: MatchingWorkflowTarget, *, receipt: DemandPostgresReceiptMaterial
             ) -> Union[MatchingWorkflowSnapshot, DemandPostgresDatabaseResult]:
        connection = self._connections.checkout()
        try:
            _preflight_writer(connection, _OPERATION)
            connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '10000ms'")
            for name, value in (
                ("app.scope_kind", "DEMAND_SYSTEM"),
                ("app.operation", "REQUEST_MATCHING"),
                ("app.actor_id", str(SYSTEM_WORKLOAD_ID)),
                ("app.organization_id", str(target.organization_id)),
                ("app.demand_id", str(target.demand_id)),
            ):
                connection.execute("SELECT pg_catalog.set_config(%s,%s,true)", (name, value))
            policy = connection.execute(
                "SELECT system_workload_principal_id,system_authority_marker_sha256,"
                "active_idempotency_key_id,active_payload_key_id,active_canonicalization_version "
                "FROM demand.receipt_key_policy WHERE singleton_key"
            ).fetchone()
            if policy != (SYSTEM_WORKLOAD_ID, SYSTEM_AUTHORITY_MARKER,
                    "demand-idempotency-2026-01", "demand-payload-2026-01", "demand-command-json-v1"):
                raise MatchingWorkflowError("WORKLOAD_AUTHORITY_UNAVAILABLE")
            replay = self._replay(connection, target, receipt)
            if replay is not None:
                connection.execute("COMMIT")
                self._connections.release(connection)
                return replay
            row = connection.execute(
                "SELECT v.id,v.content_sha256,f.source_event_id,d.creator_user_id "
                "FROM demand.demands d JOIN demand.demand_versions v "
                "ON v.id=d.current_version_id AND v.organization_id=d.organization_id "
                "AND v.demand_id=d.id JOIN demand.demand_funding_markers f "
                "ON f.id=d.current_funding_marker_id AND f.organization_id=d.organization_id "
                "AND f.demand_id=d.id AND f.demand_version_id=v.id "
                "WHERE d.organization_id=%s AND d.id=%s AND f.status='SECURED' "
                "AND d.verified_version_id=v.id",
                (target.organization_id, target.demand_id),
            ).fetchone()
            if row is None:
                raise MatchingWorkflowError("FUNDED_TARGET_NOT_FOUND")
            if (not isinstance(row[0], UUID) or not isinstance(row[2], UUID) or not isinstance(row[3], UUID)
                    or not isinstance(row[1], bytes) or len(row[1]) != 32):
                raise MatchingWorkflowError("WORKFLOW_DEPENDENCY_UNAVAILABLE")
            result = MatchingWorkflowSnapshot(*row)
            connection.execute("COMMIT")
            self._connections.release(connection)
            return result
        except BaseException:
            self._connections.discard(connection)
            raise

    @staticmethod
    def _replay(connection: Any, target: MatchingWorkflowTarget,
                receipt: DemandPostgresReceiptMaterial) -> Optional[DemandPostgresDatabaseResult]:
        row = connection.execute(
            "SELECT receipt_id,payload_hash_key_id,canonicalization_version,payload_hash,"
            "http_method,canonical_path,if_match_version,status,response_http_status,"
            "response_schema_name,response_schema_version,response_entity_tag,safe_response_body,"
            "target_id,target_version,result_status,event_types,completed_at "
            "FROM demand.command_receipts WHERE principal_kind='SYSTEM' AND principal_id=%s "
            "AND organization_id=%s AND command_name='RequestMatching' AND command_version=1 "
            "AND idempotency_key_digest_key_id=%s AND idempotency_key_digest=%s",
            (SYSTEM_WORKLOAD_ID, target.organization_id, receipt.idempotency_key_digest_key_id,
             receipt.idempotency_key_digest),
        ).fetchone()
        if row is None:
            return None
        if (row[0] != receipt.receipt_id or row[1] != receipt.payload_hash_key_id
                or row[2] != receipt.canonicalization_version or not isinstance(row[3], bytes)):
            raise MatchingWorkflowError("WORKFLOW_DEPENDENCY_UNAVAILABLE")
        if (not hmac.compare_digest(row[3], receipt.payload_hash)
                or (row[4], row[5], row[6]) != ("POST", receipt.canonical_path, target.expected_version)):
            raise MatchingWorkflowError("IDEMPOTENCY_KEY_REUSED")
        safe = row[12]
        if (row[7:11] != ("COMPLETED", 200, "DemandDto", 1)
                or row[11] != f'"v{row[14]}"' or row[13] != target.demand_id
                or type(row[14]) is not int or row[14] != target.expected_version + 1
                or row[15] != "MATCHING" or tuple(row[16]) != ("MatchingRequested",)
                or row[17] is None or not isinstance(safe, dict)
                or set(safe) != {"aggregate_version", "demand_id", "demand_version_id", "status"}
                or safe["aggregate_version"] != row[14] or safe["demand_id"] != str(target.demand_id)
                or safe["status"] != "MATCHING"):
            raise MatchingWorkflowError("WORKFLOW_DEPENDENCY_UNAVAILABLE")
        version = UUID(safe["demand_version_id"])
        if version.int == 0 or str(version) != safe["demand_version_id"]:
            raise MatchingWorkflowError("WORKFLOW_DEPENDENCY_UNAVAILABLE")
        return DemandPostgresDatabaseResult(operation=_OPERATION, replayed=True,
            demand_id=target.demand_id, current_version_id=version, status="MATCHING",
            aggregate_version=row[14], safe_response=safe, event_types=("MatchingRequested",))


class MatchingSystemWorkflow:
    def __init__(self, *, targets: Any, rules: Any, holds: Any, writer: Any,
                 idempotency_key: bytes, payload_key: bytes) -> None:
        if (not 32 <= len(idempotency_key) <= 64 or not 32 <= len(payload_key) <= 64
                or hmac.compare_digest(idempotency_key, payload_key)):
            raise ValueError("purpose-separated workflow keys are unavailable")
        self._targets, self._rules, self._holds, self._writer = targets, rules, holds, writer
        self._identity_key, self._payload_key = idempotency_key, payload_key

    def request(self, target: MatchingWorkflowTarget) -> DemandPostgresDatabaseResult:
        if not isinstance(target, MatchingWorkflowTarget):
            raise TypeError("exact Matching workflow target is required")
        now = datetime.now(timezone.utc)
        path = f"/v1/operations/demands/{target.demand_id}/request-matching"
        identity = f"{target.organization_id}:{target.request_id}".encode("ascii")
        identity_digest = self._hmac(b"workflow:request-matching:identity:v1\x00" + identity)
        command_id = self._id(identity_digest, "command")
        payload = json.dumps({
            "body": {}, "command_name": "RequestMatching", "command_version": 1,
            "organization_id": str(target.organization_id), "demand_id": str(target.demand_id),
            "http_method": "POST", "canonical_path": path,
            "if_match_version": target.expected_version,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        receipt = DemandPostgresReceiptMaterial(
            receipt_id=command_id, principal_kind="SYSTEM", principal_id=SYSTEM_WORKLOAD_ID,
            organization_id=target.organization_id, command_name="RequestMatching", command_version=1,
            idempotency_key_digest_key_id="demand-idempotency-2026-01",
            idempotency_key_digest=identity_digest, payload_hash_key_id="demand-payload-2026-01",
            canonicalization_version="demand-command-json-v1",
            payload_hash=hmac.new(self._payload_key, payload, hashlib.sha256).digest(),
            http_method="POST", canonical_path=path, if_match_version=target.expected_version,
            retain_until=now + timedelta(days=7),
        )
        snapshot = self._targets.read(target, receipt=receipt)
        if isinstance(snapshot, DemandPostgresDatabaseResult):
            return snapshot
        rule = self._rules.current_requirement(
            organization_id=str(target.organization_id), demand_id=str(target.demand_id),
            operation="REQUEST_MATCHING",
        )
        hold = self._holds.evaluate(
            actor_id=str(SYSTEM_WORKLOAD_ID), organization_id=str(target.organization_id),
            demand_id=str(target.demand_id), prospective_aggregate_version=target.expected_version + 1,
            demand_version_id=str(snapshot.demand_version_id),
            content_sha256=snapshot.content_sha256.hex(), action="REQUEST_MATCHING",
            policy_version="demand-safety-hold-v1",
        )
        if hold.decision is not DemandHoldDecision.ALLOW:
            raise MatchingWorkflowError("SAFETY_HOLD_BLOCKED")
        command = DemandPostgresCommand(
            operation=_OPERATION,
            scope=DemandPostgresExecutionScope(
                actor_kind="SYSTEM", actor_id=SYSTEM_WORKLOAD_ID, session_id=None,
                organization_id=target.organization_id, demand_id=target.demand_id,
                command_id=command_id, audit_event_id=self._id(identity_digest, "audit"),
                outbox_event_ids=(self._id(identity_digest, "outbox"),),
                correlation_id=self._id(identity_digest, "correlation"),
                causation_id=snapshot.funding_source_event_id,
                trace_id=self._id(identity_digest, "trace"), original_actor_id=snapshot.original_actor_user_id,
                expected_authority_marker_sha256=SYSTEM_AUTHORITY_MARKER,
            ),
            receipt=receipt,
            expected_aggregate_version=target.expected_version,
            demand_version_id=snapshot.demand_version_id, based_on_demand_version_id=None,
            taxonomy_bundle_id=None, matching_request_id=self._id(identity_digest, "matching-request"),
            hold=DemandPostgresHoldEvidence(
                actor_id=UUID(hold.actor_id), organization_id=UUID(hold.organization_id),
                demand_id=UUID(hold.demand_id), prospective_aggregate_version=hold.prospective_aggregate_version,
                demand_version_id=UUID(hold.demand_version_id), content_sha256=bytes.fromhex(hold.content_sha256),
                action=hold.action, decision=hold.decision.value, policy_version=hold.policy_version,
                evaluated_at=hold.evaluated_at, valid_until=hold.valid_until,
            ),
            rule_requirement=DemandPostgresRuleRequirement(
                taxonomy_bundle_id=UUID(rule.taxonomy_bundle_id),
                budget_rule_bundle_id=UUID(rule.budget_rule_bundle_id), risk_rule_bundle_id=UUID(rule.risk_rule_bundle_id),
                matching_rule_bundle_id=UUID(rule.matching_rule_bundle_id), reason_code_bundle_id=UUID(rule.reason_code_bundle_id),
                composite_rule_requirement_id=UUID(rule.composite_rule_requirement_id),
                requirement_sha256=bytes.fromhex(rule.requirement_sha256),
                effective_at=rule.effective_at, effective_until=rule.effective_until,
            ),
        )
        return self._writer.execute_request_matching_system(command)

    def _hmac(self, value: bytes) -> bytes:
        return hmac.new(self._identity_key, value, hashlib.sha256).digest()

    def _id(self, identity: bytes, kind: str) -> UUID:
        return UUID(bytes=self._hmac(b"workflow:request-matching:id:v1\x00" + identity + kind.encode("ascii"))[:16], version=4)


class _OneShotConnections:
    """No role switching, ambient DSN, or elevated credentials in this process."""

    def __init__(self, *, role: str, database: str, password: bytes) -> None:
        if role not in {"demand_system", "demand_self", "trust_decision"}:
            raise ValueError("workflow database role is closed")
        self._role, self._database, self._password = role, database, bytearray(password)

    def checkout(self) -> Any:
        connection = psycopg.connect(host="db", port=5432, dbname=self._database,
            user=self._role, password=bytes(self._password).decode("ascii"),
            sslmode="disable", connect_timeout=5, autocommit=True)
        try:
            facts = connection.execute(
                "SELECT session_user,current_user,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb "
                "FROM pg_catalog.pg_roles WHERE rolname=current_user"
            ).fetchone()
            if facts != (self._role, self._role, False, False, False, False):
                raise MatchingWorkflowError("WORKLOAD_AUTHORITY_UNAVAILABLE")
        except BaseException:
            connection.close()
            raise
        return connection

    def release(self, connection: Any) -> None:
        connection.close()

    def discard(self, connection: Any) -> None:
        connection.close()

    def close(self) -> None:
        self._password[:] = b"\x00" * len(self._password)


def _secret(directory: Path, name: str) -> bytes:
    path = directory / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or not 24 <= metadata.st_size <= 4096:
        raise MatchingWorkflowError("WORKFLOW_CREDENTIALS_UNAVAILABLE")
    value = path.read_bytes()
    if len(value) != metadata.st_size:
        raise MatchingWorkflowError("WORKFLOW_CREDENTIALS_UNAVAILABLE")
    return value


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization-id", required=True, type=UUID)
    parser.add_argument("--demand-id", required=True, type=UUID)
    parser.add_argument("--expected-version", required=True, type=int)
    parser.add_argument("--request-id", required=True, type=UUID)
    parser.add_argument("--database", required=True)
    parser.add_argument("--credential-directory", required=True, type=Path)
    args = parser.parse_args(argv)
    sources = []
    try:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", args.database) is None:
            raise MatchingWorkflowError("WORKFLOW_CONFIGURATION_INVALID")
        if not args.credential_directory.is_absolute() or args.credential_directory.is_symlink():
            raise MatchingWorkflowError("WORKFLOW_CREDENTIALS_UNAVAILABLE")
        target = MatchingWorkflowTarget(args.organization_id, args.demand_id, args.expected_version, args.request_id)
        material = [_secret(args.credential_directory, name) for name in _CREDENTIAL_FILES]
        for role, password in zip(("demand_system", "demand_self", "trust_decision"), material[:3]):
            sources.append(_OneShotConnections(role=role, database=args.database, password=password))
        validator = DemandPostgresContractValidator()
        workflow = MatchingSystemWorkflow(
            targets=PsycopgMatchingWorkflowTargetReader(connections=sources[0]),
            rules=PsycopgDemandRuleCatalog(connections=sources[1]),
            holds=PsycopgTrustDemandSafetyHoldProvider(decision_connections=sources[2]),
            writer=PsycopgDemandUnitOfWorkFactory(connections=sources[0], event_validator=validator, response_validator=validator),
            idempotency_key=material[3], payload_key=material[4],
        )
        result = workflow.request(target)
        print(json.dumps({"status": "MATCHING_REQUESTED", "demand_id": str(target.demand_id),
            "request_id": str(target.request_id), "aggregate_version": result.aggregate_version,
            "replayed": result.replayed}, sort_keys=True))
        return 0
    except Exception as error:
        safe_codes = {"WORKFLOW_CONFIGURATION_INVALID", "WORKFLOW_CREDENTIALS_UNAVAILABLE",
            "WORKLOAD_AUTHORITY_UNAVAILABLE", "FUNDED_TARGET_NOT_FOUND", "SAFETY_HOLD_BLOCKED",
            "PRECONDITION_FAILED", "INVALID_STATE_TRANSITION", "MATCHING_RULE_BUNDLE_CHANGED",
            "FUNDING_REQUIRED", "IDEMPOTENCY_KEY_REUSED", "RESOURCE_NOT_FOUND", "COMMIT_OUTCOME_UNKNOWN"}
        code = ("COMMIT_OUTCOME_UNKNOWN" if isinstance(error, DemandPostgresCommitOutcomeUnknownError)
            else getattr(error, "code", "WORKFLOW_DEPENDENCY_UNAVAILABLE"))
        print(json.dumps({"status": "FAILED", "code": code if code in safe_codes else "WORKFLOW_DEPENDENCY_UNAVAILABLE"}))
        return 1
    finally:
        for source in reversed(sources):
            source.close()


if __name__ == "__main__":
    raise SystemExit(main())
