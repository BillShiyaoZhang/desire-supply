"""Managed ownership boundary for the Trust0001 PostgreSQL runtime."""

from __future__ import annotations

from typing import Any

from desire_platform.trust_safety.adapters.postgres import (
    PsycopgTrustCommandGateway,
    PsycopgTrustHttpProjectionAdapter,
    PsycopgTrustOutcomeEvidenceProvider,
    PsycopgTrustReceiptProbe,
    PsycopgTrustRuntimeReadiness,
    PsycopgTrustSealedNoteProvider,
    TrustPostgresReceiptKeyring,
)


class InternalSandboxTrustPostgresRuntime:
    """Own Trust write/read dependencies behind its eight-query projection port.

    The HTTP composition already owns its projection capability as one managed
    resource.  This closed wrapper uses that same lifecycle slot to retain and
    close the command gateway, receipt recovery, encrypted-note, decision
    evidence, and runtime key-policy dependencies needed by the nine writes.
    """

    def __init__(
        self,
        *,
        projections: PsycopgTrustHttpProjectionAdapter,
        command_gateway: PsycopgTrustCommandGateway,
        receipt_probe: PsycopgTrustReceiptProbe,
        receipt_keyring: TrustPostgresReceiptKeyring,
        sealed_notes: PsycopgTrustSealedNoteProvider,
        outcome_evidence: PsycopgTrustOutcomeEvidenceProvider,
        runtime_readiness: PsycopgTrustRuntimeReadiness,
    ) -> None:
        values = (
            (projections, PsycopgTrustHttpProjectionAdapter),
            (command_gateway, PsycopgTrustCommandGateway),
            (receipt_probe, PsycopgTrustReceiptProbe),
            (receipt_keyring, TrustPostgresReceiptKeyring),
            (sealed_notes, PsycopgTrustSealedNoteProvider),
            (outcome_evidence, PsycopgTrustOutcomeEvidenceProvider),
            (runtime_readiness, PsycopgTrustRuntimeReadiness),
        )
        if any(not isinstance(value, expected) for value, expected in values):
            raise TypeError("managed Trust PostgreSQL runtime is unavailable")
        if len({id(value) for value, _expected in values}) != len(values):
            raise TypeError("managed Trust PostgreSQL resources are aliased")
        self._projections = projections
        self._command_gateway = command_gateway
        self._receipt_probe = receipt_probe
        self._receipt_keyring = receipt_keyring
        self._sealed_notes = sealed_notes
        self._outcome_evidence = outcome_evidence
        self._runtime_readiness = runtime_readiness
        self._closed = False

    def read_own_report(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_own_report(**values)

    def list_own_reports(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_own_reports(**values)

    def list_case_queue(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_case_queue(**values)

    def list_hold_release_queue(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_hold_release_queue(**values)

    def list_my_active_case_assignments(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_my_active_case_assignments(**values)

    def list_my_completed_case_assignments(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.list_my_completed_case_assignments(**values)

    def read_assigned_case(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_assigned_case(**values)

    def read_assigned_hold_release(self, **values: Any) -> Any:
        self._require_open()
        return self._projections.read_assigned_hold_release(**values)

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
            or self._runtime_readiness._settings.statement_timeout_ms > timeout_ms
        ):
            raise RuntimeError("TRUST_RUNTIME_NOT_READY")
        try:
            result = self._runtime_readiness.verify(
                receipt_keyring=self._receipt_keyring,
                sealed_text_keyring=self._sealed_notes._keyring,
            )
        except BaseException:
            raise RuntimeError("TRUST_RUNTIME_NOT_READY") from None
        if result is None:
            raise RuntimeError("TRUST_RUNTIME_NOT_READY")
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for resource in (
            self._runtime_readiness,
            self._projections,
            self._outcome_evidence,
            self._sealed_notes,
            self._receipt_probe,
            self._command_gateway,
            self._receipt_keyring,
        ):
            try:
                resource.close()
            except BaseException:
                pass

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("TRUST_RUNTIME_NOT_READY")

    def __repr__(self) -> str:
        return (
            "InternalSandboxTrustPostgresRuntime("
            f"closed={self._closed}, dependencies=<redacted>)"
        )


__all__ = ["InternalSandboxTrustPostgresRuntime"]
