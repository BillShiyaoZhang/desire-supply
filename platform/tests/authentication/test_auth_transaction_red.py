"""State-machine semantic RED for TEST-AUTH-TRANSACTION-001."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from typing import Any, Callable
import unittest

from desire_platform.identity_access.domain.authentication import (
    AuthPurpose,
    AuthTransaction,
    AuthTransactionStatus,
    ProviderErrorClass,
)
from desire_platform.identity_access.domain.errors import IamError
from tests.support.iam_authentication_builders import (
    AUTH_TRANSACTION_ID,
    RAW_BROWSER_COOKIE,
    RAW_CODE_VERIFIER,
    RAW_NONCE,
    RAW_STATE,
    UTC_NOW,
    authentication_fixture,
    seed_pending_auth_transaction,
)


def _capture(call: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return call(), None
    except IamError as error:
        return None, error.code
    except Exception as error:  # keep unexpected failures assertion-visible
        return None, type(error).__name__


def _pending_value() -> AuthTransaction:
    fixture = authentication_fixture()
    seed_pending_auth_transaction(fixture)
    row = dict(
        fixture.store.snapshot()["auth_transactions"][AUTH_TRANSACTION_ID]
    )
    row["status"] = AuthTransactionStatus(row["status"])
    row["purpose"] = AuthPurpose(row["purpose"])
    return AuthTransaction(**row)


class AuthTransactionStateMachineSemanticRedTest(unittest.TestCase):
    """Freeze CAS, exclusive deadlines, terminality, and safe representation."""

    def test_pending_value_is_frozen_and_hides_every_protocol_secret(self) -> None:
        transaction = _pending_value()
        rendered = repr(transaction)
        for raw_secret in (
            RAW_BROWSER_COOKIE,
            RAW_STATE,
            RAW_NONCE,
            RAW_CODE_VERIFIER,
        ):
            with self.subTest(raw_secret=raw_secret[:12]):
                self.assertNotIn(raw_secret, rendered)
        with self.assertRaises(FrozenInstanceError):
            transaction.status = AuthTransactionStatus.SUCCEEDED  # type: ignore[misc]

    def test_pending_claim_is_one_way_compare_and_consume_to_version_two(
        self,
    ) -> None:
        pending = _pending_value()
        claimed, claim_error = _capture(
            lambda: pending.claim_exchange(
                owner_id="exchange_owner_oidc_0001",
                now=UTC_NOW,
            )
        )
        duplicate, duplicate_error = _capture(
            lambda: claimed.claim_exchange(
                owner_id="exchange_owner_oidc_0002",
                now=UTC_NOW,
            )
        ) if claimed is not None else (None, claim_error)

        self.assertEqual(
            {
                "claim_error": claim_error,
                "status": getattr(claimed, "status", None),
                "owner": getattr(claimed, "exchange_owner_id", None),
                "attempt": getattr(claimed, "attempt", None),
                "version": getattr(claimed, "aggregate_version", None),
                "duplicate": duplicate,
                "duplicate_error": duplicate_error,
            },
            {
                "claim_error": None,
                "status": AuthTransactionStatus.EXCHANGING,
                "owner": "exchange_owner_oidc_0001",
                "attempt": 1,
                "version": 2,
                "duplicate": None,
                "duplicate_error": "AUTH_TRANSACTION_INVALID",
            },
        )

    def test_claim_uses_exclusive_utc_deadline_and_rejects_terminal_states(
        self,
    ) -> None:
        pending = _pending_value()
        cases = (
            ("at-deadline", replace(pending), pending.deadline),
            (
                "already-exchanging",
                replace(
                    pending,
                    status=AuthTransactionStatus.EXCHANGING,
                    aggregate_version=2,
                    attempt=1,
                    exchange_owner_id="exchange_owner_oidc_existing_0000",
                    exchange_claimed_at=UTC_NOW,
                ),
                UTC_NOW,
            ),
            (
                "succeeded",
                replace(
                    pending,
                    status=AuthTransactionStatus.SUCCEEDED,
                    aggregate_version=3,
                ),
                UTC_NOW,
            ),
            (
                "result-unknown",
                replace(
                    pending,
                    status=AuthTransactionStatus.RESULT_UNKNOWN,
                    aggregate_version=3,
                ),
                UTC_NOW,
            ),
            (
                "failed",
                replace(
                    pending,
                    status=AuthTransactionStatus.FAILED,
                    aggregate_version=3,
                ),
                UTC_NOW,
            ),
        )

        for name, transaction, now in cases:
            with self.subTest(name=name):
                claimed, code = _capture(
                    lambda: transaction.claim_exchange(
                        owner_id="exchange_owner_oidc_0001",
                        now=now,
                    )
                )
                self.assertEqual(
                    (claimed, code),
                    (None, "AUTH_TRANSACTION_INVALID"),
                )

    def test_exchanging_has_closed_success_failure_and_unknown_terminals(
        self,
    ) -> None:
        exchanging = replace(
            _pending_value(),
            status=AuthTransactionStatus.EXCHANGING,
            aggregate_version=2,
            attempt=1,
            exchange_owner_id="exchange_owner_oidc_0001",
            exchange_claimed_at=UTC_NOW,
        )
        operations = (
            (
                "success",
                lambda: exchanging.succeed(now=UTC_NOW),
                AuthTransactionStatus.SUCCEEDED,
                None,
            ),
            (
                "explicit-rejection",
                lambda: exchanging.fail(
                    error_class=ProviderErrorClass.REJECTED,
                    now=UTC_NOW,
                ),
                AuthTransactionStatus.FAILED,
                ProviderErrorClass.REJECTED,
            ),
            (
                "result-unknown",
                lambda: exchanging.mark_result_unknown(now=UTC_NOW),
                AuthTransactionStatus.RESULT_UNKNOWN,
                ProviderErrorClass.RESULT_UNKNOWN,
            ),
        )

        for name, operation, expected_status, expected_error in operations:
            with self.subTest(name=name):
                terminal, code = _capture(operation)
                self.assertEqual(
                    {
                        "code": code,
                        "status": getattr(terminal, "status", None),
                        "provider_error": getattr(
                            terminal,
                            "provider_error_class",
                            None,
                        ),
                        "version": getattr(
                            terminal,
                            "aggregate_version",
                            None,
                        ),
                    },
                    {
                        "code": None,
                        "status": expected_status,
                        "provider_error": expected_error,
                        "version": 3,
                    },
                )


if __name__ == "__main__":
    unittest.main()
