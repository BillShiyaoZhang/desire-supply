"""Supplemental fail-closed tests for the outbox delivery GREEN."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import unittest

from desire_platform.outbox.delivery import (
    OutboxDeliveryCycleResult,
    OutboxDeliveryError,
    OutboxDeliveryErrorCode,
    OutboxDeliveryStatus,
    OutboxDeliveryWorker,
    OutboxPublishAcknowledgement,
)
from tests.support.outbox_delivery_builders import (
    StrictBrokerPublisher,
    StrictTelemetry,
    UTC_NOW,
    make_envelope,
    make_outbox_fixture,
    make_row,
)


def _worker(
    fixture,
    *,
    repository=None,
    registry=None,
    publisher=None,
    backoff=None,
    telemetry=None,
    worker_id: str = "outbox-worker-faults",
) -> OutboxDeliveryWorker:
    return OutboxDeliveryWorker(
        repository=repository or fixture.repository,
        schema_registry=registry or fixture.registry,
        publisher=publisher or fixture.publisher,
        clock=fixture.clock,
        backoff=backoff or fixture.backoff,
        telemetry=telemetry or fixture.telemetry,
        shutdown=fixture.shutdown,
        worker_id=worker_id,
    )


class _RepositoryProxy:
    def __init__(self, repository) -> None:
        self.repository = repository

    def __getattr__(self, name):
        return getattr(self.repository, name)


class _MarkOutcomeUnknownRepository(_RepositoryProxy):
    def mark_published(self, *, lease):
        raise OutboxDeliveryError(
            OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
        )


class _ClaimOutcomeUnknownRepository(_RepositoryProxy):
    def claim_batch(self, **_kwargs):
        raise OutboxDeliveryError(
            OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN
        )


class _MismatchedAckPublisher(StrictBrokerPublisher):
    def publish(self, message):
        acknowledgement = super().publish(message)
        return OutboxPublishAcknowledgement(
            event_id="evt_ack_mismatch_0001",
            acknowledged_at=acknowledgement.acknowledged_at,
        )


class _CorruptRegistry:
    def __init__(self, registry) -> None:
        self.registry = registry

    def check_readiness(self) -> None:
        self.registry.check_readiness()

    def validate(self, envelope):
        return replace(
            self.registry.validate(envelope),
            event_id="evt_registry_mismatch_0001",
        )


class _InvalidBackoff:
    def delay_for(self, *, event_id: str, attempt_count: int) -> timedelta:
        del event_id, attempt_count
        return timedelta(0)


class _FailingTelemetry(StrictTelemetry):
    def emit(self, event) -> None:
        del event
        raise RuntimeError("sentinel-telemetry-must-not-change-delivery")


class _StoppingPublisher(StrictBrokerPublisher):
    def __init__(self, *, shutdown, **kwargs) -> None:
        super().__init__(**kwargs)
        self.shutdown = shutdown

    def publish(self, message):
        acknowledgement = super().publish(message)
        self.shutdown.stopping = True
        return acknowledgement


class OutboxDeliveryWorkerFaultTests(unittest.TestCase):
    def test_mismatched_ack_is_unknown_and_same_row_is_rescheduled(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(rows=(make_row(envelope),))
        publisher = _MismatchedAckPublisher(
            clock=fixture.clock,
            consumer=fixture.consumer,
        )

        result = _worker(fixture, publisher=publisher).deliver_once()
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                result,
                row.delivery_status,
                row.last_error_code,
                publisher.accepted_event_ids,
                fixture.consumer.side_effects,
            ),
            (
                OutboxDeliveryCycleResult(
                    1,
                    0,
                    1,
                    0,
                    0,
                    (OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN,),
                ),
                OutboxDeliveryStatus.PENDING,
                OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN,
                [envelope.event_id],
                [(envelope.aggregate_id, 1, envelope.event_id)],
            ),
        )

    def test_mark_commit_unknown_does_not_guess_or_call_provider_twice(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(rows=(make_row(envelope),))
        repository = _MarkOutcomeUnknownRepository(fixture.repository)

        with self.assertRaises(OutboxDeliveryError) as caught:
            _worker(fixture, repository=repository).deliver_once()
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                caught.exception.code,
                row.delivery_status,
                row.lease_owner,
                fixture.publisher.accepted_event_ids,
                fixture.backoff.calls,
            ),
            (
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN,
                OutboxDeliveryStatus.LEASED,
                "outbox-worker-faults",
                [envelope.event_id],
                [],
            ),
        )

    def test_claim_commit_unknown_never_calls_registry_or_broker(self) -> None:
        fixture = make_outbox_fixture()
        repository = _ClaimOutcomeUnknownRepository(fixture.repository)

        with self.assertRaises(OutboxDeliveryError) as caught:
            _worker(fixture, repository=repository).deliver_once()

        self.assertEqual(
            (
                caught.exception.code,
                fixture.registry.validation_calls,
                fixture.publisher.calls,
            ),
            (
                OutboxDeliveryErrorCode.DELIVERY_STORAGE_OUTCOME_UNKNOWN,
                [],
                [],
            ),
        )

    def test_registry_result_mismatch_fails_closed_without_broker(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(rows=(make_row(envelope),))
        registry = _CorruptRegistry(fixture.registry)

        with self.assertRaises(OutboxDeliveryError) as caught:
            _worker(fixture, registry=registry).deliver_once()
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                caught.exception.code,
                row.delivery_status,
                row.lease_owner,
                fixture.publisher.calls,
            ),
            (
                OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE,
                OutboxDeliveryStatus.LEASED,
                "outbox-worker-faults",
                [],
            ),
        )

    def test_invalid_backoff_never_writes_an_early_retry(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(
            rows=(make_row(envelope),),
            publisher_modes=(StrictBrokerPublisher.BEFORE_ACK,),
        )

        with self.assertRaises(OutboxDeliveryError) as caught:
            _worker(fixture, backoff=_InvalidBackoff()).deliver_once()
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                caught.exception.code,
                row.delivery_status,
                row.lease_owner,
                row.available_at,
            ),
            (
                OutboxDeliveryErrorCode.OUTBOX_CONFIGURATION_INVALID,
                OutboxDeliveryStatus.LEASED,
                "outbox-worker-faults",
                UTC_NOW,
            ),
        )

    def test_telemetry_failure_does_not_change_published_result(self) -> None:
        fixture = make_outbox_fixture()

        result = _worker(
            fixture,
            telemetry=_FailingTelemetry(),
        ).deliver_once()
        row = fixture.repository.snapshot(make_envelope().event_id)

        self.assertEqual(
            (result, row.delivery_status),
            (
                OutboxDeliveryCycleResult(1, 1, 0, 0, 0),
                OutboxDeliveryStatus.PUBLISHED,
            ),
        )

    def test_mid_batch_shutdown_releases_only_unstarted_leases(self) -> None:
        first = make_envelope(1)
        second = make_envelope(2, aggregate_sequence=2)
        fixture = make_outbox_fixture(rows=(make_row(first), make_row(second)))
        publisher = _StoppingPublisher(
            shutdown=fixture.shutdown,
            clock=fixture.clock,
            consumer=fixture.consumer,
        )

        result = _worker(fixture, publisher=publisher).deliver_once(batch_size=2)
        first_row = fixture.repository.snapshot(first.event_id)
        second_row = fixture.repository.snapshot(second.event_id)

        self.assertEqual(
            (
                result,
                first_row.delivery_status,
                second_row.delivery_status,
                second_row.lease_owner,
                publisher.accepted_event_ids,
                fixture.repository.operation_log,
            ),
            (
                OutboxDeliveryCycleResult(2, 1, 0, 0, 0),
                OutboxDeliveryStatus.PUBLISHED,
                OutboxDeliveryStatus.PENDING,
                None,
                [first.event_id],
                [
                    ("claim", first.event_id),
                    ("claim", second.event_id),
                    ("published", first.event_id),
                    ("released", second.event_id),
                ],
            ),
        )


if __name__ == "__main__":
    unittest.main()
