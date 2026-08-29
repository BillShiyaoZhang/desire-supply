"""TEST-OUTBOX-DELIVERY-001: executable RED for safe outbox delivery."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import timedelta
import json
from threading import Barrier, Lock, Thread
from typing import Optional, Tuple
import unittest

from desire_platform.outbox.delivery import (
    OutboxAttemptBucket,
    OutboxDeliveryCycleResult,
    OutboxDeliveryError,
    OutboxDeliveryErrorCode,
    OutboxDeliveryStatus,
    OutboxDeliveryWorker,
    OutboxTelemetryOutcome,
)
from tests.support.outbox_delivery_builders import (
    StrictBrokerPublisher,
    UTC_NOW,
    make_envelope,
    make_outbox_fixture,
    make_row,
    stopped_result,
)


def _cycle(
    worker: OutboxDeliveryWorker, *, batch_size: int = 100
) -> Tuple[
    Optional[OutboxDeliveryCycleResult], Optional[OutboxDeliveryErrorCode]
]:
    try:
        return worker.deliver_once(batch_size=batch_size), None
    except OutboxDeliveryError as error:
        return None, error.code


def _worker(fixture, worker_id: str) -> OutboxDeliveryWorker:
    return OutboxDeliveryWorker(
        repository=fixture.repository,
        schema_registry=fixture.registry,
        publisher=fixture.publisher,
        clock=fixture.clock,
        backoff=fixture.backoff,
        telemetry=fixture.telemetry,
        shutdown=fixture.shutdown,
        worker_id=worker_id,
    )


class OutboxDeliveryWorkerRedTests(unittest.TestCase):
    def test_contract_is_importable_immutable_closed_and_worker_is_enabled(self) -> None:
        fixture = make_outbox_fixture()
        envelope = make_envelope()

        with self.assertRaises(FrozenInstanceError):
            envelope.event_id = "evt_mutation_forbidden"  # type: ignore[misc]
        result, error = _cycle(fixture.worker)

        self.assertEqual(
            (
                {status.value for status in OutboxDeliveryStatus},
                {code.value for code in OutboxDeliveryErrorCode},
                {outcome.value for outcome in OutboxTelemetryOutcome},
                {bucket.value for bucket in OutboxAttemptBucket},
                error,
                result,
                fixture.repository.claim_calls,
                fixture.publisher.accepted_event_ids,
            ),
            (
                {"PENDING", "LEASED", "PUBLISHED", "DEAD"},
                {
                    "BROKER_UNAVAILABLE",
                    "BROKER_ACK_UNKNOWN",
                    "SCHEMA_REGISTRY_UNAVAILABLE",
                    "OUTBOX_SCHEMA_UNSUPPORTED",
                    "OUTBOX_EVENT_INVALID",
                    "DELIVERY_ATTEMPTS_EXHAUSTED",
                    "DELIVERY_STORAGE_OUTCOME_UNKNOWN",
                    "OUTBOX_CLOCK_INVALID",
                    "OUTBOX_CONFIGURATION_INVALID",
                },
                {"PUBLISHED", "RETRY_SCHEDULED", "DEAD_LETTERED", "STALE_LEASE"},
                {"1", "2_3", "4_7", "8_PLUS"},
                None,
                OutboxDeliveryCycleResult(1, 1, 0, 0, 0),
                1,
                [envelope.event_id],
            ),
        )

    def test_two_workers_concurrently_claim_one_event_once(self) -> None:
        fixture = make_outbox_fixture()
        workers = (_worker(fixture, "outbox-worker-a"), _worker(fixture, "outbox-worker-b"))
        start = Barrier(3)
        result_lock = Lock()
        errors: list[OutboxDeliveryErrorCode] = []

        def run(worker: OutboxDeliveryWorker) -> None:
            start.wait()
            _result, error = _cycle(worker)
            if error is not None:
                with result_lock:
                    errors.append(error)

        threads = [Thread(target=run, args=(worker,)) for worker in workers]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(timeout=2)

        row = fixture.repository.snapshot(make_envelope().event_id)
        claim_facts = [history[1:] for history in fixture.repository.claim_history]
        claim_owners_are_controlled = all(
            history[0] in {"outbox-worker-a", "outbox-worker-b"}
            for history in fixture.repository.claim_history
        )
        self.assertEqual(
            (
                [thread.is_alive() for thread in threads],
                errors,
                len(fixture.repository.claim_history),
                claim_facts,
                claim_owners_are_controlled,
                fixture.publisher.accepted_event_ids,
                row.delivery_status,
                row.attempt_count,
            ),
            (
                [False, False],
                [],
                1,
                [(make_envelope().event_id, 1, False)],
                True,
                [make_envelope().event_id],
                OutboxDeliveryStatus.PUBLISHED,
                1,
            ),
        )

    def test_unexpired_lease_is_not_stolen_and_equal_deadline_is_reclaimed(self) -> None:
        envelope = make_envelope()
        lease_until = UTC_NOW + timedelta(seconds=10)
        fixture = make_outbox_fixture(
            rows=(
                make_row(
                    envelope,
                    status=OutboxDeliveryStatus.LEASED,
                    attempt_count=1,
                    lease_owner="outbox-worker-old",
                    leased_at=UTC_NOW - timedelta(seconds=20),
                    lease_until=lease_until,
                ),
            ),
            worker_id="outbox-worker-new",
        )

        before_result, before_error = _cycle(fixture.worker)
        before = fixture.repository.snapshot(envelope.event_id)
        fixture.clock.advance(timedelta(seconds=10))
        after_result, after_error = _cycle(fixture.worker)
        after = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                before_error,
                before_result,
                before.delivery_status,
                before.lease_owner,
                after_error,
                None if after_result is None else after_result.lease_reclaimed_count,
                after.delivery_status,
                after.attempt_count,
                fixture.repository.claim_history,
            ),
            (
                None,
                stopped_result(),
                OutboxDeliveryStatus.LEASED,
                "outbox-worker-old",
                None,
                1,
                OutboxDeliveryStatus.PUBLISHED,
                2,
                [("outbox-worker-new", envelope.event_id, 2, True)],
            ),
        )

    def test_success_publishes_validated_original_event_and_fenced_terminal_row(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(rows=(make_row(envelope),))

        result, error = _cycle(fixture.worker)
        row = fixture.repository.snapshot(envelope.event_id)
        message = fixture.publisher.calls[0] if fixture.publisher.calls else None
        body = (
            json.loads(message.canonical_bytes.decode("utf-8"))
            if message is not None
            else None
        )

        self.assertEqual(
            (
                error,
                result,
                row.delivery_status,
                row.attempt_count,
                row.lease_owner,
                row.lease_until,
                row.published_at,
                None if message is None else message.event_id,
                None if body is None else body["event_id"],
                None if body is None else set(body),
            ),
            (
                None,
                OutboxDeliveryCycleResult(1, 1, 0, 0, 0),
                OutboxDeliveryStatus.PUBLISHED,
                1,
                None,
                None,
                UTC_NOW,
                envelope.event_id,
                envelope.event_id,
                {
                    "event_id",
                    "event_type",
                    "schema_version",
                    "occurred_at",
                    "aggregate_type",
                    "aggregate_id",
                    "aggregate_version",
                    "actor_kind",
                    "actor_id",
                    "original_actor_id",
                    "correlation_id",
                    "causation_id",
                    "trace_id",
                    "organization_id",
                    "payload",
                },
            ),
        )

    def test_provider_before_ack_reschedules_with_bounded_backoff_then_succeeds(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(
            rows=(make_row(envelope),),
            publisher_modes=(
                StrictBrokerPublisher.BEFORE_ACK,
                StrictBrokerPublisher.SUCCESS,
            ),
        )

        first_result, first_error = _cycle(fixture.worker)
        first = fixture.repository.snapshot(envelope.event_id)
        fixture.clock.advance(timedelta(seconds=1))
        second_result, second_error = _cycle(fixture.worker)
        second = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                first_error,
                first_result,
                first.delivery_status,
                first.attempt_count,
                first.available_at,
                first.last_error_code,
                second_error,
                second_result,
                second.delivery_status,
                second.attempt_count,
                [message.event_id for message in fixture.publisher.calls],
                fixture.publisher.accepted_event_ids,
                fixture.backoff.calls,
            ),
            (
                None,
                OutboxDeliveryCycleResult(
                    1,
                    0,
                    1,
                    0,
                    0,
                    (OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,),
                ),
                OutboxDeliveryStatus.PENDING,
                1,
                UTC_NOW + timedelta(seconds=1),
                OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
                None,
                OutboxDeliveryCycleResult(1, 1, 0, 0, 0),
                OutboxDeliveryStatus.PUBLISHED,
                2,
                [envelope.event_id, envelope.event_id],
                [envelope.event_id],
                [(envelope.event_id, 1)],
            ),
        )

    def test_provider_after_ack_retries_same_event_id_and_consumer_deduplicates(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(
            rows=(make_row(envelope),),
            publisher_modes=(
                StrictBrokerPublisher.AFTER_ACK,
                StrictBrokerPublisher.SUCCESS,
            ),
        )

        first_result, first_error = _cycle(fixture.worker)
        fixture.clock.advance(timedelta(seconds=1))
        second_result, second_error = _cycle(fixture.worker)
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                first_error,
                None if first_result is None else first_result.rescheduled_count,
                None if first_result is None else first_result.failure_codes,
                second_error,
                None if second_result is None else second_result.published_count,
                fixture.publisher.accepted_event_ids,
                fixture.consumer.side_effects,
                len(fixture.consumer.inbox),
                row.delivery_status,
                row.attempt_count,
            ),
            (
                None,
                1,
                (OutboxDeliveryErrorCode.BROKER_ACK_UNKNOWN,),
                None,
                1,
                [envelope.event_id, envelope.event_id],
                [(envelope.aggregate_id, 1, envelope.event_id)],
                1,
                OutboxDeliveryStatus.PUBLISHED,
                2,
            ),
        )

    def test_out_of_order_versions_wait_for_gap_and_duplicate_event_is_noop(self) -> None:
        version_two = make_envelope(
            1, aggregate_sequence=7, aggregate_version=2
        )
        version_one = make_envelope(
            2, aggregate_sequence=7, aggregate_version=1
        )
        fixture = make_outbox_fixture(
            rows=(make_row(version_two), make_row(version_one)),
        )

        first_result, first_error = _cycle(fixture.worker, batch_size=1)
        after_gap = list(fixture.consumer.side_effects)
        second_result, second_error = _cycle(fixture.worker, batch_size=1)
        duplicate_result = (
            fixture.consumer.consume(fixture.publisher.calls[0])
            if fixture.publisher.calls
            else None
        )

        self.assertEqual(
            (
                first_error,
                None if first_result is None else first_result.published_count,
                after_gap,
                second_error,
                None if second_result is None else second_result.published_count,
                [effect[1] for effect in fixture.consumer.side_effects],
                len(fixture.consumer.inbox),
                duplicate_result,
            ),
            (None, 1, [], None, 1, [1, 2], 2, False),
        )

    def test_unsupported_schema_is_dead_without_calling_broker(self) -> None:
        envelope = make_envelope(schema_version=99)
        fixture = make_outbox_fixture(rows=(make_row(envelope),))

        result, error = _cycle(fixture.worker)
        row = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                error,
                result,
                row.delivery_status,
                row.last_error_code,
                fixture.registry.validation_calls,
                fixture.publisher.calls,
            ),
            (
                None,
                OutboxDeliveryCycleResult(
                    1,
                    0,
                    0,
                    1,
                    0,
                    (OutboxDeliveryErrorCode.OUTBOX_SCHEMA_UNSUPPORTED,),
                ),
                OutboxDeliveryStatus.DEAD,
                OutboxDeliveryErrorCode.OUTBOX_SCHEMA_UNSUPPORTED,
                [envelope.event_id],
                [],
            ),
        )

    def test_exhausted_attempts_are_dead_without_another_publish(self) -> None:
        envelope = make_envelope()
        fixture = make_outbox_fixture(
            rows=(make_row(envelope, attempt_count=8),), max_attempts=8
        )

        result, error = _cycle(fixture.worker)
        row = fixture.repository.snapshot(envelope.event_id)
        replay_result, replay_error = _cycle(fixture.worker)
        after_replay = fixture.repository.snapshot(envelope.event_id)

        self.assertEqual(
            (
                error,
                result,
                row.delivery_status,
                row.attempt_count,
                row.last_error_code,
                fixture.repository.claim_history,
                fixture.publisher.calls,
                replay_error,
                replay_result,
                after_replay.delivery_status,
                after_replay.attempt_count,
            ),
            (
                None,
                OutboxDeliveryCycleResult(
                    0,
                    0,
                    0,
                    1,
                    0,
                    (OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED,),
                ),
                OutboxDeliveryStatus.DEAD,
                8,
                OutboxDeliveryErrorCode.DELIVERY_ATTEMPTS_EXHAUSTED,
                [],
                [],
                None,
                stopped_result(),
                OutboxDeliveryStatus.DEAD,
                8,
            ),
        )

    def test_hostile_provider_secret_never_reaches_result_row_or_telemetry(self) -> None:
        secret = "sentinel-provider-token-contact-consent-body"
        envelope = make_envelope()
        fixture = make_outbox_fixture(
            rows=(make_row(envelope),),
            publisher_modes=(StrictBrokerPublisher.BEFORE_ACK,),
            provider_detail=secret,
        )

        result, error = _cycle(fixture.worker)
        row = fixture.repository.snapshot(envelope.event_id)
        observable = repr(
            (
                result,
                error,
                row.delivery_status,
                row.last_error_code,
                fixture.repository.operation_log,
                fixture.telemetry.events,
            )
        )

        self.assertEqual(
            (
                error,
                None if result is None else result.rescheduled_count,
                row.delivery_status,
                row.last_error_code,
                len(fixture.publisher.calls),
                [event.error_code for event in fixture.telemetry.events],
                secret in observable,
            ),
            (
                None,
                1,
                OutboxDeliveryStatus.PENDING,
                OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
                1,
                [OutboxDeliveryErrorCode.BROKER_UNAVAILABLE],
                False,
            ),
        )

    def test_shutdown_and_non_utc_clock_fail_closed_before_claim(self) -> None:
        stopped = make_outbox_fixture(stopping=True)
        stopped_cycle, stopped_error = _cycle(stopped.worker)
        invalid_clock = make_outbox_fixture(now=UTC_NOW.replace(tzinfo=None))
        invalid_cycle, invalid_error = _cycle(invalid_clock.worker)
        registry_down = make_outbox_fixture(registry_available=False)
        registry_cycle, registry_error = _cycle(registry_down.worker)
        publisher_down = make_outbox_fixture(publisher_ready=False)
        publisher_cycle, publisher_error = _cycle(publisher_down.worker)

        self.assertEqual(
            (
                stopped_cycle,
                stopped_error,
                stopped.repository.claim_calls,
                stopped.publisher.calls,
                invalid_cycle,
                invalid_error,
                invalid_clock.repository.claim_calls,
                invalid_clock.publisher.calls,
                registry_cycle,
                registry_error,
                registry_down.repository.claim_calls,
                publisher_cycle,
                publisher_error,
                publisher_down.repository.claim_calls,
            ),
            (
                stopped_result(),
                None,
                0,
                [],
                None,
                OutboxDeliveryErrorCode.OUTBOX_CLOCK_INVALID,
                0,
                [],
                None,
                OutboxDeliveryErrorCode.SCHEMA_REGISTRY_UNAVAILABLE,
                0,
                None,
                OutboxDeliveryErrorCode.BROKER_UNAVAILABLE,
                0,
            ),
        )


if __name__ == "__main__":
    unittest.main()
