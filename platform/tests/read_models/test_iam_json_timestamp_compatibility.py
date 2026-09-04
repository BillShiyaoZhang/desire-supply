"""PostgreSQL JSON timestamp precision must not depend on Python version."""

from datetime import datetime, timezone
import unittest

from desire_platform.identity_access.application.read_models import (
    _restore_json_timestamps,
)
from desire_platform.identity_access.adapters.postgres.read_models import (
    _restore_json_fact,
)


class IamJsonTimestampCompatibilityTest(unittest.TestCase):
    def test_both_read_paths_restore_postgres_fractional_second_widths(self) -> None:
        for restore in (_restore_json_timestamps, _restore_json_fact):
            for fraction in ("1", "12", "1234", "12345"):
                for zone in ("Z", "+00:00"):
                    with self.subTest(restore=restore.__name__, fraction=fraction, zone=zone):
                        encoded = "2026-09-04T10:00:00." + fraction + zone
                        source = {
                            "created_at": encoded,
                            "policies": [{"effective_at": encoded}],
                            "label": encoded,
                        }
                        expected = datetime(
                            2026, 9, 4, 10, 0, 0,
                            int(fraction.ljust(6, "0")), tzinfo=timezone.utc,
                        )
                        self.assertEqual(restore(source), {
                            "created_at": expected,
                            "policies": [{"effective_at": expected}],
                            "label": encoded,
                        })
                        self.assertEqual(source["created_at"], encoded)

    def test_non_utc_naive_and_invalid_text_remain_untrusted(self) -> None:
        for restore in (_restore_json_timestamps, _restore_json_fact):
            for encoded in (
                "2026-09-04T10:00:00.12345+08:00",
                "2026-09-04T10:00:00.12345",
                "2026-09-04T10:00:00.12345-00:00",
                "2026-09-04T10:00:00.1234567Z",
                "2026-09-04T10:00:00.12345Z\n",
                "2026-02-30T10:00:00Z",
            ):
                with self.subTest(restore=restore.__name__, encoded=encoded):
                    self.assertEqual(
                        restore({"effective_at": encoded}),
                        {"effective_at": encoded},
                    )
