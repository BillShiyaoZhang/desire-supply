from __future__ import annotations

import unittest

from desire_platform.internal_pilot.seed_readiness import (
    InternalSandboxSeedReadinessError,
    PostgresInternalSandboxSeedReadiness,
)


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(self, row):
        self._row = row
        self.statements = []

    def execute(self, statement):
        self.statements.append(statement)
        if statement == PostgresInternalSandboxSeedReadiness.statement():
            return _Result(self._row)
        return _Result(None)


class _Pool:
    def __init__(self, row):
        self.connection = _Connection(row)
        self.released = []
        self.discarded = []

    def checkout(self):
        return self.connection

    def release(self, connection):
        self.released.append(connection)

    def discard(self, connection):
        self.discarded.append(connection)


class InternalSandboxSeedReadinessTests(unittest.TestCase):
    def test_only_the_exact_seeded_singleton_is_ready(self) -> None:
        pool = _Pool((True,))
        readiness = PostgresInternalSandboxSeedReadiness(pool=pool)

        self.assertIsNone(readiness.check_readiness(timeout_ms=500))
        self.assertEqual(pool.released, [pool.connection])
        self.assertEqual(pool.discarded, [])
        self.assertEqual(
            pool.connection.statements,
            [
                "BEGIN TRANSACTION READ ONLY",
                "SET LOCAL TIME ZONE 'UTC'",
                "SET LOCAL statement_timeout = '500ms'",
                "SELECT profile_api.internal_sandbox_taxonomy_seed_ready_v1()",
                "COMMIT",
            ],
        )

    def test_missing_false_or_open_shaped_seed_fails_closed(self) -> None:
        for row in (None, (False,), (1,), (True, False), [True]):
            with self.subTest(row=row):
                pool = _Pool(row)
                readiness = PostgresInternalSandboxSeedReadiness(pool=pool)
                with self.assertRaises(InternalSandboxSeedReadinessError) as raised:
                    readiness.check_readiness(timeout_ms=500)
                self.assertEqual(
                    raised.exception.code,
                    "INTERNAL_SANDBOX_SEED_NOT_READY",
                )
                self.assertEqual(pool.released, [])
                self.assertEqual(pool.discarded, [pool.connection])

    def test_close_is_terminal_and_repr_exposes_no_seed_facts(self) -> None:
        readiness = PostgresInternalSandboxSeedReadiness(pool=_Pool((True,)))
        readiness.close()
        with self.assertRaises(InternalSandboxSeedReadinessError):
            readiness.check_readiness(timeout_ms=500)
        self.assertNotIn("418567", repr(readiness))


if __name__ == "__main__":
    unittest.main()
