"""Online proof that the reviewed offline synthetic seed completed."""

from __future__ import annotations

from typing import Any


_STATEMENT = "SELECT profile_api.internal_sandbox_taxonomy_seed_ready_v1()"


class InternalSandboxSeedReadinessError(RuntimeError):
    def __init__(self) -> None:
        self.code = "INTERNAL_SANDBOX_SEED_NOT_READY"
        super().__init__(self.code)


class PostgresInternalSandboxSeedReadiness:
    """Read the Profile projection produced by the final offline seed stage.

    The database fixed program owns the exact seed, bundle, release and
    projection facts.  This adapter deliberately accepts none of those facts
    from ambient configuration, and it treats every result other than the
    literal PostgreSQL boolean singleton as unavailable.
    """

    def __init__(self, *, pool: Any) -> None:
        if not all(
            callable(getattr(pool, name, None))
            for name in ("checkout", "release", "discard")
        ):
            raise TypeError("internal sandbox seed readiness pool is unavailable")
        self._pool = pool
        self._closed = False

    @staticmethod
    def statement() -> str:
        return _STATEMENT

    def check_readiness(self, *, timeout_ms: int) -> None:
        if (
            self._closed
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= 30_000
        ):
            raise InternalSandboxSeedReadinessError()
        connection = None
        transaction = False
        try:
            connection = self._pool.checkout()
            connection.execute("BEGIN TRANSACTION READ ONLY")
            transaction = True
            connection.execute("SET LOCAL TIME ZONE 'UTC'")
            connection.execute(
                "SET LOCAL statement_timeout = '%dms'" % timeout_ms
            )
            row = connection.execute(_STATEMENT).fetchone()
            if not isinstance(row, tuple) or len(row) != 1 or row[0] is not True:
                raise RuntimeError("internal sandbox seed projection is unavailable")
            connection.execute("COMMIT")
            transaction = False
            self._pool.release(connection)
            connection = None
            return None
        except BaseException:
            if connection is not None:
                try:
                    if transaction:
                        connection.execute("ROLLBACK")
                except BaseException:
                    pass
                try:
                    self._pool.discard(connection)
                except BaseException:
                    pass
            raise InternalSandboxSeedReadinessError() from None

    def close(self) -> None:
        self._closed = True

    def __repr__(self) -> str:
        return (
            "PostgresInternalSandboxSeedReadiness("
            f"closed={self._closed}, expected=<database-fixed>)"
        )


__all__ = [
    "InternalSandboxSeedReadinessError",
    "PostgresInternalSandboxSeedReadiness",
]
