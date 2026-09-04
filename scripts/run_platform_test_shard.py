#!/usr/bin/env python3
"""Run a stable, complete module partition of the Platform unittest suite."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
import unittest
from typing import Iterator


def iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def partition_suite(
    suite: unittest.TestSuite, shard_count: int
) -> list[list[unittest.TestCase]]:
    if shard_count < 1:
        raise ValueError("shard count must be positive")
    shards: list[list[unittest.TestCase]] = [[] for _ in range(shard_count)]
    for test in iter_tests(suite):
        # Keep class/module fixtures together and assign newly added tests too.
        module = type(test).__module__
        digest = hashlib.sha256(module.encode("utf-8")).digest()
        shard = int.from_bytes(digest[:8], "big") % shard_count
        shards[shard].append(test)
    return shards


class ImmediateErrorResult(unittest.TextTestResult):
    """Preserve tracebacks even if a later test reaches the job time limit."""

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.writeln(self.errors[-1][1])

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.writeln(self.failures[-1][1])

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.stream.writeln(self._exc_info_to_string(err, subtest))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard-index", type=int, required=True)
    parser.add_argument("--shard-count", type=int, required=True)
    args = parser.parse_args()
    if not 0 <= args.shard_index < args.shard_count:
        parser.error("shard index must be between zero and shard count minus one")

    platform_root = Path(__file__).resolve().parents[1] / "platform"
    sys.path.insert(0, str(platform_root))
    sys.path.insert(0, str(platform_root / "src"))
    discovered = unittest.defaultTestLoader.discover(
        str(platform_root / "tests"), top_level_dir=str(platform_root)
    )
    shards = partition_suite(discovered, args.shard_count)
    selected = shards[args.shard_index]
    if not selected:
        parser.error("the selected shard contains no tests")
    print(
        f"Platform shard {args.shard_index + 1}/{args.shard_count}: "
        f"{len(selected)} of {sum(map(len, shards))} discovered tests; "
        f"partition counts={[len(shard) for shard in shards]}",
        flush=True,
    )
    result = unittest.TextTestRunner(
        verbosity=2, resultclass=ImmediateErrorResult
    ).run(unittest.TestSuite(selected))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
