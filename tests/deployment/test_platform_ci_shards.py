"""CI sharding must preserve every discovered test and fixture boundary."""

from __future__ import annotations

import io
import unittest

from scripts.run_platform_test_shard import ImmediateErrorResult, partition_suite


class PlatformCiShardsTest(unittest.TestCase):
    def test_partition_has_complete_unique_coverage_and_keeps_modules_together(self):
        cases = []
        for module in ("tests.alpha", "tests.beta", "tests.gamma", "tests.delta"):
            case_type = type("Example", (unittest.TestCase,), {"__module__": module})
            cases.extend([case_type(), case_type()])
        suite = unittest.TestSuite(
            [unittest.TestSuite(cases[:3]), unittest.TestSuite(cases[3:])]
        )
        shards = partition_suite(suite, 4)
        assigned = [case for shard in shards for case in shard]
        self.assertCountEqual(map(id, assigned), map(id, cases))
        for module in {type(case).__module__ for case in cases}:
            owners = {
                index
                for index, shard in enumerate(shards)
                if any(type(case).__module__ == module for case in shard)
            }
            self.assertEqual(len(owners), 1)
        self.assertEqual(
            [[id(case) for case in shard] for shard in shards],
            [[id(case) for case in shard] for shard in partition_suite(suite, 4)],
        )

    def test_discovery_errors_remain_executable_failures(self):
        loader = unittest.TestLoader()
        failed_discovery = loader.loadTestsFromName("missing_platform_ci_test_module")
        shards = partition_suite(failed_discovery, 4)
        assigned = [case for shard in shards for case in shard]
        self.assertEqual(len(assigned), 1)
        result = unittest.TestResult()
        unittest.TestSuite(assigned).run(result)
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(len(result.errors), 1)

    def test_failure_traceback_is_visible_before_the_suite_finishes(self):
        stream = io.StringIO()

        class FailingCase(unittest.TestCase):
            def runTest(self):
                self.fail("visible before the next test")

        class FollowingCase(unittest.TestCase):
            def runTest(self):
                self.assertIn("AssertionError: visible before the next test", stream.getvalue())

        result = unittest.TextTestRunner(
            stream=stream, verbosity=2, resultclass=ImmediateErrorResult
        ).run(unittest.TestSuite([FailingCase(), FollowingCase()]))
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(len(result.errors), 0)

    def test_invalid_partition_count_is_rejected(self):
        with self.assertRaises(ValueError):
            partition_suite(unittest.TestSuite(), 0)


if __name__ == "__main__":
    unittest.main()
