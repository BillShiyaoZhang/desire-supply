import json
import shutil
import tempfile
import unittest
from pathlib import Path

from desire_mvp.config import ConfigError, load_config

from helpers import ROOT


class ConfigTests(unittest.TestCase):
    def copied_config(self, directory):
        config_dir = Path(directory) / "config"
        shutil.copytree(ROOT / "config", config_dir)
        return config_dir

    def assert_matching_config_rejected(self, mutate):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = self.copied_config(directory)
            manifest = json.loads((config_dir / "manifest.json").read_text(encoding="utf-8"))
            matching_path = config_dir / manifest["files"]["matching"]
            matching = json.loads(matching_path.read_text(encoding="utf-8"))
            mutate(matching)
            matching_path.write_text(
                json.dumps(matching, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(config_dir)

    def test_manifest_pins_every_rule_version(self):
        bundle = load_config(ROOT / "config")
        self.assertEqual(
            bundle.rule_version,
            "taxonomy-v1+matching-v2+budget-v1+reason-codes-v1",
        )
        self.assertAlmostEqual(sum(bundle.matching["weights"].values()), 1.0)

    def test_matching_weights_reject_missing_extra_non_numeric_and_wrong_total(self):
        cases = {
            "missing": lambda config: config["weights"].pop("interest"),
            "extra": lambda config: config["weights"].update({"popularity": 0.0}),
            "non_numeric": lambda config: config["weights"].update({"interest": True}),
            "wrong_total": lambda config: config["weights"].update({"interest": 0.20}),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                self.assert_matching_config_rejected(mutate)

    def test_matching_hard_filter_order_rejects_missing_engine_code(self):
        self.assert_matching_config_rejected(
            lambda config: config["hard_filter_order"].remove("BOUNDARY_DOMAIN")
        )

    def test_legacy_matching_v1_remains_loadable_for_historical_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = self.copied_config(directory)
            manifest_path = config_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["matching"] = "matching-v1.yaml"
            manifest["versions"]["matching"] = "matching-v1"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                load_config(config_dir).rule_version,
                "taxonomy-v1+matching-v1+budget-v1+reason-codes-v1",
            )

    def test_manifest_shape_errors_raise_config_error(self):
        for field in ("files", "versions"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                config_dir = self.copied_config(directory)
                manifest_path = config_dir / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest[field] = []
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_config(config_dir)

    def test_budget_rejects_invalid_historical_medians(self):
        cases = ([], {"education": float("inf")}, {"education": 10**400})
        for medians in cases:
            with self.subTest(medians=medians), tempfile.TemporaryDirectory() as directory:
                config_dir = self.copied_config(directory)
                budget_path = config_dir / "budget-v1.yaml"
                budget = json.loads(budget_path.read_text(encoding="utf-8"))
                budget["historical_domain_medians"] = medians
                budget_path.write_text(json.dumps(budget), encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_config(config_dir)

    def test_taxonomy_budget_and_reason_semantics_are_validated(self):
        cases = (
            ("taxonomy", lambda value: value.update({"skills": ["python", "python"]})),
            ("taxonomy", lambda value: value.update({"domains": ["Bad Domain"]})),
            ("budget", lambda value: value["regional_daily_baselines"].pop("default")),
            ("budget", lambda value: value["health_thresholds"].update({"yellow": 1.0, "green": 1.0})),
            ("budget", lambda value: value.pop("provenance")),
            ("reason_codes", lambda value: value["candidate_response"].pop("OTHER")),
            ("reason_codes", lambda value: value["project_failure"].update({"bad-code": "bad"})),
        )
        for config_name, mutate in cases:
            with self.subTest(config=config_name), tempfile.TemporaryDirectory() as directory:
                config_dir = self.copied_config(directory)
                manifest = json.loads((config_dir / "manifest.json").read_text(encoding="utf-8"))
                path = config_dir / manifest["files"][config_name]
                value = json.loads(path.read_text(encoding="utf-8"))
                mutate(value)
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(ConfigError):
                    load_config(config_dir)

    def test_manifest_file_entry_must_be_a_string(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = self.copied_config(directory)
            manifest_path = config_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["matching"] = ["matching-v2.yaml"]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(config_dir)


if __name__ == "__main__":
    unittest.main()
