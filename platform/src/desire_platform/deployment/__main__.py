"""Container entry point for the reviewed migration composition."""

from __future__ import annotations

import json
import sys

from .migrations import (
    DeploymentIam42PublicNamePreflightError,
    DeploymentMigrationError,
    Iam42PublicNamePreflightReport,
    apply_reviewed_migrations,
    load_settings,
)


def _catalog_payload(report: object) -> dict[str, list[int]]:
    return {
        "applied_versions": list(getattr(report, "applied_versions")),
        "skipped_versions": list(getattr(report, "skipped_versions")),
    }


def _iam42_public_name_preflight_payload(
    report: Iam42PublicNamePreflightReport,
) -> dict[str, object]:
    if not isinstance(report, Iam42PublicNamePreflightReport):
        raise TypeError("IAM42 public-name preflight report is unavailable")
    return {
        "edge_whitespace_count": report.edge_whitespace_count,
        "forbidden_codepoint_count": report.forbidden_codepoint_count,
        "inspected_organization_count": report.inspected_organization_count,
        "invalid_organization_count": report.invalid_organization_count,
        "length_violation_count": report.length_violation_count,
        "non_nfc_count": report.non_nfc_count,
        "predicate_version": report.predicate_version,
        "relation_state": report.relation_state,
        "status": report.status,
    }


def main() -> int:
    try:
        report = apply_reviewed_migrations(load_settings())
    except DeploymentIam42PublicNamePreflightError as error:
        print(
            json.dumps(
                {
                    "code": error.code,
                    "preflights": {
                        "iam42_organization_public_name": (
                            _iam42_public_name_preflight_payload(error.report)
                        )
                    },
                    "status": "BLOCKED",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 78
    except DeploymentMigrationError as error:
        print(
            json.dumps(
                {"code": error.code, "status": "BLOCKED"},
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 78
    except Exception:
        print(
            '{"code":"DEPLOYMENT_MIGRATION_FAILED","status":"BLOCKED"}',
            file=sys.stderr,
        )
        return 78
    print(
        json.dumps(
            {
                "catalogs": {
                    "demand": _catalog_payload(report.demand),
                    "iam": _catalog_payload(report.iam),
                    "matching": _catalog_payload(report.matching),
                    "profile": _catalog_payload(report.profile),
                    "trust": _catalog_payload(report.trust),
                    "taxonomy": _catalog_payload(report.taxonomy),
                },
                "preflights": {
                    "iam42_organization_public_name": (
                        _iam42_public_name_preflight_payload(
                            report.iam42_public_name_preflight
                        )
                    )
                },
                "status": "SCHEMA_READY",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
