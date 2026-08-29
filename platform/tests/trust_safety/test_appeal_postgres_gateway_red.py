from __future__ import annotations

import importlib


def test_appeal_postgres_gateway_exports_closed_command_read_and_sealed_surfaces():
    module = importlib.import_module(
        "desire_platform.trust_safety.adapters.postgres.appeal_gateway"
    )
    expected = {
        "PsycopgAppealCommandGateway",
        "PsycopgAppealReadGateway",
        "PsycopgAppealReceiptProbe",
        "AppealPostgresGatewaySettings",
        "AppealPostgresReceiptMaterial",
        "AppealPostgresReplayMaterial",
        "OpenAppealPostgresRequest",
        "SaveAppealDraftPostgresRequest",
        "SubmitAppealPostgresRequest",
        "ClaimAppealPostgresRequest",
        "ReleaseAppealAssignmentPostgresRequest",
        "SaveAppealReviewDraftPostgresRequest",
        "DecideAppealPostgresRequest",
    }
    assert expected.issubset(set(module.__all__))


def test_appeal_postgres_production_maps_only_closed_sealed_purposes():
    module = importlib.import_module(
        "desire_platform.trust_safety.adapters.postgres.appeal_production"
    )
    assert module.APPLICATION_TO_DATABASE_SEALED_PURPOSE == {
        "APPLICATION_STATEMENT": "APPEAL_STATEMENT",
        "REVIEW_NOTE": "APPEAL_REVIEW_NOTE",
    }
