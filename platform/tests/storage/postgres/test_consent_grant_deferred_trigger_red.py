"""PostgreSQL 18 RED for consent-grant deferred trigger dispatch."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping
import unittest
import uuid

import psycopg
from psycopg import sql

from desire_platform.identity_access.adapters.postgres.migrations import (
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from tests.storage.postgres.postgres18_harness import TemporaryPostgres18


PLATFORM_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_ROOT = (
    PLATFORM_ROOT
    / "src/desire_platform/identity_access/adapters/postgres/migrations"
)


class ConsentGrantDeferredTriggerRedTest(unittest.TestCase):
    """Both trigger relation shapes dispatch to the exact immutable-offer check."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.postgres = TemporaryPostgres18().start()
        cls.catalog = MigrationCatalog.load(MIGRATION_ROOT)
        cls.contract_sources = IamContractSources(
            api_contract_bytes=(
                PLATFORM_ROOT / "contracts/api/iam-v1.openapi.yaml"
            ).read_bytes(),
            event_contract_bytes=(
                PLATFORM_ROOT / "contracts/events/iam-v1.schema.json"
            ).read_bytes(),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.postgres.stop()

    def setUp(self) -> None:
        self.database = self.postgres.create_database()
        report = IamMigrationRunner(
            driver=PsycopgMigrationDriver(
                settings=PsycopgMigrationSettings(
                    conninfo=self.postgres.conninfo(
                        database=self.database,
                        user="iam_migration_runner",
                    ),
                    application_name="desire-iam-consent-trigger-red",
                ),
                dbapi=psycopg,
            ),
            runner_version="consent-trigger-red/1",
        ).run(catalog=self.catalog, contract_sources=self.contract_sources)
        self.assertEqual(
            report.applied_versions,
            tuple(artifact.descriptor.version for artifact in self.catalog.artifacts),
        )

        from tests.storage.postgres.test_accept_access_invitation_uow_red import (
            RealPostgres18AcceptAccessInvitationUowRedTest,
        )

        support = RealPostgres18AcceptAccessInvitationUowRedTest
        with self._connect_admin() as connection:
            self.creator_policy = support._seed_policy(
                self,
                connection,
                purpose="CREATOR_ENROLLMENT",
                scope_type="USER_ROLE",
                role="CREATOR",
            )
        self.fixture = support._seed_accept_graph(self, kind="creator")

    def tearDown(self) -> None:
        self.postgres.drop_database(self.database)

    def _connect_admin(self, *, autocommit: bool = False):
        return psycopg.connect(
            self.postgres.admin_conninfo(database=self.database),
            autocommit=autocommit,
        )

    def _facts(self, connection: Any) -> Dict[str, Any]:
        offer = connection.execute(
            "SELECT offer_version,bundle_id,purpose,scope_type,recipient_ref,"
            "recipient_label,document_id,document_content_sha256,expiry_days,"
            "not_after FROM iam.consent_offers WHERE id=%s",
            (self.fixture.policy.consent_offer_id,),
        ).fetchone()
        session = connection.execute(
            "SELECT auth_transaction_id,auth_time,acr_code,amr_codes "
            "FROM iam.sessions WHERE id=%s",
            (self.fixture.session_id,),
        ).fetchone()
        assert offer is not None and session is not None
        granted_at = datetime.now(timezone.utc)
        expires_at = min(
            granted_at + timedelta(days=offer[8]),
            offer[9],
        )
        return {
            "id": uuid.uuid4(),
            "user_id": self.fixture.actor_id,
            "consent_offer_id": self.fixture.policy.consent_offer_id,
            "consent_offer_version": offer[0],
            "policy_bundle_id": offer[1],
            "purpose": offer[2],
            "scope_type": offer[3],
            "scope_id": None,
            "recipient_ref": offer[4],
            "recipient_label": offer[5],
            "document_id": offer[6],
            "document_content_sha256": offer[7],
            "granted_at": granted_at,
            "expires_at": expires_at,
            "session_id": self.fixture.session_id,
            "auth_transaction_id": session[0],
            "auth_time": session[1],
            "acr_code": session[2],
            "amr_codes": session[3],
            "command_id": uuid.uuid4(),
            "correlation_id": uuid.uuid4(),
            "status": "ACTIVE",
            "withdrawn_at": None,
            "aggregate_version": 1,
            "created_at": granted_at,
            "updated_at": granted_at,
        }

    def _insert_grant(
        self,
        connection: Any,
        *,
        overrides: Mapping[str, Any] = {},
        categories=("PROFILE", "MATCHING", "RESEARCH"),
    ) -> uuid.UUID:
        facts = self._facts(connection)
        facts.update(overrides)
        columns = tuple(facts)
        connection.execute(
            sql.SQL("INSERT INTO iam.consent_grants ({}) VALUES ({})").format(
                sql.SQL(",").join(map(sql.Identifier, columns)),
                sql.SQL(",").join(sql.Placeholder() for _column in columns),
            ),
            tuple(facts[column] for column in columns),
        )
        for position, category in enumerate(categories, start=1):
            connection.execute(
                "INSERT INTO iam.consent_grant_data_categories "
                "(grant_id,category,position) VALUES (%s,%s,%s)",
                (facts["id"], category, position),
            )
        return facts["id"]

    def _disable_only_grant_foreign_keys(self, connection: Any) -> None:
        trigger_names = connection.execute(
            "SELECT trigger_row.tgname FROM pg_catalog.pg_trigger AS trigger_row "
            "JOIN pg_catalog.pg_constraint AS constraint_row "
            "ON constraint_row.oid=trigger_row.tgconstraint "
            "WHERE trigger_row.tgrelid='iam.consent_grants'::regclass "
            "AND constraint_row.contype='f'",
        ).fetchall()
        self.assertGreater(len(trigger_names), 0)
        for (trigger_name,) in trigger_names:
            connection.execute(
                sql.SQL("ALTER TABLE iam.consent_grants DISABLE TRIGGER {}").format(
                    sql.Identifier(trigger_name)
                )
            )

    def test_exact_grant_and_all_categories_commit_together(self) -> None:
        connection = self._connect_admin()
        try:
            grant_id = self._insert_grant(connection)
            try:
                connection.commit()
            except psycopg.DatabaseError as error:
                self.fail(
                    "semantic RED: exact grant/categories did not commit: %s"
                    % getattr(error, "sqlstate", None)
                )
            count = connection.execute(
                "SELECT count(*) FROM iam.consent_grant_data_categories "
                "WHERE grant_id=%s",
                (grant_id,),
            ).fetchone()
            self.assertEqual(count, (3,))
        finally:
            connection.close()

    def test_each_offer_fact_mismatch_is_still_deferred_23514(self) -> None:
        required_document = self.fixture.policy.required_document_id
        required_hash = self.fixture.policy.required_document_hash
        mismatches = {
            "offer": {"consent_offer_id": uuid.uuid4()},
            "offer_version": {"consent_offer_version": 2},
            "bundle": {"policy_bundle_id": uuid.uuid4()},
            "purpose": {"purpose": "AI_ASSISTED_PROCESSING"},
            "scope": {"scope_type": "ORGANIZATION", "scope_id": uuid.uuid4()},
            "recipient": {"recipient_ref": "internal:wrong-controller"},
            "document": {
                "document_id": required_document,
                "document_content_sha256": required_hash,
            },
            "hash": {"document_content_sha256": required_hash},
            "expiry": {"expires_at": datetime.now(timezone.utc) + timedelta(days=2)},
        }
        cases = tuple((name, values, None) for name, values in mismatches.items()) + (
            ("category", {}, ("PROFILE", "MATCHING")),
        )
        for name, overrides, categories in cases:
            with self.subTest(fact=name):
                connection = self._connect_admin()
                try:
                    self._disable_only_grant_foreign_keys(connection)
                    arguments: Dict[str, Any] = {"overrides": overrides}
                    if categories is not None:
                        arguments["categories"] = categories
                    self._insert_grant(connection, **arguments)
                    with self.assertRaises(psycopg.DatabaseError) as raised:
                        connection.commit()
                    self.assertEqual(raised.exception.sqlstate, "23514")
                    self.assertEqual(
                        raised.exception.diag.constraint_name,
                        "trg_consent_grant_matches_offer",
                    )
                    connection.rollback()
                finally:
                    connection.close()


if __name__ == "__main__":
    unittest.main()
