"""Apply and verify the six reviewed PostgreSQL 18 migration catalogs.

This is a deployment-only composition root.  It bootstraps the exact database
role graph under an already-authenticated PostgreSQL superuser, gives each
migration runner a short-lived random password, invokes only byte-reviewed
catalogs packaged in the distribution, verifies all compatibility views, then
removes the temporary passwords.  It never accepts caller-supplied SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
import os
from pathlib import Path
import re
import secrets
from typing import Any, Callable, Mapping, NoReturn, Optional, Tuple

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from desire_platform.creator_profile.adapters.postgres.migrations import (
    PROFILE_SCHEMA_HEAD_VERSION,
    ProfileContractSources,
    ProfileMigrationCatalog,
    PsycopgCreatorProfileMigrationRunner,
)
from desire_platform.demand.adapters.postgres.migrations import (
    DEMAND_REQUIRED_IAM_SCHEMA_VERSION,
    DEMAND_SCHEMA_HEAD_VERSION,
    DemandContractSources,
    DemandMigrationCatalog,
    DemandMigrationRunner,
    DemandMigrationSettings,
    PsycopgDemandMigrationDriver,
)
from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    IamContractSources,
    IamMigrationRunner,
    MigrationCatalog,
    PsycopgMigrationDriver,
    PsycopgMigrationSettings,
)
from desire_platform.matching.adapters.postgres.migrations import (
    MATCHING_REQUIRED_IAM_SCHEMA_VERSION,
    MATCHING_SCHEMA_HEAD_VERSION,
    MatchingContractSources,
    MatchingMigrationCatalog,
    MatchingMigrationRunner,
    MatchingMigrationSettings,
    PsycopgMatchingMigrationDriver,
)
from desire_platform.taxonomy.adapters.postgres.migrations import (
    TAXONOMY_SCHEMA_HEAD_VERSION,
    PsycopgTaxonomyMigrationRunner,
    TaxonomyContractSources,
    TaxonomyMigrationCatalog,
)
from desire_platform.trust_safety.adapters.postgres.migrations import (
    PsycopgTrustMigrationDriver,
    TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
    TRUST_REQUIRED_IAM_SCHEMA_VERSION,
    TRUST_SCHEMA_HEAD_VERSION,
    TrustContractSources,
    TrustMigrationCatalog,
    TrustMigrationRunner,
    TrustMigrationSettings,
)


DATABASE_ROLE_SPECS: Tuple[Tuple[str, bool], ...] = (
    ("schema_owner", False),
    ("iam_migration_runner", True),
    ("iam_app", True),
    ("iam_session_authenticator", True),
    ("iam_onboarding", True),
    ("iam_sandbox_bootstrap", True),
    ("iam_system", True),
    ("iam_self_summary_reader", False),
    ("iam_outbox_worker", True),
    ("iam_projection_consumer", True),
    ("iam_key_policy_operator", False),
    ("audit_reader", False),
    ("break_glass", False),
    ("profile_schema_owner", False),
    ("profile_migration_runner", True),
    ("profile_app", True),
    ("profile_matcher", True),
    ("demand_schema_owner", False),
    ("demand_migration_runner", True),
    ("demand_self", True),
    ("demand_review", True),
    ("demand_finance", True),
    ("demand_matching", True),
    ("demand_system", True),
    ("matching_schema_owner", False),
    ("matching_migration_runner", True),
    ("matching_creator", True),
    ("matching_selector", True),
    ("matching_assignment", True),
    ("matching_review", True),
    ("matching_worker", True),
    ("matching_coordinator", True),
    ("trust_schema_owner", False),
    ("trust_migration_runner", True),
    ("trust_self", True),
    ("trust_officer", True),
    ("trust_appeal", True),
    ("trust_decision", True),
    ("taxonomy_schema_owner", False),
    ("taxonomy_migration_runner", True),
    ("taxonomy_publisher", True),
    ("taxonomy_admin", True),
    ("taxonomy_reader", True),
    ("taxonomy_consumer", True),
)

MIGRATION_MEMBERSHIPS: Tuple[Tuple[str, str], ...] = (
    ("schema_owner", "iam_migration_runner"),
    ("iam_self_summary_reader", "schema_owner"),
    ("profile_schema_owner", "profile_migration_runner"),
    ("demand_schema_owner", "demand_migration_runner"),
    ("schema_owner", "demand_migration_runner"),
    ("matching_schema_owner", "matching_migration_runner"),
    ("schema_owner", "matching_migration_runner"),
    ("profile_schema_owner", "matching_migration_runner"),
    ("demand_schema_owner", "matching_migration_runner"),
    ("trust_schema_owner", "matching_migration_runner"),
    ("trust_schema_owner", "trust_migration_runner"),
    ("schema_owner", "trust_migration_runner"),
    ("taxonomy_schema_owner", "taxonomy_migration_runner"),
)

_MIGRATION_ROLES = (
    "iam_migration_runner",
    "profile_migration_runner",
    "demand_migration_runner",
    "matching_migration_runner",
    "trust_migration_runner",
    "taxonomy_migration_runner",
)
_SCHEMA_CREATE_ROLES = (
    "profile_schema_owner",
    "demand_schema_owner",
    "matching_schema_owner",
    "trust_schema_owner",
    "taxonomy_schema_owner",
)
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_SECRET_MINIMUM_BYTES = 24
_SECRET_MAXIMUM_BYTES = 4096
_RUNNER_VERSION = "container-migration/1"
_PROVISIONING_LOCK_KEY = (0x44534952, 0x4D494752)  # "DSIR" / "MIGR"
IAM42_PUBLIC_NAME_PREDICATE_VERSION = "iam42-organization-public-name-v1"

_IAM42_PUBLIC_NAME_PREFLIGHT_BEGIN_SQL = (
    "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
)
_IAM42_PUBLIC_NAME_PREFLIGHT_TIMEOUT_SQL = (
    "SET LOCAL lock_timeout='2s';"
    "SET LOCAL statement_timeout='30s';"
    "SET LOCAL idle_in_transaction_session_timeout='35s'"
)

_IAM42_PUBLIC_NAME_RELATION_SQL = (
    "SELECT relation.relkind FROM pg_catalog.pg_class AS relation "
    "JOIN pg_catalog.pg_namespace AS namespace "
    "ON namespace.oid=relation.relnamespace "
    "WHERE namespace.nspname='iam' AND relation.relname='organizations'"
)
_IAM42_PUBLIC_NAME_PREFLIGHT_SQL = r"""
WITH evaluated AS (
    SELECT
        COALESCE(
            char_length(organization.public_name) BETWEEN 1 AND 160,
            false
        )
            AS length_valid,
        COALESCE(organization.public_name IS NFC NORMALIZED, false)
            AS nfc_valid,
        COALESCE(
            organization.public_name = btrim(
                organization.public_name,
                U&'\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006'
                || U&'\2007\2008\2009\200A\2028\2029\202F\205F\3000'
            ),
            false
        ) AS edge_whitespace_valid,
        organization.public_name IS NOT NULL
        AND NOT EXISTS (
                SELECT 1
                FROM generate_series(
                    1, char_length(organization.public_name)
                ) AS slot(position)
                CROSS JOIN LATERAL (
                    SELECT ascii(substr(
                        organization.public_name, slot.position, 1
                    )) AS value
                ) AS codepoint
                WHERE codepoint.value BETWEEN 0 AND 31
                   OR codepoint.value BETWEEN 127 AND 159
                   OR codepoint.value = 173
                   OR codepoint.value BETWEEN 1536 AND 1541
                   OR codepoint.value = 1564
                   OR codepoint.value = 1757
                   OR codepoint.value = 1807
                   OR codepoint.value BETWEEN 2192 AND 2193
                   OR codepoint.value = 2274
                   OR codepoint.value = 6158
                   OR codepoint.value BETWEEN 8203 AND 8207
                   OR codepoint.value BETWEEN 8234 AND 8238
                   OR codepoint.value BETWEEN 8288 AND 8292
                   OR codepoint.value BETWEEN 8294 AND 8303
                   OR codepoint.value = 65279
                   OR codepoint.value BETWEEN 65529 AND 65531
                   OR codepoint.value = 69821
                   OR codepoint.value = 69837
                   OR codepoint.value BETWEEN 78896 AND 78911
                   OR codepoint.value BETWEEN 113824 AND 113827
                   OR codepoint.value BETWEEN 119155 AND 119162
                   OR codepoint.value = 917505
                   OR codepoint.value BETWEEN 917536 AND 917631
            ) AS codepoint_valid
    FROM iam.organizations AS organization
)
SELECT
    count(*)::bigint,
    count(*) FILTER (
        WHERE NOT (
            length_valid AND nfc_valid
            AND edge_whitespace_valid AND codepoint_valid
        )
    )::bigint,
    count(*) FILTER (WHERE NOT length_valid)::bigint,
    count(*) FILTER (WHERE NOT nfc_valid)::bigint,
    count(*) FILTER (WHERE NOT edge_whitespace_valid)::bigint,
    count(*) FILTER (WHERE NOT codepoint_valid)::bigint
FROM evaluated
"""


class DeploymentMigrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DeploymentMigrationConfigurationError(DeploymentMigrationError):
    pass


class DeploymentIam42PublicNamePreflightError(DeploymentMigrationError):
    def __init__(self, report: "Iam42PublicNamePreflightReport") -> None:
        if (
            not isinstance(report, Iam42PublicNamePreflightReport)
            or report.status != "BLOCKED"
        ):
            raise TypeError("IAM42 public-name preflight error report is invalid")
        self.report = report
        super().__init__("DEPLOYMENT_IAM42_PUBLIC_NAME_PREFLIGHT_BLOCKED")


@dataclass(frozen=True, repr=False)
class DeploymentMigrationSettings:
    host: str
    database: str
    admin_user: str
    admin_password: str = field(repr=False)
    port: int = 5432

    def __repr__(self) -> str:
        return (
            "DeploymentMigrationSettings("
            f"host={self.host!r}, database={self.database!r}, "
            f"admin_user={self.admin_user!r}, port={self.port!r}, "
            "admin_password=<redacted>)"
        )


@dataclass(frozen=True)
class CatalogMigrationReport:
    applied_versions: Tuple[int, ...]
    skipped_versions: Tuple[int, ...]


@dataclass(frozen=True)
class Iam42PublicNamePreflightReport:
    predicate_version: str
    relation_state: str
    inspected_organization_count: int
    invalid_organization_count: int
    length_violation_count: int
    non_nfc_count: int
    edge_whitespace_count: int
    forbidden_codepoint_count: int
    status: str

    def __post_init__(self) -> None:
        counts = (
            self.inspected_organization_count,
            self.invalid_organization_count,
            self.length_violation_count,
            self.non_nfc_count,
            self.edge_whitespace_count,
            self.forbidden_codepoint_count,
        )
        if (
            self.predicate_version != IAM42_PUBLIC_NAME_PREDICATE_VERSION
            or self.relation_state not in {"ABSENT", "PRESENT"}
            or self.status not in {"PASSED", "BLOCKED"}
            or any(type(value) is not int or value < 0 for value in counts)
            or self.invalid_organization_count
            > self.inspected_organization_count
            or any(
                value > self.invalid_organization_count for value in counts[2:]
            )
            or (
                self.relation_state == "ABSENT"
                and any(value != 0 for value in counts)
            )
            or (
                self.status == "PASSED"
                and self.invalid_organization_count != 0
            )
            or (
                self.status == "BLOCKED"
                and self.invalid_organization_count == 0
            )
        ):
            raise ValueError("IAM42 public-name preflight report is invalid")


@dataclass(frozen=True)
class DeploymentMigrationReport:
    iam: CatalogMigrationReport
    profile: CatalogMigrationReport
    demand: CatalogMigrationReport
    matching: CatalogMigrationReport
    trust: CatalogMigrationReport
    taxonomy: CatalogMigrationReport
    iam42_public_name_preflight: Iam42PublicNamePreflightReport


def _configuration_error() -> NoReturn:
    raise DeploymentMigrationConfigurationError(
        "DEPLOYMENT_MIGRATION_CONFIGURATION_INVALID"
    )


def _read_secret(path: Path, allowed_secret_root: Path) -> str:
    try:
        resolved_root = allowed_secret_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError:
        _configuration_error()
    if resolved_path.parent != resolved_root or path.is_symlink():
        _configuration_error()
    try:
        raw = resolved_path.read_bytes().rstrip(b"\r\n")
    except OSError:
        _configuration_error()
    if (
        not _SECRET_MINIMUM_BYTES <= len(raw) <= _SECRET_MAXIMUM_BYTES
        or b"\x00" in raw
        or b"\n" in raw
        or b"\r" in raw
    ):
        _configuration_error()
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _configuration_error()


def load_settings(
    environ: Optional[Mapping[str, str]] = None,
    *,
    allowed_secret_root: Path = Path("/run/secrets"),
) -> DeploymentMigrationSettings:
    values = os.environ if environ is None else environ
    if (
        values.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX"
        or values.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED") != "false"
        or "DESIRE_DATABASE_PASSWORD" in values
        or values.get("DESIRE_DATABASE_HOST") != "db"
    ):
        _configuration_error()
    database = values.get("DESIRE_DATABASE_NAME", "")
    admin_user = values.get("DESIRE_DATABASE_ADMIN_USER", "")
    if (
        _IDENTIFIER.fullmatch(database) is None
        or _IDENTIFIER.fullmatch(admin_user) is None
        or admin_user != "postgres"
    ):
        _configuration_error()
    raw_secret_path = values.get("DESIRE_DATABASE_PASSWORD_FILE", "")
    if not raw_secret_path:
        _configuration_error()
    secret_path = Path(raw_secret_path)
    password = _read_secret(secret_path, allowed_secret_root)
    return DeploymentMigrationSettings(
        host="db",
        database=database,
        admin_user=admin_user,
        admin_password=password,
    )


def _conninfo(settings: DeploymentMigrationSettings, *, user: str, password: str) -> str:
    return make_conninfo(
        host=settings.host,
        port=settings.port,
        dbname=settings.database,
        user=user,
        password=password,
        connect_timeout=5,
    )


def _admin_connection(settings: DeploymentMigrationSettings, dbapi: Any) -> Any:
    return dbapi.connect(
        _conninfo(
            settings,
            user=settings.admin_user,
            password=settings.admin_password,
        ),
        autocommit=True,
        application_name="desire-deployment-provisioner",
        connect_timeout=5,
    )


def _assert_admin_preflight(connection: Any, settings: DeploymentMigrationSettings) -> None:
    row = connection.execute(
        "SELECT current_setting('server_version_num')::integer/10000,"
        "current_database(),session_user,current_user,"
        "(SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=session_user)"
    ).fetchone()
    if row != (
        18,
        settings.database,
        settings.admin_user,
        settings.admin_user,
        True,
    ):
        raise DeploymentMigrationError("DEPLOYMENT_POSTGRES_PREFLIGHT_FAILED")


def _preflight_iam42_public_names(
    connection: Any,
) -> Iam42PublicNamePreflightReport:
    try:
        connection.execute(_IAM42_PUBLIC_NAME_PREFLIGHT_BEGIN_SQL)
        connection.execute(_IAM42_PUBLIC_NAME_PREFLIGHT_TIMEOUT_SQL)
        relation_rows = tuple(
            connection.execute(_IAM42_PUBLIC_NAME_RELATION_SQL).fetchall()
        )
        if relation_rows == ():
            report = Iam42PublicNamePreflightReport(
                predicate_version=IAM42_PUBLIC_NAME_PREDICATE_VERSION,
                relation_state="ABSENT",
                inspected_organization_count=0,
                invalid_organization_count=0,
                length_violation_count=0,
                non_nfc_count=0,
                edge_whitespace_count=0,
                forbidden_codepoint_count=0,
                status="PASSED",
            )
        else:
            if relation_rows != (("r",),):
                raise ValueError
            row = connection.execute(_IAM42_PUBLIC_NAME_PREFLIGHT_SQL).fetchone()
            if row is None or len(row) != 6:
                raise ValueError
            counts = tuple(row)
            report = Iam42PublicNamePreflightReport(
                predicate_version=IAM42_PUBLIC_NAME_PREDICATE_VERSION,
                relation_state="PRESENT",
                inspected_organization_count=counts[0],
                invalid_organization_count=counts[1],
                length_violation_count=counts[2],
                non_nfc_count=counts[3],
                edge_whitespace_count=counts[4],
                forbidden_codepoint_count=counts[5],
                status="BLOCKED" if counts[1] else "PASSED",
            )
        connection.execute("COMMIT")
    except Exception:
        try:
            connection.execute("ROLLBACK")
        except Exception:
            pass
        raise DeploymentMigrationError(
            "DEPLOYMENT_IAM42_PUBLIC_NAME_PREFLIGHT_UNAVAILABLE"
        ) from None
    if report.status == "BLOCKED":
        raise DeploymentIam42PublicNamePreflightError(report)
    return report


def _acquire_provisioning_lock(connection: Any) -> None:
    row = connection.execute(
        "SELECT pg_catalog.pg_try_advisory_lock(%s,%s)",
        _PROVISIONING_LOCK_KEY,
    ).fetchone()
    if row != (True,):
        raise DeploymentMigrationError("DEPLOYMENT_MIGRATION_ALREADY_RUNNING")


def _release_provisioning_lock(connection: Any) -> None:
    row = connection.execute(
        "SELECT pg_catalog.pg_advisory_unlock(%s,%s)",
        _PROVISIONING_LOCK_KEY,
    ).fetchone()
    if row != (True,):
        raise DeploymentMigrationError("DEPLOYMENT_MIGRATION_LOCK_LOST")


def _ensure_roles(connection: Any) -> None:
    rows = connection.execute(
        "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,"
        "rolcreaterole,rolbypassrls FROM pg_catalog.pg_roles "
        "WHERE rolname = ANY(%s)",
        ([name for name, _login in DATABASE_ROLE_SPECS],),
    ).fetchall()
    existing = {row[0]: tuple(row[1:]) for row in rows}
    for role_name, can_login in DATABASE_ROLE_SPECS:
        facts = existing.get(role_name)
        expected = (can_login, False, False, False, False, False)
        if facts is not None and facts != expected:
            raise DeploymentMigrationError("DEPLOYMENT_ROLE_CONTRACT_MISMATCH")
        if facts is None:
            login_clause = sql.SQL("LOGIN") if can_login else sql.SQL("NOLOGIN")
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} {} NOINHERIT NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOBYPASSRLS PASSWORD NULL"
                ).format(sql.Identifier(role_name), login_clause)
            )


def _ensure_memberships(connection: Any) -> None:
    role_names = [name for name, _can_login in DATABASE_ROLE_SPECS]
    rows = connection.execute(
        "SELECT granted.rolname,member.rolname,m.admin_option,"
        "m.inherit_option,m.set_option "
        "FROM pg_catalog.pg_auth_members AS m "
        "JOIN pg_catalog.pg_roles AS granted ON granted.oid=m.roleid "
        "JOIN pg_catalog.pg_roles AS member ON member.oid=m.member "
        "WHERE granted.rolname = ANY(%s) OR member.rolname = ANY(%s)",
        (role_names, role_names),
    ).fetchall()
    actual = {(row[0], row[1]): tuple(row[2:]) for row in rows}
    expected_keys = frozenset(MIGRATION_MEMBERSHIPS)
    unexpected = frozenset(actual).difference(expected_keys)
    if unexpected:
        raise DeploymentMigrationError("DEPLOYMENT_MEMBERSHIP_CONTRACT_MISMATCH")
    for granted, member in MIGRATION_MEMBERSHIPS:
        options = actual.get((granted, member))
        if options is None:
            connection.execute(
                sql.SQL(
                    "GRANT {} TO {} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
                ).format(sql.Identifier(granted), sql.Identifier(member))
            )
        elif options != (False, False, True):
            raise DeploymentMigrationError(
                "DEPLOYMENT_MEMBERSHIP_CONTRACT_MISMATCH"
            )


def _ensure_database_privileges(connection: Any, settings: DeploymentMigrationSettings) -> None:
    owner = connection.execute(
        "SELECT owner.rolname FROM pg_catalog.pg_database AS database "
        "JOIN pg_catalog.pg_roles AS owner ON owner.oid=database.datdba "
        "WHERE database.datname=current_database()"
    ).fetchone()
    if owner == (settings.admin_user,):
        connection.execute(
            sql.SQL("ALTER DATABASE {} OWNER TO schema_owner").format(
                sql.Identifier(settings.database)
            )
        )
    elif owner != ("schema_owner",):
        raise DeploymentMigrationError("DEPLOYMENT_DATABASE_OWNER_MISMATCH")

    database_identifier = sql.Identifier(settings.database)
    connection.execute(
        sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(database_identifier)
    )
    for role_name, can_login in DATABASE_ROLE_SPECS:
        if can_login:
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    database_identifier,
                    sql.Identifier(role_name),
                )
            )
    for role_name in _SCHEMA_CREATE_ROLES:
        connection.execute(
            sql.SQL("GRANT CREATE ON DATABASE {} TO {}").format(
                database_identifier,
                sql.Identifier(role_name),
            )
        )


def _install_temporary_passwords(
    connection: Any,
    password_factory: Callable[[], str],
) -> Mapping[str, str]:
    passwords = {}
    for role_name in _MIGRATION_ROLES:
        password = password_factory()
        if not isinstance(password, str) or len(password) < 32:
            raise DeploymentMigrationError("DEPLOYMENT_PASSWORD_FACTORY_INVALID")
        connection.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(role_name),
                sql.Literal(password),
            )
        )
        passwords[role_name] = password
    return passwords


def _clear_temporary_passwords(connection: Any) -> None:
    for role_name in _MIGRATION_ROLES:
        connection.execute(
            sql.SQL("ALTER ROLE {} PASSWORD NULL").format(sql.Identifier(role_name))
        )


def _migration_root(package: str) -> Path:
    root = resources.files(package)
    path = Path(str(root))
    if not path.is_dir():
        raise DeploymentMigrationError("DEPLOYMENT_ARTIFACT_UNAVAILABLE")
    return path


def _contract_bytes(relative_path: str) -> bytes:
    contract_root = resources.files("desire_platform.contracts")
    candidate = contract_root.joinpath(*relative_path.split("/"))
    try:
        return candidate.read_bytes()
    except OSError:
        raise DeploymentMigrationError("DEPLOYMENT_ARTIFACT_UNAVAILABLE") from None


def _catalog_report(report: Any) -> CatalogMigrationReport:
    return CatalogMigrationReport(
        applied_versions=tuple(report.applied_versions),
        skipped_versions=tuple(report.skipped_versions),
    )


def _apply_catalogs(
    settings: DeploymentMigrationSettings,
    passwords: Mapping[str, str],
    dbapi: Any,
    *,
    iam42_public_name_preflight: Iam42PublicNamePreflightReport,
) -> DeploymentMigrationReport:
    iam_catalog = MigrationCatalog.load(
        _migration_root(
            "desire_platform.identity_access.adapters.postgres.migrations"
        )
    )
    iam = IamMigrationRunner(
        driver=PsycopgMigrationDriver(
            settings=PsycopgMigrationSettings(
                conninfo=_conninfo(
                    settings,
                    user="iam_migration_runner",
                    password=passwords["iam_migration_runner"],
                ),
                application_name="desire-container-iam-migration",
            ),
            dbapi=dbapi,
        ),
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=iam_catalog,
        contract_sources=IamContractSources(
            api_contract_bytes=_contract_bytes("api/iam-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/iam-v1.schema.json"),
        ),
    )

    profile_catalog = ProfileMigrationCatalog.load(
        _migration_root(
            "desire_platform.creator_profile.adapters.postgres.migrations"
        )
    )
    profile = PsycopgCreatorProfileMigrationRunner(
        conninfo=_conninfo(
            settings,
            user="profile_migration_runner",
            password=passwords["profile_migration_runner"],
        ),
        dbapi=dbapi,
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=profile_catalog,
        contract_sources=ProfileContractSources(
            api_contract_bytes=_contract_bytes("api/profile-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/profile-v1.schema.json"),
            domain_contract_bytes=_contract_bytes(
                "domain/profile-version-v1.schema.json"
            ),
        ),
    )

    demand_catalog = DemandMigrationCatalog.load(
        _migration_root("desire_platform.demand.adapters.postgres.migrations")
    )
    demand = DemandMigrationRunner(
        driver=PsycopgDemandMigrationDriver(
            settings=DemandMigrationSettings(
                conninfo=_conninfo(
                    settings,
                    user="demand_migration_runner",
                    password=passwords["demand_migration_runner"],
                ),
                application_name="desire-container-demand-migration",
            ),
            dbapi=dbapi,
        ),
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=demand_catalog,
        contract_sources=DemandContractSources(
            api_contract_bytes=_contract_bytes("api/demand-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/demand-v1.schema.json"),
            content_contract_bytes=_contract_bytes(
                "domain/demand-content-v1.schema.json"
            ),
        ),
    )

    trust_catalog = TrustMigrationCatalog.load(
        _migration_root(
            "desire_platform.trust_safety.adapters.postgres.migrations"
        )
    )
    trust = TrustMigrationRunner(
        driver=PsycopgTrustMigrationDriver(
            settings=TrustMigrationSettings(
                conninfo=_conninfo(
                    settings,
                    user="trust_migration_runner",
                    password=passwords["trust_migration_runner"],
                ),
                application_name="desire-container-trust-migration",
            ),
            dbapi=dbapi,
        ),
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=trust_catalog,
        contract_sources=TrustContractSources(
            api_contract_bytes=_contract_bytes("api/trust-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/trust-v1.schema.json"),
            report_contract_bytes=_contract_bytes(
                "domain/trust-report-v1.schema.json"
            ),
            triage_contract_bytes=_contract_bytes(
                "domain/trust-triage-v1.schema.json"
            ),
            appeal_api_contract_bytes=_contract_bytes(
                "api/appeal-v1.openapi.yaml"
            ),
            appeal_event_contract_bytes=_contract_bytes(
                "events/appeal-v1.schema.json"
            ),
            appeal_application_contract_bytes=_contract_bytes(
                "domain/appeal-application-v1.schema.json"
            ),
            appeal_review_contract_bytes=_contract_bytes(
                "domain/appeal-review-v1.schema.json"
            ),
        ),
    )

    matching_catalog = MatchingMigrationCatalog.load(
        _migration_root("desire_platform.matching.adapters.postgres.migrations")
    )
    matching = MatchingMigrationRunner(
        driver=PsycopgMatchingMigrationDriver(
            settings=MatchingMigrationSettings(
                conninfo=_conninfo(
                    settings,
                    user="matching_migration_runner",
                    password=passwords["matching_migration_runner"],
                ),
                application_name="desire-container-matching-migration",
            ),
            dbapi=dbapi,
        ),
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=matching_catalog,
        contract_sources=MatchingContractSources(
            api_contract_bytes=_contract_bytes("api/matching-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/matching-v1.schema.json"),
            rule_contract_bytes=_contract_bytes(
                "domain/matching-rule-release-v1.schema.json"
            ),
            input_manifest_contract_bytes=_contract_bytes(
                "domain/match-input-manifest-v1.schema.json"
            ),
            run_input_contract_bytes=_contract_bytes(
                "domain/match-run-input-v1.schema.json"
            ),
            candidate_contract_bytes=_contract_bytes(
                "domain/match-candidate-result-v1.schema.json"
            ),
            disclosure_contract_bytes=_contract_bytes(
                "domain/invitation-disclosure-v1.schema.json"
            ),
        ),
    )

    taxonomy_catalog = TaxonomyMigrationCatalog.load(
        _migration_root(
            "desire_platform.taxonomy.adapters.postgres.migrations"
        )
    )
    taxonomy = PsycopgTaxonomyMigrationRunner(
        conninfo=_conninfo(
            settings,
            user="taxonomy_migration_runner",
            password=passwords["taxonomy_migration_runner"],
        ),
        dbapi=dbapi,
        runner_version=_RUNNER_VERSION,
    ).run(
        catalog=taxonomy_catalog,
        contract_sources=TaxonomyContractSources(
            api_contract_bytes=_contract_bytes("api/taxonomy-v1.openapi.yaml"),
            event_contract_bytes=_contract_bytes("events/taxonomy-v1.schema.json"),
            release_contract_bytes=_contract_bytes(
                "domain/taxonomy-release-v1.schema.json"
            ),
        ),
    )
    return DeploymentMigrationReport(
        iam=_catalog_report(iam),
        profile=_catalog_report(profile),
        demand=_catalog_report(demand),
        matching=_catalog_report(matching),
        trust=_catalog_report(trust),
        taxonomy=_catalog_report(taxonomy),
        iam42_public_name_preflight=iam42_public_name_preflight,
    )


def _verify_catalogs(connection: Any) -> None:
    checks = (
        (
            "SELECT component,current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version,"
            "required_iam_schema_version,required_demand_schema_version "
            "FROM trust.schema_compatibility",
            (
                "trust",
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_SCHEMA_HEAD_VERSION,
                TRUST_REQUIRED_IAM_SCHEMA_VERSION,
                TRUST_REQUIRED_DEMAND_SCHEMA_VERSION,
            ),
        ),
        (
            "SELECT current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version "
            "FROM infra.iam_schema_compatibility",
            (IAM_SCHEMA_HEAD_VERSION,) * 4,
        ),
        (
            "SELECT current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version "
            "FROM profile.schema_compatibility",
            (PROFILE_SCHEMA_HEAD_VERSION,) * 4,
        ),
        (
            "SELECT current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version,"
            "required_iam_schema_version FROM demand.schema_compatibility",
            (DEMAND_SCHEMA_HEAD_VERSION,) * 4
            + (DEMAND_REQUIRED_IAM_SCHEMA_VERSION,),
        ),
        (
            "SELECT current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version,"
            "required_iam_schema_version FROM matching.schema_compatibility",
            (MATCHING_SCHEMA_HEAD_VERSION,) * 4
            + (MATCHING_REQUIRED_IAM_SCHEMA_VERSION,),
        ),
        (
            "SELECT current_schema_version,schema_head_version,"
            "min_app_compatible_version,max_app_compatible_version "
            "FROM taxonomy.schema_compatibility",
            (TAXONOMY_SCHEMA_HEAD_VERSION,) * 4,
        ),
    )
    for query, expected in checks:
        row = connection.execute(query).fetchone()
        if row is None or tuple(row) != expected:
            raise DeploymentMigrationError("DEPLOYMENT_SCHEMA_VERIFICATION_FAILED")


def apply_reviewed_migrations(
    settings: DeploymentMigrationSettings,
    *,
    dbapi: Any = psycopg,
    password_factory: Callable[[], str] = lambda: secrets.token_urlsafe(48),
) -> DeploymentMigrationReport:
    if not isinstance(settings, DeploymentMigrationSettings):
        raise DeploymentMigrationConfigurationError(
            "DEPLOYMENT_MIGRATION_CONFIGURATION_INVALID"
        )
    with _admin_connection(settings, dbapi) as connection:
        _assert_admin_preflight(connection, settings)
        _acquire_provisioning_lock(connection)
        password_cleanup_required = False
        try:
            iam42_public_name_preflight = _preflight_iam42_public_names(
                connection
            )
            _ensure_roles(connection)
            _ensure_memberships(connection)
            _ensure_database_privileges(connection, settings)
            # Set this before the first ALTER ROLE so a mid-loop database error
            # cannot leave an already-installed runner credential behind.
            password_cleanup_required = True
            passwords = _install_temporary_passwords(connection, password_factory)
            report = _apply_catalogs(
                settings,
                passwords,
                dbapi,
                iam42_public_name_preflight=iam42_public_name_preflight,
            )
            _verify_catalogs(connection)
            return report
        finally:
            try:
                if password_cleanup_required:
                    _clear_temporary_passwords(connection)
            finally:
                _release_provisioning_lock(connection)
