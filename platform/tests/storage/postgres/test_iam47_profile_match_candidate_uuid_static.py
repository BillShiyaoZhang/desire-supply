"""IAM47 preserves the authority boundary while making candidate keys indexable."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from desire_platform.identity_access.adapters.postgres.migrations import (
    IAM_SCHEMA_HEAD_VERSION,
    MigrationCatalog,
)

ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "src/desire_platform/identity_access/adapters/postgres/migrations"
OLD = MIGRATIONS / "0046_expand__matching_creator_authority.sql"
NEW = MIGRATIONS / "0047_expand__profile_match_candidate_uuid_predicates.sql"
POLICIES = {
    f"rls_profile_match_derivation_{kind}_{command}_v1"
    for kind in ("user", "grant", "invitation", "selector", "acceptance")
    for command in ("definer", "lock")
}


def _compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def test_iam47_is_reviewed_and_every_historical_artifact_is_unchanged() -> None:
    catalog = MigrationCatalog.load(MIGRATIONS)
    assert IAM_SCHEMA_HEAD_VERSION == 47
    assert catalog.artifacts[-1].descriptor.relative_path == NEW.name
    assert catalog.artifacts[-1].descriptor.checksum_sha256 == hashlib.sha256(
        NEW.read_bytes()
    ).digest()
    historical_manifest = json.dumps(
        json.loads(catalog.manifest_bytes)[:47], separators=(",", ":")
    ).encode() + b"\n"
    assert hashlib.sha256(historical_manifest).hexdigest() == (
        "faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5"
    )


def test_only_ten_using_predicates_change_and_canonical_text_is_required() -> None:
    old = OLD.read_text()
    new = NEW.read_text()
    old_policies = {
        name: (table, body)
        for name, table, body in re.findall(
            r"CREATE POLICY (\w+)\nON (iam\.\w+)\n"
            r"FOR (?:SELECT|UPDATE) TO schema_owner\nUSING \((.*?)\n\);",
            old,
            re.DOTALL,
        )
    }
    changes = re.findall(
        r"ALTER POLICY (\w+)\nON (iam\.\w+)\nUSING \((.*?)\n\);",
        new,
        re.DOTALL,
    )
    assert {name for name, _, _ in changes} == POLICIES
    assert len(changes) == 10
    canonical_case = (
        r"CASE\s+WHEN char_length\(current_setting\(\s*"
        r"'app\.iam_profile_candidate_user_id', true\s*\)\) = 36\s+"
        r"AND \(current_setting\(\s*'app\.iam_profile_candidate_user_id', true"
        r'\s*\) COLLATE "C"\) ~ '
        r"'\^\[0-9a-f\]\{8\}-\[0-9a-f\]\{4\}-\[0-9a-f\]\{4\}-"
        r"\[0-9a-f\]\{4\}-\[0-9a-f\]\{12\}\$'\s+"
        r"THEN current_setting\(\s*'app\.iam_profile_candidate_user_id', true"
        r"\s*\)::uuid\s+ELSE NULL::uuid\s+END"
    )
    for name, table, body in changes:
        old_table, old_body = old_policies[name]
        assert table == old_table
        # Removing exactly the new key conversion must recover the complete
        # old USING expression, including every context and graph condition.
        restored, count = re.subn(
            r"((?:creator_grant\.)?\w+) = (" + canonical_case + r")",
            lambda m: m.group(1) + "::text = NULLIF(current_setting("
            "'app.iam_profile_candidate_user_id', true), '')",
            body,
        )
        assert count == 1, name
        assert _compact(restored) == _compact(old_body), name
    assert not re.search(r"^(?:GRANT|REVOKE|CREATE INDEX|DROP POLICY)", new, re.M)


def test_resolver_changes_only_its_installed_catalog_guard() -> None:
    function = (
        r"CREATE(?: OR REPLACE)? FUNCTION "
        r"(iam_api\.resolve_profile_match_creator_eligibility_v1\(.*?\n\$function\$;)"
    )
    old = re.search(function, OLD.read_text(), re.DOTALL).group(1)
    new = re.search(function, NEW.read_text(), re.DOTALL).group(1)
    for field in (
        "schema_head_version",
        "min_app_compatible_version",
        "max_app_compatible_version",
    ):
        assert new.count(field + " = 47") == 1
        new = new.replace(field + " = 47", field + " = 46")
    assert new == old
