#!/bin/sh
# PostgreSQL 18 logical backup and isolated restore proof for INTERNAL_SANDBOX.
# The restore path is intentionally incapable of targeting the normal database
# name or project.  Cleanup of the isolated Compose volume remains an explicit
# host-side operation after the proof exits.

set -eu
umask 077

BACKUP_ROOT=/var/lib/desire-backup
FACTS_SQL=/run/desire-ops/postgres-core-facts.sql
PGPASS_PATH=/tmp/desire-postgres-operations.pgpass
EXPECTED_PINS='18|38|38|3|3|10|10|9|9|2|2'
EXPECTED_CONTRACTS='908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|7695127a039fa71cddabd62318bea39337e3acbb4b1df66a3557b7a7ae3707b4|38|10|908f3de6b6b90fd5d19004304e9df24d0e5738fe6edf88e1b2cb2b1a414c5e3e|27ec6b585a9340cbd7119d7a9b46d6098a3881f88ae1be9e00df3713c0107113|43765a3739716819c1bfc8df9625a3011534ae23aa647bf3bdaea90945e7bef9|8ef9c2321866e7509bf1a959acf64370fe74abb927635c0434618287a4348171|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622'
cleanup_partials=0

_blocked() {
    printf '{"code":"%s","status":"BLOCKED"}\n' "$1" >&2
    exit 78
}

_cleanup() {
    rm -f "$PGPASS_PATH"
    if [ "$cleanup_partials" = 1 ]; then
        rm -f \
            "${dump_partial:-}" \
            "${facts_partial:-}" \
            "${facts_after_partial:-}" \
            "${manifest_partial:-}" \
            "${restored_facts_partial:-}"
    fi
}

trap _cleanup EXIT
trap '_blocked DATABASE_OPERATIONS_INTERRUPTED' HUP INT TERM

_require_common_contract() {
    [ "${DESIRE_DEPLOYMENT_MODE:-}" = INTERNAL_SANDBOX ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_EXTERNAL_PARTICIPANTS_ENABLED:-}" = false ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_DATABASE_HOST:-}" = db ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_DATABASE_PORT:-}" = 5432 ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_DATABASE_ADMIN_USER:-}" = postgres ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_DATABASE_PASSWORD_FILE:-}" = /run/secrets/db_superuser_password ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "${DESIRE_DATABASE_BACKUP_ROOT:-}" = "$BACKUP_ROOT" ] \
        || _blocked DATABASE_OPERATIONS_CONFIGURATION_INVALID
    [ "$(id -u)" -ne 0 ] \
        || _blocked DATABASE_OPERATIONS_ROOT_USER_FORBIDDEN
    [ -d "$BACKUP_ROOT" ] && [ ! -L "$BACKUP_ROOT" ] \
        || _blocked DATABASE_BACKUP_ROOT_INVALID
    [ "$(stat -c '%a' "$BACKUP_ROOT" 2>/dev/null || true)" = 700 ] \
        || _blocked DATABASE_BACKUP_ROOT_PERMISSIONS_INVALID
    [ -f "$FACTS_SQL" ] && [ ! -L "$FACTS_SQL" ] \
        || _blocked DATABASE_OPERATIONS_CONTRACT_MISSING

    secret_path=$DESIRE_DATABASE_PASSWORD_FILE
    [ -f "$secret_path" ] && [ ! -L "$secret_path" ] \
        || _blocked DATABASE_OPERATIONS_SECRET_INVALID
    od -An -v -t u1 "$secret_path" | awk '
        {
            for (field = 1; field <= NF; field++) {
                count += 1
                if ($field < 32 || $field > 126) invalid = 1
            }
        }
        END { exit !(count >= 24 && count <= 4096 && !invalid) }
    ' || _blocked DATABASE_OPERATIONS_SECRET_INVALID

    database_password=$(cat "$secret_path")
    escaped_password=$(
        printf '%s' "$database_password" | sed 's/\\/\\\\/g; s/:/\\:/g'
    )
    printf '%s:%s:%s:%s:%s\n' \
        "$DESIRE_DATABASE_HOST" \
        "$DESIRE_DATABASE_PORT" \
        "$DESIRE_DATABASE_NAME" \
        "$DESIRE_DATABASE_ADMIN_USER" \
        "$escaped_password" > "$PGPASS_PATH"
    chmod 600 "$PGPASS_PATH"
    unset database_password escaped_password
    export PGPASSFILE="$PGPASS_PATH"
    export PGCONNECT_TIMEOUT=5

    basename=${DESIRE_DATABASE_BACKUP_BASENAME:-}
    case "$basename" in
        ''|UNSET|*[!a-z0-9._-]*|.*|*..*)
            _blocked DATABASE_BACKUP_BASENAME_INVALID
            ;;
    esac
    [ "$(printf '%s' "$basename" | wc -c | tr -d ' ')" -le 64 ] \
        || _blocked DATABASE_BACKUP_BASENAME_INVALID
}

_client_major() {
    "$1" --version | sed -n \
        's/^.*(PostgreSQL) \([0-9][0-9]*\)\..*$/\1/p'
}

_require_client_18() {
    [ "$(_client_major psql)" = 18 ] \
        || _blocked DATABASE_OPERATIONS_CLIENT_VERSION_INVALID
    [ "$(_client_major "$1")" = 18 ] \
        || _blocked DATABASE_OPERATIONS_CLIENT_VERSION_INVALID
}

_psql_read() {
    PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30000' \
        psql \
        --no-password \
        --quiet \
        --no-align \
        --tuples-only \
        --no-psqlrc \
        --set ON_ERROR_STOP=1 \
        --host "$DESIRE_DATABASE_HOST" \
        --port "$DESIRE_DATABASE_PORT" \
        --username "$DESIRE_DATABASE_ADMIN_USER" \
        --dbname "$DESIRE_DATABASE_NAME" \
        "$@"
}

_pins() {
    _psql_read --command \
        "SELECT concat_ws('|',current_setting('server_version_num')::integer/10000,iam.current_schema_version,iam.schema_head_version,profile.current_schema_version,profile.schema_head_version,demand.current_schema_version,demand.schema_head_version,trust.current_schema_version,trust.schema_head_version,taxonomy.current_schema_version,taxonomy.schema_head_version) FROM infra.iam_schema_compatibility AS iam CROSS JOIN profile.schema_compatibility AS profile CROSS JOIN demand.schema_compatibility AS demand CROSS JOIN trust.schema_compatibility AS trust CROSS JOIN taxonomy.schema_compatibility AS taxonomy"
}

_require_pins() {
    [ "$(_pins)" = "$EXPECTED_PINS" ] \
        || _blocked DATABASE_SCHEMA_PINS_INVALID
}

_contracts() {
    _psql_read --command \
        "SELECT concat_ws('|',encode(iam.combined_contract_sha256,'hex'),encode(profile.migration_manifest_sha256,'hex'),encode(demand.migration_manifest_sha256,'hex'),trust.required_iam_schema_version,trust.required_demand_schema_version,encode(trust.required_iam_contract_sha256,'hex'),encode(trust.required_demand_contract_sha256,'hex'),encode(trust.combined_contract_sha256,'hex'),encode(trust.migration_manifest_sha256,'hex'),encode(taxonomy.migration_manifest_sha256,'hex')) FROM infra.iam_schema_compatibility AS iam CROSS JOIN profile.schema_compatibility AS profile CROSS JOIN demand.schema_compatibility AS demand CROSS JOIN trust.schema_compatibility AS trust CROSS JOIN taxonomy.schema_compatibility AS taxonomy"
}

_require_contracts() {
    [ "$(_contracts)" = "$EXPECTED_CONTRACTS" ] \
        || _blocked DATABASE_SCHEMA_CONTRACTS_INVALID
}

_require_schema_contract() {
    _require_pins
    _require_contracts
}

_facts() {
    _psql_read --file "$FACTS_SQL"
}

_capture_facts() {
    target=$1
    _facts > "$target"
    [ -s "$target" ] \
        || _blocked DATABASE_CORE_FACTS_INVALID
    [ "$(wc -l < "$target" | tr -d ' ')" = 1 ] \
        || _blocked DATABASE_CORE_FACTS_INVALID
    grep -Eq '^\{.*\}$' "$target" \
        || _blocked DATABASE_CORE_FACTS_INVALID
    for required_key in \
        '"core_counts"' \
        '"continuity_counts"' \
        '"schema_contracts"' \
        '"demand_receipt_keys"' \
        '"trust_receipt_keys"' \
        '"appeal_receipt_keys"' \
        '"trust_sealed_text_keys"'
    do
        grep -Fq "$required_key" "$target" \
            || _blocked DATABASE_CORE_FACTS_INVALID
    done
}

_require_regular_0600() {
    [ -f "$1" ] && [ ! -L "$1" ] \
        || _blocked DATABASE_BACKUP_ARTIFACT_INVALID
    [ "$(stat -c '%a' "$1" 2>/dev/null || true)" = 600 ] \
        || _blocked DATABASE_BACKUP_ARTIFACT_PERMISSIONS_INVALID
}

_backup() {
    [ "$DESIRE_DATABASE_NAME" = desire ] \
        || _blocked DATABASE_BACKUP_SOURCE_INVALID
    [ -w "$BACKUP_ROOT" ] || _blocked DATABASE_BACKUP_ROOT_NOT_WRITABLE
    _require_client_18 pg_dump
    _require_schema_contract

    dump="$BACKUP_ROOT/$basename.dump"
    facts="$BACKUP_ROOT/$basename.facts.json"
    manifest="$BACKUP_ROOT/$basename.sha256"
    dump_partial="$dump.partial"
    facts_partial="$facts.partial"
    facts_after_partial="$facts.after.partial"
    manifest_partial="$manifest.partial"
    for path in \
        "$dump" "$facts" "$manifest" \
        "$dump_partial" "$facts_partial" "$facts_after_partial" "$manifest_partial"
    do
        [ ! -e "$path" ] && [ ! -L "$path" ] \
            || _blocked DATABASE_BACKUP_ALREADY_EXISTS
    done
    cleanup_partials=1

    _capture_facts "$facts_partial"
    PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=300000' \
        pg_dump \
        --no-password \
        --format=custom \
        --compress=6 \
        --serializable-deferrable \
        --lock-wait-timeout=30000 \
        --host "$DESIRE_DATABASE_HOST" \
        --port "$DESIRE_DATABASE_PORT" \
        --username "$DESIRE_DATABASE_ADMIN_USER" \
        --dbname "$DESIRE_DATABASE_NAME" \
        --file "$dump_partial"
    [ -s "$dump_partial" ] || _blocked DATABASE_BACKUP_EMPTY
    _capture_facts "$facts_after_partial"
    cmp -s "$facts_partial" "$facts_after_partial" \
        || _blocked DATABASE_BACKUP_CORE_FACTS_CHANGED

    dump_sha=$(sha256sum "$dump_partial" | awk '{print $1}')
    facts_sha=$(sha256sum "$facts_partial" | awk '{print $1}')
    printf '%s  %s.dump\n%s  %s.facts.json\n' \
        "$dump_sha" "$basename" "$facts_sha" "$basename" \
        > "$manifest_partial"
    unset dump_sha facts_sha

    mv "$dump_partial" "$dump"
    mv "$facts_partial" "$facts"
    mv "$manifest_partial" "$manifest"
    rm -f "$facts_after_partial"
    sync
    cleanup_partials=0
    printf '{"artifact":"%s","status":"DATABASE_BACKUP_READY"}\n' "$basename"
}

_require_isolated_restore_project() {
    project=${DESIRE_DATABASE_RESTORE_PROJECT:-}
    printf '%s' "$project" \
        | grep -Eq '^desire-restore-verify-[a-z0-9]{8,32}$' \
        || _blocked DATABASE_RESTORE_PROJECT_NOT_ISOLATED
    [ "$DESIRE_DATABASE_NAME" = desire_restore_verify ] \
        || _blocked DATABASE_RESTORE_TARGET_INVALID
}

_require_manifest_shape() {
    awk -v dump="$basename.dump" -v facts="$basename.facts.json" '
        NR == 1 {
            if ($1 !~ /^[0-9a-f]{64}$/ || $2 != dump || NF != 2) exit 1
        }
        NR == 2 {
            if ($1 !~ /^[0-9a-f]{64}$/ || $2 != facts || NF != 2) exit 1
        }
        NR > 2 { exit 1 }
        END { if (NR != 2) exit 1 }
    ' "$1" || _blocked DATABASE_BACKUP_MANIFEST_INVALID
}

_require_empty_restore_target() {
    restored_rows=$(
        _psql_read --command \
            "SELECT
                (SELECT count(*) FROM iam.users) +
                (SELECT count(*) FROM iam.sessions) +
                (SELECT count(*) FROM iam.access_invitations) +
                (SELECT count(*) FROM iam.memberships) +
                (SELECT count(*) FROM iam.policy_acceptances) +
                (SELECT count(*) FROM profile.creator_profiles) +
                (SELECT count(*) FROM profile.profile_versions) +
                (SELECT count(*) FROM profile.command_receipts) +
                (SELECT count(*) FROM demand.demands) +
                (SELECT count(*) FROM demand.demand_versions) +
                (SELECT count(*) FROM demand.demand_review_assignments) +
                (SELECT count(*) FROM demand.demand_reviews) +
                (SELECT count(*) FROM demand.source_inbox) +
                (SELECT count(*) FROM demand.command_receipts) +
                (SELECT count(*) FROM demand.review_claim_receipts) +
                (SELECT count(*) FROM demand.manual_funding_review_cases) +
                (SELECT count(*) FROM demand.manual_funding_review_assignments) +
                (SELECT count(*) FROM demand.demand_funding_markers) +
                (SELECT count(*) FROM demand.manual_funding_assignment_releases) +
                (SELECT count(*) FROM demand.manual_funding_findings) +
                (SELECT count(*) FROM demand.manual_funding_confirmations) +
                (SELECT count(*) FROM demand.manual_funding_receipts) +
                (SELECT count(*) FROM trust.reports) +
                (SELECT count(*) FROM trust.cases) +
                (SELECT count(*) FROM trust.case_assignments) +
                (SELECT count(*) FROM trust.case_assignment_releases) +
                (SELECT count(*) FROM trust.triage_drafts) +
                (SELECT count(*) FROM trust.triage_versions) +
                (SELECT count(*) FROM trust.safety_holds) +
                (SELECT count(*) FROM trust.case_outcome_versions) +
                (SELECT count(*) FROM trust.command_receipts) +
                (SELECT count(*) FROM trust.restricted_text_blobs) +
                (SELECT count(*) FROM trust.appeals) +
                (SELECT count(*) FROM trust.appeal_application_drafts) +
                (SELECT count(*) FROM trust.appeal_application_versions) +
                (SELECT count(*) FROM trust.appeal_review_assignments) +
                (SELECT count(*) FROM trust.appeal_assignment_releases) +
                (SELECT count(*) FROM trust.appeal_review_drafts) +
                (SELECT count(*) FROM trust.appeal_decision_versions) +
                (SELECT count(*) FROM trust.appeal_command_receipts) +
                (SELECT count(*) FROM taxonomy.bundles) +
                (SELECT count(*) FROM taxonomy.current_bundles) +
                (SELECT count(*) FROM taxonomy.nodes) +
                (SELECT count(*) FROM taxonomy.consumer_inbox) +
                (SELECT count(*) FROM profile.taxonomy_projection_inbox) +
                (SELECT count(*) FROM audit.audit_events) +
                (SELECT count(*) FROM infra.outbox_events) +
                (SELECT count(*) FROM infra.consumer_inbox_events)"
    )
    [ "$restored_rows" = 0 ] || _blocked DATABASE_RESTORE_TARGET_NOT_EMPTY
}

_restore_verify() {
    _require_isolated_restore_project
    _require_client_18 pg_restore
    _require_schema_contract
    _require_empty_restore_target

    dump="$BACKUP_ROOT/$basename.dump"
    facts="$BACKUP_ROOT/$basename.facts.json"
    manifest="$BACKUP_ROOT/$basename.sha256"
    _require_regular_0600 "$dump"
    _require_regular_0600 "$facts"
    _require_regular_0600 "$manifest"
    _require_manifest_shape "$manifest"
    (
        cd "$BACKUP_ROOT"
        sha256sum -c "$basename.sha256" >/dev/null
    ) || _blocked DATABASE_BACKUP_CHECKSUM_INVALID
    pg_restore --list "$dump" >/dev/null \
        || _blocked DATABASE_BACKUP_ARCHIVE_INVALID

    pg_restore \
        --no-password \
        --clean \
        --if-exists \
        --exit-on-error \
        --single-transaction \
        --host "$DESIRE_DATABASE_HOST" \
        --port "$DESIRE_DATABASE_PORT" \
        --username "$DESIRE_DATABASE_ADMIN_USER" \
        --dbname "$DESIRE_DATABASE_NAME" \
        "$dump"
    _require_schema_contract
    restored_facts_partial=/tmp/desire-restored-core-facts.json
    cleanup_partials=1
    _capture_facts "$restored_facts_partial"
    cmp -s "$facts" "$restored_facts_partial" \
        || _blocked DATABASE_RESTORE_CORE_FACTS_MISMATCH
    rm -f "$restored_facts_partial"
    cleanup_partials=0
    printf '{"artifact":"%s","status":"DATABASE_RESTORE_VERIFIED"}\n' "$basename"
}

[ "$#" -eq 1 ] || _blocked DATABASE_OPERATIONS_COMMAND_INVALID
operation=$1
_require_common_contract
case "$operation" in
    backup)
        _backup
        ;;
    restore-verify)
        _restore_verify
        ;;
    *)
        _blocked DATABASE_OPERATIONS_COMMAND_INVALID
        ;;
esac
