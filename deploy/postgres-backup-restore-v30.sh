#!/bin/sh
# PostgreSQL 18 logical backup and isolated restore proof for current-head v30.
# The restore target is an isolated database/project and facts contain only
# schema metadata, key identifiers, and aggregate continuity counts.

set -eu
umask 077

BACKUP_ROOT=/var/lib/desire-backup
FACTS_SQL=/run/desire-ops/postgres-core-facts.sql
PGPASS_PATH=/tmp/desire-postgres-operations.pgpass
EXPECTED_PINS='18|48|48|5|5|16|16|24|24|11|11|2|2'
EXPECTED_CONTRACTS='616cda6eac1e9f853be019f5790584e16826c295be08d10201f947e923a5ba3f|005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8|48|4802d0ba44c05a059f3dfdbe0911e7be05cfd5d8508c8ced48a0a3f22bc1290f|48|16|616cda6eac1e9f853be019f5790584e16826c295be08d10201f947e923a5ba3f|3362a606f35221c61cfb302ee54ce13bea450a44a02b33217606003a89c569ce|119f603be0862e7f35bc533005e7fef82f7bd6384eb2ab7966b04e75a5dfa199|9574f3df40b95a3b1a0fdfd778a11edc969c27dc7879efca78aa75515cbdef24|48|bbf292401809ff6b1fdf05fd687d7f337dfb34e193f5340c579dceaba4801e18|ec63cb0733f275eaedc99348427883bb958c6467c5ee49f2a26fb252c0aafb6a|144337610f3d06b8bfbb324547f3e25ca54ee6c2f821a28f94812aefc01ea4aa|38c90e5d73f7aff05d7b3dc6263c52a0c50c6769daa3b8ee541dccd58057f970|8774cf412ffa82c9acf53e6e7e95af361f84ec8040d02b972f846d57bb395418|856f95a2169a095d238277586cfdb171d38104eaaaa03d2df925502e1b919a28|6b8b739a27bbd3894372de8a566133a6991fca22d97da883c87d6ebf601763de|c7cc2c975f85723a5f4f3c7aa45fe6ebdf6f0fc0df140a06d111aad33eceffbb|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622'
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
        "SELECT concat_ws('|',current_setting('server_version_num')::integer/10000,iam.current_schema_version,iam.schema_head_version,profile.current_schema_version,profile.schema_head_version,demand.current_schema_version,demand.schema_head_version,trust.current_schema_version,trust.schema_head_version,matching.current_schema_version,matching.schema_head_version,taxonomy.current_schema_version,taxonomy.schema_head_version) FROM infra.iam_schema_compatibility AS iam CROSS JOIN profile.schema_compatibility AS profile CROSS JOIN demand.schema_compatibility AS demand CROSS JOIN trust.schema_compatibility AS trust CROSS JOIN matching.schema_compatibility AS matching CROSS JOIN taxonomy.schema_compatibility AS taxonomy"
}

_require_pins() {
    [ "$(_pins)" = "$EXPECTED_PINS" ] \
        || _blocked DATABASE_SCHEMA_PINS_INVALID
}

_contracts() {
    _psql_read --command \
        "SELECT concat_ws('|',encode(iam.combined_contract_sha256,'hex'),encode(profile.migration_manifest_sha256,'hex'),demand.required_iam_schema_version,encode(demand.migration_manifest_sha256,'hex'),trust.required_iam_schema_version,trust.required_demand_schema_version,encode(trust.required_iam_contract_sha256,'hex'),encode(trust.required_demand_contract_sha256,'hex'),encode(trust.combined_contract_sha256,'hex'),encode(trust.migration_manifest_sha256,'hex'),matching.required_iam_schema_version,encode(matching_meta.api_contract_sha256,'hex'),encode(matching_meta.event_contract_sha256,'hex'),encode(matching_meta.rule_contract_sha256,'hex'),encode(matching_meta.input_manifest_contract_sha256,'hex'),encode(matching_meta.run_input_contract_sha256,'hex'),encode(matching_meta.candidate_contract_sha256,'hex'),encode(matching_meta.disclosure_contract_sha256,'hex'),encode(matching.migration_manifest_sha256,'hex'),encode(taxonomy.migration_manifest_sha256,'hex')) FROM infra.iam_schema_compatibility AS iam CROSS JOIN profile.schema_compatibility AS profile CROSS JOIN demand.schema_compatibility AS demand CROSS JOIN trust.schema_compatibility AS trust CROSS JOIN matching.schema_compatibility AS matching CROSS JOIN matching_meta.schema_contracts AS matching_meta CROSS JOIN taxonomy.schema_compatibility AS taxonomy WHERE matching_meta.singleton_key"
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
        '"matching_continuity_counts"' \
        '"schema_contracts"' \
        '"iam_durable_counts"' \
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
    for artifact_path in \
        "$dump" "$facts" "$manifest" \
        "$dump_partial" "$facts_partial" "$facts_after_partial" "$manifest_partial"
    do
        [ ! -e "$artifact_path" ] && [ ! -L "$artifact_path" ] \
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
                (SELECT count(*) FROM iam.external_identities) +
                (SELECT count(*) FROM iam.contact_points) +
                (SELECT count(*) FROM iam.organizations) +
                (SELECT count(*) FROM iam.auth_transactions) +
                (SELECT count(*) FROM iam.session_families) +
                (SELECT count(*) FROM iam.sessions) +
                (SELECT count(*) FROM iam.session_security_events) +
                (SELECT count(*) FROM iam.access_invitations) +
                (SELECT count(*) FROM iam.memberships) +
                (SELECT count(*) FROM iam.user_role_grants) +
                (SELECT count(*) FROM iam.membership_role_grants) +
                (SELECT count(*) FROM iam.platform_duty_grants) +
                (SELECT count(*) FROM iam.policy_acceptances) +
                (SELECT count(*) FROM iam.consent_grants) +
                (SELECT count(*) FROM iam.consent_grant_data_categories) +
                (SELECT count(*) FROM iam.consent_withdrawals) +
                (SELECT count(*) FROM infra.command_receipts) +
                (SELECT count(*) FROM infra.iam_sandbox_bootstrap_state) +
                (SELECT count(*) FROM infra.iam_sandbox_bootstrap_accounts) +
                (SELECT count(*) FROM infra.iam_sandbox_bootstrap_runs) +
                (SELECT count(*) FROM infra.iam_sandbox_bootstrap_manifest_bridges) +
                (SELECT count(*) FROM profile.creator_profiles) +
                (SELECT count(*) FROM profile.profile_versions) +
                (SELECT count(*) FROM profile.command_receipts) +
                (SELECT count(*) FROM profile.match_capture_batches) +
                (SELECT count(*) FROM profile.match_input_snapshots) +
                (SELECT count(*) FROM profile.derived_match_capture_receipts) +
                (SELECT count(*) FROM profile.derived_match_raw_snapshots) +
                (SELECT count(*) FROM profile.derived_match_input_snapshots) +
                (SELECT count(*) FROM demand.demands) +
                (SELECT count(*) FROM demand.demand_versions) +
                (SELECT count(*) FROM demand.demand_review_assignments) +
                (SELECT count(*) FROM demand.demand_review_assignment_releases) +
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
                (SELECT count(*) FROM demand.matching_requested_deliveries) +
                (SELECT count(*) FROM demand.matching_delivery_claim_receipts) +
                (SELECT count(*) FROM demand.complete_selection_receipts) +
                (SELECT count(*) FROM demand.close_matching_without_selection_receipts) +
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
                (SELECT count(*) FROM matching.candidate_selector_assignments) +
                (SELECT count(*) FROM matching.candidate_selector_opt_in_receipts) +
                (SELECT count(*) FROM matching.command_receipts) +
                (SELECT count(*) FROM matching.complete_selection_close_records) +
                (SELECT count(*) FROM matching.complete_selection_records) +
                (SELECT count(*) FROM matching.complete_selection_system_close_records) +
                (SELECT count(*) FROM matching.invitation_disclosure_snapshots) +
                (SELECT count(*) FROM matching.invitation_responses) +
                (SELECT count(*) FROM matching.invitation_withdrawals) +
                (SELECT count(*) FROM matching.invitations) +
                (SELECT count(*) FROM matching.match_candidates) +
                (SELECT count(*) FROM matching.match_jobs) +
                (SELECT count(*) FROM matching.match_run_inputs) +
                (SELECT count(*) FROM matching.match_run_results) +
                (SELECT count(*) FROM matching.match_runs) +
                (SELECT count(*) FROM matching.matching_attempts) +
                (SELECT count(*) FROM matching.matching_review_assignments) +
                (SELECT count(*) FROM matching.review_hold_evidence) +
                (SELECT count(*) FROM matching.reviewer_authority_projections) +
                (SELECT count(*) FROM matching.rule_bundles) +
                (SELECT count(*) FROM matching.rule_selectors) +
                (SELECT count(*) FROM matching.selection_close_intents) +
                (SELECT count(*) FROM matching.selection_completion_jobs) +
                (SELECT count(*) FROM matching.selection_intents) +
                (SELECT count(*) FROM matching.selection_system_close_intents) +
                (SELECT count(*) FROM matching.selections) +
                (SELECT count(*) FROM matching.source_inbox) +
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
