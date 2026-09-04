#!/bin/sh
# Host requirements: Docker Desktop (Compose v2+) and the system POSIX shell.
set -eu
umask 077
docker_local_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
docker_local_project=${DESIRE_LOCAL_PROJECT:-desire-supply-local}
case "$docker_local_project" in
    ''|*[!a-z0-9_-]*|[!a-z0-9]*) echo 'DESIRE_LOCAL_PROJECT must use lowercase letters, digits, underscores or hyphens, starting with a letter or digit.' >&2; exit 64 ;;
esac
docker_local_root="$docker_local_repo/.local/$docker_local_project"
docker_local_image="desire-supply-platform:$docker_local_project"
cd "$docker_local_repo"

fail() { printf '%s\n' "$*" >&2; exit 1; }

# --env-file does not override exported shell variables. Keep input pointers
# bound to this local project even when another deployment was used in the shell.
unset DESIRE_IMAGE_TAG DESIRE_DB_PASSWORD_FILE \
    DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE \
    DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE DESIRE_IDENTITY_SOURCE_DIR \
    DESIRE_INTERNAL_SANDBOX_TLS_DIR DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR \
    COMPOSE_FILE COMPOSE_PROFILES

local_compose() {
    docker compose --project-name "$docker_local_project" \
        --env-file "$docker_local_root/compose.env" \
        -f "$docker_local_repo/compose.yaml" \
        -f "$docker_local_root/compose.ipam.yaml" \
        -f "$docker_local_repo/compose.local.yaml" "$@"
}

dev_compose() {
    DESIRE_DB_PASSWORD_FILE="$docker_local_root/dev-db-password" \
    DESIRE_IMAGE_TAG="$docker_local_project" \
    docker compose --project-name "$docker_local_project-dev" \
        -f "$docker_local_repo/compose.yaml" \
        -f "$docker_local_repo/compose.dev.yaml" "$@"
}

require_inputs() {
    test -f "$docker_local_root/initialized" || fail 'Run ./scripts/docker-local.sh init first.'
}

initialize() {
    if test -f "$docker_local_root/initialized"; then
        printf '%s\n' 'Local inputs already exist; credentials and data are preserved.'
        return
    fi
    test ! -e "$docker_local_root" && test ! -L "$docker_local_root" \
        || fail 'Incomplete local inputs exist. Inspect them; use a new DESIRE_LOCAL_PROJECT for a fresh environment.'
    test ! -L "$docker_local_repo/.local" || fail '.local must not be a symlink.'
    # Refuse to silently attach fresh credentials to an existing project volume.
    test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$docker_local_project")" \
        || fail 'This Compose project already has containers. Choose a new DESIRE_LOCAL_PROJECT.'
    test -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$docker_local_project")" \
        || fail 'This Compose project already has volumes. Choose a new DESIRE_LOCAL_PROJECT.'
    DESIRE_IMAGE_TAG="$docker_local_project" docker compose \
        --project-name "$docker_local_project" -f compose.yaml build api web edge
    mkdir -p "$docker_local_repo/.local"
    mkdir -m 700 "$docker_local_root"
    # Same absolute input path on both sides keeps generated Compose paths valid.
    # No Docker socket, host toolchain, package installation, or network needed.
    docker run --rm --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges=true --user "$(id -u):$(id -g)" \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
        --mount "type=bind,source=$docker_local_repo/scripts,target=/tools,readonly" \
        --mount "type=bind,source=$docker_local_repo/deploy/docker-local-init.sh,target=/init.sh,readonly" \
        --mount "type=bind,source=$docker_local_root,target=$docker_local_root" \
        -e DESIRE_LOCAL_INGRESS_SUBNET -e DESIRE_LOCAL_OIDC_SUBNET \
        -e DESIRE_LOCAL_APP_SUBNET -e DESIRE_LOCAL_DATA_SUBNET \
        --entrypoint sh "$docker_local_image" /init.sh "$docker_local_root" "$docker_local_project"
    local_compose config --quiet
}

start_stack() {
    initialize
    if test -f "$docker_local_root/started"; then
        # Start in dependency order without rerunning the five completed jobs.
        # Each dependency must be healthy before the next service is resumed.
        for docker_local_service in db synthetic-oidc edge api matching-runtime web; do
            test -n "$(local_compose ps --all --quiet "$docker_local_service")" \
                || fail "Missing $docker_local_service container; inspect the project before recovery."
        done
        for docker_local_service in db synthetic-oidc edge api matching-runtime web; do
            local_compose up -d --no-build --pull never --no-deps --no-recreate \
                --wait --wait-timeout 180 "$docker_local_service"
        done
    else
        test ! -f "$docker_local_root/start-attempted" \
            || fail 'The first start did not finish. Inspect status and logs before recovery; inputs and data are preserved.'
        # Pull before recording an initialization attempt so network failures are retryable.
        local_compose pull db
        touch "$docker_local_root/start-attempted"
        local_compose up -d --no-build --pull never --wait --wait-timeout 180 \
            db synthetic-oidc edge api matching-runtime web
        touch "$docker_local_root/started"
    fi
    local_compose ps --all
    printf '\n%s\n' 'Ready: https://pilot.example.test — run ./scripts/docker-local.sh browser on macOS.'
}

docker_local_command=${1:-help}
if test "$#" -gt 0; then shift; fi
case "$docker_local_command" in
    help|-h|--help)
        cat <<'USAGE'
Usage: ./scripts/docker-local.sh COMMAND
  up          Build/init on first use; start or resume the complete platform
  init        Build images and generate local credentials/configuration in Docker
  stop        Stop the platform and docs, preserving all data
  status      List platform containers, including completed initialization jobs
  logs [svc]  Follow the last 100 log lines (Ctrl-C leaves services running)
  check       Check HTTPS homepage and OIDC discovery from the API container
  match ORG DEMAND VERSION REQUEST
              Request Matching for one funded demand through the SYSTEM workflow;
              REQUEST is a UUID to retain for safe retries
  browser     Open a dedicated macOS Chrome profile for this local environment
  docs        Start the documentation site at http://localhost:5174
  dev-up      Build/start a separate development container and test database;
              install locked Python/Node dependencies into Docker volumes
  dev [cmd]   Run a command in the development container (default: bash)
  dev-stop    Stop the development environment, preserving dependencies and data
  dev-status  List development containers

Default project: desire-supply-local; inputs: .local/desire-supply-local/
Override DESIRE_LOCAL_PROJECT to create a separate local environment.
USAGE
        ;;
    init) initialize ;;
    up) start_stack ;;
    stop) require_inputs; local_compose --profile docs stop ;;
    status) require_inputs; local_compose --profile docs ps --all ;;
    logs) require_inputs; local_compose --profile docs logs --tail 100 --follow "$@" ;;
    docs) require_inputs; local_compose --profile docs up -d --no-build --no-deps --wait docs ;;
    check)
        require_inputs
        local_compose exec -T api python -c '
import json, urllib.request
for url in ("https://pilot.example.test/", "https://identity.example.test/.well-known/openid-configuration"):
    with urllib.request.urlopen(url, timeout=10) as response:
        assert response.status == 200
        if "openid-configuration" in url:
            assert json.load(response)["issuer"] == "https://identity.example.test"
        print("OK", url)
'
        ;;
    match)
        require_inputs
        test "$#" -eq 4 || fail 'Usage: match ORGANIZATION_UUID DEMAND_UUID EXPECTED_VERSION REQUEST_UUID'
        # Provision only the existing demand_system login in an isolated job.
        # The administrator credential never enters the business command container.
        docker run --rm --network "${docker_local_project}_data" --read-only \
            --cap-drop ALL --security-opt no-new-privileges=true \
            --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
            --mount "type=bind,source=$docker_local_repo/scripts,target=/tools,readonly" \
            --mount "type=bind,source=$docker_local_root/db_superuser_password.txt,target=/run/secrets/db_superuser_password,readonly" \
            --mount "type=bind,source=$docker_local_root/internal-sandbox-bundle/runtime-secrets,target=/source,readonly" \
            --mount "type=bind,source=$docker_local_root,target=/output" \
            --entrypoint python "$docker_local_image" -B /tools/prepare_local_matching_workflow.py \
            --database desire --admin-password-file /run/secrets/db_superuser_password \
            --source-secret-directory /source --output-directory /output/workflow-secrets
        docker run --rm --network "${docker_local_project}_data" --read-only \
            --cap-drop ALL --security-opt no-new-privileges=true \
            --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
            --mount "type=bind,source=$docker_local_root/workflow-secrets,target=/run/workflow-secrets,readonly" \
            --entrypoint python "$docker_local_image" -B -m desire_platform.internal_pilot.matching_workflow \
            --organization-id "$1" --demand-id "$2" --expected-version "$3" --request-id "$4" \
            --database desire --credential-directory /run/workflow-secrets
        ;;
    browser)
        require_inputs
        test "$(uname -s)" = Darwin || fail 'The browser helper currently supports macOS. See docs/operations/docker-local.md.'
        test -d '/Applications/Google Chrome.app' || fail 'Install Google Chrome to use the isolated local browser profile.'
        # Allow exactly this test leaf public key in the dedicated profile. The
        # normal browser profile, hosts file and system trust store are untouched.
        docker_local_spki=$(docker run --rm --network none --read-only \
            --cap-drop ALL --security-opt no-new-privileges=true \
            --mount "type=bind,source=$docker_local_root/internal-sandbox-tls/edge-tls-chain.pem,target=/leaf.pem,readonly" \
            --entrypoint python "$docker_local_image" -c '
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pathlib import Path
import base64, hashlib
cert = x509.load_pem_x509_certificate(Path("/leaf.pem").read_bytes())
spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
print(base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii"))
')
        test "${#docker_local_spki}" -eq 44 || fail 'Could not read the local certificate fingerprint.'
        open -na 'Google Chrome' --args \
            --user-data-dir="$docker_local_root/chrome" \
            --no-first-run --no-default-browser-check --no-proxy-server \
            '--host-resolver-rules=MAP pilot.example.test 127.0.0.1, MAP identity.example.test 127.0.0.1' \
            "--ignore-certificate-errors-spki-list=$docker_local_spki" \
            https://pilot.example.test
        ;;
    dev-up)
        require_inputs
        dev_compose build devcontainer
        dev_compose up -d --wait --wait-timeout 180 db devcontainer
        dev_compose exec -T devcontainer sh -lc \
            'cd /workspace/mvp && uv sync --locked && /usr/local/bin/desire-devcontainer-post-create'
        ;;
    dev)
        require_inputs
        if test "$#" -eq 0; then set -- bash; fi
        if test -t 0 && test -t 1; then
            dev_compose exec devcontainer "$@"
        else
            dev_compose exec -T devcontainer "$@"
        fi
        ;;
    dev-stop) require_inputs; dev_compose stop devcontainer db ;;
    dev-status) require_inputs; dev_compose ps --all ;;
    *) fail "Unknown command: $docker_local_command. Use --help." ;;
esac
