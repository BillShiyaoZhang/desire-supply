#!/bin/sh
# Reuses the existing local sandbox; no database resets, migrations or SQL writes.
set -eu
umask 077
pet_repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
pet_project=${DESIRE_LOCAL_PROJECT:-desire-workflow-20260904-verified}
pet_dev_image=${PET_FEED_RUNNER_IMAGE:-desire-supply-devcontainer:desire-supply-local}
case "$pet_project" in ''|*[!a-z0-9_-]*) exit 64 ;; esac
pet_run=$(date -u +%Y%m%dT%H%M%SZ)
pet_root="$pet_repo/.local/pet-feed"
pet_output="$pet_root/$pet_run"
mkdir -p "$pet_root"
set --
if test -n "${PET_FEED_ORIGINAL_DEMAND_ID:-}"; then
    set -- --original-id "$PET_FEED_ORIGINAL_DEMAND_ID"
fi
if test -n "${PET_FEED_SOFTWARE_DEMAND_ID:-}"; then
    set -- "$@" --software-id "$PET_FEED_SOFTWARE_DEMAND_ID"
fi
docker run --rm --network "${pet_project}_ingress" --read-only \
    --cap-drop ALL --security-opt no-new-privileges=true \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,source=$pet_repo,target=/workspace,readonly" \
    --mount "type=bind,source=$pet_root,target=/evidence" \
    --mount "type=bind,source=$pet_repo/.local/$pet_project/internal-sandbox-tls/root-ca.pem,target=/ca.pem,readonly" \
    --entrypoint python "$pet_dev_image" -B /workspace/tests/pet-feed/simulate.py \
    --ca-file /ca.pem --output-dir "/evidence/$pet_run" "$@" &
pet_pid=$!
pet_requested=false
while kill -0 "$pet_pid" 2>/dev/null; do
    if test "$pet_requested" = false && test -f "$pet_output/matching-request.args"; then
        read -r pet_org pet_demand pet_version pet_request < "$pet_output/matching-request.args"
        # This handoff is emitted only after normal dual zero-value confirmation.
        DESIRE_LOCAL_PROJECT="$pet_project" "$pet_repo/scripts/docker-local.sh" match \
            "$pet_org" "$pet_demand" "$pet_version" "$pet_request" \
            > "$pet_output/system-command.log" 2>&1
        pet_requested=true
        printf '%s\n' 'SYSTEM RequestMatching completed for the emitted demand.'
    fi
    sleep 1
done
wait "$pet_pid"
printf 'Evidence: %s\n' "$pet_output"
