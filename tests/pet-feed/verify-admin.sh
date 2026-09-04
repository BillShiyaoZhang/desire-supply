#!/bin/sh
set -eu
umask 077
pet_repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
pet_project=${DESIRE_LOCAL_PROJECT:-desire-workflow-20260904-verified}
pet_dev_image=${PET_FEED_RUNNER_IMAGE:-desire-supply-devcontainer:desire-supply-local}
case "$pet_project" in ''|*[!a-z0-9_-]*) exit 64 ;; esac
pet_run="admin-$(date -u +%Y%m%dT%H%M%SZ)"
pet_root="$pet_repo/.local/pet-feed"
mkdir -p "$pet_root"
docker run --rm --network "${pet_project}_ingress" --read-only \
    --cap-drop ALL --security-opt no-new-privileges=true \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,source=$pet_repo,target=/workspace,readonly" \
    --mount "type=bind,source=$pet_root,target=/evidence" \
    --mount "type=bind,source=$pet_repo/.local/$pet_project/internal-sandbox-tls/root-ca.pem,target=/ca.pem,readonly" \
    --entrypoint python "$pet_dev_image" -B /workspace/tests/pet-feed/verify_admin.py \
    --ca-file /ca.pem --output-dir "/evidence/$pet_run" "$@"
printf 'Evidence: %s/%s\n' "$pet_root" "$pet_run"
