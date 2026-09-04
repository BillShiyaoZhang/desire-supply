#!/bin/sh
# Runs inside platform-runtime, with only the new local input directory writable.
set -eu
# The existing generators assert exact 0444 identity files and a 0755 identity
# directory; their secret files explicitly use 0600 under the private 0700 root.
umask 022
docker_local_root=$1
docker_local_project=$2

python -B /tools/prepare_internal_sandbox_inputs.py create \
    --output-root "$docker_local_root"
python -B /tools/manage_internal_sandbox_tls.py create \
    --output-dir "$docker_local_root/internal-sandbox-tls"
python -B -m desire_platform.deployment.internal_sandbox_bundle create \
    --output-dir "$docker_local_root/internal-sandbox-bundle" \
    --oidc-issuer https://identity.example.test \
    --oidc-client-id desire-internal-sandbox \
    --oidc-redirect-uri https://pilot.example.test/v1/auth/oidc/callback \
    --oidc-client-secret-file "$docker_local_root/oidc-client-secret" \
    --oidc-network-binding-mode SYSTEM_DNS_SYNTHETIC \
    --deployment-id "$docker_local_project" \
    --release-id "$docker_local_project"
python -B /tools/prepare_internal_sandbox_compose_inputs.py create \
    --input-root "$docker_local_root" \
    --image-tag "$docker_local_project" \
    --bundle-dir-name internal-sandbox-bundle \
    --ingress-subnet "${DESIRE_LOCAL_INGRESS_SUBNET:-172.29.240.0/24}" \
    --oidc-subnet "${DESIRE_LOCAL_OIDC_SUBNET:-172.29.241.0/24}" \
    --app-subnet "${DESIRE_LOCAL_APP_SUBNET:-172.29.242.0/24}" \
    --data-subnet "${DESIRE_LOCAL_DATA_SUBNET:-172.29.243.0/24}"

# Tests use a separate Compose project, volume, and database password.
umask 077
python -B -c 'import pathlib, secrets, sys; p = pathlib.Path(sys.argv[1]) / "dev-db-password"; p.write_text(secrets.token_urlsafe(48)); p.chmod(0o600)' "$docker_local_root"
touch "$docker_local_root/initialized"
