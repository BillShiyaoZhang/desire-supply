#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
platform_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
python_command=${DESIRE_PLATFORM_TEST_PYTHON:-$platform_root/.venv/bin/python}
postgres_image=${DESIRE_TEST_POSTGRES18_IMAGE:-postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}
container_id=

cleanup() {
    if [ -n "$container_id" ]; then
        docker rm --force "$container_id" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$python_command" ]; then
    echo '{"code":"IAM_0024_TEST_PYTHON_UNAVAILABLE","status":"BLOCKED"}' >&2
    exit 78
fi

if [ -n "${DESIRE_IAM_TEST_POSTGRES_DSN:-}" ]; then
    if [ "${DESIRE_IAM_TEST_POSTGRES_EPHEMERAL:-}" != "1" ]; then
        echo '{"code":"IAM_0024_TEST_EXTERNAL_POSTGRES_NOT_EPHEMERAL","status":"BLOCKED"}' >&2
        exit 78
    fi
    cd "$platform_root"
    PYTHONPATH=tests \
        "$python_command" -m pytest -q \
        tests/storage/postgres/test_iam_http_session_security_postgres_red.py \
        -x --tb=short
    exit 0
fi

if ! container_id=$(docker run \
    --detach \
    --rm \
    --publish 127.0.0.1::5432 \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    --env POSTGRES_DB=postgres \
    "$postgres_image" 2>/dev/null); then
    echo '{"code":"IAM_0024_TEST_POSTGRES_UNAVAILABLE","status":"BLOCKED"}' >&2
    exit 69
fi

ready=false
attempt=0
while [ "$attempt" -lt 60 ]; do
    if docker exec "$container_id" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
if [ "$ready" != true ]; then
    echo '{"code":"IAM_0024_TEST_POSTGRES_UNAVAILABLE","status":"BLOCKED"}' >&2
    exit 69
fi

published_address=$(docker port "$container_id" 5432/tcp)
published_port=${published_address##*:}
case "$published_port" in
    ''|*[!0-9]*)
        echo '{"code":"IAM_0024_TEST_POSTGRES_PORT_INVALID","status":"BLOCKED"}' >&2
        exit 69
        ;;
esac

cd "$platform_root"
DESIRE_IAM_TEST_POSTGRES_DSN="postgresql://postgres@127.0.0.1:$published_port/postgres" \
DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1 \
PYTHONPATH=tests \
    "$python_command" -m pytest -q \
    tests/storage/postgres/test_iam_http_session_security_postgres_red.py \
    -x --tb=short
