#!/bin/sh
set -eu

runtime_owner="$(id -u):$(id -g)"
for dependency_root in \
    /home/node/.cache/uv \
    /home/node/.npm \
    /workspace/platform/.venv \
    /workspace/mvp/.venv \
    /workspace/web/node_modules
do
    if [ ! -d "$dependency_root" ] \
        || ! sudo -n chown -- "$runtime_owner" "$dependency_root"
    then
        echo '{"code":"DEVCONTAINER_CACHE_OWNERSHIP_INVALID","status":"BLOCKED"}' >&2
        exit 78
    fi
done
unset dependency_root runtime_owner

secret_path=/run/secrets/db_superuser_password
pgpass_path=${PGPASSFILE:-}

if [ ! -r "$secret_path" ] || [ "$pgpass_path" != /tmp/desire-pgpass ]; then
    echo '{"code":"DEVCONTAINER_DATABASE_SECRET_INVALID","status":"BLOCKED"}' >&2
    exit 78
fi

database_password=
exec 3<"$secret_path"
if ! IFS= read -r database_password <&3; then
    if [ -z "$database_password" ]; then
        echo '{"code":"DEVCONTAINER_DATABASE_SECRET_INVALID","status":"BLOCKED"}' >&2
        exit 78
    fi
fi
unexpected_line=
if IFS= read -r unexpected_line <&3 || [ -n "$unexpected_line" ]; then
    echo '{"code":"DEVCONTAINER_DATABASE_SECRET_INVALID","status":"BLOCKED"}' >&2
    exit 78
fi
exec 3<&-

case "$database_password" in
    *:*|*\\*)
        echo '{"code":"DEVCONTAINER_DATABASE_SECRET_INVALID","status":"BLOCKED"}' >&2
        exit 78
        ;;
esac
if [ "${#database_password}" -lt 24 ]; then
    echo '{"code":"DEVCONTAINER_DATABASE_SECRET_INVALID","status":"BLOCKED"}' >&2
    exit 78
fi

umask 077
printf 'db:5432:*:postgres:%s\n' "$database_password" > "$pgpass_path"
unset database_password unexpected_line

exec "$@"
