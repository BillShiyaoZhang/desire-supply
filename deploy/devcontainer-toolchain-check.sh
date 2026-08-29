#!/bin/sh
set -u
export LC_ALL=C

toolchain_blocked() {
    printf '%s\n' "$1" >&2
    exit 1
}

if ! toolchain_value="$(python --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_PYTHON_VERSION
fi
test "$toolchain_value" = "Python 3.14.1" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_PYTHON_VERSION

if ! python -c 'import bz2, ctypes, dbm.gnu, hashlib, json, lzma, readline, sqlite3, ssl, uuid, venv, zlib' \
    >/dev/null 2>&1
then
    toolchain_blocked BLOCKED:DEVCONTAINER_PYTHON_IMPORT
fi

if ! toolchain_value="$(node --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_NODE_VERSION
fi
test "$toolchain_value" = "v22.22.3" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_NODE_VERSION

if ! npm --version >/dev/null 2>&1
then
    toolchain_blocked BLOCKED:DEVCONTAINER_NPM_VERSION
fi

toolchain_status=0
toolchain_value="$(npm --help 2>&1)" || toolchain_status="$?"
case "$toolchain_status" in
    0|1) ;;
    *) toolchain_blocked BLOCKED:DEVCONTAINER_NPM_HELP ;;
esac
if [ -z "$toolchain_value" ]
then
    toolchain_blocked BLOCKED:DEVCONTAINER_NPM_HELP
fi
if ! printf '%s\n' "$toolchain_value" \
    | awk '$0 == "Usage:" || $0 == "npm <command>" { usage = 1 }
        END { exit usage == 1 ? 0 : 1 }' >/dev/null 2>&1
then
    toolchain_blocked BLOCKED:DEVCONTAINER_NPM_HELP
fi

if ! toolchain_value="$(npm config get cache 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_NPM_CACHE
fi
test "$toolchain_value" = "/home/node/.npm" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_NPM_CACHE

if ! toolchain_value="$(psql --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_PSQL_VERSION
fi
case "$toolchain_value" in
    "psql (PostgreSQL) 18.4"*) ;;
    *) toolchain_blocked BLOCKED:DEVCONTAINER_PSQL_VERSION ;;
esac

if ! toolchain_value="$(pg_dump --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_PG_DUMP_VERSION
fi
case "$toolchain_value" in
    "pg_dump (PostgreSQL) 18.4"*) ;;
    *) toolchain_blocked BLOCKED:DEVCONTAINER_PG_DUMP_VERSION ;;
esac

if ! toolchain_value="$(pg_restore --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_PG_RESTORE_VERSION
fi
case "$toolchain_value" in
    "pg_restore (PostgreSQL) 18.4"*) ;;
    *) toolchain_blocked BLOCKED:DEVCONTAINER_PG_RESTORE_VERSION ;;
esac

if ! toolchain_value="$(uv --version 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_UV_VERSION
fi
test "$toolchain_value" = "uv 0.9.15" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_UV_VERSION

if ! toolchain_value="$(id -u 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_UID
fi
if ! test "$toolchain_value" -gt 0 2>/dev/null
then
    toolchain_blocked BLOCKED:DEVCONTAINER_UID
fi

if ! toolchain_value="$(id -un 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_USERNAME
fi
test "$toolchain_value" = "node" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_USERNAME

if ! toolchain_value="$(getent passwd node 2>&1)"
then
    toolchain_blocked BLOCKED:DEVCONTAINER_SHELL
fi
test "${toolchain_value##*:}" = "/bin/bash" \
    || toolchain_blocked BLOCKED:DEVCONTAINER_SHELL

if ! sudo -n true >/dev/null 2>&1
then
    toolchain_blocked BLOCKED:DEVCONTAINER_SUDO
fi

toolchain_home=${HOME:-}
if [ "$toolchain_home" != /home/node ] \
    || [ ! -d "$toolchain_home" ] \
    || [ ! -w "$toolchain_home" ]
then
    toolchain_blocked BLOCKED:DEVCONTAINER_HOME
fi

for dependency_root in \
    /home/node/.cache/uv \
    /home/node/.npm \
    /workspace/platform/.venv \
    /workspace/mvp/.venv \
    /workspace/web/node_modules
do
    if [ ! -d "$dependency_root" ] || [ ! -w "$dependency_root" ]
    then
        toolchain_blocked BLOCKED:DEVCONTAINER_DEPENDENCY_ROOT
    fi
done
unset dependency_root toolchain_home

printf '%s\n' 'READY:DEVCONTAINER_TOOLCHAIN'
