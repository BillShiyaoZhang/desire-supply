#!/bin/sh
set -eu

cd /workspace/platform
uv sync --locked --extra test --extra server

cd /workspace/web
npm ci --ignore-scripts --no-audit

printf '%s\n' '{"status":"DEVCONTAINER_DEPENDENCIES_READY"}'
