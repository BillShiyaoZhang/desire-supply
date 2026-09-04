#!/usr/bin/env python3
"""Static, side-effect-free verifier for the container deployment contract."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


POSTGRES_IMAGE = re.compile(
    r"^postgres:18\.[0-9]+-alpine@sha256:[0-9a-f]{64}$"
)
POSTGRES_PARENT_PATH = "/var/lib/postgresql"
POSTGRES_PARENT_TMPFS = (
    "/var/lib/postgresql:rw,nosuid,nodev,noexec,size=1m"
)
POSTGRES_CHILD_DATA = "/var/lib/postgresql/data"
POSTGRES_CHILD_PGDATA = "/var/lib/postgresql/data/pgdata"
DEVCONTAINER_EXECUTABLE_TMPFS = "/tmp:rw,exec,nosuid,nodev,size=64m"
DATABASE_RESTORE_SUBNET_EXPRESSION = (
    "${DESIRE_DATABASE_RESTORE_SUBNET:-172.16.232.0/24}"
)
DATABASE_RESTORE_EMPTY_TARGET_RELATIONS = (
    "demand.demand_funding_markers",
    "demand.manual_funding_assignment_releases",
    "demand.manual_funding_findings",
)
CURRENT_HEAD_V13_FRESH_RUNBOOK_START = (
    "# BEGIN CURRENT_HEAD_V13_FRESH_RUNBOOK"
)
CURRENT_HEAD_V13_FRESH_RUNBOOK_END = "# END CURRENT_HEAD_V13_FRESH_RUNBOOK"
CURRENT_HEAD_V13_JOURNEY_RESTART_START = (
    "# BEGIN CURRENT_HEAD_V13_JOURNEY_RESTART"
)
CURRENT_HEAD_V13_JOURNEY_RESTART_END = (
    "# END CURRENT_HEAD_V13_JOURNEY_RESTART"
)
CURRENT_HEAD_BACKUP_RUNBOOK_START = (
    "#### 4.8.1 当前头部 v13 源侧备份（一次性）"
)
CURRENT_HEAD_BACKUP_RUNBOOK_END = (
    "#### 4.8.2 当前头部隔离恢复与 replay"
)
CURRENT_HEAD_RESTORE_RUNBOOK_END = "### 当前应能勾选"
CURRENT_HEAD_RESTORE_PREFLIGHT_START = (
    "# BEGIN CURRENT_HEAD_RESTORE_PREFLIGHT"
)
CURRENT_HEAD_RESTORE_PREFLIGHT_END = "# END CURRENT_HEAD_RESTORE_PREFLIGHT"
CURRENT_HEAD_RESTORE_EXECUTION_START = (
    "# BEGIN CURRENT_HEAD_RESTORE_EXECUTION"
)
CURRENT_HEAD_RESTORE_EXECUTION_END = "# END CURRENT_HEAD_RESTORE_EXECUTION"
CURRENT_HEAD_RESTORE_POSTRUN_START = "# BEGIN CURRENT_HEAD_RESTORE_POSTRUN"
CURRENT_HEAD_RESTORE_POSTRUN_END = "# END CURRENT_HEAD_RESTORE_POSTRUN"
CURRENT_HEAD_RESTORE_AUTHORITY_START = (
    "<!-- BEGIN CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->"
)
CURRENT_HEAD_RESTORE_AUTHORITY_END = (
    "<!-- END CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->"
)
CURRENT_HEAD_RESTORE_AUTHORITY_SHA256 = (
    "f587ab55d139d4143265ea0f93c084a9fdf17e96bd038da577dfbfef6088a554"
)
CURRENT_HEAD_V13_PROTOCOL_SHA256 = (
    "9f14c6e058b4ae916ff9ae82f4f4ea381d71abc66a5684a7868b97e956ff4c76"
)
CURRENT_HEAD_V13_DOCKER_HUB_PREFLIGHT_COMMAND = (
    "python3 -B scripts/preflight_docker_hub_manifests.py"
)
DOCKER_HUB_MANIFEST_PREFLIGHT_RELATIVE_PATH = (
    "scripts/preflight_docker_hub_manifests.py"
)
DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256 = (
    "0665199dc79fd359d435d9159bed69bc21d73d19887fe2f77f2c79ab199ea5b0"
)
REVIEWED_CONTAINER_ARTIFACT_SHA256 = (
    (
        "Dockerfile",
        "6d16a0a7179dcf62fe7cdf2b2a76b39b1d1db8c450ea2d1df35ed0ec84b14677",
    ),
    (
        "compose.yaml",
        "325919f3066d9d2eaa1dd943fac35fd55bde0e9005d178ee0c1211e04e224ddd",
    ),
)
BOUNDED_LOGGING = {
    "driver": "local",
    "options": {
        "compress": "true",
        "max-file": "3",
        "max-size": "10m",
    },
}
BACKUP_IGNORE_RULE = "/backups/"
BACKUP_ARTIFACT_RELATIVE = (
    "backups/internal-sandbox/v13drill01/"
    "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01.dump"
)
DEVCONTAINER_PYTHON_IMAGE = (
    "python:3.14.1-slim-bookworm@sha256:"
    "5d17fc066275d26bb2ffe05bc89367dc665310200b5f4cfa8b294e97dc679bff"
)
DEVCONTAINER_NODE_IMAGE = (
    "node:22.22.3-bookworm-slim@sha256:"
    "e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752"
)
DEVCONTAINER_UV_IMAGE = (
    "ghcr.io/astral-sh/uv:0.9.15@sha256:"
    "4c1ad814fe658851f50ff95ecd6948673fffddb0d7994bdb019dcb58227abd52"
)
DEVCONTAINER_POSTGRES_IMAGE = (
    "postgres:18.4-bookworm@sha256:"
    "1961f96e6029a02c3812d7cb329a3b03a3ac2bb067058dec17b0f5596aca9296"
)
DEVCONTAINER_POST_CREATE = (
    "cd /workspace/mvp && uv sync --locked && "
    "/usr/local/bin/desire-devcontainer-post-create"
)
DEVCONTAINER_INITIALIZE_COMMAND = (
    'if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then '
    "printf '%s\\n' 'BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME' >&2; "
    "exit 64; fi; exit 0"
)
DEVCONTAINER_DAILY_COMMANDS = (
    "docker compose --project-name desire-supply-devcontainer "
    "-f compose.yaml -f compose.dev.yaml up -d db devcontainer",
    "docker compose --project-name desire-supply-devcontainer "
    "-f compose.yaml -f compose.dev.yaml exec devcontainer sh",
    "docker compose --project-name desire-supply-devcontainer "
    "-f compose.yaml -f compose.dev.yaml stop devcontainer db",
)
DEVCONTAINER_AUDIT_PS = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml ps -a"
)
DEVCONTAINER_AUDIT_COUNT = (
    'test "$(docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml ps --all --quiet | wc -l | "
    "tr -d '[:space:]')\" = \"2\""
)
DEVCONTAINER_AUDIT_DOWN = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml down --volumes --remove-orphans"
)
DEVCONTAINER_V9_EVIDENCE = (
    "隔离 v9 的唯一 build 与唯一 up 均 GREEN",
    "v9 topology GREEN",
    "containers=2",
    "networks=3",
    "app=172.16.233.0/24 internal=true endpoints=1",
    "data=172.16.234.0/24 internal=true endpoints=2",
    "dev-egress=172.16.235.0/24 internal=false endpoints=1",
    "named/project-labeled volumes=6",
    "actual volume mounts=6",
    "anonymous volumes=0",
    "host port bindings=0",
    "privileged=0",
    "db parent `/var/lib/postgresql` 是 tmpfs",
    "child `/var/lib/postgresql/data` 是 named volume",
    "`sh: 7: 7: parameter not set`",
    "post-create=0",
    "MVP/Platform/Web locked tests=0",
    "候选不是 RED",
    "保持 running",
    "不得重试、stop、down、rm 或 prune",
    "v9 占用导致 172.16.233.0/24、172.16.234.0/24、172.16.235.0/24 均被阻断",
)
DEVCONTAINER_V10_PREBUILD_EVIDENCE = (
    "隔离 v10 的动态 preflight 全部 GREEN",
    "V8 operator wrapper",
    '`" Dockerfile".trim():`',
    "`SyntaxError: Unexpected token '.'`",
    "`0.0s`",
    "`nested exec=0`",
    "`candidate rehash=0`",
    "`build=0`、`up=0`",
    "project/network/volume/tag 仍全部 absent",
    "候选未被证伪",
    "不得复用 v10",
)
DEVCONTAINER_V11_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v11"
)
DEVCONTAINER_V11_IMAGE_TAG = "devcontainer-audit-20260824-v11"
DEVCONTAINER_V11_RED_EVIDENCE = (
    "隔离 v11 的唯一 build 与唯一 up 均 GREEN",
    "v11 topology GREEN",
    "runtime smoke GREEN",
    "post-create GREEN",
    "MVP locked tests 134/134 GREEN",
    "Platform locked tests 1072",
    "1 failure + 16 errors",
    "IAM_0024_TEST_PYTHON_UNAVAILABLE",
    "Web tests/typecheck/lint=0",
    "v11 动态 RED",
    "不得复用 v11",
)
DEVCONTAINER_V12_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v12"
)
DEVCONTAINER_V12_IMAGE_TAG = "devcontainer-audit-20260824-v12"
DEVCONTAINER_V12_PREBUILD_EVIDENCE = (
    "host preflight 只完成 hashes/static/initialize/secret stat",
    "这些已执行项全部 GREEN",
    "CIDR/route enumeration=0",
    "generic symlink check",
    "macOS 上不存在",
    "`/usr/bin/test`",
    "exit 127",
    "读取任何文件内容之前",
    "错误前 Docker command=0",
    "随后只执行 read-only preservation audit",
    "`build=0`、`up=0`、`Docker mutation=0`",
    "v12 project/network/volume/tag 全部 absent",
    "v11 保持 untouched",
    "operator harness-invalid",
    "不得重试或复用 v12",
)
DEVCONTAINER_V13_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v13"
)
DEVCONTAINER_V13_IMAGE_TAG = "devcontainer-audit-20260824-v13"
DEVCONTAINER_V13_DYNAMIC_EVIDENCE = (
    "隔离 v13 的唯一 build 与唯一 up 均 GREEN",
    "v13 topology GREEN",
    "v13 containers=2",
    "v13 networks=3",
    "app=172.16.242.0/24 internal=true endpoints=1",
    "data=172.16.243.0/24 internal=true endpoints=2",
    "dev-egress=172.16.244.0/24 internal=false endpoints=1",
    "v13 named/project-labeled volumes=6",
    "v13 actual volume mounts=6",
    "v13 anonymous volumes=0",
    "v13 host port bindings=0",
    "v13 privileged=0",
    "runtime smoke #1-#4 exit 0",
    "PyPI smoke #5",
    "exit 28",
    "20s",
    "11,463,474/45,294,663 bytes",
    "GET `/simple/`",
    "完整 large index",
    "smoke #6 execution=0",
    "post-create/toolchain/MVP/Platform/Web execution=0",
    "v13 保持 running/locked",
    "v13 不得重试、stop、down、rm 或 prune",
)
DEVCONTAINER_V14_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v14"
)
DEVCONTAINER_V14_IMAGE_TAG = "devcontainer-audit-20260824-v14"
DEVCONTAINER_V14_RED_EVIDENCE = (
    "隔离 v14 的 fresh preflight、唯一 build、唯一 up",
    "v14 topology GREEN",
    "六项 runtime smoke",
    "唯一 post-create、工具链与 MVP locked tests",
    "134/134 均 GREEN",
    "Ran 1091 tests in 157.827s",
    "14 errors、0 failures",
    "7 个 setup",
    "MigrationConnectionLost",
    "3 个同类 setup error",
    "4 个 `taxonomy_migration_runner` password authentication error",
    "Web tests/typecheck/lint=0",
    "fixed roles 跨 test database",
    "VALID UNTIL '9999-01-01 00:00:00+00'",
    "所有时区偏移下仍可被 psycopg",
    "21/21 外部 harness 回归",
    "PostgreSQL 18/18",
    "online credentials 3/3",
    "session-drain contract 2/2",
    "v14 已按一次性规则锁定",
    "172.16.245.0/24",
    "172.16.246.0/24",
    "172.16.247.0/24",
    "保持 running",
    "不得重试、stop",
    "down、rm、prune 或补跑 Web",
)
DEVCONTAINER_V15_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v15"
)
DEVCONTAINER_V15_IMAGE_TAG = "devcontainer-audit-20260824-v15"
DEVCONTAINER_V15_RED_EVIDENCE = (
    "隔离 v15 的 fresh preflight、唯一",
    "v15 topology GREEN",
    "2 containers、3 networks",
    "6 个 named/project-labeled volumes",
    "6 个 actual volume mounts",
    "0 anonymous volumes",
    "0 host port bindings",
    "0 privileged",
    "app=172.16.248.0/24 internal=true endpoints=1",
    "data=172.16.249.0/24 internal=true endpoints=2",
    "dev-egress=172.16.250.0/24 internal=false endpoints=1",
    "六项 runtime smoke",
    "Ran 134 tests in 2.075s",
    "Ran 1096 tests in 176.405s",
    "Web `70/70`",
    "typecheck 与 lint 全部 GREEN",
    "for DESIRE_DEV_AUDIT_ID in $DESIRE_DEV_AUDIT_IDS",
    "zsh",
    "no such object",
    "down execution=0",
    "v15 cleanup RED",
    "保持 running/locked",
    "不得重试、stop、down、rm 或 prune",
)
DEVCONTAINER_V16_PROJECT = (
    "desire-supply-devcontainer-audit-20260824-v16"
)
DEVCONTAINER_V16_IMAGE_TAG = "devcontainer-audit-20260824-v16"
DEVCONTAINER_V16_PROJECT_GUARD = (
    'test "${DESIRE_DEV_AUDIT_PROJECT:-}" = '
    '"desire-supply-devcontainer-audit-20260824-v16"'
)
DEVCONTAINER_V16_IMAGE_GUARD = (
    'test "${DESIRE_IMAGE_TAG:-}" = "devcontainer-audit-20260824-v16"'
)
DEVCONTAINER_V16_SUBNET_EXPORTS = (
    'export DESIRE_DEVCONTAINER_APP_SUBNET="172.16.251.0/24"',
    'export DESIRE_DEVCONTAINER_DATA_SUBNET="172.16.252.0/24"',
    'export DESIRE_DEVCONTAINER_EGRESS_SUBNET="172.16.253.0/24"',
)
DEVCONTAINER_V16_DIRECT_MARKERS = (
    "禁止任何自制 JavaScript、V8 或组合 wrapper",
    "逐条直接执行审定命令",
    "逐项记录退出码",
    "唯一 post-create 若非零，也必须立即锁定 v16",
    "禁止执行工具链和后续测试",
    "build 或 up 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。",
    "六项 runtime smoke 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。",
    "分成六条直接命令",
    "任一失败就立即锁定 v16",
    "v16 必须重新完成 fresh preflight",
    "HEAD 只证明轻量 DNS/TLS/HTTP availability",
    "HTTP 200、redirects=0、size_download=0",
    "真实 GET/package body/CDN",
)
DEVCONTAINER_V16_BUILD_COMMAND = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml build devcontainer"
)
DEVCONTAINER_V16_UP_COMMAND = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml "
    "up -d --wait --wait-timeout 120 db devcontainer"
)
DEVCONTAINER_PASSWD_SHELL_CHECK = (
    'test "$(getent passwd node | cut -d: -f7)" = "/bin/bash"'
)
DEVCONTAINER_PASSWD_SHELL_SMOKE = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer sh -lc "
    "'test \"$(getent passwd node | cut -d: -f7)\" = \"/bin/bash\"'"
)
DEVCONTAINER_DATABASE_DNS_SMOKE = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer "
    "getent ahostsv4 db"
)
DEVCONTAINER_DATABASE_READY_SMOKE = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer "
    "pg_isready -h db -p 5432"
)
DEVCONTAINER_PORTABLE_HOST_METADATA_CHECK = (
    "test ! -L secrets/db_superuser_password.txt"
)
DEVCONTAINER_REGULAR_HOST_METADATA_CHECK = (
    "test -f secrets/db_superuser_password.txt"
)
DEVCONTAINER_V16_POST_CREATE_COMMAND = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer sh -lc "
    "'cd /workspace/mvp && uv sync --locked && "
    "/usr/local/bin/desire-devcontainer-post-create'"
)
DEVCONTAINER_TMP_EXEC_SMOKE = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml "
    "exec -T devcontainer sh -lc "
    "'install -m 0700 /bin/true /tmp/desire-devcontainer-tmp-exec-check "
    "&& \"/tmp/desire-devcontainer-tmp-exec-check\"'"
)
DEVCONTAINER_REGISTRY_HEAD_SMOKES = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer "
    "curl --head --fail --silent --show-error --location "
    "--proto '=https' --proto-redir '=https' "
    "--max-time 20 --output /dev/null https://pypi.org/simple/",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer "
    "curl --head --fail --silent --show-error --location "
    "--proto '=https' --proto-redir '=https' "
    "--max-time 20 --output /dev/null https://registry.npmjs.org/",
)
DEVCONTAINER_V16_TEST_COMMANDS = (
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T devcontainer "
    "/usr/local/bin/desire-devcontainer-toolchain-check",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T -w /workspace/mvp "
    "devcontainer uv run --offline --locked python -m unittest "
    "discover -s tests -v",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T "
    "-e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=src "
    "-w /workspace/platform devcontainer uv run --offline --locked "
    "--extra test --extra server python -m unittest discover -s tests "
    "-t . -v",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T -w /workspace/web "
    "devcontainer npm test",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T -w /workspace/web "
    "devcontainer npm run typecheck",
    'docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" '
    "-f compose.yaml -f compose.dev.yaml exec -T -w /workspace/web "
    "devcontainer npm run lint",
)
DEVCONTAINER_V16_EXECUTION_SEQUENCE = (
    DEVCONTAINER_V16_BUILD_COMMAND,
    DEVCONTAINER_V16_UP_COMMAND,
    DEVCONTAINER_PASSWD_SHELL_SMOKE,
    DEVCONTAINER_TMP_EXEC_SMOKE,
    DEVCONTAINER_DATABASE_DNS_SMOKE,
    DEVCONTAINER_DATABASE_READY_SMOKE,
    *DEVCONTAINER_REGISTRY_HEAD_SMOKES,
    DEVCONTAINER_V16_POST_CREATE_COMMAND,
    *DEVCONTAINER_V16_TEST_COMMANDS,
)
DEVCONTAINER_V16_FRESH_COMMANDS = (
    f'export DESIRE_DEV_AUDIT_PROJECT="{DEVCONTAINER_V16_PROJECT}"',
    f'export DESIRE_IMAGE_TAG="{DEVCONTAINER_V16_IMAGE_TAG}"',
    *DEVCONTAINER_V16_SUBNET_EXPORTS,
    DEVCONTAINER_V16_PROJECT_GUARD,
    DEVCONTAINER_V16_IMAGE_GUARD,
    DEVCONTAINER_PORTABLE_HOST_METADATA_CHECK,
    DEVCONTAINER_REGULAR_HOST_METADATA_CHECK,
    *DEVCONTAINER_V16_EXECUTION_SEQUENCE,
    DEVCONTAINER_V16_PROJECT_GUARD,
    DEVCONTAINER_AUDIT_PS,
    DEVCONTAINER_AUDIT_COUNT,
    'DESIRE_DEV_AUDIT_DB_ID="$(docker compose --project-name '
    '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml ps -q db)"',
    'test -n "$DESIRE_DEV_AUDIT_DB_ID"',
    'DESIRE_DEV_AUDIT_DEVCONTAINER_ID="$(docker compose --project-name '
    '"$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml '
    'ps -q devcontainer)"',
    'test -n "$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"',
    'test "$DESIRE_DEV_AUDIT_DB_ID" != '
    '"$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"',
    'test "$(docker inspect --format \'{{ index .Config.Labels '
    '"com.docker.compose.project" }}\' "$DESIRE_DEV_AUDIT_DB_ID")" = '
    '"$DESIRE_DEV_AUDIT_PROJECT"',
    'test "$(docker inspect --format \'{{ index .Config.Labels '
    '"com.docker.compose.project" }}\' '
    '"$DESIRE_DEV_AUDIT_DEVCONTAINER_ID")" = '
    '"$DESIRE_DEV_AUDIT_PROJECT"',
    "unset DESIRE_DEV_AUDIT_DB_ID DESIRE_DEV_AUDIT_DEVCONTAINER_ID",
    DEVCONTAINER_AUDIT_DOWN,
    "unset DESIRE_DEV_AUDIT_PROJECT",
)
DEVCONTAINER_IPAM_SUBNETS = {
    "app": (
        "${DESIRE_DEVCONTAINER_APP_SUBNET:-172.16.221.0/24}",
        "172.16.221.0/24",
    ),
    "data": (
        "${DESIRE_DEVCONTAINER_DATA_SUBNET:-172.16.222.0/24}",
        "172.16.222.0/24",
    ),
    "dev-egress": (
        "${DESIRE_DEVCONTAINER_EGRESS_SUBNET:-172.16.223.0/24}",
        "172.16.223.0/24",
    ),
}
DEVCONTAINER_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DEVCONTAINER_TOOLCHAIN_LABELS = (
    "BLOCKED:DEVCONTAINER_PYTHON_VERSION",
    "BLOCKED:DEVCONTAINER_PYTHON_IMPORT",
    "BLOCKED:DEVCONTAINER_NODE_VERSION",
    "BLOCKED:DEVCONTAINER_NPM_VERSION",
    "BLOCKED:DEVCONTAINER_NPM_HELP",
    "BLOCKED:DEVCONTAINER_NPM_CACHE",
    "BLOCKED:DEVCONTAINER_PSQL_VERSION",
    "BLOCKED:DEVCONTAINER_PG_DUMP_VERSION",
    "BLOCKED:DEVCONTAINER_PG_RESTORE_VERSION",
    "BLOCKED:DEVCONTAINER_UV_VERSION",
    "BLOCKED:DEVCONTAINER_UID",
    "BLOCKED:DEVCONTAINER_USERNAME",
    "BLOCKED:DEVCONTAINER_SHELL",
    "BLOCKED:DEVCONTAINER_SUDO",
    "BLOCKED:DEVCONTAINER_HOME",
    "BLOCKED:DEVCONTAINER_DEPENDENCY_ROOT",
)
DEPLOYMENT_SERVICES = (
    "migrate",
    "taxonomy-seed",
    "online-credentials-reconcile",
    "online-credentials-verify",
    "identity-bootstrap",
)
API_SECRETS = (
    "db-iam-app-v1",
    "db-iam-session-authenticator-v1",
    "db-iam-onboarding-v1",
    "db-profile-app-v1",
    "db-demand-self-v1",
    "db-demand-review-v1",
    "db-demand-finance-v1",
    "db-trust-self-v1",
    "db-trust-officer-v1",
    "db-trust-appeal-v1",
    "db-trust-decision-v1",
    "db-matching-creator-v1",
    "db-matching-selector-v1",
    "db-matching-assignment-v1",
    "db-matching-review-v1",
    "key-oidc-state-v1",
    "key-oidc-browser-binding-v1",
    "key-oidc-nonce-v1",
    "key-session-handle-v1",
    "key-csrf-v1",
    "key-oidc-protocol-aead-v1",
    "key-oidc-subject-digest-v1",
    "key-oidc-recipient-binding-v1",
    "key-oidc-client-secret-v1",
    "key-editor-id-derivation-v1",
    "key-profile-idempotency-v1",
    "key-profile-payload-hash-v1",
    "key-demand-idempotency-v1",
    "key-demand-idempotency-retained-2025-12",
    "key-demand-payload-hash-v1",
    "key-demand-payload-retained-2025-12",
    "key-demand-client-reference-v1",
    "key-iam-receipt-idempotency-hmac-2026-01",
    "key-iam-receipt-payload-hmac-2026-01",
    "key-access-invitation-token-v1",
    "key-iam-read-cursor-v1",
    "key-trust-idempotency-v1",
    "key-trust-payload-hash-v1",
    "key-trust-sealed-note-v1",
    "key-trust-report-cursor-v1",
    "key-matching-idempotency-v1",
    "key-matching-payload-v1",
    "key-matching-read-cursor-v1",
)
MATCHING_RUNTIME_SECRETS = (
    "db-demand-matching-v1",
    "db-profile-matcher-v1",
    "db-trust-decision-v1",
    "db-matching-worker-v1",
    "db-matching-coordinator-v1",
    "key-matching-worker-idempotency-v1",
    "key-matching-worker-payload-hash-v1",
    "key-matching-worker-lease-digest-v1",
    "key-matching-coordinator-idempotency-v1",
    "key-matching-coordinator-payload-hash-v1",
    "key-matching-coordinator-lease-digest-v1",
)
ONLINE_SECRETS = API_SECRETS + tuple(
    name for name in MATCHING_RUNTIME_SECRETS if name not in API_SECRETS
)
ONLINE_DATABASE_SECRETS = (
    "db_superuser_password",
    *(name for name in ONLINE_SECRETS if name.startswith("db-")),
)
IDENTITY_BOOTSTRAP_SECRETS = (
    "db_superuser_password",
    "key-oidc-subject-digest-v1",
    "key-oidc-recipient-binding-v1",
)
RUNTIME_CONFIG_TARGETS = (
    "/run/desire/deployment.json",
    "/run/desire/runtime-config.json",
    "/run/desire/secret-manifest.json",
)
MATCHING_RUNTIME_CONFIG_TARGETS = (
    "/run/desire/matching-deployment.json",
    "/run/desire/matching-runtime-config.json",
    "/run/desire/matching-secret-manifest.json",
)
ONLINE_CREDENTIAL_CONFIG_TARGETS = (
    "/run/desire/online-credentials-deployment.json",
    "/run/desire/online-credentials-runtime-config.json",
    "/run/desire/online-credentials-secret-manifest.json",
)
API_CONFIG_TARGETS = RUNTIME_CONFIG_TARGETS + (
    "/run/desire-tls/root-ca.pem",
)
SYNTHETIC_OIDC_ENVIRONMENT = {
    "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
    "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
    "DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE": (
        "/run/secrets/key-oidc-client-secret-v1"
    ),
}
IDENTITY_ACCOUNT_CODES = (
    "access_admin_01",
    "appeal_reviewer_01",
    "creator_01",
    "demand_owner_01",
    "finance_operator_01",
    "finance_operator_02",
    "operations_reviewer_01",
    "org_admin_01",
    "trust_officer_01",
    "trust_officer_02",
)


def _secret_sources(service: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        item.get("source", "")
        for item in service.get("secrets", [])
        if isinstance(item, dict)
    )


def _secret_targets(service: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        item.get("target", "")
        for item in service.get("secrets", [])
        if isinstance(item, dict)
    )


def _config_targets(service: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        item.get("target", "")
        for item in service.get("configs", [])
        if isinstance(item, dict)
    )


def _volume_mount(service: dict[str, Any], target: str) -> dict[str, Any]:
    for item in service.get("volumes", []):
        if isinstance(item, dict) and item.get("target") == target:
            return item
    return {}


def _bash_commands(markdown: str) -> tuple[str, ...]:
    commands: list[str] = []
    current = ""
    in_bash = False
    for raw_line in markdown.splitlines():
        stripped = raw_line.strip()
        if stripped == "```bash":
            in_bash = True
            current = ""
            continue
        if stripped == "```" and in_bash:
            if current:
                commands.append(current.strip())
            in_bash = False
            current = ""
            continue
        if not in_bash or not stripped:
            continue
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
        else:
            commands.append(current)
            current = ""
    return tuple(commands)


def _exact_bash_function(
    section: str,
    name: str,
    expected_command: str,
) -> bool:
    """Return whether a shell function occurs once with one exact command."""

    opener = f"{name}() {{"
    if section.count(opener) != 1:
        return False
    body, separator, _ = section.partition(opener)[2].partition("\n}")
    if not separator:
        return False
    commands = _bash_commands(f"```bash\n{opener}{body}\n}}\n```")
    return commands == (opener, expected_command, "}")


def _bash_function_commands(
    section: str,
    name: str,
) -> tuple[str, ...] | None:
    """Extract commands from one exact ``name() { ... }`` shell function."""

    opener = f"{name}() {{"
    if section.count(opener) != 1:
        return None
    body, separator, _ = section.partition(opener)[2].partition("\n}")
    if not separator:
        return None
    commands = _bash_commands(f"```bash\n{opener}{body}\n}}\n```")
    if len(commands) < 2 or commands[0] != opener or commands[-1] != "}":
        return None
    return commands[1:-1]


def _has_unexpected_shell_hash(
    section: str,
    *,
    allowed_lines: tuple[str, ...] = (),
) -> bool:
    """Reject commented-out proof commands while allowing fixed markers."""

    allowed = set(allowed_lines)
    return any(
        "#" in line and line.strip() not in allowed
        for line in section.splitlines()
    )


def _current_head_v13_protocol_digest_matches(runbook: str) -> bool:
    """Pin the six reviewed one-shot protocol blocks byte-for-byte."""

    marker_pairs = (
        (
            CURRENT_HEAD_V13_FRESH_RUNBOOK_START,
            CURRENT_HEAD_V13_FRESH_RUNBOOK_END,
        ),
        (
            CURRENT_HEAD_V13_JOURNEY_RESTART_START,
            CURRENT_HEAD_V13_JOURNEY_RESTART_END,
        ),
        (
            "# BEGIN CURRENT_HEAD_V13_BACKUP",
            "# END CURRENT_HEAD_V13_BACKUP",
        ),
        (
            CURRENT_HEAD_RESTORE_PREFLIGHT_START,
            CURRENT_HEAD_RESTORE_PREFLIGHT_END,
        ),
        (
            CURRENT_HEAD_RESTORE_EXECUTION_START,
            CURRENT_HEAD_RESTORE_EXECUTION_END,
        ),
        (
            CURRENT_HEAD_RESTORE_POSTRUN_START,
            CURRENT_HEAD_RESTORE_POSTRUN_END,
        ),
    )
    lines = runbook.splitlines(keepends=True)
    blocks: list[str] = []
    previous_end = -1
    for start, end in marker_pairs:
        starts = tuple(
            index for index, line in enumerate(lines) if line.rstrip("\r\n") == start
        )
        ends = tuple(
            index for index, line in enumerate(lines) if line.rstrip("\r\n") == end
        )
        if (
            len(starts) != 1
            or len(ends) != 1
            or starts[0] <= previous_end
            or ends[0] < starts[0]
        ):
            return False
        blocks.append("".join(lines[starts[0] : ends[0] + 1]))
        previous_end = ends[0]
    return (
        hashlib.sha256("".join(blocks).encode("utf-8")).hexdigest()
        == CURRENT_HEAD_V13_PROTOCOL_SHA256
    )


def _devcontainer_docs_failures(document: str) -> tuple[str, ...]:
    failures: list[str] = []
    if "desire-supply-e2e-six-role" in document:
        failures.append("devcontainer-docs-legacy-project-name")
    commands = _bash_commands(document)
    if any(commands.count(command) != 1 for command in DEVCONTAINER_DAILY_COMMANDS):
        failures.append("devcontainer-docs-daily-stop-open")
    daily_commands = tuple(
        command
        for command in commands
        if "compose.dev.yaml" in command
        and any(
            re.search(rf"(?:^|\s){verb}(?:\s|$)", command)
            for verb in ("up", "exec", "stop")
        )
        and "DESIRE_DEV_AUDIT_PROJECT" not in command
    )
    if (
        daily_commands != DEVCONTAINER_DAILY_COMMANDS
        or "COMPOSE_PROJECT_NAME" not in document
        or '--project-name "${COMPOSE_PROJECT_NAME}"' in document
        or "--project-name $COMPOSE_PROJECT_NAME" in document
    ):
        failures.append("devcontainer-docs-daily-project-open")
    down_commands = tuple(
        command
        for command in commands
        if command.startswith("docker compose ")
        and re.search(r"(?:^|\s)down(?:\s|$)", command)
    )
    audit_guards = (
        DEVCONTAINER_AUDIT_PS,
        DEVCONTAINER_AUDIT_COUNT,
        DEVCONTAINER_V16_PROJECT_GUARD,
        'index .Config.Labels "com.docker.compose.project"',
        'test -n "$DESIRE_DEV_AUDIT_DB_ID"',
        'test -n "$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"',
        'test "$DESIRE_DEV_AUDIT_DB_ID" != '
        '"$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"',
    )
    if (
        down_commands != (DEVCONTAINER_AUDIT_DOWN,)
        or any(guard not in document for guard in audit_guards)
        or document.count(DEVCONTAINER_V16_PROJECT_GUARD) != 2
        or 'case "${DESIRE_DEV_AUDIT_PROJECT:-}" in' in document
    ):
        failures.append("devcontainer-docs-unscoped-destroy")
    ipam_markers = (
        "DESIRE_DEVCONTAINER_APP_SUBNET",
        "DESIRE_DEVCONTAINER_DATA_SUBNET",
        "DESIRE_DEVCONTAINER_EGRESS_SUBNET",
        "172.16.221.0/24",
        "172.16.222.0/24",
        "172.16.223.0/24",
        "全部 Docker CIDR",
        "宿主直连路由",
        "更具体路由",
        "全隧道 VPN",
        "desire-supply-devcontainer-audit-20260819-v6",
        "desire-supply-devcontainer-audit-20260819-v7",
        "desire-supply-devcontainer-audit-20260819-v8",
        "desire-supply-devcontainer-audit-20260824-v9",
        "隔离 v4 的唯一 build 已 GREEN",
        "唯一 up",
        "0 containers、0 volumes、2 networks",
        "隔离 v5 的唯一 build 与唯一 up 均 GREEN",
        "组合 smoke",
        "非合同变量未设置",
        "post-create 与三面 locked tests 均未",
        "2 containers、3 networks 与",
        "6 volumes",
        "隔离 v6 的唯一 build 与唯一 up 均 GREEN",
        "额外恰好 1 个 anonymous local volume",
        "db target `/var/lib/postgresql`",
        "post-create 与 MVP/Platform/Web tests 均为 0",
        "v6 topology RED",
        "v7 source/static 20/20",
        "`compose config --quiet` 精确 exit 0",
        "top-level rendered JSON network keys",
        "`app`、`data`、`dev-egress`",
        'project-specific 名称只在各 network 的 `name` 字段',
        "exit 1，且发生在 build 之前",
        "project/network/volume/tag 全部 absent",
        "build=0、up=0",
        "候选未被证伪",
        "不得重跑 v7",
        "`/var/lib/postgresql/data`",
        "`PGDATA=/var/lib/postgresql/data/pgdata`",
        "匿名 parent volume",
        "172.16.224.0/24",
        "172.16.225.0/24",
        "172.16.226.0/24",
        "172.16.233.0/24",
        "172.16.234.0/24",
        "172.16.235.0/24",
        'DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v7"',
        'DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v8"',
        'DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v9"',
        "v8 的只读宿主",
        "128.0.0.0/1",
        "v8 project/network/volume/tag 全部 absent",
        "Linux VM 内",
        "LAN/direct CIDR 重叠",
        "只记录 caveat",
        "创建后端到端网络验证",
        "pg_isready -h db -p 5432",
        "https://pypi.org/simple/",
        "https://registry.npmjs.org/",
        "不是跨宿主机通用保证",
        "BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME",
    )
    if any(marker not in document for marker in ipam_markers):
        failures.append("devcontainer-docs-ipam-preflight-open")
    if any(marker not in document for marker in DEVCONTAINER_V9_EVIDENCE):
        failures.append("devcontainer-docs-v9-evidence-open")
    if any(
        marker not in document
        for marker in DEVCONTAINER_V10_PREBUILD_EVIDENCE
    ):
        failures.append("devcontainer-docs-v10-prebuild-evidence-open")
    if (
        any(marker not in document for marker in DEVCONTAINER_V11_RED_EVIDENCE)
        or DEVCONTAINER_V11_PROJECT not in document
        or DEVCONTAINER_V11_IMAGE_TAG not in document
    ):
        failures.append("devcontainer-docs-v11-red-evidence-open")
    if (
        any(
            marker not in document
            for marker in DEVCONTAINER_V12_PREBUILD_EVIDENCE
        )
        or DEVCONTAINER_V12_PROJECT not in document
        or DEVCONTAINER_V12_IMAGE_TAG not in document
    ):
        failures.append("devcontainer-docs-v12-prebuild-evidence-open")
    if (
        any(
            marker not in document
            for marker in DEVCONTAINER_V13_DYNAMIC_EVIDENCE
        )
        or DEVCONTAINER_V13_PROJECT not in document
        or DEVCONTAINER_V13_IMAGE_TAG not in document
    ):
        failures.append("devcontainer-docs-v13-dynamic-evidence-open")
    v14_evidence_heading = "隔离 v14 的 fresh preflight、唯一 build、唯一 up"
    v14_evidence_section = document.partition(v14_evidence_heading)[2].partition(
        "隔离 v15 的 fresh preflight、唯一"
    )[0]
    if (
        document.count(v14_evidence_heading) != 1
        or any(
            marker not in v14_evidence_section
            for marker in DEVCONTAINER_V14_RED_EVIDENCE[1:]
        )
        or DEVCONTAINER_V14_PROJECT not in v14_evidence_section
        or DEVCONTAINER_V14_IMAGE_TAG not in v14_evidence_section
    ):
        failures.append("devcontainer-docs-v14-red-evidence-open")
    v15_evidence_heading = "隔离 v15 的 fresh preflight、唯一"
    v15_evidence_section = document.partition(v15_evidence_heading)[2].partition(
        "## 不使用编辑器时"
    )[0]
    if (
        document.count(v15_evidence_heading) != 1
        or any(
            marker not in v15_evidence_section
            for marker in DEVCONTAINER_V15_RED_EVIDENCE[1:]
        )
        or DEVCONTAINER_V15_PROJECT not in v15_evidence_section
        or DEVCONTAINER_V15_IMAGE_TAG not in v15_evidence_section
    ):
        failures.append("devcontainer-docs-v15-red-evidence-open")
    fresh_heading = "## Fresh project 动态验收"
    heading_count = document.count(fresh_heading)
    fresh_section = document.partition(fresh_heading)[2]
    fresh_commands = _bash_commands(fresh_section)
    fresh_coordinate_contract = (
        f'export DESIRE_DEV_AUDIT_PROJECT="{DEVCONTAINER_V16_PROJECT}"',
        f'export DESIRE_IMAGE_TAG="{DEVCONTAINER_V16_IMAGE_TAG}"',
        *DEVCONTAINER_V16_SUBNET_EXPORTS,
    )
    fresh_coordinate_variables = (
        "DESIRE_DEV_AUDIT_PROJECT",
        "DESIRE_IMAGE_TAG",
        "DESIRE_DEVCONTAINER_APP_SUBNET",
        "DESIRE_DEVCONTAINER_DATA_SUBNET",
        "DESIRE_DEVCONTAINER_EGRESS_SUBNET",
    )
    fresh_coordinate_lines = {
        variable: tuple(
            line.strip()
            for line in fresh_section.splitlines()
            if re.match(
                rf"^(?:export )?{re.escape(variable)}=",
                line.strip(),
            )
        )
        for variable in fresh_coordinate_variables
    }
    if (
        heading_count != 1
        or any(
            fresh_section.count(fragment) != 1
            for fragment in fresh_coordinate_contract
        )
        or f'export DESIRE_DEV_AUDIT_PROJECT="{DEVCONTAINER_V14_PROJECT}"'
        in fresh_section
        or f'export DESIRE_IMAGE_TAG="{DEVCONTAINER_V14_IMAGE_TAG}"'
        in fresh_section
        or f'export DESIRE_DEV_AUDIT_PROJECT="{DEVCONTAINER_V15_PROJECT}"'
        in fresh_section
        or f'export DESIRE_IMAGE_TAG="{DEVCONTAINER_V15_IMAGE_TAG}"'
        in fresh_section
        or any(
            f'="172.16.{suffix}.0/24"' in fresh_section
            for suffix in (
                233,
                234,
                235,
                236,
                237,
                238,
                239,
                240,
                241,
                242,
                243,
                244,
                245,
                246,
                247,
                248,
                249,
                250,
            )
        )
        or fresh_section.count(DEVCONTAINER_V16_PROJECT_GUARD) != 2
        or fresh_section.count(DEVCONTAINER_V16_IMAGE_GUARD) != 1
        or any(
            fresh_coordinate_lines[variable] != (expected,)
            for variable, expected in zip(
                fresh_coordinate_variables,
                fresh_coordinate_contract,
            )
        )
    ):
        failures.append("devcontainer-docs-v16-coordinate-open")
    execution_positions = tuple(
        fresh_commands.index(command)
        for command in DEVCONTAINER_V16_EXECUTION_SEQUENCE
        if fresh_commands.count(command) == 1
    )
    if (
        any(marker not in fresh_section for marker in DEVCONTAINER_V16_DIRECT_MARKERS)
        or fresh_commands != DEVCONTAINER_V16_FRESH_COMMANDS
        or len(fresh_commands) != 37
        or fresh_commands.count(DEVCONTAINER_V16_BUILD_COMMAND) != 1
        or fresh_commands.count(DEVCONTAINER_V16_UP_COMMAND) != 1
        or any(
            fresh_commands.count(command) != 1
            for command in DEVCONTAINER_V16_TEST_COMMANDS
        )
        or fresh_commands.count(DEVCONTAINER_V16_POST_CREATE_COMMAND) != 1
        or any(
            fresh_commands.count(command) != 1
            for command in DEVCONTAINER_V16_EXECUTION_SEQUENCE
        )
        or len(execution_positions) != len(DEVCONTAINER_V16_EXECUTION_SEQUENCE)
        or execution_positions != tuple(sorted(execution_positions))
        or fresh_section.count("docker compose ") != 20
        or fresh_section.count("sh -lc") != 3
        or any(
            fragment in fresh_section
            for fragment in (
                "functions.exec",
                "tools.exec_command",
                "Promise.all",
                "node -e",
                "python3 -c",
                "bash -lc",
                "zsh -lc",
                "eval ",
                "DESIRE_DEV_AUDIT_IDS",
                "for DESIRE_DEV_AUDIT_ID",
                "ps -aq",
                "xargs",
                "IFS=",
            )
        )
    ):
        failures.append("devcontainer-docs-v16-direct-execution-open")
    if (
        fresh_commands.count(DEVCONTAINER_PORTABLE_HOST_METADATA_CHECK) != 1
        or fresh_commands.count(DEVCONTAINER_REGULAR_HOST_METADATA_CHECK) != 1
        or "/usr/bin/test" in fresh_section
    ):
        failures.append("devcontainer-docs-v16-host-metadata-open")
    if (
        heading_count != 1
        or fresh_section.count(DEVCONTAINER_PASSWD_SHELL_CHECK) != 1
        or fresh_commands.count(DEVCONTAINER_TMP_EXEC_SMOKE) != 1
        or any(
            fresh_commands.count(command) != 1
            for command in DEVCONTAINER_REGISTRY_HEAD_SMOKES
        )
        or any(fragment in fresh_section for fragment in ("awk", "$7", "$SHELL"))
    ):
        failures.append("devcontainer-docs-v16-runtime-smoke-open")
    return tuple(failures)


def _devcontainer_ipam_failures(
    compose_overlay: str,
    development: dict[str, Any],
) -> tuple[str, ...]:
    failures: list[str] = []
    raw_contract_open = "gateway:" in compose_overlay
    for expression, _default in DEVCONTAINER_IPAM_SUBNETS.values():
        if compose_overlay.count(f"subnet: {expression}") != 1:
            raw_contract_open = True
    if raw_contract_open:
        failures.append("devcontainer-ipam-contract-open")

    networks = development.get("networks", {})
    if not isinstance(networks, dict):
        return tuple(
            failures
            + [
                "devcontainer-ipam-subnet-invalid:app",
                "devcontainer-ipam-subnet-invalid:data",
                "devcontainer-ipam-subnet-invalid:dev-egress",
                "devcontainer-ipam-network-boundary-open",
            ]
        )
    parsed_subnets: list[ipaddress.IPv4Network] = []
    boundary_open = False
    for name in DEVCONTAINER_IPAM_SUBNETS:
        network = networks.get(name, {})
        if not isinstance(network, dict):
            failures.append(f"devcontainer-ipam-subnet-invalid:{name}")
            boundary_open = True
            continue
        expected_internal = name in {"app", "data"}
        if bool(network.get("internal", False)) is not expected_internal:
            boundary_open = True
        ipam = network.get("ipam", {})
        config = ipam.get("config", []) if isinstance(ipam, dict) else []
        if (
            not isinstance(config, list)
            or len(config) != 1
            or not isinstance(config[0], dict)
            or "gateway" in config[0]
        ):
            failures.append(f"devcontainer-ipam-subnet-invalid:{name}")
            continue
        try:
            subnet = ipaddress.ip_network(config[0].get("subnet", ""), strict=True)
        except (TypeError, ValueError):
            failures.append(f"devcontainer-ipam-subnet-invalid:{name}")
            continue
        if (
            not isinstance(subnet, ipaddress.IPv4Network)
            or subnet.prefixlen != 24
            or not any(
                subnet.subnet_of(private_network)
                for private_network in DEVCONTAINER_RFC1918_NETWORKS
            )
        ):
            failures.append(f"devcontainer-ipam-subnet-invalid:{name}")
            continue
        parsed_subnets.append(subnet)
    if boundary_open:
        failures.append("devcontainer-ipam-network-boundary-open")
    if len(parsed_subnets) == len(DEVCONTAINER_IPAM_SUBNETS) and any(
        left.overlaps(right)
        for index, left in enumerate(parsed_subnets)
        for right in parsed_subnets[index + 1 :]
    ):
        failures.append("devcontainer-ipam-subnets-overlap")
    return tuple(failures)


def _devcontainer_host_route_preflight(
    candidate_cidrs: tuple[str, ...],
    *,
    docker_cidrs: tuple[str, ...],
    lan_direct_cidrs: tuple[str, ...],
    host_vpn_routes: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Classify host evidence without treating broad VPN routes as VM bridges."""

    blocked: list[str] = []
    caveats: list[str] = []

    def record_once(target: list[str], finding: str) -> None:
        if finding not in target:
            target.append(finding)

    parsed_candidates: list[tuple[str, ipaddress.IPv4Network]] = []
    for raw_candidate in candidate_cidrs:
        try:
            candidate = ipaddress.ip_network(raw_candidate, strict=True)
        except (TypeError, ValueError):
            record_once(blocked, "devcontainer-host-route-candidate-invalid")
            continue
        if (
            not isinstance(candidate, ipaddress.IPv4Network)
            or candidate.prefixlen != 24
            or not any(
                candidate.subnet_of(private_network)
                for private_network in DEVCONTAINER_RFC1918_NETWORKS
            )
        ):
            record_once(blocked, "devcontainer-host-route-candidate-invalid")
            continue
        parsed_candidates.append((raw_candidate, candidate))

    def parse_routes(
        raw_routes: tuple[str, ...],
        invalid_finding: str,
    ) -> tuple[tuple[str, ipaddress.IPv4Network], ...]:
        parsed: list[tuple[str, ipaddress.IPv4Network]] = []
        for raw_route in raw_routes:
            try:
                route = ipaddress.ip_network(raw_route, strict=True)
            except (TypeError, ValueError):
                record_once(blocked, invalid_finding)
                continue
            if not isinstance(route, ipaddress.IPv4Network):
                continue
            parsed.append((raw_route, route))
        return tuple(parsed)

    source_contracts = (
        (
            "devcontainer-docker-cidr-overlap",
            parse_routes(
                docker_cidrs,
                "devcontainer-docker-cidr-invalid",
            ),
        ),
        (
            "devcontainer-lan-direct-overlap",
            parse_routes(
                lan_direct_cidrs,
                "devcontainer-lan-direct-cidr-invalid",
            ),
        ),
    )
    for finding_prefix, routes in source_contracts:
        for raw_candidate, candidate in parsed_candidates:
            for raw_route, route in routes:
                if candidate.overlaps(route):
                    blocked.append(
                        f"{finding_prefix}:{raw_candidate}:{raw_route}"
                    )

    parsed_host_vpn_routes = parse_routes(
        host_vpn_routes,
        "devcontainer-host-vpn-route-invalid",
    )
    for raw_candidate, candidate in parsed_candidates:
        for raw_route, route in parsed_host_vpn_routes:
            if not candidate.overlaps(route):
                continue
            if route.prefixlen >= candidate.prefixlen:
                blocked.append(
                    "devcontainer-host-vpn-route-overlap:"
                    f"{raw_candidate}:{raw_route}"
                )
            else:
                caveats.append(
                    "devcontainer-host-vpn-broad-route-caveat:"
                    f"{raw_candidate}:{raw_route}"
                )
    return tuple(blocked), tuple(caveats)


def _devcontainer_runtime_closure_failures(
    dockerfile: str,
    runtime_closure: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    node_marker = "FROM ${NODE_IMAGE} AS devcontainer-node"
    _, node_found, node_remainder = dockerfile.partition(node_marker)
    node_stage = node_remainder.partition(
        "FROM ${PYTHON_IMAGE} AS devcontainer-python"
    )[0]
    python_marker = "FROM ${PYTHON_IMAGE} AS devcontainer-python"
    _, python_found, python_remainder = dockerfile.partition(python_marker)
    python_stage = python_remainder.partition("FROM ${UV_IMAGE} AS uv-binaries")[0]
    shared_copy = (
        "COPY --chmod=0555 deploy/devcontainer-runtime-closure.sh "
        "/tmp/desire-runtime-closure"
    )
    general_contract = (
        "#!/bin/sh",
        "BLOCKED:DEVCONTAINER_RUNTIME_CLOSURE",
        'if [ "$#" -lt 3 ]',
        'for runtime_binary_candidate in "$@"',
        'test -e "$runtime_binary_candidate"',
        'test -f "$runtime_binary_candidate"',
        'od -An -v -tx1 -N4 -- "$runtime_binary_candidate"',
        "if ! awk '",
        '$1 == "7f" && $2 == "45" && $3 == "4c" && $4 == "46"',
        'ldd "$runtime_binary_candidate"',
        "grep -F 'not found'",
        'readlink -f -- "$runtime_dependency"',
        '"$runtime_dependency" "$normalized_dependency"',
        'dpkg-query --search "$runtime_package_candidate"',
        'test "$runtime_package_owner_found" = true',
        'mv -f -- "$runtime_packages_staging_file" "$runtime_packages_file"',
        'runtime_closure_complete=true',
        'test -s "$runtime_packages_file"',
    )
    final_contract = (
        "COPY --from=devcontainer-python /python-runtime-packages.txt "
        "/tmp/python-runtime-packages.txt",
        "COPY --from=devcontainer-node /node-runtime-packages.txt "
        "/tmp/node-runtime-packages.txt",
        "< /tmp/python-runtime-packages.txt",
        "< /tmp/node-runtime-packages.txt",
        "rm -f /tmp/python-runtime-packages.txt /tmp/node-runtime-packages.txt",
    )
    if (
        not node_found
        or not python_found
        or dockerfile.count(shared_copy) != 2
        or any(fragment not in dockerfile for fragment in final_contract)
        or dockerfile.count(
            "xargs -r apt-get install --yes --no-install-recommends"
        ) != 2
    ):
        failures.append("devcontainer-runtime-closure-open")
    if (
        "RUN /tmp/desire-runtime-closure /node-runtime-packages.txt "
        "/usr/local /usr/local/bin/node" not in node_stage
    ):
        failures.append("devcontainer-node-runtime-closure-open")
    python_contract = (
        "find /usr/local/lib -type f -path "
        "'*/lib-dynload/*_tkinter*.so' -delete",
        "/tmp/desire-runtime-closure /python-runtime-packages.txt /usr/local",
        "/usr/local/bin/python3.14",
        "/usr/local/lib/libpython*.so*",
        "/usr/local/lib/python*/lib-dynload/*.so",
    )
    if (
        any(fragment not in runtime_closure for fragment in general_contract)
        or any(fragment not in python_stage for fragment in python_contract)
        or "xargs -r dpkg-query --search" in runtime_closure
        or "pipefail" in runtime_closure
        or "RUN <<'PYTHON_RUNTIME_CLOSURE'" in dockerfile
        or runtime_closure.count("runtime_closure_fail\n    fi") < 2
    ):
        failures.append("devcontainer-runtime-closure-pipeline-open")
    return tuple(failures)


def _devcontainer_toolchain_failures(
    dockerfile: str,
    toolchain_check: str,
    ci: str,
) -> tuple[str, ...]:
    failures: list[str] = []
    marker = "FROM ${POSTGRES_DEV_IMAGE} AS devcontainer"
    _, marker_found, devcontainer_stage = dockerfile.partition(marker)
    docker_contract = (
        "COPY --chmod=0555 --chown=node:node "
        "deploy/devcontainer-toolchain-check.sh "
        "/usr/local/bin/desire-devcontainer-toolchain-check",
        'USER node\nRUN test "$(id -u)" = "1000" \\\n'
        "    && /usr/local/bin/desire-devcontainer-toolchain-check",
    )
    command_contract = (
        "export LC_ALL=C",
        'python --version 2>&1',
        "python -c 'import bz2, ctypes, dbm.gnu, hashlib, json, lzma, "
        "readline, sqlite3, ssl, uuid, venv, zlib'",
        'node --version 2>&1',
        "npm --version >/dev/null 2>&1",
        'toolchain_value="$(npm --help 2>&1)" || toolchain_status="$?"',
        'case "$toolchain_status" in',
        "0|1) ;;",
        'if [ -z "$toolchain_value" ]',
        '$0 == "Usage:" || $0 == "npm <command>"',
        "npm config get cache 2>&1",
        "psql --version 2>&1",
        "pg_dump --version 2>&1",
        "pg_restore --version 2>&1",
        "uv --version 2>&1",
        "id -u 2>&1",
        'if ! test "$toolchain_value" -gt 0 2>/dev/null',
        "id -un 2>&1",
        "getent passwd node 2>&1",
        "sudo -n true >/dev/null 2>&1",
        "toolchain_home=${HOME:-}",
        '[ "$toolchain_home" != /home/node ]',
        '[ ! -w "$toolchain_home" ]',
        "for dependency_root in \\\n"
        "    /home/node/.cache/uv \\\n"
        "    /home/node/.npm \\\n"
        "    /workspace/platform/.venv \\\n"
        "    /workspace/mvp/.venv \\\n"
        "    /workspace/web/node_modules",
        '[ ! -d "$dependency_root" ] || [ ! -w "$dependency_root" ]',
    )
    legacy_ci_checks = (
        'test "$(python --version)"',
        'test "$(node --version)"',
        "npm --version >/dev/null",
        "npm --help >/dev/null",
        "npm config get cache",
        "psql --version",
        "pg_dump --version",
        "pg_restore --version",
        "sudo -n true",
    )
    legacy_fixed_runtime_uid_checks = (
        'test "$toolchain_value" = "1000"',
        'test "$toolchain_value" = 1000',
        '[ "$toolchain_value" = "1000" ]',
        '[ "$toolchain_value" = 1000 ]',
    )
    if (
        not marker_found
        or any(fragment not in devcontainer_stage for fragment in docker_contract)
        or any(fragment not in toolchain_check for fragment in command_contract)
        or any(label not in toolchain_check for label in DEVCONTAINER_TOOLCHAIN_LABELS)
        or any(
            fragment in toolchain_check
            for fragment in legacy_fixed_runtime_uid_checks
        )
        or toolchain_check.count("READY:DEVCONTAINER_TOOLCHAIN") != 1
        or ci.count(
            "/usr/local/bin/desire-devcontainer-toolchain-check"
        ) != 1
        or ci.count("READY:DEVCONTAINER_TOOLCHAIN") != 1
        or "/bin/sh -n deploy/devcontainer-runtime-closure.sh" not in ci
        or "/bin/sh -n deploy/devcontainer-toolchain-check.sh" not in ci
        or any(fragment in ci for fragment in legacy_ci_checks)
    ):
        failures.append("devcontainer-toolchain-label-contract-open")
    return tuple(failures)


def _dependency_conditions(service: dict[str, Any]) -> dict[str, str]:
    return {
        name: value.get("condition", "")
        for name, value in service.get("depends_on", {}).items()
        if isinstance(value, dict)
    }


def _devcontainer_tmpfs_failures(
    service: dict[str, Any],
) -> tuple[str, ...]:
    failures: list[str] = []
    tmpfs = service.get("tmpfs", [])
    if tmpfs.count(DEVCONTAINER_EXECUTABLE_TMPFS) != 1:
        failures.append("devcontainer-pgpass-not-on-tmpfs")
        failures.append("devcontainer-tmpfs-exec-contract-open")
    if tmpfs.count(POSTGRES_PARENT_TMPFS) != 1:
        failures.append("devcontainer-postgres-volume-not-ephemeral")
    if len(tmpfs) != 2:
        failures.append("devcontainer-tmpfs-contract-open")
    return tuple(failures)


def _dependency_graph_has_cycle(services: dict[str, Any]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> bool:
        if name in visiting:
            return True
        if name in visited:
            return False
        visiting.add(name)
        service = services.get(name, {})
        for dependency in service.get("depends_on", {}):
            if dependency in services and visit(dependency):
                return True
        visiting.remove(name)
        visited.add(name)
        return False

    return any(visit(name) for name in services)


def _postgres_parent_volume_failures(
    services: dict[str, Any],
    *,
    required_services: tuple[str, ...],
    child_volume_services: tuple[str, ...],
) -> tuple[str, ...]:
    failures: list[str] = []
    child_required = set(child_volume_services)
    for name in required_services:
        service = services.get(name, {})
        if not isinstance(service, dict):
            failures.append(f"postgres-parent-tmpfs-open:{name}")
            if name in child_required:
                failures.append(f"postgres-child-volume-open:{name}")
            continue

        tmpfs = service.get("tmpfs", [])
        parent_tmpfs = tuple(
            item
            for item in tmpfs
            if isinstance(item, str)
            and item.split(":", 1)[0] == POSTGRES_PARENT_PATH
        )
        if parent_tmpfs != (POSTGRES_PARENT_TMPFS,):
            failures.append(f"postgres-parent-tmpfs-open:{name}")

        volumes = service.get("volumes", [])
        parent_volumes = tuple(
            item
            for item in volumes
            if isinstance(item, dict)
            and item.get("target") == POSTGRES_PARENT_PATH
        )
        if parent_volumes:
            failures.append(f"postgres-parent-volume-open:{name}")

        if name not in child_required:
            continue
        child_volumes = tuple(
            item
            for item in volumes
            if isinstance(item, dict)
            and item.get("target") == POSTGRES_CHILD_DATA
            and item.get("type") == "volume"
            and isinstance(item.get("source"), str)
            and bool(item["source"])
            and item.get("read_only") is not True
        )
        if (
            len(child_volumes) != 1
            or service.get("environment", {}).get("PGDATA")
            != POSTGRES_CHILD_PGDATA
        ):
            failures.append(f"postgres-child-volume-open:{name}")
    return tuple(failures)


def _current_head_v13_runbook_failures(runbook: str) -> tuple[str, ...]:
    """Require the one-shot v13 fresh, journey, and restart protocol."""

    failures: list[str] = []

    def record(failure: str) -> None:
        if failure not in failures:
            failures.append(failure)

    if not _current_head_v13_protocol_digest_matches(runbook):
        record("current-head-v13-protocol-digest-open")

    markers = (
        CURRENT_HEAD_V13_FRESH_RUNBOOK_START,
        CURRENT_HEAD_V13_FRESH_RUNBOOK_END,
        CURRENT_HEAD_V13_JOURNEY_RESTART_START,
        CURRENT_HEAD_V13_JOURNEY_RESTART_END,
    )
    if any(runbook.count(marker) != 1 for marker in markers):
        return ("current-head-v13-runbook-markers-open",)
    marker_positions = tuple(runbook.index(marker) for marker in markers)
    if marker_positions != tuple(sorted(marker_positions)):
        return ("current-head-v13-runbook-markers-open",)
    fresh = runbook.partition(CURRENT_HEAD_V13_FRESH_RUNBOOK_START)[2].partition(
        CURRENT_HEAD_V13_FRESH_RUNBOOK_END
    )[0]
    journey = runbook.partition(CURRENT_HEAD_V13_JOURNEY_RESTART_START)[
        2
    ].partition(CURRENT_HEAD_V13_JOURNEY_RESTART_END)[0]
    if not fresh or not journey:
        return ("current-head-v13-runbook-markers-open",)

    coordinate_lines = (
        'export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v13"',
        'export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"',
        'export DESIRE_E2E_INPUT_ROOT="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13"',
        'export DESIRE_E2E_BUNDLE_NAME="internal-sandbox-bundle-iam37-demand10-trust7"',
        'export DESIRE_E2E_BUNDLE_DIR="$DESIRE_E2E_INPUT_ROOT/$DESIRE_E2E_BUNDLE_NAME"',
        'export DESIRE_E2E_DEPLOYMENT_ID="sandbox-e2e-ten-account-v13"',
        'export DESIRE_E2E_RELEASE_ID="release-e2e-ten-account-v13-iam37-demand10-trust7"',
        'export DESIRE_E2E_INGRESS_SUBNET="172.16.227.0/24"',
        'export DESIRE_E2E_OIDC_SUBNET="172.16.228.0/24"',
        'export DESIRE_E2E_APP_SUBNET="172.16.229.0/24"',
        'export DESIRE_E2E_DATA_SUBNET="172.16.231.0/24"',
        'export DESIRE_E2E_EVIDENCE_DIR="$DESIRE_E2E_INPUT_ROOT/e2e-evidence"',
        'export DESIRE_E2E_STATE="$DESIRE_E2E_EVIDENCE_DIR/state.json"',
        'export DESIRE_E2E_JOURNEY_RESULT="$DESIRE_E2E_EVIDENCE_DIR/journey-result.json"',
        'export DESIRE_E2E_RESTART_1_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-1-result.json"',
        'export DESIRE_E2E_RESTART_2_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-2-result.json"',
        'test "$DESIRE_E2E_PROJECT" = "desire-supply-e2e-ten-account-v13"',
        'test "$DESIRE_IMAGE_TAG" = "e2e-ten-account-v13-iam37-demand10-trust7"',
        'test "$DESIRE_E2E_INPUT_ROOT" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13"',
        'test "$DESIRE_E2E_BUNDLE_DIR" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/internal-sandbox-bundle-iam37-demand10-trust7"',
        'test "$DESIRE_E2E_DEPLOYMENT_ID" = "sandbox-e2e-ten-account-v13"',
        'test "$DESIRE_E2E_RELEASE_ID" = "release-e2e-ten-account-v13-iam37-demand10-trust7"',
    )
    coordinate_variables = (
        "DESIRE_E2E_PROJECT",
        "DESIRE_IMAGE_TAG",
        "DESIRE_E2E_INPUT_ROOT",
        "DESIRE_E2E_BUNDLE_NAME",
        "DESIRE_E2E_BUNDLE_DIR",
        "DESIRE_E2E_DEPLOYMENT_ID",
        "DESIRE_E2E_RELEASE_ID",
        "DESIRE_E2E_INGRESS_SUBNET",
        "DESIRE_E2E_OIDC_SUBNET",
        "DESIRE_E2E_APP_SUBNET",
        "DESIRE_E2E_DATA_SUBNET",
        "DESIRE_E2E_EVIDENCE_DIR",
        "DESIRE_E2E_STATE",
        "DESIRE_E2E_JOURNEY_RESULT",
        "DESIRE_E2E_RESTART_1_RESULT",
        "DESIRE_E2E_RESTART_2_RESULT",
    )
    subnet_exports = tuple(
        line.strip()
        for line in fresh.splitlines()
        if line.strip().startswith("export DESIRE_E2E_")
        and "_SUBNET=" in line
    )
    expected_subnet_exports = coordinate_lines[7:11]
    if (
        any(fresh.count(line) != 1 for line in coordinate_lines)
        or any(
            len(
                re.findall(
                    rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                    fresh + journey,
                    flags=re.MULTILINE,
                )
            )
            != 1
            for variable in coordinate_variables
        )
        or subnet_exports != expected_subnet_exports
        or any(
            stale in fresh + journey
            for stale in (
                "desire-supply-e2e-ten-account-v12",
                "e2e-ten-account-v12-iam36-demand9-trust6",
                "172.16.215.0/24",
                "172.16.216.0/24",
                "172.16.217.0/24",
                "172.16.218.0/24",
            )
        )
    ):
        record("current-head-v13-coordinate-open")

    preflight_lines = (
        "set -eu",
        "set -o pipefail",
        'test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"',
        'test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"',
        'test -z "${COMPOSE_PROJECT_NAME+x}"',
        'test -z "${COMPOSE_COMPATIBILITY+x}"',
        'test -z "${DESIRE_DB_PASSWORD_FILE+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"',
        'test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"',
        'test ! -e "$DESIRE_E2E_INPUT_ROOT"',
        'DESIRE_E2E_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
        'DESIRE_E2E_PROJECT_NETWORK_IDS="$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
        'DESIRE_E2E_PROJECT_VOLUME_IDS="$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"',
        'DESIRE_E2E_CONTAINER_PREFIX_MATCHES="$(docker container ls -a --format \'{{.Names}}\' | awk -v prefix="$DESIRE_E2E_CONTAINER_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'DESIRE_E2E_NETWORK_PREFIX_MATCHES="$(docker network ls --format \'{{.Name}}\' | awk -v prefix="$DESIRE_E2E_RESOURCE_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'DESIRE_E2E_VOLUME_PREFIX_MATCHES="$(docker volume ls --format \'{{.Name}}\' | awk -v prefix="$DESIRE_E2E_RESOURCE_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'DESIRE_E2E_PLATFORM_TAG_IDS="$(docker image ls --quiet "desire-supply-platform:$DESIRE_IMAGE_TAG")"',
        'DESIRE_E2E_WEB_TAG_IDS="$(docker image ls --quiet "desire-supply-web:$DESIRE_IMAGE_TAG")"',
        'DESIRE_E2E_EDGE_TAG_IDS="$(docker image ls --quiet "desire-supply-edge:$DESIRE_IMAGE_TAG")"',
        'if DESIRE_E2E_PORT_443_LISTENERS="$(lsof -nP -iTCP@127.0.0.1:443 -sTCP:LISTEN -t)"; then',
        'test "$?" = "1"',
        'test -z "$DESIRE_E2E_PROJECT_CONTAINER_IDS"',
        'test -z "$DESIRE_E2E_PROJECT_NETWORK_IDS"',
        'test -z "$DESIRE_E2E_PROJECT_VOLUME_IDS"',
        'test -z "$DESIRE_E2E_CONTAINER_PREFIX_MATCHES"',
        'test -z "$DESIRE_E2E_NETWORK_PREFIX_MATCHES"',
        'test -z "$DESIRE_E2E_VOLUME_PREFIX_MATCHES"',
        'test -z "$DESIRE_E2E_PLATFORM_TAG_IDS"',
        'test -z "$DESIRE_E2E_WEB_TAG_IDS"',
        'test -z "$DESIRE_E2E_EDGE_TAG_IDS"',
        'test -z "$DESIRE_E2E_PORT_443_LISTENERS"',
        'test ! -e "$DESIRE_E2E_STATE"',
        'test ! -L "$DESIRE_E2E_STATE"',
        'test ! -e "$DESIRE_E2E_JOURNEY_RESULT"',
        'test ! -L "$DESIRE_E2E_JOURNEY_RESULT"',
        'test ! -e "$DESIRE_E2E_RESTART_1_RESULT"',
        'test ! -L "$DESIRE_E2E_RESTART_1_RESULT"',
        'test ! -e "$DESIRE_E2E_RESTART_2_RESULT"',
        'test ! -L "$DESIRE_E2E_RESTART_2_RESULT"',
    )
    build_command = "compose_v13 build api web edge"
    input_root_mkdir = 'mkdir -m 0700 -- "$DESIRE_E2E_INPUT_ROOT"'
    evidence_mkdir = 'mkdir -m 0700 -- "$DESIRE_E2E_EVIDENCE_DIR"'
    v13_creation_fragments = (
        input_root_mkdir,
        "scripts/prepare_internal_sandbox_inputs.py create",
        "scripts/manage_internal_sandbox_tls.py create",
        "desire_platform.deployment.internal_sandbox_bundle create",
        "scripts/prepare_internal_sandbox_compose_inputs.py create",
        evidence_mkdir,
        build_command,
    )
    manifest_preflight_position = fresh.find(
        CURRENT_HEAD_V13_DOCKER_HUB_PREFLIGHT_COMMAND
    )
    first_v13_creation = re.search(
        r"^[ \t]*(?!#)[^\n]*(?:\bmkdir\b|\bcreate\b|\bbuild\b)[^\n]*$",
        fresh,
        flags=re.MULTILINE,
    )
    manifest_preflight_closed = (
        runbook.count(CURRENT_HEAD_V13_DOCKER_HUB_PREFLIGHT_COMMAND) == 1
        and manifest_preflight_position >= 0
        and first_v13_creation is not None
        and manifest_preflight_position < first_v13_creation.start()
        and all(
            fresh.find(fragment) > manifest_preflight_position
            for fragment in v13_creation_fragments
        )
    )
    preflight_closed = build_command in fresh and all(
        fresh.count(line) == 1 and fresh.index(line) < fresh.index(build_command)
        for line in preflight_lines
    )
    helper_fragments = (
        "scripts/prepare_internal_sandbox_inputs.py create",
        "scripts/manage_internal_sandbox_tls.py create",
        "desire_platform.deployment.internal_sandbox_bundle create",
        "scripts/prepare_internal_sandbox_compose_inputs.py create",
        "scripts/prepare_internal_sandbox_inputs.py verify",
        "scripts/manage_internal_sandbox_tls.py verify",
        "scripts/prepare_internal_sandbox_compose_inputs.py verify",
        '"status":"INTERNAL_SANDBOX_INPUTS_CREATED"',
        '"status":"INTERNAL_SANDBOX_TLS_CREATED"',
        '"status":"INTERNAL_SANDBOX_BUNDLE_CREATED"',
        '"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED"',
        '"status":"INTERNAL_SANDBOX_INPUTS_VERIFIED"',
        '"status":"INTERNAL_SANDBOX_TLS_VERIFIED"',
        '"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_VERIFIED"',
        '--env-file "$DESIRE_E2E_INPUT_ROOT/compose.env"',
        '-f "$PWD/compose.yaml"',
        '-f "$DESIRE_E2E_INPUT_ROOT/compose.ipam.yaml"',
    )
    subnet_arguments = (
        '--ingress-subnet "$DESIRE_E2E_INGRESS_SUBNET"',
        '--oidc-subnet "$DESIRE_E2E_OIDC_SUBNET"',
        '--app-subnet "$DESIRE_E2E_APP_SUBNET"',
        '--data-subnet "$DESIRE_E2E_DATA_SUBNET"',
    )
    if (
        not preflight_closed
        or not manifest_preflight_closed
        or any(fragment not in fresh for fragment in helper_fragments)
        or any(fresh.count(fragment) != 2 for fragment in subnet_arguments)
        or fresh.count('test ! -L "$DESIRE_E2E_INPUT_ROOT"') != 2
        or "--compatibility" in fresh
        or "--compatibility" in journey
        or "--build" in fresh + journey
        or "--pull" in fresh + journey
        or not _exact_bash_function(
            fresh,
            "compose_v13",
            'docker compose --project-name "$DESIRE_E2E_PROJECT" '
            '--env-file "$DESIRE_E2E_INPUT_ROOT/compose.env" '
            '-f "$PWD/compose.yaml" '
            '-f "$DESIRE_E2E_INPUT_ROOT/compose.ipam.yaml" "$@"',
        )
        or len(
            re.findall(
                r"^[ \t]*(?:function[ \t]+)?compose_v13(?:[ \t]*\(\))?[ \t]*\{",
                fresh + journey,
                flags=re.MULTILINE,
            )
        )
        != 1
        or fresh.count("||") != 1
        or journey.count("||") != 0
        or "&&" in fresh + journey
        or _has_unexpected_shell_hash(fresh + journey)
        or re.search(
            r"(?:;[ \t]*(?:true|:)(?:[ \t]*$)|^[ \t]*![ \t]+)",
            fresh + journey,
            flags=re.MULTILINE,
        )
        is not None
    ):
        record("current-head-v13-preflight-open")

    fresh_commands = _bash_commands(f"```bash\n{fresh}\n```")
    journey_commands = _bash_commands(f"```bash\n{journey}\n```")
    if (
        fresh_commands.count(CURRENT_HEAD_V13_DOCKER_HUB_PREFLIGHT_COMMAND)
        != 1
    ):
        record("current-head-v13-preflight-open")
    expected_fresh_flow = (
        build_command,
        "compose_v13 up -d --wait --wait-timeout 120 synthetic-oidc edge",
        "compose_v13 up -d --wait --wait-timeout 120 db",
        "compose_v13 up -d --no-deps migrate",
        'docker start "$DESIRE_E2E_MIGRATE_ID"',
        "compose_v13 up -d --no-deps taxonomy-seed",
        "compose_v13 up -d --no-deps online-credentials-reconcile",
        "compose_v13 up -d --no-deps online-credentials-verify",
        "compose_v13 up -d --no-deps identity-bootstrap",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 api",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 web",
    )
    lifecycle_prefixes = (
        "compose_v13 build ",
        "compose_v13 up ",
        "compose_v13 create ",
        "compose_v13 pull ",
        "compose_v13 tag ",
        "compose_v13 stop ",
        "compose_v13 start ",
        "compose_v13 restart ",
        "docker start ",
        "docker stop ",
        "docker restart ",
    )
    fresh_flow = tuple(
        command
        for command in fresh_commands
        if command.startswith(lifecycle_prefixes)
    )
    build_commands = tuple(
        command
        for command in fresh_commands + journey_commands
        if re.search(r"(?:^|\s)build(?:\s|$)", command)
    )
    if fresh_flow != expected_fresh_flow or build_commands != (build_command,):
        record("current-head-v13-fresh-flow-open")

    one_shots = (
        ("DESIRE_E2E_MIGRATE_ID", "migrate", 2),
        ("DESIRE_E2E_TAXONOMY_ID", "taxonomy-seed", 1),
        (
            "DESIRE_E2E_RECONCILE_ID",
            "online-credentials-reconcile",
            1,
        ),
        (
            "DESIRE_E2E_CREDENTIAL_VERIFY_ID",
            "online-credentials-verify",
            1,
        ),
        ("DESIRE_E2E_IDENTITY_ID", "identity-bootstrap", 1),
    )
    one_shot_evidence_open = False
    inspect_format = (
        "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}"
    )
    for variable, service, executions in one_shots:
        required_counts = (
            (
                f'{variable}="$(compose_v13 ps --all --quiet {service})"',
                1,
            ),
            (f'test -n "${variable}"', 1),
            (f'test "$(docker wait "${variable}")" = "0"', executions),
            (
                f'test "$(docker inspect --format \'{inspect_format}\' '
                f'"${variable}")" = "exited|0|0"',
                executions,
            ),
        )
        if any(fresh.count(line) != count for line, count in required_counts):
            one_shot_evidence_open = True

    expected_fresh_catalogs = {
        "demand": {"applied_versions": list(range(1, 11)), "skipped_versions": []},
        "iam": {"applied_versions": list(range(38)), "skipped_versions": []},
        "profile": {"applied_versions": list(range(1, 4)), "skipped_versions": []},
        "taxonomy": {"applied_versions": list(range(1, 3)), "skipped_versions": []},
        "trust": {"applied_versions": list(range(1, 8)), "skipped_versions": []},
    }
    expected_replay_catalogs = {
        name: {
            "applied_versions": [],
            "skipped_versions": value["applied_versions"],
        }
        for name, value in expected_fresh_catalogs.items()
    }

    def exported_json(name: str) -> Any:
        matches = re.findall(
            rf"^export {re.escape(name)}='([^']+)'$",
            fresh,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            return None
        try:
            return json.loads(matches[0])
        except (json.JSONDecodeError, TypeError):
            return None

    expected_schema_documents = (
        ("DESIRE_E2E_FRESH_SCHEMA_READY", expected_fresh_catalogs),
        ("DESIRE_E2E_REPLAY_SCHEMA_READY", expected_replay_catalogs),
    )
    for variable, catalogs in expected_schema_documents:
        if exported_json(variable) != {"catalogs": catalogs, "status": "SCHEMA_READY"}:
            one_shot_evidence_open = True
    one_shot_log_evidence = (
        'test "$(printf \'%s\\n\' "$DESIRE_E2E_MIGRATE_LOG" | sed \'/^$/d\' | wc -l | tr -d \' \')" = "2"',
        'test "$(printf \'%s\\n\' "$DESIRE_E2E_MIGRATE_LOG" | grep -Fxc "$DESIRE_E2E_FRESH_SCHEMA_READY")" = "1"',
        'test "$(printf \'%s\\n\' "$DESIRE_E2E_MIGRATE_LOG" | grep -Fxc "$DESIRE_E2E_REPLAY_SCHEMA_READY")" = "1"',
        'test -z "$(printf \'%s\\n\' "$DESIRE_E2E_MIGRATE_LOG" | grep -F \'"status":"BLOCKED"\' || true)"',
        '"replayed":false,"status":"INTERNAL_SANDBOX_TAXONOMY_SEED_READY"',
        '"action":"RECONCILE","online_role_count":11,"status":"ONLINE_CREDENTIALS_READY"',
        '"action":"VERIFY","online_role_count":11,"status":"ONLINE_CREDENTIALS_READY"',
        '"IDENTITY_BOOTSTRAP_ORCHESTRATION_READY|APPLIED|VERIFIED"',
    )
    if any(fragment not in fresh for fragment in one_shot_log_evidence):
        one_shot_evidence_open = True
    if one_shot_evidence_open:
        record("current-head-v13-one-shot-evidence-open")

    journey_command = (
        "python3 -B scripts/run_internal_sandbox_e2e.py journey "
        '--ca-file "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls/root-ca.pem" '
        '--state-output "$DESIRE_E2E_STATE" '
        '--result-output "$DESIRE_E2E_JOURNEY_RESULT"'
    )
    verify_restart_one = (
        "python3 -B scripts/run_internal_sandbox_e2e.py verify-restart "
        '--ca-file "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls/root-ca.pem" '
        '--state-file "$DESIRE_E2E_STATE" '
        '--result-output "$DESIRE_E2E_RESTART_1_RESULT"'
    )
    verify_restart_two = verify_restart_one.replace(
        "RESTART_1_RESULT", "RESTART_2_RESULT"
    )
    stop_round = (
        "compose_v13 stop web",
        "compose_v13 stop api",
        "compose_v13 stop edge",
        "compose_v13 stop synthetic-oidc",
        "compose_v13 stop db",
    )
    start_round = (
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 db",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 synthetic-oidc",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 edge",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 api",
        "compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 web",
    )
    expected_journey_flow = (
        (journey_command, "assert_v13_preserved")
        + stop_round
        + ("assert_v13_stopped",)
        + start_round
        + (
            "advance_v13_started_at",
            "assert_v13_preserved",
            verify_restart_one,
            "assert_v13_preserved",
        )
        + stop_round
        + ("assert_v13_stopped",)
        + start_round
        + (
            "advance_v13_started_at",
            "assert_v13_preserved",
            verify_restart_two,
            "assert_v13_preserved",
        )
    )
    journey_flow = tuple(
        command
        for command in journey_commands
        if command.startswith("python3 -B scripts/run_internal_sandbox_e2e.py ")
        or command.startswith(lifecycle_prefixes)
        or command
        in (
            "assert_v13_preserved",
            "assert_v13_stopped",
            "advance_v13_started_at",
        )
    )
    result_proofs = (
        'test -f "$DESIRE_E2E_STATE"',
        'test ! -L "$DESIRE_E2E_STATE"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$DESIRE_E2E_STATE")" = "600|$(id -u)|$(id -g)|1"',
        'test -f "$DESIRE_E2E_JOURNEY_RESULT"',
        'test ! -L "$DESIRE_E2E_JOURNEY_RESULT"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$DESIRE_E2E_JOURNEY_RESULT")" = "600|$(id -u)|$(id -g)|1"',
        'test "$(wc -l < "$DESIRE_E2E_JOURNEY_RESULT" | tr -d \' \')" = "1"',
        'value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN"',
        'test -f "$DESIRE_E2E_RESTART_1_RESULT"',
        'test ! -L "$DESIRE_E2E_RESTART_1_RESULT"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$DESIRE_E2E_RESTART_1_RESULT")" = "600|$(id -u)|$(id -g)|1"',
        'test "$(wc -l < "$DESIRE_E2E_RESTART_1_RESULT" | tr -d \' \')" = "1"',
        'test -f "$DESIRE_E2E_RESTART_2_RESULT"',
        'test ! -L "$DESIRE_E2E_RESTART_2_RESULT"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$DESIRE_E2E_RESTART_2_RESULT")" = "600|$(id -u)|$(id -g)|1"',
        'test "$(wc -l < "$DESIRE_E2E_RESTART_2_RESULT" | tr -d \' \')" = "1"',
    )
    if (
        journey_flow != expected_journey_flow
        or any(journey.count(fragment) != 1 for fragment in result_proofs)
        or journey.count(
            'value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN"'
        )
        != 2
        or fresh.count('original_umask="$(umask)"') != 1
        or fresh.count("umask 077") != 1
        or 'umask "$original_umask"' in fresh
        or journey.count('umask "$original_umask"') != 1
        or journey.index('umask "$original_umask"')
        < journey.rindex(
            'value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN"'
        )
    ):
        record("current-head-v13-journey-restart-open")

    snapshot_open = False
    first_stop = journey.find("compose_v13 stop web")
    if first_stop < 0 or journey.count("assert_v13_preserved() {") != 1:
        snapshot_open = True
        assert_body = ""
    else:
        assert_body = journey.partition("assert_v13_preserved() {")[2].partition(
            "\n}"
        )[0]
    persistent_ids = (
        ("DESIRE_E2E_DB_ID", "db"),
        ("DESIRE_E2E_OIDC_ID", "synthetic-oidc"),
        ("DESIRE_E2E_EDGE_ID", "edge"),
        ("DESIRE_E2E_API_ID", "api"),
        ("DESIRE_E2E_WEB_ID", "web"),
    )
    for variable, service in persistent_ids:
        export_line = f'{variable}="$(compose_v13 ps --quiet {service})"'
        identity_assertion = f'test "$(compose_v13 ps --quiet {service})" = "${variable}"'
        health_assertion = (
            "test \"$(docker inspect --format "
            "'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "
            f'"${variable}")" = "running|healthy|0"'
        )
        if (
            fresh.count(export_line) != 1
            or fresh.count(f'test -n "${variable}"') != 1
            or identity_assertion not in assert_body
            or health_assertion not in assert_body
        ):
            snapshot_open = True

    if journey.count("assert_v13_stopped() {") != 1:
        stopped_body = ""
        snapshot_open = True
    else:
        stopped_body = journey.partition("assert_v13_stopped() {")[2].partition(
            "\n}"
        )[0]
    if journey.count("advance_v13_started_at() {") != 1:
        advance_body = ""
        snapshot_open = True
    else:
        advance_body = journey.partition("advance_v13_started_at() {")[
            2
        ].partition("\n}")[0]
    for variable, service in persistent_ids:
        started = variable[:-3] + "_STARTED_AT"
        next_started = variable[:-3] + "_NEXT_STARTED_AT"
        initial_line = (
            f'{started}="$(docker inspect --format \'{{{{.State.StartedAt}}}}\' '
            f'"${variable}")"'
        )
        started_assertion = (
            "test \"$(docker inspect --format '{{.State.StartedAt}}' "
            f'"${variable}")" = "${started}"'
        )
        stopped_identity = (
            f'test "$(compose_v13 ps --all --quiet {service})" = "${variable}"'
        )
        stopped_status = (
            "test \"$(docker inspect --format "
            "'{{.State.Status}}|{{.RestartCount}}' "
            f'"${variable}")" = "exited|0"'
        )
        next_line = (
            f'{next_started}="$(docker inspect --format '
            f"'{{{{.State.StartedAt}}}}' \"${variable}\")\""
        )
        if (
            fresh.count(initial_line) != 1
            or fresh.count(f'test -n "${started}"') != 1
            or started_assertion not in assert_body
            or stopped_identity not in stopped_body
            or stopped_status not in stopped_body
            or next_line not in advance_body
            or f'test -n "${next_started}"' not in advance_body
            or f'test "${next_started}" != "${started}"' not in advance_body
            or f'{started}="${next_started}"' not in advance_body
        ):
            snapshot_open = True
    if (
        'test "$(compose_v13 ps --all --quiet | wc -l | tr -d \' \')" = "10"'
        not in assert_body
        or journey_commands.count("assert_v13_stopped") != 2
        or journey_commands.count("advance_v13_started_at") != 2
    ):
        snapshot_open = True
    for variable, service, _ in one_shots:
        if (
            f'test "$(compose_v13 ps --all --quiet {service})" = "${variable}"'
            not in assert_body
        ):
            snapshot_open = True

    snapshot_format = (
        "{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|"
        "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}"
    )
    one_shot_snapshots = (
        ("DESIRE_E2E_MIGRATE_SNAPSHOT", "DESIRE_E2E_MIGRATE_ID"),
        ("DESIRE_E2E_TAXONOMY_SNAPSHOT", "DESIRE_E2E_TAXONOMY_ID"),
        ("DESIRE_E2E_RECONCILE_SNAPSHOT", "DESIRE_E2E_RECONCILE_ID"),
        (
            "DESIRE_E2E_CREDENTIAL_VERIFY_SNAPSHOT",
            "DESIRE_E2E_CREDENTIAL_VERIFY_ID",
        ),
        ("DESIRE_E2E_IDENTITY_SNAPSHOT", "DESIRE_E2E_IDENTITY_ID"),
    )
    for snapshot, identifier in one_shot_snapshots:
        export_line = (
            f'{snapshot}="$(docker inspect --format \'{snapshot_format}\' '
            f'"${identifier}")"'
        )
        assertion = (
            f'test "$(docker inspect --format \'{snapshot_format}\' '
            f'"${identifier}")" = "${snapshot}"'
        )
        if (
            fresh.count(export_line) != 1
            or assertion not in assert_body
        ):
            snapshot_open = True

    log_snapshots = (
        ("DESIRE_E2E_MIGRATE_LOG_SHA", "migrate"),
        ("DESIRE_E2E_TAXONOMY_LOG_SHA", "taxonomy-seed"),
        (
            "DESIRE_E2E_RECONCILE_LOG_SHA",
            "online-credentials-reconcile",
        ),
        (
            "DESIRE_E2E_CREDENTIAL_VERIFY_LOG_SHA",
            "online-credentials-verify",
        ),
        ("DESIRE_E2E_IDENTITY_LOG_SHA", "identity-bootstrap"),
    )
    for snapshot, service in log_snapshots:
        expression = (
            f"compose_v13 logs --no-color --no-log-prefix {service} | "
            "shasum -a 256 | awk '{print $1}'"
        )
        export_line = f'{snapshot}="$({expression})"'
        assertion = f'test "$({expression})" = "${snapshot}"'
        if (
            fresh.count(export_line) != 1
            or assertion not in assert_body
        ):
            snapshot_open = True

    image_snapshots = (
        ("DESIRE_E2E_PLATFORM_IMAGE_ID", "platform", "DESIRE_E2E_API_ID"),
        ("DESIRE_E2E_WEB_IMAGE_ID", "web", "DESIRE_E2E_WEB_ID"),
        ("DESIRE_E2E_EDGE_IMAGE_ID", "edge", "DESIRE_E2E_EDGE_ID"),
    )
    for image_variable, image_name, container_variable in image_snapshots:
        export_line = (
            f'{image_variable}="$(docker image inspect --format '
            f"'{{{{.Id}}}}' \"desire-supply-{image_name}:$DESIRE_IMAGE_TAG\")\""
        )
        assertion = (
            "test \"$(docker inspect --format '{{.Image}}' "
            f'"${container_variable}")" = "${image_variable}"'
        )
        if (
            fresh.count(export_line) != 1
            or fresh.count(f'test -n "${image_variable}"') != 1
            or assertion not in assert_body
        ):
            snapshot_open = True

    fresh_platform_image_assertions = (
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-web:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_WEB_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-edge:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_EDGE_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$(compose_v13 ps --quiet api)")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$(compose_v13 ps --quiet web)")" = "$DESIRE_E2E_WEB_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$(compose_v13 ps --quiet edge)")" = "$DESIRE_E2E_EDGE_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$(compose_v13 ps --quiet synthetic-oidc)")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_MIGRATE_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_TAXONOMY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_RECONCILE_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_IDENTITY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
    )
    preserved_image_assertions = (
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_OIDC_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-web:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_WEB_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-edge:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_EDGE_IMAGE_ID"',
    )
    if any(
        fresh.count(line) != 1 for line in fresh_platform_image_assertions
    ) or any(line not in assert_body for line in preserved_image_assertions):
        snapshot_open = True

    network_snapshots = (
        ("DESIRE_E2E_INGRESS_NETWORK_ID", "ingress"),
        ("DESIRE_E2E_OIDC_NETWORK_ID", "oidc-backend"),
        ("DESIRE_E2E_APP_NETWORK_ID", "app"),
        ("DESIRE_E2E_DATA_NETWORK_ID", "data"),
    )
    for variable, network in network_snapshots:
        inspect = (
            "docker network inspect --format '{{.Id}}' "
            f'"${{DESIRE_E2E_PROJECT}}_{network}"'
        )
        export_line = f'{variable}="$({inspect})"'
        assertion = f'test "$({inspect})" = "${variable}"'
        if (
            fresh.count(export_line) != 1
            or assertion not in assert_body
        ):
            snapshot_open = True

    volume_exports = (
        'DESIRE_E2E_DATA_VOLUME="${DESIRE_E2E_PROJECT}_postgres-data"',
        'DESIRE_E2E_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format \'{{.CreatedAt}}\' "$DESIRE_E2E_DATA_VOLUME")"',
    )
    volume_assertions = (
        'test "$(docker volume inspect --format \'{{.CreatedAt}}\' "$DESIRE_E2E_DATA_VOLUME")" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"',
        'test "$(docker inspect --format \'{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}\' "$DESIRE_E2E_DB_ID")" = "volume|$DESIRE_E2E_DATA_VOLUME"',
    )
    state_exports = (
        'DESIRE_E2E_STATE_STAT="$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_E2E_STATE")"',
        'DESIRE_E2E_STATE_SHA="$(shasum -a 256 "$DESIRE_E2E_STATE" | awk \'{print $1}\')"',
    )
    state_assertions = (
        'test "$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_E2E_STATE")" = "$DESIRE_E2E_STATE_STAT"',
        'test "$(shasum -a 256 "$DESIRE_E2E_STATE" | awk \'{print $1}\')" = "$DESIRE_E2E_STATE_SHA"',
    )
    if (
        any(fresh.count(line) != 1 for line in volume_exports)
        or any(
            journey.count(line) != 1 or journey.index(line) > first_stop
            for line in state_exports
        )
        or any(line not in assert_body for line in volume_assertions + state_assertions)
    ):
        snapshot_open = True
    if journey_commands.count("assert_v13_preserved") != 5:
        snapshot_open = True

    expected_preserved_commands: list[str] = [
        'test "$(compose_v13 ps --all --quiet | wc -l | tr -d \' \')" = "10"'
    ]
    expected_preserved_commands.extend(
        f'test "$(compose_v13 ps --quiet {service})" = "${variable}"'
        for variable, service in persistent_ids
    )
    expected_preserved_commands.extend(
        f'test "$(compose_v13 ps --all --quiet {service})" = "${variable}"'
        for variable, service, _ in one_shots
    )
    expected_preserved_commands.extend(
        'test "$(docker inspect --format '
        "'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "
        f'"${variable}")" = "running|healthy|0"'
        for variable, _ in persistent_ids
    )
    expected_preserved_commands.extend(
        'test "$(docker inspect --format \'{{.State.StartedAt}}\' '
        f'"${variable}")" = "${variable[:-3]}_STARTED_AT"'
        for variable, _ in persistent_ids
    )
    expected_preserved_commands.extend(
        (
            'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_API_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
            'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_OIDC_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
            'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_WEB_ID")" = "$DESIRE_E2E_WEB_IMAGE_ID"',
            'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_E2E_EDGE_ID")" = "$DESIRE_E2E_EDGE_IMAGE_ID"',
            *preserved_image_assertions[1:],
        )
    )
    expected_preserved_commands.extend(
        f'test "$(docker inspect --format \'{snapshot_format}\' '
        f'"${identifier}")" = "${snapshot}"'
        for snapshot, identifier in one_shot_snapshots
    )
    expected_preserved_commands.extend(
        f'test "$(compose_v13 logs --no-color --no-log-prefix {service} | '
        f'shasum -a 256 | awk \'{{print $1}}\')" = "${snapshot}"'
        for snapshot, service in log_snapshots
    )
    expected_preserved_commands.extend(
        f'test "$(docker network inspect --format \'{{{{.Id}}}}\' '
        f'"${{DESIRE_E2E_PROJECT}}_{network}")" = "${variable}"'
        for variable, network in network_snapshots
    )
    expected_preserved_commands.extend(volume_assertions + state_assertions)

    expected_stopped_commands: list[str] = []
    expected_stopped_commands.extend(
        f'test "$(compose_v13 ps --all --quiet {service})" = "${variable}"'
        for variable, service in persistent_ids
    )
    expected_stopped_commands.extend(
        'test "$(docker inspect --format '
        "'{{.State.Status}}|{{.RestartCount}}' "
        f'"${variable}")" = "exited|0"'
        for variable, _ in persistent_ids
    )

    expected_advance_commands: list[str] = []
    for variable, _ in persistent_ids:
        started = variable[:-3] + "_STARTED_AT"
        next_started = variable[:-3] + "_NEXT_STARTED_AT"
        expected_advance_commands.append(
            f'{next_started}="$(docker inspect --format \'{{{{.State.StartedAt}}}}\' '
            f'"${variable}")"'
        )
    expected_advance_commands.extend(
        f'test -n "${variable[:-3]}_NEXT_STARTED_AT"'
        for variable, _ in persistent_ids
    )
    expected_advance_commands.extend(
        f'test "${variable[:-3]}_NEXT_STARTED_AT" != '
        f'"${variable[:-3]}_STARTED_AT"'
        for variable, _ in persistent_ids
    )
    expected_advance_commands.extend(
        f'{variable[:-3]}_STARTED_AT="${variable[:-3]}_NEXT_STARTED_AT"'
        for variable, _ in persistent_ids
    )
    helper_names = (
        "assert_v13_preserved",
        "assert_v13_stopped",
        "advance_v13_started_at",
    )
    expected_helper_commands = (
        tuple(expected_preserved_commands),
        tuple(expected_stopped_commands),
        tuple(expected_advance_commands),
    )
    for helper_name, expected_commands in zip(
        helper_names,
        expected_helper_commands,
    ):
        definition_count = len(
            re.findall(
                rf"^[ \t]*(?:function[ \t]+)?{re.escape(helper_name)}"
                r"(?:[ \t]*\(\))?[ \t]*\{",
                journey,
                flags=re.MULTILINE,
            )
        )
        if (
            definition_count != 1
            or _bash_function_commands(journey, helper_name)
            != expected_commands
        ):
            snapshot_open = True

    immutable_once = (
        *(variable for variable, _ in persistent_ids),
        *(variable for variable, _, _ in one_shots),
        *(snapshot for snapshot, _ in one_shot_snapshots),
        *(snapshot for snapshot, _ in log_snapshots),
        *(variable for variable, _, _ in image_snapshots),
        *(variable for variable, _ in network_snapshots),
        "DESIRE_E2E_DATA_VOLUME",
        "DESIRE_E2E_DATA_VOLUME_CREATED_AT",
        "DESIRE_E2E_STATE_STAT",
        "DESIRE_E2E_STATE_SHA",
        "DESIRE_E2E_FRESH_SCHEMA_READY",
        "DESIRE_E2E_REPLAY_SCHEMA_READY",
    )
    assignment_scope = fresh + journey
    for variable in immutable_once:
        if (
            len(
                re.findall(
                    rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                    assignment_scope,
                    flags=re.MULTILINE,
                )
            )
            != 1
        ):
            snapshot_open = True
    for variable, _ in persistent_ids:
        started = variable[:-3] + "_STARTED_AT"
        next_started = variable[:-3] + "_NEXT_STARTED_AT"
        for snapshot_variable, expected_count in (
            (started, 2),
            (next_started, 1),
        ):
            if (
                len(
                    re.findall(
                        rf"^[ \t]*(?!#)[^\n]*\b{re.escape(snapshot_variable)}\+?=",
                        assignment_scope,
                        flags=re.MULTILINE,
                    )
                )
                != expected_count
            ):
                snapshot_open = True
    if snapshot_open:
        record("current-head-v13-snapshot-open")

    forbidden_commands = tuple(
        command
        for command in fresh_commands + journey_commands
        if "run --rm" in command
        or (
            command.startswith(("compose_v13 ", "docker "))
            and re.search(
                r"(?:^|\s)(?:create|pull|tag|down|rm)(?:\s|$)",
                command,
            )
        )
        or command.startswith("compose_v13 start ")
        or (command.startswith("docker start ") and command not in fresh_commands)
    )
    if forbidden_commands:
        record("current-head-v13-destructive-command-open")
    if re.search(
        r"^[ \t]*export[ \t]+[A-Za-z_][A-Za-z0-9_]*=.*\$\(",
        fresh + journey,
        flags=re.MULTILINE,
    ):
        record("current-head-v13-export-substitution-open")
    return tuple(failures)


def _current_head_backup_runbook_failures(
    runbook: str,
) -> tuple[str, ...]:
    """Require a source-bound, retained, one-shot current-head backup drill."""

    markers = (
        CURRENT_HEAD_BACKUP_RUNBOOK_START,
        "# BEGIN CURRENT_HEAD_V13_BACKUP",
        "# END CURRENT_HEAD_V13_BACKUP",
        CURRENT_HEAD_BACKUP_RUNBOOK_END,
    )
    if (
        any(runbook.count(marker) != 1 for marker in markers)
        or tuple(runbook.index(marker) for marker in markers)
        != tuple(sorted(runbook.index(marker) for marker in markers))
    ):
        return ("database-backup-source-runbook-open",)
    if not _current_head_v13_protocol_digest_matches(runbook):
        return ("database-backup-source-runbook-open",)
    source_backup = runbook.partition(CURRENT_HEAD_BACKUP_RUNBOOK_START)[
        2
    ].partition(CURRENT_HEAD_BACKUP_RUNBOOK_END)[0]
    required = (
        "# BEGIN CURRENT_HEAD_V13_BACKUP",
        "# END CURRENT_HEAD_V13_BACKUP",
        "set -eu",
        "set -o pipefail",
        'test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"',
        'test -z "${COMPOSE_PROJECT_NAME+x}"',
        'test -z "${COMPOSE_COMPATIBILITY+x}"',
        'test -z "${DESIRE_DB_PASSWORD_FILE+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"',
        'test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"',
        'DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"',
        '--env-file "$PWD/secrets/e2e-ten-account-v13/compose.env"',
        '-f "$PWD/compose.yaml"',
        '-f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml"',
        '-f "$PWD/deploy/postgres-operations.compose.yaml"',
        "--profile database-backup",
        'SOURCE_DATA_NETWORK="desire-supply-e2e-ten-account-v13_data"',
        'SOURCE_DATA_VOLUME="desire-supply-e2e-ten-account-v13_postgres-data"',
        'DESIRE_DATABASE_BACKUP_PARENT="$PWD/backups"',
        'DESIRE_DATABASE_BACKUP_SANDBOX_PARENT="$PWD/backups/internal-sandbox"',
        'DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"',
        "# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN",
        "# END CURRENT_HEAD_BACKUP_PARENT_CHAIN",
        'test ! -e "$DESIRE_DATABASE_BACKUP_DIR"',
        'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"',
        "umask 077",
        'mkdir -m 0700 -- "$DESIRE_DATABASE_BACKUP_DIR"',
        'DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"',
        'DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"',
        "export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID",
        "stat -f '%Lp|%u|%g'",
        'DESIRE_DATABASE_BACKUP_BASENAME="v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"',
        'index .Config.Labels "com.docker.compose.project"',
        'index .Config.Labels "com.docker.compose.service"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$SOURCE_DB_CONTAINER_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$SOURCE_API_CONTAINER_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"',
        'SOURCE_DB_CONTAINER_ID="$(compose_v13_backup ps --all --quiet db)"',
        'SOURCE_API_CONTAINER_ID="$(compose_v13_backup ps --all --quiet api)"',
        'index .Labels "com.docker.compose.network"',
        'index .Labels "com.docker.compose.volume"',
        "{{.State.Health.Status}}",
        'SOURCE_DB_STARTED_AT="$(docker inspect --format \'{{.State.StartedAt}}\' "$SOURCE_DB_CONTAINER_ID")"',
        'SOURCE_DB_RESTART_COUNT="$(docker inspect --format \'{{.RestartCount}}\' "$SOURCE_DB_CONTAINER_ID")"',
        'SOURCE_DB_IMAGE_ID="$(docker inspect --format \'{{.Image}}\' "$SOURCE_DB_CONTAINER_ID")"',
        'SOURCE_API_STARTED_AT="$(docker inspect --format \'{{.State.StartedAt}}\' "$SOURCE_API_CONTAINER_ID")"',
        'SOURCE_API_RESTART_COUNT="$(docker inspect --format \'{{.RestartCount}}\' "$SOURCE_API_CONTAINER_ID")"',
        'SOURCE_API_IMAGE_ID="$(docker inspect --format \'{{.Image}}\' "$SOURCE_API_CONTAINER_ID")"',
        'SOURCE_PLATFORM_TAG_ID="$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7")"',
        'test "$SOURCE_PLATFORM_TAG_ID" = "$SOURCE_API_IMAGE_ID"',
        'test "$SOURCE_DB_CONTAINER_ID" = "$DESIRE_E2E_DB_ID"',
        'test "$SOURCE_API_CONTAINER_ID" = "$DESIRE_E2E_API_ID"',
        'test "$SOURCE_DB_STARTED_AT" = "$DESIRE_E2E_DB_STARTED_AT"',
        'test "$SOURCE_API_STARTED_AT" = "$DESIRE_E2E_API_STARTED_AT"',
        'test "$SOURCE_DB_RESTART_COUNT" = "0"',
        'test "$SOURCE_API_RESTART_COUNT" = "0"',
        'test "$SOURCE_API_IMAGE_ID" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'test "$SOURCE_DATA_NETWORK_ID" = "$DESIRE_E2E_DATA_NETWORK_ID"',
        'test "$SOURCE_DATA_VOLUME_CREATED_AT" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"',
        'SOURCE_DATA_NETWORK_ID="$(docker network inspect --format \'{{.Id}}\' "$SOURCE_DATA_NETWORK")"',
        "NetworkSettings.Networks",
        'SOURCE_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format \'{{.CreatedAt}}\' "$SOURCE_DATA_VOLUME")"',
        "compose_v13_backup up -d --no-deps --no-build --no-recreate "
        "database-backup",
        "compose_v13_backup ps --all --quiet database-backup",
        'BACKUP_EXISTING_COMPOSE_IDS="$(compose_v13_backup ps --all --quiet database-backup)"',
        'BACKUP_EXISTING_NAME_MATCHES="$(docker container ls -a --format \'{{.Names}}\' | awk -v expected="${DESIRE_DATABASE_SOURCE_PROJECT}-database-backup-1" \'$0 == expected { print }\')"',
        'test -z "$BACKUP_EXISTING_COMPOSE_IDS"',
        'test -z "$BACKUP_EXISTING_NAME_MATCHES"',
        'BACKUP_CONTAINER_ID="$(compose_v13_backup ps --all --quiet database-backup)"',
        'BACKUP_WAIT_STATUS="$(docker wait "$BACKUP_CONTAINER_ID")"',
        'test "$BACKUP_WAIT_STATUS" = 0',
        '"exited|0|0"',
        "{{.State.ExitCode}}",
        "{{.RestartCount}}",
        'BACKUP_LOG="$(compose_v13_backup logs --no-color --no-log-prefix database-backup)"',
        'BACKUP_READY_COUNT="$(printf \'%s\\n\' "$BACKUP_LOG" | grep -Fo \'"status":"DATABASE_BACKUP_READY"\' | wc -l | tr -d \' \')"',
        'test "$BACKUP_LOG" = \'{"artifact":"v13-iam37-profile3-demand10-trust7-taxonomy2-drill01","status":"DATABASE_BACKUP_READY"}\'',
        "grep -Fo",
        '"$DESIRE_DATABASE_BACKUP_BASENAME.dump"',
        '"$DESIRE_DATABASE_BACKUP_BASENAME.facts.json"',
        '"$DESIRE_DATABASE_BACKUP_BASENAME.sha256"',
        'find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1',
        'stat -f \'%Lp|%u|%g|%l\' "$backup_artifact_path"',
        'test "$(compose_v13_backup ps --all --quiet api)" = "$SOURCE_API_CONTAINER_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DB_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$SOURCE_API_CONTAINER_ID")" = "$SOURCE_API_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7")" = "$SOURCE_API_IMAGE_ID"',
        "从任一 backup parent 创建或 leaf 目录创建开始",
        "项目、basename 和三份 artifact 永久锁定",
        "VCS 或 Docker build context",
        "不是加密或 offsite 保护",
    )
    parent_chain = source_backup.partition(
        "# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN"
    )[2].partition("# END CURRENT_HEAD_BACKUP_PARENT_CHAIN")[0]
    parent_required = (
        'for backup_parent_path in \\',
        '"$DESIRE_DATABASE_BACKUP_PARENT" \\',
        '"$DESIRE_DATABASE_BACKUP_SANDBOX_PARENT"',
        'if [ -e "$backup_parent_path" ] || [ -L "$backup_parent_path" ]; then',
        'mkdir -m 0700 -- "$backup_parent_path"',
        'test "$(stat -f \'%Lp|%u|%g\' "$backup_parent_path")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"',
    )
    parent_ordered_lines = (
        '"$DESIRE_DATABASE_BACKUP_PARENT" \\',
        '"$DESIRE_DATABASE_BACKUP_SANDBOX_PARENT"',
    )
    parent_order_closed = (
        all(fragment in parent_chain for fragment in parent_ordered_lines)
        and parent_chain.index(parent_ordered_lines[0])
        < parent_chain.index(parent_ordered_lines[1])
    )
    forbidden_parent_operation = any(
        fragment in source_backup
        for fragment in (
            "mkdir -p",
            "chmod -R",
            "chown -R",
            "chmod --recursive",
            "chown --recursive",
        )
    )
    commands = _bash_commands(source_backup)
    up_commands = tuple(
        command
        for command in commands
        if re.search(r"(?:^|\s)up(?:\s|$)", command)
    )
    forbidden_command = any(
        "run --rm" in command
        or re.search(r"(?:^|\s)create(?:\s|$)", command)
        or "--force-recreate" in command
        or re.search(
            r"(?:^|\s)(?:build|pull|tag|down|rm|restart|start|stop|kill|pause)(?:\s|$)",
            command,
        )
        for command in commands
    )
    coordinate_variables = (
        "DESIRE_DATABASE_SOURCE_PROJECT",
        "SOURCE_DATA_NETWORK",
        "SOURCE_DATA_VOLUME",
        "DESIRE_DATABASE_BACKUP_PARENT",
        "DESIRE_DATABASE_BACKUP_SANDBOX_PARENT",
        "DESIRE_DATABASE_BACKUP_DIR",
        "DESIRE_DATABASE_BACKUP_BASENAME",
        "DESIRE_DATABASE_OPERATIONS_UID",
        "DESIRE_DATABASE_OPERATIONS_GID",
    )
    coordinate_assignment_open = any(
        len(
            re.findall(
                rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                source_backup,
                flags=re.MULTILINE,
            )
        )
        != 1
        for variable in coordinate_variables
    )
    immutable_backup_variables = (
        "SOURCE_DB_CONTAINER_ID",
        "SOURCE_API_CONTAINER_ID",
        "SOURCE_DB_STARTED_AT",
        "SOURCE_DB_RESTART_COUNT",
        "SOURCE_DB_IMAGE_ID",
        "SOURCE_API_STARTED_AT",
        "SOURCE_API_RESTART_COUNT",
        "SOURCE_API_IMAGE_ID",
        "SOURCE_PLATFORM_TAG_ID",
        "SOURCE_DATA_NETWORK_ID",
        "SOURCE_DATA_VOLUME_CREATED_AT",
        "BACKUP_EXISTING_COMPOSE_IDS",
        "BACKUP_EXISTING_NAME_MATCHES",
        "original_umask",
        "BACKUP_CONTAINER_ID",
        "BACKUP_WAIT_STATUS",
        "BACKUP_LOG",
        "BACKUP_READY_COUNT",
        "backup_artifact_path",
    )
    immutable_assignment_open = any(
        len(
            re.findall(
                rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                source_backup,
                flags=re.MULTILINE,
            )
        )
        != 1
        for variable in immutable_backup_variables
    )
    exact_wrapper = _exact_bash_function(
        source_backup,
        "compose_v13_backup",
        'docker compose --project-name "$DESIRE_DATABASE_SOURCE_PROJECT" '
        '--env-file "$PWD/secrets/e2e-ten-account-v13/compose.env" '
        '-f "$PWD/compose.yaml" '
        '-f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml" '
        '-f "$PWD/deploy/postgres-operations.compose.yaml" '
        '--profile database-backup "$@"',
    )
    export_substitution = re.search(
        r"^[ \t]*export[ \t]+[A-Za-z_][A-Za-z0-9_]*=.*\$\(",
        source_backup,
        flags=re.MULTILINE,
    )
    if (
        not source_backup
        or source_backup.count("# BEGIN CURRENT_HEAD_V13_BACKUP") != 1
        or source_backup.count("# END CURRENT_HEAD_V13_BACKUP") != 1
        or any(fragment not in source_backup for fragment in required)
        or not parent_chain
        or any(fragment not in parent_chain for fragment in parent_required)
        or parent_chain.count('test -d "$backup_parent_path"') != 2
        or parent_chain.count('test ! -L "$backup_parent_path"') != 2
        or parent_chain.count('mkdir -m 0700 -- "$backup_parent_path"') != 1
        or parent_chain.count("stat -f '%Lp|%u|%g'") != 1
        or not parent_order_closed
        or forbidden_parent_operation
        or coordinate_assignment_open
        or immutable_assignment_open
        or not exact_wrapper
        or len(
            re.findall(
                r"^[ \t]*(?:function[ \t]+)?compose_v13_backup(?:[ \t]*\(\))?[ \t]*\{",
                source_backup,
                flags=re.MULTILINE,
            )
        )
        != 1
        or export_substitution is not None
        or source_backup.count("||") != 1
        or "&&" in source_backup
        or _has_unexpected_shell_hash(
            source_backup,
            allowed_lines=(
                "# BEGIN CURRENT_HEAD_V13_BACKUP",
                "# END CURRENT_HEAD_V13_BACKUP",
                "# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN",
                "# END CURRENT_HEAD_BACKUP_PARENT_CHAIN",
            ),
        )
        or re.search(
            r"(?:\|\|[ \t]*(?:true|:)(?:[ \t]*$)|"
            r";[ \t]*(?:true|:)(?:[ \t]*$)|^[ \t]*![ \t]+)",
            source_backup,
            flags=re.MULTILINE,
        )
        is not None
        or "--compatibility" in source_backup
        or "--build" in source_backup
        or "--pull" in source_backup
        or up_commands
        != (
            "compose_v13_backup up -d --no-deps --no-build --no-recreate "
            "database-backup",
        )
        or forbidden_command
        or "DESIRE_DATABASE_RESTORE_PROJECT" in source_backup
        or "desire-restore-verify-" in source_backup
        or "database-restore-" in source_backup
    ):
        return ("database-backup-source-runbook-open",)
    return ()


def _current_head_restore_runbook_failures(
    runbook: str,
) -> tuple[str, ...]:
    """Require one fresh no-build v13 restore with retained proof."""

    failures: list[str] = []

    def record(failure: str) -> None:
        if failure not in failures:
            failures.append(failure)

    markers = (
        CURRENT_HEAD_BACKUP_RUNBOOK_END,
        CURRENT_HEAD_RESTORE_PREFLIGHT_START,
        CURRENT_HEAD_RESTORE_PREFLIGHT_END,
        CURRENT_HEAD_RESTORE_EXECUTION_START,
        CURRENT_HEAD_RESTORE_EXECUTION_END,
        CURRENT_HEAD_RESTORE_POSTRUN_START,
        CURRENT_HEAD_RESTORE_POSTRUN_END,
        CURRENT_HEAD_RESTORE_AUTHORITY_START,
        CURRENT_HEAD_RESTORE_AUTHORITY_END,
        CURRENT_HEAD_RESTORE_RUNBOOK_END,
    )
    if (
        any(runbook.count(marker) != 1 for marker in markers)
        or tuple(runbook.index(marker) for marker in markers)
        != tuple(sorted(runbook.index(marker) for marker in markers))
    ):
        return ("database-restore-runbook-markers-open",)
    if not _current_head_v13_protocol_digest_matches(runbook):
        record("database-restore-protocol-digest-open")

    runbook_lines = runbook.splitlines(keepends=True)
    authority_starts = tuple(
        index
        for index, line in enumerate(runbook_lines)
        if line.rstrip("\r\n") == CURRENT_HEAD_RESTORE_AUTHORITY_START
    )
    authority_ends = tuple(
        index
        for index, line in enumerate(runbook_lines)
        if line.rstrip("\r\n") == CURRENT_HEAD_RESTORE_AUTHORITY_END
    )
    if (
        len(authority_starts) != 1
        or len(authority_ends) != 1
        or authority_ends[0] < authority_starts[0]
        or hashlib.sha256(
            "".join(
                runbook_lines[authority_starts[0] : authority_ends[0] + 1]
            ).encode("utf-8")
        ).hexdigest()
        != CURRENT_HEAD_RESTORE_AUTHORITY_SHA256
    ):
        record("database-restore-offsite-authority-open")
    restore = runbook.partition(CURRENT_HEAD_BACKUP_RUNBOOK_END)[2].partition(
        CURRENT_HEAD_RESTORE_RUNBOOK_END
    )[0]
    preflight = restore.partition(CURRENT_HEAD_RESTORE_PREFLIGHT_START)[
        2
    ].partition(CURRENT_HEAD_RESTORE_PREFLIGHT_END)[0]
    execution = restore.partition(CURRENT_HEAD_RESTORE_EXECUTION_START)[
        2
    ].partition(CURRENT_HEAD_RESTORE_EXECUTION_END)[0]
    postrun = restore.partition(CURRENT_HEAD_RESTORE_POSTRUN_START)[2].partition(
        CURRENT_HEAD_RESTORE_POSTRUN_END
    )[0]

    artifact_required = (
        "set -eu",
        "set -o pipefail",
        'test -z "${COMPOSE_PROJECT_NAME+x}"',
        'test -z "${COMPOSE_COMPATIBILITY+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"',
        'test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"',
        'test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"',
        'test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"',
        'export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"',
        'export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill01"',
        'export DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"',
        'export DESIRE_DATABASE_BACKUP_BASENAME="v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"',
        'export DESIRE_DB_PASSWORD_FILE="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/db_superuser_password.txt"',
        'export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"',
        'export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"',
        'DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"',
        'DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"',
        "export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID",
        'test -f "$DESIRE_DB_PASSWORD_FILE"',
        'test ! -L "$DESIRE_DB_PASSWORD_FILE"',
        'test -s "$DESIRE_DB_PASSWORD_FILE"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$DESIRE_DB_PASSWORD_FILE")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"',
        'test -d "$DESIRE_DATABASE_BACKUP_DIR"',
        'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"',
        'test "$(stat -f \'%Lp|%u|%g\' "$DESIRE_DATABASE_BACKUP_DIR")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"',
        'test "$(find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d \' \')" = 3',
        'for restore_artifact_name in \\',
        '"$DESIRE_DATABASE_BACKUP_BASENAME.dump" \\',
        '"$DESIRE_DATABASE_BACKUP_BASENAME.facts.json" \\',
        '"$DESIRE_DATABASE_BACKUP_BASENAME.sha256"',
        'restore_artifact_path="$DESIRE_DATABASE_BACKUP_DIR/$restore_artifact_name"',
        'test -f "$restore_artifact_path"',
        'test ! -L "$restore_artifact_path"',
        'test -s "$restore_artifact_path"',
        'test "$(stat -f \'%Lp|%u|%g|%l\' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"',
        'DESIRE_DATABASE_RESTORE_DUMP_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.dump"',
        'DESIRE_DATABASE_RESTORE_FACTS_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.facts.json"',
        'DESIRE_DATABASE_RESTORE_MANIFEST_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.sha256"',
        "DESIRE_DATABASE_RESTORE_DUMP_STAT=\"$(stat -f "
        "'%Lp|%u|%g|%z|%m|%c|%i|%l' "
        "\"$DESIRE_DATABASE_RESTORE_DUMP_PATH\")\"",
        "DESIRE_DATABASE_RESTORE_FACTS_STAT=\"$(stat -f "
        "'%Lp|%u|%g|%z|%m|%c|%i|%l' "
        "\"$DESIRE_DATABASE_RESTORE_FACTS_PATH\")\"",
        "DESIRE_DATABASE_RESTORE_MANIFEST_STAT=\"$(stat -f "
        "'%Lp|%u|%g|%z|%m|%c|%i|%l' "
        "\"$DESIRE_DATABASE_RESTORE_MANIFEST_PATH\")\"",
        "DESIRE_DATABASE_RESTORE_DUMP_SHA256=\"$(shasum -a 256 "
        "\"$DESIRE_DATABASE_RESTORE_DUMP_PATH\" | awk '{print $1}')\"",
        "DESIRE_DATABASE_RESTORE_FACTS_SHA256=\"$(shasum -a 256 "
        "\"$DESIRE_DATABASE_RESTORE_FACTS_PATH\" | awk '{print $1}')\"",
        "DESIRE_DATABASE_RESTORE_MANIFEST_SHA256=\"$(shasum -a 256 "
        "\"$DESIRE_DATABASE_RESTORE_MANIFEST_PATH\" | awk '{print $1}')\"",
        'test -n "$DESIRE_DATABASE_RESTORE_DUMP_STAT"',
        'test -n "$DESIRE_DATABASE_RESTORE_FACTS_STAT"',
        'test -n "$DESIRE_DATABASE_RESTORE_MANIFEST_STAT"',
        'test -n "$DESIRE_DATABASE_RESTORE_DUMP_SHA256"',
        'test -n "$DESIRE_DATABASE_RESTORE_FACTS_SHA256"',
        'test -n "$DESIRE_DATABASE_RESTORE_MANIFEST_SHA256"',
    )
    coordinate_guards = (
        'test "$DESIRE_DATABASE_SOURCE_PROJECT" = "desire-supply-e2e-ten-account-v13"',
        'test "$DESIRE_DATABASE_RESTORE_PROJECT" = "desire-restore-verify-v13drill01"',
        'test "$DESIRE_DATABASE_BACKUP_DIR" = "/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"',
        'test "$DESIRE_DATABASE_BACKUP_BASENAME" = "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"',
        'test "$DESIRE_DB_PASSWORD_FILE" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/db_superuser_password.txt"',
        'test "$DESIRE_IMAGE_TAG" = "e2e-ten-account-v13-iam37-demand10-trust7"',
        'test "$DESIRE_DATABASE_RESTORE_SUBNET" = "172.16.232.0/24"',
    )
    coordinate_variables = (
        "DESIRE_DATABASE_SOURCE_PROJECT",
        "DESIRE_DATABASE_RESTORE_PROJECT",
        "DESIRE_DATABASE_BACKUP_DIR",
        "DESIRE_DATABASE_BACKUP_BASENAME",
        "DESIRE_DB_PASSWORD_FILE",
        "DESIRE_IMAGE_TAG",
        "DESIRE_DATABASE_RESTORE_SUBNET",
        "DESIRE_DATABASE_OPERATIONS_UID",
        "DESIRE_DATABASE_OPERATIONS_GID",
    )
    artifact_counts = (
        "set -eu",
        "set -o pipefail",
        'test -f "$DESIRE_DB_PASSWORD_FILE"',
        'test ! -L "$DESIRE_DB_PASSWORD_FILE"',
        'test -d "$DESIRE_DATABASE_BACKUP_DIR"',
        'test ! -L "$DESIRE_DATABASE_BACKUP_DIR"',
        'test -f "$restore_artifact_path"',
        'test ! -L "$restore_artifact_path"',
        'test -s "$restore_artifact_path"',
    )
    if (
        any(fragment not in preflight for fragment in artifact_required)
        or any(fragment not in preflight for fragment in coordinate_guards)
        or any(
            len(
                re.findall(
                    rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                    restore,
                    flags=re.MULTILINE,
                )
            )
            != 1
            for variable in coordinate_variables
        )
        or any(preflight.count(fragment) != 1 for fragment in artifact_counts)
        or any(token in preflight for token in ("<absolute", "<unique", "<reviewed"))
        or any(
            forbidden in preflight
            for forbidden in ("mkdir ", "chmod ", "chown ", "run --rm")
        )
        or "--compatibility" in preflight + execution + postrun
        or "--build" in preflight + execution + postrun
        or "--pull" in preflight + execution + postrun
        or re.search(
            r"^[ \t]*export[ \t]+[A-Za-z_][A-Za-z0-9_]*=.*\$\(",
            preflight + execution + postrun,
            flags=re.MULTILINE,
        )
        is not None
        or "||" in preflight + execution + postrun
        or "&&" in preflight + execution + postrun
        or _has_unexpected_shell_hash(preflight + execution + postrun)
        or re.search(
            r"(?:;[ \t]*(?:true|:)(?:[ \t]*$)|^[ \t]*![ \t]+)",
            preflight + execution + postrun,
            flags=re.MULTILINE,
        )
        is not None
    ):
        record("database-restore-artifact-revalidation-runbook-open")

    namespace_required = (
        'DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}-"',
        'DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}_"',
        'DESIRE_DATABASE_RESTORE_COMPOSE_CONTAINER_IDS="$(compose_v13_restore ps --all --quiet)"',
        'DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"',
        'DESIRE_DATABASE_RESTORE_PROJECT_NETWORK_IDS="$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"',
        'DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS="$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"',
        'DESIRE_DATABASE_RESTORE_ALL_CONTAINER_NAMES="$(docker container ls -a --format \'{{.Names}}\')"',
        'DESIRE_DATABASE_RESTORE_ALL_NETWORK_NAMES="$(docker network ls --format \'{{.Name}}\')"',
        'DESIRE_DATABASE_RESTORE_ALL_VOLUME_NAMES="$(docker volume ls --format \'{{.Name}}\')"',
        'DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES="$(printf \'%s\\n\' "$DESIRE_DATABASE_RESTORE_ALL_CONTAINER_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'DESIRE_DATABASE_RESTORE_NETWORK_PREFIX_MATCHES="$(printf \'%s\\n\' "$DESIRE_DATABASE_RESTORE_ALL_NETWORK_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES="$(printf \'%s\\n\' "$DESIRE_DATABASE_RESTORE_ALL_VOLUME_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX" \'index($0, prefix) == 1 { print }\')"',
        'test -z "$DESIRE_DATABASE_RESTORE_COMPOSE_CONTAINER_IDS"',
        'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS"',
        'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_NETWORK_IDS"',
        'test -z "$DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS"',
        'test -z "$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES"',
        'test -z "$DESIRE_DATABASE_RESTORE_NETWORK_PREFIX_MATCHES"',
        'test -z "$DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES"',
    )
    if any(
        preflight.count(fragment) != 1 for fragment in namespace_required
    ):
        record("database-restore-fresh-namespace-runbook-open")

    source_required = (
        "compose_v13_restore_source() {",
        '--project-name "$DESIRE_DATABASE_SOURCE_PROJECT"',
        '--env-file "$PWD/secrets/e2e-ten-account-v13/compose.env"',
        '-f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml" "$@"',
        "compose_v13_restore() {",
        '--project-name "$DESIRE_DATABASE_RESTORE_PROJECT"',
        '-f "$PWD/deploy/postgres-operations.compose.yaml"',
        "--profile database-restore-verify",
        "compose_v13_restore_source config --quiet",
        "compose_v13_restore config --quiet",
        'test "$(compose_v13_restore_source ps --all --quiet db | wc -l | tr -d \' \')" = 1',
        'test "$(compose_v13_restore_source ps --all --quiet api | wc -l | tr -d \' \')" = 1',
        'DESIRE_DATABASE_RESTORE_SOURCE_DB_ID="$(compose_v13_restore_source ps --all --quiet db)"',
        'DESIRE_DATABASE_RESTORE_SOURCE_API_ID="$(compose_v13_restore_source ps --all --quiet api)"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "running|healthy|0"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "running|healthy|0"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT="$(docker inspect --format \'{{.State.StartedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT="$(docker inspect --format \'{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT="$(docker inspect --format \'{{.State.StartedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT="$(docker inspect --format \'{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID="$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID="$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID="$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID" = "$SOURCE_DB_CONTAINER_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID" = "$DESIRE_E2E_DB_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID" = "$SOURCE_API_CONTAINER_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID" = "$DESIRE_E2E_API_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT" = "$SOURCE_DB_STARTED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT" = "$DESIRE_E2E_DB_STARTED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT" = "$SOURCE_DB_RESTART_COUNT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT" = "$SOURCE_API_STARTED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT" = "$DESIRE_E2E_API_STARTED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT" = "$SOURCE_API_RESTART_COUNT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID" = "$SOURCE_DB_IMAGE_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID" = "$SOURCE_API_IMAGE_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK="${DESIRE_DATABASE_SOURCE_PROJECT}_data"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME="${DESIRE_DATABASE_SOURCE_PROJECT}_postgres-data"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID="$(docker network inspect --format \'{{.Id}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")"',
        'DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format \'{{.CreatedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID" = "$SOURCE_DATA_NETWORK_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID" = "$DESIRE_E2E_DATA_NETWORK_ID"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT" = "$SOURCE_DATA_VOLUME_CREATED_AT"',
        'test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"',
        'test "$(docker network inspect --format \'{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.network" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")" = "$DESIRE_DATABASE_SOURCE_PROJECT|data"',
        'test "$(docker volume inspect --format \'{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")" = "$DESIRE_DATABASE_SOURCE_PROJECT|postgres-data"',
        'test "$(docker inspect --format \'{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"',
        'test "$(docker inspect --format \'{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "volume|$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME"',
    )
    exact_source_wrapper = _exact_bash_function(
        preflight,
        "compose_v13_restore_source",
        'docker compose --project-name "$DESIRE_DATABASE_SOURCE_PROJECT" '
        '--env-file "$PWD/secrets/e2e-ten-account-v13/compose.env" '
        '-f "$PWD/compose.yaml" '
        '-f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml" "$@"',
    )
    exact_restore_wrapper = _exact_bash_function(
        preflight,
        "compose_v13_restore",
        'docker compose --project-name "$DESIRE_DATABASE_RESTORE_PROJECT" '
        '-f "$PWD/compose.yaml" '
        '-f "$PWD/deploy/postgres-operations.compose.yaml" '
        '--profile database-restore-verify "$@"',
    )
    if (
        any(fragment not in preflight for fragment in source_required)
        or not exact_source_wrapper
        or not exact_restore_wrapper
        or len(
            re.findall(
                r"^[ \t]*(?:function[ \t]+)?compose_v13_restore_source(?:[ \t]*\(\))?[ \t]*\{",
                restore,
                flags=re.MULTILINE,
            )
        )
        != 1
        or len(
            re.findall(
                r"^[ \t]*(?:function[ \t]+)?compose_v13_restore(?:[ \t]*\(\))?[ \t]*\{",
                restore,
                flags=re.MULTILINE,
            )
        )
        != 1
    ):
        record("database-restore-source-image-runbook-open")

    expected_execution_commands = (
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        "compose_v13_restore up -d --no-build --no-recreate database-restore-replay",
        'DESIRE_DATABASE_RESTORE_REPLAY_ID="$(compose_v13_restore ps --all --quiet database-restore-replay)"',
        'test -n "$DESIRE_DATABASE_RESTORE_REPLAY_ID"',
        'test "$(docker wait "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "0"',
    )
    execution_commands = _bash_commands(f"```bash\n{execution}\n```")
    all_commands = _bash_commands(f"```bash\n{preflight}\n{execution}\n{postrun}\n```")
    up_commands = tuple(
        command
        for command in all_commands
        if re.search(r"(?:^|\s)up(?:\s|$)", command)
    )
    forbidden_commands = tuple(
        command
        for command in all_commands
        if "run --rm" in command
        or re.search(r"(?:^|\s)create(?:\s|$)", command)
        or re.search(
            r"(?:^|\s)(?:build|pull|tag|down|rm|restart|start|stop)(?:\s|$)",
            command,
        )
    )
    if (
        execution_commands != expected_execution_commands
        or up_commands != (expected_execution_commands[1],)
        or forbidden_commands
    ):
        record("database-restore-execution-runbook-open")

    resource_required = (
        'test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d \'[:space:]\')" = "4"',
        'test "$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "4"',
        'test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
        'test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d \'[:space:]\')" = "1"',
        'DESIRE_DATABASE_RESTORE_TARGET_ID="$(compose_v13_restore ps --all --quiet database-restore-target)"',
        'DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID="$(compose_v13_restore ps --all --quiet database-restore-bootstrap)"',
        'DESIRE_DATABASE_RESTORE_VERIFY_ID="$(compose_v13_restore ps --all --quiet database-restore-verify)"',
        'test -n "$DESIRE_DATABASE_RESTORE_TARGET_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_VERIFY_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_REPLAY_ID"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "running|healthy|0"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "exited|0|0"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "exited|0|0"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "exited|0|0"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID="$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_TARGET_ID")"',
        'test -n "$DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "$DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID"',
        'DESIRE_DATABASE_RESTORE_NETWORK="${DESIRE_DATABASE_RESTORE_PROJECT}_database-restore-verification"',
        'DESIRE_DATABASE_RESTORE_VOLUME="${DESIRE_DATABASE_RESTORE_PROJECT}_postgres-restore-verification-data"',
        'DESIRE_DATABASE_RESTORE_NETWORK_ID="$(docker network inspect --format \'{{.Id}}\' "$DESIRE_DATABASE_RESTORE_NETWORK")"',
        'DESIRE_DATABASE_RESTORE_VOLUME_CREATED_AT="$(docker volume inspect --format \'{{.CreatedAt}}\' "$DESIRE_DATABASE_RESTORE_VOLUME")"',
        'test -n "$DESIRE_DATABASE_RESTORE_NETWORK_ID"',
        'test -n "$DESIRE_DATABASE_RESTORE_VOLUME_CREATED_AT"',
        'test "$(docker network inspect --format \'{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.network" }}\' "$DESIRE_DATABASE_RESTORE_NETWORK")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-verification"',
        'test "$(docker network inspect --format \'{{.Internal}}|{{len .IPAM.Config}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}\' "$DESIRE_DATABASE_RESTORE_NETWORK")" = "true|1|$DESIRE_DATABASE_RESTORE_SUBNET"',
        'test "$(docker volume inspect --format \'{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}\' "$DESIRE_DATABASE_RESTORE_VOLUME")" = "$DESIRE_DATABASE_RESTORE_PROJECT|postgres-restore-verification-data"',
        'test "$(docker inspect --format \'{{with index .NetworkSettings.Networks "desire-restore-verify-v13drill01_database-restore-verification"}}{{.NetworkID}}{{end}}\' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "$DESIRE_DATABASE_RESTORE_NETWORK_ID"',
        'test "$(docker inspect --format \'{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}\' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "volume|$DESIRE_DATABASE_RESTORE_VOLUME"',
    )
    restore_service_identifiers = (
        ("database-restore-target", "DESIRE_DATABASE_RESTORE_TARGET_ID"),
        ("database-restore-bootstrap", "DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID"),
        ("database-restore-verify", "DESIRE_DATABASE_RESTORE_VERIFY_ID"),
        ("database-restore-replay", "DESIRE_DATABASE_RESTORE_REPLAY_ID"),
    )
    resource_name_commands = tuple(
        f'test "$(docker inspect --format \'{{{{.Name}}}}\' "${identifier}")" = '
        f'"/${{DESIRE_DATABASE_RESTORE_PROJECT}}-{service}-1"'
        for service, identifier in restore_service_identifiers
    )
    resource_label_commands = tuple(
        "test \"$(docker inspect --format "
        "'{{ index .Config.Labels \"com.docker.compose.project\" }}|"
        "{{ index .Config.Labels \"com.docker.compose.service\" }}' "
        f'"${identifier}")" = '
        f'"$DESIRE_DATABASE_RESTORE_PROJECT|{service}"'
        for service, identifier in restore_service_identifiers
    )
    for service, identifier in restore_service_identifiers:
        if (
            resource_name_commands[
                restore_service_identifiers.index((service, identifier))
            ]
            not in postrun
            or resource_label_commands[
                restore_service_identifiers.index((service, identifier))
            ]
            not in postrun
        ):
            record("database-restore-postrun-resource-open")
    if any(fragment not in postrun for fragment in resource_required):
        record("database-restore-postrun-resource-open")

    evidence_required = (
        'DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-bootstrap)"',
        'DESIRE_DATABASE_RESTORE_VERIFY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-verify)"',
        'DESIRE_DATABASE_RESTORE_REPLAY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-replay)"',
        'test "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP"',
        'test "$DESIRE_DATABASE_RESTORE_VERIFY_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY"',
        'test "$DESIRE_DATABASE_RESTORE_REPLAY_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY"',
        'test "$(find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d \' \')" = "3"',
        'test "$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")" = "$DESIRE_DATABASE_RESTORE_DUMP_STAT"',
        'test "$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_FACTS_PATH")" = "$DESIRE_DATABASE_RESTORE_FACTS_STAT"',
        'test "$(stat -f \'%Lp|%u|%g|%z|%m|%c|%i|%l\' "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH")" = "$DESIRE_DATABASE_RESTORE_MANIFEST_STAT"',
        'test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_DUMP_PATH" | awk \'{print $1}\')" = "$DESIRE_DATABASE_RESTORE_DUMP_SHA256"',
        'test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_FACTS_PATH" | awk \'{print $1}\')" = "$DESIRE_DATABASE_RESTORE_FACTS_SHA256"',
        'test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH" | awk \'{print $1}\')" = "$DESIRE_DATABASE_RESTORE_MANIFEST_SHA256"',
        'test "$(compose_v13_restore_source ps --all --quiet db)" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID"',
        'test "$(compose_v13_restore_source ps --all --quiet api)" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"',
        'test "$(docker inspect --format \'{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "running|healthy|0"',
        'test "$(docker inspect --format \'{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "running|healthy|0"',
        'test "$(docker inspect --format \'{{.State.StartedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT"',
        'test "$(docker inspect --format \'{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT"',
        'test "$(docker inspect --format \'{{.State.StartedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT"',
        'test "$(docker inspect --format \'{{.RestartCount}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID"',
        'test "$(docker inspect --format \'{{.Image}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'test "$(docker image inspect --format \'{{.Id}}\' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"',
        'test "$(docker network inspect --format \'{{.Id}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"',
        'test "$(docker volume inspect --format \'{{.CreatedAt}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT"',
        'test "$(docker inspect --format \'{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"',
        'test "$(docker inspect --format \'{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}\' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "volume|$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME"',
    )
    if any(fragment not in postrun for fragment in evidence_required):
        record("database-restore-postrun-evidence-open")

    expected_postrun_commands = (
        resource_required[:11]
        + resource_name_commands
        + resource_label_commands
        + resource_required[11:]
        + evidence_required
    )
    if _bash_commands(f"```bash\n{postrun}\n```") != expected_postrun_commands:
        record("database-restore-postrun-sequence-open")

    immutable_restore_variables = (
        "DESIRE_DATABASE_RESTORE_DUMP_PATH",
        "DESIRE_DATABASE_RESTORE_FACTS_PATH",
        "DESIRE_DATABASE_RESTORE_MANIFEST_PATH",
        "DESIRE_DATABASE_RESTORE_DUMP_STAT",
        "DESIRE_DATABASE_RESTORE_FACTS_STAT",
        "DESIRE_DATABASE_RESTORE_MANIFEST_STAT",
        "DESIRE_DATABASE_RESTORE_DUMP_SHA256",
        "DESIRE_DATABASE_RESTORE_FACTS_SHA256",
        "DESIRE_DATABASE_RESTORE_MANIFEST_SHA256",
        "DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP",
        "DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY",
        "DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY",
        "DESIRE_DATABASE_RESTORE_SOURCE_DB_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_API_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT",
        "DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT",
        "DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT",
        "DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT",
        "DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK",
        "DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME",
        "DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID",
        "DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT",
        "DESIRE_DATABASE_RESTORE_REPLAY_ID",
        "DESIRE_DATABASE_RESTORE_TARGET_ID",
        "DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID",
        "DESIRE_DATABASE_RESTORE_VERIFY_ID",
        "DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID",
        "DESIRE_DATABASE_RESTORE_NETWORK",
        "DESIRE_DATABASE_RESTORE_VOLUME",
        "DESIRE_DATABASE_RESTORE_NETWORK_ID",
        "DESIRE_DATABASE_RESTORE_VOLUME_CREATED_AT",
        "DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG",
        "DESIRE_DATABASE_RESTORE_VERIFY_LOG",
        "DESIRE_DATABASE_RESTORE_REPLAY_LOG",
    )
    if any(
        len(
            re.findall(
                rf"^[ \t]*(?!#)[^\n]*\b{re.escape(variable)}\+?=",
                restore,
                flags=re.MULTILINE,
            )
        )
        != 1
        for variable in immutable_restore_variables
    ):
        record("database-restore-immutable-evidence-open")

    expected_fresh_catalogs = {
        "demand": {"applied_versions": list(range(1, 11)), "skipped_versions": []},
        "iam": {"applied_versions": list(range(38)), "skipped_versions": []},
        "profile": {"applied_versions": list(range(1, 4)), "skipped_versions": []},
        "taxonomy": {"applied_versions": list(range(1, 3)), "skipped_versions": []},
        "trust": {"applied_versions": list(range(1, 8)), "skipped_versions": []},
    }
    expected_replay_catalogs = {
        name: {"applied_versions": [], "skipped_versions": value["applied_versions"]}
        for name, value in expected_fresh_catalogs.items()
    }

    def assigned_json(name: str) -> Any:
        matches = re.findall(
            rf"^{re.escape(name)}='([^']+)'$",
            preflight,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            return None
        try:
            return json.loads(matches[0])
        except (json.JSONDecodeError, TypeError):
            return None

    if (
        assigned_json("DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP")
        != {"catalogs": expected_fresh_catalogs, "status": "SCHEMA_READY"}
        or assigned_json("DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY")
        != {
            "artifact": "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01",
            "status": "DATABASE_RESTORE_VERIFIED",
        }
        or assigned_json("DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY")
        != {"catalogs": expected_replay_catalogs, "status": "SCHEMA_READY"}
    ):
        record("database-restore-postrun-evidence-open")
    normalized_restore = " ".join(restore.split())
    offsite_authority_closure = (
        "本机 drill 的 custom dump、facts JSON 和 manifest 仍是明文 artifact；"
        "`.sha256` 只是未签名 SHA-256 完整性记录，不是加密、签名或 MAC。"
        "在获得明确的 `recipient/KMS/tool/destination authority` 前，不得实现或宣称 "
        "encrypted/offsite backup； 加密离机备份仍等待有权操作者明确指定 recipient、"
        "KMS、tool 与 destination。"
    )
    authority_tail = (
        f"{CURRENT_HEAD_RESTORE_AUTHORITY_END}\n\n"
        "2026-08-19 已完成一次 v9 逻辑 backup → fresh isolated-volume restore 动态演练。"
    )
    sensitive_token_counts = {
        "encrypted/offsite backup": 1,
        "recipient/KMS/tool/destination authority": 1,
        "加密离机备份": 1,
        "authority": 1,
    }
    if (
        normalized_restore.count(offsite_authority_closure) != 1
        or authority_tail not in restore
        or any(
            restore.count(token) != count
            for token, count in sensitive_token_counts.items()
        )
    ):
        record("database-restore-offsite-authority-open")
    return tuple(failures)


def _backup_artifact_exclusion_failures(
    gitignore: str,
    dockerignore: str,
) -> tuple[str, ...]:
    """Require one exact repo-root backup exclusion in VCS and build context."""

    failures: list[str] = []
    for label, document in (
        ("gitignore", gitignore),
        ("docker-context", dockerignore),
    ):
        active_rules = tuple(
            line.strip()
            for line in document.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        backup_rules = tuple(
            rule for rule in active_rules if "backups" in rule
        )
        if (
            active_rules.count(BACKUP_IGNORE_RULE) != 1
            or backup_rules != (BACKUP_IGNORE_RULE,)
        ):
            failures.append(f"database-backup-{label}-open")
    return tuple(failures)


def _postgres_restore_closure_failures(
    operations: dict[str, Any],
    operations_compose: str,
    operations_script: str,
) -> tuple[str, ...]:
    """Close destructive-restore, isolated-network, and replay evidence gaps."""

    failures: list[str] = []
    empty_target = operations_script.partition(
        "_require_empty_restore_target() {"
    )[2].partition("\n}\n\n_restore_verify()")[0]
    for relation in DATABASE_RESTORE_EMPTY_TARGET_RELATIONS:
        if empty_target.count(f"SELECT count(*) FROM {relation}") != 1:
            failures.append(f"database-restore-empty-target-open:{relation}")

    networks = operations.get("networks", {})
    restore_network = (
        networks.get("database-restore-verification", {})
        if isinstance(networks, dict)
        else {}
    )
    if not isinstance(restore_network, dict):
        restore_network = {}
    ipam = restore_network.get("ipam", {})
    ipam_config = ipam.get("config", []) if isinstance(ipam, dict) else []
    network_ipam_closed = (
        restore_network.get("internal") is True
        and isinstance(ipam_config, list)
        and len(ipam_config) == 1
        and isinstance(ipam_config[0], dict)
        and set(ipam_config[0]) == {"subnet"}
    )
    if network_ipam_closed:
        try:
            restore_subnet = ipaddress.ip_network(
                ipam_config[0]["subnet"], strict=True
            )
        except (TypeError, ValueError):
            network_ipam_closed = False
        else:
            network_ipam_closed = (
                isinstance(restore_subnet, ipaddress.IPv4Network)
                and restore_subnet.prefixlen == 24
                and any(
                    restore_subnet.subnet_of(private_network)
                    for private_network in DEVCONTAINER_RFC1918_NETWORKS
                )
            )
    if not network_ipam_closed:
        failures.append("database-restore-network-ipam-open")

    raw_network = operations_compose.partition("\nnetworks:\n")[2].partition(
        "\nvolumes:\n"
    )[0]
    raw_subnet = f"subnet: {DATABASE_RESTORE_SUBNET_EXPRESSION}"
    if (
        raw_network.count("database-restore-verification:") != 1
        or raw_network.count("internal: true") != 1
        or raw_network.count(raw_subnet) != 1
        or any(
            forbidden in raw_network
            for forbidden in ("gateway:", "name:", "external:")
        )
    ):
        failures.append("database-restore-network-raw-open")

    services = operations.get("services", {})
    if not isinstance(services, dict):
        services = {}
    bootstrap = services.get("database-restore-bootstrap", {})
    replay = services.get("database-restore-replay", {})
    if not isinstance(bootstrap, dict):
        bootstrap = {}
    if not isinstance(replay, dict):
        replay = {}
    if _dependency_conditions(replay) != {
        "database-restore-verify": "service_completed_successfully"
    }:
        failures.append("database-restore-replay-order-open")

    replay_environment = {
        "DESIRE_DEPLOYMENT_MODE": "INTERNAL_SANDBOX",
        "DESIRE_EXTERNAL_PARTICIPANTS_ENABLED": "false",
        "DESIRE_DATABASE_HOST": "db",
        "DESIRE_DATABASE_NAME": "desire_restore_verify",
        "DESIRE_DATABASE_ADMIN_USER": "postgres",
        "DESIRE_DATABASE_PASSWORD_FILE": (
            "/run/secrets/db_superuser_password"
        ),
    }
    if (
        replay.get("profiles") != ["database-restore-verify"]
        or replay.get("command")
        != ["python", "-m", "desire_platform.deployment"]
        or replay.get("environment") != replay_environment
        or replay.get("environment") != bootstrap.get("environment")
        or replay.get("build") != bootstrap.get("build")
        or replay.get("image") != bootstrap.get("image")
        or _secret_sources(replay) != ("db_superuser_password",)
        or set(replay.get("networks", {}))
        != {"database-restore-verification"}
        or replay.get("read_only") is not True
        or replay.get("init") is not True
        or replay.get("restart") != "no"
        or replay.get("cap_drop") != ["ALL"]
        or replay.get("security_opt") != ["no-new-privileges=true"]
        or replay.get("tmpfs")
        != ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
        or bool(replay.get("ports"))
        or bool(replay.get("volumes"))
        or bool(replay.get("configs"))
        or bool(replay.get("privileged"))
    ):
        failures.append("database-restore-replay-contract-open")
    return tuple(failures)


def _compose(
    root: Path,
    *filenames: str,
    profiles: tuple[str, ...] = (),
) -> dict[str, Any]:
    command = ["docker", "compose"]
    for filename in filenames:
        command.extend(("-f", filename))
    for profile in profiles:
        command.extend(("--profile", profile))
    command.extend(("config", "--format", "json"))
    completed = subprocess.run(
        command,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        raise TypeError("compose config is not an object")
    return parsed


def _has_cap_drop_all(service: dict[str, Any]) -> bool:
    return "ALL" in service.get("cap_drop", [])


def verify(root: Path) -> tuple[str, ...]:
    failures: list[str] = []
    if (
        len(API_SECRETS) != 43
        or len(MATCHING_RUNTIME_SECRETS) != 11
        or len(ONLINE_SECRETS) != 53
        or len(set(ONLINE_SECRETS)) != 53
    ):
        failures.append("runtime-secret-contract-open")
    required = (
        "Dockerfile",
        "compose.yaml",
        "compose.dev.yaml",
        ".gitignore",
        ".dockerignore",
        ".devcontainer/devcontainer.json",
        "deploy/Caddyfile",
        "deploy/devcontainer-entrypoint.sh",
        "deploy/devcontainer-post-create.sh",
        "deploy/devcontainer-runtime-closure.sh",
        "deploy/devcontainer-toolchain-check.sh",
        "deploy/postgres-operations.compose.yaml",
        "deploy/postgres-backup-restore.sh",
        "deploy/postgres-core-facts.sql",
        "scripts/manage_internal_sandbox_tls.py",
        DOCKER_HUB_MANIFEST_PREFLIGHT_RELATIVE_PATH,
        "scripts/run_internal_sandbox_e2e.py",
        "platform/examples/internal-sandbox-identity-bootstrap-template-v1.json",
        "platform/src/desire_platform/deployment/migrations.py",
        "platform/src/desire_platform/deployment/identity_bootstrap_orchestrator.py",
        "platform/src/desire_platform/synthetic_oidc/__main__.py",
        "docs/operations/container-deployment.md",
        "docs/operations/run-and-check.md",
        "docs/development/dev-container.md",
    )
    for relative in required:
        if not (root / relative).is_file():
            failures.append(f"missing:{relative}")
    for relative, expected_sha256 in REVIEWED_CONTAINER_ARTIFACT_SHA256:
        artifact_path = root / relative
        if not artifact_path.is_file():
            continue
        try:
            observed_sha256 = hashlib.sha256(
                artifact_path.read_bytes()
            ).hexdigest()
        except OSError:
            failures.append(
                f"reviewed-container-artifact-unreadable:{relative}"
            )
        else:
            if observed_sha256 != expected_sha256:
                failures.append(
                    f"reviewed-container-artifact-digest-open:{relative}"
                )
    manifest_preflight_path = (
        root / DOCKER_HUB_MANIFEST_PREFLIGHT_RELATIVE_PATH
    )
    if manifest_preflight_path.is_file():
        try:
            manifest_preflight_sha256 = hashlib.sha256(
                manifest_preflight_path.read_bytes()
            ).hexdigest()
        except OSError:
            failures.append("docker-hub-manifest-preflight-unreadable")
        else:
            if (
                manifest_preflight_sha256
                != DOCKER_HUB_MANIFEST_PREFLIGHT_SHA256
            ):
                failures.append(
                    "docker-hub-manifest-preflight-digest-open"
                )
    if failures:
        return tuple(failures)

    try:
        base = _compose(root, "compose.yaml")
        development = _compose(root, "compose.yaml", "compose.dev.yaml")
        operations = _compose(
            root,
            "compose.yaml",
            "deploy/postgres-operations.compose.yaml",
            profiles=("database-backup", "database-restore-verify"),
        )
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, TypeError):
        return ("compose-config-invalid",)

    services = base.get("services", {})
    if not isinstance(services, dict) or _dependency_graph_has_cycle(services):
        failures.append("startup-dependency-cycle")
    if set(services) != {
        "db",
        "migrate",
        "taxonomy-seed",
        "online-credentials-reconcile",
        "online-credentials-verify",
        "identity-bootstrap",
        "synthetic-oidc",
        "api",
        "matching-runtime",
        "web",
        "edge",
    }:
        failures.append("service-set-not-closed")
    for scope, observed_services in (
        ("base", services),
        ("development", development.get("services", {})),
        ("operations", operations.get("services", {})),
    ):
        if not isinstance(observed_services, dict):
            failures.append(f"bounded-logging-services-open:{scope}")
            continue
        for name, service in observed_services.items():
            if (
                not isinstance(service, dict)
                or service.get("logging") != BOUNDED_LOGGING
            ):
                failures.append(f"bounded-logging-open:{scope}:{name}")
    db = services.get("db", {})
    if not POSTGRES_IMAGE.fullmatch(str(db.get("image", ""))):
        failures.append("postgres-image-not-pinned")
    if db.get("ports"):
        failures.append("database-published")
    if db.get("environment", {}).get("POSTGRES_PASSWORD_FILE") != "/run/secrets/db_superuser_password":
        failures.append("database-secret-file-missing")
    if "POSTGRES_PASSWORD" in db.get("environment", {}):
        failures.append("database-inline-password")
    failures.extend(
        _postgres_parent_volume_failures(
            services,
            required_services=("db",),
            child_volume_services=("db",),
        )
    )

    operations_services = operations.get("services", {})
    operations_names = {
        "database-backup",
        "database-restore-target",
        "database-restore-bootstrap",
        "database-restore-verify",
        "database-restore-replay",
    }
    if not operations_names.issubset(operations_services):
        failures.append("database-operations-services-missing")
    if _dependency_graph_has_cycle(operations_services):
        failures.append("database-operations-dependency-cycle")
    backup = operations_services.get("database-backup", {})
    restore_target = operations_services.get("database-restore-target", {})
    restore_bootstrap = operations_services.get("database-restore-bootstrap", {})
    restore_verify = operations_services.get("database-restore-verify", {})
    restore_replay = operations_services.get("database-restore-replay", {})
    failures.extend(
        _postgres_parent_volume_failures(
            operations_services,
            required_services=(
                "database-backup",
                "database-restore-target",
                "database-restore-verify",
            ),
            child_volume_services=("database-restore-target",),
        )
    )
    for name, service, profile in (
        ("database-backup", backup, "database-backup"),
        (
            "database-restore-target",
            restore_target,
            "database-restore-verify",
        ),
        (
            "database-restore-bootstrap",
            restore_bootstrap,
            "database-restore-verify",
        ),
        (
            "database-restore-verify",
            restore_verify,
            "database-restore-verify",
        ),
        (
            "database-restore-replay",
            restore_replay,
            "database-restore-verify",
        ),
    ):
        if service.get("profiles") != [profile]:
            failures.append(f"database-operations-profile-open:{name}")
        if service.get("ports"):
            failures.append(f"database-operations-published:{name}")
    for name, service in (
        ("database-backup", backup),
        ("database-restore-verify", restore_verify),
    ):
        if service.get("image") != db.get("image"):
            failures.append(f"database-operations-image-drift:{name}")
        if not service.get("read_only"):
            failures.append(f"database-operations-writable-root:{name}")
        if not _has_cap_drop_all(service):
            failures.append(f"database-operations-capabilities-open:{name}")
        if "no-new-privileges=true" not in service.get("security_opt", []):
            failures.append(f"database-operations-new-privileges:{name}")
        if _secret_sources(service) != ("db_superuser_password",):
            failures.append(f"database-operations-secret-set-open:{name}")
    if restore_target.get("image") != db.get("image"):
        failures.append("database-restore-target-image-drift")
    if restore_target.get("environment", {}).get("POSTGRES_DB") != (
        "desire_restore_verify"
    ):
        failures.append("database-restore-target-name-open")
    if restore_verify.get("environment", {}).get("DESIRE_DATABASE_NAME") != (
        "desire_restore_verify"
    ):
        failures.append("database-restore-verifier-target-open")
    if backup.get("command") != ["backup"]:
        failures.append("database-backup-command-open")
    if restore_verify.get("command") != ["restore-verify"]:
        failures.append("database-restore-command-open")
    if _dependency_conditions(backup) != {"db": "service_healthy"}:
        failures.append("database-backup-order-open")
    if _dependency_conditions(restore_bootstrap) != {
        "database-restore-target": "service_healthy"
    }:
        failures.append("database-restore-bootstrap-order-open")
    if _dependency_conditions(restore_verify) != {
        "database-restore-bootstrap": "service_completed_successfully"
    }:
        failures.append("database-restore-verify-order-open")
    if operations.get("networks", {}).get(
        "database-restore-verification", {}
    ).get("internal") is not True:
        failures.append("database-restore-network-not-internal")
    if "postgres-restore-verification-data" not in operations.get("volumes", {}):
        failures.append("database-restore-volume-missing")
    operations_compose = (
        root / "deploy" / "postgres-operations.compose.yaml"
    ).read_text(encoding="utf-8")
    operations_script = (
        root / "deploy" / "postgres-backup-restore.sh"
    ).read_text(encoding="utf-8")
    operations_runbook = (
        root / "docs" / "operations" / "run-and-check.md"
    ).read_text(encoding="utf-8")
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    failures.extend(
        _current_head_v13_runbook_failures(operations_runbook)
    )
    failures.extend(
        _current_head_backup_runbook_failures(operations_runbook)
    )
    failures.extend(
        _current_head_restore_runbook_failures(operations_runbook)
    )
    failures.extend(
        _backup_artifact_exclusion_failures(gitignore, dockerignore)
    )
    try:
        git_ignore_check = subprocess.run(
            (
                "git",
                "check-ignore",
                "--no-index",
                "--quiet",
                BACKUP_ARTIFACT_RELATIVE,
            ),
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        failures.append("database-backup-git-ignore-check-unavailable")
    else:
        if git_ignore_check.returncode != 0:
            failures.append("database-backup-git-ignore-not-effective")
    failures.extend(
        _postgres_restore_closure_failures(
            operations,
            operations_compose,
            operations_script,
        )
    )
    for fragment in (
        "${COMPOSE_PROJECT_NAME:-UNSAFE_PROJECT_NOT_SET}",
        "create_host_path: false",
    ):
        if fragment not in operations_compose:
            failures.append(f"database-operations-compose-open:{fragment}")
    for fragment in (
        "desire-restore-verify-",
        "18|47|47|5|5|15|15|23|23|10|10|2|2",
        "abc9924571cecb3027ec29ee7fdf34596bf8682d8b41c62d033964ec3094400f",
        "005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8",
        "32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73",
        "ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf",
        "96ff2fd0b3e32143b4570fff008948d13fbe5f537a746712878bd2cca77255fa",
        "0576a8872e2c9783e345d521f151b3d6f9bd7e1d9ee125ee1ef3810e01a05e47",
        "bbf292401809ff6b1fdf05fd687d7f337dfb34e193f5340c579dceaba4801e18",
        "ec63cb0733f275eaedc99348427883bb958c6467c5ee49f2a26fb252c0aafb6a",
        "144337610f3d06b8bfbb324547f3e25ca54ee6c2f821a28f94812aefc01ea4aa",
        "38c90e5d73f7aff05d7b3dc6263c52a0c50c6769daa3b8ee541dccd58057f970",
        "8774cf412ffa82c9acf53e6e7e95af361f84ec8040d02b972f846d57bb395418",
        "856f95a2169a095d238277586cfdb171d38104eaaaa03d2df925502e1b919a28",
        "6b8b739a27bbd3894372de8a566133a6991fca22d97da883c87d6ebf601763de",
        "matching_continuity_counts",
        "--serializable-deferrable",
        "--single-transaction",
        "DATABASE_RESTORE_CORE_FACTS_MISMATCH",
    ):
        if fragment not in operations_script:
            failures.append(f"database-operations-script-open:{fragment}")
    if "desire-supply-e2e" in operations_script or "PGPASSWORD" in operations_script:
        failures.append("database-operations-unsafe-source")

    published = [name for name, service in services.items() if service.get("ports")]
    if published != ["edge"]:
        failures.append("non-edge-service-published")
    for name in DEPLOYMENT_SERVICES:
        environment = services.get(name, {}).get("environment", {})
        if environment.get("DESIRE_DEPLOYMENT_MODE") != "INTERNAL_SANDBOX":
            failures.append(f"deployment-mode-open:{name}")
        if environment.get("DESIRE_EXTERNAL_PARTICIPANTS_ENABLED") != "false":
            failures.append(f"external-participants-open:{name}")
    api = services.get("api", {})
    if api.get("environment") != {
        "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
            "/run/desire/deployment.json"
        ),
        "SSL_CERT_FILE": "/run/desire-tls/root-ca.pem",
    }:
        failures.append("api-environment-open")
    if _secret_sources(api) != API_SECRETS:
        failures.append("api-runtime-secret-set-open")
    if _secret_targets(api) != API_SECRETS:
        failures.append("api-runtime-secret-target-open")
    if "db_superuser_password" in _secret_sources(api):
        failures.append("api-has-admin-secret")
    if _config_targets(api) != API_CONFIG_TARGETS:
        failures.append("api-runtime-config-set-open")
    matching_runtime = services.get("matching-runtime", {})
    if matching_runtime.get("environment") != {
        "DESIRE_INTERNAL_SANDBOX_DEPLOYMENT_CONFIG_FILE": (
            "/run/desire/matching-deployment.json"
        ),
        "DESIRE_MATCHING_RUNTIME_HEALTH_FILE": (
            "/run/matching-runtime/healthy"
        ),
    }:
        failures.append("matching-runtime-environment-open")
    if _secret_sources(matching_runtime) != MATCHING_RUNTIME_SECRETS:
        failures.append("matching-runtime-secret-set-open")
    if _secret_targets(matching_runtime) != MATCHING_RUNTIME_SECRETS:
        failures.append("matching-runtime-secret-target-open")
    if _config_targets(matching_runtime) != MATCHING_RUNTIME_CONFIG_TARGETS:
        failures.append("matching-runtime-config-set-open")
    if matching_runtime.get("ports"):
        failures.append("matching-runtime-published")
    expected_secret_definitions = {
        "db_superuser_password",
        "taxonomy_seed_workload_credential",
        "taxonomy_seed_receipt_hmac_key",
        "edge-tls-key",
        *ONLINE_SECRETS,
    }
    if set(base.get("secrets", {})) != expected_secret_definitions:
        failures.append("compose-secret-set-open")
    if set(base.get("configs", {})) != {
        "internal-sandbox-deployment",
        "internal-sandbox-runtime-config",
        "internal-sandbox-secret-manifest",
        "internal-sandbox-matching-deployment",
        "internal-sandbox-matching-runtime-config",
        "internal-sandbox-matching-secret-manifest",
        "internal-sandbox-online-credentials-deployment",
        "internal-sandbox-online-credentials-runtime-config",
        "internal-sandbox-online-credentials-secret-manifest",
        "internal-sandbox-identity-template",
        "internal-sandbox-root-ca",
        "internal-sandbox-edge-tls-chain",
    }:
        failures.append("compose-config-set-open")
    if services.get("web", {}).get("environment", {}).get(
        "DESIRE_LOOPBACK_BASE_URL"
    ) != "http://api:8000":
        failures.append("web-api-origin-not-closed")
    synthetic = services.get("synthetic-oidc", {})
    if synthetic.get("environment") != SYNTHETIC_OIDC_ENVIRONMENT:
        failures.append("synthetic-oidc-environment-open")
    if _secret_sources(synthetic) != ("key-oidc-client-secret-v1",):
        failures.append("synthetic-oidc-secret-set-open")
    if _secret_targets(synthetic) != ("key-oidc-client-secret-v1",):
        failures.append("synthetic-oidc-secret-target-open")
    if synthetic.get("ports"):
        failures.append("synthetic-oidc-published")
    synthetic_health = " ".join(
        synthetic.get("healthcheck", {}).get("test", [])
    )
    if "http://127.0.0.1:8081/health/ready" not in synthetic_health:
        failures.append("synthetic-oidc-readiness-not-gated")

    for name in (
        "api",
        "matching-runtime",
        "web",
        "edge",
        "synthetic-oidc",
        *DEPLOYMENT_SERVICES,
    ):
        service = services.get(name, {})
        if not service.get("read_only"):
            failures.append(f"writable-root:{name}")
        if not _has_cap_drop_all(service):
            failures.append(f"capabilities-not-dropped:{name}")
        if "no-new-privileges=true" not in service.get("security_opt", []):
            failures.append(f"new-privileges-allowed:{name}")

    for network in ("app", "data", "oidc-backend"):
        if base.get("networks", {}).get(network, {}).get("internal") is not True:
            failures.append(f"network-not-internal:{network}")
    if base.get("networks", {}).get("ingress", {}).get("internal") is True:
        failures.append("ingress-network-internal")
    if "egress" in base.get("networks", {}):
        failures.append("oidc-egress-network-present")
    for name in (
        "db",
        "api",
        "matching-runtime",
        "web",
        "synthetic-oidc",
        *DEPLOYMENT_SERVICES,
    ):
        if "ingress" in services.get(name, {}).get("networks", {}):
            failures.append(f"non-edge-on-ingress:{name}")
    if "ingress" not in services.get("edge", {}).get("networks", {}):
        failures.append("edge-not-on-ingress")
    expected_networks = {
        "db": {"data"},
        "migrate": {"data"},
        "taxonomy-seed": {"data"},
        "online-credentials-reconcile": {"data"},
        "online-credentials-verify": {"data"},
        "identity-bootstrap": {"data"},
        "synthetic-oidc": {"oidc-backend"},
        "api": {"app", "data"},
        "matching-runtime": {"data"},
        "web": {"app"},
        "edge": {"app", "oidc-backend", "ingress"},
    }
    for name, expected in expected_networks.items():
        if set(services.get(name, {}).get("networks", {})) != expected:
            failures.append(f"network-set-open:{name}")
    if services.get("edge", {}).get("networks", {}).get("app", {}).get(
        "aliases"
    ) != ["identity.example.test"]:
        failures.append("edge-oidc-dns-alias-open")

    edge_ports = services.get("edge", {}).get("ports", [])
    if (
        len(edge_ports) != 1
        or edge_ports[0].get("host_ip") != "127.0.0.1"
        or edge_ports[0].get("published") != "443"
        or edge_ports[0].get("target") != 443
        or edge_ports[0].get("protocol") != "tcp"
    ):
        failures.append("edge-publication-open")

    api_health = " ".join(services.get("api", {}).get("healthcheck", {}).get("test", []))
    if "/health/ready" not in api_health:
        failures.append("api-readiness-not-gated")
    migration_command = " ".join(services.get("migrate", {}).get("command", []))
    if migration_command != "python -m desire_platform.deployment":
        failures.append("migration-composition-not-wired")
    expected_commands = {
        "taxonomy-seed": (
            "python -m desire_platform.deployment.synthetic_taxonomy_seed apply"
        ),
        "online-credentials-reconcile": (
            "python -m desire_platform.deployment.online_credentials reconcile"
        ),
        "online-credentials-verify": (
            "python -m desire_platform.deployment.online_credentials verify"
        ),
        "identity-bootstrap": (
            "python -m desire_platform.deployment.identity_bootstrap_orchestrator run"
        ),
        "synthetic-oidc": "python -m desire_platform.synthetic_oidc",
        "api": "python -m desire_platform.internal_pilot.api_server",
        "matching-runtime": (
            "python -m desire_platform.matching.runtime_process"
        ),
    }
    for name, expected in expected_commands.items():
        if " ".join(services.get(name, {}).get("command", [])) != expected:
            failures.append(f"command-not-wired:{name}")
    expected_dependencies = {
        "migrate": {"db": "service_healthy"},
        "taxonomy-seed": {"migrate": "service_completed_successfully"},
        "online-credentials-reconcile": {
            "taxonomy-seed": "service_completed_successfully"
        },
        "online-credentials-verify": {
            "online-credentials-reconcile": "service_completed_successfully"
        },
        "identity-bootstrap": {
            "online-credentials-verify": "service_completed_successfully"
        },
        "synthetic-oidc": {},
        "edge": {"synthetic-oidc": "service_healthy"},
        "api": {
            "identity-bootstrap": "service_completed_successfully",
            "edge": "service_healthy",
        },
        "matching-runtime": {
            "identity-bootstrap": "service_completed_successfully"
        },
        "web": {"api": "service_healthy"},
    }
    for name, expected in expected_dependencies.items():
        if _dependency_conditions(services.get(name, {})) != expected:
            failures.append(f"startup-order-open:{name}")
    for name in ("online-credentials-reconcile", "online-credentials-verify"):
        service = services.get(name, {})
        if _secret_sources(service) != ONLINE_DATABASE_SECRETS:
            failures.append(f"deployment-secret-set-open:{name}")
        if _secret_targets(service) != ONLINE_DATABASE_SECRETS:
            failures.append(f"deployment-secret-target-open:{name}")
        if _config_targets(service) != ONLINE_CREDENTIAL_CONFIG_TARGETS:
            failures.append(f"deployment-config-set-open:{name}")
    identity = services.get("identity-bootstrap", {})
    if _secret_sources(identity) != IDENTITY_BOOTSTRAP_SECRETS:
        failures.append("deployment-secret-set-open:identity-bootstrap")
    if _secret_targets(identity) != IDENTITY_BOOTSTRAP_SECRETS:
        failures.append("deployment-secret-target-open:identity-bootstrap")
    if _config_targets(identity) != RUNTIME_CONFIG_TARGETS + (
        "/run/desire/identity-bootstrap-template.json",
    ):
        failures.append("deployment-config-set-open:identity-bootstrap")
    try:
        identity_template_bytes = (
            root
            / "platform/examples/"
            "internal-sandbox-identity-bootstrap-template-v1.json"
        ).read_bytes()
        identity_template = json.loads(identity_template_bytes)
        template_codes = tuple(
            sorted(
                item["account_code"]
                for item in identity_template["accounts"]
            )
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        template_codes = ()
        identity_template_bytes = b""
    if template_codes != IDENTITY_ACCOUNT_CODES:
        failures.append("identity-template-account-set-open")
    if identity.get("environment", {}).get(
        "DESIRE_INTERNAL_SANDBOX_IDENTITY_BOOTSTRAP_TEMPLATE_SHA256"
    ) != hashlib.sha256(identity_template_bytes).hexdigest():
        failures.append("identity-template-digest-open")
    volumes = identity.get("volumes", [])
    if (
        len(volumes) != 1
        or volumes[0].get("type") != "bind"
        or volumes[0].get("target") != "/run/identity-sources"
        or volumes[0].get("read_only") is not True
        or volumes[0].get("bind", {}).get("create_host_path") is not False
    ):
        failures.append("identity-source-mount-open")

    edge = services.get("edge", {})
    if _config_targets(edge) != ("/run/desire-tls/edge-tls-chain.pem",):
        failures.append("edge-tls-config-set-open")
    if _secret_sources(edge) != ("edge-tls-key",):
        failures.append("edge-tls-secret-set-open")
    if _secret_targets(edge) != ("/run/secrets/edge-tls-key.pem",):
        failures.append("edge-tls-secret-target-open")
    if api.get("volumes") or edge.get("volumes"):
        failures.append("tls-directory-mounted")
    if edge.get("sysctls") != {
        "net.ipv4.ip_unprivileged_port_start": "0"
    }:
        failures.append("edge-low-port-binding-open")

    caddyfile = (root / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    tls_directive = (
        "tls /run/desire-tls/edge-tls-chain.pem "
        "/run/secrets/edge-tls-key.pem"
    )
    for fragment in (
        "https://identity.example.test",
        "https://pilot.example.test",
        "reverse_proxy synthetic-oidc:8081",
        "header_up Host identity.example.test",
        "header_up X-Forwarded-Host identity.example.test",
        "header_up X-Forwarded-Proto https",
        "header_up -Forwarded",
        "header_up Host pilot.example.test",
        "header_up X-Forwarded-Host pilot.example.test",
        "reverse_proxy web:3000",
    ):
        if fragment not in caddyfile:
            failures.append(f"caddy-contract-missing:{fragment}")
    if caddyfile.count(tls_directive) != 2:
        failures.append("caddy-tls-host-set-open")
    if "auto_https off" in caddyfile:
        failures.append("caddy-tls-disabled")
    if "header_up -X-Forwarded-Proto" in caddyfile:
        failures.append("caddy-forwarded-proto-deleted")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    if (
        "./platform[server]" not in dockerfile
        or "desire-supply-platform[server]" not in dockerfile
        or 'CMD ["python", "-m", "desire_platform.internal_pilot.api_server"]'
        not in dockerfile
        or "blocked_runtime.py" in dockerfile
    ):
        failures.append("platform-runtime-image-not-wired")

    devcontainer_marker = "FROM ${POSTGRES_DEV_IMAGE} AS devcontainer"
    _, marker_found, devcontainer_stage = dockerfile.partition(devcontainer_marker)

    if f"ARG PYTHON_IMAGE={DEVCONTAINER_PYTHON_IMAGE}" not in dockerfile:
        failures.append("devcontainer-python-image-not-pinned")
    if (
        f"ARG NODE_IMAGE={DEVCONTAINER_NODE_IMAGE}" not in dockerfile
        or f"ARG UV_IMAGE={DEVCONTAINER_UV_IMAGE}" not in dockerfile
    ):
        failures.append("devcontainer-node-image-not-pinned")
    if (
        f"ARG POSTGRES_DEV_IMAGE={DEVCONTAINER_POSTGRES_IMAGE}"
        not in dockerfile
        or not marker_found
    ):
        failures.append("devcontainer-postgres-client-image-not-pinned")
    toolchain_contract = (
        "FROM ${NODE_IMAGE} AS devcontainer-node",
        "FROM ${PYTHON_IMAGE} AS devcontainer-python",
        "COPY --from=devcontainer-node /usr/local/ /usr/local/",
        "COPY --from=devcontainer-python /usr/local/ /usr/local/",
        "COPY --from=uv-binaries /uv /uvx /usr/local/bin/",
    )
    if (
        any(fragment not in dockerfile for fragment in toolchain_contract[:2])
        or any(fragment not in devcontainer_stage for fragment in toolchain_contract[2:])
        or any(
            package in devcontainer_stage
            for package in (
                "postgresql-client",
                "        python3\n",
                "        python3-pip\n",
                "        python3-venv\n",
            )
        )
    ):
        failures.append("devcontainer-toolchain-guard-missing")
    runtime_closure = (
        root / "deploy" / "devcontainer-runtime-closure.sh"
    ).read_text(encoding="utf-8")
    toolchain_check = (
        root / "deploy" / "devcontainer-toolchain-check.sh"
    ).read_text(encoding="utf-8")
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    failures.extend(
        _devcontainer_runtime_closure_failures(dockerfile, runtime_closure)
    )
    failures.extend(
        _devcontainer_toolchain_failures(dockerfile, toolchain_check, ci)
    )
    dev_docs = (
        root / "docs" / "development" / "dev-container.md"
    ).read_text(encoding="utf-8")
    failures.extend(_devcontainer_docs_failures(dev_docs))
    compose_dev = (root / "compose.dev.yaml").read_text(encoding="utf-8")
    failures.extend(_devcontainer_ipam_failures(compose_dev, development))
    if (
        "HOME=/home/node" not in devcontainer_stage
        or "NPM_CONFIG_CACHE=/home/node/.npm" not in devcontainer_stage
        or "ENV DEBIAN_FRONTEND=noninteractive" in devcontainer_stage
    ):
        failures.append("devcontainer-home-contract-open")

    if development.get("name") != "desire-supply-devcontainer":
        failures.append("devcontainer-project-not-isolated")
    dev_service = development.get("services", {}).get("devcontainer", {})
    if dev_service.get("build", {}).get("target") != "devcontainer":
        failures.append("devcontainer-target-invalid")
    if dev_service.get("ports"):
        failures.append("devcontainer-publishes-port")
    if dev_service.get("privileged"):
        failures.append("devcontainer-privileged")
    dev_environment = dev_service.get("environment", {})
    if dev_environment.get("DESIRE_IAM_TEST_POSTGRES_EPHEMERAL") != "1":
        failures.append("devcontainer-postgres-not-ephemeral")
    if dev_environment.get("PGPASSFILE") != "/tmp/desire-pgpass":
        failures.append("devcontainer-pgpass-not-temporary")
    if dev_service.get("entrypoint") != [
        "/usr/local/bin/desire-devcontainer-entrypoint"
    ]:
        failures.append("devcontainer-secret-entrypoint-missing")
    dev_secret_sources = {
        secret.get("source")
        for secret in dev_service.get("secrets", [])
        if isinstance(secret, dict)
    }
    if "db_superuser_password" not in dev_secret_sources:
        failures.append("devcontainer-database-secret-missing")
    failures.extend(_devcontainer_tmpfs_failures(dev_service))
    if "docker.sock" in json.dumps(dev_service.get("volumes", [])):
        failures.append("devcontainer-docker-socket-mounted")
    cache_contract = {
        "/workspace": "bind",
        "/workspace/platform/.venv": "volume",
        "/workspace/mvp/.venv": "volume",
        "/workspace/web/node_modules": "volume",
        "/home/node/.cache/uv": "volume",
        "/home/node/.npm": "volume",
    }
    if any(
        _volume_mount(dev_service, target).get("type") != mount_type
        for target, mount_type in cache_contract.items()
    ):
        failures.append("devcontainer-cache-contract-open")
    if (
        _volume_mount(dev_service, "/workspace/mvp/.venv").get("type")
        != "volume"
    ):
        failures.append("devcontainer-mvp-venv-not-cached")
    sudo_contract = (
        "groupadd --gid 1000 node",
        "useradd --uid 1000 --gid node --create-home "
        "--home-dir /home/node --shell /bin/bash node",
        "node ALL=(root) NOPASSWD:ALL",
        "chmod 0440 /etc/sudoers.d/node",
        "visudo -cf /etc/sudoers.d/node",
        "/workspace \\",
        "/workspace/platform/.venv \\",
        "/workspace/mvp/.venv \\",
        "/workspace/web/node_modules",
    )
    if (
        any(fragment not in devcontainer_stage for fragment in sudo_contract)
        or not devcontainer_stage.rstrip().endswith(
            'CMD ["sleep", "infinity"]'
        )
        or "\nUSER node\n" not in devcontainer_stage
        or "%sudo" in devcontainer_stage
        or dev_service.get("security_opt")
        or dev_service.get("cap_drop")
    ):
        failures.append("devcontainer-sudo-contract-open")
    dev_entrypoint = (
        root / "deploy" / "devcontainer-entrypoint.sh"
    ).read_text(encoding="utf-8")
    ownership_roots = (
        "/home/node/.cache/uv",
        "/home/node/.npm",
        "/workspace/platform/.venv",
        "/workspace/mvp/.venv",
        "/workspace/web/node_modules",
    )
    expected_ownership_loop = (
        "for dependency_root in \\\n"
        + " \\\n".join(f"    {root_path}" for root_path in ownership_roots)
        + "\ndo\n"
    )
    if (
        expected_ownership_loop not in dev_entrypoint
        or 'runtime_owner="$(id -u):$(id -g)"' not in dev_entrypoint
        or 'sudo -n chown -- "$runtime_owner" "$dependency_root"'
        not in dev_entrypoint
        or "chown -R" in dev_entrypoint
        or "chown --recursive" in dev_entrypoint
        or "\n    /workspace \\\n" in dev_entrypoint
    ):
        failures.append("devcontainer-cache-ownership-repair-open")
    post_create = (root / "deploy" / "devcontainer-post-create.sh").read_text(
        encoding="utf-8"
    )
    if "uv sync --locked --extra test --extra server" not in post_create:
        failures.append("devcontainer-python-install-not-locked")
    if "npm ci --ignore-scripts --no-audit" not in post_create:
        failures.append("devcontainer-web-install-not-locked")
    if "\nnpm ci\n" in post_create:
        failures.append("devcontainer-web-install-scripts-open")
    try:
        devconfig = json.loads(
            (root / ".devcontainer" / "devcontainer.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        failures.append("devcontainer-json-invalid")
    else:
        if devconfig.get("service") != "devcontainer":
            failures.append("devcontainer-service-invalid")
        if devconfig.get("workspaceFolder") != "/workspace":
            failures.append("devcontainer-workspace-invalid")
        if set(devconfig.get("runServices", [])) != {"db", "devcontainer"}:
            failures.append("devcontainer-run-services-open")
        if "docker.sock" in json.dumps(devconfig):
            failures.append("devcontainer-docker-socket-configured")
        if devconfig.get("postCreateCommand") != DEVCONTAINER_POST_CREATE:
            failures.append("devcontainer-mvp-install-not-locked")
        if (
            devconfig.get("initializeCommand")
            != DEVCONTAINER_INITIALIZE_COMMAND
        ):
            failures.append("devcontainer-editor-project-environment-open")
        if (
            devconfig.get("containerUser") != "node"
            or devconfig.get("remoteUser") != "node"
            or devconfig.get("updateRemoteUserUID") is not True
        ):
            failures.append("devcontainer-user-contract-open")
        for service_name in devconfig.get("runServices", []):
            if development.get("services", {}).get(service_name, {}).get("ports"):
                failures.append(f"devcontainer-run-service-publishes-port:{service_name}")

    return tuple(failures)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = verify(root)
    if failures:
        print(json.dumps({"failures": failures, "status": "FAILED"}, ensure_ascii=False))
        return 1
    print('{"status":"OK"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
