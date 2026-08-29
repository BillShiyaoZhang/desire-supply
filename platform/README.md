# Desire Supply platform

This directory contains the installable Python modular monolith for G1 Slice 0.

## Distribution resources

The built wheel and source distribution are self-contained. Their reviewed
runtime resources include:

- every versioned API, event, domain, and runtime contract;
- IAM, Creator Profile, Demand, and Taxonomy migration manifests;
- every SQL file referenced by those manifests.

The isolated PEP 517 build backend is pinned exactly in `pyproject.toml`; the
packaging acceptance test also verifies the wheel's recorded generator version.

The canonical contract source is `src/desire_platform/contracts`. The
repository-level `contracts` path is a relative symlink retained only for
compatibility with existing review tooling; it is not a second copy.

Consumers should use `importlib.resources`, for example:

```python
from importlib import resources

contracts = resources.files("desire_platform.contracts")
iam_openapi = contracts.joinpath("api", "iam-v1.openapi.yaml").read_text(
    encoding="utf-8"
)

package = resources.files("desire_platform")
iam_manifest = package.joinpath(
    "identity_access",
    "adapters",
    "postgres",
    "migrations",
    "manifest.json",
).read_bytes()
```

Build and verify the deployment artifacts from this directory:

```console
uv build
uv run python -m unittest tests.packaging.test_distribution_resources -v
```

The packaging acceptance test creates isolated environments, installs both the
wheel and the sdist without project-source path leakage, and byte-checks every
contract, manifest, and referenced SQL resource.

## 本地合成多角色平台

第一次运行、七角色 HTTP smoke、重启恢复和 Docker 当前阻断的完整步骤见
[`docs/operations/run-and-check.md`](../docs/operations/run-and-check.md)。

下面的入口只用于本机 `G1 NO-GO / G2 NO-GO` 合成演练。它不连接真实身份、
通知、文件、合同、资金或外部 provider；SQLite 文件只保存可删除的合成进度。

从 `platform/` 目录启动：

```console
mkdir -p .local
PYTHONPATH=src .venv/bin/python -m desire_platform.local_synthetic \
  --database "$PWD/.local/local-synthetic.sqlite3" \
  --host 127.0.0.1 \
  --port 8000
```

成功时会显示 `LOCAL_SYNTHETIC`、`G1 NO-GO`、`G2 NO-GO`，并且只监听
`http://127.0.0.1:8000`。另一个终端可检查：

```console
curl --fail --show-error http://127.0.0.1:8000/health/live
curl --fail --show-error http://127.0.0.1:8000/v1/local/personas
```

按 `Ctrl-C` 停止。若要丢弃演练进度，停止进程后删除精确文件
`platform/.local/local-synthetic.sqlite3`；不要备份、上传或发布该文件。

只运行本地切片测试：

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python \
  -m unittest discover -s tests/local_synthetic -v
```
