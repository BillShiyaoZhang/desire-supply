# 私有服务器运行时发布包操作手册

状态：**服务器操作者手册；所有命令均为待授权操作步骤，不是本机已执行 Docker、工作流或
部署的证据。**

本手册说明如何为同一个 Git commit 分别生成 `amd64` 与 `arm64` 单文件 bundle，记录
GitHub run 与两个摘要域，把 bundle 放入服务器 owner-only 目录，使用包外受信 helper
完全离线验包，再进入受控镜像导入、固定 PostgreSQL pull 和既有 activation 流程。

正式成员合同见 `deploy/private-server-runtime-release-bundle-v1.md`。运行时 manifest 的
机器合同是 `deploy/private-server-runtime-release-v1.schema.json`。

当前新生成制品的模式头固定为 PostgreSQL18 / IAM46 / Profile5 / Demand15 / Trust22 /
Matching9 / Taxonomy2。workflow 在构建前运行 current-head v28 静态 verifier，对
IAM46/Profile5/Demand15/Trust22/Matching9/Taxonomy2 做独立只读检查；新 runtime release 的同一模式头
绑定还由本版本 core、schema 与 bundle 合同闭合。v28 前向修复 Matching ingest 名称歧义和 coordinator
领取 scope/审计、reviewer claim 可见性/行锁，并增加精确 CREATE 回执恢复，不改变
runtime release format `v1`；其发布状态仅为
`STATIC VERIFIED / NOT PRODUCTION EXECUTED`，不能据此声称 workflow、Docker、migration、backup/restore
或生产执行。所有历史 bundle、fixture、manifest 与回执仍保留原模式头事实，包括冻结的 current-head v27
IAM46 / Profile5 / Demand15 / Trust22 / Matching3 / Taxonomy2，以及冻结的 current-head v26
IAM43 / Profile3 / Demand13 / Trust19 / Taxonomy2、冻结的 current-head v25 与 current-head v24
IAM42 / Demand12 / Trust18、current-head v23
IAM42 / Demand12 / Trust17、current-head v22 的 IAM42 / Demand12 / Trust16、current-head v20 的
IAM41 / Trust14、current-head v19 的 IAM40 / Trust13、current-head v18 的 IAM39 / Trust12，
以及 v15/v16/v17 的 Trust9/Trust10/Trust11；不得把旧 bundle 或其他旧证据重标为
IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2。旧证据只能由其
当时固定的 verifier/schema 解释，新发布必须重新生成并形成新的 run facts 与摘要。

## 0. 先确认边界

继续前必须满足：

- 已批准一个小写 40 位 commit，并有一个明确指向它的 GitHub ref；两种架构必须使用同一
  commit；
- 目标服务器原生架构是 `amd64` 或 `arm64`，且只接收同架构 bundle；
- 目标 Docker Engine 的 Server API 至少为 `1.48`，可以对 `docker image load` 使用
  `--platform`；版本门禁必须在任何 image import/pull 前完成；
- 已在 bundle 之外准备受审核、固定 commit 的 verifier checkout；不得从未验证 bundle
  运行 `tools/`；
- verifier 使用专用发布账号运行，验证和 stage 期间没有其他不受信的同一有效 UID 进程；
  该账号一旦疑似失陷，本轮必须停止；
- image import/inspect 到 activation receipt 固定期间，四个预期 repository:tag 处于排他发布窗口，
  没有其他 Docker actor 并发 load、tag、remove 或 prune；无法保证时必须停止；
- 服务器下载区与验证区都是全新的绝对路径，直接父目录 owner 正确且模式 `0700`；bundle
  最终模式为 `0400`；
- 已为每次验包产生且保留的完整解包副本规划容量；单个可接受 bundle 上限为 64 GiB，
  stage、原 bundle 和多个 verify 副本还会叠加；
- 已定义操作记录的保密位置；记录不应包含 GitHub token、registry token、secret、TLS
  private key 或 OIDC credential；
- 已分别取得运行 workflow、联网 pull、导入镜像和 activation 所需的外部批准。

bundle 的成员闭集没有专用 secret/env/credential 项，workflow 也不向 BuildKit 提供 secret
或 SSH forwarding；但 source snapshot、SBOM 与 provenance 是不受信任的证据 bytes，内置
verifier 不做 DLP 或全字符串敏感信息扫描，不能证明其中没有敏感文本。bundle 与操作记录都
必须按敏感发布证据保护。bundle 不授权 Docker、生产、迁移或公网开放；验证通过不会改变这点。

### 0.1 在批准 commit 前闭合当前工作区

运行时 source helper 只读取指定 commit 的 Git object，不读取 checkout 内容。这能避免 dirty
worktree 污染制品，但也意味着未提交或未跟踪的新 Docker、Platform、Web、部署脚本与 workflow
会被诚实地排除。不能用一次本机 Docker 成功推断这些 bytes 已经进入可发布 commit。

在批准 ref 或触发 workflow 前，必须从待发布 checkout 根目录运行只读 source-readiness gate：

```bash
python3 -B scripts/check_private_server_source_readiness.py
```

它要求 porcelain（包含所有未忽略 untracked 文件）为空，要求 Docker/Compose、Dev Container、
CI、runtime-release workflow、current-head、server activator 与自身合同均为 HEAD 中的 regular
tracked blob，再把 HEAD tree 中**每一个** tracked blob 的 Git object ID、工作区 bytes、mode 与
关闭 source digest 逐项绑定，并在返回前重新检查 HEAD、tree 与 porcelain。任一路径、内容或状态
不会进入错误输出。dirty 或 untracked checkout 只返回：

```json
{"code":"PRIVATE_SERVER_SOURCE_READINESS_DIRTY","status":"BLOCKED"}
```

成功状态为 `SOURCE_READINESS_VERIFIED_NOT_AUTHORITY`，机器合同是
`deploy/private-server-source-readiness-v1.schema.json`。结果固定保留
`remote_ref_verified=false`、`ci_verified=false`、`execution_permitted=false` 与
`production_authorized=false`：本地检查不证明 commit 已 push、不读取 GitHub check、也不形成
workflow、Docker 或 activation 权限。批准者仍须从 GitHub 原始事实确认 ref 与 CI 精确指向同一
`head`。

如需保全本地回执，只能 exclusive-create 到 checkout 之外、当前用户所有且 mode 精确为 `0700`
的既有目录；输出文件固定为 `0600`，已存在目标绝不覆盖：

```bash
python3 -B scripts/check_private_server_source_readiness.py \
  --output /absolute/owner-only-directory/source-readiness.json
```

这项 gate 已同时接入 CI 与 runtime-release workflow。workflow checkout 再次执行它，避免发布
流程在 source snapshot 前缺少同一关闭入口；该重复通过仍只表示 GitHub checkout 与其 HEAD
一致。随后 workflow 还会运行 current-head v28 的只读静态 verifier；它闭合当前
IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2 静态基线，但不替代 runtime release manifest
对同一模式头的验证，也不把
`NOT EXECUTED` 提升为动态成功，或替代 CI 结论、人工批准与后续服务器验包。

完整 HEAD 绑定允许 Git mode `120000`，但只允许 NFC UTF-8 的内部相对 symlink：目标必须解析到
同一 snapshot 的既有成员、不能越出根目录、不能 dangling 或成环。source snapshot 把这类 link
规范化为 USTAR mode `0777`/symlink type，build context 使用 dirfd 创建并回读验证；现有
`platform/contracts -> src/desire_platform/contracts` 走的就是这条合同。gitlink 与其他非常规
mode 仍然 fail closed。

## 1. 手动触发两个原生架构 run

workflow 名称是 **Private server runtime release artifact**，文件为
`.github/workflows/private-server-runtime-release.yml`。它只有 `workflow_dispatch`，唯一
input 是 `architecture`，可选值只有 `amd64` 与 `arm64`。

在 GitHub 网页中：

1. 打开仓库的 **Actions**，选择 **Private server runtime release artifact**；
2. 选择 **Run workflow**，把 “Use workflow from” 固定到已批准 ref；
3. 选择 `amd64` 并触发；
4. 再次使用同一 ref，选择 `arm64` 并触发；
5. 不要用 rerun 替代新事实而不记录 `run_attempt`；每次 attempt 都产生不同 tag/bundle；
6. 两个 run 完成后，逐个确认 run 的 head commit 精确等于批准的 40 位 commit，runner
   architecture 与 input 相同。

workflow 不 push registry、不 deploy、不执行 Compose。每个架构只上传一个未再归档的
bundle 文件，保留期为 14 天。

供应链声明只到“最终产物闭合”：固定 action commit 请求 Buildx `v0.36.1`，但下载到 runner
的 Buildx release asset 只做版本字符串核对，没有独立 checksum；BuildKit 与 SBOM scanner
container 则按 digest 固定。当前 platform wheel 构建也没有消费 `uv.lock` 的完整 transitive
lock/hash，OIDC egress guard 的 Debian index/`nftables` 没有 snapshot/version 固定。因此本流程
**不声明构建输入闭包或可复现构建**；同一 commit 仍可能得到不同 runnable bytes。bundle
验证的是本次 run 最终生成并上传的精确 OCI/statement bytes，不得把它升级为 runner、Buildx、
在线依赖来源可信或可复现证明。

## 2. 每个 run 必须记录的事实

对 `amd64` 与 `arm64` 分别填写，不得从文件名反推后省略 GitHub 原始记录：

| 字段 | 记录值 |
|---|---|
| workflow run URL | GitHub run 的完整 URL |
| run ID | URL/API 显示的十进制 `github.run_id` |
| run attempt | `github.run_attempt`；rerun 后必须增加 |
| head commit | 小写 40 位 `github.sha` |
| architecture | `amd64` 或 `arm64` |
| image tag | `sha-<commit>-<architecture>-r<run_id>-a<run_attempt>` |
| artifact/bundle 名 | `runtime-release-<image_tag>.tar` |
| local bundle SHA-256 | workflow 上传前 `sha256sum` 的 64 位值 |
| GitHub artifact digest | upload-artifact step 输出的独立 digest |
| workflow conclusion | 必须为 success；同时保存 step summary |

local bundle SHA-256 与 GitHub artifact digest 是不同摘要域。不得要求它们相等，也不得
使用 artifact digest 代替服务器上的 `sha256sum` 比较值。

## 3. 下载到全新 `0700` 传输目录

以下变量必须替换为本轮实际值。示例不表示本机已经下载：

```bash
set -euo pipefail
umask 077

export DESIRE_RUNTIME_RELEASE_RUN_ID='<run-id>'
export DESIRE_RUNTIME_RELEASE_ARTIFACT='runtime-release-sha-<40commit>-<amd64-or-arm64>-r<run-id>-a<attempt>.tar'
export DESIRE_RUNTIME_RELEASE_TRANSPORT='/srv/desire-supply/runtime-release-download/<unique-run-and-arch>'

test "${DESIRE_RUNTIME_RELEASE_TRANSPORT#/}" != "$DESIRE_RUNTIME_RELEASE_TRANSPORT"
test ! -e "$DESIRE_RUNTIME_RELEASE_TRANSPORT"
mkdir -m 0700 -- "$DESIRE_RUNTIME_RELEASE_TRANSPORT"
chmod 0700 -- "$DESIRE_RUNTIME_RELEASE_TRANSPORT"

gh run download "$DESIRE_RUNTIME_RELEASE_RUN_ID" \
  -n "$DESIRE_RUNTIME_RELEASE_ARTIFACT" \
  --dir "$DESIRE_RUNTIME_RELEASE_TRANSPORT"
```

`upload-artifact@v7.0.1` 在 `archive:false` 单文件模式下使用 bundle basename 作为
artifact name。下载工具的落盘外形不是 bundle 内容合同；下载后必须人工确认传输目录中
只有一个期望的同名 regular file，不得有 link、额外 payload 或第二个候选。若 GitHub UI
或 CLI 产生传输容器/额外目录，只能把其中唯一同名文件视作下载候选，不能把外层摘要当作
local bundle SHA-256。

## 4. 复制到全新验证目录并锁定权限

不要在下载目录原位验包。建立第二个新的 `0700` 目录，把上一步确认的唯一文件以
no-clobber 方式复制进去；下面的 `<downloaded-file>` 必须替换为它的绝对路径：

```bash
set -euo pipefail
umask 077

export DESIRE_RUNTIME_RELEASE_VERIFY_ROOT='/srv/desire-supply/runtime-release-verify/<unique-release-id>'
export DESIRE_RUNTIME_RELEASE_DOWNLOADED='<downloaded-file-absolute-path>'
export DESIRE_RUNTIME_RELEASE_BUNDLE="$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT/$DESIRE_RUNTIME_RELEASE_ARTIFACT"
export DESIRE_RUNTIME_RELEASE_EXPECTED_SHA256='<workflow-local-bundle-sha256>'

test "${DESIRE_RUNTIME_RELEASE_VERIFY_ROOT#/}" != "$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT"
test "${DESIRE_RUNTIME_RELEASE_DOWNLOADED#/}" != "$DESIRE_RUNTIME_RELEASE_DOWNLOADED"
test ! -L "$DESIRE_RUNTIME_RELEASE_DOWNLOADED"
test -f "$DESIRE_RUNTIME_RELEASE_DOWNLOADED"
test ! -e "$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT"
mkdir -m 0700 -- "$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT"
chmod 0700 -- "$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT"
cp --no-clobber -- "$DESIRE_RUNTIME_RELEASE_DOWNLOADED" "$DESIRE_RUNTIME_RELEASE_BUNDLE"
chmod 0400 -- "$DESIRE_RUNTIME_RELEASE_BUNDLE"
test "$(stat -c '%a' -- "$DESIRE_RUNTIME_RELEASE_VERIFY_ROOT")" = '700'
test "$(stat -c '%a' -- "$DESIRE_RUNTIME_RELEASE_BUNDLE")" = '400'
test "$(sha256sum -- "$DESIRE_RUNTIME_RELEASE_BUNDLE" | cut -d ' ' -f 1)" = \
  "$DESIRE_RUNTIME_RELEASE_EXPECTED_SHA256"
```

还必须确认目录与文件由将要运行 verifier 的同一有效 UID 持有、bundle link count 为 1，
且路径祖先没有可写或意外 symlink。任何不一致都停止，不要 `sudo chmod` 修补来源不明的旧文件。

## 5. 使用包外受信 helper 完全离线验包

`DESIRE_RUNTIME_RELEASE_TRUSTED_CHECKOUT` 必须是独立于 bundle/下载目录、事先审核并固定的
仓库 checkout。它至少提供：

- `scripts/prepare_private_server_runtime_release.py`；
- `scripts/private_server_runtime_release.py`；
- `deploy/private-server-runtime-release-v1.schema.json`。

断开或策略阻止该进程的网络访问后运行：

```bash
set -euo pipefail

export DESIRE_RUNTIME_RELEASE_TRUSTED_CHECKOUT='/opt/desire-supply-release-verifier/<approved-commit>'

/usr/bin/python3 -I -B \
  "$DESIRE_RUNTIME_RELEASE_TRUSTED_CHECKOUT/scripts/prepare_private_server_runtime_release.py" \
  verify-bundle \
  --bundle "$DESIRE_RUNTIME_RELEASE_BUNDLE"
```

成功 stdout 是一行 canonical JSON，必须记录并逐字段检查：

- `status` 精确为 `BUNDLE_VALIDATED_NOT_AUTHORITY`；
- `authority` 精确为 `NOT_AUTHORITY`；
- `execution_permitted=false`；
- `production_authorized=false`；
- `bundle_sha256` 等于服务器重算值和 workflow local bundle SHA-256；
- `release_id` 等于 `runtime-release-<按 workflow 原始事实构造的 image_tag>`；
- `manifest_sha256` 为小写 64 位值并进入本轮记录；
- `image_config_digests` 精确只有 `platform`、`web`、`edge`、`oidc-egress-guard` 四个 key，
  每个值都是 `sha256:<64hex>`。stdout 的 key 闭集只能是上述八项，不接受未知字段。

stdout 不包含 commit、architecture 或 `image_tag`。这些值必须已存在于第 2 步的 workflow
记录中；若任一缺失，不得通过解析 `release_id`、bundle 文件名或路径来推断并继续。

这一步只能证明 source snapshot bytes 与 bundle manifest 摘要自洽，不能只凭 bundle 独立
证明 snapshot 确实来自 `release_id` 所编码的 Git commit。该来源结论必须同时依赖第 2 步
保存的 workflow head commit/run 事实、workflow 上传前 local bundle SHA-256、服务器重算的
同一 SHA-256，以及本步固定到已批准 commit 的包外 verifier checkout；缺少任一项都停止。

verifier 在 bundle 直接父目录创建随机命名
`.<bundle-basename>.verify-*`、模式 `0700` 的完整解包树；无论成功或失败都保留该树，且每次
重跑都会再创建一棵。它不联网、不调用 Docker、不导入镜像。记录树的绝对路径、容量与本次
回执；该树不是有效 stage，不得送给 Docker。清理只能进入独立审核、独立授权流程，本手册
不授权现场删除。禁止执行 bundle 内 `tools/`，也禁止在验证前后用 `tar -xf`、`docker load`
或自写 extractor 绕过下一步的受信导入边界。

## 6. 安全 stage 并导入四个应用 OCI archive

先建立 owner-only stage 父目录；destination 本身必须尚不存在。使用第 5 步同一份包外
受信 helper 执行 `stage-bundle`：

```bash
set -euo pipefail
umask 077

export DESIRE_RUNTIME_RELEASE_STAGE_PARENT='/srv/desire-supply/runtime-release-stage/<unique-run-and-arch>-parent'
export DESIRE_RUNTIME_RELEASE_STAGE="$DESIRE_RUNTIME_RELEASE_STAGE_PARENT/<verified-release-id>"

test "${DESIRE_RUNTIME_RELEASE_STAGE_PARENT#/}" != "$DESIRE_RUNTIME_RELEASE_STAGE_PARENT"
test ! -e "$DESIRE_RUNTIME_RELEASE_STAGE_PARENT"
mkdir -m 0700 -- "$DESIRE_RUNTIME_RELEASE_STAGE_PARENT"
chmod 0700 -- "$DESIRE_RUNTIME_RELEASE_STAGE_PARENT"
test ! -e "$DESIRE_RUNTIME_RELEASE_STAGE"

DESIRE_RUNTIME_RELEASE_STAGE_RECEIPT="$(
  /usr/bin/python3 -I -B \
    "$DESIRE_RUNTIME_RELEASE_TRUSTED_CHECKOUT/scripts/prepare_private_server_runtime_release.py" \
    stage-bundle \
    --bundle "$DESIRE_RUNTIME_RELEASE_BUNDLE" \
    --destination "$DESIRE_RUNTIME_RELEASE_STAGE"
)"
printf '%s\n' "$DESIRE_RUNTIME_RELEASE_STAGE_RECEIPT"
```

`stage-bundle` 从同一 `0400` bundle fd 重新计算摘要，执行与 `verify-bundle` 相同的成员
闭集与全量 artifact 验证，再把完整闭集原子落地；stage root/目录必须为 `0700`，regular
files 必须为 `0400`。记录它的 canonical JSON stdout，并确认 bundle SHA、manifest SHA、
release ID 仍等于第 5 步事实；`status` 必须精确为
`BUNDLE_STAGED_VALIDATED_NOT_AUTHORITY`，两个 authority booleans 仍必须为 `false`。
`image_config_digests` 必须是四个固定应用 slot 到 `sha256:<64hex>` 的精确闭集；后面的
导入门禁直接消费这份已验证回执，不能人工改填或从 Docker 反推。
architecture 与 image tag 必须先由已记录的 workflow input/head commit/run ID/attempt 按
固定公式构造，再与 verified release ID 交叉核对；helper stdout 不返回这两个字段，不能从
release ID 或 stage 路径反向补齐缺失事实。禁止通用 `tar`、archive manager、bundle 内工具
或自写 extractor。

stage 成功后，四个允许送给 Docker 的输入只有：

- `images/platform.oci.tar`；
- `images/web.oci.tar`；
- `images/edge.oci.tar`；
- `images/oidc-egress-guard.oci.tar`。

从受信 stage 逐一导入，不能直接把外层 bundle 交给 Docker。`image load --platform` 要求
Docker API `1.48+`；先读取并记录 Server API，格式或版本不满足就必须在第一次 import 前
停止：

```bash
set -euo pipefail

export DESIRE_RUNTIME_RELEASE_ARCHITECTURE='<verified-amd64-or-arm64>'
export DESIRE_IMAGE_TAG='sha-<40commit>-<architecture>-r<run-id>-a<attempt>'

DESIRE_RUNTIME_RELEASE_NATIVE_MACHINE="$(uname -m)"
case "$DESIRE_RUNTIME_RELEASE_NATIVE_MACHINE" in
  x86_64) DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE=amd64 ;;
  aarch64|arm64) DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE=arm64 ;;
  *) echo 'unsupported native server architecture' >&2; exit 78 ;;
esac
test "$DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE" = \
  "$DESIRE_RUNTIME_RELEASE_ARCHITECTURE"

DESIRE_RUNTIME_RELEASE_DOCKER_API="$(
  /usr/bin/docker --host unix:///var/run/docker.sock version \
    --format '{{.Server.APIVersion}}'
)"
if [[ ! "$DESIRE_RUNTIME_RELEASE_DOCKER_API" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
  echo 'Docker Server API format is not accepted' >&2
  exit 1
fi
DESIRE_RUNTIME_RELEASE_DOCKER_API_MAJOR="${BASH_REMATCH[1]}"
DESIRE_RUNTIME_RELEASE_DOCKER_API_MINOR="${BASH_REMATCH[2]}"
if (( DESIRE_RUNTIME_RELEASE_DOCKER_API_MAJOR < 1 || \
      (DESIRE_RUNTIME_RELEASE_DOCKER_API_MAJOR == 1 && \
       DESIRE_RUNTIME_RELEASE_DOCKER_API_MINOR < 48) )); then
  echo 'Docker Server API 1.48 or newer is required' >&2
  exit 1
fi

printf '%s %s\n' \
  "$DESIRE_RUNTIME_RELEASE_NATIVE_MACHINE" \
  "$DESIRE_RUNTIME_RELEASE_NATIVE_ARCHITECTURE"

desire_runtime_release_config_digest() {
  DESIRE_RUNTIME_RELEASE_CONFIG_SLOT="$1" \
  DESIRE_RUNTIME_RELEASE_EXPECTED_RELEASE_ID="$DESIRE_RUNTIME_RELEASE_EXPECTED_RELEASE_ID" \
  DESIRE_RUNTIME_RELEASE_STAGE_RECEIPT="$DESIRE_RUNTIME_RELEASE_STAGE_RECEIPT" \
    /usr/bin/python3 -I -B -c '
import json, os, re, sys
try:
    def closed_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value
    receipt = json.loads(
        os.environ["DESIRE_RUNTIME_RELEASE_STAGE_RECEIPT"],
        object_pairs_hook=closed_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    expected_keys = {
        "authority", "bundle_sha256", "execution_permitted",
        "image_config_digests", "manifest_sha256", "production_authorized",
        "release_id", "status",
    }
    slots = {"platform", "web", "edge", "oidc-egress-guard"}
    mapping = receipt["image_config_digests"]
    slot = os.environ["DESIRE_RUNTIME_RELEASE_CONFIG_SLOT"]
    digest = mapping[slot]
    if (
        set(receipt) != expected_keys
        or receipt["authority"] != "NOT_AUTHORITY"
        or receipt["execution_permitted"] is not False
        or receipt["production_authorized"] is not False
        or receipt["status"] != "BUNDLE_STAGED_VALIDATED_NOT_AUTHORITY"
        or receipt["release_id"]
            != os.environ["DESIRE_RUNTIME_RELEASE_EXPECTED_RELEASE_ID"]
        or re.fullmatch(r"[0-9a-f]{64}", receipt["bundle_sha256"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", receipt["manifest_sha256"]) is None
        or not isinstance(mapping, dict)
        or set(mapping) != slots
        or slot not in slots
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ValueError
    print(digest)
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    sys.exit(78)
'
}

DESIRE_RUNTIME_RELEASE_EXPECTED_RELEASE_ID="runtime-release-$DESIRE_IMAGE_TAG"
DESIRE_RUNTIME_RELEASE_PLATFORM_ID="$(desire_runtime_release_config_digest platform)"
DESIRE_RUNTIME_RELEASE_WEB_ID="$(desire_runtime_release_config_digest web)"
DESIRE_RUNTIME_RELEASE_EDGE_ID="$(desire_runtime_release_config_digest edge)"
DESIRE_RUNTIME_RELEASE_GUARD_ID="$(
  desire_runtime_release_config_digest oidc-egress-guard
)"

while IFS='|' read -r DESIRE_RUNTIME_RELEASE_SLOT \
  DESIRE_RUNTIME_RELEASE_REPOSITORY \
  DESIRE_RUNTIME_RELEASE_ARCHIVE \
  DESIRE_RUNTIME_RELEASE_EXPECTED_ID
do
  DESIRE_RUNTIME_RELEASE_REFERENCE="$DESIRE_RUNTIME_RELEASE_REPOSITORY:$DESIRE_IMAGE_TAG"
  if /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
    "$DESIRE_RUNTIME_RELEASE_REFERENCE" >/dev/null 2>&1
  then
    DESIRE_RUNTIME_RELEASE_PREEXISTING_ID="$(
      /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
        --format '{{.Id}}' "$DESIRE_RUNTIME_RELEASE_REFERENCE"
    )"
    if [[ "$DESIRE_RUNTIME_RELEASE_PREEXISTING_ID" != \
      "$DESIRE_RUNTIME_RELEASE_EXPECTED_ID" ]]
    then
      echo 'pre-existing runtime tag points to a different image ID' >&2
      exit 78
    fi
  else
    /usr/bin/docker --host unix:///var/run/docker.sock image load \
      --input "$DESIRE_RUNTIME_RELEASE_STAGE/images/$DESIRE_RUNTIME_RELEASE_ARCHIVE" \
      --platform "linux/$DESIRE_RUNTIME_RELEASE_ARCHITECTURE"
  fi

  DESIRE_RUNTIME_RELEASE_ACTUAL_ID="$(
    /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
      --format '{{.Id}}' "$DESIRE_RUNTIME_RELEASE_REFERENCE"
  )"
  test "$DESIRE_RUNTIME_RELEASE_ACTUAL_ID" = \
    "$DESIRE_RUNTIME_RELEASE_EXPECTED_ID"
  test "$(/usr/bin/docker --host unix:///var/run/docker.sock image inspect \
    --format '{{.Os}}/{{.Architecture}}' \
    "$DESIRE_RUNTIME_RELEASE_REFERENCE")" = \
    "linux/$DESIRE_RUNTIME_RELEASE_ARCHITECTURE"
  DESIRE_RUNTIME_RELEASE_REPO_TAGS="$(
    /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
      --format '{{range .RepoTags}}{{println .}}{{end}}' \
      "$DESIRE_RUNTIME_RELEASE_REFERENCE"
  )"
  printf '%s\n' "$DESIRE_RUNTIME_RELEASE_REPO_TAGS" | \
    grep -Fqx -- "$DESIRE_RUNTIME_RELEASE_REFERENCE"
  /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
    --format '{{.Id}} {{json .RepoTags}} {{json .RepoDigests}}' \
    "$DESIRE_RUNTIME_RELEASE_REFERENCE"
done <<EOF
platform|desire-supply-platform|platform.oci.tar|$DESIRE_RUNTIME_RELEASE_PLATFORM_ID
web|desire-supply-web|web.oci.tar|$DESIRE_RUNTIME_RELEASE_WEB_ID
edge|desire-supply-edge|edge.oci.tar|$DESIRE_RUNTIME_RELEASE_EDGE_ID
oidc-egress-guard|desire-supply-oidc-egress-guard|oidc-egress-guard.oci.tar|$DESIRE_RUNTIME_RELEASE_GUARD_ID
EOF

unset DESIRE_RUNTIME_RELEASE_ACTUAL_ID DESIRE_RUNTIME_RELEASE_ARCHIVE \
  DESIRE_RUNTIME_RELEASE_EXPECTED_ID DESIRE_RUNTIME_RELEASE_PREEXISTING_ID \
  DESIRE_RUNTIME_RELEASE_REFERENCE DESIRE_RUNTIME_RELEASE_REPOSITORY \
  DESIRE_RUNTIME_RELEASE_REPO_TAGS DESIRE_RUNTIME_RELEASE_SLOT
```

把原始 machine 与映射后的 architecture 记入本轮记录。这里的
`DESIRE_RUNTIME_RELEASE_ARCHITECTURE` 必须来自第 2 步 workflow 原始 facts，并已按固定公式
与 verified `release_id` 交叉核对；不得从待导入镜像、文件名或模拟器能力反推。native machine
check、Docker Server API gate 任一失败时，必须在第一次 image import/pull 前停止。

四个 expected image ID 精确来自 stage receipt 中已验证的 OCI config digests。若预期 tag 已经
存在，只有它在导入前就精确解析到 expected ID 时才允许幂等复用；指向其他 ID 时必须在
`image load` 前拒绝，禁止覆盖或 retag。导入或复用后，预期 tag、expected ID、OS/architecture
和 RepoTags membership 必须同时成立。同一个 expected ID 因旧发布或重复构建同时具有其他 tag
可以保留，不要求整个 `RepoTags` 数组只含一个元素。

Docker tag 没有跨 client 的原子 no-replace；上述保证以第 0 节的排他发布窗口为前提。进入任何
已批准 activation 的最后 preflight 时，还必须 fresh inspect 四个引用并再次证明 `.Id` 等于
同一 receipt 的 expected config digest。INTERNAL_SANDBOX activator 的 locked-image gate 与
real-OIDC create 后、start 前的 reviewed-image collector 都必须保留；禁止手工 Compose 绕过。

把四个 expected/actual image ID、RepoTags/RepoDigests 与 stage/verify 输出一起记录。OCI root
index、runnable platform manifest、config、SBOM 与 provenance 已由受信 helper 在 load 前闭合
验证；每个内层 OCI tar 还必须成员连续，并且只允许至少两个完整全零 terminal blocks，不接受
非零 member padding、拼接 tar 或非零/非对齐 trailer。outer bundle 与 source snapshot 也分别
要求连续 POSIX USTAR header、逐成员全零 padding 和规范全零 terminal blocks；重新绑定摘要不能
使隐藏 GNU record 或非规范 padding 合法。Docker inspect 把导入后的 tag 最后一跳重新绑定到
同一个 config digest，不能替代前述 archive 验证。

导入成功仍不授权 Compose 或容器启动。必须记录四个本地 image ID、预期 tag/platform、
导入前使用的包外受信 helper 版本与其 stage 输出的 release ID，以及已记录 run facts 所绑定的
image tag；不得声称 helper stdout 返回了未实际返回的字段。

## 7. PostgreSQL 必须单独 online pull 固定 digest

bundle 的 `postgres/` 只有七个 registry/config/attestation raw objects，没有 runnable
layers，也没有 PostgreSQL OCI archive。因此不能离线导入 PostgreSQL。

取得独立联网批准、确认目标服务器原生架构与已验证 bundle 相同后，只允许按 Compose 的
固定 reference online pull：

```bash
set -euo pipefail

export DESIRE_RUNTIME_RELEASE_ARCHITECTURE='<verified-amd64-or-arm64>'
export DESIRE_RUNTIME_RELEASE_POSTGRES='postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15'

/usr/bin/docker --host unix:///var/run/docker.sock image pull \
  --platform "linux/$DESIRE_RUNTIME_RELEASE_ARCHITECTURE" \
  "$DESIRE_RUNTIME_RELEASE_POSTGRES"

test "$(/usr/bin/docker --host unix:///var/run/docker.sock image inspect \
  --format '{{.Os}}/{{.Architecture}}' \
  "$DESIRE_RUNTIME_RELEASE_POSTGRES")" = \
  "linux/$DESIRE_RUNTIME_RELEASE_ARCHITECTURE"
/usr/bin/docker --host unix:///var/run/docker.sock image inspect \
  --format '{{.Id}} {{json .RepoDigests}}' \
  "$DESIRE_RUNTIME_RELEASE_POSTGRES"
DESIRE_RUNTIME_RELEASE_POSTGRES_REPODIGESTS="$(
  /usr/bin/docker --host unix:///var/run/docker.sock image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    "$DESIRE_RUNTIME_RELEASE_POSTGRES"
)"
printf '%s\n' "$DESIRE_RUNTIME_RELEASE_POSTGRES_REPODIGESTS" | \
  grep -Fqx -- \
  'postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15'
```

禁止 tag-only pull、替代 registry、替代 digest 或从 bundle 声称恢复 PostgreSQL layers。
pull 后记录 image ID 与 RepoDigest，并再次确认 exact digest。只有四个 app images 和这一
固定 PostgreSQL image 共五个镜像全部 ready，才可进入 Compose preflight；`postgres/`
evidence 永远不能当作 image layers/import 输入。这次 online pull 仍不等于签名真实性、
执行或生产授权。

## 8. `DESIRE_IMAGE_TAG` 与 Compose 的不构建边界

四个应用 archive 的预期 tag 必须先由第 2 步记录的 workflow head commit、architecture
input、run ID 与 attempt 按固定公式构造，再与受信 helper 验证后的 `release_id` 交叉核对。
helper stdout 不返回 commit、architecture 或 `image_tag`，所以不得只解析 `release_id`，也
不能使用文件名、stage 路径、未记录的用户输入或 `local` 默认值补齐这些事实：

```bash
export DESIRE_IMAGE_TAG='sha-<40commit>-<architecture>-r<run-id>-a<attempt>'
test "runtime-release-$DESIRE_IMAGE_TAG" = '<verified-release-id>'
```

`compose.yaml` 与 real-OIDC overlay 使用此变量选择四个应用；PostgreSQL 始终使用上节固定
digest，不由 `DESIRE_IMAGE_TAG` 选择。后续任何批准的 Compose 操作必须保留
`--no-build --pull never`：

- 禁止 `docker compose build`、`up --build` 或现场修改 Dockerfile；
- 禁止为应用 pull、retag 或退回 `${DESIRE_IMAGE_TAG:-local}`；
- `--no-build` 只阻止现场构建，本身不授权 create/up/start；
- `--pull never` 依赖前面已导入的四个 app images 与已 pull 的固定 PostgreSQL image；
- 只有既有 preflight/activator 可以决定是否以及如何调用 Compose。

## 9. Release inputs、TLS 与 activation 是独立步骤

runtime bundle 闭集不提供专用 Compose env、IPAM、secret、OIDC identity source、TLS
certificate/private key、数据库迁移授权或公网 bind 授权成员。它仍包含完整 source snapshot
和不受信任 statement bytes，不能据此承诺没有敏感字符串；上文的敏感证据保护要求继续适用。
完成镜像导入后仍必须单独执行并通过：

1. INTERNAL_SANDBOX 先用 `scripts/private_server_release_inputs.py measure` 生成
   `PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY` 的候选树摘要，经独立审批后再用
   `scripts/private_server_release_inputs.py verify --expected-tree-sha256 <approved-sha256>` 复核；
   两项只读命令都保持 `authority=NOT_AUTHORITY`、`execution_permitted=false` 与
   `production_authorized=false`，不创建 staging 或 attempt。永久 staging 仍只能由 activator 在
   attempt 内完成；服务器实际调用必须沿用私服手册的 `/usr/bin/python3 -I -B`，其中 `-B` 禁止在
   受审 checkout 写入 `.pyc` bytecode；
2. INTERNAL_SANDBOX 使用 `scripts/manage_internal_sandbox_tls.py` 创建并验证独立 TLS
   fixture；real OIDC 则使用单独审核的真实 TLS/source tree；
3. 对应环境的静态 Compose/preflight；
4. INTERNAL_SANDBOX 只按《私有服务器入口》使用
   `scripts/activate_private_server_ingress.py`；
5. real OIDC 只按《私有服务器真实 OIDC 静态配置》当前状态使用
   `scripts/activate_private_server_real_oidc.py`，不得把未开放 execute 的计划描述成已激活。

real-OIDC release-input stager 与 Compose validator 只接受本手册的 exact runtime tag 形状；
不得改写为旧 `real-oidc-*` 命名、通用“immutable tag”或 `local`。传入前仍须把 tag 与 verified
`release_id`、服务器原生架构及第 2 步 workflow 原始事实交叉核对。

这些步骤各自有 owner/mode、输入闭集、回执和人工 gate。bundle 验证输出不能代替任何一项。

## 10. Provenance 的两个明确档位

- 四个应用：BuildKit `mode=min,version=v1`，predicate
  `https://slsa.dev/provenance/v1`；
- PostgreSQL：固定上游历史例外，保留原字节的 rich legacy predicate
  `https://slsa.dev/provenance/v0.2`。

v0.2 例外只能用于固定 PostgreSQL evidence，不能降低四个应用要求。两者都没有在本合同中
做签名认证，都是 `unsigned / untrusted / not authority`，不形成执行、生产或迁移许可。

## 11. 拒绝、隔离与回滚

以下任一情况立即停止，不导入、不 pull、不 Compose：

- run/commit/architecture/attempt 或两个摘要域记录不完整；
- 下载后不是唯一同名 regular file，或 owner/mode/link count 不符；
- 服务器 SHA-256 与 workflow local bundle SHA-256 不同；
- 包外 verifier 不可信、非零退出、返回 `BLOCKED` 或任一字段不闭合；
- bundle 成员、manifest、source、OCI、SBOM、provenance、PostgreSQL evidence 任一拒绝；
- 人工检查或另行批准的扫描实际发现 secret、不应进入证据的敏感内容、额外文件、PostgreSQL
  layer/archive 或要求绕过 digest/验证的操作；内置 verifier 本身不是 DLP 扫描器；
- 导入后任一预期应用 tag 缺失、该引用解析的 image evidence/platform 不符，或 PostgreSQL
  pull 不是 exact digest；
- 有人要求现场 build、retag、直接通用解包、运行 bundle 内工具、自动迁移或开放公网。

拒绝后把原始 bundle 保持 `0400`，连同下载记录、摘要、verifier 输出/错误一起移入本轮
owner-only 隔离记录；不要修改 bundle 后重试。

fetch、create、verify 与 stage 不会自动删除本轮创建的 owner-only `0400`/`0700`
partial/remnant；每次 verify 即使成功也会保留完整随机解包树。非零退出后不得把任何 remnant
当作有效输出，也不得送给 Docker；create、fetch、stage 重试必须换全新的 absolute
output/destination，verify 重跑会产生另一棵树。遗留对象只记录位置、容量与回执，交给独立
审核、独立授权的清理流程处置，本手册不授权现场递归删除。磁盘不能容纳预期保留副本时，
必须在下一次运行前停止。

这些防护不以同一有效 UID 下的恶意或已失陷并发进程为可抵抗攻击者：同 UID 进程可以在验证
期间或成功返回后改写 owner 文件。发布账号必须专用，运行期间不得有其他不受信同 UID 进程；
若不能保证，立即拒绝并按账号失陷处理。一次成功回执只证明受控验证时点的闭合内容，不是
返回后的持续完整性保证。

每次新 release 都必须保留上一份已完整验证的 bundle、manifest SHA、run facts、四个 app
image IDs、固定 PostgreSQL image ID、TLS/input/activation 回执与 rollback plan。新 tag 唯一，
应与旧 tag 共存。新包验证、导入、preflight 或 activation 失败时，使用既有 activator 的
独立 rollback 流程选择上一份已验证 tag；禁止把新镜像 retag 成旧 tag，禁止先删旧包/
旧镜像再试。只有保留期与人工批准同时满足后才能清理。

## 12. 操作完成记录

最终记录至少包括：

- 操作者、审批单、UTC 时间；
- architecture、run URL/ID/attempt、commit；
- artifact 名、local bundle SHA-256、GitHub artifact digest；
- 服务器 bundle absolute path、owner/mode/link count、重算 SHA-256；
- 包外 verifier checkout commit、`bundle_sha256`、`manifest_sha256`、`release_id`；
- 四个 app 导入结果与 image IDs；
- PostgreSQL exact reference、pull 时间与 image ID；
- `DESIRE_IMAGE_TAG`；
- 独立 release-input、TLS、preflight、activation/rollback 回执；
- 明确声明：`execution_permitted=false`、`production_authorized=false`，后续执行依赖独立授权。

保存记录不表示本手册编写环境已经运行 workflow、Docker、Compose、迁移或部署。
