# 私有服务器运行时发布包合同 v1

状态：**内容合同；不是执行、部署、生产、迁移或公网开放授权。**

本合同冻结 `.github/workflows/private-server-runtime-release.yml` 产生的单一
私有服务器运行时发布包。包是确定性的 POSIX USTAR，编码一个 40 位 Git commit 身份、
一个原生 Linux 架构、一次 GitHub Actions run/attempt、四个应用 OCI archive，以及
固定 PostgreSQL 上游引用的内容证据。成员闭集没有专用 secret/env/credential 项，workflow
也不向 BuildKit 提供 secret 或 SSH forwarding；但 source snapshot、SBOM 与 provenance
仍是不受信任的任意证据 bytes，验包器不执行 DLP 或全字符串敏感信息扫描。因此本合同**不能
证明 bundle 不含敏感文本**，bundle 必须按敏感发布证据保护。它也不证明签名者或 provenance
的真实性。

## 1. 身份与摘要域

一次包的身份只能由下列值共同确定：

- `commit`：小写 40 位 Git SHA-1；
- `architecture`：精确为 `amd64` 或 `arm64`；
- `run_id` 与 `run_attempt`：本次手动 GitHub Actions run 的正整数事实；
- `image_tag`：`sha-<commit>-<architecture>-r<run_id>-a<run_attempt>`；
- `release_id`：`runtime-release-<image_tag>`；
- bundle 文件名：`runtime-release-<image_tag>.tar`。

操作者必须先从 workflow 原始记录取得 commit、architecture、run ID 与 attempt，按固定公式
构造预期 `image_tag`，再与受信 helper 验证后返回的 `release_id` 交叉核对。`verify-bundle` 与
`stage-bundle` 的 stdout 不返回 commit、architecture 或 `image_tag`；不得从 `release_id`、
文件名或 stage 路径反向补齐缺失的 workflow 事实。

必须分别记录两个摘要域：

1. workflow 在上传前对单一 `.tar` 文件计算的 **local bundle SHA-256**；
2. `actions/upload-artifact` 返回的 **GitHub artifact digest**。

两者描述不同传输/对象域，不得互相替代，也不得假设相等。服务器落盘后的 bundle
文件必须重算 SHA-256，并与 workflow 记录的 local bundle SHA-256 比较；GitHub
artifact digest 只作为独立的上传记录保留。

## 2. USTAR 外层合同

发布包必须满足全部条件：

- 成员名按 ASCII bytes 升序；精确为本合同的 10 个目录成员与 26 个文件成员；
- 不允许缺失、额外、重复、绝对路径、`.`、`..`、反斜杠或控制字符成员；
- 只允许目录与 regular file；禁止 symlink、hardlink、device、FIFO、sparse 与
  PAX header；
- 目录成员模式 `0700`，文件成员模式 `0400`；
- `uid/gid/mtime/devmajor/devminor` 全部为 `0`，`uname/gname` 为空；
- 每个成员必须使用连续的单个 512-byte POSIX USTAR header，regular file 数据到下一 block 的
  padding 必须全部为零；禁止被 tar reader 隐藏的 GNU extension/header；
- 末尾只能是规范的全零 512-byte blocks，不得追加非零内容；
- 包文件本身必须是 owner 持有、单 hardlink 的 `0400` regular file，直接父目录
  必须为同一 owner 的全新 `0700` 目录。

## 3. 成员闭集

| 类别 | 精确成员 | 数量 | 合同作用 |
|---|---|---:|---|
| 根目录 | `attestations`、`contracts`、`images`、`postgres`、`source`、`tools` | 6 | 固定命名空间 |
| 应用证明目录 | `attestations/platform`、`attestations/web`、`attestations/edge`、`attestations/oidc-egress-guard` | 4 | 四个应用的独立证明投影 |
| 根文件 | `README.txt`、`release.json` | 2 | 非授权说明与 canonical release manifest |
| Source | `source/source-snapshot.tar`、`source/dockerfile-digest-set.json` | 2 | source bytes 与四个固定 Dockerfile target 的内容绑定；Git 来源边界见下文 |
| 应用 OCI | `images/platform.oci.tar`、`images/web.oci.tar`、`images/edge.oci.tar`、`images/oidc-egress-guard.oci.tar` | 4 | 与本包架构和唯一 image tag 绑定的完整应用 OCI archive |
| 应用 SBOM | `attestations/platform/sbom.intoto.json`、`attestations/web/sbom.intoto.json`、`attestations/edge/sbom.intoto.json`、`attestations/oidc-egress-guard/sbom.intoto.json` | 4 | 从对应 OCI archive 闭合读取的 SPDX statement |
| 应用 provenance | `attestations/platform/provenance.intoto.json`、`attestations/web/provenance.intoto.json`、`attestations/edge/provenance.intoto.json`、`attestations/oidc-egress-guard/provenance.intoto.json` | 4 | 对应 runnable platform manifest 的 SLSA provenance v1/min |
| PostgreSQL registry/config | `postgres/registry-index.json`、`postgres/platform-manifest.json`、`postgres/image-config.json`、`postgres/attestation-manifest.json`、`postgres/attestation-config.json` | 5 | 固定上游 root index 与所选架构的 registry/config/attestation graph |
| PostgreSQL statements | `postgres/sbom.intoto.json`、`postgres/provenance.intoto.json` | 2 | 上游原字节 SPDX 与 legacy SLSA provenance v0.2 |
| Contract | `contracts/private-server-runtime-release-v1.schema.json` | 1 | 随包留存的 schema 证据；不是验包 trust root |
| Tools | `tools/private_server_runtime_release.py`、`tools/prepare_private_server_runtime_release.py` | 2 | 随包留存的 verifier bytes；不是验包 trust root，验包前禁止执行 |

除此之外没有合法成员。构建时使用的 `source-facts.json` 与物化 build context 只作为
组装输入，不进入最终 bundle。PostgreSQL fetch 阶段的 `evidence.json` 也不进入最终
bundle；其七个已交叉验证的 raw objects 进入上述 `postgres/` 闭集。

### Git 来源证明边界

workflow 中的受信 source helper 从已 checkout 的 `github.sha` Git object 读取树并生成规范
snapshot；最终 bundle 则只保留 snapshot、Dockerfile digest set 及其 manifest 摘要，不包含
`source-facts.json`、Git commit/tree object 或签名证明。因此包外 verifier 可以离线证明
source bytes 与 `release.json` 自洽，却**不能只凭 bundle 独立证明**这些 bytes 确实来自
`release_id` 所编码的 Git commit。

exact commit 来源必须同时依赖并保留 workflow 的 head commit/run 记录、上传前 local bundle
SHA-256、服务器重算的同一 SHA-256，以及固定到已批准 commit 的包外 verifier checkout。
任一外部事实缺失或不一致都必须拒绝；不得把 bundle 内的 commit 字符串、文件名、unsigned
provenance 或 `source-facts.json` 的构建期自述升级为 Git 来源证明。

## 4. `release.json` 绑定

`release.json` 必须是 newline-terminated canonical JSON，并满足
`desire-private-server-runtime-release-v1`：

- `status=VALIDATED_RELEASE_ARTIFACT_NOT_AUTHORITY`；
- `authority=NOT_AUTHORITY`；
- `execution_permitted=false`、`production_authorized=false`；
- `target_platform` 精确绑定 `linux/<architecture>`；
- schema heads 精确绑定 PostgreSQL 18、IAM 43、Profile 3、Demand 13、Trust 19、
  Taxonomy 2；
- 该 IAM43 / Demand13 / Trust19 pin 适用于 current-head v26，且不改变 runtime release format
  `v1`。它只适用于合同前移后重新生成的新制品；所有历史 bundle、
  fixture、manifest 与回执仍保持各自的模式头事实，包括 current-head v25 与冻结的 current-head v24
  IAM42 / Demand12 / Trust18、current-head v23
  IAM42 / Demand12 / Trust17、current-head v22 的 IAM42 / Demand12 / Trust16、current-head v20 的
  IAM41 / Trust14、current-head v19 的 IAM40 / Trust13、current-head v18 的 IAM39 / Trust12，
  以及 v15/v16/v17 的 Trust9/Trust10/Trust11，不得重标或冒充 IAM43 / Demand13 / Trust19；
- source snapshot、Dockerfile digest set、每个 OCI archive、SBOM、provenance 与每个
  PostgreSQL raw object均由 `sha256 + size` 绑定；
- source snapshot 必须保持规范 producer 的连续 USTAR header、逐成员全零 padding 与至少两个
  全零 terminal blocks；摘要重绑不能使非规范 padding 合法；
- 四个应用 reference 必须分别绑定固定 repository、唯一 `image_tag` 与对应 OCI root
  index digest；
- 每个应用 OCI archive 本身必须是单一连续 tar stream；最后一个成员后至少有两个完整
  512-byte zero terminal blocks，每个 member data padding 与全部 trailing bytes 都必须为零，
  trailing 必须 512 对齐，禁止拼接第二个 tar 或藏入 opaque trailer；
- PostgreSQL reference 必须精确为：
  `postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`。

## 5. 应用与 PostgreSQL provenance 边界

workflow 通过固定 action commit 请求 Buildx `v0.36.1`，并使用 digest 固定的 BuildKit
`v0.32.2` 形成 `mode=min,version=v1` provenance。Buildx release asset 只做版本字符串核对，
没有独立内容 checksum；因此不得称为 Buildx binary 内容固定。验包器要求：

- predicate type 精确为 `https://slsa.dev/provenance/v1`；
- subject 精确绑定对应应用的 runnable platform manifest；
- builder platform 精确为 `linux/<architecture>`；
- BuildKit `mode=min` request 必须存在，`configSource.path=Dockerfile`、
  `frontend=dockerfile.v0`、`compatibilityVersion=30`，且 `args.target` 精确等于该 slot 的固定
  Dockerfile target；缺失或替代 target、额外 local source 都必须拒绝；
- Build request 的闭集不允许声明 BuildKit secret、SSH forwarding 或能重绑构建语义的任意
  客户端 authority；这不是对 source/SBOM/provenance 任意字符串的敏感信息扫描；
- SBOM predicate 精确为 `https://spdx.dev/Document`。

本合同绑定最终 OCI archive、runnable manifest 与 statement bytes，**不声明构建输入闭包或
可复现构建**。当前 platform wheel 构建没有消费 `uv.lock` 的完整 transitive lock/hash，
OIDC egress guard 的 Debian index 与 `nftables` 包也没有 snapshot/version 固定；同一 commit、
相同 base digest 和所选工具版本仍可能解析到不同在线依赖。只有最终产物在本 bundle 内被摘要
闭合，不得从这种产物闭合反推依赖可复现性或 runner/builder 可信性。

PostgreSQL 是唯一历史格式例外。bundle 原样保存固定 Docker Hub 上游的 legacy、rich
provenance，predicate type 精确为 `https://slsa.dev/provenance/v0.2`，并验证其
builder、invocation、metadata、materials 与固定 manifest subject 的封闭结构。不得把
这个例外用于四个应用，也不得把 v0.2 重新描述为本项目生成的 v1/min provenance。

两种 provenance 都是 **unsigned、untrusted、not authority**：当前合同不验证签名，
不认证 statement producer，不形成 SLSA level 声明，也不授权执行或生产发布。

## 6. PostgreSQL 不在离线镜像包内

`postgres/` 只含 registry index、所选 platform manifest、image config、attestation
manifest/config、SBOM 与 provenance。它**不含 PostgreSQL runnable filesystem
layers，也不含 PostgreSQL OCI archive**。

因此：

- 四个应用可以在 bundle 完整离线验证后从其 OCI archive 导入；
- PostgreSQL 必须在单独批准的联网阶段，从上述固定 digest online pull；
- 禁止从 tag-only `postgres:18.4-alpine` pull，禁止用镜像 tar 或其他 registry 替代；
- bundle 的 PostgreSQL 证据不会把后续 pull 自动变成可信、可执行或生产授权。

## 7. Trust bootstrap 与验包

bundle 中的 `tools/` 和 `contracts/` 是被验证内容，不是验证者。唯一支持的第一步是使用
**仓库外部、事先审核和固定的** `prepare_private_server_runtime_release.py`，以及它的
外部 sibling `private_server_runtime_release.py` 与 schema，执行完全离线：

```text
python3 -I -B <trusted-checkout>/scripts/prepare_private_server_runtime_release.py \
  verify-bundle --bundle <absolute-owner-only-0400-bundle>
```

验包器在 bundle 的直接父目录创建随机命名
`.<bundle-basename>.verify-*`、模式 `0700` 的完整解包树，逐成员和逐 artifact 验证，并且
无论成功或失败都**不自动删除**该树。每次调用都会创建新的树；它不联网、不调用 Docker、
不导入镜像、不启动容器。操作者必须在调用前为原 bundle 加一份完整展开副本预留容量；
验包器接受的 bundle 上限为 64 GiB。成功输出仍必须包含 `execution_permitted=false` 与
`production_authorized=false`，并返回四个应用 slot 到已验证 OCI `config_digest` 的精确闭集
`image_config_digests`。解包树不是有效 stage，不得送给 Docker，只能在记录路径与结果后交给
独立审核、独立授权的清理流程。

通过后，仍只能使用同一份包外受信 helper 的：

```text
python3 -I -B <trusted-checkout>/scripts/prepare_private_server_runtime_release.py \
  stage-bundle --bundle <absolute-owner-only-0400-bundle> \
  --destination <absolute-new-stage-directory>
```

`stage-bundle` 必须从同一 bundle fd 重算摘要、执行相同的成员闭集和全量 artifact 验证，
再把完整闭集原子落到 owner-only stage：root/目录 `0700`、regular files `0400`。destination
必须不存在且其直接父目录必须为同一 owner 的 `0700`。禁止用 `tar -xf`、bundle 内工具或
自写 extractor 绕过该步骤。canonical stage receipt 必须返回四个应用 slot 到已验证 OCI
`config_digest` 的精确闭集 `image_config_digests`；这是后续 Docker image ID 门禁的唯一输入，
不得手填或从 Docker 反推。

只有 stage 成功后，操作者才可从 `stage/images/` 四次执行固定的
`docker image load --input ... --platform linux/<architecture>`。随后必须证明四个预期
repository:tag 都存在、能以该精确引用解析到正确 platform，并记录解析出的 image ID/镜像
证据。每个引用的 Docker `.Id` 必须精确等于 receipt 中该 slot 的 `config_digest`。若预期 tag
在导入前已存在，只有它已解析到同一个 expected ID 时才可幂等复用；指向其他 ID 时必须在
load 前拒绝，禁止覆盖或 retag。同一个 expected ID 因旧发布或重复构建而已有其他 tag 不构成
失败；预期 tag 缺失、ID 不同或 platform 不同都必须拒绝。通用 `docker load` 不能直接读取
未 stage 的 bundle，也不能用于 `postgres/` evidence。precheck、load、postcheck 到后续
activation receipt 固定必须处于无其他 Docker actor 改写这四个 tag 的排他发布窗口；合同不把
并发 Docker 管理员当作可抵抗攻击者。最终 activation preflight 还必须 fresh inspect 并再次
把四个 tag 的 `.Id` 绑定到同一 receipt 的 expected config digests。

## 8. 必须拒绝

出现任一情况必须退出本轮、保留原始文件并记录失败，不得原地修补：

- architecture、commit、run/attempt、文件名、release ID 或 image tag 不一致；
- 服务器重算 bundle SHA-256 与 workflow local bundle SHA-256 不一致；
- 将 GitHub artifact digest 当作 local bundle SHA-256；
- bundle 或父目录 owner/mode 不符，存在 symlink、hardlink 或已有路径覆盖；
- 包成员闭集、顺序、类型、模式、metadata、terminal blocks 不符；
- `release.json`、schema、source snapshot、Dockerfile target、artifact digest/size 任一
  不闭合；
- OCI archive 的 repository/tag、架构、root index、platform manifest、config、SBOM、
  provenance subject/predicate 任一不符；
- PostgreSQL 固定 root digest、所选架构 graph 或七个 raw objects 任一不符，或包内出现
  PostgreSQL runnable layer/archive；
- 人工检查或另行批准的扫描实际发现 secret、credential、TLS private key、OIDC client
  secret、Compose env、部署授权或其他不应进入证据的内容；内置 verifier 不承诺发现任意
  statement/source 字符串中的敏感信息；
- verifier 不是事先固定的包外受信副本，或返回非零/`BLOCKED`；
- 有人要求 build、retag、关闭验证、放宽 digest、现场改 manifest 或借 v0.2 例外降低应用
  provenance 要求。

fetch、create、verify 或 stage 不自动删除它已创建的 owner-only `0700`/`0400`
partial/remnant；其中每次 verify 即使成功也保留完整随机解包树。自动 path-based cleanup
会重新打开可替换路径的竞态，因此 create、fetch、stage 失败后的重试必须使用全新的
absolute output/destination，verify 重跑则会产生另一棵随机树。遗留树既不是有效
bundle/stage，也不得送给 Docker，只能由独立审核、独立授权的清理流程处置。服务器必须把
这些保留副本计入磁盘容量和保留策略，容量不足时应在验包前拒绝，而不是边验边删。

这里的 owner-only、no-follow、closed-set、对象身份复验与 no-replace 原子发布防止非同 UID
改写、已有路径覆盖和已检查边界上的替换，也避免 helper 自己执行危险的路径清理；它们**不把
同一有效 UID 下的恶意或已失陷并发进程当作可抵抗攻击者**。同 UID 进程可在验证期间或返回后
改写其 owner 文件。因此 helper 必须在专用、无其他不受信同 UID 进程并发的发布账号下运行；
该前提不成立时必须拒绝本轮并按账号失陷处理，不能把一次成功回执当作持续完整性证明。

## 9. 非授权与回滚保留

一个通过验证的 bundle 仍然：

- 不授权执行 Docker 或 container lifecycle；
- 不批准部署、生产流量、数据库迁移、restore、seed 或公网入口；
- 不替代 release inputs、secret、TLS、OIDC、IPAM、preflight、activation 或人工批准；
- 不证明 workflow、runner、builder、scanner、registry 或 attestation producer 可信。
- 不只凭自身证明 source snapshot 的 Git commit 来源；该事实依赖上文列出的 workflow 与
  local bundle digest 外部记录。

每个已批准 release 必须保留 bundle `0400` 原件、local bundle SHA-256、GitHub artifact
digest、run URL/ID/attempt、commit、architecture、manifest SHA-256、验证输出和导入记录。
新 tag 含 commit/architecture/run/attempt，可与旧 tag 共存。新包验证、导入或激活失败时，
不得删除或 retag 旧镜像；回滚必须选择上一份完整验证并仍在保留期内的 bundle/tag，走独立
activation/rollback 流程。未经保留策略批准，不得清理旧包、旧 OCI archive、旧镜像 ID
或其操作记录。
