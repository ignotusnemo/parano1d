# 从源码构建

工作区使用 Rust 2021，并固定 Rust `1.96.0`。MDBX、证明代码和 GUI
打包需要原生依赖。

## 主机要求

所有平台都需要：

- 固定版本的 Rust 工具链，以及 `rustfmt`；
- 原生 C/C++ 编译器；
- CMake；
- libclang；
- Git。

Debian 或 Ubuntu：

```sh
sudo apt update
sudo apt install --no-install-recommends \
  build-essential clang libclang-dev cmake pkg-config
```

Linux GUI 包还需要 `appstreamcli` 和 `dpkg-deb`。Windows 发布打包使用
Inno Setup 6，macOS 使用标准的 `codesign`、`iconutil` 和 `hdiutil`。

仓库中的 `rust-toolchain.toml` 会自动选择编译器：

```sh
rustup show active-toolchain
rustc --version
cargo --version
```

## 检查工作区

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
```

构建普通开发二进制：

```sh
cargo build --locked \
  -p noid_node \
  -p noid-extminer \
  -p noid_gui \
  --bins
```

开发版二进制文件可测试解析、UI 和非生产用证明路径。能够生产区块的发布版需要
下文所述经过认证的 HistoryStep 矩阵包。

## 生产证明材料

生产构建根据一个固定矩阵库认证 Small、Large 和 Native 矩阵。请使用与源码
匹配的主网包和独立核对的摘要。生成的工件应保存在 `target/` 之外。

### 当前矩阵库

三类矩阵包的结构与固定值如下：

```text
v21-runtime-metadata.bin
v21-small.field-r1cs.zst
v21-large.field-r1cs.zst
v21-native.field-r1cs.zst
```

```text
NOID_V21_RELEASE_BANK=6c280ae869afc25e31d46d73b42870512991b78c9498bc7e5ef939bc07e5ed5e
```

固定值绑定矩阵、解释器、资源预算和共识计划。隔离测试网络的矩阵包具有不同
身份。构建会在嵌入前检查元数据及每个矩阵。

### 祖先链验证材料

同步也认证保留的祖先链。历史、矩阵和预处理密钥由独立目录提供：

```text
v1/history-step.runtime
v2-runtime-metadata.bin
v2-small.field-r1cs.zst
v2-large.field-r1cs.zst
class-0.key
class-1.key
```

```text
NOID_V2_RELEASE_BANK=c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e
NOID_RETIREMENT_KEY_0_PIN=<authenticated-key-0-digest>
NOID_RETIREMENT_KEY_1_PIN=<authenticated-key-1-digest>
```

使用独立重算的密钥摘要。固定值文件按数据解析。
[祖先链矩阵库记录](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/research/v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md)
给出矩阵身份和认证过程。

### 祖先链资源计算

以下命令评估保留的祖先链矩阵库、预处理密钥及对应递归归约：

```sh
cargo build --release --locked -p bench_prover --bin noid_v2_soundness
target/release/noid_v2_soundness \
  LEGACY_METADATA LEGACY_METADATA_PIN V2_METADATA V2_BANK_PIN \
  CLASS_0_KEY CLASS_0_KEY_PIN CLASS_1_KEY CLASS_1_KEY_PIN
```

[推导](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/noid_soundness/docs/v2-retirement.md)
明确列出计算的输入和假设。

## 原生发布物

打包前执行源码检查及[验证](testing.md)：

```sh
./scripts/build_release.sh \
  --pack ../parano1d-artifacts/history-step-pack-v1 \
  --v2-pack PATH_TO_FROZEN_V2_PACK \
  --v2-pins PATH_TO_REVIEWED_PIN_FILE \
  --v21-pack PATH_TO_FROZEN_V21_PACK \
  --v21-pins PATH_TO_REVIEWED_V21_PIN_FILE \
  --retirement-keys PATH_TO_AUTHENTICATED_KEYS \
  --retired-history

cat target/release-builds/LAST_RELEASE
```

发布脚本验证输入布局和摘要，嵌入认证材料，拒绝不匹配的计划，构建 Core 和 GUI，
执行二进制冒烟检查，验证包成员和 SHA-256。完整协议测试套件单独运行。
`proof-pins.env` 记录嵌入身份，`--output PATH` 选择新输出目录。

主网使用 `--retired-history`。节点通过 P2P 获取选定来源的证书，并根据独立
固定的预处理密钥验证。二进制嵌入三类矩阵库、保留的祖先链矩阵库及其元数据。
历史输入归档包含 `v1/history-step.runtime`、`pins.env` 及其 `SHA256SUMS`。

发布工具默认选择此配置。`--with-legacy-history` 嵌入完整历史矩阵以供源码复现。
同步根据区块的共识计划选择经过认证的关系。

## 可移植二进制

x86-64 版本针对可移植的指令集基线编译。检查主机后，运行时分派机制
会选择 `pclmul`、`avx2+vpclmul` 或 `avx512bw+vpclmul`。ARM64 选择
`neon+pmull`。

发布产物不得使用 `target-cpu=native` 构建，否则二进制会在运行时硬件
检查之前就依赖构建机器。

## 可复现归档细节

在 GNU tar 主机上，`SOURCE_DATE_EPOCH` 控制成员时间戳，默认值为零。
Core 归档成员固定为：

```text
README.txt
CONTRACTS.md
LICENSE
NOTICE
parano1d
parano1d-cli
parano1d-miner
```

GUI 包只包含应用及其私有节点，不包含运营 CLI 或外部挖矿工具。
