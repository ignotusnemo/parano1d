# 挖矿

**仅有哈希算力无法生成区块。挖矿需要 [State](../reference/glossary.md#state)；只有证明完成后才能开始搜索 [nonce](../reference/glossary.md#nonce)。**

Parano1d 的工作量证明负责为已经证明有效的 State 转换排序。在搜索
nonce 前，区块生产者必须跟随[规范链](../reference/glossary.md#canonical-chain)、持有 [Live State](../reference/glossary.md#live-state)、构建精确的下一
次转换，并完成递归 `HistoryStep`。

因此，独立生产区块的基本单元是能够生成证明的完整节点，而不是单独的哈希
挖矿工作进程。

![证明原生区块流程](../../../assets/architecture/proof-native-block-flow.svg)

## 节点和挖矿进程分别做什么

区块归属于挖矿节点。节点负责：

- 跟随并独立验证规范状态链；
- 在交易意图进入内存池前进行验证；
- 选择互不冲突的交易集；
- 固定奖励、费用、槽位写入和转换后 State 根；
- 证明与 nonce 无关的区块部分和前一终端证明；
- 验证获胜 nonce；
- 原子提交并广播完整的 `{block, HistoryStep 终端证明}` 区块包。

Nonce 搜索可以在该进程内部运行，也可以交给 `parano1d-miner`。外部
挖矿进程的职责窄得多：

- 接收一份不可变的 Poseidon2b 区块头输入序列和目标值；
- 搜索 128 位 nonce 的独立取值；
- 把候选 nonce 返回节点。

挖矿进程不会收到区块体、State 见证数据或 `HistoryStep` 见证数据。证明完成
后，它无法替换交易、更改 State 根或修改模板。

## 一次区块尝试

区块生产按以下顺序进行：

1. 节点等待同步完成，并满足所需的[已完成身份认证的对等节点](../reference/glossary.md#authenticated-peer)数量。
2. 读取规范链尖、Live State 和内存池中可接受的交易意图。
3. 选择 Small、Large 或 Native 证明类别，并固定候选区块除 nonce 之外的全部语义
   字段。
4. 计算精确的槽位写入和最终 UTXO 根。
5. 证明新的 `HistoryStep`，包括与前一终端证明的递归连续性。
6. 完成的证明固定一份不可变挖矿模板。
7. 内置矿工或外部挖矿进程搜索 Poseidon2b nonce。
8. 节点验证 nonce、封装已准备的终端证明、原子提交区块并向对等节点
   宣布。

新的规范链尖会使未完成工作过期。节点丢弃该尝试，从新的 State 重新开始；绝不
把旧证明移到不同父区块或交易集上。

对等节点只有在独立验证父区块、`HistoryStep`、PoW 目标值和所有共识
承诺后才接受结果。有效竞争链之间由累计工作量决定胜者。

## 两种挖矿模式

| 模式 | 证明构建 | Nonce 搜索 | 适合场景 |
|---|---|---|---|
| 内置 | Core 节点 | Core 节点 | 单机矿工、矿池后端、单台服务器 |
| 外部 | Core 节点 | `parano1d-miner` | 独立 CPU 挖矿进程、私有挖矿网络或矿池 |

两种模式遵循同一套共识规则，生成完全相同的区块。外部挖矿只把 nonce
搜索移过 RPC 边界。

普通 `--mode node` 进程会验证并中继区块，但不构建挖矿模板。

## 钱包与 Core

钱包提供资产和合约工作区。使用 Core 内置矿工或外部工作进程挖矿。
为独立挖矿节点选择专用数据目录。钱包通过自身验证节点跟踪已确认奖励。

操作流程见[使用 Core 挖矿](../wallet/mining.md)。

## 运行 Core 内置矿工

创建节点数据前，先检查实际主机：

```sh
parano1d --check-hardware
```

以内置矿工模式启动 Core：

```sh
parano1d --mode miner --cpu-threads 12
```

省略 `--cpu-threads` 时，使用进程可见的全部逻辑 CPU。未配置奖励地址时，
Core 使用本地钱包活动地址。也可固定一个独立的规范 bech32m 地址：

```sh
parano1d --mode miner --miner-address o1...
```

在另一个终端观察就绪状态和链进度：

```sh
parano1d-cli status
parano1d-cli peers
parano1d-cli mining
```

如果未同步或已完成身份认证的对等节点少于一个，Core 会等待，不会在孤立的本地视图上
挖矿。完整服务器和 systemd 流程见
[内置挖矿](../operate/internal-mining.md)。

## 运行外部挖矿进程

启动负责持有并证明外部挖矿模板的节点：

```sh
parano1d \
  --mode extminer \
  --mining-key-file ~/.parano1d/mining.key
```

让挖矿进程连接节点的本地回环 RPC：

```sh
parano1d-miner \
  --rpc http://127.0.0.1:9601 \
  --key-file ~/.parano1d/mining.key \
  --threads 12
```

节点在返回模板前已经完成整份证明。挖矿进程只搜索 nonce 并提交结果。模板
一次性使用，30 秒后过期；接受竞争链尖时也会立即失效。

远程挖矿进程应通过经过认证的私有网络或受防火墙限制的 TLS 端点连接。
Bearer 令牌用于认证挖矿进程，但不会加密普通 HTTP。它只允许
`getBlockTemplate` 和 `submitBlock`，不能访问钱包或节点控制方法。旧的
`--mining-key` 和 `--key` 参数继续兼容，但受保护的 key 文件可避免令牌出现在
进程参数中。

奖励地址默认由节点控制。是否允许经过认证的挖矿进程请求自己的奖励地址，是
运营者的显式选择。远程配置与信任边界见
[外部矿工](../operate/external-miner.md)。

## CPU 与证明容量

生产环境要求 x86-64 的 SSE4.1 + PCLMULQDQ 或 ARM64 的 NEON + PMULL。
证明和 PoW 共享线程预算，请为钱包和 P2P 留出资源。

矩阵库认证三种类别：

| 类别 | 页数 | 活输入 | ABI 3 调用 |
| --- | ---: | ---: | ---: |
| Small, m23 | 63 | 504 | 63 |
| Large, m24 | 206 | 504 | 63 |
| Native, m24 | 63 | 504 | 63 |

Small 和 Large 支持 NOID 付款与 ABI 3 调用。Native 另支持代币、launchpad、
DEX 和 NFT。节点自动考虑 Small 和 Native。`--v2-large-blocks` 额外允许
Large。可领取费用最高的候选胜出，费用相同时保留更早的候选，Small 首先被考虑。
节点构建一个证明。所有已更新节点均验证三类。

页数、输入和调用限制同时适用。主 coinbase 单独计算，额外系统付款占一个有效页。
`getContractProtocol` 和 `getNativeProtocol` 返回安装的预算。

实测改进见[性能](../reference/performance.md)，原生预算见
[原生金融](../protocol/native-finance.md)。

## 难度、奖励与确认

ASERT 根据已接受区块之间的完整间隔调整 Poseidon2b 目标值。证明准备、nonce
搜索与区块传播共同使用平均 30 秒的目标。累计有效工作量
最大的链获胜；工作量相同时使用规范区块哈希作确定性决胜。

奖励按高度计划从 16 NOID 开始，每 1,051,200 个区块下降一次，计时从 H210537 开始。
挖矿 RPC 显示下一块总补贴：

```sh
parano1d-cli mining
```

在三年开发分配期内，矿工获得每个新区块发行奖励的 90%。扣除共识规定的
[State 增长费](../reference/glossary.md#state-growth-fee)销毁后，可领取的交易费也归矿工。分配期结束后，每个新区块奖励的
100% 都支付给矿工。

本机找到区块后，余额并不会立刻具有最终性。后续有效区块会增加确认深度；
在保留的竞争窗口内，更高工作量的浅层重组仍可能替换它。

## 挖矿与去中心化

自主矿工不能只依靠哈希算力。它的节点必须保持最新、验证收到的工作、构建
并证明下一 State，之后 nonce 引擎才能得到有用任务。如果该节点接受入站
P2P，同一套基础设施还会中继交易和区块，并向其他节点提供同步数据。

外部挖矿进程和矿池仍然可行：一个证明节点可以服务多个 nonce 搜索进程。
专用 nonce 硬件仍需依赖能以所需速度构造有效区块证明的节点。

区块头的精确关系见[工作量证明](../protocol/proof-of-work.md)，实现流水线
见[区块生产](../architecture/mining.md)。
