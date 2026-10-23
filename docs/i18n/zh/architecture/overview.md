# 架构

Parano1d 把每一项证明责任放在相应[见证数据](../reference/glossary.md#witness)原本所在的位置。钱包知道支出秘密，矿工持有公开的 [`State`](../reference/glossary.md#state) 见证数据，全节点则两者都不需要：它只验证生成的证明，并[物化](../reference/glossary.md#materialization)其中已经证明的写入。

![证明原生区块流程](../../../assets/architecture/proof-native-block-flow.svg)

## 证明边界

钱包与矿工证明的是不同命题。

对于普通付款，钱包证明自己知道输入[所有者](../reference/glossary.md#owner)背后的 256 位秘密，并把授权绑定到完整[逻辑交易](../reference/glossary.md#logical-transaction)。它不负责证明输入当前尚未花费，因为钱包无需持有当前 Merkle 路径。

矿工证明公开执行命题：输入存在、输出槽位为空、数值守恒、手续费符合共识、槽位写入精确，而且得到的 [UTXO](../reference/glossary.md#utxo) 根正确。新证明内部还会验证前一个 [`HistoryStep`](../reference/glossary.md#historystep) [终端证明](../reference/glossary.md#terminal)。

这种分离让私有授权始终留在本地，同时允许公开的 State 见证数据在交易构造与区块收录之间发生变化。

| 阶段 | 接收 | 确立 |
|---|---|---|
| 钱包 | 秘密与自有 UTXO | 一份绑定到逻辑交易的随机化授权 |
| [内存池](../reference/glossary.md#mempool) | [`PagedSpend`](../reference/glossary.md#pagedspend) [交易意图](../reference/glossary.md#transaction-intent) | [授权证明封装](../reference/glossary.md#authorization-envelope)、结构、限制、手续费与预留均可接受 |
| 矿工 | 已接受意图与 [Live State](../reference/glossary.md#live-state) | 精确 State 转换与[递归连续性](../reference/glossary.md#recursive-validity) |
| 全节点 | 区块与终端证明 | `HistoryStep`、PoW 与规范父区块有效 |

## 交易与区块流程

1. 钱包选择未花费 UTXO，构造一个逻辑 `PagedSpend`。
2. 钱包针对 `{logical_txid, input_owner}` 构造全新的授权证明封装。
3. 内存池在保存或转发前验证完整交易意图。
4. 矿工选择互不冲突的交易意图，计算精确槽位写入。
5. 矿工证明区块关系与前一个 `HistoryStep` 终端证明，再搜索固定 Poseidon2b 区块头的 nonce。
6. 对等节点验证[已接受区块包](../reference/glossary.md#accepted-block-bundle) `{block, HistoryStep 终端证明}`，并把已证明的写入应用到 MDBX。

任何对等节点都不重复钱包的证明生成过程或矿工执行过程。矿工无法修复无效授权，算力也不能让无效 `HistoryStep` 获得接受。

## 递归连续性

从概念上看，终端证明 `T[h]` 确立三件事：

- 区块 `h` 满足公开区块关系；
- 其转换后 State 根是已证明写入的精确结果；
- 终端证明 `T[h-1]` 验证通过，其累加器给出区块 `h` 之前的精确
  State 边界。

下一个区块在自身关系中验证 `T[h]`。因此，有效性沿链递归累积，而终端形状始终固定。累计工作量仍负责在互相竞争的有效链中作出选择；递归并不替代工作量证明。

## State 物化

验证会产生一组规范槽位写入。全节点把这些写入应用到精确的稀疏 UTXO 向量，而不是再次执行交易逻辑。

[槽位](../reference/glossary.md#slot)位于每个包含 `2^16` 条记录的 [State 分段](../reference/glossary.md#state-segment)中。空分段是虚拟的；清除最后一个占用槽位会删除该分段；分配输出时会先复用空槽位，再扩展 State。新的 [`creation_id`](../reference/glossary.md#creation-id) 可防止旧引用在同一索引复用后重新生效。

节点保留用于[累计工作量](../reference/glossary.md#cumulative-work)比较的紧凑区块头，以及用于常规同步和浅层[链重组](../reference/glossary.md#reorganization)的最近 42 个规范区块体。更早的交易体不是当前共识验证所需数据。付款收据可以在[区块体保留窗口](../reference/glossary.md#body-retention-window)结束后，继续提供可独立验证的包含证据。

## 加入网络

较小的高度差通过保留的区块体以及后缀链尖上的一个已验证递归终端证明补齐。差距较大时，新节点把区块头与经过认证的 State [快照](../reference/glossary.md#snapshot)写入临时区；安装 State 前，它会验证累计工作链、[最终性边界](../reference/glossary.md#finality-boundary)和匹配的边界终端证明，随后验证近期后缀链尖上的一个终端证明并应用相互链接的区块体。

快照不是可信 State。它只是 State 的传输载体，其 State 根和历史边界都由共识认证。

## 挖矿边界

矿工先证明所有与 nonce 无关的数据。之后，PoW 只搜索固定 Poseidon2b 区块头的 128 位 nonce。工作量证明因此只有一个任务：排序有效的 State 转换。

外部矿工接收不可变的一次性模板，只返回 nonce。交易选择、State 转换、证明构造和区块转发均留在节点内。模板一经签发，外部挖矿进程就不能修改收益地址、交易或 State 根。

## 实现组件

| 组件 | 职责 |
|---|---|
| `noid_tx` | 逻辑 `PagedSpend`、交易标识与授权绑定 |
| `noid_mempool` | 交易意图准入、冲突预留与转发策略 |
| `noid_miner` | 交易选择、State 见证数据、区块准备与 PoW |
| `noid_recursive` | `HistoryStep` 关系、终端验证与递归 |
| `noid_chain` | 共识规则、MDBX State、区块头、重组与快照 |
| `noid_p2p` | GossipSub 转发、发现与同步协议 |
| `noid_node` | 运行时编排、钱包集成与关闭流程 |
| `noid_rpc` | 本地节点、钱包与外部挖矿接口 |

部署说明见[在 Linux 上运行节点](../operate/node.md)。

## 合约执行

合约输入承诺程序、策略及当前计数器。钱包使用当前领取方或恢复方的秘密授权
调用。区块关系根据公开条款检查权限，执行有界程序，并证明准确的后继输出或
关闭输出。普通付款与调用共用 State 及递归证明。
参见 [Proof-native contracts](../concepts/proof-native-contracts.md)。
