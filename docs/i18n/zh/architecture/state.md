# [Live State](../reference/glossary.md#live-state) 架构

规范 [`State`](../reference/glossary.md#state) 是一个精确的稀疏 [UTXO](../reference/glossary.md#utxo) 向量，以 32 位[槽位](../reference/glossary.md#slot)编号索引。区块头同时承诺其 Merkle 根，以及解释该向量所需的计数器：

- `state_root`；
- `log_slots`，当前槽位域的指数；
- `active_slot_count`；
- `alloc_counter`，下一个创建标识。

State 从 `2^24` 个可用槽位开始，可逐级扩展到 `2^32`。

![基于最终性窗口的 State 扩展](../../../assets/architecture/live-state-expansion.svg)

## 槽位生命周期

已占用的槽位记录金额、所有者和 `creation_id`。支出会把槽位清为规范空值。分配器优先使用空位，因此后续输出可以复用同一个数值索引。

创建标识保证复用安全。输入必须同时匹配 `slot_index` 与 `creation_id`；指向早先占用记录的引用无法花费后来替换它的输出。

```text
slot 9700063, creation 417  ── spend ──>  empty
empty slot 9700063          ─ allocate ─> slot 9700063, creation 894
```

分配器计数器单调递增，并承诺在每个区块头中。

## 分段存储

向量按每个包含 `2^16` 个槽位的 [State 分段](../reference/glossary.md#state-segment)切分。只有包含 UTXO 的分段才会[物化](../reference/glossary.md#materialization)。空分段是虚拟的；清除最后一个已占用槽位后，该分段会从物理存储中移除。

节点由此获得两种有用视图：

- MDBX 中精确的原始分段列，用于钱包查询和转换物化；
- 紧凑的分段根树，用于 State 认证。

在初始 `2^24` 域中，只需 256 个分段根。连同上层树节点，紧凑的精确根缓存约小于 17 KiB。原始分段数据可以独立加载或逐出，而承诺根始终保持精确。

## 证明 State 转换

矿工只收集选中区块所触及的分段。公开区块关系证明：

- 每条输入记录与当前槽位匹配；
- 每个输出目标为空；
- 没有槽位被矛盾使用；
- 数值与手续费守恒；
- 每个转换后的分段根都正确；
- 未触及分支保持不变；
- 重建的全局根等于区块头中的 `state_root`。

被接受的区块公开规范写入。其他全节点验证 `HistoryStep` 后应用这些写入，而不是重新执行交易来推导它们。

## 扩展

扩展依据由 18 个区块头组成的[硬最终性](../reference/glossary.md#hard-finality)占用率窗口。对于父高度为 `H` 的子区块，窗口结束于 `H - 18`，因此不会受到可重组后缀影响。

若 18 个已达最终性的区块头中至少有 10 个报告占用率达到或超过 75%，子区块将 `log_slots` 增加一。9/9 的分布不会触发扩展。

现有树成为新根的左子树，同深度的空树成为右子树：

```text
新根
├── 前一个精确 State 根
└── 规范空子树
```

UTXO 无需移动，分段无需复制，槽位编号保持有效。更新根的工作量与已占用槽位数量无关。

[发行计划](../protocol/economics.md)按区块高度推进。扩容保持现有值和槽位索引，
占用率相关增长费继续为净新增活输出定价。

## State 压力与手续费

普通输入和输出操作具有固定手续费部分。净新增已占用槽位还需支付 [State 增长费](../reference/glossary.md#state-growth-fee)，其倍数随占用率上升。

| 占用率 | 增长倍数 |
|---:|---:|
| 低于 50% | 1× |
| 50% 至低于 75% | 2× |
| 75% 至低于 90% | 4× |
| 90% 及以上 | 8× |

State 增长费会被销毁，其余手续费可由矿工领取。减少或维持已占用槽位数量的交易不支付 State 增长费。

这直接为真正稀缺的资源定价：持久 State，而不是当前共识已经不再需要的历史字节。

## 重启与重组

MDBX 以事务方式存储 State 变更。对于近期区块，有界撤销记录保存回滚 State 所需的精确原值和计数器。节点保留 36 个区块的撤销数据，而共识最多允许 18 个区块的规范链重组。

重启不会从创世区块重建 State。节点打开持久化 Live State，检查其规范元数据，并从当前[终端证明](../reference/glossary.md#terminal)继续运行。

规范规则见[State 转换](../protocol/state.md)，认证 State 传输见[同步](synchronization.md)。

## 合约承诺

输出所有者可以是合约承诺，活金额和实例仍使用同一 State 格式。调用时公开
条款和计数器，参与者保留条款及[回执](../contracts/receipts-and-recovery.md)。
