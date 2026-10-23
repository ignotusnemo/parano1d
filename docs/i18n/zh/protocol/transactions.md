# 交易协议

普通用户交易是一个规范[逻辑交易](../reference/glossary.md#logical-transaction) [`PagedSpend`](../reference/glossary.md#pagedspend)，由 1 至 128 个固定 [`Tx8x2` 物理页](../reference/glossary.md#tx8x2)以及恰好一份独立的[授权证明封装](../reference/glossary.md#authorization-envelope)组成。

## 物理页

每一页都采用固定 323 字节物理页编码：

| 字段 | 含义 |
|---|---|
| `epoch_anchor` | 当前 144 区块防重放[交易周期（epoch）锚点](../reference/glossary.md#transaction-epoch-anchor) |
| `fee` | 第一页上的逻辑手续费；后续页为零 |
| `input_owner` | 所有有效输入共同的所有者 |
| `inputs[8]` | 可能的 `{slot_index, amount, creation_id}` 记录 |
| `outputs[2]` | 可能的 `{slot_index, amount, owner}` 记录 |
| `validity_bitmap` | 有效记录及逻辑开始/结束位图 |
| `is_coinbase` | 所有用户页均为 `false` |

位 0–7 选择输入，8–9 选择输出，10–11 标记逻辑开始和结束。
合约调用还使用位 12（合约）和 13（关闭）。普通付款这两位为零，14–15 始终为零。

有效位为零的记录必须是全零规范占位记录，从而消除同一命题的替代编码。

## 交易组有效性

有效 `PagedSpend` 必须满足全部规则：

- 页面数为 1 至 128；
- 只有第零页带开始标记；
- 只有最后一页带结束标记；
- 每页具有相同的 `input_owner` 与 `epoch_anchor`；
- 只有第一页可携带非零手续费；
- 有效输入和输出按页面顺序紧密排列；
- 对于这些记录，页面数必须最小；
- 至少有一个有效输入；
- 输入不得重复；
- 输出槽位不得重复；
- 同一笔支出中，输出槽位不得同时作为输入槽位；
- 在类别页数预算内最多 504 个输入和 256 个输出；
- 输入总额等于输出总额加手续费；
- 分离授权不超过 256 KiB。

规范意图的最大编码长度为 303,495 字节。

Small 每块允许 63 页，Large 允许 206 页，共同输入预算为 504。普通逻辑花费仍
最多 128 页且必须完整放入一块。钱包规划和两次内存池检查都执行候选高度的限制。

## 逻辑交易 ID

单个物理页的哈希不能独立标识付款。逻辑 ID 是对以下内容执行带域分离的 Poseidon2b 海绵函数：

```text
version || page_count || ordered_page_hashes
```

初始协议版本为 `1`。重新排序、添加或删除页面都会改变 ID。授权证明封装针对这一精确逻辑 ID，证明其生成者知道 `input_owner` 背后的原像。

## State 检查

对于每个输入，当前[槽位](../reference/glossary.md#slot)记录中的[所有者](../reference/glossary.md#owner)、金额和 [`creation_id`](../reference/glossary.md#creation-id) 必须与交易声明完全一致。对于每个输出，目标槽位必须为空且位于当前有效槽位域内。

输出 `creation_id` 不是交易字段。共识从转换后 State 的分配序列中为其赋值，用户不能选择或复用。

区块转换对完整逻辑组原子地执行所有 State 检查。

## 手续费

最低手续费为（公式中的字段名与传输对象保持一致）：

```text
5,000
+ 100 × live_inputs
+ 700 × live_outputs
+ growth_price × max(0, live_outputs - live_inputs)
```

所有金额均以 μNOID 表示。`growth_price` 从每个净新增槽 2,500 μNOID 开始，并根据父 State 占用率乘以 1、2、4 或 8。

[State 增长费](../reference/glossary.md#state-growth-fee)会被销毁。超过必要最低值的部分是矿工可领取的自愿追加手续费。维持或缩减 State 的支出不支付 State 增长费。

## 交易周期（epoch）锚点

每页使用当前交易周期锚点。对于子高度 `C > 0`，锚点是以下高度上的区块 ID：

```text
floor((C - 1) / 144) × 144
```

高度 144 仍使用高度 0 的锚点；高度 145 开始使用高度 144。[内存池](../reference/glossary.md#mempool)会删除交易周期锚点已不再有效的意图。

## 授权与 State 分离

钱包授权只证明所有权，不证明当前槽位成员关系，也不包含 Live State 的 Merkle 路径。

区块 `HistoryStep` 证明当前成员关系、空槽、余额、分配以及转换后 State 根。两项命题绑定同一公开逻辑交易。

## 合约调用

调用携带 699 字节公开 opening 和一个规范合约页，花费精确的
`(slot_index, creation_id)` 并检查承诺程序、所选授权及金额策略。
继续调用在输出 0 创建更新承诺，输出 1 可选付款；关闭通过输出 0 向分支收款人
付款，不创建后继。

三类支持相同 ABI 和最多 63 次调用，调用与普通花费共享页数和输入预算，并形成
用户页前缀。授权证明所选授权方的秘密，State 所有者则是 opening 的对象承诺。
完整分支规则见[内核](../contracts/core.md)和[生命周期](../contracts/lifecycle.md)。

## 系统记录

主要奖励与计划中的开发付款使用同一种固定[系统记录](../reference/glossary.md#system-record)物理页格式，但并非用户 `PagedSpend` 意图。其形状、位置、接收者和金额完全由区块上下文推导，无需钱包授权。

钱包与内存池流程见[交易架构](../architecture/transactions.md)。

## 原生意图

代币、launchpad、DEX 和 NFT 意图使用类型化 opening 与准确 State 实例。
Native 关系原子验证授权和转换。NOID 付款及 ABI 3 调用可在共同页数及动作预算
内进入同一区块。参见[原生金融](native-finance.md)和
[传输格式](native-wire.md)。
