# 工作量证明

Parano1d 的[工作量证明](../reference/glossary.md#proof-of-work)是在固定语义区块头字段上计算的带[域分离](../reference/glossary.md#domain-separation) [Poseidon2b](../reference/glossary.md#poseidon2b) 摘要。它只在不含 [nonce](../reference/glossary.md#nonce) 的 `HistoryStep` 完成证明后运行。

## 字段序列

`POWHDR__` 海绵函数精确吸收 16 个 `GF(2^128)` 元素：

| 索引 | 字段 |
|---:|---|
| 0–1 | `prev_block_hash` |
| 2–3 | `state_root` |
| 4–5 | `tx_root` |
| 6 | `timestamp` |
| 7 | `height` |
| 8–9 | `miner_address` |
| 10 | 128 位 nonce |
| 11–12 | `difficulty_target` |
| 13 | `log_slots` |
| 14 | `active_slot_count` |
| 15 | `alloc_counter` |

32 字节值拆成两个小端序 128 位半段，标量整数以零扩展。海绵结构的速率为二，因此该字段序列恰好占八个速率块，不需要变长填充。

PoW 域同时区别于含 nonce 的区块身份域和无 nonce 的语义区块头承诺域。

## 目标值比较

摘要与目标值均解释为 256 位小端序整数。Nonce 只有在以下条件成立时有效：

```text
pow_digest < difficulty_target
```

相等也视为失败。

## ASERT

已接受区块之间的目标间隔为 30 秒。证明准备、nonce 搜索与区块传播共同占用
这一完整间隔。[ASERT](../reference/glossary.md#asert) 使用六区块参考周期和 180 秒半衰期。
从高度 210,537 的 v2 激活起，每个区块的精确目标值由规范锚点及其父区块的高度和时间戳推导。
同一父区块的子区块目标值相同，候选区块自己的时间戳不能改变其工作量。

时间戳还必须大于前 11 个区块头的过去时间中位数（median time past），并且最多领先验证节点本地时钟 120 秒。

## 运行时内核

同一个固定置换按 nonce 批次计算。发布版二进制文件会在运行时选择主机支持的最佳实现：

- x86-64 上以 `pclmul` 为基线；
- 可用时使用 `avx2+vpclmul`；
- 支持主机上的 `avx512bw+vpclmul`；
- ARM64 上的 `neon+pmull`。

批量执行只改变吞吐量，不改变摘要。标量实现是用于交叉校验的参考实现，不作为发布版运行时的回退路径。

## 外部挖矿边界

外部挖矿进程收到精确的 16 字段输入序列、nonce 索引与目标值，只返回规范的 16 字节小端序 nonce。节点在提交区块前，根据不可变的一次性模板验证结果。

外部挖矿进程无法修改交易、State 根、收益地址或证明。使用过期模板求得的 nonce 会被拒绝。
