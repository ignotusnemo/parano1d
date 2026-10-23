# 证明栈

Parano1d 使用同一个二进制算术栈处理所有权、State 转换、Merkle 关系、递归连续性
以及工作量证明承诺。已承诺执行轨迹使用[二进制塔域](../reference/glossary.md#binary-tower-field)
`GF(2^128)`；实际部署的扩展挑战值层使用其二次扩域 `GF(2^256)`。

![Parano1d 证明栈](../../../assets/architecture/proof-stack.svg)

## Poseidon2b

[Poseidon2b](../reference/glossary.md#poseidon2b) 是全系统共同使用的置换：

| 参数 | 数值 |
|---|---:|
| 状态宽度 | 4 个域元素 |
| S-box | `x^7` |
| 全轮数 | 8 |
| 部分轮数 | 58 |

带类型的[域分离](../reference/glossary.md#domain-separation)标签把地址、物理页、逻辑交易、Merkle 节点、State 承诺、区块标识、PoW 摘要和证明交互记录分隔开。共用一个置换并不意味着共用同一个域分离上下文。

## [FROST-GKR](../research/frost-gkr.md)

FROST-GKR 把批量 Poseidon2b 执行与 Merkle 路径表示为共享布尔超立方体上的直接七次关系。Parano1d 使用的是这种承诺列归约（committed-column reduction），而不是逐层重放电路。

该归约保留 GKR 的[多线性扩展](../reference/glossary.md#multilinear-extension)与 [sumcheck](../reference/glossary.md#sumcheck-family) 机制，同时用覆盖整条执行轨迹的全局关系替代递归电路层下降。共享列让大量置换与路径可以共同检查，无需为每个实例单独执行一次约束 sumcheck。

## 闭合关系

后续流水线组合：

- 批量 sumcheck；
- zerocheck；
- lincheck；
- 二进制域上的 [FRI-Binius/BaseFold](../reference/glossary.md#fri-family)；
- 一个 `GF(2^256)` 联合交互记录，用于三个 Link 递归区域和六个 Block 递归区域。

透明证明系统使用认证的联合 Small/Large/Native 矩阵库，固定摘要绑定解释器、预算和激活计划。
合约程序在共享关系内执行。认证来源证书在共同递归关系中保留所选祖先链边界的
绑定。验证使用独立固定的预处理密钥。

## 钱包授权

钱包证明自己知道 `input_owner` 背后的 256 位原像，并把证明绑定到逻辑交易 ID。证明每次重新随机化、隐藏[见证数据](../reference/glossary.md#witness)，且不包含 State 路径。

授权传输格式限制为 256 KiB。规范解码器在验证前检查封装和准确字节消费。

合约输入对承诺策略选定的授权方使用同一秘密知识证明，State 所有者是对象承诺。

## HistoryStep

区块证明者确立完整公开转换，并在新关系中验证前一个终端。因此，新终端绑定：

```text
前一步有效性
        +
当前区块关系
        +
精确的转换后状态
```

证明大小与终端验证不会随链高度增长。永久区块头留在递归之外，用于累计工作量和分叉选择。

## 安全性分析

C1 使用 65 个钱包查询和 133 个 History 查询。祖先链计算包含保留的祖先链及两个
矩阵退役归约。准确清单、组合假设及 Category 1 资源界限见
[安全模型](../protocol/security-model.md)。合约在共享关系内增加确定性约束。
