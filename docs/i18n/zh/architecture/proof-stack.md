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

最终证明系统是透明的，不需要[可信设置](../reference/glossary.md#trusted-setup)。发布的可执行文件内嵌经过认证的 [B25 与 B255](../reference/glossary.md#b25-b255) 矩阵包以及预期摘要。使用不同矩阵包的构建无法悄悄冒充规范关系。

## 钱包授权

钱包证明自己知道 `input_owner` 背后的 256 位原像，并把证明绑定到逻辑交易 ID。证明每次重新随机化、隐藏[见证数据](../reference/glossary.md#witness)，且不包含 State 路径。

序列化授权的最坏情况上界为 92,696 字节。网络格式允许最高 256 KiB，使解码
保持明确有界，同时为规范证明对象保留空间。

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

实际部署的扩展挑战值配置使用 65 次钱包查询和 133 次 History 查询，得到以下结果：

| 安全性结论 | 实际部署结果 |
|---|---:|
| FRI 目标安全性 | **128 位** |
| 可证明 Block–Tiwari FS-FRI 安全性 | **127 位** |
| 基于猜想的 Block–Tiwari FS-FRI 安全性 | **127 位** |
| 顺序理想 QROM 中成功概率为二分之一的边界 | **64.707407428576 位** |
| NIST 后量子密码学类别 | **Category 1** |
| Category 1 门数与深度乘积的主导下界 | **173.391078499301 位** |

Block–Tiwari 数值衡量经典随机预言机模型中的 FS-FRI 期望工作量。Category 1
结果属于另一项从创世开始的端到端无效 State 可靠性游戏，并以定理明确声明的
固定 Poseidon2b 偏差上界与相干响应成本为前提。实际部署常量、归约和精确计算见
[`noid_soundness`](https://github.com/ignotusnemo/parano1d/tree/main/noid_soundness)。

声明边界与证明系统之外的假设见[安全模型](../protocol/security-model.md)，实现 crate 见[工作区结构](../developers/workspace.md)。
