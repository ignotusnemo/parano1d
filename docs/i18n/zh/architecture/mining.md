# 挖矿架构

**只有算力无法生成区块。挖矿需要 [`State`](../reference/glossary.md#state)；只有证明完成后才能开始搜索 [nonce](../reference/glossary.md#nonce)。** 区块生产者必须持有当前 [Live State](../reference/glossary.md#live-state)，并在开始搜索 nonce 前确立精确的下一次转换。因此，独立矿工是由算力支撑、能够生成证明的全节点，而不是无状态的哈希端点。

挖矿严格分为两个有序阶段：

1. 选择交易、构造 State 转换，并证明完整的无 nonce 区块；
2. 搜索固定 Poseidon2b 区块头的 128 位 nonce。

这样的顺序避免把工作量证明浪费在尚未确立 State 转换的区块上。

## 构造模板

节点从[规范链尖](../reference/glossary.md#canonical-chain)与当前[内存池](../reference/glossary.md#mempool)出发。它按费率选择互不冲突的逻辑交易，同时遵守 State、分段和证明类别限制。随后：

- 计算 coinbase 奖励以及计划中的系统付款；
- 分配新的输出创建标识；
- 推导规范槽位写入；
- 计算交易根与转换后 State 根；
- 构造 `HistoryStep` 公开输入；
- 生成新的终端证明。

至此，除区块头 nonce 外的一切内容都已不可变。

系统铸币选择槽位时，优先避开其他待处理交易预留的输出。这只是有界的本地偏好，不是禁止条件。若未找到替代槽位，就使用原来的有效选择。已选入区块的交易仍受严格保护，基金收款方、金额和付款计划不变。

## Small、Large 和 Native

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

## CPU 调度

内置矿工在证明构造与 nonce 搜索之间共享一个 CPU 线程池，不会同时运行两个互不相关、各自占满全部核心的任务。

本地钱包工作拥有优先级。用户在挖矿期间发送交易或执行归集时，节点会在本地边界暂停或让出挖矿 CPU，完成交易授权和提交后再继续挖矿。网络规则、对等节点优先级和全局手续费策略均不会改变。

## 模板刷新策略

只有改变有效工作的事件才会重建模板：

- 出现新的规范链尖；
- 挖矿收益地址变化；
- 第一笔交易进入此前只有 coinbase 奖励的模板；
- 已选交易失效。

150 秒心跳刷新只是安全兜底，并非正常刷新循环。已经证明的模板始终绑定原始收益地址和交易集；证明构造完成后不再修改。

## 内置矿工

内置矿工运行在节点进程内。节点负责交易选择、证明构造、PoW 和区块提交。CPU 线程数与收益地址可通过 Core 及其本地 RPC 控制。

节点只有在同步完成且至少连接一个[已完成身份认证的对等节点](../reference/glossary.md#authenticated-peer)时才开始挖矿。本地找到的区块按与收到区块相同的共识规则完成封装、提交和公告。提交路径复用本地已证明的精确 State 转移，不重复验证同一个证明。收到的区块仍需验证证明。

## 外部矿工

外部矿工只把 nonce 搜索移出节点。它请求一个不透明、一次性的模板，其中包含：

- 模板标识；
- 精确的 16 字段 Poseidon2b PoW 输入序列；
- 目标值；
- 过期时间与显示元数据。

外部矿工返回一个小端序 128 位 nonce。节点根据仍然有效的模板验证 nonce，封装已经证明的区块，并使模板失效。外部模板 30 秒后过期；链尖改变或成功提交后均不能重放。

外部挖矿进程无权替换交易、改变 State、修改手续费或重新计算 coinbase 奖励。使用自定义 coinbase 地址必须显式启用相应节点设置，并提供 Bearer 密钥。

## [分叉选择](../reference/glossary.md#fork-choice)

挖矿扩展[累计工作量](../reference/glossary.md#cumulative-work)最高的有效链。工作量相同时，以字典序更小的区块哈希作为确定性决胜规则。任何试图替换[硬最终性](../reference/glossary.md#hard-finality)前缀的候选链都不具备资格。

部署方法见[内置挖矿](../operate/internal-mining.md)和[外部矿工](../operate/external-miner.md)，精确 nonce 关系见[工作量证明](../protocol/proof-of-work.md)。
