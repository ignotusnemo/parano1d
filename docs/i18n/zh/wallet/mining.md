# 使用 Core 挖矿

通过 Core 节点或外部工作进程挖矿。钱包提供 Main、Tokens、NFT、
Receipts、Scope、Contracts 和 Settings。

## Core 内置矿工

先检查硬件，再为内置矿工选择 CPU 预算：

```sh
parano1d --check-hardware
parano1d --mode miner --cpu-threads 6
```

Core 构建递归区块证明并搜索有效 nonce。Core 与钱包同时运行时，
为矿工使用独立数据目录。新建区块奖励支付到活动地址或明确配置的奖励地址。

## 外部工作进程与矿池

后端节点生成证明并发布不可变 PoW 模板。外部工作进程搜索 nonce，
再提交找到的解。证明构建保留在后端，工作进程继续使用相同的 PoW 算法。

部署说明见[内置矿工](../operate/internal-mining.md)与
[外部矿工](../operate/external-miner.md)。证明预算见[挖矿概览](../mining/index.md)。

钱包通过自身验证节点跟踪已确认奖励。Main 显示可花费 NOID 输出。
Scope 提供保留区块和永久区块头的查询。
