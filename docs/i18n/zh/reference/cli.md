# 命令行接口

Core 压缩包包含三个可执行文件：

| 可执行文件 | 角色 |
|---|---|
| `parano1d` | 完整节点、钱包后端，以及可选的内置证明/挖矿流水线 |
| `parano1d-cli` | 连接运行中节点的轻量 JSON-RPC 客户端 |
| `parano1d-miner` | 独立的 Poseidon2b nonce 搜索进程 |

## Core 守护进程

不带模式参数即可运行普通节点：

```sh
parano1d
```

守护进程公共参数：

| 参数 | 含义 |
|---|---|
| `-c, --config FILE` | TOML 配置路径 |
| `--mode node` | 普通非挖矿节点 |
| `--mode miner` | 带内置证明和 PoW 流水线的节点 |
| `--mode extminer` | 节点持有证明流水线，外部挖矿进程搜索 nonce |
| `--miner` | `--mode miner` 的简写 |
| `--extminer` | `--mode extminer` 的简写 |
| `--miner-address ADDRESS` | 挖矿奖励地址；默认使用钱包活动地址 |
| `--cpu-threads N` | 内置矿工共享线程预算 |
| `--data-dir PATH` | 链、钱包和运行时数据目录 |
| `--p2p-listen HOST:PORT` | P2P 监听；默认 `0.0.0.0:9600` |
| `--rpc-listen HOST:PORT` | JSON-RPC 监听；默认 `127.0.0.1:9601` |
| `--seed ENDPOINT` | 添加引导端点；可重复 |
| `--log LEVEL` | Tracing 过滤器，如 `error`、`warn`、`info`、`debug` |
| `--mining-key TOKEN` | 外部挖矿 Bearer 令牌；为兼容性保留 |
| `--mining-key-file FILE` | 从仅所有者可读的文件读取外部挖矿令牌 |
| `--operator-key TOKEN` | 用于固定矿池记账和付款 RPC 范围的独立 Bearer 令牌 |
| `--operator-key-file FILE` | 从仅所有者可读的文件读取运营者令牌 |
| `--allow-custom-coinbase` | 允许经过认证的外部挖矿进程请求自己的奖励地址 |
| `--purge-state` | 清除完整链数据库，并从对等节点重新同步 |
| `--check-hardware` | 报告发布版 CPU 支持情况后退出，不触碰节点数据 |

不适用于当前模式的参数会被拒绝。`--cpu-threads` 属于内置矿工模式；
外部矿工模式要求 `--mining-key` 或 `--mining-key-file`，而
`--allow-custom-coinbase` 同时要求外部模式和已配置的 key。

`--purge-state` 是修复和升级工具，不是日常启动参数。它会从链数据库中删除
区块头、链索引、保留的完整区块、撤销数据和 Live State。钱包文件、收据和
对等节点身份另行存储，不会被删除；随后，节点会重新从对等节点认证整条链和 State。

示例：

```sh
# Ordinary node
parano1d --data-dir ~/.parano1d/data

# Internal miner using 12 logical CPUs
parano1d --mode miner --cpu-threads 12

# Node with a local external nonce worker
parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key
```

除非由私有或认证传输保护，否则 RPC 应保持在回环地址上。Bearer 令牌用于认证请求，但不会加密传输。运营者令牌可以授权 `walletSend`，因此应优先使用 `--operator-key-file`，使用与挖矿凭据不同的令牌，并通过防火墙限制 listener。Core 拒绝在非回环地址上启动未认证的 RPC listener。即使配置了受限令牌，GUI 和 CLI 也可以从实际 TCP 回环地址连接而无需密钥。RPC 仅支持 HTTP，并拒绝 WebSocket 升级。

## 外部矿工

`parano1d-miner` 请求已经证明且不可变的模板，只搜索它的 128 位 nonce。

| 参数 | 默认值 | 含义 |
|---|---|---|
| `--rpc URL` | `http://127.0.0.1:9601` | 节点 JSON-RPC 端点 |
| `--key TOKEN` | — | 与节点匹配的 Bearer 令牌；为兼容性保留 |
| `--key-file FILE` | — | 从仅所有者可读的文件读取 Bearer 令牌 |
| `--threads N` | `0` | PoW 线程；零表示使用全部可见逻辑 CPU |
| `--coinbase ADDRESS` | — | 节点显式允许时使用的自定义 `o1…` 奖励地址 |
| `--poll-ms MS` | `500` | 请求新模板前的延迟 |
| `--log LEVEL` | `info` | 挖矿进程日志过滤器 |
| `--check-hardware` | — | 报告发布版 CPU 支持情况后退出 |

典型本地用法：

```sh
parano1d-miner \
  --rpc http://127.0.0.1:9601 \
  --key-file ~/.parano1d/mining.key \
  --threads 12
```

远程传输和自定义奖励边界见[外部矿工](../operate/external-miner.md)。

## 节点客户端

`parano1d-cli` 是运行中 Core 节点的轻量客户端。它不持有独立密钥，而是通过
本地 JSON-RPC 执行钱包操作。

### 全局参数

```text
-r, --rpc URL   RPC 端点
-j, --json      原始 JSON 输出
```

默认端点是 `http://127.0.0.1:9601`。环境变量 `NOID_RPC` 可修改；
`--rpc` 优先级更高。

CLI 钱包命令输入的金额以 NOID 为单位，最多六位小数：

```text
1 NOID = 1,000,000 μNOID
```

### 节点与链

| 命令 | 参数 | 结果 |
|---|---|---|
| `status` | — | 链尖、哈希、难度和当前 Live State 摘要 |
| `block-hash` | `HEIGHT` | 永久的含 nonce 区块 ID |
| `block-header` | `HEIGHT` | 结构化永久区块头 |
| `header` | `HEIGHT` | 原始规范 212 字节区块头 hex |
| `block` | `HEIGHT` | 保留期间的原始完整区块 hex |
| `history-step-terminal` | — | 当前本地终端证明的十六进制编码 |
| `tx` | `TXID` | 永久确认位置 |
| `slot` | `INDEX` | 当前槽位内容 |
| `utxos-of` | `o1…` | 某地址当前拥有的 UTXO |
| `state` | — | 容量、占用和 State 编码大小 |
| `epoch` | — | 当前 144 区块用户[交易周期（epoch）锚点](glossary.md#transaction-epoch-anchor) |

示例：

```sh
parano1d-cli status
parano1d-cli block-header 420
parano1d-cli block 420
parano1d-cli slot 9700063
parano1d-cli utxos-of o1...
```

`block` 只在 18 区块体保留窗口内返回数据。每个规范高度的 `header` 和
`block-header` 都永久可用。

### 网络与挖矿

| 命令 | 选项 | 结果 |
|---|---|---|
| `peers` | — | 已连接对等节点数 |
| `mining` | — | 难度、下一奖励和挖矿状态 |
| `block-template` | `--miner-addr o1…` | 节点持有的外部挖矿模板 |
| `submit-block` | `TEMPLATE_ID NONCE_HEX` | 提交一个 16 字节 little-endian nonce |

外部挖矿命令属于低层接口。`parano1d-miner` 会自动刷新模板并编码 nonce。

### 手续费与内存池

```sh
parano1d-cli estimate-fee 2 --inputs 1
parano1d-cli mempool
parano1d-cli mempool-tx TXID
```

`estimate-fee` 报告节点当前针对所声明有效输入和输出数量接受的最低费用。
内存池中的每一行是一笔逻辑 `PagedSpend` 交易意图，而不是单独的物理页。

### 地址验证

```sh
parano1d-cli validate o1...
```

命令报告有效性、规范 bech32m 形式和原始 32 字节载荷。

### 钱包地址

```sh
parano1d-cli address
parano1d-cli address --list
parano1d-cli address --new
parano1d-cli address --index 3
parano1d-cli address --use 3
```

`--new`、`--index` 和 `--use` 是互斥操作。生成的地址在被选中前保持
非活动。发送只使用活动地址的 UTXO，并把找零返回给该地址。

### 余额与 UTXO

```sh
parano1d-cli balance
parano1d-cli utxos
parano1d-cli scan
```

`balance` 分别列出已确认、预留外发、待定入账和可花费金额。`scan` 从
经过验证的持久所有者索引重新加载活动地址对应的 UTXO。

### 发送

预览：

```sh
parano1d-cli send o1... 10.5 --dry-run
```

自动费用提交：

```sh
parano1d-cli send o1... 10.5
```

仅在确有需要时指定精确 NOID 费用：

```sh
parano1d-cli send o1... 10.5 --fee 0.012
```

返回 ID 指向完整逻辑花费。建议使用自动费用，因为占用率和中继费率下限
可能变化。

### 历史与收据

```sh
parano1d-cli history
parano1d-cli history --last 20
parano1d-cli history --address o1...
```

导出已确认的外发收据：

```sh
parano1d-cli receipt TXID > receipt.hex
```

验证：

```sh
parano1d-cli verify "$(tr -d '\n' < receipt.hex)"
```

只有本机保存的不同所有者付款才能导出收据。

### 停止

```sh
parano1d-cli stop
```

该命令请求守护进程正常关闭，等同于 GUI 的普通退出流程，而不是强制终止进程。

### 脚本

使用 `--json`，并检查进程退出状态：

```sh
height="$(
  parano1d-cli --json status |
    jq -er '.height'
)"
```

人类可读输出和颜色属于展示接口，脚本应读取 JSON。
