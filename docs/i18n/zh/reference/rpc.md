# JSON-RPC API

Core 通过 HTTP 提供 JSON-RPC 2.0，并拒绝 WebSocket 升级。默认端点：

```text
http://127.0.0.1:9601
```

所有方法都带有 `paranoid_` namespace 前缀。参数使用位置 JSON 数组。请求体限制为 1 MiB，JSON-RPC batch 在该请求体限制内继续受支持。

```sh
curl --silent --show-error \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "paranoid_getChainInfo",
    "params": []
  }' \
  http://127.0.0.1:9601
```

## 约定

- 货币整数字段以 μNOID 为单位。
- 1 NOID 等于 1,000,000 μNOID。
- 哈希使用不带 `0x` 的小写十六进制。
- 目标值（target）与 nonce 字节使用各自规范的小端编码。
- 地址默认使用规范 bech32m `o1…`，除非字段明确要求 hex。
- 未知的永久对象通常返回 `null`。
- 超出 18 区块保留窗口的旧区块体返回 `null`，其区块头仍可查询。
- 可能超出 JSON number 精确范围的聚合值使用 decimal string。
- `*_noid` 浮点字段只为展示方便；记账代码应使用对应的
  `*_micronoid` 整数字段。

## 认证

RPC 默认没有认证，因此必须仅监听回环地址。Core 拒绝在任何非回环地址上启动未认证的 listener。

从实际 TCP 回环地址接受且不带 Origin 的连接，即使已配置挖矿令牌或运营者令牌，也可以在没有 Authorization 头的情况下获得本地所有者权限，因此节点主机上的 GUI 和 CLI 不需要密码。只要提供 Authorization 头，节点就一定会验证它，并且只授予对应令牌的权限范围。非回环客户端必须提供已配置的令牌。`Host`、`Forwarded`、`X-Forwarded-For` 和其他 HTTP 头不能把远程连接伪装成本地连接。

使用 `--mining-key TOKEN` 或 `--mining-key-file FILE` 启动 Core 后，外部挖矿
请求必须提供：

```http
Authorization: Bearer TOKEN
```

Token 缺失或不匹配时返回 HTTP `401`，没有 JSON-RPC 结果。有效的挖矿 Token 只允许 `paranoid_getBlockTemplate` 和 `paranoid_submitBlock`；它不能访问钱包、节点控制或其他 RPC 方法。Token 只负责认证，不加密连接，因此远程访问应使用私有传输或 TLS 代理。

将记账或付款服务放在独立主机上的矿池可以配置不同的 `--operator-key TOKEN` 或 `--operator-key-file FILE`。该凭据仅允许：

- `paranoid_walletMinedBlocks`
- `paranoid_walletGetBalance`
- `paranoid_walletStatus`
- `paranoid_walletPlanSend`
- `paranoid_walletSend`
- `paranoid_walletPlanConsolidation`
- `paranoid_walletConsolidate`
- `paranoid_walletReceipts`
- `paranoid_walletExportReceipt`
- `paranoid_getTx`
- `paranoid_getMempoolEntry`
- `paranoid_verifyReceipt`
- `paranoid_submitTxIntent`
- `paranoid_validateAddress`
- `paranoid_getChainInfo`
- `paranoid_estimateFee`
- `paranoid_estimateFeeDetailed`

运营者令牌不能调用挖矿方法、`paranoid_stop`、钱包扫描和地址发现、地址管理、无界的钱包历史或 UTXO 列表，也不能调用任何当前或未来未列出的方法。挖矿令牌和运营者令牌必须不同。同时配置两者时，每个请求只获得其所提供令牌的权限范围，权限范围不会合并。

运营者令牌可以通过 `walletSend` 支出活动钱包中的资金。Bearer 认证不提供传输加密。请绑定私有接口，通过防火墙限制来源地址，并在网络不完全可信时使用 VPN、SSH 隧道或经过认证的 TLS 代理。通过回环地址连接节点的反向代理必须转发 Bearer 头。如果代理删除 Authorization，节点会把该代理视为本地所有者客户端，不会应用远程令牌的权限范围。

使用 `openssl rand -hex 32` 生成彼此独立的令牌。命令行 Token 形式继续保留以兼容现有部署。建议使用仅所有者可读的 key 文件，避免 Token 出现在进程参数中。

## 链方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `blockCount` | `[]` | `u64` 链尖高度 |
| `getChainInfo` | `[]` | `ChainInfo` |
| `getBlockHash` | `[height: u64]` | `string \| null` |
| `getBlockHeader` | `[height: u64]` | `BlockHeaderInfo \| null` |
| `getBlockHeaderByHash` | `[hash: string]` | `BlockHeaderInfo \| null` |
| `getHeaderByHeight` | `[height: u64]` | 原始 212 字节区块头 hex 或 `null` |
| `getHeaderByHash` | `[hash: string]` | 原始 212 字节区块头 hex 或 `null` |
| `getHistoryStepTerminal` | `[]` | 当前终端证明的十六进制编码或 `null` |
| `getSlot` | `[slot_index: u32]` | `SlotInfo` |
| `getSlotsByOwner` | `[address: string]` | `SlotInfo[]` |
| `getActiveSlotCount` | `[]` | `u64` |
| `getStateInfo` | `[]` | `StateInfo` |
| `getStateMap` | `[]` | `StateMapInfo` |
| `getTx` | `[txid: string]` | `TxInfo \| null` |
| `getBlock` | `[height: u64]` | 保留的规范区块 hex 或 `null` |
| `getBlockDetails` | `[height: u64]` | `BlockDetailsInfo \| null` |
| `getRecentTransactions` | `[page: u32, page_size: u32, address: string \| null]` | `RecentTransactionsPage` |

`getRecentTransactions` 只扫描仍保留的完整区块。页码从 1 开始，页面大小
限制在 1–32。提供地址后，会为该所有者附加精确的已花费和已接收聚合值。

如果索引超出当前 `2^log_slots` 域，`getSlot` 返回错误。范围内的空槽位
返回 `empty: true`、零金额和空所有者字符串。

## 节点、网络与费用方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `getMiningInfo` | `[]` | `MiningInfo` |
| `getPeerCount` | `[]` | 已连接对等节点数量 |
| `getNodeStatus` | `[]` | `NodeStatus` |
| `estimateFee` | `[n_outputs: u32]` | 假设一个输入时可接受的最低 μNOID |
| `estimateFeeDetailed` | `[n_inputs: u32, n_outputs: u32]` | `FeeEstimate` |

详细费用要求 1–1,020 个输入和 1–256 个输出。返回费用包含当前中继费率
下限。

## 工具与提交方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `validateAddress` | `[address: string]` | `AddressInfo` |
| `getSlotHints` | `[count: u32]` | `u32[]` |
| `getSlotHintsSalted` | `[count: u32, salt_hex: string]` | `u32[]` |
| `getEpochAnchor` | `[]` | 当前用户交易周期（epoch）锚点的十六进制编码 |
| `submitTxIntent` | `[intent_hex: string]` | 逻辑交易 ID |

槽位提示不是预留。两个方法都会排除内存池当前预留的输出，最多返回
256 项；若找不到足够空槽，返回项可能更少。解码后的 salt 上限为 256
字节。

`submitTxIntent` 接受一份规范编码的 `PagedSpendIntent`，其中包含分离的
授权证明封装。解析和证明验证前，解码输入上限为 303,495 字节。

## 内存池方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `getMempoolInfo` | `[]` | `MempoolInfo` |
| `getMempoolSize` | `[]` | 待处理逻辑交易数 |
| `getMempoolStats` | `[]` | `MempoolStats` |
| `getMempoolEntry` | `[txid: string]` | `MempoolTxInfo \| null` |

内存池响应描述的是原子逻辑交易，而不是物理页。

## 收据方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `verifyReceipt` | `[receipt_hex: string]` | `ReceiptVerifyResult` |

收据输入经过 hex 解码后上限为 128 KiB。`merkle_valid` 与 `canonical`
彼此独立：数学上自洽的收据可能声明一个不属于该节点规范链的根。

## 外部挖矿方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `getBlockTemplate` | `[miner_address: string]` | `BlockTemplateResponse` |
| `submitBlock` | `[template_id: string, nonce_hex: string]` | 已接受区块 ID |

节点必须运行在外部矿工模式。`miner_address` 为空时使用节点奖励地址；
非空地址只有在节点启用 custom coinbase 后才会接受。

`nonce_hex` 必须恰好是 32 个小写 hex 字符，编码 16 个 little-endian
字节。模板一次性使用，30 秒后过期。

## 节点控制

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `stop` | `[]` | 状态字符串 |

第一次调用请求正常关闭。进程退出期间再次调用不会造成影响。

## 钱包方法

| 方法后缀 | 位置参数 | 结果 |
|---|---|---|
| `walletStatus` | `[]` | `WalletStatus` |
| `walletGetAddress` | `[index: u32]` | 地址字符串 |
| `walletGetBalance` | `[]` | `WalletBalance` |
| `walletListUtxos` | `[]` | `WalletUtxoInfo[]` |
| `walletHistory` | `[]` | `WalletHistoryEntry[]`，最旧在前 |
| `walletReceipts` | `[page: u32, page_size: u32]` | `WalletReceiptsPage` |
| `walletMinedBlocks` | `[page: u32, page_size: u32]` | `WalletMinedBlocksPage` |
| `walletScan` | `[]` | `WalletScanResult` |
| `walletDiscoverAddresses` | `[max_additional: u32]` | `WalletAddressInfo[]` |
| `walletPlanSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendPlan` |
| `walletSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendResult` |
| `walletPlanConsolidation` | `[]` | `WalletConsolidationPlan` |
| `walletConsolidate` | `[slots: u32[], expected_fee: u64, expected_output: u64]` | `WalletConsolidationResult` |
| `walletExportReceipt` | `[txid: string]` | 收据 hex |
| `walletNextAddress` | `[]` | `WalletAddressInfo` |
| `walletListAddresses` | `[]` | `WalletAddressInfo[]` |
| `walletActiveAddress` | `[]` | `WalletAddressInfo` |
| `walletSetActiveAddress` | `[index: u32]` | `WalletAddressInfo` |

金额和费用均为 μNOID。发送或计划费用设为零表示请求自动选费。

收据和已挖区块页从 1 开始，页面大小接受 1–50。
`walletDiscoverAddresses` 接受 1–20，并在第一个空派生所有者处停止。

`walletConsolidate` 绑定报价。槽位列表、费用和输出金额必须与最新计划完全
一致，否则调用失败，客户端必须重新获取报价。

## 响应 schema

以下 schema 使用 `?` 表示可选字段；JSON 明确没有值时使用 `null`。

### 链与 State

```text
ChainInfo {
  height: u64
  best_hash: string
  difficulty_target: string
  active_slot_count: u64
  log_slots: u32
  circulating_supply_micronoid: decimal string
}

BlockHeaderInfo {
  height: u64
  hash: string
  prev_hash: string
  state_root: string
  tx_root: string
  timestamp: u64
  miner: string
  nonce_hex: string
  difficulty_target: string
  log_slots: u32
  active_slot_count: u64
  alloc_counter: u64
}

SlotInfo {
  slot_index: u32
  value: u64
  creation_id: u64
  owner: string
  empty: bool
}

TxInfo {
  tx_hash: string
  height: u64
  block_hash: string
  tx_position: u32
}
```

`circulating_supply_micronoid` 是 Live State 中所有 UTXO 数值之和，以
μNOID 为单位。该字段使用十进制字符串编码，避免 JSON 数字精度造成截断。

```text
StateInfo {
  log_slots: u32
  capacity: u64
  active_slots: u64
  fill_pct: number
  slots_until_expand: i64
  expand_trigger_pct: u8
  log_slots_max: u32
  state_bytes: u64
  state_size_human: string
}

StateMapInfo {
  log_slots: u32
  bucket_capacity: u64
  live_counts: u64[]
}
```

`state_bytes` 是规范编码的段数据，不含 MDBX 页面、索引和文件系统开销。

### 区块详情

```text
BlockDetailsInfo {
  header: BlockHeaderInfo
  retained: RetainedBlockInfo | null
}

RetainedBlockInfo {
  proof_class: string
  logical_transactions: u16
  user_pages: u16
  live_inputs: u16
  live_outputs: u16
  reward_micronoid: u64
  reward_noid: number
  total_fees_micronoid: decimal string
  block_bytes: u64
  history_step_bytes: u64
  bundle_bytes: u64
  transactions: BlockTransactionInfo[]
}
```

```text
BlockTransactionInfo {
  position: u16
  txid: string
  page_count: u16
  live_inputs: u16
  live_outputs: u16
  fee_micronoid: u64
  coinbase: bool
  development_payout: bool
  epoch_anchor: string
  input_owner: string | null
  input_sum_micronoid: decimal string
  output_sum_micronoid: decimal string
  page_hashes: string[]
  inputs: BlockTransactionInputInfo[]
  outputs: BlockTransactionOutputInfo[]
}

BlockTransactionInputInfo {
  page: u16
  lane: u8
  slot_index: u32
  amount_micronoid: u64
  creation_id: u64
}

BlockTransactionOutputInfo {
  page: u16
  lane: u8
  slot_index: u32
  amount_micronoid: u64
  owner: string
  creation_id: u64
}
```

```text
RecentTransactionsPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  tip_height: u64
  retained_from_height: u64
  address: string | null
  transactions: RecentTransactionInfo[]
}

RecentTransactionInfo {
  height: u64
  block_hash: string
  timestamp: u64
  position: u16
  txid: string
  page_count: u16
  live_inputs: u16
  live_outputs: u16
  fee_micronoid: u64
  coinbase: bool
  development_payout: bool
  input_owner: string | null
  input_sum_micronoid: decimal string
  output_sum_micronoid: decimal string
  address_spent_micronoid: decimal string | null
  address_received_micronoid: decimal string | null
}
```

### 节点与挖矿

```text
MiningInfo {
  height: u64
  difficulty_bits: u32
  difficulty_target: string
  block_reward_micronoid: u64
  block_reward_noid: number
  active_slot_count: u64
}

NodeStatus {
  synced: bool
  sync_stage: "headers" | "state" | "tip"
  mining: bool
  mining_ready: bool
  mining_confirmed_peers: usize
  mining_required_peers: usize
  isolated_mining: bool
  backend: string
  available_threads: usize
  worker_threads: usize
}
```

`isolated_mining` 是节点在特殊运营上下文中启动时的状态信息。公网部署不应
把它用作远程控制凭据或对等节点属性。

### 费用

```text
FeeEstimate {
  n_inputs: usize
  n_outputs: usize
  net_new_slots: u64
  active_slot_count: u64
  log_slots: u32
  fee_micronoid: u64
  breakdown: FeeBreakdownInfo
}

FeeBreakdownInfo {
  base: u64
  input: u64
  output: u64
  io: u64
  state_growth: u64
  required_total: u64
  relay_floor: u64
  relay_total: u64
  paid_total: u64
  burned: u64
  miner_claimable: u64
}
```

### 内存池（Mempool）

```text
MempoolInfo {
  size: usize
  fee_floor: u64
  txs: MempoolTxInfo[]
}

MempoolStats {
  size: usize
  capacity: usize
  intent_bytes: u64
  max_intent_bytes: u64
  fee_floor: u64
}

MempoolTxInfo {
  tx_hash: string
  fee_micronoid: u64
  fee_rate: u64
  n_inputs: usize
  n_outputs: usize
  page_count: usize
  minimum_proof_class: string
  requires_b255_miner: bool
  admitted_height: u64
  has_authorization: bool
}
```

手续费率（fee rate）使用以下加权单位：

```text
inputs + outputs + 4 × net_new_slots
```

### 地址验证

```text
AddressInfo {
  valid: bool
  bech32: string | null
  hex: string | null
  error: string | null
}
```

地址语法无效时返回 `valid: false`，而不是 JSON-RPC 传输错误。

### 钱包身份与余额

```text
WalletAddressInfo {
  address: string
  key_index: u32
  is_active: bool
}

WalletStatus {
  exists: bool
  address: string
  active_index: u32
  balance_micronoid: u64
  balance_noid: number
  utxo_count: usize
  address_count: u32
}

WalletBalance {
  balance_micronoid: u64
  balance_noid: number
  utxo_count: usize
  pending_outbound_micronoid: u64
  pending_incoming_micronoid: u64
  spendable_micronoid: u64
  spendable_noid: number
}
```

```text
WalletUtxoInfo {
  slot_index: u32
  value_micronoid: u64
  creation_id: u64
  value_noid: number
  address: string
  key_index: u32
  confirmed_height: u64
  reserved: bool
}

WalletHistoryEntry {
  tx_hash: string
  height: u64
  direction: "sent" | "received"
  is_coinbase: bool
  amount_micronoid: u64
  amount_noid: number
  peer_address: string | null
  timestamp: u64
  own_address: string | null
  own_key_index: u32 | null
}
```

### 钱包发送与归集

```text
WalletSendPlan {
  amount_micronoid: u64
  fee_micronoid: u64
  total_spend_micronoid: u64
  input_count: usize
  output_count: usize
  change_micronoid: u64
  fee_breakdown: FeeBreakdownInfo
}

WalletSendResult {
  txid: string
  amount_micronoid: u64
  fee_micronoid: u64
  input_count: usize
  output_count: usize
}
```

```text
WalletConsolidationPlan {
  input_value_micronoid: u64
  fee_micronoid: u64
  output_value_micronoid: u64
  balance_before_micronoid: u64
  balance_after_micronoid: u64
  input_count: usize
  untouched_count: usize
  remaining_count: usize
  freed_slots: usize
  selected_input_slots: u32[]
  fee_breakdown: FeeBreakdownInfo
}

WalletConsolidationResult {
  txid: string
  input_value_micronoid: u64
  fee_micronoid: u64
  output_value_micronoid: u64
  input_count: usize
  output_count: usize
  freed_slots: usize
}
```

### 钱包扫描与分页

```text
WalletScanResult {
  found_utxos: usize
  balance_micronoid: u64
  balance_noid: number
  active_index: u32
  snapshot_height: u64
  snapshot_tip_hash: string
  snapshot_state_root: string
}
```

```text
WalletReceiptsPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  receipts: WalletReceiptInfo[]
}

WalletReceiptInfo {
  txid: string
  height: u64
  timestamp: u64
  amount_micronoid: u64
  fee_micronoid: u64
  peer_address: string | null
  own_address: string | null
  own_key_index: u32 | null
  input_count: usize
  output_count: usize
  receipt_bytes: usize
}
```

```text
WalletMinedBlocksPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  blocks: WalletMinedBlockInfo[]
}

WalletMinedBlockInfo {
  height: u64
  block_hash: string
  coinbase_txid: string
  timestamp: u64
  reward_micronoid: u64
  reward_noid: number
  payout_address: string
  payout_key_index: u32
  confirmations: u64
  full_block_available: bool
}
```

### 收据验证

```text
ReceiptVerifyResult {
  merkle_valid: bool
  canonical: bool
  confirmed: bool
  error: string | null
  authenticated_summary?: ReceiptSummaryInfo
}

ReceiptSummaryInfo {
  txid: string
  claimed_height: u64
  confirmed_unix: u64
  tx_index: u16
  tx_count: u16
  fee_micronoid: u64
  inputs: ReceiptInputInfo[]
  outputs: ReceiptOutputInfo[]
}

ReceiptInputInfo {
  slot_index: u32
  owner: string
}

ReceiptOutputInfo {
  slot_index: u32
  amount_micronoid: u64
  owner: string
}
```

只有 Merkle 证明有效时才包含 `authenticated_summary`。

### 外部模板

```text
BlockTemplateResponse {
  template_id: string
  pow_fields_hex: string
  nonce_field_index: usize
  difficulty_target_hex: string
  height: u64
  expires_in_seconds: u64
  n_txs: usize
  tx_input_counts?: usize[]
  tx_output_counts?: usize[]
  coinbase_value_micronoid: u64
  claimable_fees_micronoid: u64
}
```

`pow_fields_hex` 包含 16 个连续的 16 字节小端字段。外部挖矿进程替换
`nonce_field_index` 指向的字段，规范值为 10。

## 错误

标准 JSON-RPC 解析、无效请求、方法和参数错误使用常规 JSON-RPC 代码。

应用错误通常使用：

```text
-32000
```

并附带人类可读消息。

有一项钱包规划错误具有稳定的机器可读契约：

```json
{
  "code": -32011,
  "message": "InputLimitExceeded",
  "data": {
    "max_inputs": 1020
  }
}
```

这表示余额可能足够，但在规范输入上限内无法构建合法付款。

客户端应：

1. 解码 JSON 前先检查 HTTP 状态；
2. 检查 JSON-RPC `error` 对象；
3. 根据已文档化的稳定代码分支；
4. 其他应用消息直接展示给运营者，不要解析其文字。
