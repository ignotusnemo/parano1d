# JSON-RPC API

Core exposes JSON-RPC 2.0 over HTTP. WebSocket upgrades are rejected. The default endpoint is:

```text
http://127.0.0.1:9601
```

Every method has the `paranoid_` namespace prefix. Parameters are positional JSON arrays. Request bodies are limited to 1 MiB, and JSON-RPC batches remain supported within that body limit.

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

## Conventions

- Monetary integer fields are in μNOID.
- One NOID equals 1,000,000 μNOID.
- Hashes are lowercase hexadecimal without `0x`.
- Targets and nonce bytes use their canonical little-endian encoding.
- Addresses use canonical bech32m `o1…` unless a field explicitly says hex.
- Unknown permanent objects generally return `null`.
- Old block bodies return `null` after the 18-block retention window; their
  headers remain queryable.
- Decimal strings carry aggregates that may exceed exact JSON-number range.
- `*_noid` floating-point fields are display conveniences. Accounting code
  should use the corresponding `*_micronoid` integer.

## Authentication

RPC has no authentication by default and must remain on loopback. Core refuses to start if an unauthenticated listener is configured on any non-loopback address.

An originless connection accepted from the actual TCP loopback address receives local owner access without an Authorization header, even when mining or operator credentials are configured. This keeps the GUI and CLI passwordless on the node host. If an Authorization header is supplied, it is always validated and selects only that credential's scope. Non-loopback clients must supply a configured credential. `Host`, `Forwarded`, `X-Forwarded-For` and other HTTP headers cannot claim local access.

Starting Core with `--mining-key TOKEN` or `--mining-key-file FILE` requires:

```http
Authorization: Bearer TOKEN
```

on external-mining requests. A missing or different token receives HTTP `401` without a JSON-RPC result. A valid mining credential is restricted to `paranoid_getBlockTemplate` and `paranoid_submitBlock`; it cannot authorize wallet, node-control or other RPC methods. The token authenticates but does not encrypt the connection, so use a private transport or TLS proxy remotely.

Pools with accounting or payouts on a separate host may configure a distinct `--operator-key TOKEN` or `--operator-key-file FILE`. That credential is limited to exactly:

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

It cannot call mining methods, `paranoid_stop`, wallet scanning and discovery, address-management methods, unbounded wallet history or UTXO listings, or any other current or future RPC method. Mining and operator tokens must differ. When both are configured, each request receives only the scope of the token it supplied. Scopes are never combined.

The operator credential can spend the active wallet through `walletSend`. Bearer authentication is not transport encryption. Bind to a private interface, restrict the source addresses with a firewall, and use a VPN, SSH tunnel, or authenticated TLS proxy whenever the network is not fully trusted. A reverse proxy that connects to the node through loopback must forward the Bearer header. If it removes Authorization, the node sees the proxy as a local owner client and does not apply a remote credential scope.

Generate independent tokens with `openssl rand -hex 32`. Command-line tokens remain supported for compatibility. Owner-only key files are preferred because they keep tokens out of process arguments.

## Chain methods

| Method suffix | Positional params | Result |
|---|---|---|
| `blockCount` | `[]` | `u64` tip height |
| `getChainInfo` | `[]` | `ChainInfo` |
| `getBlockHash` | `[height: u64]` | `string \| null` |
| `getBlockHeader` | `[height: u64]` | `BlockHeaderInfo \| null` |
| `getBlockHeaderByHash` | `[hash: string]` | `BlockHeaderInfo \| null` |
| `getHeaderByHeight` | `[height: u64]` | Raw 212-byte header hex or `null` |
| `getHeaderByHash` | `[hash: string]` | Raw 212-byte header hex or `null` |
| `getHistoryStepTerminal` | `[]` | Current terminal hex or `null` |
| `getSlot` | `[slot_index: u32]` | `SlotInfo` |
| `getSlotsByOwner` | `[address: string]` | `SlotInfo[]` |
| `getActiveSlotCount` | `[]` | `u64` |
| `getStateInfo` | `[]` | `StateInfo` |
| `getStateMap` | `[]` | `StateMapInfo` |
| `getTx` | `[txid: string]` | `TxInfo \| null` |
| `getBlock` | `[height: u64]` | Retained canonical block hex or `null` |
| `getBlockDetails` | `[height: u64]` | `BlockDetailsInfo \| null` |
| `getRecentTransactions` | `[page: u32, page_size: u32, address: string \| null]` | `RecentTransactionsPage` |

`getRecentTransactions` scans only retained complete blocks. Page numbering
starts at one; page size is clamped to 1–32. Supplying an address adds exact
spent and received aggregates for that owner.

`getSlot` returns an error for an index outside the current `2^log_slots`
domain. An in-range empty slot returns `empty: true`, zero value and an empty
owner string.

## Node, network and fee methods

| Method suffix | Positional params | Result |
|---|---|---|
| `getMiningInfo` | `[]` | `MiningInfo` |
| `getPeerCount` | `[]` | Connected-peer count |
| `getNodeStatus` | `[]` | `NodeStatus` |
| `estimateFee` | `[n_outputs: u32]` | Accepted minimum in μNOID, assuming one input |
| `estimateFeeDetailed` | `[n_inputs: u32, n_outputs: u32]` | `FeeEstimate` |

Detailed fee counts must be 1–1,020 inputs and 1–256 outputs. The returned fee
includes the current relay floor.

## Utility and submission methods

| Method suffix | Positional params | Result |
|---|---|---|
| `validateAddress` | `[address: string]` | `AddressInfo` |
| `getSlotHints` | `[count: u32]` | `u32[]` |
| `getSlotHintsSalted` | `[count: u32, salt_hex: string]` | `u32[]` |
| `getEpochAnchor` | `[]` | Current user transaction anchor hex |
| `submitTxIntent` | `[intent_hex: string]` | Logical transaction ID |

Slot hints are not reservations. Both methods exclude currently reserved
mempool outputs, return at most 256 entries and may return fewer if the node
cannot find enough empty slots. Salt is bounded to 256 decoded bytes.

`submitTxIntent` accepts one canonical encoded `PagedSpendIntent`, including
the detached authorization capsule. Decoded input is bounded to 303,495 bytes
before parsing and proof verification.

## Mempool methods

| Method suffix | Positional params | Result |
|---|---|---|
| `getMempoolInfo` | `[]` | `MempoolInfo` |
| `getMempoolSize` | `[]` | Pending logical transaction count |
| `getMempoolStats` | `[]` | `MempoolStats` |
| `getMempoolEntry` | `[txid: string]` | `MempoolTxInfo \| null` |

Mempool responses describe atomic logical transactions rather than physical
pages.

## Receipt method

| Method suffix | Positional params | Result |
|---|---|---|
| `verifyReceipt` | `[receipt_hex: string]` | `ReceiptVerifyResult` |

Receipt input is bounded to 128 KiB after hex decoding. `merkle_valid` and
`canonical` are separate: a mathematically consistent receipt can claim a root
that is not on this node's canonical chain.

## External-mining methods

| Method suffix | Positional params | Result |
|---|---|---|
| `getBlockTemplate` | `[miner_address: string]` | `BlockTemplateResponse` |
| `submitBlock` | `[template_id: string, nonce_hex: string]` | Accepted block ID |

The node must run in external-miner mode. An empty `miner_address` uses the
node payout. A non-empty address is accepted only when the node enabled custom
coinbase.

`nonce_hex` is exactly 32 lowercase hex characters encoding 16 little-endian
bytes. Templates are single-use and expire after 30 seconds.

## Node control

| Method suffix | Positional params | Result |
|---|---|---|
| `stop` | `[]` | Status string |

The first call requests graceful shutdown. Later calls are harmless while the
process is exiting.

## Wallet methods

| Method suffix | Positional params | Result |
|---|---|---|
| `walletStatus` | `[]` | `WalletStatus` |
| `walletGetAddress` | `[index: u32]` | Address string |
| `walletGetBalance` | `[]` | `WalletBalance` |
| `walletListUtxos` | `[]` | `WalletUtxoInfo[]` |
| `walletHistory` | `[]` | `WalletHistoryEntry[]`, oldest first |
| `walletReceipts` | `[page: u32, page_size: u32]` | `WalletReceiptsPage` |
| `walletMinedBlocks` | `[page: u32, page_size: u32]` | `WalletMinedBlocksPage` |
| `walletScan` | `[]` | `WalletScanResult` |
| `walletDiscoverAddresses` | `[max_additional: u32]` | `WalletAddressInfo[]` |
| `walletPlanSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendPlan` |
| `walletSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendResult` |
| `walletPlanConsolidation` | `[]` | `WalletConsolidationPlan` |
| `walletConsolidate` | `[slots: u32[], expected_fee: u64, expected_output: u64]` | `WalletConsolidationResult` |
| `walletExportReceipt` | `[txid: string]` | Receipt hex |
| `walletNextAddress` | `[]` | `WalletAddressInfo` |
| `walletListAddresses` | `[]` | `WalletAddressInfo[]` |
| `walletActiveAddress` | `[]` | `WalletAddressInfo` |
| `walletSetActiveAddress` | `[index: u32]` | `WalletAddressInfo` |

Amounts and fees are μNOID. A send or plan fee of zero requests automatic fee
selection.

Receipt and mined-block pages start at one and accept sizes 1–50.
`walletDiscoverAddresses` accepts 1–20 and stops at the first empty derived
owner.

`walletConsolidate` is quote-bound. Its slot list, fee and output value must
exactly match the latest plan; otherwise it fails and the caller must request a
new quote.

## Response schemas

The following schemas use `?` for optional fields and `null` where JSON can
explicitly carry no value.

### Chain and State

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

`circulating_supply_micronoid` is the exact sum of all UTXO values in Live
State, expressed in μNOID. It is encoded as a decimal string so JSON does not
lose precision.

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

`state_bytes` is canonical encoded segment data. It excludes MDBX page,
indexing and filesystem overhead.

### Block details

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

### Node and mining

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

`isolated_mining` is status information from a node started in a special
operator context. Public deployments should not use it as a remote control or
peer property.

### Fees

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

### Mempool

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

Fee rate uses weighted units:

```text
inputs + outputs + 4 × net_new_slots
```

### Address validation

```text
AddressInfo {
  valid: bool
  bech32: string | null
  hex: string | null
  error: string | null
}
```

Invalid address syntax is represented as `valid: false`, not a JSON-RPC
transport error.

### Wallet identity and balance

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

### Wallet send and consolidation

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

### Wallet scan and pages

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

### Receipt verification

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

`authenticated_summary` is present only when the Merkle proof is valid.

### External template

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

`pow_fields_hex` contains 16 consecutive 16-byte little-endian fields. The
worker replaces field `nonce_field_index`, canonically 10.

## Errors

Standard JSON-RPC parse, invalid-request, method and parameter errors use the
normal JSON-RPC codes.

Application failures normally use:

```text
-32000
```

with a human-readable message.

One wallet planning error has a stable machine-readable contract:

```json
{
  "code": -32011,
  "message": "InputLimitExceeded",
  "data": {
    "max_inputs": 1020
  }
}
```

This means sufficient value may exist, but no legal payment can be built inside
the canonical input bound.

Clients should:

1. test HTTP status before decoding JSON;
2. inspect the JSON-RPC `error` object;
3. branch on documented stable codes;
4. present other application messages to the operator without parsing their
   prose.
