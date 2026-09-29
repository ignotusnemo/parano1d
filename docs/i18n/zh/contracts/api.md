# 合约 API 与应用集成

合约使用现有本地 JSON-RPC 端点及 `paranoid_` 前缀，参数为位置数组。
所有合约方法要求**本地所有者权限**；挖矿和运营令牌都不授予合约权限。
见 [RPC 身份验证](../reference/rpc.md#认证)。

## 协议发现

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_getContractProtocol",
  "params": []
}
```

响应包含 `tip_height`、`activation_height`、`active_at_next_block`、
`runtime_available`、`next_block_time_seconds`、`abi_version`、`instructions`、
`persistent_registers` 及 `classes`。每类包含 `class`、`pages`、`live_inputs`、
`contract_calls`。v2 为 ABI 3、16 条指令、2 个持久寄存器，Small 63/504/63，
Large 206/504/63。

主网 v2 规则从 **H210537** 开始。新二进制在此之前可准备公开条款、观察 opening
并读取本地元数据。充值、预览和调用要求**下一个候选高度**已激活且已认证 v2
运行时可用。旧二进制不提供这些方法。

## 方法

| 方法后缀 | 位置参数 | 结果 |
| --- | --- | --- |
| `getContractProtocol` | `[]` | `ObjectProtocolInfo` |
| `createObject` | `[definition]` | `ObjectInfo` |
| `getObjectStatus` | `[opening_hex, slot_index]` | `ObjectStatus` |
| `getObjectInstances` | `[opening_hex, from_slot, limit]` | `ObjectInstances` |
| `previewObjectCall` | `[request]` | `ObjectCallPreview` |
| `walletFundObject` | `[opening_hex, amount_micronoid, fee_micronoid, expected_sender?]` | `WalletSendResult` |
| `walletCallObject` | `[request]` | `ObjectCallResult` |
| `walletGetObjectOpening` | `[address]` | `ObjectInfo` |
| `walletWatchObject` | `[opening_hex]` | `ObjectInfo` |
| `walletListObjectStates` | `[opening_hex, after_root, limit]` | `ObjectKnownStates` |
| `walletListObjectReceipts` | `[opening_hex, after_cursor, limit]` | `ObjectActivityPage` |
| `exportObjectReceipt` | `[opening_hex, txid]` | `hex` |
| `verifyObjectReceipt` | `[receipt_hex]` | `ObjectReceiptResult` |
| `walletImportObjectReceipt` | `[receipt_hex, expected_opening_hex?]` | `ObjectReceiptResult` |

`createObject` 编码并验证公开条款，不广播交易、不收费。请保存返回的 opening。
`walletWatchObject` 保留条款供未来观察。`walletGetObjectOpening` 恢复本地
保留的条款，不能从链上哈希恢复任意原像。

`getObjectStatus` 检查某槽位是否匹配 opening，客户端还必须比较目标实例的
`creation_id`。`getObjectInstances` 扫描当前 State 中的精确承诺：`from_slot`
为包含式起点，`limit` 为 1–256，`next_slot` 是下一页的包含式游标或 null。
结果包含 `height`、`tip_hash`；多页读取期间链尖变化时应重新开始。

`walletListObjectStates` 列出具有相同不可变条款的本地已知状态，并重新检查
`has_balance`。`after_root` 是排他游标，初始为 null，limit 为 1–64。
`walletListObjectReceipts` 按新到旧列出双方保留调用，使用排他 `after_cursor`
（初始 null）和 1–64 的 limit。`canonical` 与本地保留是不同属性。
这些端点都不能重建完整全局历史。

## 定义与金额

定义使用 `kind` 区分，拒绝未知字段。金额为整数 μNOID，高度及周期为区块数。
构造器字段如下：

| `kind` | 字段 |
| --- | --- |
| `refundable_payment` | `payer`, `payee`, `expiry_height`, `max_fee_micronoid` |
| `timelocked_vault` | `owner`, `unlock_height`, `max_fee_micronoid` |
| `allowance_wallet` | `spending_key`, `recovery_key`, `payout_recipient`, `recover_at`, `max_fee_micronoid`, `max_payout_micronoid`, `min_retained_micronoid` |
| `period_budget_wallet` | Allowance + `start_height`, `period_blocks`, `budget_micronoid` |
| `recurring_payment` | `payer`, `payee`, `first_due_height`, `period_blocks`, `payment_micronoid`, `recover_at`, `max_fee_micronoid` |
| `tranche_vesting` | `beneficiary`, `first_unlock_height`, `period_blocks`, `tranche_micronoid`, `mature_at`, `max_fee_micronoid` |
| `custom_program` | `definition` |
| `custom` | `opening_hex` |

“Allowance +” 指全部 `allowance_wallet` 字段再加所列三个字段。
可选 `payout_recipient` 可以为 null。分支、保留额及周期行为见[模板](templates.md)。

`custom_program.definition` 必须提供 `state`、`program`、`claim_authority`、
`recovery_authority`、`claim_recipient`、`recovery_recipient`、`deadline_height`、
`max_fee_micronoid`、`max_payout_micronoid`、`min_retained_micronoid`、
`claim_can_continue`、`claim_can_close`、`recovery_can_continue`、
`recovery_can_close` 及 `unrestricted_payout_recipient`。没有隐式权限。
`state` 恰为两个规范十进制 u64 字符串，`program` 最多包含 16 条[指令](core.md)，
末尾自动补齐。`custom` 使用同一 ABI 验证已编码 opening。

`ObjectInfo` 返回策略字段、`abi_version`、`address`、`opening_hex`、`code_id`、
`state_hex`、两个状态字符串及完整 16 条指令。`opening_hex` 编码 699 字节，
地址为规范 `o1…`。u64 金额和高度必须无损处理，浏览器 `Number` 无法准确表示
所有 u64。不要通过浮点数转换计数器和立即数字符串。

## 先审阅，再提交

调用请求必填 `opening_hex`、`slot_index`、**`creation_id`**、`terminal`、
`payout` 和 `fee_micronoid`。`payout` 为 null 或 `{address, amount_micronoid}`，
关闭时必须为 null。零手续费请求当前最低要求，但仍受策略上限约束。
手续费来自合约输入，不使用另一个钱包输入。

1. 找到并选择精确活实例。
2. 发送给 `previewObjectCall`，检查 `txid`、`call_height`、`authority`、
   `recovery`、`terminal`、手续费、保留余额、付款及后继。
3. 保存审阅结果，在 `walletCallObject` 中用 `expected_txid`、
   `expected_call_height`、`expected_authority`、`expected_recovery` 绑定。
   不匹配时必须重新审阅，不能悄悄修改已授权交易体。
4. 保存返回的 `transaction.txid`、`call_height`、`successor` 和 `output_slot`。
   此响应表示提交，不表示确认。
5. 跟踪纳入后导出回执，按需要分享后继条款。

充值时，可选 `expected_sender` 约束当前钱包地址。充值是普通付款，可为同一个
opening 创建多个独立实例。若响应丢失，应先查询审阅过的交易 ID；RPC 超时
不代表提交失败。

交易体裁剪后，`getTx` 仍可能保留索引指针。该指针不是交易体或当前未花费证明。
过去调用使用回执证据，当前余额使用 State 查询。

## 索引公开调用

索引器可从 `getMempoolInfo` 取得待处理交易的 txid，再逐笔调用
`getMempoolEntry(txid)`。待处理的合约调用包含规范的 699 字节
`contract_opening_hex`；普通付款的该字段为 `null`。`getBlockDetails(height)`
在保留的区块体中以 `contract: "call"`、`"close"` 或 `null` 标记交易。
详见 [RPC 参考](../reference/rpc.md)。

索引器必须在调用仍处于内存池时保存 opening。区块保留合约标志，但之后无法
通过 RPC 取回 opening。错过的内存池时段无法从 State 或已剪枝的区块体重建。

## 回执结果及限制

验证或导入返回 `valid`、`height`、`txid`、`terminal`、`authority`、`original`、
可选 `successor`、`input_micronoid`、`fee_micronoid`、`retained_micronoid`
及可选 `payout`。关闭时 `original` 仍存在，`successor` 为 null，语义付款为
关闭转账。活动项另含 `block_hash` 和 `canonical`。

验证是只读的。导入验证后保留证据和条款，可选 `expected_opening_hex` 必须
匹配原始或后继 opening。重复导入按 txid 合并，保留本地记录。
见[恢复](receipts-and-recovery.md)。

HTTP 请求体上限为 **2,237,632 字节**。合约回执解码后最多 **1,110,624 字节**，
hex 将其字节数加倍。普通付款回执有独立 128 KiB 上限。JSON-RPC 批量请求共享
HTTP 请求体上限，请使用分页，不要收集无限列表。

## CLI 流程

CLI 金额使用十进制 **NOID**，不同于 RPC 的整数 μNOID。请替换尖括号占位符。
关闭时必须激活由纳入高度决定的收款或恢复钱包。

```sh
parano1d-cli contract protocol
parano1d-cli contract payment <payee-o1-address> <expiry-height> --max-fee 1 --out payment.json
parano1d-cli contract fund payment.json 10
parano1d-cli contract watch payment.json
parano1d-cli contract instances payment.json --limit 64
parano1d-cli contract call payment.json <slot> <creation-id> --close --preview
parano1d-cli contract call payment.json <slot> <creation-id> --close --expected-txid <reviewed-txid> --out closing.json
parano1d-cli contract receipt payment.json <confirmed-txid> --out closing.receipt
parano1d-cli contract verify closing.receipt
```

CLI 提交前绑定预览，并先持久保存审阅工件，以便响应丢失后恢复。
`--out` 必须指定新文件。`call --wait-seconds 0` 在提交后返回，默认等待
600 秒。已关闭结果没有后继 opening。

其他构造器为 `vault`、`allowance`、`budget`、`recurring`、`vesting`。
`create definition.json --out object.json` 接受自定义定义。
准确参数见 `parano1d-cli contract <command> --help`。
`restore <address> --out object.json` 恢复本地保留 opening。
