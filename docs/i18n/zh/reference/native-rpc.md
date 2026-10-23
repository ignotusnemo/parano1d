# 原生钱包 RPC

原生钱包操作使用所有者的本地节点。访问限于本地钱包应用或经过认证的集成。金额使用精确十进制整数字符串。NOID 与同质化代币均为六位小数。高度为 JSON 整数。资产和集合 ID 为 64 个十六进制字符。

<a id="inspect-current-rights"></a>
## 查看当前权利

| 方法 | 参数 | 结果 |
|---|---|---|
| `paranoid_getNativeProtocol` | `[]` | 激活、运行时可用性和容量 |
| `paranoid_getNativeHoldings` | `[owner, cursor, limit]` | 同一规范 State 下的类型化活跃持仓 |
| `paranoid_walletGetNativeHoldings` | `[cursor, limit]` | 当前钱包的类型化持仓 |
| `paranoid_getNativeCatalog` | `[kind, cursor, limit]` | `markets`、`collections` 或 `nft_listings` |
| `paranoid_getNativeMarket` | `[asset_id]` | 当前定义、曲线/池及储备 |
| `paranoid_walletNativePending` | `[]` | 钱包待处理和未确认活动 |

游标绑定所有者或目录类型、高度和区块哈希。分页期间规范 State 改变时，重新请求第一页。解码每个开口，并将根、槽位、创建 ID 和相关定义绑定到返回的 State。GUI 在展示持仓前执行这些检查。

<a id="preview-review-authorize"></a>
## 预览、审核与授权

向 `paranoid_walletPreviewNative` 发送一个请求：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_walletPreviewNative",
  "params": [{
    "action": "trade",
    "asset_id": "<64-character asset ID>",
    "buy": true,
    "gross_input": "1000000",
    "minimum_output": "<minimum token base units>",
    "valid_until": 100
  }]
}
```

审核 `owner`、`key_index`、`height`、`parent_hash`、`state_root`、返回的 `request`、NOID 扣款/入账、费用、费用上限、最小输出和期限。`pending_quote` 区分本地候选预测与基于已确认 State 的估计。

使用 `paranoid_walletSubmitNative` 和参数 `[same_request, reviewed_plan_id]` 授权。节点重建操作，并在生成 Owner 胶囊前检查确切审核绑定、规范父区块和当前钱包。上下文改变后需要重新预览。结果包含交易 ID 和实际费用。通过钱包现有收据 API 跟踪确认并保存收据。

<a id="request-actions"></a>
## 请求动作

| 动作 | 除 `action` 之外的字段 |
|---|---|
| `create_token` | `whole_tokens`、`metadata_hash`，可选 `initial_buy_units` |
| `transfer_token` | `asset_id`、`units`、`recipient` |
| `burn_token` | `asset_id`、`units` |
| `trade` | `asset_id`、`buy`、`gross_input`，可选 `minimum_output`、`slippage_bps`、`valid_until` |
| `create_collection` | `maximum_items`、`metadata_hash` |
| `mint_nft` | `collection_id`、`metadata_hash` |
| `mint_nfts` | `collection_id`、`metadata_hashes`，后者为非空有序数组 |
| `transfer_nft` | `collection_id`、`serial`、`recipient` |
| `burn_nft` | `collection_id`、`serial` |
| `list_nft` | `collection_id`、`serial`、`ask_micronoid`、`expiry_height` |
| `buy_nft` | `collection_id`、`serial`、`maximum_ask_micronoid` |
| `cancel_listing` | `collection_id`、`serial` |

`getNativeProtocol.nft_batch_limit` 返回批次上限，随后还需执行取决于资金的页检查。`mint_nfts` 使用现有铸造关系，创建一个集合后继，并按元数据哈希数组顺序为每个哈希创建一个 NFT，序号连续。预览返回包含两端的 `serial` 和 `last_serial`。同一创建者可以继续提交后续批次。钱包创建的多项目集合使用 `maximum_items = "18446744073709551615"`。独立 NFT 准备使用 `maximum_items = "1"`。GUI 自动设置这些值。现有集合保持已承诺条款。

未知字段被拒绝。交易 API 默认采用 100 个基点滑点，到期高度为候选高度后三个高度。显式期限必须位于候选高度起 30 个区块内。显式最小输出直接固定下限。是否纳入取决于操作在所选区块中的有效性。

`burn_token` 执行统一的销毁/赎回操作。`buy_nft` 限制接受的要价。上架与取消消耗当前确切项目或挂单实例。实际资金、费用、算术和资源选择均依据活跃 State 检查。

`create_token.initial_buy_units` 是以代币最小单位表示的精确整数字符串。省略或设置 `"0"` 表示创建时不购买，上限为固定供应的 60%。创建交易支付完整储备、标准曲线成本和网络费，并将购买代币分配给创建者。购买全部曲线配额会立即创建永久 DEX 池。分别审核 `reserve_deposit_micronoid`、`initial_buy_cost_micronoid`、`quoted_output` 和总 `noid_debit_micronoid`。Pruv 的 `create_token` 模板支持相同可选字段，提供时数量须为正。

[Pruv 原生模板](../contracts/native-templates.md)生成这些预览/提交请求，包含类型化身份、规范金额和明确交易边界。

<a id="saved-receipts"></a>
## 已保存收据

`paranoid_walletReceipts` 保持现有 `[page, page_size, family]` 接口。更多过滤条件使用 `paranoid_walletQueryReceipts`：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_walletQueryReceipts",
  "params": [1, 7, {
    "filter": "trades",
    "asset_id": "<64-character lowercase hexadecimal asset ID>",
    "operation": "trade",
    "timestamp_from": 1790812800,
    "timestamp_before": 1793491200,
    "verification": "confirmed",
    "order": "newest"
  }]
}
```

页码从 1 开始，每页大小为 1 至 50。省略查询字段时采用 `all`、不限资产或日期、操作 `any`、验证状态 `any` 和 `newest` 顺序。未知字段被拒绝。日期边界以 Unix 秒计，包含 `timestamp_from`，不包含 `timestamp_before`。

类别为 `all`、`noid`、`tokens`、`trades` 和 `nfts`。操作为 `any`、`payment`、`create_token`、`transfer_token`、`burn_token`、`trade`、`create_nft`、`transfer_nft`、`burn_nft`、`list_nft`、`buy_nft` 和 `cancel_listing`。`create_nft` 包括集合准备和项目铸造。验证值为 `any`、`confirmed`、`off_chain` 和 `missing_header`。顺序为 `newest`、`oldest`、`asset` 和 `operation`。

节点验证已保存的纳入数据，过滤完整收据库，并在分页前排序。资产和操作分组内部按最新优先排列。资产顺序使用收据已排序身份集合中的首个完整身份，NOID 支付排在前面。最新/最旧顺序使用高度、时间戳和逻辑交易 ID 稳定决定次序。响应回显精确查询，并返回 `page`、`page_size`、`total`、`total_pages` 和 `receipts`。原生交换保持为一张包含多个资产方向的收据。

同一时刻只执行一次高级扫描。收据修订号或规范链顶身份改变时中止查询，请基于当前库重试。普通收据导出与详细验证保持现有接口。

<a id="client-held-keys"></a>
## 客户端持有密钥

[`prepareNativeIntent`](client-native-rpc.md)为提供的所有者地址准备相同动作，返回规范未授权字节和供客户端授权的审核内容。通过 `submitTxIntent` 提交完成后的字节。
