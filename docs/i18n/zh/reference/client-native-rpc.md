# 客户端授权的原生操作

`paranoid_prepareNativeIntent` 为明确提供的所有者地址准备代币、交易和 NFT 操作。客户端从桌面钱包采用的同一规划器接收规范意图和精确审核内容。客户端在提交前完成操作授权。

此方法使用本地所有者 RPC 访问。Web 服务通过 loopback 调用节点，并通过 HTTPS 提供自身受限的应用 API。

<a id="prepare"></a>
## 准备

参数为 `[owner, request, expected_parent_hash?]`。请求使用[原生操作动作](native-rpc.md#request-actions)。金额为最小单位的十进制整数字符串。可选父区块哈希固定调用方预期的规范快照。

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_prepareNativeIntent",
  "params": [
    "<owner address>",
    {
      "action": "trade",
      "asset_id": "<64-character asset ID>",
      "buy": true,
      "gross_input": "1000000",
      "slippage_bps": 1000
    },
    "<canonical parent hash>"
  ]
}
```

响应为 `NativeClientPlan`：

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 响应模式版本，当前为 `1` |
| `plan_id` | 对父区块、所有者、锚、请求和未授权意图的 BLAKE3 承诺 |
| `intent_id` | 逻辑操作 ID 或带资金交易授权 ID |
| `owner` | 其秘密授权此操作的地址 |
| `candidate_height` | 用于规则与费用规划的高度 |
| `parent_header_hex` | 完整规范的 212 字节父区块头 |
| `chain_id` | 原生操作的链身份 |
| `epoch_anchor` | 候选高度的交易锚 |
| `owner_authorization_version` | 候选规则选择的构造 |
| `intent_kind` | `operation` 或 `trade` |
| `unsigned_intent_hex` | 授权为空的规范传输意图 |
| `review` | 请求、State 身份、精确金额、费用和操作条款 |

审核内容包括 NOID 扣款和入账、费用与上限、持有人储备、创建者购买、赎回、报价与最小输出、期限、资产和集合 ID、序号范围及输入/输出数量。交易审核还报告本地待处理策略预测。

准备读取已验证 State 和本地内存池，保持节点钱包地址、密钥、本地活动及预留状态不变。多个客户端可以为各自地址请求计划。计划作为快照，不预留输入或输出槽位。完成的意图到达时，接纳检查会验证其可用性。

<a id="check-and-authorize-on-the-client"></a>
## 客户端检查与授权

1. 依据应用选定的节点连接检查 `schema_version`、链、父区块头、时期锚和候选规则。
2. 将 `unsigned_intent_hex` 解码为 `operation` 的 `NativeIntent`，或 `trade` 的 `TradeOwnerIntent`，并检查授权为空。
3. 重新计算规范所有者声明和 `intent_id`。对照用户批准的操作检查所有者、确切动作、资产身份、资金来源、接收者、输出和费用。交易还检查总输入、最小输出、费用上限和有效区间。
4. 使用 `owner_authorization_version` 生成 Owner 胶囊。原生资产、金融和交易授权函数在证明前检查各自公开关系。
5. 在本地验证完成的胶囊，将其规范包字节放入 `authorization_bytes`，再序列化同一意图。
6. 通过 `paranoid_submitTxIntent` 提交这些字节。保存操作 ID 和确认收据以供跟踪及导出。

金融操作使用候选高度、父区块 ID 和父分配计数器构造 `NftRoundContext`。这些值都包含在返回的区块头和计划中。公开关系由解码出的操作选择。

原生操作采用 `NOIDNT21` 格式。带资金交易采用 `NOIDTO21`，其中包含规范交易策略和资金声明。详见[传输格式](../protocol/native-wire.md)。

<a id="reproduce-the-plan-identity"></a>
## 重现计划身份

对以下字节序列计算 BLAKE3：

```text
"NOIDNativeClientPlan1"
|| parent_header_bytes
|| owner_bytes
|| epoch_anchor_bytes
|| request_json_length_u32_le
|| request_json_bytes
|| unsigned_intent_bytes
```

`request_json_bytes` 是 `NativeWalletRequest` 按声明顺序生成的紧凑 Serde 编码。计划身份使客户端能够保存精确准备并审核的内容。Owner 胶囊绑定规范意图的授权声明。

<a id="snapshot-and-resource-bounds"></a>
## 快照与资源边界

`expected_parent_hash` 不匹配时返回错误 `-32041`，并附带当前 `height` 和 `block_hash`。刷新 State 后重新准备。规划器还检查资金记录的链顶绑定和待处理策略快照。

请求编码上限为 32 KiB。NOID 资金发现最多读取 16,384 个已验证来源。归集可减少资金碎片化所有者的来源数量。全部原生页、动作、市场和费用检查采用已安装运行时的常规接纳预算。

交易默认值与期限规则同原生钱包 API。传入 `slippage_bps: 1000` 以采用桌面 GUI 的 10% 容差，或指定明确最小输出。通过 `getMempoolEntry` 和规范收据跟踪提交操作。过期未成交策略离开内存池后，其未花费来源可以用于新计划。
