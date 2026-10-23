# 原生金融模板

示例假定 `pruv` 位于 PATH；本地构建后可使用 `target/release/pruv`。

除 ABI 3 编译器外，Pruv 提供 钱包 RPC 的类型化请求模板。
`AssetId`、`Owner` 与 `Quantity` 检查身份、规范地址及正整数金额字符串。
支持固定原生配置中的代币、交易和 NFT 操作。

模板声明单个操作。节点提供精确输入、费用、State 实例及 Owner 授权，
金融关系将其执行与整个区块一起证明。

将[原生 RPC](../reference/native-rpc.md) 中的请求保存为
`buy.native.json`。交易模板必须使用当前资产 ID，并明确提供
`minimum_output` 和 `valid_until`。

```sh
pruv native check buy.native.json
pruv native build buy.native.json --out preview.json
curl --fail-with-body -H 'Content-Type: application/json' --data-binary @preview.json http://127.0.0.1:9601
```

核对活动所有者、State、支出、最低收到数量及手续费上限。使用节点返回且
已经核对的 `plan_id` 准备提交：

```sh
pruv native submit buy.native.json --plan-id <reviewed-plan-id> --out submit.json
curl --fail-with-body -H 'Content-Type: application/json' --data-binary @submit.json http://127.0.0.1:9601
```

生成的提交保留模板中的全部条款，并绑定节点计划。已有输出文件不会被覆盖。
CLI 生成 JSON 文件；将 `walletSubmitNative` 请求发送给本地节点才会开始授权。

使用 `transfer_token` 和 `burn_token` 执行持有人操作，使用 `trade` 声明有明确
边界的买卖，使用 `list_nft`、`buy_nft` 和 `cancel_listing` 完成 NFT 原子托管与
付款。节点根据当前 State 验证实际资源费用。

现有 `pruv check`、`build`、`smt` 和 `verify` 命令继续用于
[ABI 3 程序](pruv.md)。16 条指令和两个状态寄存器的限制保持不变。
