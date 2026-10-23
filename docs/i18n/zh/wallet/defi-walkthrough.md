# 钱包中的代币、交易和 NFT

钱包可以创建代币，在联合曲线和原生 DEX 交易，发行 NFT 并管理市场挂单。
节点通过共同递归区块证明验证所有权、储备、付款及最终 State。

截图来自隔离测试网络中的实际 Rust/Iced 钱包。**TESTNET** 标识该网络。
名称、地址和余额为示例。操作时请核对自己钱包中的地址和完整资产身份。

## 选择操作地址

打开 **F1 Main**。等待 **Synced**，选择付款地址，并保留可花费的 NOID
支付网络费。**Send** 打开发送窗口。余额选择器默认显示 NOID，并列出当前
地址持有的代币。

![主界面和当前地址](../../../assets/wallet/v2.1-main.png)

**F2 Tokens** 包含持仓、Launchpad、DEX 和创建功能。
**F3 NFT** 包含 My NFTs、Marketplace、My Listings 和创建功能。
**F4 Receipts** 保存已确认操作的回执。

## 创建代币并进行首次购买

1. 打开 **Tokens → Create** 或 **Launchpad → Create Token**。
2. 输入名称、代码和固定整币发行量。最低为 **100,000 枚**，精度为六位小数。
3. 可添加说明、HTTPS 项目网站和标志。**Choose Logo** 接受最大 4 MB 的
   PNG、JPEG 或 WebP。
4. 在 **Initial buy** 输入创建者要同时购买的代币数量。零表示从曲线起点开放。
5. 核对 **NOID backing deposit** 和 **Initial buy cost**，然后选择 **Review**。

![代币创建表单](../../../assets/wallet/v2.1-token-create.png)

每整枚代币提供 **0.001 NOID** 的持有人储备。发行 100,000 枚需要 100 NOID
储备，同时购买 10,000 枚另需 38.888889 NOID。网络费单独显示。

首次购买最多可覆盖发行量的 60%，即全部曲线分配。余下 40% 用于永久 DEX
流动性。创建和首次购买在一笔交易中完成，购买所得直接进入创建者地址。
公众从成交后的曲线位置和价格开始交易。代币在整个生命周期保持固定供应量。

![储备、首次购买和总支出](../../../assets/wallet/v2.1-token-review.png)

核对地址、发行量、首次购买数量、储备、购买金额、网络费和 NOID 总支出。
选择一次 **Confirm & Send**。确认后在 **My Tokens** 和 **Launchpad** 查看代币。

## 查找代币并核对身份

**My Tokens** 显示当前地址持有或创建的代币。可按名称、代码或完整 asset ID
搜索。选择一行可查看完整身份、余额、锁定数量及操作。复制图标复制完整 ID。

![代币持仓与资产身份](../../../assets/wallet/v2.1-token-holdings.png)

**Launchpad** 提供 **New**、**Top Gainers** 和 **Graduated**。卡片显示图像、
名称、代码、价格和曲线进度。涨跌幅相对于标准曲线起始价。Graduated 保留已
进入 DEX 的代币，打开卡片会进入对应 DEX 市场。

![Launchpad 卡片](../../../assets/wallet/v2.1-launchpad-catalogue.png)

## 在联合曲线买卖

1. 从 Launchpad 打开代币，查看曲线、当前位置、资产信息和交易表单。
2. 选择 **Buy** 或 **Sell**。
3. 买入时输入 NOID 支出，卖出时输入代币数量。**MAX** 使用未锁定、未预留余额。
4. 默认价格容差为 **10%**。也可以在 Minimum receive 中输入准确的最低到账量。
5. 选择 **Review**，检查预计到账、最低到账、网络费上限和最后有效区块。

![曲线与交易表单](../../../assets/wallet/v2.1-launchpad.png)

报价包含本节点已知的待处理交易。各节点所知订单可能不同。授权的最低到账量和
费用上限保持固定。一个区块可执行多笔交易，每笔使用前一笔成交后的市场储备。

![交易审阅与最低到账条件](../../../assets/wallet/v2.1-trade-review.png)

**Confirm & Send** 后显示 Waiting for confirmation。确认并刷新余额后面板
自动关闭。**Close** 返回交易表单，Receipts 保留操作状态。

无法满足最低到账量的订单保持输入未花费。默认有效期覆盖四个候选高度，在
30 秒区块间隔下约两分钟。本地钱包在等待期间预留输入。刷新观察到确认或到期
后更新预留。到期未成交的订单释放预留，且不支付执行网络费。

## 进入 DEX

曲线分配售完后，同一资产自动进入永久 NOID 流动性池。资产身份和持有人余额
保持连续，曲线资金与剩余代币形成交易流动性。

| 发行量 | 持有人储备 | 曲线分配 | DEX 分配 | 毕业时曲线 NOID |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 100 NOID | 60,000 | 40,000 | 400 NOID |
| 5,000,000 | 5,000 NOID | 3,000,000 | 2,000,000 | 20,000 NOID |

赎回储备保持独立。创建者首次购买计入曲线进度。

**DEX** 提供搜索、分页和 Liquidity、Top Gainers、Newest 排序。打开卡片后
使用同样的 Buy、Sell 和 Review 流程。

![DEX 市场目录](../../../assets/wallet/v2.1-dex-catalogue.png)

![DEX 价格、储备和交易](../../../assets/wallet/v2.1-dex.png)

DEX 费为输入的 0.3%，向上取整到基础单位。网络费另行显示。当前价格来自
节点。**External data** 为打开的市场补充历史价格。Back 恢复原目录的搜索、
过滤、页码及滚动位置。

## 发送与销毁代币

在 **My Tokens → Send** 选择代币，也可使用 Main 的发送窗口。粘贴收款方
`o1` 地址，输入数量或选择 MAX。确认前核对资产、收款方、数量和 NOID 网络费。

![代币发送与 MAX](../../../assets/wallet/v2.1-token-send.png)

**Burn & Redeem** 在一笔交易中销毁所选代币，并返还其比例储备。输入数量或
选择 MAX，审阅 NOID 返还与网络费。返还量为 `储备 × 销毁量 / 流通量` 的整数
部分。舍入余量留给其余持有人，最后一次全部赎回取得所有剩余储备。

![销毁并赎回](../../../assets/wallet/v2.1-token-burn.png)

发送和销毁使用覆盖当前列表的窗口。Esc 或 Close 返回原来的选择。

## 创建单个 NFT

1. 打开 **NFT → Create → Single NFT**。
2. 输入名称并选择最大 4 MB 的 PNG、JPEG 或 WebP 图像。说明与 HTTPS 网站可选。
3. 选择 **Review preparation · Step 1/2**，核对费用并确认。
4. 确认后在 My NFTs 打开准备完成的卡片，选择 Complete NFT。
5. 审阅并确认 Mint · Step 2/2。确认后即可发送或挂牌出售。

![单个 NFT 创建](../../../assets/wallet/v2.1-nft-create.png)

两个步骤分别是一笔交易，各有网络费。准备卡片跨钱包重启保留，可以稍后完成发行。

## 创建集合并批量发行

1. 选择 **NFT → Create → Collection**。输入名称，可添加封面、说明和 HTTPS
   网站。审阅并确认集合创建。
2. 从 My NFTs 打开已确认的集合。
3. 选择 **Add NFTs → Add Images**，同时选择多个文件。
4. 编辑建议名称，按需填写共用说明和网站。
5. 在 Review 核对数量、序号范围及费用，一次确认整批原子发行。

![创建集合](../../../assets/wallet/v2.1-nft-collection-create.png)

![集合及其 NFT](../../../assets/wallet/v2.1-nft-collection.png)

![添加下一批 NFT](../../../assets/wallet/v2.1-nft-batch.png)

使用一个 NOID 资金输入时，一笔交易最多发行 122 项。更多资金输入可能减少
批次容量，Review 根据实际资源验证。每个源图像最大 4 MB，准备批次的内存
上限为 128 MB。

集合创建者可以随时返回并发行下一批。每项有自己的序号和元数据承诺。发送或
销毁后，该序号的发行记录仍保留。

## 持有、发送与市场

My NFTs 按集合组织持有的项目。自己创建的集合也可用于继续发行。使用 All、
Collections、Single NFTs，或按名称、ID 和序号搜索。

![按集合分组的持有项目](../../../assets/wallet/v2.1-nft-gallery.png)

打开持有项目并选择 Send，填写收款方，核对集合、序号及网络费后确认。
Burn 永久消耗该项目。操作窗口覆盖 NFT 工作区。

出售时选择 **Marketplace → List NFT**，选中可用项目并输入 NOID 价格。
也可使用 My NFTs → List for sale。核对售价、0.1 NOID 挂单信用、网络费和
到期高度。挂单有效 2,880 个区块，在 30 秒间隔下约一天。

![NFT 市场](../../../assets/wallet/v2.1-nft-marketplace.png)

买家使用另一个地址打开挂单，核对图像、集合、序号、卖方和售价，再审阅购买。
确认后 NFT 所有权与付款原子转移，卖方收到售价和挂单信用。

![使用另一个地址购买](../../../assets/wallet/v2.1-nft-buy.png)

卖方可在 **My Listings → Remove listing** 取回未售项目及扣除取消费后的
信用余额。确认后可按另一个价格重新挂牌。

## 图像、价格历史与回执

顶部 External data 默认关闭，提示为 Load token images and price history。
启用后加载图像和当前打开市场的价格历史。两个模式的余额、权利及实时价格都
来自自己的节点。

**Settings → Interface → Clear asset cache** 清除缓存图像、元数据和图表。
图像缓存上限为 64 MiB，准备上传的材料和已保存回执继续保留。

在 F4 Receipts 中选择 All、NOID、Tokens、Trades 或 NFT，结合过滤与排序
查找操作。打开回执可验证规范链状态并复制便携证据。导出重要回执并备份钱包。
区块体修剪后仍可验证回执。

![回执及规范链验证](../../../assets/wallet/v2.1-receipts.png)

精确规则见[代币](tokens.md)、[NFT](nfts.md)、[媒体](asset-media.md)和
[原生金融规范](../protocol/native-finance.md)。
