# 资产图片与价格历史

`parano1d-media` 分发公开资产元数据、静态图片和已确认交易历史。图片发布采用原生收据与内容哈希，价格历史跟随进行完整验证的本地节点的规范区块。服务与节点部署在同一主机。

<a id="build-and-configure"></a>
## 构建与配置

```sh
cargo build --release --locked -p noid_gui --bin parano1d-media
```

配置独立存储目录、loopback 监听地址、本地节点 RPC 和存储配额：

```sh
export NOID_MEDIA_STORE=/srv/parano1d-media
export NOID_MEDIA_LISTEN=127.0.0.1:9610
export NOID_MEDIA_RPC=http://127.0.0.1:9601
export NOID_MEDIA_QUOTA_MIB=4096
export NOID_HISTORY_QUOTA_MIB=1024
./target/release/parano1d-media
```

存储写入租约由一个进程持有。在 loopback 监听前部署 TLS 反向代理，在代理处限制请求速率，将请求体上限设为 10,518,528 字节，并保留固定请求长度。服务限制头部、上传大小、节点响应、超时、图片解码和并发请求，拒绝 chunked 请求帧与重定向。

钱包默认使用 `https://tradedata.parano1d.org/`。独立部署或隔离测试网络可覆盖 origin：

```sh
export NOID_GUI_MEDIA_ORIGIN=https://tradedata.parano1d.org/
./target/release/parano1d-gui
```

Origin 包含主机、可选端口和路径 `/`。用户信息、查询字符串、片段和路径前缀被拒绝。HTTP 仅允许在隔离开发的 loopback 地址使用。共享同一注册表的钱包应采用同一 origin。外部下载遵循钱包保存的 **External data** 偏好，初始为 Off。

<a id="publication-checks"></a>
## 发布检查

`POST /publish` 接受模式 1，包含 `metadata_hash`、`manifest_hex`、可选 `image_hex` 和 `receipt_hex`。未知字段被拒绝。服务通过自身 loopback 节点调用 `paranoid_verifyReceipt`，并要求 `merkle_valid`、`canonical` 和 `confirmed` 三个标志均成立。

服务随后将精确元数据哈希与清单类型匹配到经过认证的原生创建效果或 NFT 输出。代币和集合身份来自 `native.created`，NFT 输出绑定集合 ID 和序号。独立 NFT 的准备收据可在铸造完成前发布已承诺图片。收据检查高度与公开证明一起记录。当前可花费权利始终来自当前 State。

规范清单采用域分离 BLAKE3，图片使用独立域分离哈希。服务验证两者，在大小限制内解码 PNG，并原子写入不可变文件。重复有效发布会去重。配额计算包含中断写入后已部分提交的对象，下次尝试可以补全剩余对象。

<a id="reading-and-backup"></a>
## 读取与备份

公开读取路由：

```text
GET /metadata/<64 lowercase hex characters>.json
GET /images/<64 lowercase hex characters>.png
GET /history/<64 lowercase hex asset ID>/<end height>.json
```

响应采用固定内容类型、`nosniff` 和严格的内容安全策略。图片和清单使用不可变缓存头。历史使用 `no-store`，使规范更新及时可见。钱包下载后检查图片与清单承诺。

<a id="price-history"></a>
## 价格历史

服务在 `history/` MDBX 数据库中索引已确认执行。每个区块原子提交区块头、涉及资产和 K 线。规范链改变时先移除被替换记录，再索引替代区块。历史配额默认为 1,024 MiB，数据库逐步增长。归档增长时增加 `NOID_HISTORY_QUOTA_MIB`。

持续运行服务可保留超出节点区块服务窗口的价格。启动时索引可用近期区块，重启后从保存的游标继续。若错过的区间已被节点剪枝，则从仍保留的近期范围恢复索引。

历史端点为一个资产返回最多 512 个区块，结束于请求高度或最近已索引区块。价格采用精确 NOID 和代币数量。每根 K 线包含首次、最高、最低、最后执行价和交易次数。钱包将响应链身份及终点区块头与自身节点核对。

**External data** 开启时，钱包仅为当前打开的 DEX 代币请求历史，并在有界内存中保存响应。两种开关状态下，当前价格和实时价格线均来自钱包自己的节点。

将以下三个目录备份到媒体仓库：

```text
metadata/<metadata hash>.json
images/<image hash>.png
proofs/<transaction ID>-<metadata hash>.json
```

排除 `service.lock`、临时文件和钱包私有 `queue/` 目录。公开收据与绑定记录一起保存。复制备份前停止服务或创建一致文件系统快照。恢复后，在启动服务前检查全部清单和图片承诺：

```sh
./target/release/parano1d-media --verify-store /srv/parano1d-media
```

服务停止时或通过文件系统快照，将 `history/` 备份为一致数据库快照。公开图片仓库保存上面列出的元数据、图片与发布证明文件。

此命令离线检查内容完整性。发布时通过本地节点检查收据的规范性，保存的发布记录给出检查成功高度。恢复后的媒体仍依据各接收钱包当前的 State 承诺进行匹配。
