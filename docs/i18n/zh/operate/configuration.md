# 配置

Core 默认从以下位置读取 TOML 配置：

```text
~/.parano1d/parano1d.toml
```

也可通过 `--config` 指定其他文件。文件不存在时会以安全默认值原子创建。
TOML 格式错误会直接阻止启动，程序不会静默覆盖它。

## 完整配置

```toml
[network]
listen = "0.0.0.0:9600"
seeds = []

[storage]
backend = "mdbx"
path = "~/.parano1d/data"

[rpc]
listen = "127.0.0.1:9601"

[mining]
enabled = false
miner_address = ""
```

命令行参数会覆盖对应的文件配置。

## 网络

`network.listen` 接受 `HOST:PORT` 或 libp2p multiaddress。绑定
`0.0.0.0:9600` 可接受公网 IPv4 连接。

`network.seeds` 用于添加引导节点，支持以下形式：

```text
198.51.100.10:9600
seed.example.org:9600
/ip4/198.51.100.10/tcp/9600
dnsaddr:seed.example.org
```

内置 DNS 种子始终可用，自定义种子只是在其基础上补充。

`--seed HOST:PORT` 可重复使用，并追加到配置的种子列表。

## 存储

发布版运行时 `storage.backend` 使用 `mdbx`。RAM 后端仅供测试，不提供
持久化 Live State。

`storage.path` 包含链数据库、钱包文件、对等身份、证明缓存以及快照暂存
数据。不要让两个正在运行的节点共用同一个目录。

命令行参数 `--data-dir` 会覆盖该路径。

## RPC

RPC 应保持监听：

```text
127.0.0.1:9601
```

该接口包含钱包提交和进程控制功能，并不是带有通用认证的公网浏览器 API。

外部挖矿部署需要 `--mining-key` 或 `--mining-key-file`。该令牌只允许
`getBlockTemplate` 和 `submitBlock`，不能访问钱包或进程控制方法。
Bearer token 不会加密传输；远程挖矿进程应通过回环地址、私有网络、SSH
隧道或经过认证的 TLS 代理连接。

矿池或交易所可以为远程记账和付款主机增加独立的 `--operator-key-file`。其固定权限包括有界的钱包状态、余额、已挖区块和收据查询、付款规划与提交、已确认交易和内存池交易查询、收据验证、地址验证、链状态、费用估算、精确的钱包合并，以及提交已在外部获得授权的原始交易意图。挖矿、进程控制、钱包扫描和地址发现、地址管理、无界的钱包列表以及所有未列出的方法均被拒绝。运营者令牌必须与挖矿令牌不同，并具有支出权限，因此应将其保存在仅所有者可读的文件中，并仅通过有防火墙保护的私有或加密传输开放 listener。完整方法列表见 [JSON-RPC API](../reference/rpc.md#认证)。

RPC 仅支持 HTTP。WebSocket 升级会被拒绝，请求体限制为 1 MiB。JSON-RPC batch 在该请求体限制内继续受支持。

## 挖矿

进程模式具有决定性：

```sh
parano1d --mode node
parano1d --mode miner
parano1d --mode extminer --mining-key-file ~/.parano1d/mining.key
```

旧的 `mining.enabled` 字段不会覆盖 `--mode`。`miner_address` 为空时，
使用钱包活动地址；`--miner-address` 则覆盖当前进程的奖励地址。

`--cpu-threads N` 限制内置挖矿共享 CPU 池，对普通节点模式和独立的外部
挖矿进程均无影响。

## 日志

`--log` 接受 `error`、`warn`、`info`、`debug` 等过滤器。建议先使用
`info`。`debug` 适合有时间边界的诊断，但日志量会明显增加。

systemd 环境下输出进入 journal。GUI 则把私有节点日志写入所选数据目录的
`parano1d-node.log`。

## 启动前检查

无需创建配置、钱包或数据库即可检查 CPU：

```sh
parano1d --check-hardware
```

检查成功时，最后一行是 `NODE READY`。
