# 测试

Parano1d 使用三层测试：crate 级不变量、跨 crate 发布测试，以及从全新数据目录启动真实进程的
端到端测试场景。

## 快速检查

针对性修改前运行：

```sh
cargo fmt --all -- --check
cargo check --release --locked --workspace --all-targets
cargo test --release --locked -p CHANGED_CRATE
```

协议代码还应包含直接依赖者。交易改动通常至少需要：

```sh
cargo test --release --locked \
  -p noid_tx \
  -p noid_chain \
  -p noid_mempool \
  -p noid_miner \
  -p noid_rpc \
  -p noid_node
```

## 证明内核

生产用证明内核的测试应使用 release 模式：

```sh
cargo test --locked --release \
  -p noid_core \
  -p noid_poseidon2b \
  -p noid-ivc-core
```

x86-64 上强制测试发布版最低后端：

```sh
NOID_CPU_BACKEND=pclmul \
  cargo test --locked --release \
  -p noid_core -p noid_poseidon2b -p noid-ivc-core
```

标量后端只用于差分检查：

```sh
NOID_CPU_BACKEND=scalar \
  cargo test --locked --release \
  -p noid_core -p noid_poseidon2b
```

## 发布门禁

`scripts/build_release.sh` 认证并嵌入发布矩阵包，然后对本机构建程序执行冒烟测试。
源码检查和测试须在打包前单独运行。包内检查包括：

- 硬件预检；
- 节点帮助和启动边界；
- CLI；
- 外部矿工；
- 已打包 GUI 自检。

调试版二进制文件或没有矩阵包的开发节点不能算作区块生产测试。

## 真实进程测试场景

真实进程测试脚本会在 `target/live-tests` 下创建全新数据目录，并运行真实进程、
RPC、P2P、MDBX 和生产用证明路径。

| 场景 | 覆盖范围 |
|---|---|
| `live_cli_wallet_scenarios.py` | 三节点 CLI、中继、地址、发送、历史与收据生命周期 |
| `live_single_transaction_scenario.py` | 钱包 → 内存池 → 矿工 → 规范区块 |
| `live_multi_transaction_mempool_scenario.py` | 三笔互不冲突的交易意图与中继 |
| `live_large_mempool_single_miner_scenario.py` | 按测试网络的活动类别处理 128 笔交易意图 |
| `live_large_mempool_two_miners_scenario.py` | 矿工竞争下的大型内存池 |
| `live_two_miner_fork_reorg_scenario.py` | 竞争子区块与浅层重组 |
| `live_connected_miner_restart_sync_scenario.py` | 矿工重启与过期父区块防护 |
| `live_mining_peer_gate_scenario.py` | 普通对等节点数量要求 |
| `live_sync_scenarios.py` | 全新、5 区块和 19 区块同步边界 |
| `live_incremental_snapshot_scenario.py` | 完整与增量快照发布 |
| `live_sync_announced_tip_scenario.py` | 以宣布链尖为上界的追赶同步 |
| `live_state_restart_scenario.py` | 紧凑 Live State 重启和首个新区块 |
| `live_state_slot_lifecycle_scenario.py` | Live State 槽位清除、复用、密度与重启 |
| `live_receipt_lifecycle_scenario.py` | 收据保存、篡改、重启与区块体裁剪后验证 |
| `live_wallet_active_address_scenario.py` | 生成、注资、激活并持久化活动地址 |
| `live_wallet_mining_payout_switch_scenario.py` | 原子切换奖励地址 |
| `live_wallet_receive_online_scenario.py` | 在线接收者增量更新 |
| `live_wallet_receive_offline_shallow_scenario.py` | 通过保留区块恢复离线接收者 |
| `live_wallet_receive_offline_snapshot_scenario.py` | 通过快照同步恢复离线接收者 |
| `live_slot_mempool_wallet_scenarios.py` | 带盐值的槽位提示、多节点发送与收敛 |
| `live_p2p_identity_handshake_scenario.py` | 持久对等节点 ID 与双向握手 |
| `live_p2p_fan_in_scenario.py` | 并发入站握手负载 |
| `live_p2p_inbound_sybil_scenario.py` | 每 IP 入站限制 |
| `live_p2p_outbound_diversity_scenario.py` | 出站网络组多样性 |
| `live_p2p_mesh_block_scenario.py` | 超出首选网格的区块中继 |

每个脚本开头都说明环境参数和二进制要求。从仓库根目录运行：

```sh
python3 scripts/live_two_miner_fork_reorg_scenario.py
```

## 边界改动

涉及最终性、周期或 State 扩展边界的修改，需要显式边界测试向量，不能只依赖长时间运行的
正常路径测试。应覆盖：

- 交易锚点高度 143、144、145；
- 17 和 18 区块分叉深度；
- 18 和 19 区块同步差距；
- 占用率 9/9 和 10/8 的已达最终性扩展窗口；
- 使用完整 36 区块头扩展回看窗口的重启；
- 奖励分配边界和最终分配高度；
- 从一个 `log_slots` 层级扩展到下一个；
- 共享路径终端往返编码、畸形输入与解码上限；
- 内存池数量和字节占用在 50% 与 80% 的边界、清空重置和 Auto 重试；
- 部分内存池恢复、重复递送和断开的来源；
- Small/Large 选择与系统铸币预留槽位，包括全部软预留时的回退。

测试应使用隔离数据目录。并发运行时可以使用不同端口，但不得修改测试样例
或生产数据。

## v2 验证

`live_v2_*` 脚本使用只有回环接口的隔离网络，以及配置早期测试高度的程序。
运行前阅读各脚本对矩阵库、环境及已停止测试网络的要求。主网源码使用 H210537；
早期测试高度的矩阵包不能用于主网构建。

| 脚本 | 覆盖内容 |
| --- | --- |
| `live_v2_contract_scenario.py` | 合约程序、双方权限、裁剪和重启 |
| `live_v2_capacity_scenario.py` | 满载 Small/Large 付款和调用；Large 之后的 Small |
| `live_v2_boundary_reorg_scenario.py` | 分叉边界、浅层竞争祖先链和恢复 |
| `live_v2_parent_target_scenario.py` | v2 同父竞争区块使用相同目标，三个节点在同高度分叉后收敛 |
| `live_v2_retired_sync_scenario.py` | 不内嵌旧矩阵的冷同步 |
| `live_v2_retired_mining_scenario.py` | 移除旧矩阵后继续生产 |
| `live_v2_contract_discovery_scenario.py` | 关联合约状态及已保存回执发现 |
| `live_v2_shared_receipts_scenario.py` | 共用终端存储和回执完整性 |
| `live_v2_contract_wallet_scenario.py` | 两钱包、双方操作、离线及裁剪后合并 |

边界向量还覆盖 H−1/H/H+1、两种旧前驱类别、混合 ASERT 间隔、年度发行档位、
合约截止高度、检查溢出的 u64 运算及冲突花费。满载场景遵守共同的页面、输入
和调用预算。主网矩阵库与早期高度矩阵库分别验证；
[性能页](../reference/performance.md)注明测量工件。
