# 术语表

本页解释 Parano1d 文档中具有特定协议含义的术语。代码标识符、协议对象名和
通行缩写保留原文；首次出现时给出中文含义。普通的操作系统、Rust 与 JSON 类型
不在此重复定义。

## State 与共识

<a id="state"></a>
### State

由当前区块头承诺的精确规范对象，包括稀疏索引 UTXO 向量及其共识计数器。
文档中首字母大写的 `State` 专指这一协议对象，不表示界面或进程的状态。

<a id="live-state"></a>
### Live State

节点当前保存并物化的 `State`。它随已接受区块推进，包含当前未花费 UTXO，
但不包含已经裁剪的历史交易体。

<a id="proof-native-layer-1"></a>
### 证明原生 Layer 1

一种把证明作为共识必要对象的第一层网络架构。每个已接受区块都证明精确的
`State` 转换并验证前一个 `HistoryStep` 终端；工作量证明只对有效转换排序。

<a id="history-stateless"></a>
### 无需历史重放（history-stateless）

验证当前 `State` 无需重放历史交易。该性质不表示节点无需保存或传输
`Live State`，也不表示永久区块头可以删除。

<a id="utxo"></a>
### UTXO

未花费交易输出（unspent transaction output）。在 Parano1d 中，每条 UTXO
占用一个精确槽位，并记录金额、创建标识符和所有者。

<a id="slot"></a>
### 槽位（slot）

精确稀疏 UTXO 向量中的一个带索引位置。槽位被花费后可以清空并安全复用。

<a id="creation-id"></a>
### 创建标识符（creation ID）

UTXO 写入槽位时分配的新标识符；代码字段为 `creation_id`。它防止过期引用
花费同一数值槽位的后续占用者。

<a id="state-segment"></a>
### State 分段（State segment）

由 `2^16` 个连续槽位组成的存储与传输单元。空分段是虚拟的；最后一条 UTXO
被花费后，物理分段可以删除。

<a id="materialization"></a>
### 物化（materialization）

把已经证明的规范槽位变化写入完整节点的精确本地 `State`。物化不同于推导或
证明该转换。

<a id="snapshot-manifest"></a>
### 快照清单（snapshot manifest）

描述快照边界、`State` 根、计数器以及每个分段标识、长度和根的认证清单。

<a id="snapshot"></a>
### 快照（snapshot）

在最终性边界传输 `State` 的分段格式。安装前，节点会验证快照清单、
分段根、规范区块头和匹配的终端证明。

<a id="undo-data"></a>
### 撤销数据（undo data）

节点为近期可重组后缀保存的本地回滚记录。它不能作为共识依据，也不能替代
候选分支自身的有效证明。

<a id="historystep"></a>
### HistoryStep

递归区块关系，用于证明当前转换有效、转换后 `State` 精确，并验证前一个终端
证明。

<a id="terminal"></a>
### 终端证明（terminal proof）

当前 `HistoryStep` 的固定形状递归证明输出。

<a id="recursive-validity"></a>
### 递归有效性与递归连续性

递归有效性表示当前证明验证前一个终端证明；递归连续性表示相邻证明绑定同一条
不间断的 `State` 转换序列。

<a id="canonical-chain"></a>
### 规范链与规范链尖（canonical chain and tip）

在全部合格候选链中由确定性分叉选择规则选出的链，以及该链当前最后一个区块。

<a id="cumulative-work"></a>
### 累计工作量（cumulative work）

一条候选链所有区块目标工作量的累计值。合格链之间优先选择累计工作量最大的链。

<a id="fork-choice"></a>
### 分叉选择（fork choice）

在保留具备硬最终性的前缀的有效候选链之间比较累计工作量，并在工作量相同
时使用确定性决胜规则。

<a id="hard-finality"></a>
### 硬最终性（hard finality）

候选链不得替换最近 18 区块后缀之前、已经具备最终性的前缀。这是共识规则，
不是界面确认策略。

<a id="finality-boundary"></a>
### 最终性边界（finality boundary）

把不可重组前缀与近期可重组后缀分开的规范高度。快照认证和 `State` 扩展观测
都以该边界为准。

<a id="reorganization"></a>
### 链重组（reorganization，reorg）

规范链近期后缀被累计工作量更大的合格分支替换。共识允许的回滚深度严格小于
18 个区块。

<a id="proof-of-work"></a>
### 工作量证明（proof of work，PoW）

对已经证明有效的候选转换进行排序的计算。PoW 不能修复无效证明，也不能单独
构造区块。

<a id="nonce"></a>
### nonce

证明完成后由矿工搜索的 128 位区块头字段。它只影响含 nonce 的区块 ID，
不改变已经证明的区块语义。

<a id="asert"></a>
### ASERT

指数型目标调整算法，用于根据区块时间确定下一目标值。ASERT 使用 6 区块参考周期、
180 秒半衰期和 30 秒目标间隔。

<a id="block-id"></a>
### 区块 ID（block ID）

包含 nonce 的完整规范区块头经过域分离 Poseidon2b 得到的哈希，用于父链接、
交易周期锚点和规范链身份。

<a id="semantic-header-id"></a>
### 语义区块头 ID（semantic header ID）

在 `HistoryStep` 内绑定的无 nonce 区块头投影。它承诺其他全部共识关键区块头
字段。

<a id="accepted-block-bundle"></a>
### 已接受区块包（accepted block bundle）

直接接纳区块时使用的网络对象：规范区块字节及其匹配的 `HistoryStep` 终端证明。两者一同验证和转发。认证追赶同步在验证精确后缀链尖的递归终端证明后，可以省略重复的中间终端证明字节。

<a id="body-retention-window"></a>
### 区块体保留窗口（block-body retention window）

完整区块交易数据可由普通节点提供的最近 42 个区块窗口。它不同于 18 区块认证后缀与最终性边界。区块头永久保存。

## 交易与钱包

<a id="address"></a>
### 地址（address）

所有者值的 bech32m 用户界面编码，使用 `o1…` 格式。地址是公开接收标识，
不是支出秘密。

<a id="owner"></a>
### 所有者（owner）

UTXO 中记录的 32 字节公开值。普通所有者值由 256 位支出秘密经 Poseidon2b
派生，钱包用零知识证明其秘密知识；合约输出则在此字段存储对象承诺。

<a id="active-address"></a>
### 活动地址（active address）

钱包当前选中的派生地址。该地址对应的所有者用于发送、找零和默认内置挖矿
奖励；其他派生地址仍然有效，但其 UTXO 不会自动混入当前付款。

<a id="main-address"></a>
### 主地址（Main address）

由主密钥派生的索引 `0` 地址。`Main` 是默认本地标签，不赋予额外共识权限。

<a id="transaction-intent"></a>
### 交易意图（transaction intent）

钱包提交、内存池验证并由网络转发的完整原子付款对象，包括有序物理页和授权
证明封装。

<a id="logical-transaction"></a>
### 逻辑交易（logical transaction）

一笔原子的 `PagedSpend`，可以由多个物理页组成，但只有一个逻辑交易 ID 和
一份钱包授权。

<a id="pagedspend"></a>
### PagedSpend

由 1 至 128 个有序 `Tx8x2` 物理页组成的一笔原子钱包交易意图。

<a id="tx8x2"></a>
### Tx8x2 物理页（physical page）

固定的 323 字节交易记录，可容纳八个输入和两个输出。

<a id="authorization-envelope"></a>
### 授权证明封装（authorization proof envelope）

绑定完整逻辑交易 ID 及授权方的随机化钱包证明对象。普通付款使用输入所有者，
合约调用使用策略的当前授权方。它证明支出秘密的
知识，但不证明输入当前仍存在于 `Live State`。

<a id="transaction-epoch-anchor"></a>
### 交易周期锚点（transaction epoch anchor）

每 144 个区块更新一次的区块 ID，用于限制钱包授权和内存池交易的重放期限。

<a id="mempool"></a>
### 内存池（mempool）

节点已经完成本地准入、但尚未被规范区块收录的原子交易意图集合。

<a id="system-record"></a>
### 系统记录（system record）

由区块上下文确定、无需钱包授权的固定物理页，例如主要奖励和到期开发付款。

<a id="receipt"></a>
### 收据（receipt）

自包含交易陈述及八层 Merkle 路径，用于证明交易被纳入某个声明的规范区块头
交易根。

<a id="master-secret"></a>
### 主密钥与支出秘密

钱包保存一个 256 位主密钥，并由它确定性派生各地址的 256 位支出秘密。知道
相应秘密即拥有支出权限。

<a id="micronoid"></a>
### μNOID

最小货币单位。1 NOID 等于 1,000,000 μNOID。

<a id="state-growth-fee"></a>
### State 增长费（State-growth fee）

净增加 `Live State` 中已占用 UTXO 槽位所支付的手续费部分。它随占用率变化，
并由协议销毁，矿工不能领取。

## 证明系统与安全性

<a id="zero-knowledge-proof"></a>
### 零知识证明（zero-knowledge proof，ZK proof）

使证明者能够证明命题成立、同时不泄露命题之外私有见证数据的证明系统。
Parano1d 的钱包证明隐藏支出秘密，不隐藏公开金额和所有者。

<a id="prover-verifier"></a>
### 证明者与验证者（prover and verifier）

证明者使用命题和见证数据生成证明；验证者只根据公开命题、证明和协议参数决定
接受或拒绝。

<a id="witness"></a>
### 见证数据（witness）

证明者掌握、用于使公开命题成立的输入。钱包见证包含支出秘密；矿工见证包含
所证明转换需要的公开 `State` 数据。

<a id="commitment"></a>
### 承诺（commitment）

在不立即公开完整内容的情况下绑定一个值或多项式的密码学对象。

<a id="opening"></a>
### 打开证明与求值声明（opening proof and opening claim）

证明某个承诺对象在指定点具有所声明值的证明，以及相应的公开求值声明。

<a id="transcript"></a>
### 交互记录（transcript）

证明协议中公开消息和挑战值的规范序列。非交互式证明从该序列确定挑战值。

<a id="poseidon2b"></a>
### Poseidon2b

Parano1d 在 `GF(2^128)` 上使用的宽度为 4 的代数置换，服务于地址、交易、Merkle
节点、`State` 根、证明交互记录、区块 ID 和 PoW 摘要。

<a id="binary-tower-field"></a>
### 二进制塔域（binary tower field）

通过二次扩域逐层构造的特征二有限域。Poseidon2b 与已承诺执行轨迹使用
`GF(2^128)`；实际部署 C1 配置的 Fiat–Shamir 挑战值、终端声明和递归区域认证
使用其二次扩域 `GF(2^256)`。

<a id="domain-separation"></a>
### 域分离（domain separation）

为不同哈希用途使用不同类型标签或上下文，使相同底层置换生成彼此不可混用的
协议对象。这里的“域”不是有限域（field）。

<a id="frost-gkr"></a>
### [FROST-GKR](../research/frost-gkr.md)

一种承诺列归约（committed-column reduction）：在共享布尔超立方上表达批量
Poseidon2b 与 Merkle 关系，再通过多线性 sumcheck 归约。

<a id="multilinear-extension"></a>
### 多线性扩展（multilinear extension，MLE）

把布尔超立方上的求值表唯一扩展为每个变量次数至多为一的多项式。

<a id="sumcheck-family"></a>
### sumcheck、zerocheck 与 lincheck

用于把高维多项式求和、零关系或线性关系归约为更少求值断言的交互式协议族。

<a id="polynomial-commitment"></a>
### 多项式承诺方案（polynomial commitment scheme，PCS）

承诺多项式并证明其在指定点求值的密码学方案。

<a id="iop"></a>
### 交互式预言机证明（interactive oracle proof，IOP）

验证者通过有限查询访问证明者提供的预言机编码，并据此检查命题的证明模型。

<a id="r1cs"></a>
### 秩一约束系统（rank-1 constraint system，R1CS）

以双线性乘积等式表示算术关系的约束系统。

<a id="fri-family"></a>
### FRI、FRI-Binius 与 BaseFold

FRI 是低次数测试框架；FRI-Binius 与 BaseFold 是适配二进制域证明栈的具体
组合。文档中的安全性指标始终保留其所依据的明确模型。

<a id="small-large"></a>
### Small / Large / Native

三类证明。Small m23 为 63 页，Large m24 为 206 页，Native m24 为
63 页并支持原生金融。每类有 504 输入及 63 次调用预算。自动考虑 Small
和 Native，`--v2-large-blocks` 额外允许 Large。节点按费用选择一个候选并构建
一个证明。所有节点验证三类。

### Block–Tiwari FS-FRI 安全性

Block 和 Tiwari 为非交互式 FRI 定义的具体经典随机预言机期望工作量指标。
可证明值与猜想值使用不同的 RBR 前提，即使整数位表示相同也不例外。

<a id="c1-profile"></a>
### C1 配置

源码中实际部署扩展挑战值配置的标识符。其代数挑战值从 `GF(2^256)` 中基数为
`2^255` 的迹为 1 仿射集合采样。资源评估单独见[安全模型](../protocol/security-model.md)。

<a id="completeness"></a>
### 完备性（completeness）

对于真实命题，诚实证明者按协议生成的证明会被诚实验证者接受。

<a id="soundness"></a>
### 可靠性（soundness）

对于错误命题，验证者错误接受的概率不超过协议声明的上界。该数值只有连同
对手模型、密码学前提和组合范围才有意义。

<a id="round-by-round-soundness"></a>
### 逐轮可靠性（round-by-round soundness，RBR）

逐轮分析交互式证明中错误命题继续通过后续检查的概率。文档中的 RBR 数值按其
明确公开的安全模型报告。

<a id="knowledge-error"></a>
### 知识误差（knowledge error）

知识证明中，验证者接受但提取器不能提取有效见证数据的概率上界。

<a id="grinding"></a>
### Grinding（多次试探）

在提交查询或挑战之前允许攻击者尝试多个候选值的计算工作。安全性公式必须明确
说明 grinding 工作量被计入哪一个概率项。

<a id="toy-problem-conjecture"></a>
### Toy Problem 猜想

Plonky2、RISC Zero 等 FRI 实现公开采用的一种基于码率、查询数和 grinding
计算安全性评分的约定。该评分与 RBR 或知识误差是不同指标。

<a id="trusted-setup"></a>
### 可信设置（trusted setup）

生成证明系统公共参数时必须由参与者保守秘密的初始化过程。Parano1d 的透明
证明栈不需要此类设置。

<a id="post-quantum-resistance"></a>
### 后量子安全性（post-quantum resistance）

Parano1d 的交易共识不依赖椭圆曲线签名或可信设置。其端到端 QROM 定理在明确
前提下，把从创世开始的无效 State 可靠性游戏与 NIST 后量子密码学 Category 1 资源
门槛比较。

<a id="nist-category-one"></a>
### NIST 后量子密码学 Category 1

以穷举 AES-128 密钥为参照并包含公开 `MAXDEPTH` 限制的 NIST 资源目标。
Parano1d 针对从创世开始的端到端无效 State 可靠性游戏评估这一目标。

## 网络

<a id="peer-identity"></a>
### 对等节点身份（peer identity）

节点持久保存的 libp2p Ed25519 网络身份。它认证网络会话，但没有钱包支出或
区块共识权限。

<a id="authenticated-peer"></a>
### 已完成身份认证的对等节点（authenticated peer）

已通过 libp2p 身份握手建立会话的对等节点。身份认证不表示该节点可信，也不
构成共识投票。

<a id="dns-seed"></a>
### DNS 种子（DNS seed）

首次连接时提供公网对等节点地址的引导来源。DNS 记录不定义规范链或 `State`。

<a id="kademlia"></a>
### Kademlia

节点持续发现其他对等节点所使用的分布式路由与发现协议。

<a id="mdns"></a>
### mDNS

在同一本地网络中发现 Parano1d 节点的组播 DNS 机制。

<a id="gossipsub"></a>
### GossipSub

libp2p 的主题式消息传播协议，用于转发交易意图和区块公告。

<a id="network-group"></a>
### 网络组（network group）

连接管理器按网络前缀归类的地址组，用于限制单一网络范围占满全部连接。

<a id="sybil"></a>
### Sybil 攻击

攻击者创建大量网络身份以试图控制发现、连接或消息视图的攻击。对等节点身份
本身不等于独立运营方。

<a id="rpc"></a>
### RPC

节点的本地 JSON-RPC 管理接口。它与公网 P2P 端口分离，不应未经认证直接暴露
到互联网。

## Proof-native 合约

承诺短整数程序、授权策略及两个计数器的活输出。调用在 `HistoryStep` 内证明
允许的后继或关闭。见[合约](../contracts/index.md)。

## 合约 opening

包含不可变条款及当前计数器的 699 字节公开编码，用于重建 State 所有者承诺。
钱包保留并分享这些数据。

## 合约回执

合约调用的可携带证据，包含原条款、可选后继、纳入及递归证明。交易体裁剪后
仍可验证，当前可花费性单独通过 State 检查。

## 合约实例

某 opening 下已出资的 `(slot_index, creation_id)`。即使条款相同，不同存款仍
有独立余额和计数器。
