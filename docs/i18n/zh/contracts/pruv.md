# Pruv

Pruv 是 Parano1d 的 proof-native 合约语言。编译器将状态更新和明确的支出策略
编译为现有 ABI 3，由共同区块关系证明执行。符合此 ABI 限制的程序可以直接
使用现有节点，无需网络分叉或节点升级。

## 构建与参数

在仓库根目录运行：

```sh
cargo build --release --locked -p noid_pruv
target/release/pruv --help
```

可执行文件为 `pruv`，Windows 下为 `pruv.exe`。后置条件验证使用本地 Z3；
将 `z3` 加入 PATH，或通过 `--z3` 指定可执行文件路径。

预算示例位于 `noid_pruv/examples/budget.pruv`。创建 `budget.params.json`，
填写实际地址并选择未来的恢复区块高度：

```json
{
  "spending_key": "<支出钱包的 o1 地址>",
  "recovery_key": "<恢复钱包的 o1 地址>",
  "recipient": "<收款人的 o1 地址>",
  "recover_at": "<未来区块高度>",
  "budget": "10000000",
  "max_fee": "1000000",
  "max_payment": "1000000"
}
```

`u64` 参数使用规范十进制字符串；`bool` 使用 JSON 布尔值；地址使用 `o1…` 字符串。
重复、缺失、未知及类型不匹配的参数均会被拒绝。金额单位是整数 μNOID。
预算同时扣除支付金额与手续费；`max_fee` 和 `max_payment` 分别限制每次调用的
手续费与支付金额。节点计算实际手续费。

```sh
target/release/pruv check noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv verify noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv build noid_pruv/examples/budget.pruv --params budget.params.json --out budget.json
parano1d-cli contract create budget.json --out budget.opening.json
```

`check` 检查语法、类型、策略完整性及 ABI 资源限制。`verify` 通过 Z3 验证声明的
后置条件。`build` 执行源码与 ABI 检查，并输出现有 CLI/RPC 接受的 `custom_program`
定义。输出文件必须尚不存在；省略 `--out` 时输出到 stdout。

## 注资、调用与恢复

通过注资钱包的本地节点运行：

```sh
parano1d-cli contract protocol
parano1d-cli contract fund budget.opening.json 10
parano1d-cli contract instances budget.opening.json
```

CLI 金额单位为十进制 **NOID**；Pruv 参数与 RPC 使用整数 **μNOID**。
协议必须报告 ABI 3 和可用运行时。等待注资确认；每次独立注资都有自己的状态与余额。

在支出钱包的节点上导入公开条件，查询当前 `slot_index` 和 `creation_id`，并预览支付：

```sh
parano1d-cli contract watch budget.opening.json
parano1d-cli contract instances budget.opening.json
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <收款-o1-地址> --preview
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <收款-o1-地址> --expected-txid <预览-txid> --out call-1.json
```

检查权限、收款人、手续费、剩余金额和后继状态。CLI 在授权前保存预览，将其绑定到
确切高度与交易，等待确认，并保存 `call-1.receipt`。高度或交易变化时需要重新预览。
下次调用使用 `call-1.json` 中的后继状态，并重新查询当前实例：

```sh
parano1d-cli contract instances call-1.json
parano1d-cli contract verify call-1.receipt
```

截止高度之前，支出密钥可继续支付。到达截止高度后，恢复钱包可以关闭当前后继：

```sh
parano1d-cli contract watch call-1.json
parano1d-cli contract call call-1.json <后继-slot> <后继-creation-id> --close --preview
parano1d-cli contract call call-1.json <后继-slot> <后继-creation-id> --close --expected-txid <关闭-txid> --out closing.json
```

保存公开条件、后继文件与回执。旧区块正文被裁剪后，回执仍可验证历史调用；当前可支配
权利则根据 State 验证。参见[回执与恢复](receipts-and-recovery.md)。

## 语法与指令

一个文件包含一个 `contract`、一个 `policy` 块和一个 `call` 块。`param` 声明外部
参数；`const` 声明编译期值；`state` 声明持久化 `u64` 值。最多两个持久化寄存器，
按声明顺序分配；每次调用有两个初始为零的临时寄存器。

```text
call {
    when !terminal {
        require payout <= remaining;
        remaining -= payout + fee;
        calls += 1;
    }
}
ensures remaining <= old(remaining);
ensures calls >= old(calls);
```

赋值按源码顺序执行。`when` 在进入时只计算一次条件，嵌套块保留父条件；跳过的分支
不执行算术。`require` 生成原生断言，条件为假时调用被拒绝。`+` 与 `-` 使用检查边界
的 u64 运算，溢出或下溢会拒绝调用；无效的常量运算在编译时被拒绝。

| Pruv | 原生操作 |
| --- | --- |
| `x = value` | `move` |
| `a + b`, `a - b` | `add`, `subtract` |
| `min(a, b)`, `max(a, b)` | `min`, `max` |
| `<`, `>` | `less_than`；`>` 交换操作数 |
| `==` | `equal` |
| `!=`, `<=`, `>=`, `!` | 比较与布尔取反 |
| `require a == b` | `assert_equal` |
| `require a <= b`, `require a >= b` | `assert_less_or_equal` |
| 未使用的尾部指令槽 | 规范 `keep` |

一条源码语句可能需要多条原生指令。上限为 16 条指令、两个持久化寄存器和两个临时
寄存器；计算条件和嵌套条件也占用临时寄存器。超出限制会在编译时被拒绝。
源码和参数文件最多 64 KiB；源码还限制为 8192 个 token 和 64 层嵌套。

预算示例使用三条指令。`noid_pruv/examples/instructions.pruv` 使用 13 条指令及
`keep` 填充，覆盖全部十种 ABI 操作。

## 上下文与策略

数值上下文包括 `height`、`fee`、`payout`、`retained`、`input_amount`、
`input_creation_id`、`input_slot`、`retained_slot`、`payout_slot`，以及
`payout_owner0` 至 `payout_owner3`。布尔标志为 `before_deadline`、
`after_deadline`、`terminal`、`has_payout`。

`height` 是包含高度。`before_deadline` 表示 `height < deadline_height`；
相等时已进入恢复分支。上下文对应实际输出位置：关闭时输出 0 是关闭支付，
`retained` 为其金额，`payout = 0`。预算示例的 `when !terminal` 允许在继续调用
会溢出或耗尽预算时仍可按策略恢复。

所有策略字段必须明确填写。具体权限、收款人和分支语义见 [API](api.md) 与
[整数内核](core.md)。

## 后置条件验证

`ensures` 是本地验证器对编译后程序检查的规格；`old(name)` 表示调用开始时的状态。
网络执行编译后的指令和 `require` 检查。

```sh
target/release/pruv smt noid_pruv/examples/budget.pruv --params budget.params.json --out budget.smt2
z3 budget.smt2
```

预期答案先为 `sat`，再为 `unsat`。第一个答案确认存在成功的整数执行；第二个答案
在 Z3 QF_BV 语义及编码的 ABI 3 指令语义下，确认每次成功执行都满足全部声明的后置条件。

输入状态与数值上下文为任意 u64；临时寄存器初始为零。槽索引限制为 u32，标志为布尔值，
截止标志由高度计算。模型包含谓词、断言失败及算术拒绝；后置条件中的算术也须保持 u64 边界。

这是每次调用的性质。所有可达状态的不变量还需要初始状态论证和归纳保持。应用检查也包含
明确策略、允许分支与收款人。源码到指令的对应关系通过现有原生解释器进行差分测试。

对于预算示例，初始 `remaining = budget` 与每次保持
`remaining <= old(remaining)` 可推出任意次成功的继续调用之后都有
`remaining <= budget`，条件是每个转换使用相同程序及经过认证的后继状态。
带边界检查的 `remaining -= payout + fee` 还意味着，这些调用的剩余预算、
累计支付和累计费用之和始终等于初始预算。恢复分支关闭实例，其最终输出由单独承诺的
支出策略决定。完整的生命周期论证涵盖初始化、所有允许转换及关闭。

反例、不可执行程序、不完整回答、求解器错误和超时均会导致验证失败。
每个 Z3 查询限制 10 秒，进程限制 30 秒。


类型化的代币、交易和 NFT 请求见[原生金融模板](native-templates.md)。
