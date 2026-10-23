# Pruv

Pruv 是 proof-native 合约语言，将合约状态更新和支出策略编译到现有 ABI 3。节点通过共享区块关系执行并证明生成的程序。

编译器是独立开发工具，其输出配合现有合约 CLI 与 RPC 使用。ABI 3 提供 16 条指令、两个持久化 u64 寄存器和两个临时寄存器。Pruv 在编译时检查这些限制。

<a id="build-and-use"></a>
## 构建与使用

从仓库根目录运行：

```sh
cargo build --release --locked -p noid_pruv
target/release/pruv check noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv verify noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv build noid_pruv/examples/budget.pruv --params budget.params.json --out budget.json
parano1d-cli contract create budget.json --out budget.opening.json
```

`check` 验证语法、类型、策略字段和原生资源限制。`verify` 使用本地 Z3 检查声明的后置条件。`build` 导出 `custom_program` 定义，并执行与 `check` 相同的检查。输出文件必须为新文件，省略 `--out` 时写入 stdout。

参数为 JSON 对象，地址使用普通 `o1…` 格式。所有 u64 参数都采用规范十进制字符串，包括高度和金额。bool 参数使用 JSON `true` 或 `false`。重复、缺失和未知参数会导致错误。预算示例参数为：

```json
{
  "spending_key": "<spending wallet o1 address>",
  "recovery_key": "<recovery wallet o1 address>",
  "recipient": "<recipient o1 address>",
  "recover_at": "<future block height>",
  "budget": "10000000",
  "max_fee": "1000000",
  "max_payment": "1000000"
}
```

金额以整数 μNOID 计。每个独立注资实例拥有自己的状态和预算。示例从 `remaining` 同时扣除支付与费用。截止高度前支出密钥可继续，之后恢复密钥可关闭。关闭遵循 ABI 3 的物理输出约定，`retained` 是输出 0，`payout` 是输出 1，因此关闭时 `payout = 0`。

<a id="fund-call-and-recover"></a>
## 注资、调用与恢复

通过注资钱包的本地节点创建并注资。CLI 使用十进制 **NOID**，Pruv 参数和 RPC 使用整数 **μNOID**。

```sh
parano1d-cli contract protocol
parano1d-cli contract fund budget.opening.json 10
parano1d-cli contract instances budget.opening.json
```

运行时应可用并报告 ABI 3。等待注资确认，再采用 `instances` 返回的确切当前 `slot_index` 和 `creation_id`。费用上限针对每次调用，节点计算实际费用。每个注资实例拥有自己的计数器和余额。

在支出钱包节点观察公开开口并审核支付：

```sh
parano1d-cli contract watch budget.opening.json
parano1d-cli contract instances budget.opening.json
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <recipient-o1-address> --preview
```

检查权限、费用、支付、保留金额和后继，使用已审核交易 ID 提交：

```sh
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <recipient-o1-address> --expected-txid <reviewed-txid> --out call-1.json
```

CLI 将审核绑定到确切高度和交易，在授权前保存审核，等待确认并写入 `call-1.receipt`。高度或交易改变后需要重新审核。下一次调用使用 `call-1.json` 中的后继，并重新发现其当前实例：

```sh
parano1d-cli contract instances call-1.json
parano1d-cli contract verify call-1.receipt
```

到达截止高度后，恢复钱包可以关闭该当前后继：

```sh
parano1d-cli contract watch call-1.json
parano1d-cli contract call call-1.json <successor-slot> <successor-creation-id> --close --preview
parano1d-cli contract call call-1.json <successor-slot> <successor-creation-id> --close --expected-txid <reviewed-close-txid> --out closing.json
```

保存公开条款、后继文件和收据。区块体剪枝后，收据仍认证历史调用，当前可花费权利依据 State 检查。详见[收据与恢复](receipts-and-recovery.md)。

<a id="language"></a>
## 语言

```text
contract Name {
    param amount: u64;
    const limit: u64 = amount + 1;
    state remaining: u64 = limit;
    state calls: u64 = 0;

    policy {
        // All policy fields are explicit; see examples/budget.pruv.
    }

    call {
        when !terminal {
            require payout <= remaining;
            remaining -= payout + fee;
            calls += 1;
        }
    }

    ensures remaining <= old(remaining);
}
```

完整源码位于仓库的 `noid_pruv/examples/budget.pruv`。

- `param` 声明外部 `u64`、`bool` 或 `address` 绑定。
- `const` 声明编译期值，可使用参数和先前常量。初始状态与策略表达式也使用编译期值。
- `state` 按寄存器顺序声明最多两个持久化 u64 值。未使用的持久化寄存器从零开始并保持零。
- 赋值按源码顺序执行，`+=` 和 `-=` 更新指定状态值。
- `+` 和 `-` 使用受检查的 u64 算术。上溢或下溢拒绝调用，常量中的此类错误在编译时拒绝。
- `min(a, b)` 与 `max(a, b)` 返回 u64。`==`、`!=`、`<`、`<=`、`>` 和 `>=` 比较返回 bool，`!` 反转 bool。
- `when condition { ... }` 在进入时计算一次条件。嵌套块在其外层条件成立时执行，跳过分支的算术不生效。
- `require condition;` 添加原生运行时断言，断言为假则拒绝调用。
- `ensures condition;` 为 `pruv verify` 声明后置条件。`old(name)` 表示调用入口时的状态变量值。后置条件作为验证规范保存在源码中。

只读上下文名称为 `height`、`fee`、`payout`、`retained`、`input_amount`、`before_deadline`、`after_deadline`、`terminal`、`has_payout`、`input_creation_id`、`input_slot`、`retained_slot`、`payout_slot` 以及 `payout_owner0` 到 `payout_owner3`。期限采用纳入高度，`before_deadline` 表示 `height < deadline_height`。

参数、常量和状态变量使用不同名称。上下文名称、关键字和原始寄存器名称为保留名称。源码上限为 64 KiB、8192 个 token 和 64 层嵌套。表达式与条件同时受原生临时寄存器及指令预算约束。语法提供合约声明、顺序指令和条件块。

策略字段与原生输出约定见[合约 API](api.md) 和[整数核心](core.md)。

<a id="native-instructions"></a>
## 原生指令

| Pruv 表达式 | 原生操作 |
| --- | --- |
| `x = value` | `move` |
| `a + b`、`a - b` | `add`、`subtract` |
| `min(a, b)`、`max(a, b)` | `min`、`max` |
| `<`、`>` | `less_than`，`>` 交换操作数 |
| `==` | `equal` |
| `!=`、`<=`、`>=`、布尔 `!` | 比较与布尔取反 |
| `require a == b` | `assert_equal` |
| `require a <= b`、`require a >= b` | `assert_less_or_equal` |
| 未使用的尾部指令槽 | 规范 `keep` |

一条源码语句可能需要多条原生指令，计算条件和嵌套条件也占用临时寄存器。超出 16 条指令或两个临时寄存器的程序会被编译器拒绝。

`noid_pruv/examples/instructions.pruv` 编译为 13 条指令及填充，覆盖全部十种原生操作码，涉及算术、比较、条件快照和指令顺序。预算示例使用三条指令。

<a id="postcondition-verification"></a>
## 后置条件验证

安装 Z3 并将 `z3` 放入 PATH，或传入 `--z3 /path/to/z3`。查看或独立运行精确查询：

```sh
target/release/pruv smt noid_pruv/examples/budget.pruv --params budget.params.json --out budget.smt2
z3 budget.smt2
```

预期回答为 `sat` 和 `unsat`。第一个建立成功整数执行的存在性，第二个在 Z3 的 QF_BV 语义与编码后的 ABI 3 指令语义下，建立每次成功整数执行都满足全部声明后置条件。

模型覆盖任意输入 u64 状态和上下文、零初始化临时寄存器、布尔标志、u32 槽位索引，以及由高度计算的期限标志，并包含原生指令谓词、断言失败、上溢和下溢。后置条件中的算术同样须处于 u64 范围内。

该性质针对编译后整数程序的一次调用。例如预算的成功调用满足 `remaining <= old(remaining)`。全部可达状态的边界还需初始状态论证和归纳保持。应用验证也应覆盖支出策略、允许分支和预期接收者。测试通过与原生解释器比较检查源码到指令的对应关系。

预算示例从 `remaining = budget` 开始，若每次转换采用相同程序和认证后继状态，并保持 `remaining <= old(remaining)`，则任意次成功继续调用后均有 `remaining <= budget`。受检查减法 `remaining -= payout + fee` 还建立这些调用中的 `remaining + cumulative payouts + cumulative fees = initial budget`。恢复关闭实例，最终输出由独立承诺的支出策略决定。完整生命周期论证覆盖初始化、每个允许转换和关闭。

验证器接受确定结果。反例、不可执行程序、缺少 Z3、求解器错误和超时均使验证失败。每个查询的求解器上限为 10 秒，进程总时间上限为 30 秒。

<a id="tests"></a>
## 测试

```sh
cargo test -p noid_pruv
PRUV_TEST_Z3=/path/to/z3 cargo test -p noid_pruv -- --include-ignored
```

测试在 u64 边界和分支组合下比较源码执行与现有原生解释器。求解器测试包含成立性质、刻意错误性质和不可执行程序。

类型化代币、交易与 NFT 请求见[原生金融模板](native-templates.md)。
