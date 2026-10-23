# Pruv

Pruv is a language for proof-native contracts. It compiles a contract's
state updates and spending policy into the existing ABI 3. Nodes execute and
prove the resulting program through the shared block relation.

The compiler is a separate developer tool. Its output works with the existing
contract CLI and RPC. ABI 3 provides 16 instructions, two persistent u64
registers and two scratch registers. Pruv checks these limits during compilation.

## Build and use

From the repository root:

```sh
cargo build --release --locked -p noid_pruv
target/release/pruv check noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv verify noid_pruv/examples/budget.pruv --params budget.params.json
target/release/pruv build noid_pruv/examples/budget.pruv --params budget.params.json --out budget.json
parano1d-cli contract create budget.json --out budget.opening.json
```

`check` validates syntax, types, policy fields and native resource limits.
`verify` checks declared postconditions with a local Z3 executable. `build`
exports a `custom_program` definition; it performs the same checks as `check`.
Output files must be new. Omit `--out` to write to stdout.

Parameters are a JSON object. Addresses use the ordinary `o1…` format. Every
u64 parameter is a canonical decimal string, including heights and amounts.
Bool parameters use JSON `true` or `false`. Duplicate, missing and unknown parameters are
errors. For the budget example, provide:

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

Amounts are integer μNOID. Each separately funded instance has its own state
and budget. The example debits both the payout and its fee from `remaining`.
Before the deadline, the spending key can continue; afterwards, the recovery
key can close. Closing follows ABI 3's physical output convention: `retained`
is output 0 and `payout` is output 1, so a close has `payout = 0`.

## Fund, call and recover

Run creation and funding through the funding wallet's local node. The CLI
uses decimal **NOID**, while Pruv parameters and RPC use integer **μNOID**.

```sh
parano1d-cli contract protocol
parano1d-cli contract fund budget.opening.json 10
parano1d-cli contract instances budget.opening.json
```

The runtime must be available and report ABI 3. Wait for funding confirmation.
Use the exact current `slot_index` and `creation_id` from `instances`.
The fee ceiling is a limit on each call; the node calculates the actual fee.
Each funded instance has its own counters and balance.

On the spending wallet's node, watch the public opening and review a payout:

```sh
parano1d-cli contract watch budget.opening.json
parano1d-cli contract instances budget.opening.json
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <recipient-o1-address> --preview
```

Inspect authority, fee, payout, retained amount and successor. Submit with the
reviewed transaction ID:

```sh
parano1d-cli contract call budget.opening.json <slot> <creation-id> --pay 0.1 --pay-to <recipient-o1-address> --expected-txid <reviewed-txid> --out call-1.json
```

The CLI binds the review to the exact height and transaction, saves it before
authorization, waits for confirmation, and writes `call-1.receipt`. A changed
height or transaction requires a fresh review. For another call, use the
successor in `call-1.json` and discover its current instance again:

```sh
parano1d-cli contract instances call-1.json
parano1d-cli contract verify call-1.receipt
```

At the deadline, the recovery wallet can close that current successor:

```sh
parano1d-cli contract watch call-1.json
parano1d-cli contract call call-1.json <successor-slot> <successor-creation-id> --close --preview
parano1d-cli contract call call-1.json <successor-slot> <successor-creation-id> --close --expected-txid <reviewed-close-txid> --out closing.json
```

Keep public terms, successor files and receipts. Receipts authenticate historical
calls after block bodies have been pruned; current spendable rights are checked
against State. See [receipts and recovery](receipts-and-recovery.md).

## Language

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

The complete source is `noid_pruv/examples/budget.pruv` in the repository.

- `param` declares an external `u64`, `bool` or `address` binding.
- `const` declares a compile-time value. Constants can use parameters and earlier
  constants. Initial state and policy expressions also use compile-time values.
- `state` declares up to two persistent u64 values, in register order. Unused
  persistent registers start at zero and remain untouched.
- Assignments run in source order. `+=` and `-=` update the selected state value.
- `+` and `-` use checked u64 arithmetic. Overflow or underflow rejects the call.
  Constant overflow and underflow are compile errors.
- `min(a, b)` and `max(a, b)` return u64 values. Comparisons `==`, `!=`, `<`,
  `<=`, `>` and `>=` return bool. `!` negates a bool.
- `when condition { ... }` evaluates its condition once on entry. Nested blocks
  run only when their enclosing conditions hold. Skipped arithmetic is inactive.
- `require condition;` adds a native runtime assertion. A false assertion rejects
  the call.
- `ensures condition;` declares a postcondition for `pruv verify`. `old(name)`
  refers to that state variable at call entry. Postconditions are verification
  specifications stored in the source.

Read-only context names are `height`, `fee`, `payout`, `retained`, `input_amount`,
`before_deadline`, `after_deadline`, `terminal`, `has_payout`, `input_creation_id`,
`input_slot`, `retained_slot`, `payout_slot` and `payout_owner0` through
`payout_owner3`. Deadlines use inclusion height: `before_deadline` is
`height < deadline_height`.

Parameters, constants and state variables have distinct names. Context names,
keywords and raw register names are reserved. Source files are bounded to
64 KiB, 8192 tokens and 64 levels of nesting. Expressions and conditions also
have to fit the native scratch and instruction budgets. Functions, loops and
cross-contract calls are outside this grammar.

The policy fields and native output conventions are described in
[the contract API](api.md) and [the integer core](core.md).

## Native instructions

| Pruv expression | Native operation |
| --- | --- |
| `x = value` | `move` |
| `a + b`, `a - b` | `add`, `subtract` |
| `min(a, b)`, `max(a, b)` | `min`, `max` |
| `<`, `>` | `less_than`, swapping operands for `>` |
| `==` | `equal` |
| `!=`, `<=`, `>=`, Boolean `!` | comparison and Boolean inversion |
| `require a == b` | `assert_equal` |
| `require a <= b`, `require a >= b` | `assert_less_or_equal` |
| Trailing unused instruction slots | canonical `keep` |

One source statement can require several native instructions. Computed and
nested conditions also use scratch registers. The compiler rejects a program
that exceeds 16 instructions or two scratch registers.

`noid_pruv/examples/instructions.pruv` compiles to 13 instructions and padding,
covering all ten native opcodes. It exercises arithmetic, comparisons, guard
snapshots and instruction order. The budget example uses three instructions.

## Postcondition verification

Install Z3 and make `z3` available on PATH, or pass `--z3 /path/to/z3`.
To inspect or independently run the exact query:

```sh
target/release/pruv smt noid_pruv/examples/budget.pruv --params budget.params.json --out budget.smt2
z3 budget.smt2
```

The expected answers are `sat` and `unsat`. The first establishes that a
successful integer execution exists. The second establishes that every
successful integer execution satisfies all declared postconditions, under
Z3's QF_BV semantics and the encoded ABI 3 instruction semantics.

The model quantifies over arbitrary incoming u64 state and context values,
with zero-initialized scratch registers, Boolean flags, u32 slot indices and
deadline flags derived from height. It includes native instruction predicates,
assertion failures, overflow and underflow. Arithmetic inside a postcondition
must also stay within u64 bounds.

This is a per-call property over the compiled integer program. For example,
`remaining <= old(remaining)` holds for the budget's successful calls. A bound
on all reachable states additionally requires an initial-state argument and
inductive preservation. Application verification must also cover the spending
policy, allowed branches and intended recipients. Source-to-instruction
correspondence is exercised against the native interpreter in the test suite.

For the budget example, an initial `remaining = budget` and preservation of
`remaining <= old(remaining)` establish `remaining <= budget` after any number
of successful continuing calls, provided each transition uses the same program
and the authenticated successor state. The checked subtraction
`remaining -= payout + fee` also gives
`remaining + cumulative payouts + cumulative fees = initial budget` across
those calls. Recovery closes the instance; its final output follows the
separately committed spending policy. A complete lifecycle argument covers
initialization, every allowed transition and closing.

The verifier accepts only conclusive results. Counterexamples, infeasible
programs, missing Z3, solver errors and timeouts fail verification. Each query
has a 10-second solver limit, with a 30-second process wall limit.

## Tests

```sh
cargo test -p noid_pruv
PRUV_TEST_Z3=/path/to/z3 cargo test -p noid_pruv -- --include-ignored
```

Tests compare source execution with the existing native interpreter across
u64 boundaries and branch combinations. Solver tests include valid properties,
deliberately false properties and infeasible programs.


For typed token, trading and NFT requests, see [native financial templates](native-templates.md).
