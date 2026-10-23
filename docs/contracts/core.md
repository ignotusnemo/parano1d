# Integer core and ABI

Every ABI 3 contract uses the shared block relation. ABI **3** commits to a program
of **16 instructions**, two persistent unsigned 64-bit registers (`state0`,
`state1`), immutable authorization rules and recipient addresses. Each call
starts two scratch registers (`scratch0`, `scratch1`) at zero. No application
registration, per-application matrix or separate proof is required.

## Instructions

| Opcode | Effect on the selected destination |
| --- | --- |
| `keep` | Preserve its value |
| `move` | Copy the left operand |
| `add`, `subtract` | Checked unsigned addition or subtraction |
| `min`, `max` | Minimum or maximum of the operands |
| `less_than`, `equal` | Store Boolean 0 or 1 |
| `assert_equal`, `assert_less_or_equal` | Reject a false comparison; preserve the destination |

A failed assertion, overflow, underflow or non-Boolean predicate rejects the
call. There is no wraparound arithmetic. Instructions run in order; later
instructions see earlier writes. The final persistent pair becomes the next
state on a continuing call. A closing call still executes the program but
creates no successor.

Each instruction selects one destination from the four registers, two operands
and a predicate. Predicates are `always`, `before_deadline`, `terminal`,
`has_payout`, `scratch0` or `scratch1`; `inverted` negates the selected Boolean.
An inactive instruction leaves its destination unchanged. Unused trailing
instructions are canonical `keep` operations.

```json
{
  "opcode": "add",
  "destination": "state0",
  "left": "state0",
  "right": "one",
  "predicate": {"source": "terminal", "inverted": true},
  "immediate": "0"
}
```

This instruction counts continuing calls. It is an instruction example, not a
complete spending policy. [API integration](api.md) describes the required
explicit policy fields.

## Operands

| Group | Names |
| --- | --- |
| Registers | `state0`, `state1`, `scratch0`, `scratch1` |
| Constants | `immediate`, `zero`, `one` |
| Context | `height`, `fee`, `payout`, `retained`, `input_amount` |
| Flags | `before_deadline`, `after_deadline`, `terminal`, `has_payout` |
| Output-1 owner | `payout_owner0`, `payout_owner1`, `payout_owner2`, `payout_owner3` |
| Exact incarnation and slots | `input_creation_id`, `input_slot`, `retained_slot`, `payout_slot` |

`height` is the inclusion height. `before_deadline` means `height < deadline`;
`after_deadline` includes equality. There is no raw deadline operand: embed any
additional boundary as an instruction immediate. Owner words are four
little-endian u64 chunks of the canonical 32-byte owner commitment.

**The program context follows physical output positions.** `retained` and
`retained_slot` always refer to output 0; `payout`, `payout_slot` and owner words
refer to output 1. On a close, output 0 pays the closing recipient and output 1
is absent. Consequently, the core sees that closing amount as `retained` and
`payout = 0`, whereas the RPC's semantic call result reports the closing amount
as a payout and no retained contract balance. Branch on `terminal` when writing
a program that must distinguish these cases.

## Policy and commitment

The immutable policy contains claim and recovery authorities, claim and
recovery recipients, a deadline, fee ceiling, per-call payout ceiling,
minimum retained amount and five mode flags. Those flags separately permit
continuation and closing on each branch and optionally allow an arbitrary
recipient for a continuing payout. There is no implicit administrator.
See [lifecycle](lifecycle.md) for the exact branch and value rules.

Three domain-separated commitments bind program (`CNTCODE_`), policy
(`CNTPOL__`) and live object state (`CNTOBJ__`). The final 32-byte commitment
is encoded as the contract address. Changing either persistent counter changes
that address. A wallet groups related states by their immutable terms; this
local grouping is not a globally registered contract account.

The canonical public opening is **699 bytes**:

| Field | Bytes |
| --- | ---: |
| `NOIDOBJ3` magic + little-endian ABI version | 8 + 2 |
| 16 instruction descriptor/immediate pairs | 16 × 32 |
| Packed persistent state | 16 |
| Two authorities and two recipients | 4 × 32 |
| Deadline | 8 |
| Fee ceiling, reserve, payout ceiling and mode byte | 8 + 8 + 8 + 1 |

Each descriptor and immediate occupies a little-endian 128-bit field. A
descriptor uses 20 bits: opcode 4, destination 2, left 5, right 5, predicate 3,
inverted 1. Remaining bits must be zero; an immediate must fit u64. Persistent
state packs `state0` in the low 64 bits and `state1` in the high 64 bits.
Use the supplied encoder/API instead of inventing a serialization.

JSON represents counters and instruction immediates as **canonical decimal
strings**, including `"0"`, up to `"18446744073709551615"`. Leading zeroes,
signs and floating-point values are invalid. Other integer API fields retain
their documented numeric representation; clients must handle them losslessly.

## Scope

The core supports bounded, independently funded rights: budgets, delegated
spending, delayed access, recurring claims and staged release. It has no loops,
unbounded storage, cross-contract calls, network access or automatic timer.
Execution requires an authorized transaction. Each funded output has its own
counters; depositing twice does not create one shared budget.

Programs and policies cannot be upgraded in place. A permitted payout can move
value into new terms. New applications that fit this ABI need no new matrix;
adding new consensus operations can require a protocol upgrade. Application
logic must be tested for every permitted branch, including recovery and close.
