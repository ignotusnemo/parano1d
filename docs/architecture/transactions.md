# Transaction architecture

Parano1d separates the physical transaction page carried by a block from the
logical payment authorized by a wallet.

The physical record is `Tx8x2`: at most eight inputs and two outputs in a
fixed 323-byte encoding. A logical `PagedSpend` joins up to 128 of those pages
into one atomic intent with one transaction ID and one authorization capsule.

| Layer | Limit | Purpose |
|---|---:|---|
| `Tx8x2` page | 8 inputs, 2 outputs | Fixed consensus and proof record |
| `PagedSpend` | 128 pages | One atomic wallet operation |
| Active logical transaction | 504 inputs, class page budget | Must fit the selected proof class |

Admission checks the complete intent against Small (63 pages) or Large
(206 pages), with 504 live inputs per block. The 128-page ordinary group
limit also applies. See [combined limits](../protocol/parameters.md).

## Fixed physical pages

Each page has one shared `input_owner`, an epoch anchor, a fee field, eight
input records, two output records and a validity bitmap. Dead records must be
canonical zeroes.

An input identifies:

```text
{slot_index, amount, creation_id}
```

An output identifies:

```text
{slot_index, amount, owner}
```

The allocator supplies a fresh `creation_id` when the output is materialized.
This prevents a stale input reference from becoming valid if its numerical
slot is later reused.

## One logical intent

The first page carries the fee and start marker. The final page carries the end
marker. Every page uses the same owner and epoch anchor, and live records must
be densely packed. Page count must be minimal for the declared inputs and
outputs.

The logical transaction ID commits to:

- protocol version;
- page count;
- every ordered physical page hash.

It is computed with a domain-separated Poseidon2b sponge. The wallet
authorization is bound to this logical ID rather than to any one page.

The entire group is admitted, selected, proved and included atomically. A miner
cannot include only the profitable pages of a larger spend.

## Wallet construction

For a normal payment, the wallet spends outputs of the active owner. It chooses
largest values first to reduce the number of proof inputs, creates the recipient
output, and returns any change to the same active owner. Output slots come from
node-provided empty-slot hints.

Construction has two proof boundaries:

1. the wallet proves knowledge of the active owner's secret;
2. the miner proves current input membership, output emptiness, value
   conservation, fee rules and the exact post-State.

The wallet proof runs outside the wallet-state lock. Mining may continue, but
the node gives local transaction work priority so a user is not forced to wait
behind continuous proving.

## Mempool admission

Admission deliberately repeats the cheap checks around expensive proof
verification:

1. decode canonical wire data and validate group semantics;
2. under the mempool lock, check fee, epoch, conflicts and the current State;
3. release the lock and verify the authorization capsule under a bounded CPU
   permit;
4. reacquire the lock and repeat the cheap State and conflict checks;
5. reserve every live input and output slot, then relay the intent.

Both cheap passes check the candidate height's class budgets. This closes the
race between authorization verification and a new block, fork boundary or
competing transaction. Duplicate submission is idempotent.

The mempool holds at most 1,024 logical transactions and 384 MiB of intent
data. Slot reservations make conflicting-input and output detection constant
time.

## Selection

Miners order admissible atomic groups by fee rate, breaking ties by transaction
ID. Small and Large enforce their own page limits, plus 504 live inputs,
63 calls and 256 touched segments. Calls form the canonical user-page prefix.
The primary coinbase is separate; a due extra system page reduces user capacity
by one. [Class selection](mining.md#small-large-and-native) is a local production
choice; every verifier accepts either class under the same contract semantics.

## Confirmation and receipts

Submission means the local node accepted and relayed the complete intent. It
does not mean a block has included it. Once included and confirmed, the wallet
can recover a receipt from the retained block.

Same-owner consolidation is intentionally omitted from receipts. Payments to
any distinct owner, including another inactive address derived by the same
wallet, are retained as outgoing payment evidence.

For normative validity rules, see
[Transaction protocol](../protocol/transactions.md). For user-facing behavior,
see [Send NOID](../wallet/send.md).

## Contract intent

A contract intent carries public program and policy terms plus one call page.
The wallet authorizes the branch selected at inclusion height; the miner
proves the opening, program and exact successor. Fees, conflicts and budgets
are checked during both admission passes. See [contracts](../contracts/index.md).
