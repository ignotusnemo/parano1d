# Send NOID

The Send flow builds one atomic `PagedSpend`, forges a fresh authorization
proof and submits it to the local node.

## Before sending

Wait until the header reports **ONLINE**. Confirm that the active address is
the owner whose UTXOs you intend to spend.

Open **F1 → Main → Send**, then enter:

- the recipient's complete `o1…` address;
- the amount in NOID.

The wallet obtains current empty-slot hints and an exact fee quote. It selects
the active address's largest UTXOs first, which normally reduces input count
and proof work.

## Review

The review shows:

- selected input count and value;
- recipient output;
- change output when required;
- network fee;
- resulting active-owner balance.

The fee quote includes base, input, output and any State-growth component.
Creating one net-new UTXO costs more as State occupancy rises. A voluntary fee
above minimum is miner-claimable.

Auto includes the current local relay floor as well as the consensus minimum.
A fee rejection before local admission can trigger a fresh Auto calculation
and proof within the existing three-attempt submission limit. Explicit fees
are not silently raised. The final panel reports the submitted fee.

See [Fees](../protocol/economics.md#fees) for State-occupancy multipliers and
the local mempool pressure policy.

## Forge and submit

Choose **Proof & Send**. The dialog locks and displays the forging animation
while the wallet:

1. binds all ordered physical pages into one logical transaction ID;
2. proves knowledge of the active owner's secret for that ID;
3. submits the complete intent to its local mempool.

If internal mining is active, local transaction proving receives CPU priority.
Mining resumes after submission. This priority is local to the wallet and does
not change network or consensus behavior.

## Final panel

A successful final panel means the complete intent was accepted by the local
node and submitted to the network. It shows the logical transaction ID, amount,
fee, inputs and outputs.

Confirmation follows when a canonical block includes the transaction. You may
leave the panel immediately; the node continues tracking the mempool and
canonical chain.

When a canonical block confirms the payment, the wallet recovers and stores
its receipt. The payment then appears under **Receipts**.

## Failure cases

The wallet can refuse or abandon a send when:

- the address is invalid;
- amount plus fee exceeds active-owner balance;
- selected inputs exceed the active limit: 504 inputs;
- no current output-slot hints are available;
- the transaction epoch changes during construction;
- an input is spent by a newly accepted block;
- authorization construction fails;
- the local node rejects or cannot relay the intent.

No balance is reserved on-chain merely because the review opened. If the final
submission fails, refresh current State and build the payment again.

## Privacy

The authorization hides the spending secret, not the public payment. Recipient,
amount, input owner, slots and fee are transparent.
