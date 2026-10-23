# Addresses

The wallet derives indexed addresses from one master secret. Address `0` is
created during setup and named **Main**. Further addresses can be generated
from the Addresses dialog.

![Address book and active-owner selection](../assets/wallet/addresses.png)

## Open the address book

On Main, select **Switch** beside the active address. The table shows:

- derivation index;
- local label;
- address;
- whether the address is active.

Labels are stored locally and are not part of consensus.

## Create an address

Select **New address**. The next derivation index is created and added to the
wallet. A new address is inactive until selected explicitly.

Copy an address with the control beside it. Parano1d addresses use the
bech32m `o1…` display form; use the complete string.

## Change the active address

Choose **Use** for an inactive row. The active address determines:

- which owner's UTXOs a new payment can spend;
- where payment change returns;
- the default internal-mining payout.

Switching is blocked while the wallet has a local send, consolidation or
activation operation in progress. This prevents a completed proof from being
presented under a different UI owner.

Existing mining work keeps the payout embedded in its immutable template.
New templates use the newly active address.

## Restored addresses

After master-secret import, automatic discovery tests addresses sequentially.
It adds a contiguous funded prefix and stops at the first empty address, with a
maximum of 20 candidates per import.

This is intentionally bounded. The node does not search every possible derived
address or store an index for someone else's wallet.

## Sending to another wallet address

A payment from the active owner to one of the wallet's inactive addresses is a
real different-owner payment. It receives a normal receipt.

Consolidation is different: it spends and returns value to the same active
owner, so no payment receipt is created.
