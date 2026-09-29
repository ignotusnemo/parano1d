# Contract API and application integration

Contract operations use the existing local JSON-RPC endpoint and the
`paranoid_` prefix. Parameters are positional arrays. All contract methods
require **local owner scope**; neither a mining token nor the operator token
adds contract authority. See [RPC authentication](../reference/rpc.md#authentication).

## Protocol discovery

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_getContractProtocol",
  "params": []
}
```

The response contains `tip_height`, `activation_height`, `active_at_next_block`,
`runtime_available`, `next_block_time_seconds`, `abi_version`, `instructions`,
`persistent_registers` and `classes`. Each class gives `class`, `pages`,
`live_inputs`, `contract_calls`. The v2 values are ABI 3, 16 instructions,
2 persistent registers, Small 63/504/63 and Large 206/504/63.

Mainnet v2 rules start at **H210537**. The new binary can prepare public terms,
watch openings and read local metadata before that height. Funding, previews
and calls require both activation at the **next candidate height** and an
available authenticated v2 runtime. A pre-v2 binary does not expose these methods.

## Methods

| Method suffix | Positional parameters | Result |
| --- | --- | --- |
| `getContractProtocol` | `[]` | `ObjectProtocolInfo` |
| `createObject` | `[definition]` | `ObjectInfo` |
| `getObjectStatus` | `[opening_hex, slot_index]` | `ObjectStatus` |
| `getObjectInstances` | `[opening_hex, from_slot, limit]` | `ObjectInstances` |
| `previewObjectCall` | `[request]` | `ObjectCallPreview` |
| `walletFundObject` | `[opening_hex, amount_micronoid, fee_micronoid, expected_sender?]` | `WalletSendResult` |
| `walletCallObject` | `[request]` | `ObjectCallResult` |
| `walletGetObjectOpening` | `[address]` | `ObjectInfo` |
| `walletWatchObject` | `[opening_hex]` | `ObjectInfo` |
| `walletListObjectStates` | `[opening_hex, after_root, limit]` | `ObjectKnownStates` |
| `walletListObjectReceipts` | `[opening_hex, after_cursor, limit]` | `ObjectActivityPage` |
| `exportObjectReceipt` | `[opening_hex, txid]` | `hex` |
| `verifyObjectReceipt` | `[receipt_hex]` | `ObjectReceiptResult` |
| `walletImportObjectReceipt` | `[receipt_hex, expected_opening_hex?]` | `ObjectReceiptResult` |

`createObject` encodes and validates public terms; it does not broadcast or
charge a fee. Save its returned opening. `walletWatchObject` retains terms for
future observation. `walletGetObjectOpening` restores locally retained terms,
not arbitrary preimages from a chain hash.

`getObjectStatus` checks one slot against an opening. Clients must also compare
its `creation_id` with the intended instance. `getObjectInstances` scans current
State for that exact commitment: `from_slot` is inclusive, `limit` is 1–256,
and `next_slot` is the next inclusive cursor or null. Results identify their
`height` and `tip_hash`; restart a multi-page snapshot if the tip changes.

`walletListObjectStates` lists locally known states with the same immutable
terms and a freshly checked `has_balance`. It uses an exclusive `after_root`
cursor, initially null, and limit 1–64. `walletListObjectReceipts` lists retained
calls of both parties, newest first, with an exclusive `after_cursor`, initially
null, and limit 1–64. Its `canonical` flag is separate from local retention.
Neither endpoint reconstructs a complete global history.

## Definitions and amounts

Definitions have a `kind` discriminator and reject unknown fields. Amounts are
integer μNOID; heights and periods are block counts. Constructor fields are:

| `kind` | Fields |
| --- | --- |
| `refundable_payment` | `payer`, `payee`, `expiry_height`, `max_fee_micronoid` |
| `timelocked_vault` | `owner`, `unlock_height`, `max_fee_micronoid` |
| `allowance_wallet` | `spending_key`, `recovery_key`, `payout_recipient`, `recover_at`, `max_fee_micronoid`, `max_payout_micronoid`, `min_retained_micronoid` |
| `period_budget_wallet` | Allowance + `start_height`, `period_blocks`, `budget_micronoid` |
| `recurring_payment` | `payer`, `payee`, `first_due_height`, `period_blocks`, `payment_micronoid`, `recover_at`, `max_fee_micronoid` |
| `tranche_vesting` | `beneficiary`, `first_unlock_height`, `period_blocks`, `tranche_micronoid`, `mature_at`, `max_fee_micronoid` |
| `custom_program` | `definition` |
| `custom` | `opening_hex` |

In the table, “Allowance +” means every `allowance_wallet` field plus the three
listed fields. Optional `payout_recipient` may be null. See [templates](templates.md)
for branch behavior, reserves and period boundaries.

`custom_program.definition` requires `state`, `program`, `claim_authority`,
`recovery_authority`, `claim_recipient`, `recovery_recipient`, `deadline_height`,
`max_fee_micronoid`, `max_payout_micronoid`, `min_retained_micronoid`,
`claim_can_continue`, `claim_can_close`, `recovery_can_continue`,
`recovery_can_close` and `unrestricted_payout_recipient`. There are no implicit
permissions. `state` is exactly two canonical decimal u64 strings. `program`
contains at most 16 [instructions](core.md); trailing steps are padded.
`custom` validates an already encoded opening using the same ABI.

`ObjectInfo` returns those policy fields together with `abi_version`, `address`,
`opening_hex`, `code_id`, `state_hex`, the two state strings and all 16 decoded
instructions. `opening_hex` encodes 699 bytes. Addresses are canonical `o1…`.
Treat u64 amounts and heights losslessly; browser `Number` cannot represent all
u64 values. Counter and instruction-immediate strings must not be converted
through floating point.

## Review, then submit

A call request requires `opening_hex`, `slot_index`, **`creation_id`**,
`terminal`, `payout` and `fee_micronoid`. `payout` is null or
`{address, amount_micronoid}`; closing requires null. Zero fee asks for the
current required minimum, still constrained by the policy fee ceiling.
Fees come from the contract input, not a separate wallet input.

1. Discover and choose an exact live instance.
2. Send the request to `previewObjectCall`. Inspect `txid`, `call_height`,
   `authority`, `recovery`, `terminal`, fee, retained balance, payout and successor.
3. Preserve that review. Bind it with `expected_txid`, `expected_call_height`,
   `expected_authority` and `expected_recovery` when calling `walletCallObject`.
   A mismatch requires a new review; never edit an authorized body silently.
4. Record the returned `transaction.txid`, `call_height`, `successor` and
   `output_slot`. This response is submission, not confirmation.
5. Track inclusion, then export the receipt and share successor terms as needed.

For funding, `expected_sender` optionally guards the active wallet address.
Funding uses an ordinary payment and can create multiple independent instances
of the same opening. If a response is lost, query the reviewed transaction ID
before resubmitting: an RPC timeout does not prove that submission failed.

`getTx` can retain an index pointer after bodies are pruned. That pointer is not
a body or a proof of current unspentness. Use receipts for retained call evidence
and State queries for current balances.

## Indexing public calls

An indexer can read pending transaction IDs from `getMempoolInfo`, then call
`getMempoolEntry(txid)` for each one. A pending contract call includes its
canonical 699-byte `contract_opening_hex`; ordinary payments return `null` in
that field. `getBlockDetails(height)` marks retained transactions with
`contract: "call"`, `"close"` or `null`. See the [RPC reference](../reference/rpc.md).

Capture an opening while its call is pending. The block carries the contract
flags, but it does not preserve the opening for later RPC retrieval. A missed
mempool interval cannot be reconstructed from State or a pruned block body.

## Receipt results and bounds

A verified or imported receipt returns `valid` plus `height`, `txid`, `terminal`,
`authority`, `original`, optional `successor`, `input_micronoid`,
`fee_micronoid`, `retained_micronoid` and optional `payout`. On closing,
`original` remains available, `successor` is null and the semantic payout is the
closing transfer. Activity entries add `block_hash` and `canonical`.

Verification is read-only. Import verifies and retains the evidence and terms;
its optional `expected_opening_hex` must match the original or successor.
Repeated imports merge by transaction ID and preserve local records.
See [recovery](receipts-and-recovery.md).

The HTTP request-body cap is **2,237,632 bytes**. A decoded contract receipt is
at most **1,110,624 bytes**; hex doubles its byte count. Ordinary payment
receipts have a separate 128 KiB decoded bound. JSON-RPC batches share the HTTP
body cap; use pagination instead of collecting unbounded lists.

## CLI workflow

Amounts in the CLI are decimal **NOID**, unlike RPC integer μNOID. Replace the
angle-bracket placeholders. The receiving or recovery wallet must be active
for the closing call, as determined by the inclusion height.

```sh
parano1d-cli contract protocol
parano1d-cli contract payment <payee-o1-address> <expiry-height> --max-fee 1 --out payment.json
parano1d-cli contract fund payment.json 10
parano1d-cli contract watch payment.json
parano1d-cli contract instances payment.json --limit 64
parano1d-cli contract call payment.json <slot> <creation-id> --close --preview
parano1d-cli contract call payment.json <slot> <creation-id> --close --expected-txid <reviewed-txid> --out closing.json
parano1d-cli contract receipt payment.json <confirmed-txid> --out closing.receipt
parano1d-cli contract verify closing.receipt
```

The CLI binds preview results before submission and writes a durable review
artifact first, so a lost response remains recoverable. `--out` must name a new
file. `call --wait-seconds 0` returns after submission; the default wait is
600 seconds. A closed result has no successor opening.

Other constructors are `vault`, `allowance`, `budget`, `recurring`, `vesting`;
`create definition.json --out object.json` accepts a custom definition.
Use `parano1d-cli contract <command> --help` for their exact arguments.
`restore <address> --out object.json` recovers a locally retained opening.
