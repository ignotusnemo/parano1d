# Client-authorized native operations

`paranoid_prepareNativeIntent` prepares token, trading and NFT operations for
an explicitly supplied owner address. The client receives a canonical intent
and an exact review from the same planner used by the desktop wallet. Client
authorization completes the operation before submission.

The method uses local owner RPC access. A web service calls the node over
loopback and exposes its own bounded application API over HTTPS.

## Prepare

Parameters are `[owner, request, expected_parent_hash?]`. The request uses the
[native operation actions](native-rpc.md#request-actions). Amounts are decimal
integer strings in base units. An optional parent hash fixes the canonical
snapshot expected by the caller.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_prepareNativeIntent",
  "params": [
    "<owner address>",
    {
      "action": "trade",
      "asset_id": "<64-character asset ID>",
      "buy": true,
      "gross_input": "1000000",
      "slippage_bps": 1000
    },
    "<canonical parent hash>"
  ]
}
```

The response is a `NativeClientPlan`:

| Field | Meaning |
| --- | --- |
| `schema_version` | Response schema, currently `1` |
| `plan_id` | BLAKE3 commitment to the parent, owner, anchor, request and unsigned intent |
| `intent_id` | Logical operation ID or funded trade authorization ID |
| `owner` | Address whose secret authorizes the operation |
| `candidate_height` | Height used for rules and fee planning |
| `parent_header_hex` | Complete canonical 212-byte parent header |
| `chain_id` | Native-operation chain identity |
| `epoch_anchor` | Transaction anchor for the candidate height |
| `owner_authorization_version` | Construction selected by the candidate's rules |
| `intent_kind` | `operation` or `trade` |
| `unsigned_intent_hex` | Canonical wire intent with empty authorization |
| `review` | Request, State identity, exact amounts, fees and operation-specific terms |

The review includes NOID debit and credit, fee and fee ceiling, holder backing,
creator purchase, redemption, quoted and minimum outputs, expiry, asset and
collection IDs, serial range and input/output counts. A trading review also
reports the local pending-policy projection.

Preparation reads verified State and the local mempool. It keeps the node's
wallet address, key, local activity and reservations unchanged. Several
clients can request plans for their respective addresses. A plan reserves no
inputs or output slots. Admission checks their availability when the completed
intent arrives.

## Check and authorize on the client

1. Check `schema_version`, the chain, parent header, epoch anchor and candidate
   rules against the node connection selected by the application.
2. Decode `unsigned_intent_hex` using `NativeIntent` for `operation`, or
   `TradeOwnerIntent` for `trade`. Check that authorization is empty.
3. Recompute the canonical owner statement and `intent_id`. Check the owner,
   exact action, asset identities, funding sources, recipients, outputs and
   fee against the user's approved operation. For trading, check gross input,
   minimum output, fee ceiling and validity range.
4. Produce the Owner capsule using `owner_authorization_version`. The native
   asset, financial and trade authorization functions check their respective
   public relations before proving.
5. Verify the completed capsule locally. Place its canonical bundle bytes in
   `authorization_bytes` and serialize the same intent.
6. Send those bytes through `paranoid_submitTxIntent`. Retain the operation ID
   and confirmed receipt for tracking and export.

For a financial operation, construct `NftRoundContext` from the candidate
height, parent block ID and parent allocation counter. All of these values
are available in the returned header and plan. The relevant public relation
is selected by the decoded operation.

Native operations use the `NOIDNT21` wire format. A funded trade uses
`NOIDTO21`, containing its canonical trade policy and funding claims.
See [wire formats](../protocol/native-wire.md).

## Reproduce the plan identity

Hash this byte sequence with BLAKE3:

```text
"NOIDNativeClientPlan1"
|| parent_header_bytes
|| owner_bytes
|| epoch_anchor_bytes
|| request_json_length_u32_le
|| request_json_bytes
|| unsigned_intent_bytes
```

`request_json_bytes` is the compact Serde encoding of `NativeWalletRequest` in
declaration order. The plan identity lets the client retain the exact prepared
review. The Owner capsule binds the canonical intent's authorization statement.

## Snapshot and resource bounds

A mismatched `expected_parent_hash` returns error `-32041` with current
`height` and `block_hash`. Refresh State and prepare again. The planner also
checks the tip binding of funding records and the pending-policy snapshot.

The request encoding is limited to 32 KiB. NOID funding discovery reads at
most 16,384 verified sources. Consolidation reduces the source count for a
fragmented owner. All native page, action, market and fee checks use the
installed runtime's ordinary admission budget.

Trade defaults and expiry rules match the native wallet API. Pass
`slippage_bps: 1000` for the desktop's 10% tolerance, or supply an explicit
minimum output. Use `getMempoolEntry` and canonical receipts to follow the
submitted operation. After an expired unfilled policy leaves the mempool,
its unspent sources can fund a fresh plan.
