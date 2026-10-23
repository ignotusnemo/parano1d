# Native wallet RPC

Native wallet operations use the wallet owner's local node. Keep access
limited to the local wallet application or an authenticated integration.
Amounts are exact integer strings. Both NOID and fungible tokens have six
decimal places. Heights are JSON integers. Asset and collection IDs are
64-character hexadecimal identities.

## Inspect current rights

| Method | Parameters | Result |
|---|---|---|
| `paranoid_getNativeProtocol` | `[]` | Activation, runtime availability and capacities |
| `paranoid_getNativeHoldings` | `[owner, cursor, limit]` | Typed live holdings at one canonical State |
| `paranoid_walletGetNativeHoldings` | `[cursor, limit]` | Active wallet's typed holdings |
| `paranoid_getNativeCatalog` | `[kind, cursor, limit]` | `markets`, `collections` or `nft_listings` |
| `paranoid_getNativeMarket` | `[asset_id]` | Current definition, curve/pool and reserve |
| `paranoid_walletNativePending` | `[]` | Pending and unconfirmed wallet activity |

A cursor binds owner or catalog kind, height and block hash. If the canonical
State changes during pagination, request a fresh first page. Decode each
opening and bind its root, slot, creation ID and related definitions to the
returned State. The GUI performs these checks before presenting holdings.

## Preview, review, authorize

Send one request to `paranoid_walletPreviewNative`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_walletPreviewNative",
  "params": [{
    "action": "trade",
    "asset_id": "<64-character asset ID>",
    "buy": true,
    "gross_input": "1000000",
    "minimum_output": "<minimum token base units>",
    "valid_until": 100
  }]
}
```

Review `owner`, `key_index`, `height`, `parent_hash`, `state_root`, the returned
`request`, NOID debit/credit, fee, fee ceiling, minimum and expiry. The
`pending_quote` distinguishes the locally projected candidate from the
confirmed-State estimate.

Authorize with `paranoid_walletSubmitNative` and parameters
`[same_request, reviewed_plan_id]`. The node rebuilds the operation and checks
its exact review binding, canonical parent and active wallet before producing
an Owner capsule. A changed context requires a fresh preview. The result
contains the transaction ID and charged fee. Track confirmation and retain
its receipt through the wallet's existing receipt APIs.

## Request actions

| Action | Fields in addition to `action` |
|---|---|
| `create_token` | `whole_tokens`, `metadata_hash`, optional `initial_buy_units` |
| `transfer_token` | `asset_id`, `units`, `recipient` |
| `burn_token` | `asset_id`, `units` |
| `trade` | `asset_id`, `buy`, `gross_input`, optional `minimum_output`, `slippage_bps`, `valid_until` |
| `create_collection` | `maximum_items`, `metadata_hash` |
| `mint_nft` | `collection_id`, `metadata_hash` |
| `mint_nfts` | `collection_id`, `metadata_hashes` (ordered, nonempty array) |
| `transfer_nft` | `collection_id`, `serial`, `recipient` |
| `burn_nft` | `collection_id`, `serial` |
| `list_nft` | `collection_id`, `serial`, `ask_micronoid`, `expiry_height` |
| `buy_nft` | `collection_id`, `serial`, `maximum_ask_micronoid` |
| `cancel_listing` | `collection_id`, `serial` |

`getNativeProtocol.nft_batch_limit` reports the current batch ceiling before
funding-dependent page checks. `mint_nfts` uses the existing mint relation:
one successor collection and one NFT per supplied metadata hash, with consecutive
serials in array order. The preview returns `serial` and `last_serial` for the
inclusive range. The same creator can submit subsequent batches. Wallet-created
multi-item collections use `maximum_items = "18446744073709551615"`. Standalone
NFT preparation retains `maximum_items = "1"`. The GUI exposes no collection
supply setting. Existing collections retain their committed terms.


Unknown fields reject. Wallet trade defaults are 100 basis points of slippage
and expiry three heights after the candidate height. An explicit expiry must
be within 30 blocks of that height. Supplying a minimum fixes that bound
directly. An expiry does not guarantee inclusion.

`burn_token` performs the single burn/redemption operation. `buy_nft` caps the
accepted ask. Listing and cancellation consume the exact current item or
listing incarnation. Actual funding, fees, arithmetic and resource selection
are checked against live State.

`create_token.initial_buy_units` is an exact integer string in token base
units. Omit it or use `"0"` to create without buying. Its maximum is 60% of the
fixed supply. The creation transaction pays full backing plus the standard
curve cost and the network fee, and assigns the purchased tokens to the
creator. Buying the entire curve allocation creates the permanent DEX pool
immediately. Review `reserve_deposit_micronoid`,
`initial_buy_cost_micronoid`, `quoted_output` and the total
`noid_debit_micronoid` separately. Pruv's `create_token` template supports the
same optional field, using a positive quantity when present.

[Pruv native templates](../contracts/native-templates.md) generate these
preview/submit envelopes with typed identities, canonical amounts and explicit
trade bounds.

## Saved receipts

`paranoid_walletReceipts` keeps the existing `[page, page_size, family]` interface.
For additional filters, use `paranoid_walletQueryReceipts`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_walletQueryReceipts",
  "params": [1, 7, {
    "filter": "trades",
    "asset_id": "<64-character lowercase hexadecimal asset ID>",
    "operation": "trade",
    "timestamp_from": 1790812800,
    "timestamp_before": 1793491200,
    "verification": "confirmed",
    "order": "newest"
  }]
}
```

Pages start at 1. Page size is 1 through 50. Omitted query fields use the
defaults `all`, no asset or date bounds, `any` operation, `any` verification
status and `newest` order. Unknown fields reject. Date bounds are Unix seconds:
`timestamp_from` is inclusive and `timestamp_before` exclusive.

Families are `all`, `noid`, `tokens`, `trades` and `nfts`. Operations are
`any`, `payment`, `create_token`, `transfer_token`, `burn_token`, `trade`,
`create_nft`, `transfer_nft`, `burn_nft`, `list_nft`, `buy_nft` and
`cancel_listing`. `create_nft` includes collection preparation and item minting.
Verification values are `any`, `confirmed`, `off_chain` and `missing_header`.
Orders are `newest`, `oldest`, `asset` and `operation`.

The node validates saved inclusion data, filters the full library and sorts
before pagination. Asset and operation groups use newest-first ordering within
each group. Asset ordering uses the first full identity in a receipt's sorted
identity set, with NOID payments first. Newest/oldest order uses height,
timestamp and logical transaction ID as stable tie breakers. The response
echoes the exact query and returns `page`, `page_size`, `total`, `total_pages`
and `receipts`. A native exchange remains one receipt with its asset legs.

Only one advanced scan runs at a time. A changed receipt revision or canonical
tip identity aborts the query. Retry against the current library. Ordinary
receipt export and detailed verification keep their existing interfaces.

## Client-held keys

[`prepareNativeIntent`](client-native-rpc.md) prepares the same actions for a
provided owner address. It returns canonical unsigned bytes and a review for
client-side authorization. Submit the completed bytes through `submitTxIntent`.
