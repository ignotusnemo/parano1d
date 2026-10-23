# Native financial templates

Pruv provides typed requests for the wallet's token, trading and NFT
operations. `AssetId`, `Owner` and `Quantity` check asset identities,
canonical addresses and positive integer amounts. The node supplies exact
funding inputs, current State incarnations, fees and Owner authorization.
The native relation checks execution inside the block proof.

The examples assume `pruv` is on your PATH. After a local build, use
`target/release/pruv`.

## Check and preview

Save a request from the [native RPC reference](../reference/native-rpc.md)
as `buy.native.json`. A trade template needs the current asset ID, an explicit
`minimum_output` and an explicit `valid_until` height. Amounts use integer
base-unit strings. NOID and fungible tokens have six decimal places.

```sh
pruv native check buy.native.json
pruv native build buy.native.json --out preview.json
curl --fail-with-body -H 'Content-Type: application/json' --data-binary @preview.json http://127.0.0.1:9601
```

Review the active owner, exact asset, total debit, minimum output, expiry and
fee ceiling returned by the node. Keep its reviewed `plan_id`.

## Submit the reviewed plan

```sh
pruv native submit buy.native.json --plan-id <reviewed-plan-id> --out submit.json
curl --fail-with-body -H 'Content-Type: application/json' --data-binary @submit.json http://127.0.0.1:9601
```

Pruv preserves the template's terms and binds submission to the reviewed node
plan. Sending `walletSubmitNative` to the local node starts authorization and
submission. Follow confirmation through the returned transaction ID and save
the resulting receipt. Output files are created with exclusive-write handling.

## Available operations

- `create_token` launches fixed supply with holder backing and an optional
  atomic creator purchase.
- `transfer_token` moves tokens to an exact owner.
- `burn_token` burns tokens and pays their share of holder backing.
- `trade` declares a bounded buy or sell on the asset's current market.
- NFT collection and minting templates establish creator rights and items.
- `transfer_nft` and `burn_nft` act on an exact collection and serial.
- `list_nft`, `buy_nft` and `cancel_listing` handle atomic NFT custody and
  payment.

The node checks each operation's actual resources against current State.
See the [wallet token guide](../wallet/tokens.md) and
[NFT guide](../wallet/nfts.md) for the corresponding GUI workflows.

`pruv check`, `build`, `smt` and `verify` continue to work with
[ABI 3 programs](pruv.md). Their native resource limits remain 16
instructions and two persistent registers.
