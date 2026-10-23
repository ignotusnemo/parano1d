# Native request examples

These files use example identities and inclusion heights. Replace the asset
or collection ID, committed metadata hash and expiry with current values from
your node before requesting a live preview.

```sh
pruv native check noid_pruv/examples/native/create-token.json
pruv native build noid_pruv/examples/native/buy.json --out preview.json
```

The launch creates 100,000 fixed-supply tokens and requires 100 NOID of holder
backing plus its quoted network fee. `buy.json` declares 1 NOID of gross input
and a minimum of 99 whole tokens. `list-nft.json` declares a 1 NOID ask.
`burn-token.json` burns one whole token and redeems its backing share.

Amounts use six decimal places as integer strings. The template's expiry is
an inclusion height. Use the node's exact reviewed plan ID for `native submit`.
See [the workflow](../../../docs/contracts/native-templates.md).
