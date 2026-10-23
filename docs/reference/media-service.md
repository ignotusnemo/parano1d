# Asset images and price history

`parano1d-media` distributes public asset metadata, static images and confirmed
trade history. Image publication uses native receipts and content hashes.
Price history follows canonical blocks from a fully verifying local node.
Run the service and node on the same host.

## Build and configure

```sh
cargo build --release --locked -p noid_gui --bin parano1d-media
```

Configure a dedicated storage directory, loopback listener, local node RPC
and storage quota:

```sh
export NOID_MEDIA_STORE=/srv/parano1d-media
export NOID_MEDIA_LISTEN=127.0.0.1:9610
export NOID_MEDIA_RPC=http://127.0.0.1:9601
export NOID_MEDIA_QUOTA_MIB=4096
export NOID_HISTORY_QUOTA_MIB=1024
./target/release/parano1d-media
```

One process holds the storage writer lease. Put a TLS reverse proxy in front
of the loopback listener. Apply request rate limits there, allow at most
10,518,528 request-body bytes, and preserve the fixed request length. The
service bounds headers, upload size, node responses, timeouts, image decoding
and concurrent requests. It rejects chunked request framing and redirects.

Wallets use `https://tradedata.parano1d.org/` by default. Override the origin
for a separate deployment or an isolated test network:

```sh
export NOID_GUI_MEDIA_ORIGIN=https://tradedata.parano1d.org/
./target/release/parano1d-gui
```

The origin is a host and optional port with `/` as its path. User information,
query strings, fragments and path prefixes are rejected. HTTP is allowed only
on loopback for isolated development. Configure the same origin for wallets
that should share a registry. External downloads follow the wallet's saved
**External data** preference, which starts Off.

## Publication checks

`POST /publish` accepts schema 1 with `metadata_hash`, `manifest_hex`, optional
`image_hex` and `receipt_hex`. Unknown fields are rejected. The service calls
`paranoid_verifyReceipt` on its own loopback node and requires all three flags:
`merkle_valid`, `canonical` and `confirmed`.

It then matches the exact metadata hash and manifest kind to authenticated
native creation effects or an NFT output. Token and collection identities
come from `native.created`. NFT outputs bind collection ID and serial.
The single-item NFT preparation receipt can publish its committed artwork
before minting completes. The receipt's checked height is recorded with the
public proof. Current spendable rights always come from current State.

The canonical manifest uses domain-separated BLAKE3. Images have a separate
domain-separated hash. The service validates both, decodes the PNG within its
size limit and writes immutable files atomically. A repeated valid publication
deduplicates. The quota includes partial committed objects after an interrupted
write. The next attempt can finish the remaining objects.

## Reading and backup

Public read routes:

```text
GET /metadata/<64 lowercase hex characters>.json
GET /images/<64 lowercase hex characters>.png
GET /history/<64 lowercase hex asset ID>/<end height>.json
```

Responses have fixed content types, `nosniff` and a restrictive content security
policy. Images and manifests use immutable cache headers. History uses
`no-store` so canonical updates become visible promptly. The wallet checks
image and manifest commitments after download.

## Price history

The service indexes confirmed executions in its `history/` MDBX database.
Each block commits its header, affected assets and candles atomically.
Canonical changes remove displaced records before replacement blocks are
indexed. The history quota defaults to 1,024 MiB and grows incrementally.
Increase `NOID_HISTORY_QUOTA_MIB` as the archive grows.

Run the service continuously to retain prices beyond the node's block-serving
window. On startup it indexes the available recent blocks. After a restart,
it resumes from its saved cursor. If the node has pruned a missed interval,
indexing resumes with the retained recent range.

The history endpoint returns at most 512 blocks for one asset, ending at the
requested height or the latest indexed block. Prices use exact NOID and token
quantities. Each candle includes the first, highest, lowest and last executed
price and the trade count. The wallet checks the response's chain identity
and endpoint header against its own node.

Wallet history requests run for the open DEX token when **External data** is
On. The wallet keeps the response in bounded memory. Its current price and
live price line come from its own node in both switch modes.

Back up these three directories into the media repository:

```text
metadata/<metadata hash>.json
images/<image hash>.png
proofs/<transaction ID>-<metadata hash>.json
```

Exclude `service.lock`, temporary files and the wallet's private `queue/`
directory. Store public receipts with their binding records. Stop the service
or take a consistent filesystem snapshot before copying a backup. After a
restore, check all manifest and image commitments before starting the service:

```sh
./target/release/parano1d-media --verify-store /srv/parano1d-media
```

Back up `history/` as a consistent database snapshot while the service is
stopped or through a filesystem snapshot. The public image repository holds
the metadata, image and publication-proof files listed above.

This command checks content integrity offline. Receipt canonicality is checked
against the local node when publishing. A saved publication record gives the
height at which that check succeeded. Restored media continues to be matched
against each receiving wallet's current State commitment.
