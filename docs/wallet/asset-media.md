# Token and NFT media

Names, tickers, descriptions, optional project websites and pictures are
public asset metadata. The
native definition or NFT item commits to the metadata hash in State. The
wallet checks the manifest and image against that commitment before display.
The asset ID, or collection ID and serial, identifies the asset.

## Creating an asset

Choose an image from your computer while creating a token or NFT. The wallet
accepts PNG, JPEG or WebP input up to 4 MiB and prepares a static PNG. Token
logos fit within 512 × 512 pixels. NFT images fit within 2,048 × 2,048.
Input dimensions are limited to 4,096 × 4,096.

Your wallet saves the prepared files before you confirm the creation. After
confirmation it sends those files and the saved public creation receipt to
the configured media service. The service checks the receipt with its own
node and accepts files whose exact hash and asset identity match the receipt.
Publication retries in the background and resumes after a wallet restart.

Other wallets fetch the same files from the configured service. They check
the metadata hash from their own node, the image hash, its dimensions and
its byte length. Descriptions contain text. Images use the wallet's bounded
image decoder. Metadata uses a fixed schema and content hashes.

Project website links use HTTPS, contain no login credentials and open only
when selected, in the external browser. Asset images come from the configured
media service.

## Automatic downloads

**External data** in the top-right header starts **Off**. Turn it **On** to
load token and NFT images and DEX price history. The choice is saved for
future wallet sessions. The default service is https://tradedata.parano1d.org/.
Images use placeholders while the switch is Off.
Cached names and tickers remain available in both modes. Creating an asset
publishes its selected media. The creation form previews your local image.

DEX always shows the current price from your node. With External data Off,
its live line follows the price from the time you open that token. With it
On, the wallet also loads confirmed trade candles from the configured service.
Requests run for the open token. The wallet keeps up to 512 blocks in memory
and releases that chart when you leave the market. The server retains history.

**Settings → Interface → Clear asset cache** clears downloaded names and
images. The download cache uses up to 64 MiB and evicts old files as it fills.
Prepared and created asset media, queued publications and receipts stay saved.

## Availability and copies

The media service stores immutable `metadata/`, `images/` and public `proofs/`
files. A Git copy can restore those exact files. Replacing a file under an
existing hash is rejected.

If media is unavailable, the wallet shows the asset identity and a placeholder.
Your node still verifies ownership, balances, transfers and trades. Keep the
`native-media` directory in your wallet backup to preserve your local copies
and any pending publication entries.

See [media service operations](../reference/media-service.md) for hosting and
backup configuration.
