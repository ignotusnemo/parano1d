# Backup and recovery

The master secret and receipts have different recovery properties. Back them
up separately.

## Master secret

The 256-bit master secret derives every address and grants spending authority.
It can be backed up as:

- the exported 64-character hexadecimal value; or
- the exact original photo used for pixel derivation.

Store the backup offline and test that its short key ID matches before relying
on it.

The local `wallet.key` file is not password-encrypted. On Unix it is created
with mode `0600`; the operating-system account and storage encryption remain
the security boundary.

## Photo recovery

Only identical decoded pixels derive the same secret. Keep the original file.
Do not rely on a thumbnail, cloud preview, screenshot or messenger copy.

Metadata does not matter. Pixel changes do.

## Receipts

`wallet.receipts` contains confirmed outgoing payment evidence. It is not
derived from the master secret and is intentionally cleared when a different
secret is imported.

Copy it together with the master-secret backup if you need the complete local
payment record. Individual receipts can also be exported as self-contained
text.

## What an import restores

Import restores:

- deterministic address derivation;
- current UTXOs found for discovered addresses;
- authority to spend those UTXOs.

It does not restore:

- local address labels;
- receipts that existed only on another device;
- pruned historical transactions without a saved receipt;
- generated addresses beyond the contiguous discovery range.

## Safe replacement

Before replacing the secret:

1. stop mining;
2. export and verify the current secret;
3. copy `wallet.receipts` if needed;
4. record any locally meaningful address labels;
5. install the new secret;
6. allow address discovery and synchronization to finish.

Never paste a secret into a website, issue report, chat or support message.

## Contract data

Back up `wallet.contracts.json`, `contract-activity/` and the complete
`objects/` directory, including `objects/terminals/`, together with wallet
authority. They contain public terms, activity and proof evidence that cannot
be reconstructed from the secret alone. Stop the node for a consistent copy.
See [contract recovery](../contracts/receipts-and-recovery.md).

## Tokens, NFTs and media

Current native ownership is discovered from authenticated State for your
wallet addresses. Keep `wallet.receipts`, the saved native activity and
`native-media/` with the data-directory backup. This preserves your local
operation records, prepared NFT metadata, artwork and queued publications.
Close the wallet and stop its node before copying the directory.
