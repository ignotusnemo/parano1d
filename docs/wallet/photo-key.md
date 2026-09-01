# Photo-derived key

The wallet can derive its 256-bit master secret from an image. It does not hide
an existing key inside the file: the decoded pixels are the source of the key.
The same pixels recreate the same wallet and every address derived from it.

![Deriving a wallet key from photo pixels](../assets/wallet/photo-key.png)

## What the wallet reads

The wallet decodes the selected image, converts it to a canonical RGBA pixel
stream and feeds the following data to domain-separated BLAKE3 derive-key mode:

```text
"RGBA8" || width_le32 || height_le32 || pixel_length_le64 || rgba_pixels
```

The derivation context is fixed by the wallet format:

```text
Parano1d master secret from canonical image pixels v1
```

The 32-byte output is the master secret.

The file name and image metadata are not inputs. Two files with identical
decoded dimensions and pixels therefore derive the same key even if their
metadata differs.

The short **Key ID** shown before import is a separate domain-separated
fingerprint of the derived key. Compare it when testing a backup on another
device.

## What stays private

The image is processed locally. It is not uploaded, placed in a transaction or
copied into the wallet data directory. After setup, the keystore contains the
derived master secret, just as it would after Generate or Import.

On-chain, a photo-derived owner is no different from any other Parano1d
owner. The photo is only a human-chosen source for the same 256-bit wallet
secret.

## Choose the photo carefully

Use a private original that has never been published. A public or easily
guessed image is not a secret: anyone with the same pixels can derive the same
wallet.

The GUI rejects obvious low-complexity sources: an image must be at least
32 × 32 pixels and contain at least 64 distinct decoded pixel values. This is a
safety floor, not an entropy proof. A public, generated or otherwise predictable
image remains unsafe even when it passes these checks.

Keep the original file offline. The following changes produce a different
wallet:

- resizing, cropping or rotating pixels;
- filters and color correction;
- lossy format conversion;
- messenger or social-network recompression;
- a screenshot or thumbnail of the original.

When moving the backup between your own devices, send it as a file rather than
as an optimized image. Metadata may change safely, but preserving the original
file is the simplest reliable recovery procedure.

See [Backup and recovery](backup-recovery.md) before receiving funds.
