# Build from source

The workspace is Rust 2021 and pins Rust `1.96.0`. Native dependencies are
needed for MDBX, proof code and GUI packaging.

## Host requirements

All platforms need:

- the pinned Rust toolchain with `rustfmt`;
- a native C/C++ compiler;
- CMake;
- libclang;
- Git.

On Debian or Ubuntu:

```sh
sudo apt update
sudo apt install --no-install-recommends \
  build-essential clang libclang-dev cmake pkg-config
```

The Linux GUI package additionally needs `appstreamcli` and `dpkg-deb`.
Windows release packaging uses Inno Setup 6. macOS packaging uses the standard
`codesign`, `iconutil` and `hdiutil` tools.

The repository's `rust-toolchain.toml` selects the compiler automatically:

```sh
rustup show active-toolchain
rustc --version
cargo --version
```

## Check the workspace

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
```

Build ordinary development binaries:

```sh
cargo build --locked \
  -p noid_node \
  -p noid-extminer \
  -p noid_gui \
  --bins
```

Development binaries exercise parsing, UI and non-production test paths. A
block-producing release requires the authenticated HistoryStep matrix pack
described below.

## Production proof material

A production build authenticates the Small, Large and Native matrices against
one pinned bank. Use the mainnet packs and independently checked pins for the
source tree being built. Keep these generated artifacts outside `target/`.

### Current matrix bank

The three-class pack has this layout and bank pin:

```text
v21-runtime-metadata.bin
v21-small.field-r1cs.zst
v21-large.field-r1cs.zst
v21-native.field-r1cs.zst
```

```text
NOID_V21_RELEASE_BANK=6c280ae869afc25e31d46d73b42870512991b78c9498bc7e5ef939bc07e5ed5e
```

The pin binds the matrices, interpreter, budgets and consensus schedule.
An isolated test-network pack has a different identity. The build checks the
metadata and every matrix before embedding the material.

### Ancestry verification material

Synchronization also authenticates retained ancestry. Its inputs are supplied
as separate history, matrix and preprocessing-key directories:

```text
v1/history-step.runtime
v2-runtime-metadata.bin
v2-small.field-r1cs.zst
v2-large.field-r1cs.zst
class-0.key
class-1.key
```

```text
NOID_V2_RELEASE_BANK=c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e
NOID_RETIREMENT_KEY_0_PIN=<authenticated-key-0-digest>
NOID_RETIREMENT_KEY_1_PIN=<authenticated-key-1-digest>
```

Use independently recomputed key digests. The pin file is parsed as data.
The [ancestry-bank record](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/research/v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md)
identifies its matrices and authentication procedure.

### Ancestry resource calculation

This command evaluates the retained ancestry bank, its preprocessing keys and
the corresponding recursive reductions:

```sh
cargo build --release --locked -p bench_prover --bin noid_v2_soundness
target/release/noid_v2_soundness \
  LEGACY_METADATA LEGACY_METADATA_PIN V2_METADATA V2_BANK_PIN \
  CLASS_0_KEY CLASS_0_KEY_PIN CLASS_1_KEY CLASS_1_KEY_PIN
```

The [derivation](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/noid_soundness/docs/v2-retirement.md)
states the exact inputs and premises for that calculation.

## Native deliverables

Run source checks and [qualification](testing.md) before packaging:

```sh
./scripts/build_release.sh \
  --pack ../parano1d-artifacts/history-step-pack-v1 \
  --v2-pack PATH_TO_FROZEN_V2_PACK \
  --v2-pins PATH_TO_REVIEWED_PIN_FILE \
  --v21-pack PATH_TO_FROZEN_V21_PACK \
  --v21-pins PATH_TO_REVIEWED_V21_PIN_FILE \
  --retirement-keys PATH_TO_AUTHENTICATED_KEYS \
  --retired-v2-history

cat target/release-builds/LAST_RELEASE
```

The release script validates input layouts and pins, embeds authenticated
material, rejects a mismatched schedule, builds Core and GUI, smoke-tests the
executables and verifies package membership and SHA-256 sums. It does not run
the entire protocol test suite. `proof-pins.env` records the embedded identities.
Use `--output PATH` for a fresh output directory.

Use `--retired-v2-history` for mainnet. The executable embeds the current
three-class bank, compressed verifier metadata and the checked unified
v1-to-v2-to-v2.1 origin from `noid_node/assets/mainnet-v21-retirement/`.
Historical matrix rows are replaced by independently release-pinned sparse
preprocessing keys. Build-time and startup checks verify both handoffs using
metadata-only historical runtimes. The original metadata and bank digests
remain the authentication identities after decompression.

Version 2.1.1 uses the existing consensus rules, activation heights, bank
identities and block encodings. Its additional fork-origin protocol exports
the original certificate encoding on the existing `/sync/fork-origin/1`
stream for 2.1 peers. Updated peers can use the complete auxiliary certificate
on `/sync/fork-origin/2`. Both streams return the same requested origin.

`--retired-history` retains the earlier profile with v2 rows available.
The history input archive contains `v1/history-step.runtime`, `pins.env`
and their `SHA256SUMS`.
Use that profile for independent verification of standalone historical v2
terminals and saved contract receipts whose proof boundary is still in v2.
The unified certificate closes the scheduled historical boundary. Other
standalone matrix claims require their corresponding rows or a separate
evaluation proof. Current v2.1 synchronization and production use the
`--retired-v2-history` profile.

The bundled certificate is 12,949,667 bytes. Its SHA-256 is
`0ba48aa2232f34751b27607acdb5f14c3b6e3448c99728de53669b5e9d326880`.
It closes the actual mainnet handoffs at blocks 210536 and 279369 and produces
origin request `c1f09b8419874aa058611f584320beb2de8f166cca40e765ffbe0b85d981161e`.
The two 304-byte v2 preprocessing keys were recomputed from the authenticated
Small and Large matrices. Their independently retained protocol digests are
recorded in the bundled `pins.env`. Only live obligations enter the certificate.

The offline tool reproduces both keys and the complete certificate:

```sh
cargo build --release --locked -p bench_prover --bin noid_retire_authorization
target/release/noid_retire_authorization prepare INPUTS.json NEW_OUTPUT_DIRECTORY 96
target/release/noid_retire_authorization verify VERIFIED_INPUTS.json NEW_OUTPUT_DIRECTORY
```

The final argument is a planning allowance in GiB. Inputs identify the pinned
legacy metadata, v2 pack, v2.1 metadata, old retirement keys and the original
authorization-origin certificate. The `Inputs` structure in
[`noid_retire_authorization.rs`](../../bench_prover/src/bin/noid_retire_authorization.rs)
defines the JSON fields. Verification also requires `v2_key_pins` supplied
from the independently retained preprocessing results. It verifies both
handoffs with historical matrix loading disabled. The
[replacement argument](../../noid_soundness/docs/v2-retirement.md#authorization-boundary-matrix-closure)
states the preprocessing and proof conditions.

The publisher selects this profile by default. `--with-legacy-history` embeds
the full historical matrices for source reproduction. Synchronization selects
the authenticated relation by the block's consensus schedule.

## Portable binaries

x86-64 releases are compiled against a portable process baseline. After
checking the host, runtime dispatch selects `pclmul`, `avx2+vpclmul` or
`avx512bw+vpclmul`. ARM64 selects `neon+pmull`.

Do not compile official artifacts with `target-cpu=native`. That would make the
binary depend on the build machine before runtime hardware checks can run.

## Reproducible archive details

On GNU tar hosts, `SOURCE_DATE_EPOCH` controls member timestamps and defaults
to zero. The Core archive has a fixed member set:

```text
README.txt
CONTRACTS.md
LICENSE
NOTICE
parano1d
parano1d-cli
parano1d-miner
```

The GUI package contains only the application and its private node. It does not
include operator CLI or external-mining tools.
