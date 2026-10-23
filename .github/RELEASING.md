# Native releases

The canonical repository is `git.parano1d.org/ignotusnemo/parano1d`. GitHub `proof-native/parano1d` runs the manual Platform CI and Native Release workflows. GitLab `ignotusnemo/parano1d` mirrors the same source, tag, release notes and binary files. The former GitHub `ignotusnemo/parano1d` mirror is unavailable and is excluded from release checks.

## Prepare

- Maintainers merge reviewed release changes from `dev` into canonical `main`, then synchronize `main` on `proof-native` and `gitlab`. Keep `dev` synchronized with any release fixes made on `main`.
- Set the workspace version and commit `.github/release-notes/vVERSION.md`. Keep each prose paragraph and list item on one physical line.
- Use the frozen mainnet legacy metadata, v2 and v2.1 packs, their reviewed pins and two legacy retirement verification keys. Include each bank's `matrix-checks.json` from its successful local full preflight. Mainnet executables embed the selected ancestry proof from `noid_node/assets/mainnet-retirement.origin` and verify it locally under those keys before accepting peers. Cold synchronization must pass through an unchanged v2.0.3 peer retaining only the legacy certificate, with DNS seeds disabled and no internet access.
- Authenticate `gh` for `proof-native/parano1d`, or supply `GH_TOKEN` with access to that repository. The local publisher checks every remote's `main` before assigning a release tag.

```sh
./scripts/publish_release.sh VERSION /path/to/history-step-pack-v1 \
  --v2-pack /path/to/frozen-v2-pack \
  --v2-pins /path/to/v2-pins.env \
  --v21-pack /path/to/frozen-v21-pack \
  --v21-pins /path/to/v21-pins.env \
  --retirement-keys /path/to/verification-keys \
  --channel stable
```

The publisher runs Platform CI for the exact source commit. After success it creates one annotated tag on all three remotes, opens a draft in `proof-native`, uploads all three normalized packs and starts Native Release. Both workflows use manual dispatch.

The transition release carries the following authenticated inputs:

| Input | Contents |
| --- | --- |
| `history-step-pack-v1.tar.gz` | Legacy runtime metadata and pins |
| `history-step-pack-v2.tar.gz` | Small and Large matrices, runtime metadata, local matrix checks, pins and two legacy retirement verification keys |
| `history-step-pack-v21.tar.gz` | Small, Large and Native matrices, runtime metadata, local matrix checks and pins |
| `noid_node/assets/mainnet-retirement.origin` | The embedded certificate for the v1 to v2 transition |

The v2 matrices support synchronization and block production before the scheduled activation. Both scheduled banks are included in the same executable. The legacy v1 matrices are replaced by their verified certificate in the retired-history build.

## Build and publish

Platform CI checks reproducible packing for all three formats, explicit build inputs and native executables on five platforms. Native Release verifies the tag, source version, notes, successful Platform CI run, archive digests and complete archive contents. Each platform receives the same three packs and builds with `--pack`, `--v2-pack`, `--v2-pins`, `--v21-pack`, `--v21-pins`, `--retirement-keys`, `--retired-history` and `--prechecked-matrices`. The legacy archive contains pinned runtime metadata. Rust build validation binds each matrix to its locally verified result through the approved archive digest, SHA-256 payload hashes, bank pin, class shape and statement digest. It authenticates runtime metadata and retirement keys and checks the source schedule. The tagged source supplies the mainnet retirement proof. Every node verifies the complete proof at startup, retains it for P2P serving and applies the normal HistoryStep checks to its selected State and headers. Core and the GUI sidecar use the same daemon.

A local build with the default full preflight emits `matrix-checks.json` into each `OUT_DIR/embedded-v2` and `OUT_DIR/embedded-v21` directory. Copy those records beside their exact checked matrices before creating the release archives. Review the archive SHA-256 values as the independent pins for CI. `--prechecked-matrices` uses those approved records for every native platform.

Before packaging, each native build starts its daemon with a fresh data directory, loopback listeners and DNS bootstrap disabled. The release check confirms the native runtime is available and the embedded certificate is verified and retained. It stops the daemon and removes the temporary data after the check.

The publisher and workflow default to retired history. Pass `--with-legacy-history` to the publisher, or set the workflow's `retired_history` input to false, when reproducing a transition release. This selects the full legacy archive and omits the retired-history Cargo feature together.

Release build scripts and their host dependencies use optimization. The full matrix preflight runs during local artifact preparation. Each native CI job verifies the approved matrix records and payload hashes, allows up to six hours for a cold build and retains its build log and Cargo timing reports as a separate diagnostics artifact. The Cargo cache contains downloaded sources, not compiled binaries.

Linux x86-64, Linux ARM64, Windows x86-64, macOS Apple Silicon and macOS Intel each produce a Core archive and a GUI installer. The release stays a draft until all ten deliverables succeed. Publication adds the three input packs and `SHA256SUMS`, for fourteen release assets in total.

If a build fails, inspect that job before rerunning it. A changed source commit requires a new Platform CI result. Never move an already published release tag or combine assets from different release commits.

## Synchronize delivery

Download the complete published release from `proof-native` and verify every entry in `SHA256SUMS`. Copy those exact fourteen files and the committed release notes to the canonical Forgejo release and GitLab mirror. GitLab stores the files in its generic package registry and exposes them as release asset links. No platform rebuild is needed for mirroring.

Before considering publication complete, download the assets from each destination and compare their digests with the original manifest. Check the release title, notes, channel and annotated tag on every host as well. Automatic source-code archives generated by a hosting service are separate from the fourteen release assets.
