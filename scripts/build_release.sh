#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=release_common.sh
source "$SCRIPT_DIR/release_common.sh"

BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEFAULT_RELEASE_DIR="$RELEASE_ROOT_DIR/target/release-builds/$BUILD_ID"
LAST_RELEASE_FILE="$RELEASE_ROOT_DIR/target/release-builds/LAST_RELEASE"
PACK_DIR=
RELEASE_DIR=
V2_PACK_DIR=
V2_PIN_FILE=
RETIREMENT_KEYS_DIR=
RETIRED_HISTORY=0
usage() {
  cat <<'EOF'
Usage: ./scripts/build_release.sh --pack LEGACY_PACK --v2-pack V2_PACK \
  --v2-pins PIN_FILE --retirement-keys KEY_DIR [--output RELEASE_DIR] \
  [--retired-history]

Embed authenticated legacy and scheduled v2 release material into the node and
build two native deliverables for the current host:
the operator bundle (node, CLI, external miner) and the independently
installable GUI wallet (GUI plus its private node). This command never
regenerates matrices. The node build authenticates the v2 material and rejects
a pack for a different source schedule. Source checks and tests are separate
pre-build gates.

Options:
  --pack DIR             Canonical legacy HistoryStep pack root.
  --v2-pack DIR          Frozen source-scheduled v2 matrix pack.
  --v2-pins FILE         Three reviewed assignments: NOID_V2_RELEASE_BANK,
                        NOID_RETIREMENT_KEY_0_PIN, NOID_RETIREMENT_KEY_1_PIN.
  --retirement-keys DIR  Authenticated class-0.key and class-1.key files.
  --retired-history     Later release without embedded legacy matrices;
                        requires certificate availability on the network.
  --output DIR          Fresh directory, default under target/release-builds/.
  -h, --help            Show this help.

Environment:
  NOID_MACOS_SIGN_IDENTITY        Optional Developer ID identity; defaults to
                                  an ad-hoc macOS application signature.
  SOURCE_DATE_EPOCH               Archive timestamp on GNU tar hosts (default 0).

Native GUI packaging requires appstreamcli and dpkg-deb on Linux, Inno Setup 6
on Windows, and the standard codesign/iconutil/hdiutil toolchain on macOS.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --pack)
      (( $# >= 2 )) || release_die "--pack requires a directory"
      PACK_DIR=$2
      shift 2
      ;;
    --output)
      (( $# >= 2 )) || release_die "--output requires a directory"
      RELEASE_DIR=$2
      shift 2
      ;;
    --v2-pack)
      (( $# >= 2 )) || release_die "--v2-pack requires a directory"
      V2_PACK_DIR=$2
      shift 2
      ;;
    --v2-pins)
      (( $# >= 2 )) || release_die "--v2-pins requires a file"
      V2_PIN_FILE=$2
      shift 2
      ;;
    --retirement-keys)
      (( $# >= 2 )) || release_die "--retirement-keys requires a directory"
      RETIREMENT_KEYS_DIR=$2
      shift 2
      ;;
    --retired-history)
      RETIRED_HISTORY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      release_die "unknown argument: $1"
      ;;
  esac
done

[[ -n $PACK_DIR ]] || {
  usage >&2
  release_die "--pack is required"
}
PACK_DIR=$(release_absolute_from_root "$PACK_DIR")
PACK_DIR=$(release_canonical_directory "$PACK_DIR")
[[ -n $V2_PACK_DIR && -n $V2_PIN_FILE && -n $RETIREMENT_KEYS_DIR ]] || \
  release_die "scheduled v2 builds require --v2-pack, --v2-pins and --retirement-keys"
V2_PACK_DIR=$(release_absolute_from_root "$V2_PACK_DIR")
V2_PACK_DIR=$(release_canonical_directory "$V2_PACK_DIR")
RETIREMENT_KEYS_DIR=$(release_absolute_from_root "$RETIREMENT_KEYS_DIR")
RETIREMENT_KEYS_DIR=$(release_canonical_directory "$RETIREMENT_KEYS_DIR")
V2_PIN_FILE=$(release_absolute_from_root "$V2_PIN_FILE")
release_read_v2_pin_file "$V2_PIN_FILE"
release_validate_v2_layout "$V2_PACK_DIR" "$RETIREMENT_KEYS_DIR"
if [[ $RETIRED_HISTORY == 1 ]]; then
  release_validate_retired_legacy_layout "$PACK_DIR"
else
  release_validate_pack_layout "$PACK_DIR" 1
fi
release_read_pin_file "$PACK_DIR/pins.env"
RELEASE_METADATA_DIGEST=$RELEASE_FILE_METADATA_DIGEST
if [[ -z $RELEASE_DIR ]]; then
  RELEASE_DIR=$DEFAULT_RELEASE_DIR
else
  RELEASE_DIR=$(release_absolute_from_root "$RELEASE_DIR")
fi

release_require_command cargo
release_require_command rustc
release_require_command date
release_require_command gzip
release_require_command sed
release_require_command tar
release_require_command tr

release_workspace_version
HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')
case "$HOST_TRIPLE" in
  x86_64-unknown-linux-gnu)
    PLATFORM=linux-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64'
    ISA_PROFILE='portable x86-64 control path; runtime PCLMULQDQ / AVX2+VPCLMULQDQ / AVX-512'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    GUI_ARTIFACT_NAME="parano1d-gui-v$RELEASE_VERSION-linux-x86_64.deb"
    ;;
  aarch64-unknown-linux-gnu)
    PLATFORM=linux-aarch64
    RELEASE_RUSTFLAGS=
    ISA_PROFILE='portable AArch64 control path; runtime NEON+PMULL'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    GUI_ARTIFACT_NAME="parano1d-gui-v$RELEASE_VERSION-linux-aarch64.deb"
    ;;
  x86_64-pc-windows-msvc)
    PLATFORM=windows-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64'
    ISA_PROFILE='portable x86-64 control path; runtime PCLMULQDQ / AVX2+VPCLMULQDQ / AVX-512'
    BINARY_SUFFIX=.exe
    ARCHIVE_KIND=zip
    GUI_ARTIFACT_NAME="parano1d-gui-v$RELEASE_VERSION-windows-x86_64-setup.exe"
    ;;
  aarch64-apple-darwin)
    PLATFORM=macos-aarch64
    RELEASE_RUSTFLAGS=
    ISA_PROFILE='portable Apple Silicon control path; runtime NEON+PMULL'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    GUI_ARTIFACT_NAME="parano1d-gui-v$RELEASE_VERSION-macos-aarch64.dmg"
    ;;
  x86_64-apple-darwin)
    PLATFORM=macos-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64'
    ISA_PROFILE='portable Intel x86-64 control path; runtime PCLMULQDQ / AVX2+VPCLMULQDQ'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    GUI_ARTIFACT_NAME="parano1d-gui-v$RELEASE_VERSION-macos-x86_64.dmg"
    ;;
  *) release_die "unsupported release host: $HOST_TRIPLE" ;;
esac

if [[ $PLATFORM == macos-* ]]; then
  export MACOSX_DEPLOYMENT_TARGET=11.0
fi

if [[ $ARCHIVE_KIND == zip ]]; then
  ARCHIVE_NAME="parano1d-core-v$RELEASE_VERSION-$PLATFORM.zip"
  release_require_command 7z
else
  ARCHIVE_NAME="parano1d-core-v$RELEASE_VERSION-$PLATFORM.tar.gz"
fi

RELEASE_PARENT=$(dirname -- "$RELEASE_DIR")
mkdir -p -- "$RELEASE_PARENT"
[[ ! -e $RELEASE_DIR && ! -L $RELEASE_DIR ]] || \
  release_die "release directory already exists: $RELEASE_DIR"
mkdir -- "$RELEASE_DIR"
RELEASE_DIR=$(release_canonical_directory "$RELEASE_DIR")
BIN_DIR="$RELEASE_DIR/bin"
GUI_BIN_DIR="$RELEASE_DIR/gui-bin"
ARCHIVE="$RELEASE_DIR/$ARCHIVE_NAME"
GUI_ARTIFACT="$RELEASE_DIR/$GUI_ARTIFACT_NAME"
LOG_FILE="$RELEASE_DIR/build.log"
USER_GUIDE_SOURCE="$RELEASE_ROOT_DIR/scripts/release/README.txt"
LICENSE_SOURCE="$RELEASE_ROOT_DIR/LICENSE"
NOTICE_SOURCE="$RELEASE_ROOT_DIR/NOTICE"
LOCK_DIR="$RELEASE_ROOT_DIR/target/.build_release.lock"
LOCK_HELD=0
CURRENT_STAGE=initialization

[[ -f $USER_GUIDE_SOURCE && -s $USER_GUIDE_SOURCE && ! -L $USER_GUIDE_SOURCE ]] || \
  release_die "release user guide is missing, empty, or a symlink: $USER_GUIDE_SOURCE"
for legal_source in "$LICENSE_SOURCE" "$NOTICE_SOURCE"; do
  [[ -f $legal_source && -s $legal_source && ! -L $legal_source ]] || \
    release_die "release legal file is missing, empty, or a symlink: $legal_source"
done

on_exit() {
  local status=$?
  if [[ $LOCK_HELD == 1 ]]; then
    rmdir -- "$LOCK_DIR" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    printf '\nFAILED during: %s\n' "$CURRENT_STAGE" >&2
    printf 'Partial output was kept at: %s\n' "$RELEASE_DIR" >&2
  fi
  exit "$status"
}
trap on_exit EXIT

mkdir -p -- "$RELEASE_ROOT_DIR/target"
mkdir -- "$LOCK_DIR" 2>/dev/null || \
  release_die "another build_release.sh process is running (or remove stale $LOCK_DIR)"
LOCK_HELD=1

exec > >(tee "$LOG_FILE") 2>&1
cd "$RELEASE_ROOT_DIR"

unset CARGO_BUILD_TARGET CARGO_ENCODED_RUSTFLAGS RUSTFLAGS
unset NOID_HISTORY_STEP_PACK_DIR
unset NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST
unset NOID_HISTORY_STEP_PACK_LEAF_DIGESTS
unset NOID_V2_PACK_DIR NOID_V2_RELEASE_BANK
unset NOID_RETIREMENT_KEYS_DIR NOID_RETIREMENT_KEY_0_PIN NOID_RETIREMENT_KEY_1_PIN
unset TAR_OPTIONS GZIP GZIP_OPT
export CARGO_TARGET_DIR="$RELEASE_ROOT_DIR/target"

printf 'ParanO(1)d self-contained release build\n'
printf '  source:       %s\n' "$RELEASE_ROOT_DIR"
printf '  matrix pack:  %s\n' "$PACK_DIR"
printf '  v2 pack:      %s\n' "$V2_PACK_DIR"
printf '  v2 bank:      %s\n' "$RELEASE_V2_BANK"
printf '  legacy rows:  %s\n' "$((1 - RETIRED_HISTORY))"
printf '  release dir:  %s\n' "$RELEASE_DIR"
printf '  version:      %s\n' "$RELEASE_VERSION"
printf '  target:       %s\n' "$HOST_TRIPLE"
printf '  ISA profile:  %s\n' "$ISA_PROFILE"
printf '  core bundle:  %s\n' "$ARCHIVE_NAME"
printf '  GUI package:  %s\n' "$GUI_ARTIFACT_NAME"
printf '  rustc:        %s\n' "$(rustc --version)"
printf '  cargo:        %s\n' "$(cargo --version)"

export RUSTFLAGS="$RELEASE_RUSTFLAGS"
export NOID_HISTORY_STEP_PACK_DIR="$PACK_DIR"
export NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST="$RELEASE_METADATA_DIGEST"
export NOID_V2_PACK_DIR="$V2_PACK_DIR"
export NOID_V2_RELEASE_BANK="$RELEASE_V2_BANK"
export NOID_RETIREMENT_KEYS_DIR="$RETIREMENT_KEYS_DIR"
export NOID_RETIREMENT_KEY_0_PIN="$RELEASE_RETIREMENT_KEY_0_PIN"
export NOID_RETIREMENT_KEY_1_PIN="$RELEASE_RETIREMENT_KEY_1_PIN"
NODE_BUILD_ARGS=(--locked --release --timings --target "$HOST_TRIPLE" -p noid_node --bins)
if [[ $RETIRED_HISTORY == 1 ]]; then
  NODE_BUILD_ARGS+=(--features retired-history)
fi
{
  printf 'NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=%s\n' "$RELEASE_METADATA_DIGEST"
  printf 'NOID_V2_RELEASE_BANK=%s\n' "$RELEASE_V2_BANK"
  printf 'NOID_RETIREMENT_KEY_0_PIN=%s\n' "$RELEASE_RETIREMENT_KEY_0_PIN"
  printf 'NOID_RETIREMENT_KEY_1_PIN=%s\n' "$RELEASE_RETIREMENT_KEY_1_PIN"
  printf 'RETIRED_HISTORY=%s\n' "$RETIRED_HISTORY"
} > "$RELEASE_DIR/proof-pins.env"

CURRENT_STAGE='self-contained binary build'
printf '\n==> Building matrix-embedded native binaries\n'
cargo build "${NODE_BUILD_ARGS[@]}"
cargo build --locked --release --timings --target "$HOST_TRIPLE" \
  -p noid-extminer --bin parano1d-miner
cargo build --locked --release --timings --target "$HOST_TRIPLE" \
  -p noid_gui --bin parano1d-gui

TARGET_BIN_DIR="$CARGO_TARGET_DIR/$HOST_TRIPLE/release"
for binary in parano1d parano1d-cli parano1d-miner; do
  [[ -f $TARGET_BIN_DIR/$binary$BINARY_SUFFIX ]] || \
    release_die "release binary is missing: $TARGET_BIN_DIR/$binary$BINARY_SUFFIX"
done
[[ -f $TARGET_BIN_DIR/parano1d-gui$BINARY_SUFFIX ]] || \
  release_die "release GUI is missing: $TARGET_BIN_DIR/parano1d-gui$BINARY_SUFFIX"

CURRENT_STAGE='native smoke test'
printf '\n==> Smoke-testing native executables\n'
"$TARGET_BIN_DIR/parano1d$BINARY_SUFFIX" --check-hardware >/dev/null
"$TARGET_BIN_DIR/parano1d$BINARY_SUFFIX" --help >/dev/null
"$TARGET_BIN_DIR/parano1d-cli$BINARY_SUFFIX" --help >/dev/null
"$TARGET_BIN_DIR/parano1d-miner$BINARY_SUFFIX" --check-hardware >/dev/null
"$TARGET_BIN_DIR/parano1d-miner$BINARY_SUFFIX" --help >/dev/null
"$TARGET_BIN_DIR/parano1d-gui$BINARY_SUFFIX" --release-self-check >/dev/null

CURRENT_STAGE='binary packaging'
printf '\n==> Packaging %s\n' "$ARCHIVE_NAME"
mkdir -- "$BIN_DIR"
for binary in parano1d parano1d-cli parano1d-miner; do
  cp -- "$TARGET_BIN_DIR/$binary$BINARY_SUFFIX" "$BIN_DIR/$binary$BINARY_SUFFIX"
  chmod 0755 "$BIN_DIR/$binary$BINARY_SUFFIX" 2>/dev/null || true
done

CURRENT_STAGE='GUI wallet packaging'
printf '\n==> Packaging %s\n' "$GUI_ARTIFACT_NAME"
mkdir -- "$GUI_BIN_DIR"
cp -- "$TARGET_BIN_DIR/parano1d-gui$BINARY_SUFFIX" \
  "$GUI_BIN_DIR/parano1d-gui$BINARY_SUFFIX"
cp -- "$TARGET_BIN_DIR/parano1d$BINARY_SUFFIX" \
  "$GUI_BIN_DIR/parano1d$BINARY_SUFFIX"
chmod 0755 "$GUI_BIN_DIR/parano1d-gui$BINARY_SUFFIX" 2>/dev/null || true
chmod 0755 "$GUI_BIN_DIR/parano1d$BINARY_SUFFIX" 2>/dev/null || true
case "$PLATFORM" in
  linux-*)
    "$RELEASE_ROOT_DIR/scripts/release/package_linux_gui.sh" \
      "$GUI_BIN_DIR" "$RELEASE_DIR" "$RELEASE_VERSION" "$PLATFORM" >/dev/null
    ;;
  windows-*)
    release_require_command pwsh
    pwsh -NoLogo -NoProfile -NonInteractive \
      -File "$RELEASE_ROOT_DIR/scripts/release/package_windows_gui.ps1" \
      -BinDir "$GUI_BIN_DIR" \
      -OutputDir "$RELEASE_DIR" \
      -Version "$RELEASE_VERSION" \
      -Platform "$PLATFORM" >/dev/null
    ;;
  macos-*)
    "$RELEASE_ROOT_DIR/scripts/release/package_macos_gui.sh" \
      "$GUI_BIN_DIR" "$RELEASE_DIR" "$RELEASE_VERSION" "$PLATFORM" >/dev/null
    ;;
esac
[[ -f $GUI_ARTIFACT && -s $GUI_ARTIFACT ]] || \
  release_die "GUI package is missing or empty: $GUI_ARTIFACT"
cp -- "$USER_GUIDE_SOURCE" "$BIN_DIR/README.txt"
cp -- "$RELEASE_ROOT_DIR/docs/reference/contracts.md" "$BIN_DIR/CONTRACTS.md"
cp -- "$LICENSE_SOURCE" "$BIN_DIR/LICENSE"
cp -- "$NOTICE_SOURCE" "$BIN_DIR/NOTICE"
chmod 0644 "$BIN_DIR/README.txt" "$BIN_DIR/CONTRACTS.md" 2>/dev/null || true
chmod 0644 "$BIN_DIR/LICENSE" "$BIN_DIR/NOTICE" 2>/dev/null || true

archive_entries=(
  README.txt
  CONTRACTS.md
  LICENSE
  NOTICE
  "parano1d$BINARY_SUFFIX"
  "parano1d-cli$BINARY_SUFFIX"
  "parano1d-miner$BINARY_SUFFIX"
)

if [[ $ARCHIVE_KIND == zip ]]; then
  (
    cd "$BIN_DIR"
    7z a -bd -tzip -mx=9 "$ARCHIVE" "${archive_entries[@]}" >/dev/null
  )
else
  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
  [[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || \
    release_die "SOURCE_DATE_EPOCH must be a non-negative integer"
  if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar -C "$BIN_DIR" \
      --sort=name \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      --mtime="@$SOURCE_DATE_EPOCH" \
      -cf - "${archive_entries[@]}" |
      gzip -n -9 > "$ARCHIVE"
  else
    COPYFILE_DISABLE=1 tar -C "$BIN_DIR" -cf - "${archive_entries[@]}" |
      gzip -n -9 > "$ARCHIVE"
  fi
fi

CURRENT_STAGE='archive member verification'
archive_members=()
if [[ $ARCHIVE_KIND == zip ]]; then
  while IFS= read -r member; do
    archive_members+=("$member")
  done < <(7z l -ba -slt "$ARCHIVE" | sed -n 's/^Path = //p' | tr -d '\r')
else
  while IFS= read -r member; do
    member=${member%$'\r'}
    archive_members+=("$member")
  done < <(tar -tzf "$ARCHIVE")
fi
(( ${#archive_members[@]} == ${#archive_entries[@]} )) || \
  release_die "release archive contains an unexpected number of entries"
for expected in "${archive_entries[@]}"; do
  member_count=0
  for member in "${archive_members[@]}"; do
    if [[ $member == "$expected" ]]; then
      (( member_count += 1 ))
    fi
  done
  (( member_count == 1 )) || release_die "release archive must contain exactly one $expected"
done

ARCHIVE_DIGEST=$(release_sha256_file "$ARCHIVE")
GUI_ARTIFACT_DIGEST=$(release_sha256_file "$GUI_ARTIFACT")
printf '%s  %s\n' "$ARCHIVE_DIGEST" "$ARCHIVE_NAME" > "$RELEASE_DIR/SHA256SUMS"
printf '%s  %s\n' "$GUI_ARTIFACT_DIGEST" "$GUI_ARTIFACT_NAME" >> "$RELEASE_DIR/SHA256SUMS"

mkdir -p -- "$(dirname -- "$LAST_RELEASE_FILE")"
LAST_RELEASE_TMP="$LAST_RELEASE_FILE.tmp.$$"
printf '%s\n' "$RELEASE_DIR" > "$LAST_RELEASE_TMP"
mv -- "$LAST_RELEASE_TMP" "$LAST_RELEASE_FILE"

CURRENT_STAGE=complete
printf '\nSUCCESS\n'
printf '  binaries:     %s\n' "$BIN_DIR"
printf '  archive:      %s\n' "$ARCHIVE"
printf '  SHA-256:      %s\n' "$ARCHIVE_DIGEST"
printf '  GUI package:  %s\n' "$GUI_ARTIFACT"
printf '  GUI SHA-256:  %s\n' "$GUI_ARTIFACT_DIGEST"
printf '  checksums:    %s\n' "$RELEASE_DIR/SHA256SUMS"
printf '  build log:    %s\n' "$LOG_FILE"
printf '  last release: %s\n' "$LAST_RELEASE_FILE"
