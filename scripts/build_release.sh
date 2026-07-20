#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=release_common.sh
source "$SCRIPT_DIR/release_common.sh"

BUILD_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
DEFAULT_RELEASE_DIR="$RELEASE_ROOT_DIR/target/release-builds/$BUILD_ID"
LAST_RELEASE_FILE="$RELEASE_ROOT_DIR/target/release-builds/LAST_RELEASE"
PACK_DIR=
RELEASE_DIR=
SKIP_TESTS=${NOID_RELEASE_SKIP_TESTS:-0}

usage() {
  cat <<'EOF'
Usage: ./scripts/build_release.sh --pack PACK_DIR [--output RELEASE_DIR] [--skip-tests]

Authenticate one existing canonical HistoryStep pack, embed it into the node,
run the release gates, and package the node, CLI, and external miner for the
current host. This command never regenerates matrices.

Options:
  --pack DIR       Canonical HistoryStep pack root (required).
  --output DIR     Fresh output directory. Defaults under target/release-builds/.
  --skip-tests     Build and smoke-test only. Intended for the five release jobs;
                   source validation must already have passed on main.
  -h, --help       Show this help.

Environment:
  NOID_RELEASE_SKIP_TESTS=1       Equivalent to --skip-tests.
  NOID_RELEASE_TOOL_TARGET_DIR    Override the pack-tool Cargo target directory.
  SOURCE_DATE_EPOCH               Archive timestamp on GNU tar hosts (default 0).
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
    --skip-tests)
      SKIP_TESTS=1
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
[[ $SKIP_TESTS == 0 || $SKIP_TESTS == 1 ]] || \
  release_die "NOID_RELEASE_SKIP_TESTS must be 0 or 1"

PACK_DIR=$(release_absolute_from_root "$PACK_DIR")
PACK_DIR=$(release_canonical_directory "$PACK_DIR")
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

HOST_TRIPLE=$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')
case "$HOST_TRIPLE" in
  x86_64-unknown-linux-gnu)
    PLATFORM=linux-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq,+vpclmulqdq'
    ISA_PROFILE='x86-64-v3 + PCLMULQDQ + VPCLMULQDQ (runtime AVX-512)'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    ;;
  aarch64-unknown-linux-gnu)
    PLATFORM=linux-aarch64
    RELEASE_RUSTFLAGS='-C target-feature=+aes'
    ISA_PROFILE='AArch64 NEON + PMULL'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    ;;
  x86_64-pc-windows-msvc)
    PLATFORM=windows-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq,+vpclmulqdq'
    ISA_PROFILE='x86-64-v3 + PCLMULQDQ + VPCLMULQDQ (runtime AVX-512)'
    BINARY_SUFFIX=.exe
    ARCHIVE_KIND=zip
    ;;
  aarch64-apple-darwin)
    PLATFORM=macos-aarch64
    RELEASE_RUSTFLAGS='-C target-feature=+aes'
    ISA_PROFILE='Apple Silicon NEON + PMULL'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    ;;
  x86_64-apple-darwin)
    PLATFORM=macos-x86_64
    RELEASE_RUSTFLAGS='-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq'
    ISA_PROFILE='Intel macOS x86-64-v3 + PCLMULQDQ (runtime AVX2)'
    BINARY_SUFFIX=
    ARCHIVE_KIND=tar
    ;;
  *) release_die "unsupported release host: $HOST_TRIPLE" ;;
esac

release_workspace_version
if [[ $ARCHIVE_KIND == zip ]]; then
  ARCHIVE_NAME="paranoid-v$RELEASE_VERSION-$PLATFORM.zip"
  release_require_command 7z
else
  ARCHIVE_NAME="paranoid-v$RELEASE_VERSION-$PLATFORM.tar.gz"
fi

RELEASE_PARENT=$(dirname -- "$RELEASE_DIR")
mkdir -p -- "$RELEASE_PARENT"
[[ ! -e $RELEASE_DIR && ! -L $RELEASE_DIR ]] || \
  release_die "release directory already exists: $RELEASE_DIR"
mkdir -- "$RELEASE_DIR"
RELEASE_DIR=$(release_canonical_directory "$RELEASE_DIR")
BIN_DIR="$RELEASE_DIR/bin"
ARCHIVE="$RELEASE_DIR/$ARCHIVE_NAME"
LOG_FILE="$RELEASE_DIR/build.log"
LOCK_DIR="$RELEASE_ROOT_DIR/target/.build_release.lock"
LOCK_HELD=0
CURRENT_STAGE=initialization

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
unset TAR_OPTIONS GZIP GZIP_OPT
export CARGO_TARGET_DIR="$RELEASE_ROOT_DIR/target"

printf 'ParanO(1)d self-contained release build\n'
printf '  source:       %s\n' "$RELEASE_ROOT_DIR"
printf '  matrix pack:  %s\n' "$PACK_DIR"
printf '  release dir:  %s\n' "$RELEASE_DIR"
printf '  version:      %s\n' "$RELEASE_VERSION"
printf '  target:       %s\n' "$HOST_TRIPLE"
printf '  ISA profile:  %s\n' "$ISA_PROFILE"
printf '  rustc:        %s\n' "$(rustc --version)"
printf '  cargo:        %s\n' "$(cargo --version)"

CURRENT_STAGE='pack tool build'
release_build_pack_tools 0

CURRENT_STAGE='pack authentication'
printf '\n==> Authenticating the canonical HistoryStep pack\n'
release_authenticate_pack "$PACK_DIR" 0

export RUSTFLAGS="$RELEASE_RUSTFLAGS"

CURRENT_STAGE='format check'
printf '\n==> Checking formatting\n'
cargo fmt --all -- --check

CURRENT_STAGE='workspace check'
printf '\n==> Checking the workspace for %s\n' "$HOST_TRIPLE"
cargo check --locked --workspace --all-targets --target "$HOST_TRIPLE"

export NOID_HISTORY_STEP_PACK_DIR="$PACK_DIR"
export NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST="$RELEASE_METADATA_DIGEST"
export NOID_HISTORY_STEP_PACK_LEAF_DIGESTS="$RELEASE_LEAF_DIGESTS"

CURRENT_STAGE='self-contained binary build'
printf '\n==> Building matrix-embedded native binaries\n'
cargo build --locked --release --target "$HOST_TRIPLE" -p noid_node --bins
cargo build --locked --release --target "$HOST_TRIPLE" \
  -p noid-extminer --bin noid-extminer

if [[ $SKIP_TESTS == 1 ]]; then
  printf '\n==> Skipping repeated release tests; source gates must already be green\n'
else
  CURRENT_STAGE='release test suite'
  printf '\n==> Running native release tests\n'
  cargo test --locked --release --target "$HOST_TRIPLE" \
    -p noid_block \
    -p noid_chain \
    -p noid_miner \
    -p noid_p2p \
    -p noid_recursive \
    -p noid_rpc \
    -p noid_node
fi

TARGET_BIN_DIR="$CARGO_TARGET_DIR/$HOST_TRIPLE/release"
for binary in paranoid noid-cli noid-extminer; do
  [[ -f $TARGET_BIN_DIR/$binary$BINARY_SUFFIX ]] || \
    release_die "release binary is missing: $TARGET_BIN_DIR/$binary$BINARY_SUFFIX"
done

CURRENT_STAGE='native smoke test'
printf '\n==> Smoke-testing native executables\n'
"$TARGET_BIN_DIR/paranoid$BINARY_SUFFIX" --help >/dev/null
"$TARGET_BIN_DIR/noid-cli$BINARY_SUFFIX" --help >/dev/null
"$TARGET_BIN_DIR/noid-extminer$BINARY_SUFFIX" --help >/dev/null

CURRENT_STAGE='binary packaging'
printf '\n==> Packaging %s\n' "$ARCHIVE_NAME"
mkdir -- "$BIN_DIR"
for binary in paranoid noid-cli noid-extminer; do
  cp -- "$TARGET_BIN_DIR/$binary$BINARY_SUFFIX" "$BIN_DIR/$binary$BINARY_SUFFIX"
  chmod 0755 "$BIN_DIR/$binary$BINARY_SUFFIX" 2>/dev/null || true
done

if [[ $ARCHIVE_KIND == zip ]]; then
  (
    cd "$BIN_DIR"
    7z a -bd -tzip -mx=9 "$ARCHIVE" \
      "paranoid$BINARY_SUFFIX" \
      "noid-cli$BINARY_SUFFIX" \
      "noid-extminer$BINARY_SUFFIX" >/dev/null
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
      -cf - \
      paranoid noid-cli noid-extminer |
      gzip -n -9 > "$ARCHIVE"
  else
    COPYFILE_DISABLE=1 tar -C "$BIN_DIR" -cf - \
      paranoid noid-cli noid-extminer |
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
(( ${#archive_members[@]} == 3 )) || \
  release_die "binary archive must contain exactly three entries"
for binary in paranoid noid-cli noid-extminer; do
  member_count=0
  for member in "${archive_members[@]}"; do
    if [[ $member == "$binary$BINARY_SUFFIX" ]]; then
      (( member_count += 1 ))
    fi
  done
  (( member_count == 1 )) || \
    release_die "binary archive must contain exactly one $binary$BINARY_SUFFIX"
done

ARCHIVE_DIGEST=$(release_sha256_file "$ARCHIVE")
printf '%s  %s\n' "$ARCHIVE_DIGEST" "$ARCHIVE_NAME" > "$RELEASE_DIR/SHA256SUMS"

mkdir -p -- "$(dirname -- "$LAST_RELEASE_FILE")"
LAST_RELEASE_TMP="$LAST_RELEASE_FILE.tmp.$$"
printf '%s\n' "$RELEASE_DIR" > "$LAST_RELEASE_TMP"
mv -- "$LAST_RELEASE_TMP" "$LAST_RELEASE_FILE"

CURRENT_STAGE=complete
printf '\nSUCCESS\n'
printf '  binaries:     %s\n' "$BIN_DIR"
printf '  archive:      %s\n' "$ARCHIVE"
printf '  SHA-256:      %s\n' "$ARCHIVE_DIGEST"
printf '  checksums:    %s\n' "$RELEASE_DIR/SHA256SUMS"
printf '  build log:    %s\n' "$LOG_FILE"
printf '  last release: %s\n' "$LAST_RELEASE_FILE"
