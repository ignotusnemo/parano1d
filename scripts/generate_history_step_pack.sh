#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=release_common.sh
source "$SCRIPT_DIR/release_common.sh"

usage() {
  cat <<'EOF'
Usage: ./scripts/generate_history_step_pack.sh OUTPUT_DIR

Generate the canonical two-class HistoryStep v1 pack once from honest genesis
fixtures, authenticate it, and publish it atomically at OUTPUT_DIR. Matrix
generation can take roughly 90 minutes on the reference laptop. OUTPUT_DIR
must not exist; keep it outside the disposable repository target/ directory.
EOF
}

if (( $# != 1 )); then
  usage >&2
  exit 2
fi
if [[ $1 == -h || $1 == --help ]]; then
  usage
  exit 0
fi

OUTPUT_DIR=$(release_absolute_from_root "$1")
OUTPUT_PARENT=$(dirname -- "$OUTPUT_DIR")
OUTPUT_NAME=$(basename -- "$OUTPUT_DIR")
[[ $OUTPUT_NAME != . && $OUTPUT_NAME != .. && -n $OUTPUT_NAME ]] || \
  release_die "invalid output directory: $OUTPUT_DIR"
mkdir -p -- "$OUTPUT_PARENT"
OUTPUT_PARENT=$(release_canonical_directory "$OUTPUT_PARENT")
OUTPUT_DIR="$OUTPUT_PARENT/$OUTPUT_NAME"
[[ ! -e $OUTPUT_DIR && ! -L $OUTPUT_DIR ]] || \
  release_die "output directory already exists: $OUTPUT_DIR"

STAGING_DIR="$OUTPUT_PARENT/.$OUTPUT_NAME.generating.$$"
[[ ! -e $STAGING_DIR && ! -L $STAGING_DIR ]] || \
  release_die "staging path already exists: $STAGING_DIR"
CURRENT_STAGE=initialization

on_error() {
  local status=$?
  if (( status != 0 )); then
    printf '\nFAILED during: %s\n' "$CURRENT_STAGE" >&2
    if [[ -e $STAGING_DIR ]]; then
      printf 'Partial generator output was preserved at: %s\n' "$STAGING_DIR" >&2
    fi
  fi
  exit "$status"
}
trap on_error EXIT

release_require_command cargo
release_require_command rustc
release_require_command sed

cd "$RELEASE_ROOT_DIR"
release_build_pack_tools 1

CURRENT_STAGE='canonical HistoryStep matrix generation'
printf '\n==> Generating B64/m23 and B255/m24 matrices at zstd level 19\n'
NOID_ARTIFACT_ZSTD_LEVEL=19 "$RELEASE_MATRIX_GENERATOR" "$STAGING_DIR"

CURRENT_STAGE='pack authentication'
printf '\n==> Authenticating generated artifacts and deriving release pins\n'
release_validate_pack_layout "$STAGING_DIR" 0
release_compute_pack_pins "$STAGING_DIR"
release_write_pin_file "$STAGING_DIR"
release_write_sha256_manifest "$STAGING_DIR"
release_authenticate_pack "$STAGING_DIR" 1

CURRENT_STAGE='atomic pack publication'
mv -- "$STAGING_DIR" "$OUTPUT_DIR"

CURRENT_STAGE=complete
printf '\nSUCCESS\n'
printf '  canonical pack: %s\n' "$OUTPUT_DIR"
printf '  pins:           %s\n' "$OUTPUT_DIR/pins.env"
printf '  checksums:      %s\n' "$OUTPUT_DIR/SHA256SUMS"
