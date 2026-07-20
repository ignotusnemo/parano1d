#!/usr/bin/env bash

# Shared, source-only helpers for ParanO(1)d release tooling.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  printf 'error: scripts/release_common.sh must be sourced, not executed\n' >&2
  exit 2
fi

RELEASE_ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly RELEASE_ROOT_DIR

release_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

release_require_command() {
  command -v "$1" >/dev/null 2>&1 || release_die "required command not found: $1"
}

release_absolute_from_root() {
  local path=$1
  if [[ $path = /* || $path =~ ^[A-Za-z]:[/\\] ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$RELEASE_ROOT_DIR" "$path"
  fi
}

release_canonical_directory() {
  local path=$1
  [[ -d $path && ! -L $path ]] || release_die "not a regular directory: $path"
  (CDPATH= cd -- "$path" && pwd -P)
}

release_sha256_file() {
  local path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$path" | sed 's/[[:space:]].*$//'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$path" | sed 's/[[:space:]].*$//'
  else
    release_die "required SHA-256 tool not found (sha256sum or shasum)"
  fi
}

release_validate_pack_layout() {
  local pack_root=$1
  local require_manifest=${2:-0}
  local entry artifact name
  local root_entries=()
  local version_entries=()
  local expected_files=(
    history-step.runtime
    history-step-c00.field-r1cs.zst
    history-step-c01.field-r1cs.zst
  )

  [[ -d $pack_root && ! -L $pack_root ]] || \
    release_die "HistoryStep pack is not a regular directory: $pack_root"
  [[ -d $pack_root/v1 && ! -L $pack_root/v1 ]] || \
    release_die "HistoryStep pack is missing its regular v1 directory: $pack_root/v1"

  for name in "${expected_files[@]}"; do
    artifact="$pack_root/v1/$name"
    [[ -f $artifact && -s $artifact && ! -L $artifact ]] || \
      release_die "HistoryStep artifact is missing, empty, or a symlink: $artifact"
  done

  shopt -s nullglob dotglob
  version_entries=("$pack_root/v1"/*)
  root_entries=("$pack_root"/*)
  shopt -u nullglob dotglob

  (( ${#version_entries[@]} == 3 )) || \
    release_die "HistoryStep v1 must contain exactly three artifacts"
  for entry in "${version_entries[@]}"; do
    [[ -f $entry && ! -L $entry ]] || \
      release_die "unexpected non-regular HistoryStep v1 entry: $entry"
    case "$(basename -- "$entry")" in
      history-step.runtime|history-step-c00.field-r1cs.zst|history-step-c01.field-r1cs.zst) ;;
      *) release_die "unexpected HistoryStep v1 entry: $entry" ;;
    esac
  done

  for entry in "${root_entries[@]}"; do
    case "$(basename -- "$entry")" in
      v1)
        [[ -d $entry && ! -L $entry ]] || \
          release_die "HistoryStep v1 entry is not a regular directory"
        ;;
      pins.env|SHA256SUMS)
        [[ -f $entry && -s $entry && ! -L $entry ]] || \
          release_die "pack metadata is empty, non-regular, or a symlink: $entry"
        ;;
      *) release_die "unexpected HistoryStep pack entry: $entry" ;;
    esac
  done

  if [[ $require_manifest == 1 ]]; then
    [[ -f $pack_root/pins.env && ! -L $pack_root/pins.env ]] || \
      release_die "publishable pack is missing pins.env"
    [[ -f $pack_root/SHA256SUMS && ! -L $pack_root/SHA256SUMS ]] || \
      release_die "publishable pack is missing SHA256SUMS"
    (( ${#root_entries[@]} == 3 )) || \
      release_die "publishable pack must contain only v1, pins.env, and SHA256SUMS"
  fi
}

release_read_pin_file() {
  local pin_file=$1
  local line
  local line_count=0
  local metadata_digest=
  local leaf_digests=

  [[ -f $pin_file && ! -L $pin_file ]] || release_die "invalid pin file: $pin_file"
  while IFS= read -r line || [[ -n $line ]]; do
    (( line_count += 1 ))
    case "$line" in
      NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=*)
        [[ -z $metadata_digest ]] || release_die "duplicate runtime metadata pin in $pin_file"
        metadata_digest=${line#*=}
        ;;
      NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=*)
        [[ -z $leaf_digests ]] || release_die "duplicate matrix leaf pins in $pin_file"
        leaf_digests=${line#*=}
        ;;
      *) release_die "unexpected line in $pin_file" ;;
    esac
  done < "$pin_file"

  (( line_count == 2 )) || release_die "$pin_file must contain exactly two assignments"
  [[ $metadata_digest =~ ^[0-9a-f]{64}$ ]] || \
    release_die "runtime metadata pin in $pin_file is not 64 lowercase hex characters"
  [[ $leaf_digests =~ ^[0-9a-f]{128}$ ]] || \
    release_die "matrix leaf pins in $pin_file are not two lowercase hex digests"

  RELEASE_FILE_METADATA_DIGEST=$metadata_digest
  RELEASE_FILE_LEAF_DIGESTS=$leaf_digests
}

release_write_pin_file() {
  local pack_root=$1
  local pin_file="$pack_root/pins.env"
  local temporary="$pin_file.tmp.$$"

  [[ ${RELEASE_METADATA_DIGEST:-} =~ ^[0-9a-f]{64}$ ]] || \
    release_die "cannot write pins.env without a computed runtime metadata digest"
  [[ ${RELEASE_LEAF_DIGESTS:-} =~ ^[0-9a-f]{128}$ ]] || \
    release_die "cannot write pins.env without two computed matrix digests"
  printf 'NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=%s\n' \
    "$RELEASE_METADATA_DIGEST" > "$temporary"
  printf 'NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=%s\n' \
    "$RELEASE_LEAF_DIGESTS" >> "$temporary"
  mv -- "$temporary" "$pin_file"
}

release_verify_sha256_manifest() {
  local pack_root=$1
  local manifest="$pack_root/SHA256SUMS"
  local line digest path actual
  local index=0
  local expected_paths=(
    v1/history-step.runtime
    v1/history-step-c00.field-r1cs.zst
    v1/history-step-c01.field-r1cs.zst
    pins.env
  )

  [[ -f $manifest && ! -L $manifest ]] || release_die "invalid SHA256SUMS: $manifest"
  while IFS= read -r line || [[ -n $line ]]; do
    (( index < ${#expected_paths[@]} )) || release_die "too many entries in $manifest"
    [[ $line =~ ^([0-9a-f]{64})[[:space:]][[:space:]](.+)$ ]] || \
      release_die "malformed SHA-256 line in $manifest"
    digest=${BASH_REMATCH[1]}
    path=${BASH_REMATCH[2]}
    [[ $path == "${expected_paths[$index]}" ]] || \
      release_die "unexpected SHA-256 path in $manifest: $path"
    actual=$(release_sha256_file "$pack_root/$path")
    [[ $actual == "$digest" ]] || release_die "SHA-256 mismatch for $pack_root/$path"
    (( index += 1 ))
  done < "$manifest"
  (( index == ${#expected_paths[@]} )) || release_die "missing entries in $manifest"
}

release_write_sha256_manifest() {
  local pack_root=$1
  local manifest="$pack_root/SHA256SUMS"
  local temporary="$manifest.tmp.$$"
  local path digest
  local paths=(
    v1/history-step.runtime
    v1/history-step-c00.field-r1cs.zst
    v1/history-step-c01.field-r1cs.zst
    pins.env
  )

  : > "$temporary"
  for path in "${paths[@]}"; do
    digest=$(release_sha256_file "$pack_root/$path")
    printf '%s  %s\n' "$digest" "$path" >> "$temporary"
  done
  mv -- "$temporary" "$manifest"
}

release_tool_executable() {
  local name=$1
  local suffix=
  case "$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')" in
    *-windows-*) suffix=.exe ;;
  esac
  printf '%s/release/%s%s\n' "$RELEASE_TOOL_TARGET_DIR" "$name" "$suffix"
}

release_build_pack_tools() {
  local include_generator=${1:-0}
  local build_args=(--bin noid_pack_pins)

  release_require_command cargo
  release_require_command rustc
  release_require_command tr
  RELEASE_TOOL_TARGET_DIR=${NOID_RELEASE_TOOL_TARGET_DIR:-$RELEASE_ROOT_DIR/target/release-tools}
  if [[ $include_generator == 1 ]]; then
    build_args+=(--bin noid_matrix_gen)
  fi

  printf '\n==> Building release pack tools\n'
  (
    unset CARGO_BUILD_TARGET CARGO_ENCODED_RUSTFLAGS
    unset NOID_HISTORY_STEP_PACK_DIR
    unset NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST
    unset NOID_HISTORY_STEP_PACK_LEAF_DIGESTS
    export CARGO_TARGET_DIR="$RELEASE_TOOL_TARGET_DIR"
    export RUSTFLAGS='-C target-cpu=native'
    cd "$RELEASE_ROOT_DIR"
    cargo build --locked --release -p bench_prover "${build_args[@]}"
  )

  RELEASE_PIN_TOOL=$(release_tool_executable noid_pack_pins)
  [[ -x $RELEASE_PIN_TOOL ]] || release_die "pin tool was not built: $RELEASE_PIN_TOOL"
  if [[ $include_generator == 1 ]]; then
    RELEASE_MATRIX_GENERATOR=$(release_tool_executable noid_matrix_gen)
    [[ -x $RELEASE_MATRIX_GENERATOR ]] || \
      release_die "matrix generator was not built: $RELEASE_MATRIX_GENERATOR"
  fi
}

release_compute_pack_pins() {
  local pack_root=$1
  local output metadata_digest leaf_digests

  [[ -x ${RELEASE_PIN_TOOL:-} ]] || release_die "release pin tool is unavailable"
  output=$("$RELEASE_PIN_TOOL" "$pack_root")
  output=${output//$'\r'/}
  printf '%s\n' "$output"
  metadata_digest=$(
    printf '%s\n' "$output" |
      sed -n 's/^NOID_HISTORY_STEP_RUNTIME_METADATA_RELEASE_DIGEST=//p'
  )
  leaf_digests=$(
    printf '%s\n' "$output" |
      sed -n 's/^NOID_HISTORY_STEP_PACK_LEAF_DIGESTS=//p'
  )
  [[ $metadata_digest =~ ^[0-9a-f]{64}$ ]] || \
    release_die "computed runtime metadata pin is not 64 lowercase hex characters"
  [[ $leaf_digests =~ ^[0-9a-f]{128}$ ]] || \
    release_die "computed matrix pins are not two lowercase hex digests"

  RELEASE_METADATA_DIGEST=$metadata_digest
  RELEASE_LEAF_DIGESTS=$leaf_digests
}

release_authenticate_pack() {
  local pack_root=$1
  local require_manifest=${2:-0}

  release_validate_pack_layout "$pack_root" "$require_manifest"
  if [[ -f $pack_root/SHA256SUMS ]]; then
    release_verify_sha256_manifest "$pack_root"
  fi
  release_compute_pack_pins "$pack_root"
  if [[ -f $pack_root/pins.env ]]; then
    release_read_pin_file "$pack_root/pins.env"
    [[ $RELEASE_FILE_METADATA_DIGEST == "$RELEASE_METADATA_DIGEST" ]] || \
      release_die "pins.env runtime metadata digest does not match the pack"
    [[ $RELEASE_FILE_LEAF_DIGESTS == "$RELEASE_LEAF_DIGESTS" ]] || \
      release_die "pins.env matrix digests do not match the pack"
  elif [[ $require_manifest == 1 ]]; then
    release_die "publishable pack is missing pins.env"
  fi
}

release_workspace_version() {
  local node_pkg extminer_pkg node_version extminer_version

  release_require_command tr
  node_pkg=$(cd "$RELEASE_ROOT_DIR" && cargo pkgid -p noid_node | tr -d '\r')
  extminer_pkg=$(cd "$RELEASE_ROOT_DIR" && cargo pkgid -p noid-extminer | tr -d '\r')
  if [[ $node_pkg == *@* ]]; then
    node_version=${node_pkg##*@}
  else
    node_version=${node_pkg##*#}
  fi
  if [[ $extminer_pkg == *@* ]]; then
    extminer_version=${extminer_pkg##*@}
  else
    extminer_version=${extminer_pkg##*#}
  fi
  [[ $node_version =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || \
    release_die "cannot determine noid_node version from: $node_pkg"
  [[ $node_version == "$extminer_version" ]] || \
    release_die "node version $node_version differs from external miner version $extminer_version"
  RELEASE_VERSION=$node_version
}
