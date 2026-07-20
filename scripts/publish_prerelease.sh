#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=release_common.sh
source "$SCRIPT_DIR/release_common.sh"

usage() {
  cat <<'EOF'
Usage: ./scripts/publish_prerelease.sh VERSION PACK_DIR

From a clean main branch synchronized with origin/main, authenticate the
canonical HistoryStep pack, create and push vVERSION, open a draft GitHub
release, attach the normalized pack, and dispatch the five-platform native
release workflow. The workflow publishes the prerelease only after every
native bundle has built and uploaded successfully.

Example:
  ./scripts/publish_prerelease.sh 0.0.1 \
    /home/neo/rust/paranoid-artifacts/history-step-v1
EOF
}

if (( $# != 2 )); then
  usage >&2
  exit 2
fi
if [[ $1 == -h || $1 == --help ]]; then
  usage
  exit 0
fi

VERSION=$1
PACK_DIR=$(release_absolute_from_root "$2")
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || \
  release_die "VERSION must be a semantic version without a leading v"
TAG="v$VERSION"
TITLE="ParanO(1)d $TAG"
NOTES_FILE="$RELEASE_ROOT_DIR/.github/release-notes/$TAG.md"
PACK_ASSET=history-step-pack-v1.tar.gz
WORKFLOW=release.yml

release_require_command cargo
release_require_command gh
release_require_command git
release_require_command gzip
release_require_command mktemp
release_require_command sed
release_require_command tar

[[ -f $NOTES_FILE && ! -L $NOTES_FILE ]] || \
  release_die "release notes are missing: $NOTES_FILE"
PACK_DIR=$(release_canonical_directory "$PACK_DIR")

cd "$RELEASE_ROOT_DIR"
[[ $(git rev-parse --show-toplevel) == "$RELEASE_ROOT_DIR" ]] || \
  release_die "run this command from the ParanO(1)d repository"
[[ $(git branch --show-current) == main ]] || \
  release_die "prereleases may be published only from main"
[[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || \
  release_die "main must be completely clean before publication"

printf '==> Synchronizing release authority with origin/main\n'
git fetch --prune origin main
LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git rev-parse origin/main)
[[ $LOCAL_HEAD == "$REMOTE_HEAD" ]] || \
  release_die "local main is not identical to origin/main"

release_workspace_version
[[ $RELEASE_VERSION == "$VERSION" ]] || \
  release_die "requested version $VERSION differs from workspace version $RELEASE_VERSION"

if git show-ref --verify --quiet "refs/tags/$TAG"; then
  release_die "local tag already exists: $TAG"
fi
set +e
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1
REMOTE_TAG_STATUS=$?
set -e
case "$REMOTE_TAG_STATUS" in
  0) release_die "remote tag already exists: $TAG" ;;
  2) ;;
  *) release_die "could not determine whether remote tag $TAG exists" ;;
esac
if gh release view "$TAG" >/dev/null 2>&1; then
  release_die "GitHub release already exists: $TAG"
fi
gh auth status >/dev/null

release_build_pack_tools 0
printf '\n==> Authenticating publishable HistoryStep pack\n'
release_authenticate_pack "$PACK_DIR" 1

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  release_die "prerelease publication requires GNU tar for a normalized pack archive"
fi

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/paranoid-release.XXXXXX")
cleanup() {
  local status=$?
  if [[ -d $TEMP_DIR && $TEMP_DIR == "${TMPDIR:-/tmp}"/paranoid-release.* ]]; then
    rm -r -- "$TEMP_DIR" || true
  fi
  exit "$status"
}
trap cleanup EXIT

NORMALIZED_ROOT="$TEMP_DIR/history-step-pack-v1"
mkdir -- "$NORMALIZED_ROOT"
cp -R -- "$PACK_DIR/v1" "$NORMALIZED_ROOT/v1"
cp -- "$PACK_DIR/pins.env" "$NORMALIZED_ROOT/pins.env"
cp -- "$PACK_DIR/SHA256SUMS" "$NORMALIZED_ROOT/SHA256SUMS"
PACK_ARCHIVE="$TEMP_DIR/$PACK_ASSET"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || \
  release_die "SOURCE_DATE_EPOCH must be a non-negative integer"
tar -C "$TEMP_DIR" \
  --sort=name \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  --mtime="@$SOURCE_DATE_EPOCH" \
  -cf - history-step-pack-v1 |
  gzip -n -9 > "$PACK_ARCHIVE"
PACK_SHA256=$(release_sha256_file "$PACK_ARCHIVE")

printf '\nRelease candidate\n'
printf '  commit:       %s\n' "$LOCAL_HEAD"
printf '  tag:          %s\n' "$TAG"
printf '  title:        %s\n' "$TITLE"
printf '  matrix pack:  %s\n' "$PACK_ARCHIVE"
printf '  pack SHA-256: %s\n' "$PACK_SHA256"

printf '\n==> Creating and pushing annotated release identity\n'
git tag -a "$TAG" -m "$TITLE"
git push origin "refs/tags/$TAG"

printf '\n==> Creating draft release and uploading the canonical pack\n'
gh release create "$TAG" "$PACK_ARCHIVE" \
  --verify-tag \
  --draft \
  --title "$TITLE" \
  --notes-file "$NOTES_FILE"

printf '\n==> Dispatching five-platform native release workflow\n'
WORKFLOW_URL=$(gh workflow run "$WORKFLOW" \
  --ref "$TAG" \
  -f "tag=$TAG" \
  -f "pack_sha256=$PACK_SHA256")

printf '\nDISPATCHED\n'
printf 'The GitHub release remains a draft until all five native builds succeed.\n'
if [[ -n $WORKFLOW_URL ]]; then
  printf 'Workflow: %s\n' "$WORKFLOW_URL"
  printf 'Watch: gh run watch %s --exit-status\n' "${WORKFLOW_URL##*/}"
else
  printf 'Watch: gh run list --workflow %s --limit 1\n' "$WORKFLOW"
fi
printf 'Release: gh release view %s --web\n' "$TAG"
