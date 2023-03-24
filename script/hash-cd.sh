#!/usr/bin/sh

set -e

# This script calculates the hash of the ISO FS on a CD or DVD.

. oks-lib.sh

TMP_DIR=$(mktemp --directory)
trap 'rm -rf -- "$TMP_DIR"' EXIT

HASH=$(cd_sha256 "$CD_DEV" "$TMP_DIR")
echo "CD in \"$CD_DEV\" hash \"sha256-$HASH\""
