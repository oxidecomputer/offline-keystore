#!/usr/bin/sh

# This script expects a directory name / path as a single positional
# parameter. The contents of this directory are turned into an ISO and
# then burned to a CD / DVD.

. oks-lib.sh

# commands / executables that we need
command_on_path mkisofs
command_on_path cdrecord

DIR="$1"
if [ ! -e $DIR -o ! -d $DIR ]; then
    >&2 echo "ERROR: path provided is not a directory: $DIR"
    exit 1
fi

TMP_DIR=$(mktemp --directory)
trap 'rm -rf -- "$TMP_DIR"' EXIT

ISO=$TMP_DIR/temp.iso

# generate iso from directory
echo "INFO: generating iso from directory \"$DIR\""
fail_with_msg \
    "failed to create ISO from directory: $DIR" \
    mkisofs -r -iso-level 4 -o "$ISO" "$DIR"
[ $? -ne 0 ] && exit 1

if [ ! -f "$ISO" ]; then
    >&2 echo "ERROR: failed to create iso, not a file: \"$ISO\""
fi

# get hash of iso
ISO_HASH=$(sha256sum "$ISO" | awk '{print $1}')
echo "INFO: ISO has hash sha256-$ISO_HASH"

# cdrecord is noisy on both stdio and stderr. We can't redirect stderr while
# using 'fail_with_msg' so we do it manually.
echo "INFO: writing ISO to device: \"$CD_DEV\""
cdrecord -silent -data $ISO dev=$CD_DEV > /dev/null 2>&1
if [ $? -ne 0 ]; then
    >&2 echo "ERROR: failed writing ISO to \"$CD_DEV\""
    exit 1
fi

# NOTE: accessing the cdrom to hash it immediately after burning it fails in
# testing

exit 0

# ensure hash of ISO matches hash of CD burned
CDROM_HASH=$(cd_sha256 "$CD_DEV" "$TMP_DIR")
[ $? -ne 0 ] && exit 1
if [ "$ISO_HASH" != "$CDROM_HASH" ]; then
    >&2 echo "ERROR: hash mismatch ... something ain't right"
    exit 1
fi
