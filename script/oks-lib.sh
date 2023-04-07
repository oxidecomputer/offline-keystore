#!/usr/bin/env bash
# functions common to oks scripts

CD_DEV=/dev/cdrom

error() {
    >&2 command echo ["$(date --utc +%FT%TZ)" ERROR "${0##*/}"] "$@"
}

info() {
    command echo ["$(date --utc +%FT%TZ)" INFO "${0##*/}"] "$@"
}

# check that a given command is on PATH, if not exit 1
command_on_path() {
    if ! command -v "$1" &> /dev/null; then
        error "missing required command: $1"
        exit 1
    fi
}

command_on_path sha256sum
command_on_path isoinfo
command_on_path dd
command_on_path sed
command_on_path awk

# implement common error handling for commands executed
fail_with_stderr() {
    local ERR_LOG
    ERR_LOG=$(mktemp)

    echo "executing \"$*\""
    if ! "$@" 2> "$ERR_LOG"; then
        error "failed command: \"$*\"\nwith stderr:"
        >&2 cat "$ERR_LOG"
        rm "$ERR_LOG"
        exit 1
    fi
    rm "$ERR_LOG"
}

cd_sha256() {
    local DEVICE=$1
    local TMP_DIR=$2

    # get hash of iso we just burned
    ISOINFO_OUT=$TMP_DIR/isoinfo.log
    fail_with_stderr isoinfo -d -i "$DEVICE" > "$ISOINFO_OUT"
    
    BLOCK_SIZE=$(sed -n 's/^Logical block size is: \([0-9]\+\)/\1/p' \
        "$ISOINFO_OUT")
    BLOCK_COUNT=$(sed -n 's/^Volume size is: \([0-9]\+\)/\1/p' \
        "$ISOINFO_OUT")
    
    dd if=$CD_DEV bs="$BLOCK_SIZE" count="$BLOCK_COUNT" status=none \
        | sha256sum \
        | awk '{print $1}'
}
