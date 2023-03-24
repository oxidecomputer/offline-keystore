# functions common to oks scripts

CD_DEV=/dev/cdrom

# check that a given command is on PATH, if not exit 1
command_on_path() {
    if ! command -v $1 &> /dev/null; then
        >&2 echo "ERROR: missing required command: $1"
        exit 1
    fi
}

command_on_path sha256sum
command_on_path isoinfo
command_on_path dd
command_on_path sed
command_on_path awk

# Execute a command, if it fails display a message and exit 1.
# The first parameter is an error message, everything after is passed
# directly to the shell. All output from the command executed is discarded.
fail_with_msg() {
    local MSG=$1
    shift

    # catching error output in a temp file would be nice
    $@
    if [ $? -ne 0 ]; then
        >&2 echo "ERROR: $MSG"
        exit 1
    fi
}

cd_sha256() {
    local DEVICE=$1
    local TMP_DIR=$2

    # get hash of iso we just burned
    ISOINFO_OUT=$TMP_DIR/isoinfo.log
    fail_with_msg \
        "failed to get isoinfo for device: \"$DEVICE\"" \
        isoinfo -d -i $DEVICE > $ISOINFO_OUT
    
    BLOCK_SIZE=$(sed -n 's/^Logical block size is: \([0-9]\+\)/\1/p' \
        $ISOINFO_OUT)
    BLOCK_COUNT=$(sed -n 's/^Volume size is: \([0-9]\+\)/\1/p' \
        $ISOINFO_OUT)
    
    dd if=$CD_DEV bs=$BLOCK_SIZE count=$BLOCK_COUNT status=none \
        | sha256sum \
        | awk '{print $1}'
}
