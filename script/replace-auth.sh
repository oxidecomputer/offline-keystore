#!/usr/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -e

DEFAULT_WRAP_FILE=wrap.key
DEFAULT_AUTH_FILE=auth.enc

print_usage ()
{
    cat <<END
Usage: $0
    [ --auth-file - file containing auth key exported under '--wrap-file' (DEFAULT: $DEFAULT_WRAP_FILE) ]
    [ --wrap-file - file containing hex encoded wrap key (DEFAULT: $DEFAULT_AUTH_FILE ]
    [ -h | --help  ]
END

    exit 2
}

print_help ()
{
    print_usage
    exit 0
}

usage_error ()
{
    >&2 echo "$1"
    print_usage
    exit 2
}

while test $# -gt 0; do
    case $1 in
    -a|--auth-file) AUTH_FILE=$2; shift;;
    -a=*|--auth-file=*) AUTH_FILE="${1#*=}";;
    -w|--wrap-file) WRAP_FILE=$2; shift;;
    -w=*|--wrap-file=*) WRAP_FILE="${1#*=}";;
    -f|--force) FORCE=1;;
    -h|--help) print_help; exit $?;;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done
 
if [ -z ${WRAP_FILE+x} ]; then
    WRAP_FILE=$DEFAULT_WRAP_FILE
fi
if [ -f $WRAP_FILE -a -z ${FORCE+x} ]; then
    2> echo "path provided for wrap key already exists, use -f to overwrite"
    exit 1
fi
if [ -f $WRAP_FILE ]; then
    rm $WRAP_FILE
fi

if [ -z ${AUTH_FILE+x} ]; then
    AUTH_FILE=$DEFAULT_AUTH_FILE
fi
if [ -f $AUTH_FILE -a -z ${FORCE+x} ]; then
    2> echo "path provided for auth wrap already exists, use -f to overwrite"
    exit 1
fi
if [ -f $AUTH_FILE ]; then
    rm $AUTH_FILE
fi

# default auth key
DEFAULT_PASSWD=password
DEFAULT_AUTH_ID=1
# new auth key
AUTH_ID=2
AUTH_LABEL="admin"

# get new password for auth key
IFS= read -s -p 'Enter new auth password: ' PASSWD

# create new auth key
yubihsm-shell --password $DEFAULT_PASSWD --authkey $DEFAULT_AUTH_ID \
    --action put-authentication-key --object-id $AUTH_ID --domains all \
    --capabilities all --delegated all --label $AUTH_LABEL \
    --new-password $PASSWD

# delete default auth key w/ well known password
yubihsm-shell --password $PASSWD --authkey $AUTH_ID \
    --action delete-object --object-id $DEFAULT_AUTH_ID \
    --object-type authentication-key

## create a wrap key 
## NOTE: this wrap key is a mock of the wrap key created by yubihsm-split
WRAP_ID=1
#WRAP_LABEL="backup"
## wrap key is aes256
#WRAP_SIZE=32
#if [ ! -e $WRAP_FILE ]; then
#    yubihsm-shell --password $PASSWD --authkey $AUTH_ID \
#        --action get-pseudo-random --count $WRAP_SIZE --out $WRAP_FILE
#fi
#yubihsm-shell --password $PASSWD --authkey $AUTH_ID \
#    --action put-wrap-key --object-id $WRAP_ID \
#    --algorithm aes256-ccm-wrap \
#    --domain all --capabilities all --delegated all --label $WRAP_LABEL \
#    --in $WRAP_FILE --informat hex

# backup auth key using the wrap key
yubihsm-shell --password $PASSWD --authkey $AUTH_ID \
    --action get-wrapped --wrap-id $WRAP_ID --object-id $AUTH_ID \
    --object-type authentication-key --out $AUTH_FILE --outformat base64
