#!/usr/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -e

# restore backup files to new YubiHSM
# assumptions:
# YubiHSM is in its default state (fresh out of the box)
# wrap key (used to encrypt other exported keys) is in file wrap.key encoded as hex
# auth key (export-wrapped) is in file auth.enc base64 encoded

DEFAULT_WRAP_FILE=wrap.key
DEFAULT_AUTH_FILE=auth.enc

print_usage ()
{
    cat <<END
Usage: $0
    Restore an authentication key that's been export-wrap'd with the provided wrap key.
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
if [ ! -f $WRAP_FILE ]; then
    2> echo "path provided for wrap key does not exist"
    exit 1
fi
if [ -z ${AUTH_FILE+x} ]; then
    AUTH_FILE=$DEFAULT_AUTH_FILE
fi
if [ ! -f $AUTH_FILE ]; then
    2> echo "path provided for auth wrap does not exist"
    exit 1
fi

IFS= read -s -p 'Enter password for auth key being restored: ' PASSWD

# default auth key
DEFAULT_PASSWD=password
DEFAULT_AUTH_ID=1

# put previously export-wrapped auth key
WRAP_ID=1
WRAP_LABEL=backup
WRAP_DOMAINS=all
WRAP_CAPABILITIES=all
WRAP_DELEGATED=all
WRAP_FORMAT=hex
yubihsm-shell --password $DEFAULT_PASSWD --authkey $DEFAULT_AUTH_ID \
    --action put-wrap-key --object-id $WRAP_ID --domains $WRAP_DOMAINS \
    --capabilities $WRAP_CAPABILITIES --delegated $WRAP_DELEGATED \
    --label $WRAP_LABEL --in $WRAP_FILE --informat $WRAP_FORMAT

# import previously export-wrapped auth key
AUTH_ID=2
yubihsm-shell --password $DEFAULT_PASSWD --authkey $DEFAULT_AUTH_ID \
    --action put-wrapped --wrap-id $WRAP_ID --object-id $AUTH_ID \
    --object-type authentication-key --in $AUTH_FILE --informat base64

# delete default auth key
yubihsm-shell --password $PASSWD --authkey $AUTH_ID \
   --action delete-object --object-id $DEFAULT_AUTH_ID \
   --object-type authentication-key
