#!/bin/bash

SCRIPTSDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
BASEDIR="$SCRIPTSDIR/.."

IP="${1:-127.0.0.1}"
CMD="$BASEDIR/bin/node"

if [ "$2" = "debug" ]; then
    CMD="$BASEDIR/bin/node"
fi

# TODO(mark)
# These settings cause the node to connect
# to itself and then ban itself. Needs to
# be fixed. See swaps-net logs.

$CMD --memory true \
    --network regtest \
    --host "$IP" \
    --brontide-host "$IP" \
    --http-host "$IP" \
    --rs-host "$IP" \
    --ns-host "$IP" \
    --wallet-http-host "$IP" \
    --api-key foo \
    --listen true \
    --memory true \
    --max-inbound 8

