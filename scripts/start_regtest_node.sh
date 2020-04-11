#!/bin/bash

# Start a

DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
ROOTDIR=$(echo $(cd $DIR/.. && pwd))

NODE="$ROOTDIR/bin/node"

if [ "$1" = "debug" ]; then
    (
        cd $DIR
        FILE=$(sed '1d' $NODE)
        echo "$FILE"
        HSD_NETWORK=regtest HSD_MEMORY=true node debug -e "$FILE"
    )
else
   $NODE --network regtest --memory true
fi

