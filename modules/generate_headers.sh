#!/bin/env bash

for YANG_FILE in *.yang; do
    # generate HEX
    HEX=$(echo "$(cat "$YANG_FILE")" | xxd -i)

    # generate array name
    ARRAY_NAME="$(echo "$YANG_FILE" | cut -f1 -d"@" | tr - _)_yang"

    if [ ${YANG_FILE:0:17} = "ietf-yang-library" ]; then
        # generate header file name with the revision
        HEADER_FILE="$(echo "$YANG_FILE" | tr .- _).h"
    else
        # generate header file name without the revision
        HEADER_FILE="${ARRAY_NAME}.h"
    fi

    # print into a C header file
    echo -e "char ${ARRAY_NAME}[] = {\n$HEX, 0x00\n};" > "$HEADER_FILE"
done
