#!/bin/sh
set -e

COREFILES=$(find . -name "core*")

for CORE in ${COREFILES}
do
    echo -e "\n\n>>> Core file '${CORE}' was found: "
    EXE=$(file $CORE | sed -n "s/^.*, from '\(.\+\)'$/\1/p")
    gdb -ex "core ${CORE}" -ex "thread apply all bt" -batch --args ${EXE}
done
