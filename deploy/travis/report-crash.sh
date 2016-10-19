#!/bin/sh
set -e

COREFILES=$(find . -maxdepth 1 -name "core*")

for CORE in ${COREFILES}
do
    echo "Core file '${CORE}' was found: "
    EXE=$(file $CORE | sed -n "s/^.*, from '\(.\+\)'$/\1/p")
    gdb -ex "core ${CORE}" -ex "thread apply all bt" -batch --args ${EXE}
done
