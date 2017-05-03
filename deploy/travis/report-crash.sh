#!/bin/sh
set -e

COREFILES=$(find . -name "core*")

for CORE in ${COREFILES}
do
    echo -e "\n\n>>> Core file '${CORE}' was found: "
    sudo chmod +r "${CORE}"
    EXE=$(file $CORE | sed -n "s/^.*, from '\(.\+\)'$/\1/p")
    # Note: ${EXE} may be an absolute path or a path relative to the tests sub-directory
    (cd tests; gdb -ex "core ../${CORE}" -ex "thread apply all bt" -batch --args ${EXE})
done
