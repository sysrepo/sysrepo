#!/bin/sh

while true;
do
        sleep 60;
        TEST=$(ps -ef | grep _test | grep -v "grep\|valgrind\|defunct\|gdb\|ctest\|timeout")
        PID=$(echo ${TEST} | awk '{ print $2 }')
        EXE=$(echo ${TEST} | awk '{ print $8 }')
        if [ ! -z "$PID" ];
        then
            echo; echo "Backtrace for ${EXE} (pid=${PID}):";
            (cd tests; gdb -ex "attach ${PID}" -ex "thread apply all bt" -batch --args ${EXE} </dev/null)
        fi
done
