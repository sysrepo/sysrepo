#!/usr/bin/env bash

# get path to sysrepoctl executable, this will be stored in $SYSREPOCTL
if [ -n "$SYSREPOCTL_EXECUTABLE" ]; then
    SYSREPOCTL="$SYSREPOCTL_EXECUTABLE"
elif [ $(id -u) -eq 0 ] && [ -n "$USER" ] && [ $(command -v su) ]; then
    SYSREPOCTL=$(su -c 'command -v sysrepoctl' -l "$USER")
else
    SYSREPOCTL=$(command -v sysrepoctl)
fi

if [ -z "$SYSREPOCTL" ]; then
    echo "$0: Unable to find sysrepoctl executable." >&2
    exit 1
fi

# modules to uninstall (in reverse order of their dependencies)
MODULES=(
"ietf-subscribed-notif-receivers"
"ietf-subscribed-notifications"
)

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

function UNINSTALL_MODULE_QUIET() {
    "$SYSREPOCTL" -u $1 &> /dev/null
}

function UNINSTALL_CMD() {
    for name in "${MODULES[@]}"; do
        sctl_module=$(echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I")
        if [ -n "$sctl_module" ]; then
            # uninstall module and ignore the result, there may be other modules depending on it
            UNINSTALL_MODULE_QUIET "$name"
        fi
    done
}

UNINSTALL_CMD
