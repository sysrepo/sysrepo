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

# run sysrepoctl so that a connection is created and repository and SHM initialized (ideally as a non-privileged user)
if [ $(id -u) -eq 0 ] && [ -n "$USER" ] && [ $(command -v su) ]; then
    su -c "$SYSREPOCTL -L" -l $USER
else
    "$SYSREPOCTL" -L > /dev/null
fi
