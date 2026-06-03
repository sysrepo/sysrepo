#!/usr/bin/env bash

# env variables SR_NOTIFD_MODULE_DIR, SR_NOTIFD_MODULE_PERMS must be defined
# and SR_NOTIFD_MODULE_OWNER, SR_NOTIFD_MODULE_GROUP will be used if defined when executing this script!

if [ -z "$SR_NOTIFD_MODULE_DIR" -o -z "$SR_NOTIFD_MODULE_PERMS" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi

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

MODDIR=${DESTDIR}${SR_NOTIFD_MODULE_DIR}
PERMS=${SR_NOTIFD_MODULE_PERMS}
OWNER=${SR_NOTIFD_MODULE_OWNER}
GROUP=${SR_NOTIFD_MODULE_GROUP}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

# modules to install with their features
MODULES=(
"ietf-subscribed-notifications@2019-09-09.yang -e configured -e replay -e subtree -e xpath"
"ietf-subscribed-notif-receivers@2024-02-01.yang"
"ietf-udp-notif-transport@2025-06-04.yang"
)

# the install command will be stored in this variable
CMD_INSTALL=
# names of newly installed modules (to fix permissions afterwards)
NEW_MODULES=()

function INSTALL_MODULE_CMD() {
    if [ -z "${CMD_INSTALL}" ]; then
        CMD_INSTALL="'$SYSREPOCTL' -s '$1' -v2"
    fi

    CMD_INSTALL="$CMD_INSTALL -i $1/$2 -p '$PERMS'"
    if [ ! -z "${OWNER}" ]; then
        CMD_INSTALL="$CMD_INSTALL -o '$OWNER'"
    fi
    if [ ! -z "${GROUP}" ]; then
        CMD_INSTALL="$CMD_INSTALL -g '$GROUP'"
    fi

    # record the module name for fixing permissions afterwards
    name=$(echo "$2" | sed 's/\([^@]*\).*/\1/')
    NEW_MODULES+=("$name")
}

function ENABLE_FEATURE() {
    "$SYSREPOCTL" -c $1 -e $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function CHANGE_PERMS() {
    CMD="'$SYSREPOCTL' -c $1 -p '$PERMS' -v2"
    if [ ! -z "${OWNER}" ]; then
        CMD="$CMD -o '$OWNER'"
    fi
    if [ ! -z "${GROUP}" ]; then
        CMD="$CMD -g '$GROUP'"
    fi

    eval "$CMD"
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function SETUP_CMD() {
    module_dir="$1"
    shift
    modules=("$@")
    for i in "${modules[@]}"; do
        name=$(echo "$i" | sed 's/\([^@]*\).*/\1/')
        sctl_module=$(echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I")
        if [ -z "$sctl_module" ]; then
            # prepare command to install module with all its features
            INSTALL_MODULE_CMD "$module_dir" "$i"
            continue
        fi

        sctl_owner=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{3\} \([^:]*\).*/\2/')
        sctl_group=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{3\}[^:]*:\([^ ]*\).*/\2/')
        sctl_perms=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{4\} \([^ ]*\).*/\2/')
        if [ "$sctl_perms" != "$PERMS" ] || [ ! -z "${OWNER}" -a "$sctl_owner" != "$OWNER" ] || [ ! -z "${GROUP}" -a "$sctl_group" != "$GROUP" ]; then
            # change permissions/owner
            CHANGE_PERMS "$name"
        fi

        # parse sysrepoctl features and add extra space at the end for easier matching
        sctl_features="`echo "$sctl_module" | sed 's/\([^|]*|\)\{6\}\(.*\)/\2/'` "
        # parse features we want to enable
        features=$(echo "$i" | sed 's/[^ ]* \(.*\)/\1/')
        while [ "${features:0:3}" = "-e " ]; do
            # skip "-e "
            features=${features:3}
            # parse feature
            feature=$(echo "$features" | sed 's/\([^[:space:]]*\).*/\1/')

            # enable feature if not already
            sctl_feature=$(echo "$sctl_features" | grep " ${feature} ")
            if [ -z "$sctl_feature" ]; then
                ENABLE_FEATURE $name $feature
            fi

            # next iteration, skip this feature
            features=$(echo "$features" | sed 's/[^[:space:]]* \(.*\)/\1/')
        done
    done
}

# setup the cmd for install
SETUP_CMD "$MODDIR" "${MODULES[@]}"

# install all the new modules
if [ ! -z "${CMD_INSTALL}" ]; then
    eval $CMD_INSTALL
    rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi

    # fix permissions on newly installed modules (sysrepoctl -i may not properly apply -o/-g)
    for name in "${NEW_MODULES[@]}"; do
        CHANGE_PERMS "$name"
    done
fi
