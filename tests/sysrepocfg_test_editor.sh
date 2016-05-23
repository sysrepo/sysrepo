#!/bin/sh

set -x

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

# Overwrite the current config with whatever was prepared by sysrepocfg_test
cp sysrepocfg_test-new_config.txt  $1
