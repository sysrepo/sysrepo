#!/bin/bash
set -ex

version=`sysrepoctl --version`
echo "$version" | grep 'v2\.[0-9.]\+'
