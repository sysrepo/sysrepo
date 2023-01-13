#!/bin/bash
set -ex

version=`pkg-config --modversion sysrepo`
echo "$version" | grep '2\.[0-9.]\+'
