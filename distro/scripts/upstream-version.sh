#!/usr/bin/env bash
# get latest upstream sysrepo version from github

RLS_URL=https://api.github.com/repos/sysrepo/sysrepo/releases
VERSION=$(curl -s $RLS_URL | grep tag_name | cut -d '"' -f 4 | sort --version-sort | tail -n 1)
VERSION=${VERSION#v}
echo $VERSION
