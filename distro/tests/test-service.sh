#!/usr/bin/env bash
set -ex

systemctl list-unit-files | grep 'sysrepo-plugind'
