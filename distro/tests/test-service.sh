#!/bin/bash
set -ex

systemctl list-unit-files | grep 'sysrepo-plugind'

systemctl start sysrepo-plugind
systemctl stop sysrepo-plugind
