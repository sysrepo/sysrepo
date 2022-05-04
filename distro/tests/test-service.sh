#!/bin/bash
set -ex

systemctl list-unit-files | grep 'sysrepo-plugind'
