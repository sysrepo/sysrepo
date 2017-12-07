#!/bin/bash
set -e

# get running diretory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# build the base dockerfile
(cd "$DIR" &&
docker build -t sysrepo/sysrepo-netopeer2:ubuntu_base -f dockerfiles/Dockerfile.ubuntu_base .
)

# build dockerfile with the latest changes in sysrepo/netopeer2
(cd "$DIR" &&
docker build --no-cache -t sysrepo/sysrepo-netopeer2:ubuntu_test -f dockerfiles/Dockerfile.ubuntu_test .
)

# create docker network
docker network create --subnet=172.77.0.0/16 ubuntuSysrepoNetwork

# run the docker container
docker run -d --name ubuntu_test --network ubuntuSysrepoNetwork --ip 172.77.0.77 --rm sysrepo/sysrepo-netopeer2:ubuntu_test

# run the NETCONF tests
(cd "$DIR" &&
docker run -i -t -v "$DIR":/opt/golang --name golang --network ubuntuSysrepoNetwork --rm golang:1.8  bash -c /opt/golang/netconf_tests/run.sh
)

# stop the docker container
docker stop ubuntu_test

# destroy docker network
docker network rm ubuntuSysrepoNetwork
