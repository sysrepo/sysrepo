#!/bin/bash
set -e

# get running diretory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# build the base dockerfile
(cd "$DIR" &&
docker build -t sysrepo/sysrepo-netopeer2:openwrt_base -f dockerfiles/Dockerfile.openwrt_base .
)

# build dockerfile with the latest changes in sysrepo/netopeer2
(cd "$DIR" &&
docker build --no-cache -t sysrepo/sysrepo-netopeer2:openwrt_test -f dockerfiles/Dockerfile.openwrt_test .
)

docker run --name tmp_openwrt_image sysrepo/sysrepo-netopeer2:openwrt_test /bin/true
docker cp tmp_openwrt_image:/home/openwrt/openwrt/bin/targets/x86/generic/openwrt-x86-generic-generic-rootfs.tar.gz .
cat openwrt-x86-generic-generic-rootfs.tar.gz | docker import - sysrepo/sysrepo-netopeer2:openwrt_run
rm openwrt-x86-generic-generic-rootfs.tar.gz
docker rm tmp_openwrt_image

# create docker network
docker network create --subnet=172.77.0.0/16 openwrtSysrepoNetwork

# run the docker container
docker run -d -v "$DIR":/opt --name openwrt_run --network openwrtSysrepoNetwork --ip 172.77.0.77 --rm sysrepo/sysrepo-netopeer2:openwrt_run ash /opt/dockerfiles/openwrt_entrypoint.sh

# run the NETCONF tests
(cd "$DIR" &&
docker run -i -t -v "$DIR":/opt/golang --name golang --network openwrtSysrepoNetwork --rm golang:1.8  bash -c /opt/golang/netconf_tests/run.sh
)

# stop the docker container
docker stop openwrt_run

# destroy docker network
docker network rm openwrtSysrepoNetwork
