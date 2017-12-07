#!/bin/ash

mkdir /var/run
mkdir /var/lock

adduser netconf -D
echo "netconf:netconf" | chpasswd

ash /etc/uci-defaults/95_libsysrepo
ash /etc/uci-defaults/97_netopeer2-keystored
ash /etc/uci-defaults/99_netopeer2-server

sysrepoctl -i -g /etc/sysrepo/yang/ietf-interfaces@2014-05-08.yang
sysrepoctl -i -g /etc/sysrepo/yang/iana-if-type.yang
sysrepoctl -i -g /etc/sysrepo/yang/ietf-ip@2014-06-16.yang
sysrepocfg -i /etc/sysrepo/ietf-interfaces.data.xml -f xml -d startup ietf-interfaces

sysrepod
sysrepo-plugind
netopeer2-server

/bin/application_example ietf-interfaces
