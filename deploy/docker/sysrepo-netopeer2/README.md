# Docker image with Sysrepo & Netopeer2 setup

Run `netopeer2-server` in the container:
```
docker run -it --name sysrepo -p 830:830 --rm sysrepo/sysrepo-netopeer2:latest
```

Connect to the NETCONF server via SSH to port `830` (username / password is `netconf`):
```
ssh netconf@<docker_container_ip> -p 830 -s netconf
```

You can get the IP from the docker container with:
```
docker inspect sysrepo | grep -w "IPAddress"
```

In order to get running config via the SSH session use the following snippet. Paste this into the terminal where the ssh connection was esstablished:
```
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
	<capabilities>
		<capability>urn:ietf:params:neconf:base:1.0</capability>
		<capability>urn:ietf:params:netconf:base:1.1</capability>
		<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
		<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>
	</capabilities>
</hello>
]]>]]>

#139
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<get-config>
	<source>
		<running />
	</source>
</get-config>
</rpc>
##
```

To access `sysrepoctl` or `sysrepocfg` exec bash in the container:
```
docker exec -it sysrepo /bin/bash
sysrepoctl -l
sysrepocfg -E -f xml -d running -m <module_to_configure>
```

You can also connect to the NETCONF server via [testconf](https://hub.docker.com/r/sysrepo/testconf/):
```
docker run -it --link sysrepo --rm sysrepo/testconf:latest
```
