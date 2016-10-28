# Docker image with Sysrepo & Netopeer2 setup

Run `sysrepod` and `netopeer2-server` in the container:
```
docker run -it --name sysrepo --rm sysrepo/sysrepo-netopeer2:latest
```

Connect to the NETCONF server via SSH to port `6001` (username / password is `netconf`):
```
docker inspect sysrepo | grep -w "IPAddress"
# assuming output of the above commnd is 172.17.0.2
ssh netconf@172.17.0.2 -p 6001 -s netconf 
```

In order to get running config via the SSH session use the following snippet:
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
sysrepocfg turing-machine
```

You can also connect to the NETCONF server via [testconf](https://hub.docker.com/r/sysrepo/testconf/):
```
docker run -it --link sysrepo --rm sysrepo/testconf:latest
```

asciinema demo:

[![demo](https://asciinema.org/a/05cdmz78fhcl5jeo4xyiqqr33.png)](https://asciinema.org/a/05cdmz78fhcl5jeo4xyiqqr33?autoplay=1)
