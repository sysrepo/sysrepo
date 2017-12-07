#!/bin/bash

cd /opt/golang/netconf_tests

go get github.com/BurntSushi/toml
go get github.com/sartura/go-netconf/netconf
go run goconf.go
