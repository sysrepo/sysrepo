# Requirements

* docker

# Run

```
$ cd . # cd to this folder
$ ./build_and_run_on_ubuntu.sh # for end to end tests on Ubuntu
$ ./build_and_run_on_openwrt.sh # fore end to end tests on OpenWrt
```

## Warnings

1) Run one script at a time because the IP address is manually assigned.
2) The first run is longer because the base docker images are being build.
3) The OpenWrt base image is 10Gb big.
3) Every next script run will fetch the latest changes from master branch and run the tests.

## NETCONF tests

1) The NETCONF tests are run with [go-netconf](https://github.com/Juniper/go-netconf).
2) A simple toml [config](./netconf_tests/config/ietf-interfaces.toml) file is use to define the tests.
