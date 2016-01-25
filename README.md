[![Build Status](https://travis-ci.org/sysrepo/sysrepo.svg)](https://travis-ci.org/sysrepo/sysrepo)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7479/badge.svg)](https://scan.coverity.com/projects/sysrepo-sysrepo)
[![codecov.io](https://codecov.io/github/sysrepo/sysrepo/coverage.svg?branch=master)](https://codecov.io/github/sysrepo/sysrepo?branch=master)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/sysrepo/sysrepo/blob/master/LICENSE)

Sysrepo provides [YANG](http://tools.ietf.org/html/rfc6020)-based datastore functionality for Unix/Linux applications. Applications can use sysrepo to store their configuration modeled by provided YANG model instead of using e.g. flat configuration files. Sysrepo will ensure data consistency of the data stored in the datastore and enforce data constraints defined by YANG model. Applications can currently use [C language API](inc/sysrepo.h) of sysrepo to access their configuration, but the support of other programming languages is planed for later too.

Sysrepo can be easily integrated to management agents such as [NETCONF](https://tools.ietf.org/html/rfc6241) or [RESTCONF](https://tools.ietf.org/html/draft-ietf-netconf-restconf) servers, using the same API that applications use to access their configuration (see the picture below). As of now, integration to [Netopeer NETCONF server](https://github.com/cesnet/netopeer) is in progress. This way, applications that use sysrepo to store their configuration will automatically benefit from ability to control the application via NETCONF.

## Status
- January 2016: get-config functionality ready, see public API header file [inc/sysrepo.h](inc/sysrepo.h)
- December 2015: working on the first milestone - internal infrastructure, get-config functionality

## Features


## Installation Steps
See [INSTALL.md](INSTALL.md) file, which contains detailed installation steps.

## Usage examples
See [examples](examples) directory, which contains an example per each data-acess API function.

Also see our [fork of dnsmasq](https://github.com/sysrepo/dnsmasq-sysrepo) that uses sysrepo to store its configuration for short demonstration of how sysrepo can be integrated into an existing application.

## Other Resources
- [Sysrepo Project WIKI](http://www.sysrepo.org/)
- CESNET's [libyang](https://github.com/cesnet/libyang) YANG toolkit
- CESNET's [Netopeer](https://github.com/cesnet/netopeer) NETCONF Toolset
- [RFC 6020](http://tools.ietf.org/html/rfc6020) (YANG Data Modeling Language)
- [RFC 6241](https://tools.ietf.org/html/rfc6241) (Network Configuration Protocol - NETCONF)
