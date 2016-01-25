[![Build Status](https://travis-ci.org/sysrepo/sysrepo.svg)](https://travis-ci.org/sysrepo/sysrepo)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7479/badge.svg)](https://scan.coverity.com/projects/sysrepo-sysrepo)
[![codecov.io](https://codecov.io/github/sysrepo/sysrepo/coverage.svg?branch=master)](https://codecov.io/github/sysrepo/sysrepo?branch=master)
[![GitHub license](https://img.shields.io/badge/license-Apache%20license%202.0-blue.svg)](https://github.com/sysrepo/sysrepo/blob/master/LICENSE)

## Sysrepo
Sysrepo provides [YANG](http://tools.ietf.org/html/rfc6020)-based datastore functionality for Unix/Linux applications. 

Applications can use sysrepo to store their configuration modeled by provided YANG model instead of using e.g. flat configuration files. Sysrepo will ensure data consistency of the data stored in the datastore and enforce data constraints defined by YANG model. Applications can currently use [C language API](inc/sysrepo.h) of sysrepo Client Library to access their configuration, but the support of other programming languages is planed for later too.

Sysrepo can be easily integrated to management agents such as [NETCONF](https://tools.ietf.org/html/rfc6241) or [RESTCONF](https://tools.ietf.org/html/draft-ietf-netconf-restconf) servers, using the same API that applications use to access their configuration. As of now, integration to [Netopeer NETCONF server](https://github.com/cesnet/netopeer) is in progress. This way, applications that use sysrepo to store their configuration will automatically benefit from ability to control the application via NETCONF.

![Sysrepo Architecture](doc/high_level_architecture.png)

## Status
- January 2016: get-config functionality ready, see Client Library API header file [inc/sysrepo.h](inc/sysrepo.h)
- December 2015: implementation of the first milestone started - building internal infrastructure, get-config functionality

## Features
- ability to store / retrieve YANG-modeled data elements adressed by XPath
- data consistency and constraint enforecment according to YANG model (with help of [libyang](https://github.com/cesnet/libyang) library)
- no single point of failure design (client library is able to prerform most of the data-access operations also by itself, whithout the need of contacting any system daemon)
- (TODO) full transaction and concurrency support with ACID properties
- (TODO) notifications of subscribed applications about the changes made in the datastore
- (TODO) ability to subscribe to notifications as a verifier and validate the changes before they are committed
- (TODO) plugins architecture for applications that cannot use sysrepo to store their configuration, but still want to be manageable via sysrepo
- (TODO) operational data support (publishing of application's state data to sysrepo)
- (TODO) [NACM](https://tools.ietf.org/html/rfc6536) (NETCONF Access Control Model)
- (TODO) custom RPC support
- (TODO) [NETCONF Event Notifications](https://tools.ietf.org/html/rfc5277) support
- (TODO) bindings for other programming languages

## Build & Installation Steps
See [INSTALL.md](INSTALL.md) file, which contains detailed build and installation steps.

## Usage Examples
See [examples](examples) directory, which contains an example per each data-acess API function.

Also see our [fork of dnsmasq](https://github.com/sysrepo/dnsmasq-sysrepo) that uses sysrepo to store its configuration for short demonstration of how sysrepo can be integrated into an existing application ([see the diff](https://github.com/sysrepo/dnsmasq-sysrepo/commit/39ce80b6eae1d155af3b20f195c1e13efbc9094a)).

## Documentation
Client Library API, as well as all internal modules of sysrepo are extensively documented with Doxygen comments. To read the documentation, [run Doxygen build](INSTALL.md) and open the documentation index file doc/html/index.html.

## Other Resources
- [Sysrepo Project WIKI](http://www.sysrepo.org/)
- CESNET's [libyang](https://github.com/cesnet/libyang) YANG toolkit
- CESNET's [Netopeer](https://github.com/cesnet/netopeer) NETCONF Toolset
- [RFC 6020](http://tools.ietf.org/html/rfc6020) (YANG Data Modeling Language)
- [RFC 6241](https://tools.ietf.org/html/rfc6241) (Network Configuration Protocol - NETCONF)
