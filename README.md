# Sysrepo

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Website](https://img.shields.io/website?down_color=lightgrey&down_message=offline&up_color=blue&up_message=online&url=https%3A%2F%2Fwww.sysrepo.org%2F)](https://www.sysrepo.org/)
[![Build](https://github.com/sysrepo/sysrepo/workflows/sysrepo%20CI/badge.svg)](https://github.com/sysrepo/sysrepo/actions?query=workflow%3A%22sysrepo+CI%22)
[![Docs](https://img.shields.io/badge/docs-link-blue)](https://netopeer.liberouter.org/doc/sysrepo/)
[![Coverity](https://scan.coverity.com/projects/7479/badge.svg)](https://scan.coverity.com/projects/sysrepo-sysrepo)
[![Codecov](https://codecov.io/gh/sysrepo/sysrepo/branch/master/graph/badge.svg?token=tsZ6WOOMNz)](https://codecov.io/gh/sysrepo/sysrepo)

Sysrepo is a [YANG](http://tools.ietf.org/html/rfc7950)-based configuration and operational state data store for Unix/Linux applications.

Applications can use sysrepo to store their configuration modeled by provided YANG model instead of using e.g. flat configuration files. Sysrepo will ensure data consistency of the data stored in the datastore and enforce data constraints defined by YANG model. Applications can currently use [C language API](inc/sysrepo.h) of sysrepo Client Library to access the configuration in the datastore, but the support for other programming languages is planed for later, too.

Sysrepo can be easily integrated with management agents such as [NETCONF](https://tools.ietf.org/html/rfc6241) or [RESTCONF](https://tools.ietf.org/html/rfc8040) servers, using the same client library API that applications use to access their configuration. As of now, sysrepo is integrated with the [Netopeer 2 NETCONF server](https://github.com/CESNET/Netopeer2). This means that applications that use sysrepo to store their configuration can automatically benefit from the ability to being controlled via NETCONF.

## Branches

The project uses 2 main branches `master` and `devel`. Other branches should not be cloned. In `master` there are files of the
last official *release*. Any latest improvements and changes, which were tested at least briefly are found in `devel`. On every
new *release*, `devel` is merged into `master`.

This means that when only stable official releases are to be used, either `master` can be used or specific *releases* downloaded.
If all the latest bugfixes should be applied, `devel` branch is the  one to be used. Note that whenever **a new issue is created**
and it occurs on the `master` branch, the **first response will likely be** to use `devel` before any further provided support.

## Compatibility Between Versions

When upgrading Sysrepo to a newer major SO version, look into the `compatibility` directory for a summary of changes.
Each directory describes the changes between the specific SO versions. Be aware that they do not match project versions.

## Provided Features

* Ability to store / retrieve YANG-modeled data elements adressed by XPath
* Startup, running, candidate, and operational datastore support
* Data consistency and constraints enforcement according to YANG models
* No single point of failure design (is just a library)
* Full transaction and concurrency support
* Notifications of subscribed applications about the changes made in the datastore
* Commit verifiers (change verification by subscribed applications)
* Operational data support (publishing of application's state/configuration data to sysrepo)
* YANG 1.1 support
* Custom RPC, Event Notifications, YANG 1.1 Actions support
* Notification store & notification replay
* Factory Default Datastore support (RFC 8808)

## Packages

Binary RPM or DEB packages of the latest release can be built locally using `apkg`, look into `README` in
the `distro` directory.

## Security Notes

Sysrepo does not have any master process that could enforce complex access control. So instead, it relies on and
utilizes standard file system permissions but there are some things to bear in mind.

To prevent any sensitive data from being accessible by unauthorized processes, it is imperative to **always
set correct permissions and owner** for all YANG modules being installed. The utility `sysrepoctl` can help
with both displaying all the permissions (`--list`) and modifying them (`--change <module>`) in addition
to this functionality being available in the API.

Having made certain of this, the default configuration should be suitable for a reasonably secure machine
that has no malicious running processes. Specifically, it is trivial for such a process to completely break
sysrepo by writing into shared files that must be accessible for all the processes linked with sysrepo. Also,
with some reverse engineering, it may even be possible to access data by an unathorized process when they are being
communicated in these shared files.

In order to avoid all such security issues, there are 2 `cmake` variables `SYSREPO_UMASK` and `SYSREPO_GROUP`
that should be adjusted. Generally, a new system group should be created and set for `SYSREPO_GROUP` and then
all outside access frobidden by setting `SYSREPO_UMASK` to `00007`. If then all the users executing sysrepo
processes belong to this group, none of sysrepo files and no sensitive information should be accessible to
other users.

## Requirements

### Build Requirements

* C compiler (gcc >= 4.8.4, clang >= 3.0, ...)
* cmake >= 2.8.12
* [libyang](https://github.com/CESNET/libyang)
* tar(1)

#### Optional

* pkg-config & libsystemd (to support `sysrepo-plugind` systemd service)
* doxygen (for generating documentation)
* cmocka >= 1.0.1 (for tests only, see [Tests](#Tests))
* valgrind (for enhanced testing)
* gcov (for code coverage)
* lcov (for code coverage)
* genhtml (for code coverage)

## Building

```
$ mkdir build; cd build
$ cmake ..
$ make
# make install
```

### Plugin development documentation

Another markdown document aimed at plugin developers is available in [plugin_dev_doc.md](./plugin_dev_doc.md).
The goal of the document is to provide a single place where a complete overview of information required to
start developing plugins is available.
The document describes the basics of Sysrepo plugin development and the technologies required to work with
Sysrepo like YANG, XPath, NETCONF and others.

### Useful CMake sysrepo Options

Set custom repository path:
```
-DREPO_PATH=/opt/sysrepo/my_repository
```

Set custom `sysrepo` DS and NTF plugins path:
```
-DSR_PLUGINS_PATH=/opt/sysrepo/plugins
```

Set custom `sysrepo-plugind` plugins path:
```
-DSRPD_PLUGINS_PATH=/opt/sysrepo-plugind/plugins
```

Set global `umask` for all sysrepo file and directory creation:
```
-DSYSREPO_UMASK=00007
```

Set system group to own all sysrepo-related files:
```
-DSYSREPO_GROUP=sysrepo
```

Set `systemd` system service unit path:
```
-DSYSTEMD_UNIT_DIR=/usr/lib/systemd/system
```

Set [NACM](#NACM) recovery username with unrestricted access:
```
-DNACM_RECOVERY_USER=root
```

Set [NACM](#NACM) configuration data and 'sysrepo-monitoring' default permissions:
```
-DNACM_SRMON_DATA_PERM=000
```

Set `startup` and `factory-default` datastore data for internal modules (such as `ietf-netconf-acm`):
```
-DINTERNAL_MODULE_DATA_PATH=/etc/config/factory_default_config.xml
```
### Useful CMake Build Options

#### Changing Compiler

Set `CC` variable:

```
$ CC=/usr/bin/clang cmake ..
```

#### Changing Install Path

To change the prefix where the library, headers and any other files are installed,
set `CMAKE_INSTALL_PREFIX` variable:
```
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
```

Default prefix is `/usr/local`.

#### Build Modes

There are two build modes:
* Release.
  This generates library for the production use without any debug information.
* Debug.
  This generates library with the debug information and disables optimization
  of the code.

The `Debug` mode is currently used as the default one. to switch to the
`Release` mode, enter at the command line:
```
$ cmake -D CMAKE_BUILD_TYPE:String="Release" ..
```

#### Code Coverage

Based on the tests run, it is possible to generate code coverage report. But
it must be enabled and these commands are needed to generate the report:
```
$ cmake -DENABLE_COVERAGE=ON ..
$ make
$ make coverage
```

## Usage

All basic Sysrepo functions are available via the main header:

```C
#include <sysrepo.h>
```

To compile your program with libsysrepo, it is necessary to link it using the
following linker parameters:
```
-lsysrepo
```

Note, that it may be necessary to call `ldconfig(8)` after library installation and if the
library was installed into a non-standard path, the path to it must be specified to the
linker. To help with setting all the compiler's options, there is `sysrepo.pc` file for
`pkg-config(1)` available in the source tree. The file is installed with the library.

## Utils

There are additional utility functions available as part of Sysrepo but their headers need to be
included manually. They are:
```C
#include <sysrepo/error_format.h>
```
Implements basic creation and retrieval of well-known Sysrepo errors generated by callbacks. Currently, the
only supported error format is NETCONF.

```C
#include <sysrepo/netconf_acm.h>
```
NETCONF Access Control Module with configuration data in *ietf-netconf-acm* YANG module is implemented
as part of *sysrepo*. By default, no users other than the recovery user (default `root`) will be allowed
to *write* any data but should be granted *read* and *execute* permissions unless the access was modified
by a NACM extension.

```C
#include <sysrepo/subscribed_notifications.h>
```
This header provides additional functionality to simplify implementing *ietf-subscribed-notifications* and
*ietf-yang-push* YANG modules. But these modules need to be installed manually and can be found with all
their imports in `modules/subscribed_notifications`.

```C
#include <sysrepo/values.h>
```
Utility header for working with `sr_val_t` Sysrepo value structures. Note that these are generally
considered deprecated and *libyang* `struct lyd_node` should be used instead.

```C
#include <sysrepo/xpath.h>
```
More complex handling of XPath expressions that has lots of features at the cost of efficiency.

### Used run-time enviromental variables

It is possible to change the repository path by setting `SYSREPO_REPOSITORY_PATH` variable.
Also, if `SYSREPO_SHM_PREFIX` is defined, it is used for all SHM files created. This way
everal *sysrepo* instances can effectively be run simultanously on one machine.

## Factory Default

The `factory-default` datastore contents of a module are automatically populated by the initial data used
when installing the specific module and **cannot** be changed (unless the module is reinstalled). There is
an internal subscription to the `/ietf-factory-default:factory-reset` RPC which performs the copying of
`factory-default` data into all the other datastores. This RPC has a priority 10 so applications are
able to subscribe to it with higher or lower priority and perform any other tasks required for a device
to be rest to its factory settings.

## Examples

See [examples](examples) directory, which contains an example for basic API functions.

## Bindings

There are no bindings for other languages directly in this project but they are
available separately.

* [Python](https://github.com/sysrepo/sysrepo-python/)
* [C++](https://github.com/sysrepo/sysrepo-cpp/)

## Tests

There are several tests included and built with [cmocka](https://cmocka.org/). The tests
can be found in `tests` subdirectory and they are designed for checking library
functionality after code changes.

The tests are by default built in the `Debug` build mode by running
```
$ make
```

In case of the `Release` mode, the tests are not built by default (it requires
additional dependency), but they can be enabled via cmake option:
```
$ cmake -DENABLE_TESTS=ON ..
```

Note that if the necessary [cmocka](https://cmocka.org/) headers are not present
in the system include paths, tests are not available despite the build mode or
cmake's options.

Tests can be run by the make's `test` target:
```
$ make test
```

### Perf

There is a performance measurement tool included that prints information about
the time required to execute common use-cases of working with large YANG instance data.

To enable this test, use an option and to get representative results, enable Release build type:
```
$ cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PERF_TESTS=ON ..
```
and to run the test with seeing its output run:
```
$ make
$ ctest -V -R sr_perf
```
