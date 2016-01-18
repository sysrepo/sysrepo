[![Build Status](https://travis-ci.org/sysrepo/sysrepo.svg)](https://travis-ci.org/sysrepo/sysrepo)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7479/badge.svg)](https://scan.coverity.com/projects/sysrepo-sysrepo)
[![codecov.io](https://codecov.io/github/sysrepo/sysrepo/coverage.svg?branch=master)](https://codecov.io/github/sysrepo/sysrepo?branch=master)
[![GitHub license](https://img.shields.io/github/license/sysrepo/sysrepo.svg)](https://github.com/sysrepo/sysrepo/blob/master/LICENSE)

## Status
- Dec 2015: working on the first milestone - internal infrastructure, get-config functionality

## Before install
Install following libraries that sysrepo depends on:

###CMocka
(for unit-tests only)
```
$ git clone git://git.cryptomilk.org/projects/cmocka.git
$ cd cmocka
$ git checkout tags/cmocka-1.0.1
$ mkdir build; cd build
$ cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
$ make
# make install
```

###LibYang
```
# apt-get install libpcre3-dev
$ git clone https://github.com/CESNET/libyang.git
$ cd libyang; mkdir build; cd build
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
$ make
# make install
```

###Google protocol buffers
```
# apt-get install autoconf libtool
$ git clone https://github.com/google/protobuf.git
$ cd protobuf
$ ./autogen.sh
$ ./configure --prefix=/usr
$ make
# make install
```

###Protobuf-c
```
$ git clone https://github.com/protobuf-c/protobuf-c.git
$ cd protobuf-c
$ ./autogen.sh && ./configure --prefix=/usr 
$ make 
# make install
```

## How to build
```
# apt-get install git cmake doxygen valgrind libavl-dev
$ git clone https://github.com/sysrepo/sysrepo.git
$ cd sysrepo
$ mkdir build; cd build
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
$ make
```
To run the test execute following command in build directory
```
ctest
```
Doxygen documentation can be genareted using
```
make doc
```

## Repository structure

## Other
To generte eclipse project
```cmake -G"Eclipse CDT4 - Unix Makefiles" -D CMAKE_BUILD_TYPE=Debug ../<sysrepo-dir>```

File->Import->General->Existing projects into Workspace
```
http://www.cthing.com/CMakeEd.asp
cd /usr/share/cmake-2.8/Modules/
```

