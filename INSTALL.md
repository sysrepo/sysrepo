## Requirements

#### Build tools:
- compiler: gcc or clang
- build automation tools: make + [cmake](https://cmake.org/)

#### Required libraries:
- [libyang](https://github.com/CESNET/libyang)
- [Google Protocol Buffers](https://github.com/google/protobuf)
- [protobuf-c](https://github.com/protobuf-c/protobuf-c)
- [libev](http://software.schmorp.de/pkg/libev.html)
- [libredblack](http://libredblack.sourceforge.net/) or [GNU libavl](http://adtinfo.org/) (either of these two)

#### Optional tools for running tests and building documentation:
- [CMocka](https://cmocka.org/)
- [valgrind](http://valgrind.org/)
- [doxygen](www.doxygen.org)


#### Installation of required libraries:
On Debian-like Linux distributions:
- `apt-get install cmake libev-dev libavl-dev`
- libyang, Google Protocol Buffers and protobuf-c need to be installed from sources

On FreBSD:
- `pkg install cmake protobuf protobuf-c libev libredblack`
- libyang needs to be installed from sources

On Mac OS X:
- `brew cmake protobuf protobuf-c libev`
- libyang and libredblack need to be installed from sources

## Installation of required libraries from sources

#### LibYang
```
# apt-get install libpcre3-dev
$ git clone https://github.com/CESNET/libyang.git
$ cd libyang; mkdir build; cd build
$ cmake ..
$ make
# make install
```

#### Google Protocol Buffers
```
# apt-get install autoconf libtool
$ git clone https://github.com/google/protobuf.git
$ cd protobuf
$ ./autogen.sh
$ ./configure
$ make
# make install
```

#### Protobuf-c
```
$ git clone https://github.com/protobuf-c/protobuf-c.git
$ cd protobuf-c
$ ./autogen.sh && ./configure --prefix=/usr 
$ make 
# make install
```

#### libredblack
```
$ git clone https://github.com/sysrepo/libredblack.git
$ cd libredblack
$ ./configure
$ make
# make install
```

#### CMocka
```
$ git clone git://git.cryptomilk.org/projects/cmocka.git
$ cd cmocka
$ git checkout tags/cmocka-1.0.1
$ mkdir build; cd build
$ cmake -DCMAKE_BUILD_TYPE=Debug ..
$ make
# make install
```

## Building sysrepo
1) Get the source code and prepare the build directory:
```
$ git clone https://github.com/sysrepo/sysrepo.git
$ cd sysrepo
$ mkdir build; cd build
```
2 a) Configure build for testing and development (Debug build):
```
$ cmake ..
```
2 b) Configure build for production use (Release build):
```
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
```
3) Build:
```
$ make
```
4 a) Run unit tests (applicable only to Debug build)
```
$ ctest
```
4 b) Install (applicable only to Release build)
```
$ make install
```
5) (optional) Build Doxygen documentation:
```
make doc
```
