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
Install required libraries:
```
$ apt-get install git cmake doxygen valgrind libavl-dev libev-dev
```
1) Get the source code and prepare build directory:
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
$ cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr -DREPOSITORY_LOC:PATH=/etc/sysrepo ..
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
