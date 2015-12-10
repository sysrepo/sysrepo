
## Before install

###LibYang
- sudo apt-get install libpcre3-dev
- git clone https://github.com/CESNET/libyang.git
- cd libyang; mkdir build; cd build
- cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
- make
- sudo make install

###CMocka

- git clone git://git.cryptomilk.org/projects/cmocka.git
- cd cmocka
- git checkout tags/cmocka-1.0.1
- mkdir build; cd build
- cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
- make
- sudo make install

## How to build
- sudo apt-get install git cmake doxygen valgrind
- git clone https://github.com/lukasmacko/sr.git
- cd sr
- mkdir build
- cd build
- cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
- make
- ctest
- make doc


## Repository structure

## Other
To generte eclipse project
```cmake -G"Eclipse CDT4 - Unix Makefiles" -D CMAKE_BUILD_TYPE=Debug ../<sysrepo-dir>```

File->Import->General->Existing projects into Workspace

http://www.cthing.com/CMakeEd.asp
cd /usr/share/cmake-2.8/Modules/

