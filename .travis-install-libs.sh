#!/bin/sh
set -e

INSTALL_PREFIX_DIR=$HOME/local
export PKG_CONFIG_PATH=$INSTALL_PREFIX_DIR/lib/pkgconfig:$PKG_CONFIG_PATH

# check to see if cache folder is empty
if [ ! -d "$INSTALL_PREFIX_DIR/lib" ]; then
    echo "Building all libraries."
    cd ~

    # CMocka
    git clone git://git.cryptomilk.org/projects/cmocka.git
    cd cmocka ; mkdir build; cd build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX_DIR ..
    make -j2 && make install
    cd ../..

    # protobuf 
    git clone https://github.com/google/protobuf.git
    cd protobuf
    ./autogen.sh && ./configure --prefix=$INSTALL_PREFIX_DIR 
    make -j2 && make install
    cd ..

    # protobuf-c
    git clone https://github.com/protobuf-c/protobuf-c.git
    cd protobuf-c
    ./autogen.sh && ./configure --prefix=$INSTALL_PREFIX_DIR
    make -j2 && make install
    cd ..

else
    echo "Using cached libraries from $INSTALL_PREFIX_DIR"
fi

# libraries that we don't want to cache

# libyang
git clone https://github.com/CESNET/libyang.git
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILD_TESTS=OFF ..
make -j2 && sudo make install
cd ../..

