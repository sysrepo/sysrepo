#!/bin/sh
set -e

INSTALL_PREFIX_DIR=$HOME/local
export PKG_CONFIG_PATH=$INSTALL_PREFIX_DIR/lib/pkgconfig:$PKG_CONFIG_PATH

sudo apt-get update -qq
sudo apt-get install -y libavl-dev libev-dev valgrind swig python-dev gdb
pip install --user codecov
echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca-certificates.crt

# check to see if cache folder is empty
if [ ! -d "$INSTALL_PREFIX_DIR/lib" ]; then
    echo "Building all libraries."
    cd ~

    # CMocka
    git clone git://git.cryptomilk.org/projects/cmocka.git
    cd cmocka ; mkdir build; cd build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX_DIR -DCMAKE_C_FLAGS="-DUNIT_TESTING_DEBUG" ..
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
if [[ "$TRAVIS_BRANCH" -eq "devel" ]]; then
    git clone -b devel https://github.com/CESNET/libyang.git
else
    git clone https://github.com/CESNET/libyang.git
fi
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILD_TESTS=OFF ..
make -j2 && sudo make install
cd ../..

