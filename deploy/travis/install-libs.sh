#!/bin/sh
set -e

INSTALL_PREFIX_DIR=$HOME/local
export PKG_CONFIG_PATH=$INSTALL_PREFIX_DIR/lib/pkgconfig:$PKG_CONFIG_PATH

sudo apt-get install --reinstall ca-certificates
sudo apt-get install software-properties-common # add-apt-repository tool
sudo apt-get update -qq
sudo apt-get install -y --force-yes libavl-dev libev-dev valgrind coreutils python-dev gdb acl
sudo dpkg -i ./deploy/travis/swig3.0_3.0.8-0ubuntu3_amd64.deb
pip install --user codecov
echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca-certificates.crt

# check to see if cache folder is empty
if [ ! -d "$INSTALL_PREFIX_DIR/lib" ]; then
    echo "Building all libraries."
    cd ~

    # CMocka
    wget https://cmocka.org/files/1.1/cmocka-1.1.2.tar.xz
    tar -xf cmocka-1.1.2.tar.xz
    cd cmocka-1.1.2; mkdir build; cd build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX_DIR -DCMAKE_C_FLAGS="-DUNIT_TESTING_DEBUG" ..
    make -j2 > /dev/null && make install
    cd ../..

    # protobuf
    wget https://github.com/google/protobuf/archive/v3.2.0.tar.gz
    tar -xzf v3.2.0.tar.gz
    cd protobuf-3.2.0
    ./autogen.sh && ./configure --prefix=$INSTALL_PREFIX_DIR
    make -j2 > /dev/null && make install
    cd ..

    # protobuf-c
    wget https://github.com/protobuf-c/protobuf-c/archive/v1.2.1.tar.gz
    tar -xzf v1.2.1.tar.gz
    cd protobuf-c-1.2.1
    ./autogen.sh && ./configure --prefix=$INSTALL_PREFIX_DIR
    make -j2 > /dev/null && make install
    cd ..

else
    echo "Using cached libraries from $INSTALL_PREFIX_DIR"
fi

# libraries that we don't want to cache

# libyang
if [[ (( "$TRAVIS_BRANCH" == *"master"* )) || (( "$TRAVIS_TAG" =~ "v"[0-9]+"."[0-9]+"."[0-9]+ )) ]]; then
    git clone https://github.com/CESNET/libyang.git
else
    git clone -b devel https://github.com/CESNET/libyang.git
fi
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILD_TESTS=OFF ..
make -j2 > /dev/null && sudo make install
cd ../..

