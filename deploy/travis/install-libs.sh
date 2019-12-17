#!/bin/sh
set -e

INSTALL_PREFIX_DIR=$HOME/local
export PKG_CONFIG_PATH=$INSTALL_PREFIX_DIR/lib/pkgconfig:$PKG_CONFIG_PATH

sudo apt-get install --reinstall ca-certificates
sudo apt-get install software-properties-common # add-apt-repository tool
sudo apt-get update -qq
sudo apt-get install -y --force-yes valgrind coreutils python3-dev libpcre3-dev gdb acl swig libcmocka-dev
pip install --user codecov
echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca-certificates.crt

# libyang
if [[ (( "$TRAVIS_BRANCH" == *"master"* )) || (( "$TRAVIS_TAG" =~ "v"[0-9]+"."[0-9]+"."[0-9]+ )) ]]; then
    git clone https://github.com/CESNET/libyang.git
else
    git clone -b devel https://github.com/CESNET/libyang.git
fi
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DGEN_LANGUAGE_BINDINGS=ON -DENABLE_BUILD_TESTS=OFF ..
make -j2 > /dev/null && sudo make install
cd ../..
