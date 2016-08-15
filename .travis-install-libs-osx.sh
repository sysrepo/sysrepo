#install dependencies using homebrew
brew update
brew install protobuf-c
brew install libev
brew install pcre

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
    cmake ..
    make -j2 && make install
    cd ../..

    #libredblack
    git clone https://github.com/sysrepo/libredblack.git
    cd libredblack; ./configure && make && make install
else
    echo "Using cached libraries from $INSTALL_PREFIX_DIR"
fi

git clone -b devel https://github.com/CESNET/libyang.git
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILD_TESTS=OFF ..
make -j2 && sudo make install
cd ../..
