brew update
brew install protobuf-c
brew install libev
brew install pcre

# CMocka
git clone git://git.cryptomilk.org/projects/cmocka.git
cd cmocka ; mkdir build; cd build
cmake ..
make -j2 && make install
cd ../..

git clone https://github.com/CESNET/libyang.git
cd libyang ; mkdir build ; cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_BUILD_TESTS=OFF ..
make -j2 && sudo make install
cd ../..

#libredblack
git clone https://github.com/sysrepo/libredblack.git
cd libredblack; ./configure && make && make install
