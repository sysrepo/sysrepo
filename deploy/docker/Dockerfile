FROM ubuntu:16.04
MAINTAINER raszabo@cisco.com

RUN apt-get update && apt-get install -y \
	# general tools
	git \
        cmake \
        build-essential \
	vim \
	#libyang
	libpcre3-dev \
	# sysrepo 
	libavl-dev \
	libev-dev \
	libprotobuf-c-dev \
	protobuf-c-compiler \
        # bindings
        swig \
        python-dev \
	# tests
	libcmocka-dev \
	valgrind 

RUN \
	git clone https://github.com/CESNET/libyang.git ; \
	cd libyang ; mkdir build ; cd build ; \
	cmake -DCMAKE_BUILD_TYPE=Debug .. ; \
	make -j2 ; \
	make install

RUN \
        git clone https://github.com/sysrepo/sysrepo.git ; \
        cd sysrepo ; mkdir build ; cd build ; \
        cmake -DCMAKE_BUILD_TYPE=Debug .. ; \
        make -j2 ; \
        make install

CMD ["/usr/bin/sysrepod"]
