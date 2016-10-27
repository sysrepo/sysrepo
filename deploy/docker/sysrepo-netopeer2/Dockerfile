FROM ubuntu:16.04

MAINTAINER raszabo@cisco.com

RUN apt-get update && apt-get install -y \
	# general tools
	git \
        cmake \
        build-essential \
	vim \
	supervisor \
	# libyang
	libpcre3-dev \
	# sysrepo 
	libavl-dev \
	libev-dev \
	libprotobuf-c-dev \
	protobuf-c-compiler \
        # netopeer2 \
        libssh-dev \
        libssl-dev \
        # bindings
        swig \
        python-dev

# add netconf user
RUN \
	adduser --system netconf && \
	echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
RUN \
	mkdir -p /home/netconf/.ssh && \
	ssh-keygen -A && \
	ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
	cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# libyang
RUN \
	git clone https://github.com/CESNET/libyang.git && \
	cd libyang && mkdir build && cd build && \
	cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
	make -j2 && \
	make install && \
	ldconfig 

# sysrepo
RUN \
        git clone https://github.com/sysrepo/sysrepo.git && \
        cd sysrepo && mkdir build && cd build && \
        cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo .. && \
        make -j2 && \
        make install && \
        ldconfig

# libssh
RUN \
        git clone http://git.libssh.org/projects/libssh.git && \
        cd libssh && mkdir build && cd build && \
        cmake .. && \
        make -j2 && \
        make install && \
        ldconfig

# libnetconf2
RUN \
        git clone https://github.com/CESNET/libnetconf2.git && \
        cd libnetconf2 && mkdir build && cd build && \
        cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
        make -j2 && \
        make install && \
        ldconfig

# netopeer2
RUN \
        git clone https://github.com/CESNET/Netopeer2.git && \
        cd Netopeer2/server && mkdir build && cd build && \
        cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
        make -j2 && \
        make install && \
        cd ../../cli && mkdir build && cd build && \
        cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
        make -j2 && \
        make install

ENV EDITOR vim
EXPOSE 6001

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
