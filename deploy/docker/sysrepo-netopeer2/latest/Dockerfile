FROM ubuntu:18.04

# defaults
RUN \
	apt-get update && apt-get install -y \
	git \
	curl \
	wget \
	libssl-dev \
	libtool \
	build-essential \
	vim \
	autoconf \
	automake \
	pkg-config \
	libgtk-3-dev \
	make \
	valgrind \
	doxygen \
	libev-dev \
	libpcre3-dev \
	unzip \
	sudo \
	python3 \
	bison \
	flex \
	swig \
	libcmocka0 \
	libcmocka-dev \
	cmake \
	supervisor

# Adding netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo


# Clearing and setting authorized ssh keys
RUN \
	echo '' > /home/netconf/.ssh/authorized_keys && \
	ssh-keygen -A && \
	ssh-keygen -t rsa -b 4096 -P '' -f /home/netconf/.ssh/id_rsa && \
	cat /home/netconf/.ssh/id_rsa.pub >> /home/netconf/.ssh/authorized_keys


# Updating shell to bash
RUN sed -i s#/home/netconf:/bin/false#/home/netconf:/bin/bash# /etc/passwd

RUN mkdir /opt/dev && sudo chown -R netconf /opt/dev

# set password for user (same as the username)
RUN echo "root:root" | chpasswd

# libyang and sysrepo
RUN \
      sh -c "echo 'deb http://download.opensuse.org/repositories/home:/liberouter/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/home:liberouter.list" && \
      wget -nv https://download.opensuse.org/repositories/home:liberouter/xUbuntu_18.04/Release.key -O Release.key && \
      apt-key add - < Release.key && \
      apt-get update && \
      apt-get install libyang1 libyang-dev sysrepo sysrepo-dev

# libssh
RUN \
      cd /opt/dev && \
      git clone https://git.libssh.org/projects/libssh.git && cd libssh && git checkout stable-0.9 && \
      mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="Release" -DWITH_ZLIB=ON -DWITH_NACL=OFF -DWITH_PCAP=OFF .. && \
      make -j2 && \
      make install

# libnetconf2 (latest package is not available on Ubuntu 18.04, so we have to compile it from source)
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/libnetconf2.git && cd libnetconf2 && \
      git checkout master && \
      mkdir build && cd build && \
      cmake  -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install

# netopeer 2 (latest package is not available on Ubuntu 18.04, so we have to compile it from source)
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/Netopeer2.git && cd Netopeer2 && \
      git checkout master && \
      mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install

ENV EDITOR vim
EXPOSE 830

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
