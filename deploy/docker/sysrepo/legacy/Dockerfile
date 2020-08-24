FROM ubuntu:18.04

# defaults
RUN \
	apt-get update && apt-get install -y \
	git \
	wget \
	libssl-dev \
	build-essential \
	vim \
	libtool	\
	autoconf \
	automake \
	pkg-config \
	libgtk-3-dev \
	vim \
	valgrind \
	libev-dev \
	libpcre3-dev \
	sudo \
	python3 \
	bison \
	flex \
	swig \
	libcmocka0 \
	libcmocka-dev \
	cmake \
	libprotobuf-c-dev \
	protobuf-c-compiler \
	libavl-dev

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

# libyang
RUN \
      sh -c "echo 'deb http://download.opensuse.org/repositories/home:/liberouter/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/home:liberouter.list" && \
      wget -nv https://download.opensuse.org/repositories/home:liberouter/xUbuntu_18.04/Release.key -O Release.key && \
      apt-key add - < Release.key && \
      apt-get update && \
      apt-get install libyang1 libyang-dev

# sysrepo
RUN \
      cd /opt/dev && \
      git clone https://github.com/sysrepo/sysrepo.git --branch legacy && cd sysrepo && \
      mkdir build && cd build && \
      cmake -DENABLE_TESTS=OFF -DCMAKE_BUILD_TYPE="Debug" -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && \
      make -j2 && \
      make install

ENV EDITOR vim
EXPOSE 830
