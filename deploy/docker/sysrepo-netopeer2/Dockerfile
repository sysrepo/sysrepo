FROM ubuntu:18.04

# defaults
RUN \
	apt-get update && apt-get install -y \
	git \
	curl \
	wget \
	libssh-dev \
	libssl-dev \
	libtool \
	build-essential \
	vim \
	libtool	\
	autoconf \
	automake \
	pkg-config \
	libgtk-3-dev \
	make \
	vim \
	valgrind \
	doxygen \
	libev-dev \
	libpcre3-dev \
	unzip \
	sudo \
	python2.7 \
	python3 \
	python-pip \
	python3-pip \
	python-dev	\
	python3-dev \
	build-essential \
	bison \
	flex

# pyang
RUN pip install --upgrade pyang

# Adding netconf user
RUN adduser --system netconf
RUN mkdir -p /home/netconf/.ssh
RUN echo "netconf:netconf" | chpasswd && adduser netconf sudo


# Clearing and setting authorized ssh keys
RUN echo '' > /home/netconf/.ssh/authorized_keys
RUN ssh-keygen -A
RUN ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa
RUN cat /home/netconf/.ssh/id_dsa.pub >> /home/netconf/.ssh/authorized_keys


# Updating shell to bash
RUN sed -i s#/home/netconf:/bin/false#/home/netconf:/bin/bash# /etc/passwd

RUN mkdir /opt/dev && sudo chown -R netconf /opt/dev

# set password for user (same as the username)
RUN echo "root:root" | chpasswd

# upgrade cmake to 3.10
RUN \
      cd /opt/dev && \
      wget https://cmake.org/files/v3.10/cmake-3.10.0.tar.gz && \
      tar -xvf cmake-3.10.0.tar.gz && rm cmake-3.10.0.tar.gz && cd cmake-3.10.0 && \
      ./bootstrap && \
      make -j2 && \
      make install

# swig
RUN \
      cd /opt/dev && \
      wget http://downloads.sourceforge.net/swig/swig-4.0.1.tar.gz && \
      tar -xvf swig-4.0.1.tar.gz && rm swig-4.0.1.tar.gz && cd swig-4.0.1 && \
      ./configure --prefix=/usr --without-clisp --without-maximum-compile-warnings && \
      make && \
      make install && \
      install -v -m755 -d /usr/share/doc/swig-4.0.1 && \
      cp -v -R Doc/* /usr/share/doc/swig-4.0.1

# cmoka
RUN \
      cd /opt/dev && \
      git clone git://git.cryptomilk.org/projects/cmocka.git && cd cmocka && \
      git checkout tags/cmocka-1.1.5 && \
      mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && \
      make -j2 && \
      make install

# protobuf
RUN \
      cd /opt/dev && \
      git clone https://github.com/google/protobuf.git && cd protobuf && \
      ./autogen.sh && \
      ./configure --prefix=/usr && \
      make -j2 && \
      make install

# protobuf-c
RUN \
      cd /opt/dev && \
      git clone https://github.com/protobuf-c/protobuf-c.git && cd protobuf-c && \
      ./autogen.sh && \
      ./configure --prefix=/usr && \
      make -j2 && \
      make install


# install lua
RUN \
      apt-get update && apt-get install -y \
      luajit \
      luarocks

# install node v12.x
RUN \
     curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash - && \
     sudo apt-get install -y nodejs && \
     npm install -g node-gyp

# libyang
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/libyang.git && cd libyang && \
      git checkout master && \
      mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install

# libnetconf2
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/libnetconf2.git && cd libnetconf2 && \
      git checkout master && \
      mkdir build && cd build && \
      cmake  -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install

# sysrepo
RUN \
      cd /opt/dev && \
      git clone https://github.com/sysrepo/sysrepo.git && cd sysrepo && \
      mkdir build && cd build && \
      cmake -DENABLE_TESTS=OFF -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr -DREPOSITORY_LOC:PATH=/etc/sysrepo .. && \
      make -j2 && \
      make install

# netopeer 2
RUN \
      cd /opt/dev && git clone https://github.com/CESNET/Netopeer2.git && cd Netopeer2 && \
      git checkout master && \
      cd /opt/dev/Netopeer2/server && \
      mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && \
      make -j2 && \
      make install && \
      cd /opt/dev/Netopeer2/cli && \
      mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && \
      make -j2 && \
      make install

ENV EDITOR vim
EXPOSE 830

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
