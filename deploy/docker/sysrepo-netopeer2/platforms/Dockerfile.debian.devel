FROM debian:sid

MAINTAINER mislav.novakovic@sartura.hr

# update system
RUN \
      apt-get update

# install basic dependencies
RUN \
   apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre3-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      # netopeer2 \
      libssl-dev \
      libssh-dev \
      # bindings
      swig

# add password to root
RUN \
      echo "root:root" | chpasswd

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# generate default ssh key
RUN \
      ssh-keygen -t rsa -N "" -f /etc/ssh/ssh_host_rsa_key

# libredblack
RUN \
      git clone https://github.com/sysrepo/libredblack.git && \
      cd libredblack && \
      ./configure --prefix=/usr && \
      make && \
      make install && \
      ldconfig

# libyang
RUN \
      git clone https://github.com/CESNET/libyang.git && \
      cd libyang && mkdir build && cd build && \
      git checkout devel && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      ldconfig

# sysrepo
RUN \
      git clone https://github.com/sysrepo/sysrepo.git && \
      cd sysrepo && mkdir build && cd build && \
      git checkout devel && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      ldconfig

# libnetconf2
RUN \
      git clone https://github.com/CESNET/libnetconf2.git && \
      cd libnetconf2 && mkdir build && cd build && \
      git checkout devel && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      ldconfig

# keystore
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/Netopeer2.git && \
      cd Netopeer2 && git checkout devel-server && \
      cd keystored && mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      ldconfig

# netopeer2
RUN \
      cd Netopeer2/server && mkdir build && cd build && \
      git checkout devel-server && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install

# install python2 sysrepo language bindings
RUN apt-get install -y python-dev
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_PYTHON_VERSION=2 .. && \
      make -j2 && \
      make install

# install lua5.1 sysrepo language bindings
RUN apt-get install -y lua5.1-dev
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_LUA_VERSION=5.1 .. && \
      make -j2 && \
      make install

# install python3 sysrepo language bindings
RUN apt-get install -y python3-dev
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_PYTHON_VERSION=3 .. && \
      make -j2 && \
      make install

# install lua5.2 sysrepo language bindings
RUN apt-get install -y lua5.2-dev
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_LUA_VERSION=5.2 .. && \
      make -j2 && \
      make install

ENV EDITOR vim
EXPOSE 830

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
