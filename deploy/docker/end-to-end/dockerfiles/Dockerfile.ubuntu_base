FROM ubuntu:16.04

MAINTAINER mislav.novakovic@sartura.hr

RUN \
      apt-get update && apt-get install -y \
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      libpcre3-dev \
      pkg-config \
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      libssh-dev \
      libssl-dev \
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

# libssh
RUN \
      git clone http://git.libssh.org/projects/libssh.git && \
      cd libssh && mkdir build && cd build && \
      cmake .. && \
      make -j2 && \
      make install && \
      ldconfig

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev
