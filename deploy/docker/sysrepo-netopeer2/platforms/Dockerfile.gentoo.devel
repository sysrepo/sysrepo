FROM gentoo/stage3-amd64

MAINTAINER mislav.novakovic@sartura.hr

# update system
RUN \
      emerge --sync

# install basic dependencies
RUN \
      emerge -q \
      automake \
       bison \
       flex \
      dev-vcs/git \
      cmake \
      vim \
      supervisor \
      # libyang
      pkg-config \
      # sysrepo
      libev \
      protobuf-c \
      # netopeer2 \
      # libssh
      # bindings
      swig

# Netopeer2 requires ssh server
RUN USE=server emerge -q libssh

# add password to root
RUN \
      echo "root:root" | chpasswd

# add netconf user
RUN \
      useradd --system netconf && \
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
      sed -i '1s/^/#!\/usr\/bin\/env python2\n/' rbgen.in && \
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
      cd /opt/dev && \
      cd Netopeer2/server && \
      git checkout devel-server && \
      mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install

# install python2 sysrepo language bindings
RUN emerge -q python:2.7
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_PYTHON_VERSION=2 .. && \
      make -j2 && \
      make install

# install lua5.1 sysrepo language bindings
RUN \
      echo "=app-eselect/eselect-lua-1 ~amd64" >> /etc/portage/package.accept_keywords && \
      echo "=dev-lang/lua-5.1.5-r100 ~amd64" >> /etc/portage/package.accept_keywords && \
      echo "=dev-lang/lua-5.1.5-r100" >> /etc/portage/package.unmask && \
      echo "=app-eselect/eselect-lua-1" >> /etc/portage/package.unmask && \
      emerge -q lua:5.1
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_LUA_VERSION=5.1 .. && \
      make -j2 && \
      make install

# install python3 sysrepo language bindings
RUN emerge -q python:3.4
RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_PYTHON_VERSION=3 .. && \
      make -j2 && \
      make install

RUN \
      cd /opt/dev/sysrepo/build && \
      cmake -DGEN_LUA_VERSION=5.2 .. && \
      make -j2 && \
      make install

ENV EDITOR vim
EXPOSE 830

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
