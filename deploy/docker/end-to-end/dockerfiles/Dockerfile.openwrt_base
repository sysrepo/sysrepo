FROM ubuntu:xenial

RUN \
      DEBIAN_FRONTEND=noninteractive apt-get -qq update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -yqq \
      sudo \
      git-core \
      subversion \
      build-essential \
      gcc-multilib \
      ccache \
      quilt \
      libncurses5-dev \
      zlib1g-dev \
      gawk \
      flex \
      gettext \
      wget \
      unzip \
      python \
      vim \
      libssl-dev && \
      apt-get clean && \
      useradd -m openwrt && \
      echo 'openwrt ALL=NOPASSWD: ALL' > /etc/sudoers.d/openwrt

USER openwrt

RUN \
      cd /home/openwrt && \
      git clone https://github.com/openwrt/openwrt.git openwrt && \
      cd openwrt && \
      cp feeds.conf.default feeds.conf && \
      ./scripts/feeds update -a; ./scripts/feeds install -a

COPY dockerfiles/sysrepo_config /home/openwrt/sysrepo_config

RUN cp /home/openwrt/sysrepo_config /home/openwrt/openwrt/.config

RUN \
      cd /home/openwrt/openwrt && \
      make defconfig

RUN \
      cd /home/openwrt/openwrt && \
      make -j4
