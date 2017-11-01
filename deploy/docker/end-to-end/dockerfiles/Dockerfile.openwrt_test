FROM sysrepo/sysrepo-netopeer2:openwrt_base

MAINTAINER mislav.novakovic@sartura.hr

# fetch latest git commit for libyang,sysrepo, libnetcon2 and netopeer2
RUN \
      cd /home/openwrt/openwrt/feeds/packages/ && \
      COMMIT=$(git ls-remote https://github.com/CESNET/libyang.git --heads master | cut -f1) && \
      sed -i "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$COMMIT/" libs/libyang/Makefile && \
      COMMIT=$(git ls-remote https://github.com/sysrepo/sysrepo.git --heads master | cut -f1) && \
      sed -i "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$COMMIT/" net/sysrepo/Makefile && \
      COMMIT=$(git ls-remote https://github.com/CESNET/libnetconf2.git --heads master | cut -f1) && \
      sed -i "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$COMMIT/" libs/libnetconf2/Makefile && \
      COMMIT=$(git ls-remote https://github.com/CESNET/Netopeer2.git --heads master | cut -f1) && \
      sed -i "s/^PKG_SOURCE_VERSION:=.*/PKG_SOURCE_VERSION:=$COMMIT/" net/netopeer2/Makefile

# compile sysrepo examples
RUN \
      cd /home/openwrt/openwrt/feeds/packages/ && \
      TAB=$'\t' && \
      sed -i "s/DBUILD_EXAMPLES:BOOL=FALSE/DBUILD_EXAMPLES:BOOL=TRUE/" net/sysrepo/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_BIN) \$(PKG_BUILD_DIR)/examples/application_example \$(1)/bin" '/define\ Package\/sysrepo\/install/ {$0=$0mytext} 1' net/sysrepo/Makefile > /tmp/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DIR) \$(1)/bin" '/define\ Package\/sysrepo\/install/ {$0=$0mytext} 1' /tmp/Makefile > net/sysrepo/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DATA) \$(PKG_BUILD_DIR)/tests/yang/ietf-interfaces@2014-05-08.yang \$(1)/etc/sysrepo/yang/" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' net/sysrepo/Makefile > /tmp/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DIR) \$(1)/etc/sysrepo/yang" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' /tmp/Makefile > net/sysrepo/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DATA) \$(PKG_BUILD_DIR)/tests/yang/iana-if-type.yang \$(1)/etc/sysrepo/yang/" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' net/sysrepo/Makefile > /tmp/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DIR) \$(1)/etc/sysrepo/yang" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' /tmp/Makefile > net/sysrepo/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DATA) \$(PKG_BUILD_DIR)/tests/yang/ietf-ip@2014-06-16.yang \$(1)/etc/sysrepo/yang/" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' net/sysrepo/Makefile > /tmp/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DIR) \$(1)/etc/sysrepo/yang" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' /tmp/Makefile > net/sysrepo/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DATA) \$(PKG_BUILD_DIR)/examples/yang/ietf-interfaces.data.xml \$(1)/etc/sysrepo" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' net/sysrepo/Makefile > /tmp/Makefile && \
      awk -v mytext="\n\t\$(INSTALL_DIR) \$(1)/etc/sysrepo" '/define\ Package\/sysrepo\/install/  {$0=$0mytext} 1' /tmp/Makefile > net/sysrepo/Makefile && \
      echo 'Index: sysrepo-0.7.1-0b36f308574a60d7ee36b1a3118b999618bb40d8/examples/CMakeLists.txt\n\
===================================================================\n\
--- sysrepo-0.7.1-0b36f308574a60d7ee36b1a3118b999618bb40d8.orig/examples/CMakeLists.txt\n\
+++ sysrepo-0.7.1-0b36f308574a60d7ee36b1a3118b999618bb40d8/examples/CMakeLists.txt\n\
@@ -49,7 +49,7 @@ macro(INSTALL_EXAMPLE_YANG MODULE_NAME R\n\
     EXEC_AT_INSTALL_TIME(${CMD})\n\
 endmacro(INSTALL_EXAMPLE_YANG)\n\
\n\
-INSTALL_EXAMPLE_YANG("turing-machine" "")\n\
-INSTALL_EXAMPLE_YANG("iana-if-type" "")\n\
-INSTALL_EXAMPLE_YANG("ietf-ip" "@2014-06-16")\n\
-INSTALL_EXAMPLE_YANG("ietf-interfaces" "@2014-05-08")\n\
+#INSTALL_EXAMPLE_YANG("turing-machine" "")\n\
+#INSTALL_EXAMPLE_YANG("iana-if-type" "")\n\
+#INSTALL_EXAMPLE_YANG("ietf-ip" "@2014-06-16")\n\
+#INSTALL_EXAMPLE_YANG("ietf-interfaces" "@2014-05-08")' >> net/sysrepo/patches/999-remove-sysrepoctl

# build the image
RUN \
      cd /home/openwrt/openwrt && \
      make defconfig && \
      make -j4
