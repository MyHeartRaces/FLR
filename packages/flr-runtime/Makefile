include $(TOPDIR)/rules.mk
PKG_NAME:=flr-runtime
PKG_VERSION:=0.8
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

# Approved prebuilt payloads must remain byte-identical to the verified stage.
RSTRIP:=:

define Package/flr-runtime
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FLR routing controller
  DEPENDS:=@TARGET_mediatek_filogic +flint-sing-box +ip-full +nftables-json +conntrack +amneziawg-tools +ca-bundle
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef
define Build/Configure
endef
define Build/Compile
endef

define Package/flr-runtime/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/hotplug.d/iface $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/flr-runtime.keep $(1)/lib/upgrade/keep.d/flr-runtime
	$(INSTALL_BIN) ./files/99-flr-runtime $(1)/etc/uci-defaults/99-flr-runtime
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/flr-controller $(1)/usr/sbin/flr-controller
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/flr-runtime.init $(1)/etc/init.d/flr-runtime
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/flr-proxies.init $(1)/etc/init.d/flr-proxies
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/flr-runtime.rollback $(1)/usr/sbin/flr-rollback
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/flr-runtime.hotplug $(1)/etc/hotplug.d/iface/95-flr-runtime
endef

$(eval $(call BuildPackage,flr-runtime))
