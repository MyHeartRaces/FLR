include $(TOPDIR)/rules.mk
# Per-build official latest-compatible selection; no recipe version ceiling.
include $(TOPDIR)/flr-engine-lock.mk
PKG_NAME:=flint-wstunnel
PKG_VERSION:=$(FLR_WSTUNNEL_VERSION)
PKG_RELEASE:=1
PKG_SOURCE:=$(FLR_WSTUNNEL_ARCHIVE)
PKG_SOURCE_URL:=$(FLR_WSTUNNEL_SOURCE_URL)
PKG_HASH:=$(FLR_WSTUNNEL_SHA256)
PKG_LICENSE:=MIT
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

# Approved prebuilt payloads must remain byte-identical to the verified stage.
RSTRIP:=:

define Package/flint-wstunnel
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Compatible wstunnel ARM64 runtime
  DEPENDS:=@TARGET_mediatek_filogic +ca-bundle
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	tar -xzf $(DL_DIR)/$(PKG_SOURCE) -C $(PKG_BUILD_DIR) wstunnel LICENSE
endef

define Build/Configure
endef
define Build/Compile
endef

define Package/flint-wstunnel/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/licenses/wstunnel
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wstunnel $(1)/usr/bin/wstunnel
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/wstunnel/LICENSE
endef

$(eval $(call BuildPackage,flint-wstunnel))
