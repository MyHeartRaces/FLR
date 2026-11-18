include $(TOPDIR)/rules.mk
# Per-build official latest-compatible selection; no recipe version ceiling.
include $(TOPDIR)/flr-engine-lock.mk
PKG_NAME:=flint-xray
PKG_VERSION:=$(FLR_XRAY_VERSION)
PKG_RELEASE:=1
PKG_SOURCE:=$(FLR_XRAY_ARCHIVE)
PKG_SOURCE_URL:=$(FLR_XRAY_SOURCE_URL)
PKG_HASH:=$(FLR_XRAY_SHA256)
PKG_LICENSE:=MPL-2.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

# Approved prebuilt payloads must remain byte-identical to the verified stage.
RSTRIP:=:

define Package/flint-xray
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Compatible xray ARM64 runtime
  DEPENDS:=@TARGET_mediatek_filogic +ca-bundle
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	unzip -q $(DL_DIR)/$(PKG_SOURCE) xray LICENSE -d $(PKG_BUILD_DIR)
endef

define Build/Configure
endef
define Build/Compile
endef

define Package/flint-xray/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/licenses/xray
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xray $(1)/usr/bin/xray
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/xray/LICENSE
endef

$(eval $(call BuildPackage,flint-xray))
