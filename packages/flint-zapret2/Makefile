include $(TOPDIR)/rules.mk
# Per-build official latest-compatible selection; no recipe version ceiling.
include $(TOPDIR)/flr-engine-lock.mk
PKG_NAME:=flint-zapret2
PKG_VERSION:=$(FLR_ZAPRET2_VERSION)
PKG_RELEASE:=1
PKG_SOURCE:=$(FLR_ZAPRET2_ARCHIVE)
PKG_SOURCE_URL:=$(FLR_ZAPRET2_SOURCE_URL)
PKG_HASH:=$(FLR_ZAPRET2_SHA256)
PKG_LICENSE:=MIT
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

# Approved prebuilt payloads must remain byte-identical to the verified stage.
RSTRIP:=:

define Package/flint-zapret2
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Compatible zapret2 ARM64 runtime
  DEPENDS:=@TARGET_mediatek_filogic +ca-bundle +kmod-nfnetlink-queue +kmod-nft-queue +nftables-json
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	tar -xzf $(DL_DIR)/$(PKG_SOURCE) -C $(PKG_BUILD_DIR) --strip-components=1 \
		zapret2-$(FLR_ZAPRET2_TAG)/binaries/linux-arm64/nfqws2 \
		zapret2-$(FLR_ZAPRET2_TAG)/lua/zapret-lib.lua.gz \
		zapret2-$(FLR_ZAPRET2_TAG)/lua/zapret-antidpi.lua.gz \
		zapret2-$(FLR_ZAPRET2_TAG)/lua/zapret-auto.lua.gz
	gunzip $(PKG_BUILD_DIR)/lua/zapret-lib.lua.gz
	gunzip $(PKG_BUILD_DIR)/lua/zapret-antidpi.lua.gz
	gunzip $(PKG_BUILD_DIR)/lua/zapret-auto.lua.gz
endef

define Build/Configure
endef
define Build/Compile
endef

define Package/flint-zapret2/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/licenses/zapret2
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/binaries/linux-arm64/nfqws2 $(1)/usr/bin/nfqws2
	$(INSTALL_DIR) $(1)/usr/share/flr-bypass/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-lib.lua $(1)/usr/share/flr-bypass/lua/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-antidpi.lua $(1)/usr/share/flr-bypass/lua/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lua/zapret-auto.lua $(1)/usr/share/flr-bypass/lua/
	$(INSTALL_DATA) ./files/LICENSE $(1)/usr/share/licenses/zapret2/LICENSE
endef

$(eval $(call BuildPackage,flint-zapret2))
