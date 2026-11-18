include $(TOPDIR)/rules.mk
# Exact minimal source-built payload, verified before SDK preparation.
include $(TOPDIR)/flr-engine-lock.mk

PKG_NAME:=flint-sing-box
# The binary reports e.g. 1.14.4-flr-random-sni.1, which is not a valid apk
# version. The package version is FLR_SING_BOX_PACKAGE_VERSION when the lock
# provides it, else the same mapping as ci/sing_box_source.package_version():
# <x.y.z>-flr-random-sni.<n> becomes <x.y.z>.<n> (plain versions are unchanged).
# CI verifies the resulting manifest line `flint-sing-box - <package_version>-r1`.
PKG_VERSION:=$(or $(FLR_SING_BOX_PACKAGE_VERSION),$(subst -flr-random-sni.,.,$(FLR_SING_BOX_VERSION)))
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0-or-later
# Keyed by the binary version: ci/sdk-output.py locates the verified payload here.
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(FLR_SING_BOX_VERSION)

include $(INCLUDE_DIR)/package.mk

# Source-built payloads must remain byte-identical to the verified stage.
RSTRIP:=:

define Package/flint-sing-box
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Compatible sing-box with Hysteria2 Gecko and random SNI
  URL:=https://github.com/SagerNet/sing-box
  DEPENDS:=@TARGET_mediatek_filogic +ca-bundle +kmod-inet-diag +kmod-tun
  CONFLICTS:=sing-box sing-box-tiny
endef

define Package/flint-sing-box/description
  Static ARM64 engine built from pinned upstream source plus the audited FLR
  random-SNI patch, SHA-256 verified. Hysteria2, WireGuard and uTLS are included.
  No active service or personal VPN configuration is included.
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/sing-box ./src/LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/flint-sing-box/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/licenses/sing-box
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sing-box $(1)/usr/bin/sing-box
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/sing-box/LICENSE
endef

$(eval $(call BuildPackage,flint-sing-box))
