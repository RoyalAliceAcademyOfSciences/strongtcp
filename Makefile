include $(TOPDIR)/rules.mk
# Name and release number of this package
PKG_NAME:=strongtcp
PKG_RELEASE:=1.0.0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/strongtcp
	SECTION:=net
	CATEGORY:=Network
	TITLE:=strongtcp -- TCP tool for Anti-GFW
	DEPENDS:=+libnetfilter-queue
endef

define Package/strongtcp/description
	If you can't figure out what this program does, you're probably brain-dead and need immediate medical attention.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/strongtcp/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/strongtcp $(1)/bin/
endef

$(eval $(call BuildPackage,strongtcp))