# Verbatim enable/disable from OpenWrt rc.common (GPL-2.0).
# Copyright (C) 2006-2012 OpenWrt.org
# https://raw.githubusercontent.com/openwrt/openwrt/f0a60eee2fe051741c643ea6118718aae1ef17fb/package/base-files/files/etc/rc.common
# Full upstream file SHA256: dd8ae95c78d10cccf78cb487874f163ace4c1ee14dace05fe28393b19ba639e4
# rc.common defines these before sourcing the service, then dispatches its action.
disable() {
	name="$(basename "${initscript}")"
	rm -f "$IPKG_INSTROOT"/etc/rc.d/S??$name
	rm -f "$IPKG_INSTROOT"/etc/rc.d/K??$name
}

enable() {
	err=1
	name="$(basename "${initscript}")"
	[ "$START" ] && \
		ln -sf "../init.d/$name" "$IPKG_INSTROOT/etc/rc.d/S${START}${name##S[0-9][0-9]}" && \
		err=0
	[ "$STOP" ] && \
		ln -sf "../init.d/$name" "$IPKG_INSTROOT/etc/rc.d/K${STOP}${name##K[0-9][0-9]}" && \
		err=0
	return $err
}
