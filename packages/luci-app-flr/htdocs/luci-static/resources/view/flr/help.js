'use strict';
'require view';
'require flr';
return view.extend({
 load:function(){return flr.read({operation:'settings'});},
 render:function(settings) {
  var d=settings.direct_proxy || {bind:'',port:1080};
  return E('div',{class:'flr-page'},[
   flr.style(),E('h2',{},_('Choosing VPN connections')),
   E('p',{},_('The "Proxy" page offers three modes: "Auto" follows the order of all protocols and connections; "Protocol only" chooses within one protocol; "Specific connection" keeps the manual choice even when it fails. The Backup/Main groups are your VPS labels, not hidden fallback rules.')),
   E('p',{},_('Priority is set separately for protocols and for the connections within each. AWG and HY2 can take any place. A new order takes effect at the next choice; a healthy connection stays until you explicitly ask for re-evaluation.')),
   E('p',{},_('AWG counts as degraded on sustained errors or slowdowns at both probe providers. A failure of one provider does not cause a switch. Returning needs fast successful probes at both providers for at least 60 s and an eligible priority. HTTPS/DNS timing is measured; it is no proof of throttling by the ISP.')),
   E('p',{},_('AWG files with Table=off are accepted: FLR manages routing. JSON, URI, base64 and AWG imports are limited by the 64 KiB web envelope; subscriptions up to 1 MiB load through an HTTPS URL. Old keys and private configs are not shown. A connection test briefly changes the VPN path and then restores the original choice.')),
   E('p',{},_('After the return to AWG a healthy reserve that was in use stays on: old TCP/UDP sessions keep going through it, new ones get the chosen route. A repeated AWG failure uses the same reserve. Replacing or deleting the connection, a manual mode change, a complete channel failure or a service stop can interrupt its sessions. A cold reserve is not started in advance while AWG has been healthy from the start.')),
   E('p',{},_('"Proxy" shows the actual route of new connections, the retained reserve and the age of the last measurement. A skipped probe does not mean a failure. WAN diagnostics run separately and do not choose the VPN path.')),
   E('p',{},_('The history keeps up to 720 rounds and 256 events in RAM, at most 4 MiB. IDs, measurements and apply outcomes are recorded; keys, configs and command output are not stored. A service restart starts a new history. "Download diagnostics" needs write permission and returns bounded pages. If the history changes during the download, repeat it.')),
   E('h2',{},_('qBittorrent — direct via WAN')),
   E('p',{},_('Mac 5.2.3: qBittorrent → Preferences / Settings → Connection → Proxy Server. PC: Tools → Options → Connection. Translated item names may differ.')),
   E('ol',{},[
    E('li',{},[_('Type: SOCKS5; Host: %s; Port: %s; Authentication: off.').format(d.bind || _('router LAN address'),d.port)]),
    E('li',{},_('Enable "Perform hostname lookup via proxy" (DNS through the proxy).')),
    E('li',{},_('Enable "Use proxy for BitTorrent purposes" and within it "Use proxy for peer connections". Otherwise peer connections can bypass SOCKS.')),
    E('li',{},_('If your client version offers to block unsupported/unproxied connections or fallback, enable the block. The 5.2.3 interface has no separate old checkbox; SOCKS settings do not prove that every packet is covered.')),
    E('li',{},_('For a conservative SOCKS setup choose TCP, disable DHT, PeX, LSD and UPnP/NAT-PMP, and do not configure inbound port forwarding. This reduces unproxied paths but does not guarantee every packet.'))
   ]),
   E('p',{},_('UDP ASSOCIATE is supported for IPv4: up to 4096 bytes, FRAG=0, one owner per IP, up to 32 destinations with an idle one removed after 60 seconds. Closing the controlling TCP connection closes UDP. DHT/uTP/UDP trackers depend on the libtorrent and client version; verify them separately or stay with TCP.')),
   E('p',{},_('SOCKS CONNECT does not accept inbound P2P connections. DHT/PeX/LSD, inbound connections, DNS, RSS and service requests cannot be considered covered by one checkbox. IPv6 SOCKS destinations are refused.')),
   E('p',{},_('For a stronger guarantee choose "Settings → Device route → Direct" for the Mac/PC IP: all routed IPv4 of the device goes through the WAN and never through the VPS. Pin its DHCP address. For IPv6 disable IPv6 on the device; the VPN policy gives it no direct guarantee.')),
   E('p',{},_('Rules by torrent domains do not recognize every peer and do not protect all P2P traffic. Stop SOCKS and check how the client behaves, then check the route with the WAN/VPN counters. These checks have not been run on your router yet.')),
   E('p',{},_('On an error check "Overview" and the state of the controller, the listener and the components. Importing a profile does not activate the VPN. Do not confirm the rollback before checking LAN, WAN, VPN and direct.')),
   E('p',{},[E('a',{href:'https://github.com/qbittorrent/qBittorrent/blob/release-5.2.3/src/gui/optionsdialog.ui',target:'_blank',rel:'noopener'},_('Official qBittorrent 5.2.3 setting names'))])
  ]);
 },handleSave:null,handleSaveApply:null,handleReset:null
});
