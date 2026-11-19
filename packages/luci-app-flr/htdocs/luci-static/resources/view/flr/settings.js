'use strict';
'require view';
'require flr';

return view.extend({
 load:function(){return Promise.all([flr.read({operation:'settings'})]);},
 render:function(data) {
  var s=data[0],d=s.direct_proxy || {enabled:true,bind:'',port:1080};
  function controlE(tag,attrs,children){attrs=attrs || {};attrs.disabled=L.hasViewPermission()?null:true;return E(tag,attrs,children);}
  var health=s.health_policy || {enabled:true,window_seconds:60,min_samples:8,failure_percent:25,slow_percent:75,tcp_floor_ms:1500,udp_floor_ms:400,tcp_recovery_ms:750,udp_recovery_ms:200,latency_multiplier:4,recovery_multiplier:2,baseline_samples:12,recovery_seconds:60,max_gap_seconds:30};
  var healthEnabled=controlE('input',{type:'checkbox',checked:health.enabled?true:null});
  var healthFields=[
   ['window_seconds',_('Observation window, s'),30,300],['min_samples',_('Minimum rounds in the window'),6,60],
   ['failure_percent',_('Errors per provider, %'),25,100],['slow_percent',_('Slow requests per provider, %'),50,100],
   ['tcp_floor_ms',_('TCP: slowdown threshold, ms'),500,3500],['udp_floor_ms',_('UDP: slowdown threshold, ms'),100,2000],
   ['tcp_recovery_ms',_('TCP: recovery / learning threshold, ms'),100,3499],['udp_recovery_ms',_('UDP: recovery / learning threshold, ms'),25,1999],
   ['latency_multiplier',_('Baseline time multiplier: slowdown'),2,10],['recovery_multiplier',_('Baseline time multiplier: recovery'),1,9],
   ['baseline_samples',_('Clean rounds for the baseline time'),6,60],['recovery_seconds',_('Continuous recovery, s'),60,600],['max_gap_seconds',_('Maximum pause between probes, s'),10,60]
  ];
  var healthInputs={};var healthRows=healthFields.map(function(f){var input=controlE('input',{type:'number',min:f[2],max:f[3],step:1,value:health[f[0]]});healthInputs[f[0]]=input;return flr.field(f[1],input);});
  var bypass=s.direct_bypass || {enabled:false,tcp:'off',quic:'off'};
  var bypassEnabled=controlE('input',{type:'checkbox',checked:bypass.enabled?true:null});
  function preset(value){return controlE('select',{},[E('option',{value:'off',selected:!value || value==='off'?true:null},_('Off (no bypass)')),E('option',{value:'fake',selected:value==='fake'?true:null},_('Experiment: fake ×2'))]);}
  var bypassTCP=preset(bypass.tcp),bypassQUIC=preset(bypass.quic);
  var enabled=controlE('input',{type:'checkbox',checked:d.enabled?true:null}),bind=controlE('input',{value:d.bind,readonly:true}),port=controlE('input',{type:'number',min:1024,max:65535,value:d.port});
  var ip=controlE('input',{placeholder:/^\d+\.\d+\.\d+\.\d+$/.test(d.bind || '')?d.bind.replace(/\.\d+$/,'.2'):_('Device IPv4 address in the LAN'),value:''}),mode=controlE('select',{},[
   E('option',{value:'auto'},_('Auto (domain policy)')),E('option',{value:'general'},_('VPN — general')),E('option',{value:'games'},_('VPN — games')),E('option',{value:'direct'},_('Direct — the whole device via the WAN'))]);
  // Tunnel CAKE shaping; hidden on controllers that do not report it.
  var qos=[];
  if(s.tunnel_qos && typeof s.tunnel_qos==='object') {
   var q=s.tunnel_qos;
   var qosEnabled=controlE('input',{type:'checkbox',checked:q.enabled===true?true:null});
   function rate(value,field){return controlE('input',{type:'number',min:0,max:10000000,step:1,'data-field':field,value:Number.isSafeInteger(value)?value:0});}
   var qosUp=rate(q.upload_kbit,'upload_kbit'),qosDown=rate(q.download_kbit,'download_kbit');
   qos=[E('h3',{},_('Tunnel queue (CAKE)')),
    E('p',{},_('CAKE keeps the queue inside the VPN tunnel on the router, so games and calls do not wait behind large downloads. Set a rate slightly below the real line rate (about 5–10 % lower): if it is higher, the queue builds up at the ISP again. 0 leaves a direction unlimited.')),
    E('p',{class:'flr-muted'},_('Allowed: 0 or 1000 to 10 000 000 kbit/s; enabling needs at least one non-zero rate.')),
    flr.field(_('Enable CAKE in the tunnel'),qosEnabled),flr.field(_('Upload, kbit/s'),qosUp),flr.field(_('Download, kbit/s'),qosDown),
    flr.action(_('Save tunnel queue'),function(){
     var up=Number(qosUp.value),down=Number(qosDown.value);
     [up,down].forEach(function(v){if(!Number.isInteger(v) || (v!==0 && (v<1000 || v>10000000)))throw new Error(_('Rate: 0 or a whole number from 1000 to 10 000 000 kbit/s.'));});
     if(qosEnabled.checked && up===0 && down===0)throw new Error(_('To enable CAKE, set at least one rate.'));
     return {operation:'settings',settings:{tunnel_qos:{enabled:qosEnabled.checked,upload_kbit:up,download_kbit:down}}};})];
  }
  var devices=E('div');
  function updateDevices(map){devices.replaceChildren(E('pre',{},[JSON.stringify(map || {},null,2)]));}
  updateDevices(s.options.profiles);
  return E('div',{class:'flr-page'},[flr.style(),E('h2',{},_('FLR settings')),
   E('p',{},_('Protocol choice, VPS connections, fallback priority and configurations are on the "Proxy" page.')),
   E('p',{},_('The routing mode, custom rules and the routing policy are on the "Routing" page.'))
  ].concat(qos,[
   E('h3',{},_('AWG resilience')),
   E('p',{},_('Two independent providers: Cloudflare and Google. The HTTPS/DNS request time covers the whole request; it is not ICMP and no proof of intentional throttling. The threshold applies to each provider. A single error or a failure of one provider does not switch AWG.')),
   E('p',{},_('The minimum rounds are at most window/5 + 1. Recovery thresholds and their multiplier must be below the slowdown thresholds. The effective threshold is the maximum of the given time and baseline time × multiplier; while there is no baseline, the given time is used. Learning happens only below the recovery thresholds. Returning needs both providers and both protocols without a pause longer than the set limit (30 s by default). Turning the detector off keeps three complete failures, a missing interface and the return qualification.')),
   E('p',{},_('The values are preliminary: tuning for the installed router and ISP has not been verified yet. Saving changed thresholds resets the collected measurements and the recovery count.')),
   flr.field(_('Detect sustained impairments'),healthEnabled),E('div',{},healthRows),
   flr.action(_('Save AWG checks'),function(){var policy={enabled:healthEnabled.checked};healthFields.forEach(function(f){var value=Number(healthInputs[f[0]].value);if(!Number.isInteger(value))throw new Error(_('Thresholds must be whole numbers.'));policy[f[0]]=value;});return {operation:'settings',settings:{health_policy:policy}};}),
   E('h3',{},_('Permanent direct SOCKS5')),E('p',{},[_('Works independently of the VPN and without expiry. The address is the router’s own LAN address, detected automatically (now: %s); port 1024–65535 except the temporary 1088 and the DNS ports. IPv6 destinations are not supported. One UDP ASSOCIATE per device IP; up to 32 destinations and 64 TCP connections.').format(d.bind || _('not detected'))]),
   flr.field(_('Listener enabled'),enabled),flr.field(_('Router LAN address (detected automatically)'),bind),flr.field(_('TCP/UDP port'),port),
   flr.action(_('Save direct'),function(){return {operation:'settings',settings:{direct_proxy:{enabled:enabled.checked,bind:bind.value,port:Number(port.value)}}};}),
   E('h3',{},_('Experimental direct bypass (IPv4)')),
   E('p',{},_('Off by default. Only the first 6 outgoing direct packets: TCP 443 and QUIC UDP 443. The VPN, its outer connections, probes and the temporary SOCKS 1088 are excluded. Conntrack accounting must already be on; the controller does not change sysctl. The presets do not guarantee access at your ISP. Discord voice and Telegram need a separate check; arbitrary UDP ports are not handled.')),
   flr.field(_('Explicitly enable the experiment'),bypassEnabled),flr.field('TCP',bypassTCP),flr.field('QUIC',bypassQUIC),
   flr.action(_('Save direct bypass'),function(){return {operation:'settings',settings:{direct_bypass:{enabled:bypassEnabled.checked,tcp:bypassTCP.value,quic:bypassQUIC.value}}};}),
   E('h3',{},_('Device route')),E('p',{},_('Direct sends all routed IPv4 traffic of the device through the WAN, including unproxied inbound/outbound paths. IPv6 gets no such guarantee; disable it on the device for IPv4-only operation.')),devices,
   flr.field(_('Device IPv4'),ip),flr.field(_('Mode'),mode),
   flr.action(_('Apply device mode'),function(){return {operation:'device',client:ip.value,value:mode.value};},function(result){updateDevices(result.devices);}),
   E('h3',{},_('Turning the VPN off')),E('p',{},_('Restores the saved network/firewall/DNS. If the restore does not finish, "Overview" shows a retry button. Direct SOCKS5 stays independent.')),
   flr.action(_('Turn the VPN off / retry the restore'),{operation:'settings',settings:{enabled:false}})
  ]));
 },handleSave:null,handleSaveApply:null,handleReset:null
});
