'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'status'});},
 render:function(data) {
  var box=E('div',{class:'flr-page'});
  var update=function(d) {
   var s=d.status || {}, proxy=s.direct_proxy || {}, active=s.active_connection,requested=s.requested || {mode:'auto'},intent=s.proxy || {};
   var choice=requested.mode==='connection'?_('Specific connection'):requested.mode==='transport'?_('Protocol only %s').format(flr.familyLabel(requested.family)):_('Auto');
   var route=_('Route of new connections: %s · choice: %s').format(active?active.name+' · '+flr.familyLabel(active.family)+' · '+(active.group || '')+' · '+active.endpoint:_('no working connection'),choice);
   var socks=(proxy.running?_('Permanent SOCKS5: running · %s:%s'):_('Permanent SOCKS5: not running · %s:%s')).format((proxy.config || {}).bind || _('LAN address unknown'),(proxy.config || {}).port || 1080);
   var children=[flr.style(),E('h2',{},_('FLR — status')),
    E('p',{},[(d.runtime?_('Controller running'):_('Controller stopped'))+' · '+(d.vpn_enabled?_('VPN on'):_('VPN off'))]),
    E('p',{},[_('Transport: %s · games: %s').format((s.selection || {}).general || 'down',(s.selection || {}).games || 'down')]),
    E('p',{},[route+(intent.pending?' · '+_('waiting to be applied'):'')]),
    E('p',{},[socks])];
   if(intent.reserve_connection){var reserve=intent.reserve_connection;children.push(E('p',{},[_('Retained reserve: %s · %s · details and history in "Proxy".').format(reserve.name,flr.familyLabel(reserve.family))]));}
   if(proxy.lan_error)children.push(E('p',{class:'alert-message warning'},[_('Router LAN address unknown, using the fallback: %s').format(proxy.lan_error)]));
   if(proxy.error)children.push(E('p',{class:'alert-message error'},[proxy.error]));
   if(s.last_error)children.push(E('p',{class:'alert-message error'},[s.last_error]));
   if(d.deactivation_pending)children.push(E('div',{class:'alert-message warning'},[
    E('p',{},_('The VPN is off in the settings, but restoring the network has not finished. Repeat the shutdown.')),
    flr.action(_('Repeat the shutdown'),{operation:'settings',settings:{enabled:false}},refresh)]));
   if(d.rollback_pending) {
    var accepted=E('input',{type:'checkbox',disabled:L.hasViewPermission()?null:true});
    children.push(E('div',{class:'alert-message warning'},[
     E('p',{},_('Rollback is armed. Confirm only after checking access to LuCI/LAN, the WAN, VPN routing and direct.')),
     E('label',{},[accepted,' ',_('I have checked LAN, WAN, VPN and direct')]),
     flr.action(_('Accept the connection and disarm the rollback'),function(){if(!accepted.checked)throw new Error(_('Run and confirm the connection checks first.'));return {operation:'rollback-confirm',accepted:true};},refresh)
    ]));
   }
   var awg=(s.channels || {}).awg;
   if(awg) {
    var reasons={healthy:_('healthy'),interface_absent:_('interface missing'),consecutive_failures:_('three complete failures in a row'),sustained_failures:_('sustained errors at both providers'),sustained_latency:_('sustained slowdown at both providers')};
    var w=awg.window || {},baselines=awg.baselines || [],targets=(awg.probe || {}).targets || [];
    var since=awg.recovery_since && !awg.recovery_since.startsWith('0001-')?' · '+_('since %s').format(awg.recovery_since):'';
    children.push(E('h3',{},_('AWG health')),E('p',{},[_('State: %s').format(reasons[awg.reason] || _('waiting for measurements'))+' · '+(awg.healthy?_('chosen as healthy'):_('not chosen as healthy'))]),
     E('p',{},[_('Window: %s rounds · baseline: %s clean rounds · recovery: %s clean rounds').format(w.samples || 0,awg.baseline_samples || 0,awg.recovery_clean_samples || 0)+since]),
     E('p',{},_('The time of successful HTTPS/DNS requests is measured in ms; errors do not count as time. These observations do not prove intentional throttling.')));
    ['Cloudflare','Google'].forEach(function(name,i){var b=baselines[i] || {},t=targets[i] || {};children.push(E('p',{},[_('%s: errors %s · slow TCP/UDP %s/%s · last TCP/UDP %s/%s ms · baseline TCP/UDP %s/%s ms').format(name,(w.failed || [])[i] || 0,(w.tcp_slow || [])[i] || 0,(w.udp_slow || [])[i] || 0,t.tcp?t.tcp_duration_ms:_('failed / no data'),t.udp?t.udp_duration_ms:_('failed / no data'),b.tcp_ms || _('none yet'),b.udp_ms || _('none yet'))]));});
   }
   children.push(E('details',{class:'flr-details'},[E('summary',{},_('Detailed channel checks')),E('pre',{},[JSON.stringify(s.channels || {},null,2)])]),flr.action(_('Repeat the checks'),{operation:'refresh'},refresh));
   box.replaceChildren.apply(box,children);
  };
  var refresh=function(){return flr.read({operation:'status'}).then(update).catch(flr.error);};
  update(data);poll.add(refresh,5);return box;
 },handleSave:null,handleSaveApply:null,handleReset:null
});
