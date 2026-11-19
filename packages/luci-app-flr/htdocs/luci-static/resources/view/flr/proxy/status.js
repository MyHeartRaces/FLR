'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  function label(f){return flr.familyLabel(f);}
  var reasons={failback:_('return to AWG'),fallback:_('switch to the reserve'),selection:_('connection choice'),native_replacement:_('AWG replacement'),connection_unavailable:_('connection unavailable'),channel_failed:_('channel failure'),cleanup_retry:_('cleanup retry'),slot_replacement:_('proxy replacement'),admission_failed:_('connection failed admission'),manual_test:_('manual test'),shutdown:_('service stop'),warm_reserve:_('warm reserve')};
  var outcomes={applied:_('applied'),failed:_('error'),pending:_('pending'),prepared:_('prepared'),superseded:_('cancelled by a new choice')};
  var phases={queued:_('queued'),probing:_('probing'),restoring:_('restoring'),finished:_('finished'),cancelled:_('cancelled by a new choice'),failed:_('not started'),'recovery-pending':_('restore needs a service restart')};
  return flr.connectionPage(initial,poll,function(state,page) {
   var status=E('section',{class:'flr-card flr-status'});
   page.status=function(d) {
    var s=d.status || {},p=s.proxy || {},active=s.active_connection,test=s.connection_test;
    var children=[E('h2',{},_('Proxy · status')),E('div',{class:'flr-status-grid'},[
     E('div',{},[E('span',{class:'flr-muted'},_('Requested mode')),E('strong',{},[flr.selectionText(d.selection,d.connections)])]),
     E('div',{},[E('span',{class:'flr-muted'},_('New connections · actual route')),E('strong',{},[active?label(active.family)+' · '+(active.group || active.name):_('No working connection')])]),
     E('div',{},[E('span',{class:'flr-muted'},'VPN'),E('strong',{class:'flr-badge'},[d.vpn_enabled?_('VPN is on'):_('VPN is off')])])])];
    if(active)children.push(E('p',{},[active.name+' · '+active.endpoint+' · '+(((s.selection || {}).general || 'down')==='down'?_('VPN traffic blocked'):((s.selection || {}).games || 'down')==='down'?_('TCP · games/UDP blocked'):'TCP / UDP')]));
    if(p.reserve_connection){var reserve=p.reserve_connection,unchecked=p.pending || !(s.channels || {}).gecko || !s.channels.gecko.healthy,what=label(reserve.family)+' · '+reserve.name;
     children.push(E('p',{},[E('strong',{},[p.reserve_warm?_('Warm reserve:'):_('Retained reserve:')]),' ',(p.reserve_warm?(unchecked?_('%s · started in advance, the state needs checking.'):_('%s · started in advance and probed; it carries no sessions, so when AWG fails new connections move without a cold start.')):(unchecked?_('%s · the channel is kept, the state needs checking.'):_('%s · old sessions keep using this channel.'))).format(what)]));}
    Object.keys(s.channels || {}).forEach(function(channel){var h=s.channels[channel],probe=h.probe || {},checked=Date.parse(h.last_check),age=isFinite(checked)&&checked>0?_('%s s ago').format(Math.max(0,Math.floor((Date.now()-checked)/1000))):_('not received yet'),family=channel==='gecko'?((p.reserve_connection || (active && active.family!=='awg'?active:null) || {}).family):channel,parts=[family?label(family):_('Proxy'),_('Last measurement: %s').format(age)];
     if(probe.not_measured)parts.push(_('Measurement skipped: %s').format({cancelled:_('cancelled'),budget_exhausted:_('no budget')}[probe.not_measured] || _('no result')));
     if(h.degraded)parts.push(_('quality degraded'));
     children.push(E('p',{class:'flr-muted'},[parts.join(' · ')]));});
    if(s.diagnostics){var diag=s.diagnostics,last=diag.last_decision,line=_('History in RAM: %s rounds · %s decisions').format(diag.rounds,diag.decisions);
     if(last)line+=' · '+_('Last transition: %s / %s').format(reasons[last.reason] || _('route application'),outcomes[last.outcome] || _('outcome unknown'));
     children.push(E('p',{class:'flr-muted'},[line]));if(diag.snapshot_pending)children.push(E('p',{class:'flr-notice'},_('Saving the history snapshot needs a retry; the current records can be downloaded.')));
     if(diag.wan){var wan=diag.wan.probe || {};children.push(E('p',{class:'flr-muted'},[_('WAN diagnostics: %s · does not affect the VPN choice.').format(wan.not_measured || !wan.measured?_('result unknown'):wan.tcp&&wan.udp?_('TCP / UDP available'):_('the TCP/UDP check failed'))]));}}
    if(p.pending)children.push(E('p',{class:'flr-notice'},[s.last_error?_('Applying is paused. The actual route is shown above.'):_('The choice is saved and waiting to be applied. TCP/UDP checks will confirm a working connection.')]));
    if(p.pending && p.desired_connection && (!active || active.id!==p.desired_connection.id))children.push(E('p',{class:'flr-muted'},[_('Waiting to be applied: %s').format(label(p.desired_connection.family)+' · '+p.desired_connection.name)]));
    if(s.last_error)children.push(E('p',{class:'flr-notice'},[s.last_error]));
    else if(!active && d.vpn_enabled)children.push(E('p',{class:'flr-notice'},_('No working connection. A manual choice is kept on failure; VPN traffic is blocked until it recovers.')));
    if(p.reason)children.push(E('p',{class:'flr-muted'},[p.reason]));
    if(test){var phase=phases[test.phase] || test.phase,result=test.measured?(test.tcp?_('TCP available'):_('TCP failed'))+' · '+(test.udp?_('UDP available'):_('UDP failed')):_('No confirmed measurement');
     children.push(E('div',{class:'flr-notice'},[E('strong',{},[_('Connection test: %s').format(phase)]),E('p',{},[result+' · '+(test.restored?_('original mode restored'):_('restore not confirmed'))])]));}
    if(d.rollback_pending)children.push(E('p',{class:'flr-notice'},_('A 180-second rollback is armed. After checking LAN, WAN, VPN and direct, confirm the connection in "Overview".')));
    if(d.migration_notice)children.push(E('p',{class:'flr-notice'},[d.migration_notice]));
    status.replaceChildren.apply(status,children);
   };
   var diagnostics=flr.button(_('Download diagnostics'),async function(){var data=await flr.collectDiagnostics(function(value){return flr.write({operation:'diagnostics-export',value:value});});flr.download('flr-diagnostics.json',JSON.stringify(data,null,2),'application/json');},null,true);
   var tools=E('section',{class:'flr-card'},[E('h3',{},_('Diagnostics')),E('p',{class:'flr-muted'},_('The history keeps up to 720 rounds and 256 events in RAM. Downloading needs write permission and returns bounded pages; keys and configs are not included.')),diagnostics]);
   var activation=E('section',{class:'flr-card'},[E('h3',{},_('VPN activation')),E('p',{class:'flr-muted'},_('The first activation changes the network with a 180-second rollback guard. After the start check LAN/LuCI, the WAN, the chosen VPN connection and direct; then confirm in "Overview".')),page.action(_('Activate VPN'),function(){if(!window.confirm(_('Activate the VPN with the rollback guard and check LAN/WAN after the start?')))throw new Error(_('Activation cancelled.'));return {operation:'vpn-activate',accepted:true};})]);
   return [status,tools,activation];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
