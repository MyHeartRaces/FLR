'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  function label(f){return flr.familyLabel(f);}
  var formats={url:_('link (URL)'),json:'JSON (sing-box / Xray)','awg-conf':_('AWG file (.conf)')};
  var formatNotes={url:_('The FLR import and compatible clients accept this link.'),json:_('A link cannot carry every setting of this connection, so this is JSON, which the FLR import accepts.'),'awg-conf':_('AWG has no link format: this is the complete .conf file, which the FLR import accepts.')};
  var phases={queued:_('queued'),probing:_('probing'),restoring:_('restoring'),finished:_('finished'),cancelled:_('cancelled by a new choice'),failed:_('not started'),'recovery-pending':_('restore needs a service restart')};
  function health(channel){if(!channel)return _('no checks yet');if(channel.degraded)return channel.healthy?_('checks pass, quality degraded'):_('checks fail, quality degraded');return channel.healthy?_('checks pass'):_('checks fail');}
  // Live role of one connection in the current status; text only, never HTML.
  function role(c,d) {
   var s=d.status || {},p=s.proxy || {},active=s.active_connection,channels=s.channels || {},test=s.connection_test,parts=[],channel=c.family==='awg'?channels.awg:channels.gecko,isActive=!!(active && active.id===c.id);
   if(isActive)parts.push(_('Active: new connections go here'),health(channel));
   else if(p.reserve_connection && p.reserve_connection.id===c.id)parts.push(p.reserve_warm?_('Warm reserve'):_('Retained reserve: old sessions keep going through it'),channels.gecko && channels.gecko.healthy?_('checks pass'):_('state needs checking'));
   else if(p.pending && p.desired_connection && p.desired_connection.id===c.id)parts.push(_('Waiting to be applied'));
   else parts.push(c.enabled?_('Not in use now'):_('Disabled for selection'));
   if(test && test.id===c.id){parts.push(_('Test: %s').format(phases[test.phase] || test.phase));if(test.measured)parts.push(test.tcp?_('TCP available'):_('TCP failed'),test.udp?_('UDP available'):_('UDP failed'));}
   return {active:isActive,text:parts.join(' · ')};
  }
  return flr.connectionPage(initial,poll,function(state,page) {
   var field=page.field,items=state.connections || [],selection=state.selection || {mode:'auto'},updates=[];
   function exportButton(c,box) {
    return flr.button(_('Export'),async function() {
     var data;
     try{data=await flr.write({operation:'connection-export',id:c.id,expected_generation:page.state.generation});}catch(e){await page.failed(e);throw e;}
     if(!data || data.id!==c.id || typeof data.config!=='string' || !formats[data.format])throw new Error(_('FLR returned an invalid export.'));
     var text=E('textarea',{rows:data.format==='url'?3:14,readonly:true,spellcheck:'false','aria-label':_('Configuration %s').format(c.name),'data-export':c.id});
     text.value=data.config;
     box.replaceChildren(E('h4',{},[_('Export: %s').format(formats[data.format])]),E('p',{class:'flr-notice'},_('Contains the connection keys and passwords. Do not publish it or send it over open channels; press "Hide" after copying.')),E('p',{class:'flr-muted'},[formatNotes[data.format]]),text,E('div',{class:'flr-actions'},[
      flr.button(_('Copy'),async function(){var nav=window.navigator;if(nav && nav.clipboard && window.isSecureContext)await nav.clipboard.writeText(text.value);else{text.select();if(!document.execCommand('copy'))throw new Error(_('The browser did not allow copying. Select the text and copy it by hand.'));}flr.notify(_('Configuration copied.'));},_('Copy configuration %s').format(c.name)),
      flr.button(_('Download'),async function(){flr.download(data.filename,data.config,data.format==='json'?'application/json':'text/plain');},_('Download configuration %s').format(c.name)),
      flr.button(_('Hide'),async function(){text.value='';box.replaceChildren();},_('Hide configuration %s').format(c.name))]));
    },_('Export %s').format(c.name),true);
   }
   var cards=items.map(function(c) {
    var pinned=selection.mode==='connection' && selection.id===c.id,unavailable=(state.availability || {})[c.id];
    var name=field('input',{type:'text',maxlength:80,value:c.name}),group=field('input',{type:'text',maxlength:80,value:c.group}),enabled=field('input',{type:'checkbox',checked:c.enabled?true:null}),replacement=field('textarea',{rows:4,'data-replace':c.id,placeholder:_('New complete configuration: AWG, JSON, URI or base64')}),file=field('input',{type:'file',accept:'.json,.txt,.conf'});
    var activeBadge=E('span',{class:'flr-badge flr-badge-active'}),live=E('p',{class:'flr-live'}),exportBox=E('div',{class:'flr-export'});
    function replace(data){return {operation:'connection-replace',id:c.id,data:data};}
    var actions=[];
    if(!pinned)actions.push(page.action(_('Make active'),function(){if((!c.enabled || unavailable) && !window.confirm((unavailable?_('"%s" is unavailable: a component is missing. The manual choice will be kept, but VPN traffic is blocked until the connection works. Continue?'):_('"%s" is disabled for selection. The manual choice will be kept, but VPN traffic is blocked until the connection works. Continue?')).format(c.name)))throw new Error(_('Choice cancelled.'));return {operation:'selection',selection:flr.proxySelection('connection','',c.id)};},null,_('Make active %s').format(c.name)));
    actions.push(
     page.action(_('Test'),function(){if(!window.confirm(_('A test briefly changes the VPN path, also when testing a disabled connection. Current TCP/UDP sessions may be interrupted. The original choice and an eligible reserve are restored afterwards; interrupted sessions do not come back. Continue?')))throw new Error(_('Test cancelled.'));return {operation:'connection-test',id:c.id};},null,_('Test %s').format(c.name)),
     exportButton(c,exportBox),
     page.action(_('Delete'),function(){if(!window.confirm((pinned?_('Delete "%s"? The manual choice will be switched to "Auto" explicitly.'):_('Delete "%s"?')).format(c.name)))throw new Error(_('Deletion cancelled.'));var request={operation:'connection-delete',id:c.id};if(pinned)request.selection={mode:'auto'};return request;},null,_('Delete %s').format(c.name)));
    var facts=[c.endpoint,c.capabilities.udp?'TCP / UDP':_('TCP only')];
    if(!c.enabled)facts.push(_('turned off'));
    if(unavailable)facts.push(_('missing %s').format(unavailable.replace('missing-component:','')));
    var card=E('article',{class:'flr-card flr-connection'},[
     E('div',{class:'flr-connection-head'},[E('h4',{},[c.name]),E('span',{class:'flr-badge'},[label(c.family)]),E('span',{class:'flr-muted'},[c.group || _('No group set')]),pinned?E('span',{class:'flr-badge'},_('Chosen manually')):'',activeBadge]),
     E('p',{class:'flr-muted'},[facts.join(' · ')]),
     live,E('div',{class:'flr-actions'},actions),exportBox,
     E('details',{class:'flr-details'},[E('summary',{},_('Name, group, selection')),flr.field(_('Connection name'),name),flr.field(_('VPS group'),group),flr.field(_('Included in selection'),enabled),page.action(_('Save'),function(){return {operation:'connection-update',id:c.id,metadata:{name:name.value,group:flr.group(group.value),enabled:enabled.checked}};},null,_('Save %s').format(c.name))]),
     E('details',{class:'flr-details'},[E('summary',{},_('Replace configuration')),E('p',{class:'flr-muted'},_('Replacing keeps the ID, name, group and inclusion. Paste the complete new config; the current one is available with the "Export" button.')),flr.field(_('New config'),replacement),page.action(_('Replace configuration'),function(){return replace(replacement.value);},function(){replacement.value='';},_('Replace configuration %s').format(c.name)),flr.field(_('Replacement file'),file),page.action(_('Replace from file'),async function(){return replace(await flr.fileText(file,65536));},function(){file.value='';},_('Replace from file %s').format(c.name))])]);
    updates.push(function(d){var r=role(c,d);live.replaceChildren(r.text);activeBadge.replaceChildren(r.active?_('Active'):'');activeBadge.hidden=!r.active;if(card.classList)card.classList.toggle('flr-connection-active',r.active);});
    return card;
   });
   page.status=function(d){updates.forEach(function(update){update(d);});};
   var mode=E('section',{class:'flr-card'},[E('h2',{},_('Proxy · connections')),E('p',{},[_('Mode:'),' ',E('strong',{},[flr.selectionText(selection,items)])]),
    E('p',{class:'flr-muted'},_('"Make active" pins a connection manually: when it fails, FLR does not switch on its own and VPN traffic is blocked until it recovers. "Auto" brings back fallback by the "Order" tab. A test briefly changes the VPN path and may interrupt sessions.')),
    selection.mode!=='auto'?page.action(_('Return to "Auto"'),function(){return {operation:'selection',selection:{mode:'auto'}};}):''].filter(Boolean));
   return [mode,E('div',{class:'flr-connections'},cards.length?cards:[E('p',{class:'flr-notice'},_('No connections. Add a configuration on the "Import" tab.'))])];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
