'use strict';
'require view';
'require flr';

// Routing · custom rules: hand-picked domains and IPv4 addresses, subnets or
// ranges sent through the VPN or directly through the ISP. Every edit names
// the list revision it was made against; a changed list is reloaded.
return view.extend({
 load:function() {
  return Promise.all([flr.routing('routing-rules',{offset:0,limit:50}),flr.routing('routing-policy')]).catch(function(e){return [{unsupported:String(e && e.message || e)},{}];});
 },
 render:function(data) {
  var state={list:data[0],policy:data[1] || {},query:'',offset:0,limit:50},canWrite=L.hasViewPermission();
  var head=[flr.style(),E('h2',{},_('Routing · custom rules'))];
  if(!state.list || state.list.unsupported || !Array.isArray(state.list.rules))
   return E('div',{class:'flr-page'},head.concat([E('p',{class:'flr-notice'},[_('The controller did not return the custom rules: %s').format(state.list && state.list.unsupported || _('no data'))])]));
  function field(tag,attrs,children){attrs=attrs || {};attrs.disabled=canWrite?null:true;return E(tag,attrs,children);}
  var types=[['',_('Detect automatically')],['domain',_('Domain and subdomains')],['ip',_('IPv4 address')],['cidr',_('IPv4 subnet (CIDR)')],['range',_('IPv4 range (first-last)')]];
  var modes=[['vpn',_('Through the VPN')],['direct',_('Directly through the ISP')]];
  var typeNames={domain:_('domain'),ip:_('address'),cidr:_('subnet'),range:_('range')};
  var listBox=E('div',{class:'flr-rules'}),info=E('p',{class:'flr-muted'});
  async function refresh(){state.list=await flr.routing('routing-rules',{query:state.query,offset:state.offset,limit:state.limit});draw();}
  async function after(result){if(result && result.apply)flr.notify(flr.applyText(result.apply));await refresh();}
  async function failed(error){if(/routing rules changed/i.test(error && error.message || ''))await refresh();}
  function act(label,make,aria){return flr.action(label,function(){var request=make();request.routing.revision=state.list.revision;return request;},after,failed,aria);}
  function select(options,value,name){return field('select',{'data-field':name},options.map(function(o){return E('option',{value:o[0],selected:o[0]===value?true:null},[o[1]]);}));}
  // One rule form; read() checks the obvious mistakes before the router does.
  function form(rule,prefix) {
   rule=rule || {type:'',value:'',mode:'vpn',comment:'',enabled:true};
   var value=field('input',{type:'text',maxlength:253,value:rule.value,'data-field':prefix+'value',placeholder:'example.com, 198.51.100.7, 198.51.100.0/24, 198.51.100.10-198.51.100.20'});
   var type=select(types,rule.type || '',prefix+'type'),mode=select(modes,rule.mode,prefix+'mode');
   var comment=field('input',{type:'text',maxlength:120,value:rule.comment || '','data-field':prefix+'comment'}),enabled=field('input',{type:'checkbox',checked:rule.enabled?true:null,'data-field':prefix+'enabled'});
   return {nodes:[flr.field(_('Domain or address'),value),flr.field(_('Type'),type),flr.field(_('Route'),mode),flr.field(_('Comment (optional)'),comment),flr.field(_('Rule enabled'),enabled)],
    value:value,comment:comment,
    read:function() {
     var v=String(value.value || '').trim();
     if(!v)throw new Error(_('Enter a domain, an IPv4 address, a subnet or a range.'));
     if(v.indexOf(':')>=0)throw new Error(_('Only IPv4 is supported: FLR does not route IPv6 destinations.'));
     if(!modes.some(function(m){return m[0]===mode.value;}) || !types.some(function(t){return t[0]===type.value;}))throw new Error(_('Choose a type and a route.'));
     return {type:type.value,value:v,mode:mode.value,comment:String(comment.value || '').trim(),enabled:!!enabled.checked};
    }};
  }
  var add=form(null,'new-');
  var addCard=E('section',{class:'flr-card'},[E('h3',{},_('Add a rule'))].concat(add.nodes,[act(_('Add rule'),function(){return {operation:'routing-rule-add',routing:{rule:add.read()}};})]));
  function ruleCard(rule) {
   var edit=form(rule,'edit-'+rule.id+'-'),badges=[E('span',{class:'flr-badge'},[rule.mode==='vpn'?_('via VPN'):_('direct (ISP)')]),E('span',{class:'flr-badge'},[typeNames[rule.type] || String(rule.type)])];
   if(!rule.enabled)badges.push(E('span',{class:'flr-badge'},_('rule disabled')));
   var notes=[];
   if(rule.local)notes.push(E('p',{class:'flr-notice'},_('Local destinations cover this rule; there they always stay local.')));
   if(rule.mode==='direct' && state.policy.mode==='full')notes.push(E('p',{class:'flr-muted'},_('Ignored in the current routing mode "Everything via VPN".')));
   function update(changes){var r={type:rule.type,value:rule.value,mode:rule.mode,comment:rule.comment || '',enabled:rule.enabled};Object.keys(changes).forEach(function(k){r[k]=changes[k];});return {operation:'routing-rule-update',routing:{id:rule.id,rule:r}};}
   return E('article',{class:'flr-card flr-rule','data-rule':rule.id},[
    E('div',{class:'flr-connection-head'},[E('h4',{class:'flr-value'},[String(rule.value)])].concat(badges)),
    rule.comment?E('p',{class:'flr-muted'},[String(rule.comment)]):'',
   ].concat(notes,[
    E('div',{class:'flr-actions'},[
     act(rule.enabled?_('Disable'):_('Enable'),function(){return update({enabled:!rule.enabled});},(rule.enabled?_('Disable rule %s'):_('Enable rule %s')).format(rule.value)),
     act(_('Delete'),function(){if(!window.confirm(_('Delete the rule for "%s"?').format(rule.value)))throw new Error(_('Deletion cancelled.'));return {operation:'routing-rule-delete',routing:{id:rule.id}};},_('Delete rule %s').format(rule.value))]),
    E('details',{class:'flr-details'},[E('summary',{},_('Edit'))].concat(edit.nodes,[act(_('Save rule'),function(){return {operation:'routing-rule-update',routing:{id:rule.id,rule:edit.read()}};},_('Save rule %s').format(rule.value))]))]).filter(Boolean));
  }
  var search=E('input',{type:'search',maxlength:200,placeholder:_('Search rules and comments'),'data-field':'rule-query'});
  var prev=E('button',{class:'cbi-button',click:function(){state.offset=Math.max(0,state.offset-state.limit);return refresh().catch(flr.error);}},_('Previous page'));
  var next=E('button',{class:'cbi-button',click:function(){state.offset+=state.limit;return refresh().catch(flr.error);}},_('Next page'));
  function draw() {
   var l=state.list,rules=l.rules || [],from=rules.length?l.offset+1:0,to=l.offset+rules.length;
   listBox.replaceChildren.apply(listBox,rules.length?rules.map(ruleCard):[E('p',{class:'flr-muted'},_('No custom rules match.'))]);
   info.replaceChildren(_('Rules %s–%s of %s matching (%s in total).').format(from,to,l.matched,l.total));
   prev.disabled=l.offset>0?null:true;next.disabled=to<l.matched?null:true;
   if(l.error)info.replaceChildren(_('Rules %s–%s of %s matching (%s in total).').format(from,to,l.matched,l.total),E('br'),_('The stored rules file is not in use: %s').format(l.error));
  }
  draw();
  return E('div',{class:'flr-page'},head.concat([
   E('section',{class:'flr-card'},[
    E('p',{},_('A custom rule sends a domain (with its subdomains), an IPv4 address, subnet or range either through the VPN or directly through the ISP. Custom rules take precedence over the lists of the routing policy; only local destinations always stay local. The most specific rule wins; for the same destination the VPN wins.')),
    E('p',{class:'flr-muted'},_('"Direct" rules apply in the routing modes "Split" and "Everything via VPN except essential direct services" and are ignored in "Everything via VPN"; "VPN" rules always apply. A change applies to new connections at once, without restarting the VPN; existing connections keep their route. IPv6 is not supported. The rules are stored on the router only.'))]),
   addCard,
   E('section',{class:'flr-card'},[E('h3',{},_('Rules')),E('div',{class:'flr-actions'},[search,E('button',{class:'cbi-button',click:function(){state.query=search.value;state.offset=0;return refresh().catch(flr.error);}},_('Search'))]),info,listBox,E('div',{class:'flr-actions'},[prev,next])])]));
 },handleSave:null,handleSaveApply:null,handleReset:null
});
