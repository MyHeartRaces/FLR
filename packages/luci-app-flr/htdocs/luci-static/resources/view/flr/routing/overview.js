'use strict';
'require view';
'require poll';
'require flr';

// Routing · overview: the policy in use, the routing mode and a paged,
// searchable view of every ruleset. Entries are fetched a page at a time; a
// large overlay never reaches the DOM whole.
return view.extend({
 load:function(){return flr.routing('routing-policy').catch(function(e){return {unsupported:String(e && e.message || e)};});},
 render:function(p) {
  var canWrite=L.hasViewPermission();
  function controlE(tag,attrs,children){attrs=attrs || {};attrs.disabled=canWrite?null:true;return E(tag,attrs,children);}
  var head=[flr.style(),E('h2',{},_('Routing · overview'))];
  if(!p || p.unsupported || !Array.isArray(p.rulesets))
   return E('div',{class:'flr-page'},head.concat([E('p',{class:'flr-notice'},[_('The controller did not return the routing policy: %s').format(p && p.unsupported || _('no data'))])]));
  var names={'local-domains':_('Local domains'),'local-ips':_('Local addresses'),'vpn-required':_('Always via VPN'),'direct-essential':_('Essential direct services'),'game-platforms':_('Game platforms'),'vpn-services':_('VPN services'),'roscom-direct-domains':_('Broad direct domains'),'roscom-direct-ips':_('Broad direct addresses')};
  var classes={local:_('Local'),direct:_('Direct (ISP)'),general:_('VPN'),games:_('Games (VPN)')};
  var kinds={domain:_('exact domain'),domain_suffix:_('domain and subdomains'),domain_keyword:_('keyword'),domain_regex:_('regular expression'),ip_cidr:_('address / subnet')};
  var meta=p.policy || {},live=p.live || {},custom=p.custom_rules || {},summary=custom.summary || {};
  var modes=[
   {value:'split',label:_('Full proxy'),description:_('Default mode. Traffic uses the VPN unless an installed direct list or custom rule routes it through the ISP.')},
   {value:'tunnel',label:_('Tunnel'),description:_('Traffic uses the ISP by default. Protected destinations, game platforms, VPN services and custom VPN rules use the VPN. Custom Direct rules are inactive.')},
   {value:'direct',label:_('Direct'),description:_('Traffic follows the normal ISP route and uses the router’s usual DNS. Direct bypasses FLR routing rules, device routes and DNS filtering.')}];
  var legacyLabels=new Map([['proxy',_('Full proxy with custom exceptions')],['full_domestic',_('Tunnel with essential bypasses')],['full',_('Strict tunnel')]]);
  var routingMode,legacyOption,description;
  var rulesetStates=new Map();
  function findMode(value){return modes.find(function(mode){return mode.value===value;});}
  function modeLabel(value){var mode=findMode(value);return mode?mode.label:legacyLabels.get(value) || String(value || '—');}
  function selectableOptions(selected){return modes.map(function(mode){return E('option',{value:mode.value,selected:selected===mode.value?true:null},[mode.label]);});}
  function describe(value){var mode=findMode(value);description.replaceChildren(mode?mode.description:'');}
  function pending(){return live.controller && (live.pending===true || (live.vpn && p.mode && p.mode!==live.applied_mode));}
  function liveText(){
   if(!live.controller)return _('The controller is not running; changes apply when it starts.');
   if(pending())return _('Waiting to apply %s. Active mode: %s.').format(modeLabel(p.mode),modeLabel(live.applied_mode));
   if(!live.vpn && live.applied_mode!=='direct')return _('The VPN is not running; changes apply when it starts.');
   return _('Active routing mode: %s.').format(modeLabel(live.applied_mode));
  }
  function lastApplyText(){return live.last_apply?_('Last applied: %s (%s).').format(String(live.last_apply),String(live.last_apply_source || '')):'';}
  var lastLiveText=liveText(),liveStatus=E('p',{class:'flr-muted','aria-live':'polite'},[lastLiveText]);
  var appliedAt=E('p',{class:'flr-muted',hidden:live.last_apply?null:true},[lastApplyText()]);
  async function refreshMode(){
   var latest=await flr.routing('routing-policy');
   p.mode=latest.mode;
   live=latest.live || {};
   if(legacyOption && findMode(p.mode)) {
    var selected=findMode(routingMode.value)?routingMode.value:p.mode;
    routingMode.replaceChildren.apply(routingMode,selectableOptions(selected));
    routingMode.value=selected;
    describe(selected);
    legacyOption=null;
   }
   var text=liveText();
   if(text!==lastLiveText) {
    lastLiveText=text;
    liveStatus.replaceChildren(text);
   }
   appliedAt.hidden=!live.last_apply;
   appliedAt.replaceChildren(lastApplyText());
   if(Array.isArray(latest.rulesets))latest.rulesets.forEach(function(rs){if(rulesetStates.has(rs.name))rulesetStates.get(rs.name).replaceChildren(ruleState(rs));});
  }
  var policyCard=[E('h3',{},_('Installed policy')),
   E('p',{},[p.source==='overlay'?_('The private overlay from /etc/flr-runtime/policy is installed.'):_('The image policy is installed.')]),
   E('p',{class:'flr-muted'},[_('policy.json: status %s · version %s').format(String(meta.status || '—'),String(meta.version || '—'))])];
  if(meta.note)policyCard.push(E('p',{class:'flr-muted'},[String(meta.note)]));
  if(p.overlay_error)policyCard.push(E('p',{class:'flr-notice'},[_('The private overlay was refused, so the image default is in use: %s').format(p.overlay_error)]));
  if(p.backup_present)policyCard.push(E('p',{class:'flr-muted'},_('A previous overlay is kept as a backup; "Import & export" can restore it.')));
  policyCard.push(liveStatus,appliedAt);
  var customError=custom.error || live.custom_rules_error;
  if(customError)policyCard.push(E('p',{class:'flr-notice'},[_('Custom rules are not in use: %s').format(customError)]));
  var routing=[];
  if(typeof p.mode==='string') {
   description=E('p',{id:'flr-routing-mode-description',class:'flr-muted','aria-live':'polite'});
   legacyOption=findMode(p.mode)?null:E('option',{value:p.mode,selected:true,disabled:true},[_('Current: %s').format(modeLabel(p.mode))]);
   var options=selectableOptions(p.mode);
   if(legacyOption)options.unshift(legacyOption);
   routingMode=controlE('select',{'data-field':'routing_mode','aria-describedby':'flr-routing-mode-description',change:function(){describe(routingMode.value);}},options);
   describe(p.mode);
   routing=[E('h3',{},_('Routing mode')),
    flr.field(_('Mode'),routingMode),
    description,
    E('p',{class:'flr-muted'},_('Mode changes apply to new connections. Existing connections keep their routes. Local destinations stay on the LAN.')),
    E('p',{},[E('a',{href:L.url('admin','flr','proxy','order')},_('Choose the VPN connection in Proxy'))]),
    flr.action(_('Save routing mode'),function(){if(!findMode(routingMode.value))throw new Error(_('Choose a routing mode.'));return {operation:'settings',settings:{routing_mode:routingMode.value}};},refreshMode)];
   poll.add(function(){if(pending())return refreshMode().catch(flr.error);},5);
  }
  // Paged entry browser for one ruleset.
  var browser=E('section',{class:'flr-card','data-browser':'',hidden:true}),view={ruleset:'',query:'',offset:0,limit:100};
  var search=E('input',{type:'search',maxlength:200,placeholder:_('Search entries'),'data-field':'entry-query'});
  function drawPage(d) {
   var entries=Array.isArray(d.entries)?d.entries:[],from=entries.length?d.offset+1:0,to=d.offset+entries.length;
   var rows=entries.map(function(e){return E('tr',{class:'tr'},[E('td',{class:'td'},[kinds[e.kind] || String(e.kind)]),E('td',{class:'td flr-value'},[String(e.value)])]);});
   var prev=E('button',{class:'cbi-button',disabled:d.offset>0?null:true,click:function(){view.offset=Math.max(0,view.offset-view.limit);return fetchPage();}},_('Previous page'));
   var next=E('button',{class:'cbi-button',disabled:to<d.matched?null:true,click:function(){view.offset+=view.limit;return fetchPage();}},_('Next page'));
   browser.replaceChildren(E('h3',{},[_('Entries of %s').format(names[view.ruleset] || view.ruleset)]),
    E('div',{class:'flr-actions'},[search,E('button',{class:'cbi-button',click:function(){view.query=search.value;view.offset=0;return fetchPage();}},_('Search')),E('button',{class:'cbi-button',click:function(){browser.hidden=true;browser.replaceChildren();}},_('Close'))]),
    E('p',{class:'flr-muted'},[_('%s–%s of %s matching (%s in total).').format(from,to,d.matched,d.total)]),
    E('table',{class:'table flr-table'},[E('tr',{class:'tr table-titles'},[E('th',{class:'th'},_('Kind')),E('th',{class:'th'},_('Value'))])].concat(rows)),
    E('div',{class:'flr-actions'},[prev,next]));
  }
  function fetchPage(){return flr.routing('routing-entries',{ruleset:view.ruleset,query:view.query,offset:view.offset,limit:view.limit}).then(drawPage).catch(flr.error);}
  function browse(name){view.ruleset=name;view.query='';view.offset=0;search.value='';browser.hidden=false;return fetchPage();}
  function ruleState(rs){return rs.active?_('in use'):_('off in this mode');}
  var rows=p.rulesets.map(function(rs) {
   var counts=rs.counts || {},domains=(counts.domain || 0)+(counts.domain_suffix || 0)+(counts.domain_keyword || 0)+(counts.domain_regex || 0);
   var state=E('td',{class:'td'},[ruleState(rs)]);
   rulesetStates.set(rs.name,state);
   return E('tr',{class:'tr','data-ruleset':rs.name},[
    E('td',{class:'td'},[E('strong',{},[names[rs.name] || String(rs.name)]),E('br'),E('code',{},[String(rs.name)])]),
    E('td',{class:'td'},[classes[rs.class] || String(rs.class)]),
    E('td',{class:'td'},[rs.error?_('unreadable: %s').format(rs.error):_('%s in total · %s domain · %s address').format(rs.total || 0,domains,counts.ip_cidr || 0)]),
    state,
    E('td',{class:'td'},[E('button',{class:'cbi-button','aria-label':_('Browse %s').format(rs.name),disabled:rs.total?null:true,click:function(){return browse(rs.name);}},_('Browse'))])]);
  });
  var rulesets=[E('h3',{},_('Rulesets')),
   E('p',{class:'flr-muted'},_('Counts per matcher kind of the policy in use. Lists switched off by the routing mode stay listed but do not route.')),
   E('table',{class:'table flr-table'},[E('tr',{class:'tr table-titles'},[E('th',{class:'th'},_('Ruleset')),E('th',{class:'th'},_('Class')),E('th',{class:'th'},_('Entries')),E('th',{class:'th'},_('In this mode')),E('th',{class:'th'},'')])].concat(rows))];
  var customCard=[E('h3',{},_('Custom rules')),
   E('p',{},[_('Custom rules: %s in total, %s enabled (%s via VPN, %s direct).').format(summary.total || 0,summary.enabled || 0,summary.vpn || 0,summary.direct || 0)]),
   E('p',{},[E('a',{href:L.url('admin','flr','routing','rules')},_('Manage custom rules'))])];
  return E('div',{class:'flr-page'},head.concat([
   E('section',{class:'flr-card'},policyCard),
   routing.length?E('section',{class:'flr-card'},routing):'',
   E('section',{class:'flr-card'},rulesets),browser,
   E('section',{class:'flr-card'},customCard)].filter(Boolean)));
 },handleSave:null,handleSaveApply:null,handleReset:null
});
