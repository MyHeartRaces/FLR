'use strict';
'require view';
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
  var policyCard=[E('h3',{},_('Active policy')),
   E('p',{},[p.source==='overlay'?_('The private overlay from /etc/flr-runtime/policy is in use.'):_('The image default is in use: everything except local destinations goes through the VPN.')]),
   E('p',{class:'flr-muted'},[_('policy.json: status %s · version %s').format(String(meta.status || '—'),String(meta.version || '—'))])];
  if(meta.note)policyCard.push(E('p',{class:'flr-muted'},[String(meta.note)]));
  if(p.overlay_error)policyCard.push(E('p',{class:'flr-notice'},[_('The private overlay was refused, so the image default is in use: %s').format(p.overlay_error)]));
  if(p.backup_present)policyCard.push(E('p',{class:'flr-muted'},_('A previous overlay is kept as a backup; "Import & export" can restore it.')));
  policyCard.push(E('p',{class:'flr-muted'},[!live.controller?_('The controller is not running; changes apply when it starts.'):!live.vpn?_('The VPN is not running; changes apply when it starts.'):_('Applied live in mode %s.').format(String(live.applied_mode || '—'))]));
  if(live.last_apply)policyCard.push(E('p',{class:'flr-muted'},[_('Last applied: %s (%s).').format(String(live.last_apply),String(live.last_apply_source || ''))]));
  var customError=custom.error || live.custom_rules_error;
  if(customError)policyCard.push(E('p',{class:'flr-notice'},[_('Custom rules are not in use: %s').format(customError)]));
  // Routing mode (moved here from Settings).
  var routingModes=[['split',_('Split: lists from the private policy')],['full_domestic',_('Everything via VPN except essential direct services')],['full',_('Everything via VPN')]],routing=[];
  if(typeof p.mode==='string') {
   var known=routingModes.some(function(m){return m[0]===p.mode;});
   var routingMode=controlE('select',{'data-field':'routing_mode'},(known?[]:[E('option',{value:p.mode,selected:true},[_('Current: %s').format(p.mode)])]).concat(routingModes.map(function(m){return E('option',{value:m[0],selected:p.mode===m[0]?true:null},[m[1]]);})));
   routing=[E('h3',{},_('Routing mode')),
    E('p',{},_('"Split" sends destinations from the private policy directly (without it, only local ones). "Everything via VPN except essential direct services" keeps a short list of services that do not work from a foreign address direct. "Everything via VPN" keeps only the LAN, the router itself and explicit direct (SOCKS, the "Direct" device route) direct.')),
    E('p',{},_('Custom "direct" rules apply in the first two modes; custom "VPN" rules apply in all of them.')),
    E('p',{class:'flr-muted'},_('The full modes increase traffic to the server, add latency for domestic sites and show them the server address.')),
    flr.field(_('Mode'),routingMode),
    flr.action(_('Save routing mode'),function(){if(!routingModes.some(function(m){return m[0]===routingMode.value;}))throw new Error(_('Choose a routing mode.'));return {operation:'settings',settings:{routing_mode:routingMode.value}};})];
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
  var rows=p.rulesets.map(function(rs) {
   var counts=rs.counts || {},domains=(counts.domain || 0)+(counts.domain_suffix || 0)+(counts.domain_keyword || 0)+(counts.domain_regex || 0);
   return E('tr',{class:'tr','data-ruleset':rs.name},[
    E('td',{class:'td'},[E('strong',{},[names[rs.name] || String(rs.name)]),E('br'),E('code',{},[String(rs.name)])]),
    E('td',{class:'td'},[classes[rs.class] || String(rs.class)]),
    E('td',{class:'td'},[rs.error?_('unreadable: %s').format(rs.error):_('%s in total · %s domain · %s address').format(rs.total || 0,domains,counts.ip_cidr || 0)]),
    E('td',{class:'td'},[rs.active?_('in use'):_('off in this mode')]),
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
