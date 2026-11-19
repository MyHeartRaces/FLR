'use strict';
'require view';
'require flr';

// Routing · import & export: the whole effective routing configuration as one
// JSON file, moved in chunks below the LuCI request limit and checked whole
// on both sides; a RoscomVPN routing profile converted on the router; plus
// apply, reset to the image default and backup restore.
var roscomPresets=[
 ['Whitelist','https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/refs/heads/main/HAPP/WHITELIST.JSON'],
 ['Default','https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/refs/heads/main/HAPP/DEFAULT.JSON']];
return view.extend({
 load:function(){return flr.routing('routing-policy').catch(function(e){return {unsupported:String(e && e.message || e)};});},
 render:function(p) {
  p=p || {};
  var head=[flr.style(),E('h2',{},_('Routing · import & export'))];
  if(p.unsupported)return E('div',{class:'flr-page'},head.concat([E('p',{class:'flr-notice'},[_('The controller did not return the routing policy: %s').format(p.unsupported)])]));
  var maxBytes=16*1024*1024;
  var exportProgress=E('p',{class:'flr-muted','data-progress':'export'}),importProgress=E('p',{class:'flr-muted','data-progress':'import'}),backupState=E('p',{class:'flr-muted'});
  function progress(node){return function(done,total){node.replaceChildren(_('%s of %s bytes').format(done,total));};}
  function showBackup(present){backupState.replaceChildren(present?_('A backup of the previous overlay is saved.'):_('No backup is saved.'));}
  showBackup(p.backup_present);
  async function after(result){if(result && result.apply)flr.notify(flr.applyText(result.apply));if(result && typeof result.backup_present==='boolean')showBackup(result.backup_present);}
  var file=E('input',{type:'file',accept:'.json,application/json',disabled:L.hasViewPermission()?null:true});
  var exportButton=flr.button(_('Download routing configuration'),async function() {
   var result=await flr.exportRouting(progress(exportProgress));
   flr.download(result.filename,result.bytes,'application/json');
   exportProgress.replaceChildren(_('Downloaded (%s).').format(result.source==='overlay'?_('private overlay'):_('image default')));
  },null,true);
  var importButton=flr.button(_('Import file'),async function() {
   var chosen=file.files && file.files[0];
   if(!chosen)throw new Error(_('Choose a file.'));
   if(!chosen.size || chosen.size>maxBytes)throw new Error(_('The file is empty or larger than 16 MiB.'));
   if(!window.confirm(_('Import "%s"? The router checks the whole file first; the current overlay is kept as the backup.').format(chosen.name)))throw new Error(_('Import cancelled.'));
   var bytes=new Uint8Array(await chosen.arrayBuffer());
   var result=await flr.importRouting(bytes,progress(importProgress));
   var parts=[];
   if(result && result.imported && result.imported.policy)parts.push(_('policy and rulesets'));
   if(result && result.imported && typeof result.imported.custom_rules==='number')parts.push(_('%s custom rules').format(result.imported.custom_rules));
   importProgress.replaceChildren(_('Imported: %s.').format(parts.join(', ')));
   file.value='';
   if(result && result.imported && result.imported.policy)showBackup(true);
   flr.notify(flr.applyText(result && result.apply));
  },null,true);
  // RoscomVPN: a profile from an HTTPS URL or a (possibly edited) file.
  var roscomURL=E('input',{type:'text',placeholder:'https://…','data-field':'roscomvpn_url',disabled:L.hasViewPermission()?null:true});
  var roscomFile=E('input',{type:'file',accept:'.json,.deeplink,.txt,application/json,text/plain',disabled:L.hasViewPermission()?null:true});
  var roscomState=E('p',{class:'flr-muted','data-progress':'roscomvpn'}),roscomReport=E('div',{'data-report':'roscomvpn'});
  function phaseText(phase){return {queued:_('Waiting to start…'),'downloading profile':_('Downloading the profile…'),'downloading geosite':_('Downloading geosite…'),'downloading geoip':_('Downloading geoip…'),converting:_('Converting…'),installing:_('Installing…')}[phase] || String(phase || '');}
  function pathText(path){return {'vpn-awg':_('through the VPN (AWG)'),'vpn-gecko':_('through the VPN (Hysteria2)'),'vpn-vless':_('through the VPN (VLESS)'),wan:_('through the ISP (WAN)')}[path] || String(path || '');}
  // Issue and note codes from the router (geodata.Reasons): translated here,
  // the router's English text is the fallback for codes this page predates.
  var reasonTexts={
   empty_entry:_('empty entry'),
   private_in_proxy:_('private destinations always stay local in FLR'),
   no_geosite_data:_('no geosite data'),
   no_geoip_data:_('no geoip data'),
   category_unreadable:_('unreadable category: %s'),
   category_missing:_('category not found in the data file'),
   ext_unsupported:_('external data files are not supported'),
   prefix_unsupported:_('unsupported matcher prefix'),
   ipv6:_('IPv6: FLR routes IPv4 only'),
   geoip_inverted:_('inverted geoip categories are not supported'),
   not_ip:_('not an IP address, CIDR or geoip category'),
   regex_too_long:_('regular expression longer than 1024 bytes'),
   regex_invalid:_('invalid regular expression'),
   name_empty:_('empty domain'),
   name_too_long:_('domain longer than 253 characters'),
   name_not_punycode:_('internationalized name not in punycode (xn--…)'),
   name_invalid:_('invalid characters in domain'),
   block_not_applied:_('FLR does not block destinations; they follow the other lists (unlisted: VPN)'),
   dns_hosts:_('FLR resolves every name through its own DNS broker; static host entries are not imported'),
   dns_servers:_('FLR uses its own resolvers: DoH inside the VPN, and the direct resolver of its settings for direct names'),
   fake_dns:_('FLR does not use fake DNS answers'),
   domain_strategy:_('FLR always matches the name first and, for unlisted names, the resolved IPv4 address (the same as IPIfNonMatch)'),
   route_order:_('FLR always gives the VPN lists precedence over the direct lists (block-proxy-direct)'),
   global_proxy:_('FLR still sends unlisted destinations through the VPN'),
   note_bare_keywords:_('%s bare entries were imported as substring (keyword) matches, as Xray matches them; write domain:example.com for a domain and its subdomains'),
   note_proxyip_wins:_('an address in ProxyIp goes through the VPN even when its name is in DirectSites (FLR matches address sets before name-derived direct sets)'),
   note_split_only:_('DirectSites and DirectIp apply in routing mode split only; full_domestic and full ignore them'),
   note_duplicate_refs:_('%s repeated category references were expanded once'),
   note_attribute_filter:_('attribute filters follow Xray: geosite:name@attr keeps domains with the attribute key attr; a leading ! is part of the key')};
  function coded(item,fallback){var t=reasonTexts[item && item.code],args=Array.isArray(item && item.args)?item.args.map(String):[];return t?t.format.apply(t,args):String(fallback || '');}
  function issues(title,list){
   if(!Array.isArray(list) || !list.length)return [];
   return [E('h4',{},[title]),E('ul',{},list.map(function(i){return E('li',{},[_('%s: %s entries — %s').format(String(i.field),String(i.count),coded(i,i.reason))+(Array.isArray(i.examples) && i.examples.length?' ('+i.examples.map(String).join(', ')+')':'')]);}))];
  }
  function showReport(result){
   var r=result && result.report || {},rows=[];
   Object.keys(r.rulesets || {}).forEach(function(name){var x=r.rulesets[name] || {};rows.push(E('tr',{},[E('td',{},[String(name)]),E('td',{},[String(x.total)]),E('td',{},[String(x.imported)])]));});
   var parts=[E('p',{},[result && result.installed?_('Installed: the previous policy is kept as the backup.'):_('Preview only: nothing was changed.')]),
    E('p',{},[_('Profile: %s').format(String(r.name || ''))]),
    E('p',{},[_('Downloads went %s.').format(pathText(result && result.download_path))]),
    E('table',{class:'table'},[E('tr',{},[E('th',{},[_('Ruleset')]),E('th',{},[_('Entries')]),E('th',{},[_('From the profile')])])].concat(rows))];
   if(Array.isArray(r.categories) && r.categories.length)parts.push(E('p',{},[_('Categories: %s').format(r.categories.map(function(c){return String(c.name)+' · '+String(c.entries);}).join(', '))]));
   parts=parts.concat(issues(_('Skipped entries'),r.skipped),issues(_('Not applied by FLR'),r.not_applied));
   if(Array.isArray(r.notes) && r.notes.length)parts.push(E('h4',{},[_('Notes')]),E('ul',{},r.notes.map(function(n){return E('li',{},[coded(n,n && n.text)]);})));
   roscomReport.replaceChildren.apply(roscomReport,parts);
  }
  async function roscomRun(dryRun){
   var chosen=roscomFile.files && roscomFile.files[0],url=String(roscomURL.value || '').trim();
   if(!chosen && !/^https:\/\//.test(url))throw new Error(_('Choose a preset, enter an HTTPS URL or choose a profile file.'));
   if(chosen && (!chosen.size || chosen.size>1024*1024))throw new Error(_('The profile file is empty or larger than 1 MiB.'));
   if(!dryRun && !window.confirm(_('Import this RoscomVPN profile? It replaces the current routing policy on the router. The previous policy is kept as the backup and can be brought back with "Restore backup". Custom rules stay as they are.')))throw new Error(_('Import cancelled.'));
   var self=flr,args=dryRun?{dry_run:true}:{accepted:true},phase=function(p){roscomState.replaceChildren(phaseText(p));};
   roscomReport.replaceChildren();phase('queued');
   var result;
   if(chosen) {
    var bytes=new Uint8Array(await chosen.arrayBuffer());
    result=await flr.stageRouting(bytes,null,function(id){args.staging_id=id;return self.roscomvpn(args,phase);});
   } else {
    args.url=url;result=await flr.roscomvpn(args,phase);
   }
   roscomState.replaceChildren(result && result.installed?_('Imported.'):_('Preview ready.'));
   showReport(result);
   if(result && result.installed){showBackup(result.backup_present!==false);flr.notify(flr.applyText(result.apply));}
  }
  var presetButtons=roscomPresets.map(function(p){return E('button',{class:'cbi-button',disabled:L.hasViewPermission()?null:true,click:function(){roscomURL.value=p[1];roscomFile.value='';}},p[0]==='Whitelist'?_('Whitelist preset'):_('Default preset'));});
  var roscomSection=E('section',{class:'flr-card'},[E('h3',{},[_('RoscomVPN routing profile')]),
   E('p',{},[_('Converts a RoscomVPN routing profile (Happ or INCY JSON, or its routing link) into the private policy overlay: DirectSites and DirectIp become the broad direct lists, ProxySites and ProxyIp always go through the VPN, private destinations stay local, everything else keeps going through the VPN. Blocking, DNS and fake-DNS settings of the profile are not applied. Custom rules stay as they are.')]),
   E('p',{},[_('The router downloads the profile and the geosite and geoip files it names: through the VPN while the VPN runs, otherwise through the ISP. Preview shows the result without changing anything; Import replaces the current routing policy and keeps the previous one as the backup.')]),
   E('div',{class:'flr-actions'},presetButtons),
   flr.field(_('Profile URL (HTTPS)'),roscomURL),
   flr.field(_('Or a profile file (it takes precedence over the URL)'),roscomFile),
   E('div',{class:'flr-actions'},[flr.button(_('Preview'),function(){return roscomRun(true);},null,true),flr.button(_('Import RoscomVPN profile'),function(){return roscomRun(false);},null,true)]),
   roscomState,roscomReport]);
  return E('div',{class:'flr-page'},head.concat([
   E('section',{class:'flr-card'},[E('h3',{},_('Export')),
    E('p',{},_('Downloads the effective routing configuration as one JSON file: the policy in use (private overlay or image default), all its rulesets and the custom rules. The file contains your private routing lists; keep it private.')),
    exportButton,exportProgress]),
   E('section',{class:'flr-card'},[E('h3',{},_('Import')),
    E('p',{},_('Accepts a file from this export or a custom rules file. A policy in the file replaces the private overlay and custom rules in it replace the stored ones; parts the file does not contain stay as they are. The router checks the whole file before changing anything, keeps the current overlay as the backup and applies the result to new connections without restarting the VPN.')),
    flr.field(_('Routing configuration file (.json)'),file),importButton,importProgress]),
   roscomSection,
   E('section',{class:'flr-card'},[E('h3',{},_('Apply the installed policy')),
    E('p',{},_('Reloads the installed policy and the custom rules and applies them to new connections, for example after installing an overlay by hand. Existing connections keep their route.')),
    flr.action(_('Reload and apply'),{operation:'routing-apply'},after)]),
   E('section',{class:'flr-card'},[E('h3',{},_('Image default and backup')),
    E('p',{},_('"Reset to image default" moves the private overlay to the backup: everything except local destinations then goes through the VPN; custom rules stay. "Restore backup" brings the saved overlay back and keeps the current one as the backup.')),
    backupState,
    E('div',{class:'flr-actions'},[
     flr.action(_('Reset to image default'),function(){if(!window.confirm(_('Remove the private overlay? It is kept as the backup.')))throw new Error(_('Reset cancelled.'));return {operation:'routing-reset',routing:{accepted:true}};},after),
     flr.action(_('Restore backup'),function(){if(!window.confirm(_('Restore the saved overlay? The current one becomes the backup.')))throw new Error(_('Restore cancelled.'));return {operation:'routing-restore-backup',routing:{accepted:true}};},after)])])]));
 },handleSave:null,handleSaveApply:null,handleReset:null
});
