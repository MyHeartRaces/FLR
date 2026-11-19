'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  return flr.connectionPage(initial,poll,function(state,page) {
   var field=page.field,count=(state.connections || []).length;
   var content=field('textarea',{rows:6,placeholder:_('AWG [Interface]/[Peer], JSON, URI or a base64 subscription')}),file=field('input',{type:'file',accept:'.json,.txt,.conf'}),url=field('input',{type:'url',placeholder:'https://…'});
   var importCard=E('section',{class:'flr-card'},[E('h3',{},_('Add connections')),
    E('p',{class:'flr-muted'},_('Import stores configs privately and does not turn the VPN on. The whole web request is limited to 64 KiB including UTF-8 and escaping. Subscriptions up to 1 MiB can be loaded through an HTTPS URL on the router. An export from the "Connections" tab (link, JSON or AWG file) is accepted here as is; a connection that is already stored is not added again.')),
    flr.field(_('Configuration / subscription'),content),page.action(_('Import text'),function(){return {operation:'connection-import',data:content.value};},function(){content.value='';}),
    flr.field(_('AWG / JSON / URI file'),file),page.action(_('Import file'),async function(){return {operation:'connection-import',data:await flr.fileText(file,65536)};},function(){file.value='';}),
    flr.field(_('Subscription HTTPS URL'),url),page.action(_('Load subscription'),function(){return {operation:'connection-import',url:url.value};},function(){url.value='';})]);
   return [E('h2',{},_('Proxy · import')),importCard,E('p',{class:'flr-muted'},[_('Stored connections: %s. New connections appear on the "Connections" tab and at the end of their protocol on the "Order" tab.').format(count)])];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
