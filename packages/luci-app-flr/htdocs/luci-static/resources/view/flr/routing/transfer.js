'use strict';
'require view';
'require flr';

// Routing · import & export: the whole effective routing configuration as one
// JSON file, moved in chunks below the LuCI request limit and checked whole
// on both sides; plus apply, reset to the image default and backup restore.
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
  return E('div',{class:'flr-page'},head.concat([
   E('section',{class:'flr-card'},[E('h3',{},_('Export')),
    E('p',{},_('Downloads the effective routing configuration as one JSON file: the policy in use (private overlay or image default), all its rulesets and the custom rules. The file contains your private routing lists; keep it private.')),
    exportButton,exportProgress]),
   E('section',{class:'flr-card'},[E('h3',{},_('Import')),
    E('p',{},_('Accepts a file from this export or a custom rules file. A policy in the file replaces the private overlay and custom rules in it replace the stored ones; parts the file does not contain stay as they are. The router checks the whole file before changing anything, keeps the current overlay as the backup and applies the result to new connections without restarting the VPN.')),
    flr.field(_('Routing configuration file (.json)'),file),importButton,importProgress]),
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
