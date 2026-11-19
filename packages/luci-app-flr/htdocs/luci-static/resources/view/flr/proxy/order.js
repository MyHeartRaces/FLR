'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  function label(f){return flr.familyLabel(f);}
  return flr.connectionPage(initial,poll,function(state,page) {
   var field=page.field,canWrite=page.canWrite;
   var items=state.connections || [],byID={};items.forEach(function(c){byID[c.id]=c;});
   var order=flr.proxyOrder(state.order.families,state.order.connections);
   var selected=state.selection || {mode:'auto'},selectedItem=byID[selected.id];
   var mode=field('select',{'data-field':'mode'},[['auto',_('Auto')],['transport',_('Protocol only')],['connection',_('Specific connection')]].map(function(v){return E('option',{value:v[0],selected:selected.mode===v[0]?true:null},[v[1]]);}));
   var family=field('select',{'data-field':'family'},flr.families.map(function(f){return E('option',{value:f,selected:(selected.family || (selectedItem || {}).family || 'awg')===f?true:null},[label(f)]);}));
   function connectionLabel(c,parts){if(c.group)parts.push(c.group);if(!c.enabled)parts.push(_('turned off'));return parts;}
   var endpoint=field('select',{'data-field':'connection'},[E('option',{value:''},_('Choose a connection'))].concat(items.map(function(c){var parts=connectionLabel(c,[label(c.family),c.name]);if((state.availability || {})[c.id])parts.push(_('component missing'));return E('option',{value:c.id,selected:selected.id===c.id?true:null},[parts.join(' · ')]);})));
   var familyRow=flr.field(_('Protocol'),family),connectionRow=flr.field(_('Connection / VPS'),endpoint);
   function showMode(){familyRow.hidden=mode.value!=='transport';connectionRow.hidden=mode.value!=='connection';}
   mode.addEventListener && mode.addEventListener('change',showMode);showMode();
   var selectionCard=E('section',{class:'flr-card'},[E('h3',{},_('Selection mode')),E('p',{class:'flr-muted'},[_('Now: %s. Auto tries protocols and connections in your order. "Protocol only" allows fallback within it. A specific connection keeps the manual choice when it fails.').format(flr.selectionText(selected,items))]),flr.field(_('Mode'),mode),familyRow,connectionRow,page.action(_('Apply selection'),function(){return {operation:'selection',selection:flr.proxySelection(mode.value,family.value,endpoint.value)};})]);
   var priorities=E('div',{class:'flr-order'}),reselect=field('input',{type:'checkbox'});
   function arrow(text,up,disabled,click){return E('button',{class:'cbi-button flr-arrow','aria-label':text,disabled:!canWrite || disabled?true:null,click:click},[up?'↑':'↓']);}
   function move(list,index,delta){var value=list[index];list.splice(index,1);list.splice(index+delta,0,value);updateOrder();}
   function updateOrder(){priorities.replaceChildren.apply(priorities,order.families.map(function(f,i){return E('div',{class:'flr-order-family'},[
    E('div',{class:'flr-order-title'},[E('strong',{},[(i+1)+'. '+label(f)]),E('div',{class:'flr-actions'},[arrow(_('Move protocol up %s').format(label(f)),true,i===0,function(){move(order.families,i,-1);}),arrow(_('Move protocol down %s').format(label(f)),false,i===order.families.length-1,function(){move(order.families,i,1);})])]),
    E('div',{},order.connections[f].length?order.connections[f].map(function(id,n){var c=byID[id];return E('div',{class:'flr-order-item'},[E('span',{},[(n+1)+'. '+connectionLabel(c,[c.name]).join(' · ')]),E('div',{class:'flr-actions'},[arrow(_('Move connection up %s').format(c.name),true,n===0,function(){move(order.connections[f],n,-1);}),arrow(_('Move connection down %s').format(c.name),false,n===order.connections[f].length-1,function(){move(order.connections[f],n,1);})])]);}):E('p',{class:'flr-muted'},_('No connections yet')))]);}));}
   updateOrder();
   var orderCard=E('section',{class:'flr-card'},[E('h3',{},_('Fallback priority')),E('p',{class:'flr-muted'},_('Higher means earlier at the next choice. A healthy connection is kept after the order changes; tick the box for an immediate re-evaluation.')),priorities,E('label',{class:'flr-inline'},[reselect,' ',_('Re-evaluate the active connection now')]),page.action(_('Save order'),function(){return {operation:'connection-order',order:flr.proxyOrder(order.families,order.connections),reselect:reselect.checked};})]);
   return [E('h2',{},_('Proxy · order')),selectionCard,orderCard];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
