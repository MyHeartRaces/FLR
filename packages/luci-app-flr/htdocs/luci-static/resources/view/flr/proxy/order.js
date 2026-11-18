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
   var mode=field('select',{'data-field':'mode'},[['auto','Авто'],['transport','Только протокол'],['connection','Конкретное подключение']].map(function(v){return E('option',{value:v[0],selected:selected.mode===v[0]?true:null},[v[1]]);}));
   var family=field('select',{'data-field':'family'},flr.families.map(function(f){return E('option',{value:f,selected:(selected.family || (selectedItem || {}).family || 'awg')===f?true:null},[label(f)]);}));
   var endpoint=field('select',{'data-field':'connection'},[E('option',{value:''},'Выберите подключение')].concat(items.map(function(c){return E('option',{value:c.id,selected:selected.id===c.id?true:null},[label(c.family)+' · '+c.name+(c.group?' · '+c.group:'')+(!c.enabled?' · выключено':'')+((state.availability || {})[c.id]?' · компонент отсутствует':'')]);})));
   var familyRow=flr.field('Протокол',family),connectionRow=flr.field('Подключение / VPS',endpoint);
   function showMode(){familyRow.hidden=mode.value!=='transport';connectionRow.hidden=mode.value!=='connection';}
   mode.addEventListener && mode.addEventListener('change',showMode);showMode();
   var selectionCard=E('section',{class:'flr-card'},[E('h3',{},'Режим выбора'),E('p',{class:'flr-muted'},['Сейчас: '+flr.selectionText(selected,items)+'. Авто перебирает протоколы и подключения по вашему порядку. «Только протокол» допускает fallback внутри него. Конкретное подключение сохраняет ручной выбор при отказе.']),flr.field('Режим',mode),familyRow,connectionRow,page.action('Применить выбор',function(){return {operation:'selection',selection:flr.proxySelection(mode.value,family.value,endpoint.value)};})]);
   var priorities=E('div',{class:'flr-order'}),reselect=field('input',{type:'checkbox'});
   function arrow(text,disabled,click){return E('button',{class:'cbi-button flr-arrow','aria-label':text,disabled:!canWrite || disabled?true:null,click:click},[text.indexOf('Поднять')===0?'↑':'↓']);}
   function move(list,index,delta){var value=list[index];list.splice(index,1);list.splice(index+delta,0,value);updateOrder();}
   function updateOrder(){priorities.replaceChildren.apply(priorities,order.families.map(function(f,i){return E('div',{class:'flr-order-family'},[
    E('div',{class:'flr-order-title'},[E('strong',{},[(i+1)+'. '+label(f)]),E('div',{class:'flr-actions'},[arrow('Поднять протокол '+label(f),i===0,function(){move(order.families,i,-1);}),arrow('Опустить протокол '+label(f),i===order.families.length-1,function(){move(order.families,i,1);})])]),
    E('div',{},order.connections[f].length?order.connections[f].map(function(id,n){var c=byID[id];return E('div',{class:'flr-order-item'},[E('span',{},[(n+1)+'. '+c.name+(c.group?' · '+c.group:'')+(!c.enabled?' · выключено':'')]),E('div',{class:'flr-actions'},[arrow('Поднять подключение '+c.name,n===0,function(){move(order.connections[f],n,-1);}),arrow('Опустить подключение '+c.name,n===order.connections[f].length-1,function(){move(order.connections[f],n,1);})])]);}):E('p',{class:'flr-muted'},'Подключений пока нет'))]);}));}
   updateOrder();
   var orderCard=E('section',{class:'flr-card'},[E('h3',{},'Приоритет fallback'),E('p',{class:'flr-muted'},'Выше — раньше при следующем выборе. Здоровое соединение сохраняется после изменения порядка; для немедленного пересмотра отметьте флажок.'),priorities,E('label',{class:'flr-inline'},[reselect,' Пересмотреть активное подключение сейчас']),page.action('Сохранить порядок',function(){return {operation:'connection-order',order:flr.proxyOrder(order.families,order.connections),reselect:reselect.checked};})]);
   return [E('h2',{},'Прокси · порядок'),selectionCard,orderCard];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
