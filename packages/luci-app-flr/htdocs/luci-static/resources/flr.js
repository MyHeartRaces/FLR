'use strict';
'require baseclass';
'require rpc';
'require ui';

var readRPC = rpc.declare({object:'luci.flr', method:'read', params:['request'], reject:true, nobatch:true});
var writeRPC = rpc.declare({object:'luci.flr', method:'write', params:['request'], reject:true, nobatch:true});
function httpRequestBytes(request, sessionID, method) {
 // LuCI serializes this exact envelope. Reserve the largest safe numeric ID
 // so the check remains valid as the page makes more requests.
 var envelope={jsonrpc:'2.0',id:Number.MAX_SAFE_INTEGER,method:'call',params:[sessionID,'luci.flr',method,{request:JSON.stringify(request)}]};
 return new TextEncoder().encode(JSON.stringify(envelope)).length;
}
function bounded(request, method) {
 var text = JSON.stringify(request);
 if (httpRequestBytes(request,rpc.getSessionID(),method)>65536)
  throw new Error('Запрос превышает лимит веб-интерфейса 64 КиБ. Для большой подписки используйте HTTPS URL.');
 return text;
}
function reply(value) {
 if (!value || typeof value !== 'object' || typeof value.ok !== 'boolean' || !Object.prototype.hasOwnProperty.call(value,'data'))
  throw new Error('FLR не вернул корректный ответ. Проверьте службу и повторите запрос.');
 if (!value.ok) throw new Error(typeof value.error === 'string' && value.error ? value.error : 'Операция FLR не выполнена.');
 return value.data;
}
var families=['awg','hy2','reality','vless','ss2022','wgws'];
var fieldSequence=0;
return baseclass.extend({
 families:families,
 familyLabel:function(family){return {awg:'AWG',hy2:'HY2',reality:'VLESS / REALITY',vless:'VLESS / TLS',ss2022:'SS2022 / ShadowTLS',wgws:'WG / WebSocket'}[family] || family;},
 proxySelection:function(mode,family,id) {
  if(mode==='auto')return {mode:'auto'};
  if(mode==='transport' && families.includes(family))return {mode:'transport',family:family};
  if(mode==='connection' && /^[a-z0-9_-]{1,80}$/.test(id || ''))return {mode:'connection',id:id};
  throw new Error('Выберите режим и доступное значение протокола или подключения.');
 },
 proxyOrder:function(order,connections) {
  if(!Array.isArray(order) || order.length!==families.length || families.some(function(f){return order.filter(function(x){return x===f;}).length!==1;}))throw new Error('Порядок должен содержать каждый протокол один раз.');
  var copy={families:order.slice(),connections:{}},seen={};
  families.forEach(function(f){if(!Array.isArray(connections[f]))throw new Error('Некорректный порядок подключений.');copy.connections[f]=connections[f].map(function(id){if(!/^[a-z0-9_-]{1,80}$/.test(id) || seen[id])throw new Error('Подключение повторяется в порядке.');seen[id]=true;return id;});});
  return copy;
 },
 style:function(){return E('link',{rel:'stylesheet',href:L.resource('flr.css')});},
 httpRequestBytes:httpRequestBytes,
 boundedJSON:function(request,method) {return bounded(request,method || 'write');},
 group:function(value) {
  if(new TextEncoder().encode(value).length>80 || /[\r\n\x00]/.test(value) || value.includes('://'))
   throw new Error('Группа: не более 80 байт UTF-8, без переводов строк, NUL и URL.');
  return value;
 },
 read:async function(request) {return reply(await readRPC(bounded(request,'read')));},
 collectDiagnostics:async function(fetchPage) {
  var output=null,cursor=0,upper=0,bytes=0;
  for(var pages=0;pages<1000;pages++) {
   var page=await fetchPage(output?cursor+':'+upper:'0');
   if(!page || !Array.isArray(page.rounds) || !Array.isArray(page.decisions) || !Number.isSafeInteger(page.next) || !Number.isSafeInteger(page.last_sequence) || page.next<cursor || page.next>page.last_sequence)throw new Error('Некорректная страница диагностики.');
   if(!output){upper=page.last_sequence;output={boot:page.boot,source:page.source,version:page.version,last_sequence:upper,dropped_rounds:page.dropped_rounds,dropped_decisions:page.dropped_decisions,dropped_round_sequence:page.dropped_round_sequence,dropped_decision_sequence:page.dropped_decision_sequence,rounds:[],decisions:[]};}
   else if(page.boot!==output.boot || page.source!==output.source || page.version!==output.version || page.last_sequence!==upper)throw new Error('История изменилась во время выгрузки; повторите экспорт.');
   ['round','decision'].forEach(function(kind){
    var key='dropped_'+kind+'_sequence',value=page[key],base=output[key];
    if(!Number.isSafeInteger(value) || value<0 || !Number.isSafeInteger(base) || base<0)throw new Error('Некорректная граница истории диагностики.');
    if(value>Math.max(base,cursor))throw new Error('История потеряла ещё не выгруженные записи; повторите экспорт.');
   });
   page.rounds.concat(page.decisions).forEach(function(record){if(!Number.isSafeInteger(record.sequence) || record.sequence<=cursor || record.sequence>page.next)throw new Error('Некорректный курсор диагностики.');});
   bytes+=new TextEncoder().encode(JSON.stringify([page.rounds,page.decisions])).length;
   if(bytes>4*1024*1024)throw new Error('История диагностики превышает лимит 4 МиБ.');
   output.rounds=output.rounds.concat(page.rounds);output.decisions=output.decisions.concat(page.decisions);
   if(!page.more)return output;
   if(page.next===cursor)throw new Error('Выгрузка диагностики остановилась; повторите экспорт.');
   cursor=page.next;
  }
  throw new Error('Слишком много страниц диагностики.');
 },
 write:async function(request) {return reply(await writeRPC(bounded(request,'write')));},
 error:function(error) {ui.addNotification(null,E('p',{},[String(error.message || error)]),'error');},
 notify:function(text) {ui.addNotification(null,E('p',{},[text]),'info');},
 action:function(label,request,after,failed,aria) {
  return E('button',{class:'cbi-button cbi-button-action','aria-label':aria || null,disabled:L.hasViewPermission()?null:true,click:async function(ev) {
   var button=ev.currentTarget;button.disabled=true;
   try {var value=typeof request==='function'?await request():request;var data=await this.write(value);if(after) await after(data);ui.addNotification(null,E('p',{},[data && data.activation_state==='pending'?'Активация ожидает запуска VPN. Проверьте состояние и LAN/WAN перед подтверждением отката.':data && data.pending?'Проверка запущена. Дождитесь результата и восстановления подключения.':'Изменения приняты.']),'info');}
   catch(e){if(failed)try{await failed(e);}catch(refreshError){this.error(refreshError);}this.error(e);}finally{button.disabled=!L.hasViewPermission();}
  }.bind(this)},label);
 },
 // A button that changes nothing on its own (export, copy, download). Writes
 // that return secrets still need the write ACL: pass write=true.
 button:function(label,click,aria,write) {
  var canUse=!write || L.hasViewPermission();
  return E('button',{class:'cbi-button','aria-label':aria || null,disabled:canUse?null:true,click:async function(ev) {
   var button=ev.currentTarget;button.disabled=true;
   try{await click(ev);}catch(e){this.error(e);}finally{button.disabled=!canUse;}
  }.bind(this)},label);
 },
 download:function(name,text,type) {
  var blob=new Blob([text],{type:type || 'text/plain'}),url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=/^[A-Za-z0-9_.-]{1,100}$/.test(name || '')?name:'flr-download.txt';link.click();URL.revokeObjectURL(url);
 },
 selectionText:function(selection,connections) {
  selection=selection || {mode:'auto'};
  if(selection.mode==='transport')return 'Только протокол · '+this.familyLabel(selection.family);
  if(selection.mode==='connection'){var item=(connections || []).find(function(c){return c.id===selection.id;});return 'Конкретное подключение · '+(item?item.name:'подключение отсутствует');}
  return 'Авто · заданный порядок fallback';
 },
 // Shared frame of the Proxy tabs: one connection-list snapshot, writes carry
 // its generation, a conflict reloads it, and polling never overwrites forms.
 // build(state,page) returns the tab body; it may set page.status(d) to update
 // live parts from every poll without redrawing the forms.
 connectionPage:function(initial,poll,build) {
  var self=this,body=E('div'),stale=E('div'),signature='',page={state:initial,canWrite:L.hasViewPermission(),status:null};
  function fingerprint(d){return JSON.stringify([d.connections,d.selection,d.order,d.vpn_enabled]);}
  function draw(){signature=fingerprint(page.state);page.status=null;body.replaceChildren.apply(body,build(page.state,page));if(page.status)page.status(page.state);}
  page.field=function(tag,attrs,children){attrs=attrs || {};attrs.disabled=page.canWrite?null:true;return E(tag,attrs,children);};
  page.refresh=async function(){page.state=await self.read({operation:'connection-list'});draw();stale.replaceChildren();};
  page.failed=async function(error){if(/state changed/i.test(error.message || ''))await page.refresh();};
  page.action=function(name,make,after,aria){return self.action(name,async function(){var request=await make();request.expected_generation=page.state.generation;return request;},async function(d){if(after)await after(d);await page.refresh();},page.failed,aria);};
  draw();
  poll.add(async function(){try{var d=await self.read({operation:'connection-list'});if(page.status)page.status(d);if(fingerprint(d)===signature){page.state.generation=d.generation;}else{stale.replaceChildren(E('span',{class:'flr-notice'},'Настройки изменились. Обновите их перед сохранением.'));}}catch(e){self.error(e);}},5);
  return E('div',{class:'flr-page'},[self.style(),E('div',{class:'flr-toolbar'},[E('button',{class:'cbi-button',click:async function(){try{await page.refresh();}catch(e){self.error(e);}}},'Обновить настройки'),stale]),body]);
 },
 field:function(label,input) {var id=null;if(input && ['INPUT','SELECT','TEXTAREA'].includes(input.tagName)){id='flr-field-'+(++fieldSequence);input.id=id;}return E('div',{class:'cbi-value'},[E('label',{class:'cbi-value-title',for:id},label),E('div',{class:'cbi-value-field'},input)]);},
 fileText:async function(input,max) {
  var file=input.files && input.files[0];if(!file)throw new Error('Выберите файл.');
  if(file.size>max)throw new Error('Файл превышает допустимый размер.');
  return await file.text();
 },
 handleSave:null,handleSaveApply:null,handleReset:null
});
