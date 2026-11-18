'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  function label(f){return flr.familyLabel(f);}
  var formats={url:'ссылка (URL)',json:'JSON (sing-box / Xray)','awg-conf':'файл AWG (.conf)'};
  var formatNotes={url:'Ссылку принимают импорт FLR и совместимые клиенты.',json:'Ссылка не передаёт все параметры этого подключения, поэтому выдан JSON, который принимает импорт FLR.','awg-conf':'У AWG нет формата ссылки: это полный файл .conf, который принимает импорт FLR.'};
  var phases={queued:'в очереди',probing:'проверяется',restoring:'восстанавливается',finished:'завершена',cancelled:'отменена новым выбором',failed:'не запущена','recovery-pending':'восстановление требует перезапуска службы'};
  // Live role of one connection in the current status; text only, never HTML.
  function role(c,d) {
   var s=d.status || {},p=s.proxy || {},active=s.active_connection,channels=s.channels || {},test=s.connection_test,parts=[],channel=c.family==='awg'?channels.awg:channels.gecko,isActive=!!(active && active.id===c.id);
   if(isActive)parts.push('Активно: новые соединения идут здесь',channel?(channel.healthy?'проверки в норме':'проверки не проходят')+(channel.degraded?', качество ухудшилось':''):'проверок ещё нет');
   else if(p.reserve_connection && p.reserve_connection.id===c.id)parts.push(p.reserve_warm?'Тёплый резерв':'Сохранённый резерв: старые сессии продолжают идти через него',channels.gecko && channels.gecko.healthy?'проверки в норме':'состояние требует проверки');
   else if(p.pending && p.desired_connection && p.desired_connection.id===c.id)parts.push('Ожидает применения');
   else parts.push(c.enabled?'Сейчас не используется':'Выключено в выборе');
   if(test && test.id===c.id)parts.push('Проверка: '+(phases[test.phase] || test.phase)+(test.measured?' · TCP '+(test.tcp?'доступен':'сбой')+' · UDP '+(test.udp?'доступен':'сбой'):''));
   return {active:isActive,text:parts.join(' · ')};
  }
  return flr.connectionPage(initial,poll,function(state,page) {
   var field=page.field,items=state.connections || [],selection=state.selection || {mode:'auto'},updates=[];
   function exportButton(c,box) {
    return flr.button('Экспорт',async function() {
     var data;
     try{data=await flr.write({operation:'connection-export',id:c.id,expected_generation:page.state.generation});}catch(e){await page.failed(e);throw e;}
     if(!data || data.id!==c.id || typeof data.config!=='string' || !formats[data.format])throw new Error('FLR вернул некорректный экспорт.');
     var text=E('textarea',{rows:data.format==='url'?3:14,readonly:true,spellcheck:'false','aria-label':'Конфигурация '+c.name,'data-export':c.id});
     text.value=data.config;
     box.replaceChildren(E('h4',{},['Экспорт: '+formats[data.format]]),E('p',{class:'flr-notice'},'Содержит ключи и пароли подключения. Не публикуйте и не пересылайте по открытым каналам; после копирования нажмите «Скрыть».'),E('p',{class:'flr-muted'},[formatNotes[data.format]]),text,E('div',{class:'flr-actions'},[
      flr.button('Копировать',async function(){var nav=window.navigator;if(nav && nav.clipboard && window.isSecureContext)await nav.clipboard.writeText(text.value);else{text.select();if(!document.execCommand('copy'))throw new Error('Браузер не разрешил копирование. Выделите текст и скопируйте вручную.');}flr.notify('Конфигурация скопирована.');},'Копировать конфигурацию '+c.name),
      flr.button('Скачать',async function(){flr.download(data.filename,data.config,data.format==='json'?'application/json':'text/plain');},'Скачать конфигурацию '+c.name),
      flr.button('Скрыть',async function(){text.value='';box.replaceChildren();},'Скрыть конфигурацию '+c.name)]));
    },'Экспорт '+c.name,true);
   }
   var cards=items.map(function(c) {
    var pinned=selection.mode==='connection' && selection.id===c.id,unavailable=(state.availability || {})[c.id];
    var name=field('input',{type:'text',maxlength:80,value:c.name}),group=field('input',{type:'text',maxlength:80,value:c.group}),enabled=field('input',{type:'checkbox',checked:c.enabled?true:null}),replacement=field('textarea',{rows:4,'data-replace':c.id,placeholder:'Новая полная конфигурация: AWG, JSON, URI или base64'}),file=field('input',{type:'file',accept:'.json,.txt,.conf'});
    var activeBadge=E('span',{class:'flr-badge flr-badge-active'}),live=E('p',{class:'flr-live'}),exportBox=E('div',{class:'flr-export'});
    function replace(data){return {operation:'connection-replace',id:c.id,data:data};}
    var actions=[];
    if(!pinned)actions.push(page.action('Сделать активным',function(){if((!c.enabled || unavailable) && !window.confirm('«'+c.name+'» '+(unavailable?'недоступно: отсутствует компонент':'выключено в выборе')+'. Ручной выбор сохранится, но трафик VPN будет заблокирован, пока подключение не заработает. Продолжить?'))throw new Error('Выбор отменён.');return {operation:'selection',selection:flr.proxySelection('connection','',c.id)};},null,'Сделать активным '+c.name));
    actions.push(
     page.action('Проверить',function(){if(!window.confirm('Проверка кратковременно меняет VPN-путь, включая проверку выключенного подключения. Текущие TCP/UDP-сессии могут прерваться. Затем восстанавливаются исходный выбор и допустимый резерв; уже прерванные сессии не возвращаются. Продолжить?'))throw new Error('Проверка отменена.');return {operation:'connection-test',id:c.id};},null,'Проверить '+c.name),
     exportButton(c,exportBox),
     page.action('Удалить',function(){if(!window.confirm('Удалить «'+c.name+'»?'+(pinned?' Ручной выбор будет явно переведён в «Авто».':'')))throw new Error('Удаление отменено.');var request={operation:'connection-delete',id:c.id};if(pinned)request.selection={mode:'auto'};return request;},null,'Удалить '+c.name));
    var card=E('article',{class:'flr-card flr-connection'},[
     E('div',{class:'flr-connection-head'},[E('h4',{},[c.name]),E('span',{class:'flr-badge'},[label(c.family)]),E('span',{class:'flr-muted'},[c.group || 'Группа не задана']),pinned?E('span',{class:'flr-badge'},'Выбрано вручную'):'',activeBadge]),
     E('p',{class:'flr-muted'},[c.endpoint+' · '+(c.capabilities.udp?'TCP / UDP':'Только TCP')+(!c.enabled?' · выключено':'')+(unavailable?' · отсутствует '+unavailable.replace('missing-component:',''):'')]),
     live,E('div',{class:'flr-actions'},actions),exportBox,
     E('details',{class:'flr-details'},[E('summary',{},'Название, группа, включение'),flr.field('Название',name),flr.field('Группа VPS',group),flr.field('Включено в выбор',enabled),page.action('Сохранить',function(){return {operation:'connection-update',id:c.id,metadata:{name:name.value,group:flr.group(group.value),enabled:enabled.checked}};},null,'Сохранить '+c.name)]),
     E('details',{class:'flr-details'},[E('summary',{},'Заменить конфигурацию'),E('p',{class:'flr-muted'},'Замена сохраняет ID, имя, группу и включение. Вставьте полный новый конфиг; текущий можно получить кнопкой «Экспорт».'),flr.field('Новый конфиг',replacement),page.action('Заменить конфигурацию',function(){return replace(replacement.value);},function(){replacement.value='';},'Заменить конфигурацию '+c.name),flr.field('Файл для замены',file),page.action('Заменить из файла',async function(){return replace(await flr.fileText(file,65536));},function(){file.value='';},'Заменить из файла '+c.name)])]);
    updates.push(function(d){var r=role(c,d);live.replaceChildren(r.text);activeBadge.replaceChildren(r.active?'Активно':'');activeBadge.hidden=!r.active;if(card.classList)card.classList.toggle('flr-connection-active',r.active);});
    return card;
   });
   page.status=function(d){updates.forEach(function(update){update(d);});};
   var mode=E('section',{class:'flr-card'},[E('h2',{},'Прокси · подключения'),E('p',{},['Режим: ',E('strong',{},[flr.selectionText(selection,items)])]),
    E('p',{class:'flr-muted'},'«Сделать активным» закрепляет подключение вручную: при его отказе FLR не переключается сам, трафик VPN блокируется до восстановления. «Авто» возвращает fallback по вкладке «Порядок». Проверка кратковременно меняет VPN-путь и может прервать сессии.'),
    selection.mode!=='auto'?page.action('Вернуться к «Авто»',function(){return {operation:'selection',selection:{mode:'auto'}};}):''].filter(Boolean));
   return [mode,E('div',{class:'flr-connections'},cards.length?cards:[E('p',{class:'flr-notice'},'Подключений нет. Добавьте конфигурацию во вкладке «Импорт».')])];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
