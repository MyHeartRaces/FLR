'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  function label(f){return flr.familyLabel(f);}
  return flr.connectionPage(initial,poll,function(state,page) {
   var status=E('section',{class:'flr-card flr-status'});
   page.status=function(d) {
    var s=d.status || {},p=s.proxy || {},active=s.active_connection,test=s.connection_test;
    var children=[E('h2',{},'Прокси · состояние'),E('div',{class:'flr-status-grid'},[
     E('div',{},[E('span',{class:'flr-muted'},'Запрошен режим'),E('strong',{},[flr.selectionText(d.selection,d.connections)])]),
     E('div',{},[E('span',{class:'flr-muted'},'Новые соединения · фактический маршрут'),E('strong',{},[active?label(active.family)+' · '+(active.group || active.name):'Нет рабочего подключения'])]),
     E('div',{},[E('span',{class:'flr-muted'},'VPN'),E('strong',{class:'flr-badge'},[d.vpn_enabled?'Включён':'Выключен'])])])];
    if(active)children.push(E('p',{},[active.name+' · '+active.endpoint+' · '+(((s.selection || {}).general || 'down')==='down'?'трафик VPN заблокирован':((s.selection || {}).games || 'down')==='down'?'TCP · игры/UDP заблокированы':'TCP / UDP')]));
    if(p.reserve_connection){var reserve=p.reserve_connection,unchecked=p.pending || !(s.channels || {}).gecko || !s.channels.gecko.healthy;children.push(E('p',{},[E('strong',{},[p.reserve_warm?'Тёплый резерв: ':'Сохранённый резерв: ']),label(reserve.family)+' · '+reserve.name+(p.reserve_warm?(unchecked?' · запущен заранее, состояние требует проверки.':' · запущен заранее и проверяется; сессий на нём нет, при отказе AWG новые соединения перейдут без холодного старта.'):(unchecked?' · канал сохранён, состояние требует проверки.':' · старые сессии продолжают использовать этот канал.'))]));}
    Object.keys(s.channels || {}).forEach(function(channel){var h=s.channels[channel],probe=h.probe || {},checked=Date.parse(h.last_check),age=isFinite(checked)&&checked>0?Math.max(0,Math.floor((Date.now()-checked)/1000))+' с назад':'ещё не получено',family=channel==='gecko'?((p.reserve_connection || (active && active.family!=='awg'?active:null) || {}).family):channel;children.push(E('p',{class:'flr-muted'},[(family?label(family):'Прокси')+' · Последнее измерение: '+age+(probe.not_measured?' · Измерение пропущено: '+({cancelled:'отмена',budget_exhausted:'нет бюджета'}[probe.not_measured] || 'нет результата'):'')+(h.degraded?' · качество ухудшилось':'')]));});
    if(s.diagnostics){var diag=s.diagnostics,last=diag.last_decision;children.push(E('p',{class:'flr-muted'},['История в RAM: '+diag.rounds+' раундов · '+diag.decisions+' решений'+(last?' · Последний переход: '+({failback:'возврат на AWG',fallback:'переход на резерв',selection:'выбор подключения',native_replacement:'замена AWG',connection_unavailable:'подключение недоступно',channel_failed:'отказ канала',cleanup_retry:'повтор очистки',slot_replacement:'замена прокси',admission_failed:'подключение не прошло проверку',manual_test:'ручная проверка',shutdown:'остановка службы',warm_reserve:'тёплый резерв'}[last.reason] || 'применение маршрута')+' / '+({applied:'применено',failed:'ошибка',pending:'ожидает',prepared:'подготовлено',superseded:'отменено новым выбором'}[last.outcome] || 'исход неизвестен'):'')]));if(diag.snapshot_pending)children.push(E('p',{class:'flr-notice'},'Сохранение снимка истории требует повтора; текущие записи доступны для скачивания.'));if(diag.wan){var wan=diag.wan.probe || {};children.push(E('p',{class:'flr-muted'},['Диагностика WAN: '+(wan.not_measured || !wan.measured?'результат неизвестен':wan.tcp&&wan.udp?'TCP / UDP доступны':'проверка TCP/UDP не прошла')+' · не влияет на выбор VPN.']));}}
    if(p.pending)children.push(E('p',{class:'flr-notice'},[s.last_error?'Применение приостановлено. Фактический маршрут показан выше.':'Выбор сохранён и ожидает применения. Рабочее соединение подтвердят проверки TCP/UDP.']));
    if(p.pending && p.desired_connection && (!active || active.id!==p.desired_connection.id))children.push(E('p',{class:'flr-muted'},['Ожидает применения: '+label(p.desired_connection.family)+' · '+p.desired_connection.name]));
    if(s.last_error)children.push(E('p',{class:'flr-notice'},[s.last_error]));
    else if(!active && d.vpn_enabled)children.push(E('p',{class:'flr-notice'},'Нет рабочего подключения. Ручной выбор сохраняется при отказе; трафик VPN блокируется до восстановления.'));
    if(p.reason)children.push(E('p',{class:'flr-muted'},[p.reason]));
    if(test){var phase={queued:'в очереди',probing:'проверяется',restoring:'восстанавливается',finished:'завершена',cancelled:'отменена новым выбором',failed:'не запущена','recovery-pending':'восстановление требует перезапуска службы'}[test.phase] || test.phase;children.push(E('div',{class:'flr-notice'},[E('strong',{},['Проверка подключения: '+phase]),E('p',{},[(test.measured?'TCP: '+(test.tcp?'доступен':'сбой')+' · UDP: '+(test.udp?'доступен':'сбой'):'Нет подтверждённого измерения')+' · '+(test.restored?'исходный режим восстановлен':'восстановление не подтверждено')])]));}
    if(d.rollback_pending)children.push(E('p',{class:'flr-notice'},'Вооружён откат на 180 секунд. После проверки LAN, WAN, VPN и direct подтвердите подключение в «Обзоре».'));
    if(d.migration_notice)children.push(E('p',{class:'flr-notice'},[d.migration_notice]));
    status.replaceChildren.apply(status,children);
   };
   var diagnostics=flr.button('Скачать диагностику',async function(){var data=await flr.collectDiagnostics(function(value){return flr.write({operation:'diagnostics-export',value:value});});flr.download('flr-diagnostics.json',JSON.stringify(data,null,2),'application/json');},null,true);
   var tools=E('section',{class:'flr-card'},[E('h3',{},'Диагностика'),E('p',{class:'flr-muted'},'История хранит до 720 раундов и 256 событий в RAM. Скачивание требует права записи и выдаёт ограниченные страницы; ключи и конфиги не включаются.'),diagnostics]);
   var activation=E('section',{class:'flr-card'},[E('h3',{},'Активация VPN'),E('p',{class:'flr-muted'},'Первая активация меняет сеть с защитой отката на 180 секунд. После запуска проверьте LAN/LuCI, WAN, выбранное VPN-подключение и direct; затем подтвердите в «Обзоре».'),page.action('Активировать VPN',function(){if(!window.confirm('Активировать VPN с защитой отката и проверить LAN/WAN после запуска?'))throw new Error('Активация отменена.');return {operation:'vpn-activate',accepted:true};})]);
   return [status,tools,activation];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
