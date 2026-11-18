'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'status'});},
 render:function(data) {
  var box=E('div',{class:'flr-page'});
  var update=function(d) {
   var s=d.status || {}, proxy=s.direct_proxy || {}, active=s.active_connection,requested=s.requested || {mode:'auto'},intent=s.proxy || {};
   var choice=requested.mode==='connection'?'Конкретное подключение':requested.mode==='transport'?'Только протокол '+flr.familyLabel(requested.family):'Авто';
   var children=[flr.style(),E('h2',{},'FLR — состояние'),
    E('p',{},['Контроллер: '+(d.runtime?'работает':'остановлен')+' · VPN: '+(d.vpn_enabled?'включён':'выключен')]),
    E('p',{},['Транспорт: '+((s.selection || {}).general || 'down')+' · игры: '+((s.selection || {}).games || 'down')]),
    E('p',{},['Маршрут новых соединений: '+(active?active.name+' · '+flr.familyLabel(active.family)+' · '+(active.group || '')+' · '+active.endpoint:'нет рабочего подключения')+' · выбор: '+choice+(intent.pending?' · ожидает применения':'')]),
    E('p',{},['Постоянный SOCKS5: '+(proxy.running?'работает':'не работает')+' · '+((proxy.config || {}).bind || 'адрес LAN не определён')+':'+((proxy.config || {}).port || 1080)])];
   if(intent.reserve_connection){var reserve=intent.reserve_connection;children.push(E('p',{},['Сохранённый резерв: '+reserve.name+' · '+flr.familyLabel(reserve.family)+' · подробности и история в «Прокси».']));}
   if(proxy.lan_error)children.push(E('p',{class:'alert-message warning'},['Адрес LAN роутера не определён, использован запасной: '+proxy.lan_error]));
   if(proxy.error)children.push(E('p',{class:'alert-message error'},[proxy.error]));
   if(s.last_error)children.push(E('p',{class:'alert-message error'},[s.last_error]));
   if(d.deactivation_pending)children.push(E('div',{class:'alert-message warning'},[
    E('p',{},'VPN выключен в настройках, но восстановление сети не завершено. Повторите отключение.'),
    flr.action('Повторить отключение',{operation:'settings',settings:{enabled:false}},refresh)]));
   if(d.rollback_pending) {
    var accepted=E('input',{type:'checkbox',disabled:L.hasViewPermission()?null:true});
    children.push(E('div',{class:'alert-message warning'},[
     E('p',{},'Откат вооружён. Подтвердите только после проверки доступа к LuCI/LAN, WAN, маршрутизации VPN и direct.'),
     E('label',{},[accepted,' Я проверил LAN, WAN, VPN и direct']),
     flr.action('Принять подключение и снять откат',function(){if(!accepted.checked)throw new Error('Сначала выполните и подтвердите проверки подключения.');return {operation:'rollback-confirm',accepted:true};},refresh)
    ]));
   }
   var awg=(s.channels || {}).awg;
   if(awg) {
    var reasons={healthy:'здоров',interface_absent:'интерфейс отсутствует',consecutive_failures:'три полных сбоя подряд',sustained_failures:'устойчивые ошибки у обоих провайдеров',sustained_latency:'устойчивое замедление у обоих провайдеров'};
    var w=awg.window || {},baselines=awg.baselines || [],targets=(awg.probe || {}).targets || [];
    children.push(E('h3',{},'Здоровье AWG'),E('p',{},['Состояние: '+(reasons[awg.reason] || 'ожидание измерений')+' · выбран как здоровый: '+(awg.healthy?'да':'нет')]),
     E('p',{},['Окно: '+(w.samples || 0)+' раундов · база: '+(awg.baseline_samples || 0)+' чистых раундов · восстановление: '+(awg.recovery_clean_samples || 0)+' чистых раундов'+(awg.recovery_since && !awg.recovery_since.startsWith('0001-')?' с '+awg.recovery_since:'')]),
     E('p',{},'Измеряется время успешных HTTPS/DNS-запросов в мс; ошибки не считаются временем. Эти наблюдения не доказывают намеренное ограничение.'));
    ['Cloudflare','Google'].forEach(function(name,i){var b=baselines[i] || {},t=targets[i] || {};children.push(E('p',{},[name+': ошибки '+((w.failed || [])[i] || 0)+' · медленные TCP/UDP '+((w.tcp_slow || [])[i] || 0)+'/'+((w.udp_slow || [])[i] || 0)+' · последний TCP/UDP '+(t.tcp?t.tcp_duration_ms:'сбой / нет данных')+'/'+(t.udp?t.udp_duration_ms:'сбой / нет данных')+' мс · база TCP/UDP '+(b.tcp_ms || 'ещё нет')+'/'+(b.udp_ms || 'ещё нет')+' мс']));});
   }
   children.push(E('details',{class:'flr-details'},[E('summary',{},'Подробные проверки каналов'),E('pre',{},[JSON.stringify(s.channels || {},null,2)])]),flr.action('Повторить проверки',{operation:'refresh'},refresh));
   box.replaceChildren.apply(box,children);
  };
  var refresh=function(){return flr.read({operation:'status'}).then(update).catch(flr.error);};
  update(data);poll.add(refresh,5);return box;
 },handleSave:null,handleSaveApply:null,handleReset:null
});
