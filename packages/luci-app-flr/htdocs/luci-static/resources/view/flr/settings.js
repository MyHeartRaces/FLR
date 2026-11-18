'use strict';
'require view';
'require flr';

return view.extend({
 load:function(){return Promise.all([flr.read({operation:'settings'})]);},
 render:function(data) {
  var s=data[0],d=s.direct_proxy || {enabled:true,bind:'',port:1080};
  function controlE(tag,attrs,children){attrs=attrs || {};attrs.disabled=L.hasViewPermission()?null:true;return E(tag,attrs,children);}
  var health=s.health_policy || {enabled:true,window_seconds:60,min_samples:8,failure_percent:25,slow_percent:75,tcp_floor_ms:1500,udp_floor_ms:400,tcp_recovery_ms:750,udp_recovery_ms:200,latency_multiplier:4,recovery_multiplier:2,baseline_samples:12,recovery_seconds:60,max_gap_seconds:30};
  var healthEnabled=controlE('input',{type:'checkbox',checked:health.enabled?true:null});
  var healthFields=[
   ['window_seconds','Окно наблюдения, с',30,300],['min_samples','Минимум раундов в окне',6,60],
   ['failure_percent','Ошибки каждого провайдера, %',25,100],['slow_percent','Медленные запросы каждого провайдера, %',50,100],
   ['tcp_floor_ms','TCP: порог замедления, мс',500,3500],['udp_floor_ms','UDP: порог замедления, мс',100,2000],
   ['tcp_recovery_ms','TCP: порог восстановления / обучения, мс',100,3499],['udp_recovery_ms','UDP: порог восстановления / обучения, мс',25,1999],
   ['latency_multiplier','Множитель базового времени: замедление',2,10],['recovery_multiplier','Множитель базового времени: восстановление',1,9],
   ['baseline_samples','Чистые раунды для базового времени',6,60],['recovery_seconds','Непрерывное восстановление, с',60,600],['max_gap_seconds','Максимальная пауза между проверками, с',10,60]
  ];
  var healthInputs={};var healthRows=healthFields.map(function(f){var input=controlE('input',{type:'number',min:f[2],max:f[3],step:1,value:health[f[0]]});healthInputs[f[0]]=input;return flr.field(f[1],input);});
  var bypass=s.direct_bypass || {enabled:false,tcp:'off',quic:'off'};
  var bypassEnabled=controlE('input',{type:'checkbox',checked:bypass.enabled?true:null});
  function preset(value){return controlE('select',{},[E('option',{value:'off',selected:!value || value==='off'?true:null},'Выключен'),E('option',{value:'fake',selected:value==='fake'?true:null},'Эксперимент: fake ×2')]);}
  var bypassTCP=preset(bypass.tcp),bypassQUIC=preset(bypass.quic);
  var enabled=controlE('input',{type:'checkbox',checked:d.enabled?true:null}),bind=controlE('input',{value:d.bind,readonly:true}),port=controlE('input',{type:'number',min:1024,max:65535,value:d.port});
  var ip=controlE('input',{placeholder:/^\d+\.\d+\.\d+\.\d+$/.test(d.bind || '')?d.bind.replace(/\.\d+$/,'.2'):'IPv4 устройства из LAN',value:''}),mode=controlE('select',{},[
   E('option',{value:'auto'},'Авто (политика доменов)'),E('option',{value:'general'},'VPN — общий'),E('option',{value:'games'},'VPN — игры'),E('option',{value:'direct'},'Direct — всё устройство через WAN')]);
  // Older controllers do not report routing_mode; the control stays hidden.
  var routingModes=[['split','Раздельный: списки из частной политики'],['full_domestic','Всё через VPN, кроме обязательных direct-сервисов'],['full','Всё через VPN']],routing=[];
  if(typeof s.routing_mode==='string') {
   var known=routingModes.some(function(m){return m[0]===s.routing_mode;});
   var routingMode=controlE('select',{'data-field':'routing_mode'},(known?[]:[E('option',{value:s.routing_mode,selected:true},['Текущий: '+s.routing_mode])]).concat(routingModes.map(function(m){return E('option',{value:m[0],selected:s.routing_mode===m[0]?true:null},[m[1]]);})));
   routing=[E('h3',{},'Режим маршрутизации'),
    E('p',{},'«Раздельный» отправляет напрямую назначения из частной политики (без неё — только локальные). «Всё через VPN, кроме обязательных direct-сервисов» оставляет напрямую короткий список сервисов, которые не работают с зарубежного адреса. «Всё через VPN» оставляет напрямую только LAN, сам роутер и явный direct (SOCKS, маршрут устройства «Direct»).'),
    E('p',{class:'flr-muted'},'Полные режимы увеличивают объём трафика к серверу, добавляют задержку для внутренних сайтов и показывают им адрес сервера.'),
    flr.field('Режим',routingMode),
    flr.action('Сохранить режим маршрутизации',function(){if(!routingModes.some(function(m){return m[0]===routingMode.value;}))throw new Error('Выберите режим маршрутизации.');return {operation:'settings',settings:{routing_mode:routingMode.value}};})];
  }
  // Tunnel CAKE shaping; hidden on controllers that do not report it.
  var qos=[];
  if(s.tunnel_qos && typeof s.tunnel_qos==='object') {
   var q=s.tunnel_qos;
   var qosEnabled=controlE('input',{type:'checkbox',checked:q.enabled===true?true:null});
   function rate(value,field){return controlE('input',{type:'number',min:0,max:10000000,step:1,'data-field':field,value:Number.isSafeInteger(value)?value:0});}
   var qosUp=rate(q.upload_kbit,'upload_kbit'),qosDown=rate(q.download_kbit,'download_kbit');
   qos=[E('h3',{},'Очередь в туннеле (CAKE)'),
    E('p',{},'CAKE держит очередь внутри VPN-туннеля на роутере, чтобы игры и звонки не ждали за большими загрузками. Укажите скорость немного ниже реальной скорости линии (примерно на 5–10 %): если задать выше, очередь снова соберётся у провайдера. 0 — направление без ограничения.'),
    E('p',{class:'flr-muted'},'Допустимо 0 или от 1000 до 10 000 000 кбит/с; для включения нужна хотя бы одна ненулевая скорость.'),
    flr.field('Включить CAKE в туннеле',qosEnabled),flr.field('Отдача (upload), кбит/с',qosUp),flr.field('Загрузка (download), кбит/с',qosDown),
    flr.action('Сохранить очередь в туннеле',function(){
     var up=Number(qosUp.value),down=Number(qosDown.value);
     [up,down].forEach(function(v){if(!Number.isInteger(v) || (v!==0 && (v<1000 || v>10000000)))throw new Error('Скорость: 0 или целое число от 1000 до 10 000 000 кбит/с.');});
     if(qosEnabled.checked && up===0 && down===0)throw new Error('Для включения CAKE укажите хотя бы одну скорость.');
     return {operation:'settings',settings:{tunnel_qos:{enabled:qosEnabled.checked,upload_kbit:up,download_kbit:down}}};})];
  }
  var devices=E('div');
  function updateDevices(map){devices.replaceChildren(E('pre',{},[JSON.stringify(map || {},null,2)]));}
  updateDevices(s.options.profiles);
  return E('div',{class:'flr-page'},[flr.style(),E('h2',{},'Настройки FLR'),
   E('p',{},'Выбор протокола, подключения VPS, приоритет fallback и конфигурации доступны на странице «Прокси».'),
  ].concat(routing,qos,[
   E('h3',{},'Устойчивость AWG'),
   E('p',{},'Два независимых провайдера: Cloudflare и Google. Время HTTPS/DNS-запросов включает весь запрос; это не ICMP и не доказательство намеренного ограничения. Порог действует для каждого провайдера. Разовая ошибка или отказ одного провайдера не переключает AWG.'),
   E('p',{},'Минимум раундов не больше окно/5 + 1. Пороги восстановления и их множитель должны быть ниже порогов замедления. Фактический порог — максимум указанного времени и базового времени × множитель; пока базы нет, используется указанное время. Обучение только ниже порогов восстановления. Для возврата нужны оба провайдера и оба протокола без паузы больше заданного предела (по умолчанию 30 с). Отключение детектора сохраняет три полных сбоя, отсутствие интерфейса и квалификацию возврата.'),
   E('p',{},'Значения предварительные: настройка под установленный роутер и провайдера ещё не проверена. Сохранение изменённых порогов сбрасывает накопленные измерения и отсчёт восстановления.'),
   flr.field('Распознавать устойчивые нарушения',healthEnabled),E('div',{},healthRows),
   flr.action('Сохранить проверки AWG',function(){var policy={enabled:healthEnabled.checked};healthFields.forEach(function(f){var value=Number(healthInputs[f[0]].value);if(!Number.isInteger(value))throw new Error('Пороги должны быть целыми числами.');policy[f[0]]=value;});return {operation:'settings',settings:{health_policy:policy}};}),
   E('h3',{},'Постоянный direct SOCKS5'),E('p',{},['Работает независимо от VPN и без срока действия. Адрес — собственный адрес роутера в LAN, он определяется автоматически (сейчас: '+(d.bind || 'не определён')+'); порт 1024–65535, кроме временного 1088 и портов DNS. IPv6-назначения не поддерживаются. Один UDP ASSOCIATE на IP устройства; до 32 назначений и 64 TCP-соединений.']),
   flr.field('Включён',enabled),flr.field('Адрес роутера в LAN (определяется автоматически)',bind),flr.field('Порт TCP/UDP',port),
   flr.action('Сохранить direct',function(){return {operation:'settings',settings:{direct_proxy:{enabled:enabled.checked,bind:bind.value,port:Number(port.value)}}};}),
   E('h3',{},'Экспериментальный direct bypass (IPv4)'),
   E('p',{},'По умолчанию выключен. Только первые 6 исходящих пакетов direct: TCP 443 и QUIC UDP 443. VPN, его внешние соединения, проверки и временный SOCKS 1088 исключены. Нужно уже включённое conntrack accounting; контроллер не меняет sysctl. Пресеты не гарантируют доступ у вашего провайдера. Discord voice и Telegram требуют отдельной проверки; произвольные UDP-порты не обрабатываются.'),
   flr.field('Явно включить эксперимент',bypassEnabled),flr.field('TCP',bypassTCP),flr.field('QUIC',bypassQUIC),
   flr.action('Сохранить direct bypass',function(){return {operation:'settings',settings:{direct_bypass:{enabled:bypassEnabled.checked,tcp:bypassTCP.value,quic:bypassQUIC.value}}};}),
   E('h3',{},'Маршрут устройства'),E('p',{},'Direct направляет весь маршрутизируемый IPv4-трафик устройства через WAN, в том числе непроксируемые входящие/исходящие пути. IPv6 не получает такой гарантии; отключите его на устройстве для режима только IPv4.'),devices,
   flr.field('IPv4 устройства',ip),flr.field('Режим',mode),
   flr.action('Применить режим устройства',function(){return {operation:'device',client:ip.value,value:mode.value};},function(result){updateDevices(result.devices);}),
   E('h3',{},'Отключение VPN'),E('p',{},'Восстанавливает сохранённую сеть/фаервол/DNS. Если восстановление не завершится, «Обзор» покажет кнопку повтора. Direct SOCKS5 остаётся независимым.'),
   flr.action('Отключить VPN / повторить восстановление',{operation:'settings',settings:{enabled:false}})
  ]));
 },handleSave:null,handleSaveApply:null,handleReset:null
});
