'use strict';
'require view';
'require poll';
'require flr';

return view.extend({
 load:function(){return flr.read({operation:'connection-list'});},
 render:function(initial) {
  return flr.connectionPage(initial,poll,function(state,page) {
   var field=page.field,count=(state.connections || []).length;
   var content=field('textarea',{rows:6,placeholder:'AWG [Interface]/[Peer], JSON, URI или подписка base64'}),file=field('input',{type:'file',accept:'.json,.txt,.conf'}),url=field('input',{type:'url',placeholder:'https://…'});
   var importCard=E('section',{class:'flr-card'},[E('h3',{},'Добавить подключения'),
    E('p',{class:'flr-muted'},'Импорт сохраняет конфиги приватно и не включает VPN. Полный веб-запрос ограничен 64 КиБ с учётом UTF-8 и экранирования. Подписки до 1 МиБ можно загрузить через HTTPS URL на роутере. Экспорт из вкладки «Подключения» (ссылка, JSON или файл AWG) принимается здесь как есть; уже сохранённое подключение повторно не добавляется.'),
    flr.field('Конфигурация / подписка',content),page.action('Импортировать текст',function(){return {operation:'connection-import',data:content.value};},function(){content.value='';}),
    flr.field('Файл AWG / JSON / URI',file),page.action('Импортировать файл',async function(){return {operation:'connection-import',data:await flr.fileText(file,65536)};},function(){file.value='';}),
    flr.field('HTTPS URL подписки',url),page.action('Загрузить подписку',function(){return {operation:'connection-import',url:url.value};},function(){url.value='';})]);
   return [E('h2',{},'Прокси · импорт'),importCard,E('p',{class:'flr-muted'},['Сохранено подключений: '+count+'. Новые подключения появляются во вкладке «Подключения» и в конце своего протокола во вкладке «Порядок».'])];
  });
 },handleSave:null,handleSaveApply:null,handleReset:null
});
