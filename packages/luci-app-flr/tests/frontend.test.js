'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const root = path.join(__dirname, '..');
// LuCI128a7812f4be233c5dd7f7466f534fd888785caf: luci.js DOM.create
// calls DOM.attr (line1595), which skips only null/undefined (1490–1517).
// False is still a present HTML
// Boolean attribute. This adapter deliberately preserves those browser semantics.
// LuCI dom.append also assigns a lone string child to innerHTML (arrays and
// replaceChildren() make text nodes). Model that: markup in a lone string
// becomes element nodes, so tests can see untrusted text parsed as HTML.
function luciElement(tag,attrs,children) {
 attrs=attrs||{};
 if(typeof children==='string' && /<[a-z]/i.test(children))children=[...children.matchAll(/<([a-z][a-z0-9]*)/gi)].map(m=>({tag:m[1].toLowerCase(),attrs:{},children:[],parsedFrom:children}));
 return {tag,attrs,children:children||[],value:tag==='select'?(children.find(n=>n.attrs.selected!=null)||children[0]).attrs.value:attrs.value,checked:attrs.checked!=null,disabled:attrs.disabled!=null,replaceChildren(...c){this.children=c;}};
}
function api(reply,canWrite=true,transport={calls:[],declarations:[]},browser={}) {
 const source = fs.readFileSync(path.join(root,'htdocs/luci-static/resources/flr.js'),'utf8');
 const scope = { baseclass:{extend:x=>x},rpc:{getSessionID:()=> 'a'.repeat(32),declare:options=>{transport.declarations.push(options);return async request=>{transport.calls.push({method:options.method,request});return reply;};}}, TextEncoder, E:luciElement,L:{hasViewPermission:()=>canWrite,resource:p=>'/luci-static/resources/'+p},ui:{addNotification:()=>{}}, console, ...browser };
 return vm.runInNewContext('(function(){'+source+'})()',scope);
}
test('rejects absent, malformed, numeric and CLI failure replies',async()=> {
 for (const reply of [undefined,null,7,'garbage',{}, {ok:false,error:'failed'},{ok:true}]) {
  await assert.rejects(api(reply).read({operation:'status'}));
 }
 assert.deepEqual(await api({ok:true,data:{runtime:true},error:''}).read({operation:'status'}),{runtime:true});
});
test('bounds encoded JSON including rpc wrapper before network use',async()=>{
 const a=api({ok:true,data:{},error:''});
 await assert.rejects(a.write({operation:'import',content:'x'.repeat(1048576)}));
 await assert.rejects(a.write({operation:'import',content:'"'.repeat(400000)}));
});
test('HTTP envelope boundary rejects before transport including UTF8 and escapes',async()=>{
 const transport={calls:[],declarations:[]},a=api({ok:true,data:{}},true,transport);
 // Independent fixture of the documented LuCI JSON-RPC call, including a
 // conservative numeric request ID. Counting only the inner CLI wrapper fails.
 const request={operation:'import',content:'Ж"\\\n'};
 const envelope=content=>JSON.stringify({jsonrpc:'2.0',id:9007199254740991,method:'call',params:['a'.repeat(32),'luci.flr','write',{request:JSON.stringify({...request,content})}]});
 const prefix=request.content;
 const padding=65536-Buffer.byteLength(envelope(prefix),'utf8');
 const accepted={...request,content:prefix+'x'.repeat(padding)};
 assert.equal(Buffer.byteLength(envelope(accepted.content),'utf8'),65536);
 await a.write(accepted);
 assert.equal(transport.calls.length,1);
 await assert.rejects(a.write({...accepted,content:accepted.content+'x'}),/64 КиБ/);
 assert.equal(transport.calls.length,1,'oversized body reached RPC transport');
 await assert.rejects(a.write({...request,content:'Ж'.repeat(40000)}),/64 КиБ/);
 assert.equal(transport.calls.length,1);
});
test('FLR calls use nonbatch transport for read and write',async()=>{
 const transport={calls:[],declarations:[]},a=api({ok:true,data:{}},true,transport);
 await Promise.all([a.read({operation:'status'}),a.write({operation:'refresh'})]);
 assert.deepEqual(transport.declarations.map(d=>[d.method,d.nobatch]),[['read',true],['write',true]]);
 assert.deepEqual(transport.calls.map(c=>c.method),['read','write']);
});
test('menu and ACL grant only fixed FLR read/write methods',()=>{
 const acl=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/rpcd/acl.d/luci-app-flr.json')));
 assert.deepEqual(acl['luci-app-flr'].read.ubus,{'luci.flr':['read']});
 assert.deepEqual(acl['luci-app-flr'].write.ubus,{'luci.flr':['write']});
 assert.equal(acl['luci-app-flr'].read.file,undefined);
 const menu=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/luci/menu.d/luci-app-flr.json')));
 for (const page of ['overview','settings','help']) assert.equal(menu['admin/flr/'+page].action.path,'flr/'+page);
});
const cp = require('node:child_process');
const os = require('node:os');
test('rpc plugin allowlists methods and forwards literal stdin to fixed CLI',()=>{
 const original=fs.readFileSync(path.join(root,'root/usr/libexec/rpcd/luci.flr'),'utf8');
 const file=path.join(root,'root/usr/libexec/rpcd/luci.flr');
 const listed=cp.spawnSync('/bin/sh',[file,'list'],{encoding:'utf8'});
 assert.equal(listed.status,0);assert.deepEqual(JSON.parse(listed.stdout),{read:{request:''},write:{request:''}});
 assert.equal(cp.spawnSync('/bin/sh',[file,'call','evil'],{encoding:'utf8'}).status,1);
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'flr-rpc-'));
 try {
  const spy=path.join(dir,'controller');fs.writeFileSync(spy,'#!/bin/sh\nprintf "%s\\n" "$*"\ncat\n',{mode:0o700});
  const plugin=path.join(dir,'plugin');fs.writeFileSync(plugin,original.replaceAll('/usr/sbin/flr-controller',spy));
  const input='{"request":"$(touch should-not-exist); `echo nope`"}';
  for(const method of ['read','write']){
   const result=cp.spawnSync('/bin/sh',[plugin,'call',method],{input,encoding:'utf8',cwd:dir});
   assert.equal(result.status,0);assert.equal(result.stdout,(method==='read'?'api --rpc --read-only':'api --rpc')+'\n'+input);
   assert.equal(fs.existsSync(path.join(dir,'should-not-exist')),false);
  }
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('all LuCI modules parse using native LuCI function wrapper',()=>{
 for(const f of ['flr.js',...['overview','profiles','proxy','settings','help','proxy/status','proxy/connections','proxy/order','proxy/import'].map(p=>'view/flr/'+p+'.js')]) {
  new vm.Script('(function(){'+fs.readFileSync(path.join(root,'htdocs/luci-static/resources',f),'utf8')+'})()',{filename:f});
 }
});

function viewModule(page,canWrite=true) {
 const source=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr',page+'.js'),'utf8');
 const E=luciElement;
 const flr={style:()=>E('link',{rel:'stylesheet',href:'/flr.css'}),group:api({ok:true,data:{}}).group,field:(name,input)=>E('label',{},[name,input]),action:(name,request)=>({tag:'action',name,request}),familyLabel:f=>f,read:async()=>({}),error:()=>{}};
 return vm.runInNewContext('(function(){'+source+'})()',{view:{extend:x=>x},E,flr,poll:{add:()=>{}},L:{hasViewPermission:()=>canWrite},window:{}});
}
function allNodes(node) {if(!node||typeof node!=='object')return [];return [node,...(Array.isArray(node.children)?node.children:[node.children]).flatMap(allNodes)];}
test('health settings sends complete numeric policy and preserves direct form',()=>{
 const policy={enabled:true,window_seconds:60,min_samples:8,failure_percent:25,slow_percent:75,tcp_floor_ms:1500,udp_floor_ms:400,tcp_recovery_ms:750,udp_recovery_ms:200,latency_multiplier:4,recovery_multiplier:2,baseline_samples:12,recovery_seconds:60,max_gap_seconds:30};
 const tree=viewModule('settings').render([{health_policy:policy,options:{},direct_proxy:{enabled:true,bind:'192.168.1.1',port:1080}},{}]);
 const nodes=allNodes(tree),action=nodes.find(n=>n.name==='Сохранить проверки AWG');assert.ok(action);
 assert.deepEqual(JSON.parse(JSON.stringify(action.request())),{operation:'settings',settings:{health_policy:policy}});
 const direct=nodes.find(n=>n.name==='Сохранить direct');assert.equal(direct.request().settings.direct_proxy.port,1080);
});
test('overview explains measured AWG degradation without ping or intentional restriction claim',()=>{
 const tree=viewModule('overview').render({status:{channels:{awg:{healthy:false,reason:'sustained_latency',degraded:true,window:{samples:12,failed:[0,0],tcp_slow:[10,10],udp_slow:[0,0]},baselines:[{tcp_ms:100,udp_ms:50},{tcp_ms:120,udp_ms:55}],probe:{targets:[]},recovery_clean_samples:3}}}});
 const text=JSON.stringify(tree);assert.ok(text.includes('устойчивое замедление'));assert.ok(text.includes('мс'));assert.ok(text.includes('3'));assert.ok(!text.includes('ping'));
});

test('LuCI Boolean attributes preserve writable buttons and unchecked saved settings',async()=>{
 for(const canWrite of [true,false]) {
  const a=api({ok:true,data:{}},canWrite),button=a.action('save',{operation:'settings'});
  assert.equal(button.disabled,!canWrite);
  await button.attrs.click({currentTarget:button});assert.equal(button.disabled,!canWrite);
  const settings=viewModule('settings',canWrite).render([{options:{},direct_proxy:{enabled:false,bind:'192.168.1.1',port:1080},health_policy:{enabled:false}},{}]);
  const checks=allNodes(settings).filter(n=>n.tag==='input'&&n.attrs.type==='checkbox');
  assert.equal(checks.length,3);for(const checkbox of checks)assert.equal(checkbox.checked,false);
  assert.equal(allNodes(settings).some(n=>n.attrs&&n.attrs.type==='file'),false);
 }
});


test('direct bypass defaults disabled and sends only bounded profile settings',()=>{
 const tree=viewModule('settings').render([{options:{}},{}]);
 const action=allNodes(tree).find(n=>n.name==='Сохранить direct bypass');
 assert.deepEqual(JSON.parse(JSON.stringify(action.request())),{operation:'settings',settings:{direct_bypass:{enabled:false,tcp:'off',quic:'off'}}});
});

test('fixed LAN bind stays readonly and routing policy moves to Proxy',()=>{
 const tree=viewModule('settings').render([{options:{},direct_proxy:{enabled:true,bind:'192.168.1.1',port:1080}},{}]);
 const nodes=allNodes(tree),bind=nodes.find(n=>n.tag==='input'&&n.value==='192.168.1.1');
 assert.ok(bind.attrs.readonly!=null);
 assert.equal(nodes.some(n=>n.name==='Сохранить порядок'),false);
 assert.equal(nodes.some(n=>n.attrs&&n.attrs.type==='file'),false);
});
test('direct proxy UI takes the LAN from API data and does not state a fixed one',()=>{
 for(const lanAddr of ['192.168.1.1','10.10.0.1']) {
  const tree=viewModule('settings').render([{options:{},direct_proxy:{enabled:true,bind:lanAddr,port:1080}},{}]);
  const nodes=allNodes(tree),text=JSON.stringify(tree);
  assert.ok(!text.includes('192.168.8.'));
  assert.ok(nodes.find(n=>n.tag==='input'&&n.value===lanAddr));
  assert.ok(nodes.find(n=>n.tag==='input'&&n.attrs&&n.attrs.placeholder===lanAddr.replace(/\.\d+$/,'.2')));
  assert.ok(nodes.find(n=>n.name==='Сохранить direct').request().settings.direct_proxy.bind===lanAddr);
 }
 const empty=viewModule('settings').render([{options:{}},{}]);assert.ok(!JSON.stringify(empty).includes('192.168.8.'));
 const over=viewModule('overview').render({status:{direct_proxy:{running:false,config:{bind:'192.168.1.1',port:1080},lan_error:'no such network interface'}}});
 const overText=JSON.stringify(over);assert.ok(overText.includes('192.168.1.1:1080'));assert.ok(overText.includes('no such network interface'));assert.ok(!overText.includes('192.168.8.'));
 const help=JSON.stringify(viewModule('help').render({direct_proxy:{bind:'192.168.1.1',port:1080}}));
 assert.ok(help.includes('Host: 192.168.1.1;'));assert.ok(!help.includes('192.168.8.'));
});
test('actionable import errors remain distinct and activation pending is visible',async()=>{
 for(const [code,message] of [['duplicate_profile','Profile already exists; delete it before importing again.'],['unsupported_field','Use Sec-WebSocket-Protocol for Xray WS early data.'],['registry_capacity','Delete profiles or split the batch.']]) {
  await assert.rejects(api({ok:false,data:null,error:message,error_detail:{code,field:'content',item:2}}).write({operation:'import',content:'test'}),new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 }
 const source=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/flr.js'),'utf8');
 assert.ok(source.includes('activation_state'));assert.ok(source.includes('pending'));
});

test('group byte bounds match imported Unicode and primary metadata',()=>{
 const a=api({ok:true,data:{}});
 assert.equal(a.group('Ж'.repeat(40)),'Ж'.repeat(40));
 assert.equal(a.group('Сервер / A'),'Сервер / A');
 for(const group of ['Ж'.repeat(41),'a'.repeat(81),'a\nb','https://token'])assert.throws(()=>a.group(group));
});

const proxyFamilies=['awg','hy2','reality','vless','ss2022','wgws'];
const proxyTabs=['status','connections','order','import'];
function proxyFixture(){return {generation:7,selection:{mode:'connection',id:'b'},order:{families:[...proxyFamilies],connections:{awg:['w'],hy2:['a','b'],reality:[],vless:[],ss2022:[],wgws:[]}},vpn_enabled:true,availability:{w:'missing-component:awg'},connections:[{id:'a',name:'Backup <img src=x>',family:'hy2',group:'Backup',enabled:true,endpoint:'192.0.2.1:443',capabilities:{tcp:true,udp:true}},{id:'b',name:'Main',family:'hy2',group:'Main',enabled:false,endpoint:'192.0.2.2:443',capabilities:{tcp:true,udp:true}},{id:'w',name:'AWG Main',family:'awg',group:'Main',enabled:true,endpoint:'192.0.2.3:51820',capabilities:{tcp:true,udp:true}}],status:{requested:{mode:'connection',id:'b'},proxy:{pending:false,requested:{mode:'connection',id:'b'},reason:'no enabled connection ready'},selection:{general:'down',games:'down'}}};}
// Browser stand-ins for clipboard and file download; they record what the page hands over.
function browser(){
 const record={copied:[],downloads:[],confirms:[]};
 const window={confirm:text=>{record.confirms.push(text);return record.confirmReply!==false;},location:{href:''},isSecureContext:true,navigator:{clipboard:{writeText:async text=>{record.copied.push(text);}}}};
 const document={createElement:()=>({click(){record.downloads.push({name:this.download,href:this.href});}}),execCommand:()=>false};
 class Blob{constructor(parts,options){record.blob={text:parts.join(''),type:options.type};}}
 const URL={createObjectURL:()=>'blob:flr',revokeObjectURL:()=>{}};
 return {record,window,document,Blob,URL};
}
function proxyHarness(canWrite=true,page='order'){
 const response={ok:true,data:proxyFixture()},transport={calls:[],declarations:[]},b=browser(),flr=api(response,canWrite,transport,{document:b.document,Blob:b.Blob,URL:b.URL}),pollers=[];
 const scope={view:{extend:x=>x},E:luciElement,flr,poll:{add:f=>pollers.push(f)},L:{hasViewPermission:()=>canWrite,resource:p=>'/luci-static/resources/'+p,url:(...p)=>'/cgi-bin/luci/'+p.join('/')},window:b.window,document:b.document};
 const source=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/proxy',page+'.js'),'utf8');
 const mod=vm.runInNewContext('(function(){'+source+'})()',scope),tree=mod.render(response.data);
 return {tree,response,transport,pollers,flr,browser:b.record,nodes:()=>allNodes(tree),text:()=>JSON.stringify(tree),find(label){return allNodes(tree).find(n=>n.tag==='button'&&(n.children===label || n.attrs['aria-label']===label));},async click(label){const button=this.find(label);assert.ok(button,'missing action '+label);await button.attrs.click({currentTarget:button});},writes(){return transport.calls.filter(c=>c.method==='write').map(c=>JSON.parse(c.request));}};
}
test('unified selection and order helpers emit strict cloned policy',()=>{
 const a=api({ok:true,data:{}});
 for(const [mode,family,id,want] of [['auto','hy2','b',{mode:'auto'}],['transport','hy2','b',{mode:'transport',family:'hy2'}],['connection','hy2','b',{mode:'connection',id:'b'}]])assert.deepEqual(JSON.parse(JSON.stringify(a.proxySelection(mode,family,id))),want);
 assert.throws(()=>a.proxySelection('transport','naive','b'));
 assert.throws(()=>a.proxySelection('connection','hy2',''));
 const order=proxyFixture().order,copy=a.proxyOrder(order.families,order.connections);copy.connections.hy2.reverse();assert.deepEqual(order.connections.hy2,['a','b']);
 assert.throws(()=>a.proxyOrder(['hy2','hy2'],order.connections));
});
test('Proxy is split into LuCI tabs and keeps the other pages',()=>{
 const menu=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/luci/menu.d/luci-app-flr.json')));
 assert.deepEqual(menu['admin/flr/proxy'],{title:'Прокси',order:20,action:{type:'firstchild'}});
 const tabs=Object.keys(menu).filter(k=>k.startsWith('admin/flr/proxy/')).sort((a,b)=>menu[a].order-menu[b].order);
 assert.deepEqual(tabs.map(k=>[k,menu[k].title,menu[k].action.type,menu[k].action.path]),[
  ['admin/flr/proxy/status','Состояние','view','flr/proxy/status'],['admin/flr/proxy/connections','Подключения','view','flr/proxy/connections'],
  ['admin/flr/proxy/order','Порядок','view','flr/proxy/order'],['admin/flr/proxy/import','Импорт','view','flr/proxy/import']]);
 for(const k of tabs)assert.ok(fs.existsSync(path.join(root,'htdocs/luci-static/resources/view',menu[k].action.path+'.js')),k);
 assert.deepEqual(['overview','settings','help'].map(p=>menu['admin/flr/'+p].title),['Обзор','Настройки','qBittorrent и помощь']);
 assert.equal(menu['admin/flr/profiles'].title,undefined);
 const legacy=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/profiles.js'),'utf8');assert.match(legacy,/L\.url\('admin',\s*'flr',\s*'proxy',\s*'connections'\)/);
 const old=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/proxy.js'),'utf8');assert.match(old,/L\.url\('admin',\s*'flr',\s*'proxy',\s*'status'\)/);
 assert.ok(fs.readFileSync(path.join(root,'htdocs/luci-static/resources/flr.css'),'utf8').includes('@media'));
 // Every capability of the former single page is still reachable from one tab.
 const labels=Object.fromEntries(proxyTabs.map(p=>[p,proxyHarness(true,p).nodes().filter(n=>n.tag==='button').map(n=>n.attrs['aria-label']||n.children)]));
 for(const [tab,label] of [['status','Скачать диагностику'],['status','Активировать VPN'],['order','Применить выбор'],['order','Сохранить порядок'],['import','Импортировать текст'],['import','Импортировать файл'],['import','Загрузить подписку'],['connections','Сохранить Main'],['connections','Проверить Main'],['connections','Экспорт Main'],['connections','Удалить Main'],['connections','Заменить конфигурацию Main'],['connections','Заменить из файла Main'],['connections','Сделать активным Backup <img src=x>']])assert.ok(labels[tab].includes(label),tab+': '+label);
});
test('order tab preserves disabled pinned choice and sends fresh generation',async()=>{
 const h=proxyHarness();let mode=h.nodes().find(n=>n.attrs['data-field']==='mode'),family=h.nodes().find(n=>n.attrs['data-field']==='family'),connection=h.nodes().find(n=>n.attrs['data-field']==='connection');
 assert.equal(mode.value,'connection');assert.equal(connection.value,'b');
 for(const [selected,want] of [['auto',{mode:'auto'}],['transport',{mode:'transport',family:'hy2'}],['connection',{mode:'connection',id:'b'}]]){mode.value=selected;family.value='hy2';connection.value='b';await h.click('Применить выбор');assert.deepEqual(h.writes().at(-1),{operation:'selection',expected_generation:7,selection:want});mode=h.nodes().find(n=>n.attrs['data-field']==='mode');family=h.nodes().find(n=>n.attrs['data-field']==='family');connection=h.nodes().find(n=>n.attrs['data-field']==='connection');}
 assert.match(h.text(),/Main/);assert.match(h.text(),/Backup/);
 for(const page of proxyTabs)assert.equal(proxyHarness(true,page).nodes().some(n=>n.tag==='img'),false,page+' parsed a label as HTML');
 assert.match(proxyHarness(false,'status').text(),/Нет рабочего подключения/);
});
test('priority arrows change both family and endpoint orders without implicit reselection',async()=>{
 const h=proxyHarness();await h.click('Поднять протокол HY2');await h.click('Поднять подключение Main');await h.click('Сохранить порядок');
 const write=h.writes().at(-1);assert.equal(write.operation,'connection-order');assert.equal(write.expected_generation,7);assert.deepEqual(write.order.families,['hy2','awg','reality','vless','ss2022','wgws']);assert.deepEqual(write.order.connections.hy2,['b','a']);assert.equal(write.reselect,false);
});
test('proxy readonly disables every control on every tab including upload, metadata, export and ordering',()=>{
 let total=0;
 for(const page of proxyTabs){const h=proxyHarness(false,page);const controls=h.nodes().filter(n=>['input','select','textarea','button'].includes(n.tag) && n.children!=='Обновить настройки');total+=controls.length;for(const control of controls)assert.equal(control.disabled,true,page+': '+control.tag+' '+(control.attrs['aria-label']||control.children)+' writable under read ACL');}
 assert.ok(total>25);
});
test('replacement uses full config and clears secret text on success; pinned delete explicitly selects auto',async()=>{
 const h=proxyHarness(true,'connections');const box=h.nodes().find(n=>n.attrs['data-replace']==='b');box.value='PUBLIC_TEST_REPLACEMENT';await h.click('Заменить конфигурацию Main');assert.equal(h.writes().at(-1).data,'PUBLIC_TEST_REPLACEMENT');assert.equal(h.writes().at(-1).id,'b');assert.equal(box.value,'');
 await h.click('Удалить Main');assert.deepEqual(h.writes().at(-1),{operation:'connection-delete',id:'b',selection:{mode:'auto'},expected_generation:7});
});
test('delete asks for confirmation and sends nothing when declined',async()=>{
 const h=proxyHarness(true,'connections');h.browser.confirmReply=false;
 await h.click('Удалить Backup <img src=x>');assert.equal(h.writes().length,0);assert.match(h.browser.confirms.at(-1),/Удалить «Backup <img src=x>»\?$/);
 h.browser.confirmReply=true;await h.click('Удалить Backup <img src=x>');
 assert.deepEqual(h.writes().at(-1),{operation:'connection-delete',id:'a',expected_generation:7},'unpinned delete must not change selection');
 assert.doesNotMatch(h.browser.confirms.at(-1),/Авто/);
});
test('connections tab switches the active connection and returns to auto',async()=>{
 const h=proxyHarness(true,'connections');
 assert.equal(h.find('Сделать активным Main'),undefined,'pinned connection offered again');assert.match(h.text(),/Выбрано вручную/);assert.match(h.text(),/Конкретное подключение · Main/);
 await h.click('Сделать активным Backup <img src=x>');
 assert.deepEqual(h.writes().at(-1),{operation:'selection',selection:{mode:'connection',id:'a'},expected_generation:7});assert.equal(h.browser.confirms.length,0,'enabled connection needs no confirmation');
 h.browser.confirmReply=false;await h.click('Сделать активным AWG Main');assert.equal(h.writes().length,1,'unavailable connection pinned without confirmation');assert.match(h.browser.confirms.at(-1),/отсутствует компонент/);
 await h.click('Вернуться к «Авто»');assert.deepEqual(h.writes().at(-1),{operation:'selection',selection:{mode:'auto'},expected_generation:7});
 const auto=proxyFixture();auto.selection={mode:'auto'};h.response.data=auto;await h.click('Обновить настройки');
 assert.equal(h.find('Вернуться к «Авто»'),undefined);assert.ok(h.find('Сделать активным Main'));
});
test('connections tab marks the active connection and its health from polling',async()=>{
 const h=proxyHarness(false,'connections');assert.doesNotMatch(h.text(),/Активно: /);
 const d=proxyFixture();d.status.active_connection=d.connections[0];d.status.channels={gecko:{healthy:true}};d.status.connection_test={id:'w',phase:'finished',measured:true,tcp:true,udp:false};h.response.data=d;await h.pollers[0]();
 const card=h.nodes().find(n=>n.tag==='article'&&JSON.stringify(n).includes('Backup <img src=x>'));
 assert.match(JSON.stringify(card),/Активно: новые соединения идут здесь · проверки в норме/);assert.ok(allNodes(card).some(n=>n.children&&n.children[0]==='Активно'));
 const awg=h.nodes().find(n=>n.tag==='article'&&JSON.stringify(n).includes('AWG Main'));assert.match(JSON.stringify(awg),/Проверка: завершена · TCP доступен · UDP сбой/);assert.doesNotMatch(JSON.stringify(awg),/Активно: /);
});
test('export shows the config as text with copy, download and hide; it never parses it as HTML',async()=>{
 const h=proxyHarness(true,'connections'),config='hysteria2://PUBLIC_TEST@example.com:443/?obfs=salamander&obfs-password=<img src=x>';
 h.response.data={id:'a',name:'Backup',family:'hy2',format:'url',engine:'sing-box',config,filename:'a.txt',generation:7};
 await h.click('Экспорт Backup <img src=x>');
 assert.deepEqual(h.writes().at(-1),{operation:'connection-export',id:'a',expected_generation:7});
 const area=h.nodes().find(n=>n.attrs&&n.attrs['data-export']==='a');assert.ok(area);assert.equal(area.value,config);assert.ok(area.attrs.readonly);
 assert.equal(h.nodes().some(n=>n.tag==='img'),false);assert.match(h.text(),/ссылка \(URL\)/);assert.match(h.text(),/ключи и пароли/);
 await h.click('Копировать конфигурацию Backup <img src=x>');assert.deepEqual(h.browser.copied,[config]);
 await h.click('Скачать конфигурацию Backup <img src=x>');assert.deepEqual(h.browser.downloads,[{name:'a.txt',href:'blob:flr'}]);assert.deepEqual(h.browser.blob,{text:config,type:'text/plain'});
 await h.click('Скрыть конфигурацию Backup <img src=x>');assert.equal(area.value,'');assert.equal(h.nodes().some(n=>n.attrs&&n.attrs['data-export']),false);
 // JSON and AWG formats download with their own type; a malformed reply shows nothing.
 h.response.data={id:'w',format:'awg-conf',config:'[Interface]\nPrivateKey = PUBLIC_TEST\n',filename:'w.conf'};await h.click('Экспорт AWG Main');
 assert.match(h.text(),/файл AWG/);await h.click('Скачать конфигурацию AWG Main');assert.equal(h.browser.downloads.at(-1).name,'w.conf');
 h.response.data={id:'b',format:'json',config:'{}',filename:'../../etc/passwd'};await h.click('Экспорт Main');await h.click('Скачать конфигурацию Main');
 assert.equal(h.browser.downloads.at(-1).name,'flr-download.txt','unsafe filename used');assert.equal(h.browser.blob.type,'application/json');
 for(const reply of [{id:'other',format:'url',config:'x'},{id:'a',format:'html',config:'<b>x</b>'},{id:'a',format:'url',config:7}]){
  const fresh=proxyHarness(true,'connections');fresh.response.data=reply;await fresh.click('Экспорт Backup <img src=x>');
  assert.equal(fresh.nodes().some(n=>n.attrs&&n.attrs['data-export']),false,JSON.stringify(reply));
 }
 const ro=proxyHarness(false,'connections');assert.equal(ro.find('Экспорт Backup <img src=x>').disabled,true);
});
test('export conflict refreshes the list instead of showing a stale config',async()=>{
 const h=proxyHarness(true,'connections');h.response.ok=false;h.response.error='state changed; refresh before repeating the action';
 await h.click('Экспорт Main');assert.ok(h.transport.calls.some(c=>c.method==='read'&&JSON.parse(c.request).operation==='connection-list'));
 assert.equal(h.nodes().some(n=>n.attrs&&n.attrs['data-export']),false);
});
test('conflict refreshes list and real test requires explicit route-switch warning',async()=>{
 const h=proxyHarness();h.response.ok=false;h.response.error='state changed; refresh before repeating the action';await h.click('Применить выбор');assert.ok(h.transport.calls.some(c=>c.method==='read'&&JSON.parse(c.request).operation==='connection-list'));
 const c=proxyHarness(true,'connections');assert.match(c.text(),/кратковременно/i);await c.click('Проверить Main');assert.match(c.browser.confirms.at(-1),/кратковременно меняет VPN-путь/);assert.deepEqual(c.writes().at(-1),{operation:'connection-test',id:'b',expected_generation:7});
 const i=proxyHarness(true,'import');assert.match(i.text(),/64 КиБ/);assert.match(i.text(),/1 МиБ/);
 const content=i.nodes().find(n=>n.tag==='textarea');content.value='PUBLIC_TEST_IMPORT';await i.click('Импортировать текст');assert.deepEqual(i.writes().at(-1),{operation:'connection-import',data:'PUBLIC_TEST_IMPORT',expected_generation:7});assert.equal(content.value,'');
});
test('proxy shows pending separately and actual measured connection after polling',async()=>{
 const h=proxyHarness(true,'status');h.response.data.status.proxy.pending=true;await h.pollers[0]();assert.match(h.text(),/ожидает применения/i);
 h.response.data.status.proxy.pending=false;h.response.data.status.active_connection=h.response.data.connections[0];h.response.data.status.selection={general:'gecko',games:'gecko'};await h.pollers[0]();assert.match(h.text(),/TCP.*UDP/);assert.match(h.text(),/192.0.2.1/);
});
test('file action awaits browser file read before encoding its request',async()=>{
 const transport={calls:[],declarations:[]},a=api({ok:true,data:{}},true,transport);
 const button=a.action('file',async()=>({operation:'connection-import',expected_generation:7,data:'PUBLIC_FILE'}));
 await button.attrs.click({currentTarget:button});assert.deepEqual(JSON.parse(transport.calls[0].request),{operation:'connection-import',expected_generation:7,data:'PUBLIC_FILE'});
});

test('polling preserves edited forms and does not adopt generation of remote config edits',async()=>{
 const h=proxyHarness(true,'connections'),group=h.nodes().find(n=>n.tag==='input'&&n.value==='Backup');group.value='Edited';
 h.response.data=proxyFixture();h.response.data.generation=8;await h.pollers[0]();assert.equal(group.value,'Edited');await h.click('Сохранить Backup <img src=x>');assert.equal(h.writes().at(-1).expected_generation,8);
 const updated=h.nodes().find(n=>n.tag==='input'&&n.value==='Backup');updated.value='Local edit';
 h.response.data=proxyFixture();h.response.data.generation=9;h.response.data.connections[0].group='External edit';await h.pollers[0]();assert.equal(updated.value,'Local edit');assert.match(h.text(),/Настройки изменились/);await h.click('Сохранить Backup <img src=x>');assert.equal(h.writes().at(-1).expected_generation,8,'adopted newer token over stale form');
});

test('field label explicitly names its editable control',()=>{
 const a=api({ok:true,data:{}}),input={tagName:'INPUT'},tree=a.field('Режим',input);
 assert.ok(input.id);assert.equal(tree.children[0].attrs.for,input.id);
});

test('proxy status separates new flows from retained reserve and missing measurements',async()=>{
 const h=proxyHarness(false,'status');const d=proxyFixture();d.status.active_connection=d.connections[2];d.status.proxy.reserve_connection=d.connections[0];d.status.channels={awg:{healthy:true,last_check:'2026-10-06T00:00:00Z',probe:{not_measured:'cancelled'}},gecko:{healthy:true,last_check:'2026-10-06T00:00:00Z',probe:{measured:true,tcp:true,udp:true}}};h.response.data=d;await h.pollers[0]();
 const text=h.text();assert.match(text,/Новые соединения/);assert.match(text,/Сохранённый резерв/);assert.match(text,/Измерение пропущено/);assert.match(text,/Последнее измерение/);
 const c=proxyHarness(false,'connections');c.response.data=d;await c.pollers[0]();assert.match(c.text(),/Сохранённый резерв: старые сессии продолжают идти через него/);
});
test('proxy status labels a warm standby apart from a reserve with old sessions',async()=>{
 const h=proxyHarness(false,'status');
 async function show(warm,healthy){const d=proxyFixture();d.status.active_connection=d.connections[2];d.status.selection={general:'awg',games:'awg'};d.status.proxy.reserve_connection=d.connections[0];d.status.proxy.reserve_warm=warm;d.status.channels={awg:{healthy:true,last_check:'2026-10-06T00:00:00Z',probe:{measured:true,tcp:true,udp:true}},gecko:{healthy,last_check:'2026-10-06T00:00:00Z',probe:{measured:true,tcp:healthy,udp:healthy}}};d.status.diagnostics={rounds:3,decisions:1,last_decision:{reason:'warm_reserve',outcome:'applied'}};h.response.data=d;await h.pollers[0]();return h.text();}
 let text=await show(true,true);
 assert.match(text,/Тёплый резерв: /);assert.match(text,/сессий на нём нет/);assert.match(text,/без холодного старта/);assert.match(text,/тёплый резерв \/ применено/);
 assert.doesNotMatch(text,/старые сессии/);assert.doesNotMatch(text,/Сохранённый резерв/);
 text=await show(true,false);
 assert.match(text,/Тёплый резерв: /);assert.match(text,/запущен заранее, состояние требует проверки/);assert.doesNotMatch(text,/сессий на нём нет/);
 text=await show(false,true);
 assert.match(text,/Сохранённый резерв: /);assert.match(text,/старые сессии продолжают использовать этот канал/);assert.doesNotMatch(text,/Тёплый резерв/);
});
test('status tab downloads diagnostics through the write method',async()=>{
 const h=proxyHarness(true,'status'),meta={boot:'boot',source:'a'.repeat(40),version:'0.6-runtime',last_sequence:1,dropped_rounds:0,dropped_decisions:0,dropped_round_sequence:0,dropped_decision_sequence:0};
 h.response.data={...meta,rounds:[{sequence:1}],decisions:[],next:1,more:false};await h.click('Скачать диагностику');
 assert.deepEqual(h.writes().at(-1),{operation:'diagnostics-export',value:'0'});assert.equal(h.browser.downloads.at(-1).name,'flr-diagnostics.json');assert.equal(h.browser.blob.type,'application/json');
});
test('settings routing mode is a bounded select and hidden for older controllers',()=>{
 const tree=viewModule('settings').render([{options:{},routing_mode:'split'},{}]),nodes=allNodes(tree);
 const select=nodes.find(n=>n.tag==='select'&&n.attrs['data-field']==='routing_mode');assert.ok(select);assert.equal(select.value,'split');
 assert.deepEqual(JSON.parse(JSON.stringify(select.children.map(o=>[o.attrs.value,[].concat(o.children)[0]]))),[['split','Раздельный: списки из частной политики'],['full_domestic','Всё через VPN, кроме обязательных direct-сервисов'],['full','Всё через VPN']]);
 const action=nodes.find(n=>n.name==='Сохранить режим маршрутизации');
 for(const mode of ['full','full_domestic','split']){select.value=mode;assert.deepEqual(JSON.parse(JSON.stringify(action.request())),{operation:'settings',settings:{routing_mode:mode}});}
 select.value='everything';assert.throws(()=>action.request(),/режим/);
 const older=allNodes(viewModule('settings').render([{options:{}},{}]));
 assert.equal(older.some(n=>n.attrs&&n.attrs['data-field']==='routing_mode'),false);assert.equal(older.some(n=>n.name==='Сохранить режим маршрутизации'),false);assert.doesNotMatch(JSON.stringify(older),/Режим маршрутизации/);
 const unknown=allNodes(viewModule('settings').render([{options:{},routing_mode:'<b>future</b>'},{}])),current=unknown.find(n=>n.tag==='select'&&n.attrs['data-field']==='routing_mode');
 assert.equal(current.value,'<b>future</b>');assert.equal(unknown.some(n=>n.tag==='b'),false);assert.throws(()=>unknown.find(n=>n.name==='Сохранить режим маршрутизации').request());
 const readonly=allNodes(viewModule('settings',false).render([{options:{},routing_mode:'full'},{}])).find(n=>n.attrs&&n.attrs['data-field']==='routing_mode');assert.equal(readonly.disabled,true);
});
test('diagnostic export freezes cursor range and refuses stale or stalled pages',async()=>{
 const a=api({ok:true,data:{}}),meta={boot:'boot',source:'a'.repeat(40),version:'0.6-runtime',last_sequence:3,dropped_rounds:0,dropped_decisions:0,dropped_round_sequence:0,dropped_decision_sequence:0};let values=[];
 const result=await a.collectDiagnostics(async value=>{values.push(value);return value==='0'?{...meta,rounds:[{sequence:1}],decisions:[],next:1,more:true}:{...meta,rounds:[{sequence:3}],decisions:[{sequence:2}],next:3,more:false};});
 assert.deepEqual(values,['0','1:3']);assert.equal(result.rounds.length,2);assert.equal(result.decisions.length,1);
 await assert.rejects(a.collectDiagnostics(async()=>({...meta,rounds:[],decisions:[],next:0,more:true})),/диагностик/i);
 let calls=0;await assert.rejects(a.collectDiagnostics(async()=>({...meta,boot:++calls===1?'boot':'changed',rounds:[{sequence:calls}],decisions:[],next:calls,more:calls===1})),/измени/i);
});

test('diagnostic export accepts eviction behind cursor but rejects unread loss in either ring',async()=>{
 const a=api({ok:true,data:{}}),meta={boot:'boot',source:'a'.repeat(40),version:'0.6-runtime',last_sequence:101,dropped_rounds:10,dropped_decisions:4,dropped_round_sequence:100,dropped_decision_sequence:0};
 const first={...meta,rounds:[],decisions:[{sequence:1},{sequence:16}],next:16,more:true};
 const second={...meta,dropped_decisions:5,dropped_decision_sequence:1,rounds:[{sequence:101}],decisions:[{sequence:32}],next:101,more:false};
 let calls=0;const result=await a.collectDiagnostics(async()=>++calls===1?first:second);
 assert.equal(result.rounds.length,1);assert.equal(result.decisions.length,3);
 for(const tail of [{...second,dropped_round_sequence:101,dropped_rounds:11},{...second,dropped_decision_sequence:20}]) {
  calls=0;await assert.rejects(a.collectDiagnostics(async()=>++calls===1?first:tail),/измени|потер|диагностик/i);
 }
});

test('no view parses controller or user strings as HTML',async()=>{
 const x='<img src=x>';
 const d=proxyFixture();for(const c of d.connections){c.name+=x;c.group+=x;c.endpoint+=x;}
 Object.assign(d,{migration_notice:x,rollback_pending:true});
 Object.assign(d.status,{last_error:x,active_connection:d.connections[0],connection_test:{id:'a',phase:x,measured:true,tcp:true,udp:true},channels:{gecko:{healthy:true,last_check:x,probe:{not_measured:x}}},diagnostics:{rounds:x,decisions:x,last_decision:{reason:x,outcome:x},wan:{probe:{}}}});
 Object.assign(d.status.proxy,{reason:x,pending:true,reserve_connection:d.connections[1],desired_connection:d.connections[2]});
 for(const page of proxyTabs){const h=proxyHarness(true,page);h.response.data=d;await h.click('Обновить настройки');await h.pollers[0]();assert.equal(h.nodes().some(n=>n.parsedFrom),false,page+' parsed '+JSON.stringify(h.nodes().find(n=>n.parsedFrom)));}
 const status={runtime:true,status:{last_error:x,active_connection:d.connections[0],selection:{general:x},proxy:{reserve_connection:d.connections[1]},direct_proxy:{error:x,lan_error:x,config:{bind:x}},channels:{awg:{reason:x,window:{},probe:{}}}}};
 assert.equal(allNodes(viewModule('overview').render(status)).some(n=>n.parsedFrom),false,'overview');
 assert.equal(allNodes(viewModule('help').render({direct_proxy:{bind:x,port:x}})).some(n=>n.parsedFrom),false,'help');
 assert.equal(allNodes(viewModule('settings').render([{options:{profiles:{x}},routing_mode:x,tunnel_qos:{enabled:x,upload_kbit:x,download_kbit:x},direct_proxy:{bind:x,port:x}},{}])).some(n=>n.parsedFrom),false,'settings');
});

test('settings tunnel CAKE sends the complete object, bounds rates and hides for older controllers',()=>{
 const render=(qos,canWrite=true)=>allNodes(viewModule('settings',canWrite).render([{options:{},tunnel_qos:qos},{}]));
 const nodes=render({enabled:true,upload_kbit:45000,download_kbit:90000});
 assert.match(JSON.stringify(nodes),/Очередь в туннеле \(CAKE\)/);assert.match(JSON.stringify(nodes),/немного ниже реальной скорости линии/);
 const up=nodes.find(n=>n.attrs&&n.attrs['data-field']==='upload_kbit'),down=nodes.find(n=>n.attrs&&n.attrs['data-field']==='download_kbit'),enabled=nodes.find(n=>n.tag==='input'&&n.attrs.type==='checkbox'&&n.checked);
 assert.equal(up.value,45000);assert.equal(down.value,90000);assert.ok(enabled);
 const action=nodes.find(n=>n.name==='Сохранить очередь в туннеле');
 assert.deepEqual(JSON.parse(JSON.stringify(action.request())),{operation:'settings',settings:{tunnel_qos:{enabled:true,upload_kbit:45000,download_kbit:90000}}});
 up.value='0';assert.deepEqual(JSON.parse(JSON.stringify(action.request())).settings.tunnel_qos,{enabled:true,upload_kbit:0,download_kbit:90000});
 for(const [u,d] of [['999','90000'],['45000','10000001'],['1500.5','90000'],['-1000','90000'],['abc','0']]){up.value=u;down.value=d;assert.throws(()=>action.request(),/кбит/,u+'/'+d);}
 up.value='0';down.value='0';assert.throws(()=>action.request(),/хотя бы одну/);enabled.checked=false;
 assert.deepEqual(JSON.parse(JSON.stringify(action.request())).settings.tunnel_qos,{enabled:false,upload_kbit:0,download_kbit:0});
 const off=render({enabled:false,upload_kbit:0,download_kbit:0});assert.equal(off.find(n=>n.attrs&&n.attrs['data-field']==='upload_kbit').value,0);
 const older=allNodes(viewModule('settings').render([{options:{}},{}]));assert.equal(older.some(n=>n.name==='Сохранить очередь в туннеле'),false);assert.doesNotMatch(JSON.stringify(older),/CAKE/);
 for(const control of render({enabled:true,upload_kbit:45000,download_kbit:0},false).filter(n=>n.attrs&&['upload_kbit','download_kbit'].includes(n.attrs['data-field'])))assert.equal(control.disabled,true);
});
