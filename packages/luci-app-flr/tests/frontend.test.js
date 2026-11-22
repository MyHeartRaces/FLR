'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const crypto = require('node:crypto');
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
// LuCI i18n (luci-base cbi.js): _() looks a source string up in the loaded
// catalog, String.prototype.format substitutes %s/%d. The tests run the views
// in Russian through the shipped po file, and in English without a catalog.
function parsePo(file) {
 const map={},unquote=s=>JSON.parse(s);let id=null;
 for(const line of fs.readFileSync(file,'utf8').split('\n')) {
  if(line.startsWith('msgid '))id=unquote(line.slice(6));
  else if(line.startsWith('msgstr ') && id)map[id]=unquote(line.slice(7));
 }
 return map;
}
const RU=parsePo(path.join(root,'po/ru/flr.po'));
const FORMAT='String.prototype.format=function(){var a=arguments,i=0;return this.replace(/%(%|s|d)/g,function(m,t){if(t==="%")return "%";var v=a[i++];if(t==="d")return String(parseInt(v,10));return v==null||typeof v==="object"||typeof v==="function"?"":String(v);});};';
let language='ru';
function translate(s){return language==='ru'?(RU[s]||s):language==='mark'?'⟦'+s+'⟧':s;}
function run(source,scope,filename) {
 const context=vm.createContext({_:s=>translate(s),...scope});
 vm.runInContext(FORMAT,context);
 return vm.runInContext('(function(){'+source+'})()',context,{filename});
}
function api(reply,canWrite=true,transport={calls:[],declarations:[]},browser={}) {
 const source = fs.readFileSync(path.join(root,'htdocs/luci-static/resources/flr.js'),'utf8');
 transport.notes=transport.notes||[];
 const scope = { baseclass:{extend:x=>x},rpc:{getSessionID:()=> 'a'.repeat(32),declare:options=>{transport.declarations.push(options);return async request=>{transport.calls.push({method:options.method,request});return typeof reply==='function'?reply(JSON.parse(request),options.method):reply;};}}, TextEncoder, E:luciElement,L:{hasViewPermission:()=>canWrite,resource:p=>'/luci-static/resources/'+p},ui:{addNotification:(t,node,kind)=>{transport.notes.push({kind,text:JSON.stringify(node)});}}, console, btoa, atob, ...browser };
 return run(source,scope,'flr.js');
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
const VIEWS=['overview','profiles','proxy','settings','help','proxy/status','proxy/connections','proxy/order','proxy/import','routing/overview','routing/rules','routing/transfer'];
test('all LuCI modules parse using native LuCI function wrapper',()=>{
 for(const f of ['flr.js',...VIEWS.map(p=>'view/flr/'+p+'.js')]) {
  new vm.Script('(function(){'+fs.readFileSync(path.join(root,'htdocs/luci-static/resources',f),'utf8')+'})()',{filename:f});
 }
});

function viewModule(page,canWrite=true) {
 const source=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr',page+'.js'),'utf8');
 const E=luciElement;
 const flr={style:()=>E('link',{rel:'stylesheet',href:'/flr.css'}),projectLink:()=>E('p',{class:'flr-project'},[]),group:api({ok:true,data:{}}).group,field:(name,input)=>E('label',{},[name,input]),action:(name,request)=>({tag:'action',name,request}),familyLabel:f=>f,read:async()=>({}),error:()=>{}};
 return run(source,{view:{extend:x=>x},E,flr,poll:{add:()=>{}},L:{hasViewPermission:()=>canWrite,url:(...p)=>'/cgi-bin/luci/'+p.join('/')},window:{}},page);
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
 class Blob{constructor(parts,options){record.blob={text:parts.join(''),type:options.type};record.blobParts=parts;}}
 const URL={createObjectURL:()=>'blob:flr',revokeObjectURL:()=>{}};
 return {record,window,document,Blob,URL};
}
function proxyHarness(canWrite=true,page='order'){
 const response={ok:true,data:proxyFixture()},transport={calls:[],declarations:[]},b=browser(),flr=api(response,canWrite,transport,{document:b.document,Blob:b.Blob,URL:b.URL}),pollers=[];
 const scope={view:{extend:x=>x},E:luciElement,flr,poll:{add:f=>pollers.push(f)},L:{hasViewPermission:()=>canWrite,resource:p=>'/luci-static/resources/'+p,url:(...p)=>'/cgi-bin/luci/'+p.join('/')},window:b.window,document:b.document};
 const source=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/proxy',page+'.js'),'utf8');
 const mod=run(source,scope,page),tree=mod.render(response.data);
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
 assert.deepEqual(menu['admin/flr/proxy'],{title:'Proxy',order:20,action:{type:'firstchild'}});
 const tabs=Object.keys(menu).filter(k=>k.startsWith('admin/flr/proxy/')).sort((a,b)=>menu[a].order-menu[b].order);
 assert.deepEqual(tabs.map(k=>[k,menu[k].title,RU[menu[k].title],menu[k].action.type,menu[k].action.path]),[
  ['admin/flr/proxy/status','Status','Состояние','view','flr/proxy/status'],['admin/flr/proxy/connections','Connections','Подключения','view','flr/proxy/connections'],
  ['admin/flr/proxy/order','Order','Порядок','view','flr/proxy/order'],['admin/flr/proxy/import','Import','Импорт','view','flr/proxy/import']]);
 for(const k of tabs)assert.ok(fs.existsSync(path.join(root,'htdocs/luci-static/resources/view',menu[k].action.path+'.js')),k);
 assert.deepEqual(['overview','settings','help'].map(p=>RU[menu['admin/flr/'+p].title]),['Обзор','Настройки','qBittorrent и помощь']);
 assert.equal(RU[menu['admin/flr/proxy'].title],'Прокси');
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
 assert.match(text,/Тёплый резерв:/);assert.match(text,/сессий на нём нет/);assert.match(text,/без холодного старта/);assert.match(text,/тёплый резерв \/ применено/);
 assert.doesNotMatch(text,/старые сессии/);assert.doesNotMatch(text,/Сохранённый резерв/);
 text=await show(true,false);
 assert.match(text,/Тёплый резерв:/);assert.match(text,/запущен заранее, состояние требует проверки/);assert.doesNotMatch(text,/сессий на нём нет/);
 text=await show(false,true);
 assert.match(text,/Сохранённый резерв:/);assert.match(text,/старые сессии продолжают использовать этот канал/);assert.doesNotMatch(text,/Тёплый резерв/);
});
test('status tab downloads diagnostics through the write method',async()=>{
 const h=proxyHarness(true,'status'),meta={boot:'boot',source:'a'.repeat(40),version:'0.6-runtime',last_sequence:1,dropped_rounds:0,dropped_decisions:0,dropped_round_sequence:0,dropped_decision_sequence:0};
 h.response.data={...meta,rounds:[{sequence:1}],decisions:[],next:1,more:false};await h.click('Скачать диагностику');
 assert.deepEqual(h.writes().at(-1),{operation:'diagnostics-export',value:'0'});assert.equal(h.browser.downloads.at(-1).name,'flr-diagnostics.json');assert.equal(h.browser.blob.type,'application/json');
});
test('settings no longer carries the routing mode and points to the Routing page',()=>{
 const nodes=allNodes(viewModule('settings').render([{options:{},routing_mode:'split'},{}]));
 assert.equal(nodes.some(n=>n.attrs&&n.attrs['data-field']==='routing_mode'),false);assert.equal(nodes.some(n=>n.name==='Сохранить режим маршрутизации'),false);
 assert.match(JSON.stringify(nodes),/«Маршрутизация»/);
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

test('diagnostic export downloads attempt-only pages and detects unread attempt loss',async()=>{
 const a=api({ok:true,data:{}}),meta={boot:'boot',instance:'0123456789abcdef',source:'a'.repeat(40),version:'0.8-runtime',last_sequence:4,dropped_rounds:0,dropped_decisions:0,dropped_round_sequence:0,dropped_decision_sequence:0};
 const first={...meta,rounds:[],decisions:[],attempts:[{sequence:2}],next:2,more:true};
 const second={...meta,dropped_attempt_sequence:2,dropped_attempts:1,rounds:[{sequence:3}],decisions:[],attempts:[{sequence:4}],next:4,more:false};
 const cursors=[];
 const result=await a.collectDiagnostics(async value=>{cursors.push(value);return value==='0'?first:second;});
 assert.deepEqual(cursors,['0','2:4']);assert.equal(result.instance,meta.instance);assert.equal(result.attempts.map(record=>record.sequence).join(','),'2,4');
 for(const tail of [{...second,dropped_attempt_sequence:3},{...second,instance:'fedcba9876543210'},{...second,attempts:[{sequence:2}]}]) {
  await assert.rejects(a.collectDiagnostics(async value=>value==='0'?first:tail),/измени|потер|диагностик/i);
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

// ---- i18n -----------------------------------------------------------------
const MSGID=/_\('((?:[^'\\]|\\.)*)'\)/g;
function sources(){return ['flr.js',...VIEWS.map(p=>'view/flr/'+p+'.js')].map(f=>[f,fs.readFileSync(path.join(root,'htdocs/luci-static/resources',f),'utf8')]);}
function poIds(file){return new Set(Object.keys(parsePo(file)));}
test('every msgid is in the Russian catalog and the template; no Russian is left in the sources',()=>{
 const pot=poIds(path.join(root,'po/templates/flr.pot')),used=new Set();
 for(const [f,text] of sources()) {
  assert.doesNotMatch(text,/[А-Яа-яЁё]/,f+' still has Russian source text');
  assert.doesNotMatch(text,/(?<![A-Za-z0-9_$.])_\((?!')/,f+' calls _() with a non-literal');
  for(const m of text.matchAll(MSGID)) {
   const id=m[1];used.add(id);
   assert.ok(!/\\/.test(id) && id===id.trim(),f+': msgid needs no escapes or edge whitespace: '+id);
   assert.ok(RU[id],f+': missing Russian translation: '+id);assert.ok(pot.has(id),f+': missing from flr.pot: '+id);
   const holes=x=>(x.match(/%[sd]/g)||[]).length;assert.equal(holes(RU[id]),holes(id),'placeholders differ: '+id);
  }
 }
 const menu=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/luci/menu.d/luci-app-flr.json'),'utf8'));
 for(const node of Object.values(menu))if(node.title){assert.doesNotMatch(node.title,/[А-Яа-яЁё]/);assert.ok(RU[node.title] && pot.has(node.title),node.title);used.add(node.title);}
 for(const id of pot)assert.ok(used.has(id),'stale msgid in flr.pot: '+id);
 assert.deepEqual([...poIds(path.join(root,'po/ru/flr.po'))].sort(),[...pot].sort());
});
test('the package builds the Russian translation and the image installs it',()=>{
 // luci.mk: LUCI_BASENAME "flr" from luci-app-flr; po/ru/*.po → luci-i18n-flr-ru with flr.ru.lmo.
 const project=path.join(root,'../..');
 assert.match(fs.readFileSync(path.join(root,'Makefile'),'utf8'),/include \$\(TOPDIR\)\/feeds\/luci\/luci\.mk/);
 const lock=JSON.parse(fs.readFileSync(path.join(project,'build/versions.lock.json'),'utf8'));
 assert.ok(lock.packages.includes('luci-i18n-flr-ru'));
 for(const [file,want] of [['ci/prepare-sdk.py','CONFIG_PACKAGE_luci-i18n-flr-ru=y'],['ci/sdk-output.py','"luci-i18n-flr-ru"'],['ci/sdk-build.sh','CONFIG_PACKAGE_luci-i18n-flr-ru=m'],['ci/buildlib.py',"'usr/lib/lua/luci/i18n/flr.ru.lmo'"]])
  assert.ok(fs.readFileSync(path.join(project,file),'utf8').includes(want),file);
});
// Every visible string of every view comes through _(): render with a
// translator that marks its output, drop marked text and fixture data, and
// no words may remain.
function words(tree,data) {
 const known=new Set();(function walk(v){if(typeof v==='string')known.add(v);else if(v&&typeof v==='object')for(const [k,x] of Object.entries(v)){known.add(k);walk(x);}})(data);
 const texts=[];(function walk(n){if(typeof n==='string'){texts.push(n);return;}if(!n||typeof n!=='object')return;for(const k of ['aria-label','placeholder','title'])if(n.attrs&&typeof n.attrs[k]==='string')texts.push(n.attrs[k]);(Array.isArray(n.children)?n.children:[n.children]).forEach(walk);})(tree);
 const allowed=new Set(['TCP','UDP','QUIC','VPN','AWG','HY2','VLESS','REALITY','TLS','ShadowTLS','WebSocket','SS2022','JSON','Cloudflare','Google','sing','box','Xray','https','down','awg','gecko','hy2','flr','css','luci','static','resources','split','full','domestic']);
 const left=[];
 for(let t of texts){for(let prev='';prev!==t;){prev=t;t=t.replace(/⟦[^⟦⟧]*⟧/g,' ');}for(const k of [...known].sort((a,b)=>b.length-a.length))if(k.length>1)t=t.split(k).join(' ');for(const w of t.match(/[A-Za-zА-Яа-яЁё]{3,}/g)||[])if(!allowed.has(w))left.push(w);}
 return left;
}
test('views pass every visible text through _()',async()=>{
 const fixtures=[['overview',{runtime:true,vpn_enabled:true,rollback_pending:true,deactivation_pending:true,status:{proxy:{reserve_connection:{name:'R',family:'hy2'},pending:true},direct_proxy:{lan_error:'x',config:{bind:'192.168.1.1',port:1080}},channels:{awg:{reason:'sustained_latency',window:{samples:1},probe:{targets:[]},recovery_since:'2026-11-01'}}}}],
  ['settings',[{options:{},tunnel_qos:{enabled:true,upload_kbit:1000,download_kbit:0},direct_proxy:{enabled:true,bind:'192.168.1.1',port:1080}},{}]],['help',{direct_proxy:{bind:'192.168.1.1',port:1080}}]];
 const prev=language;language='mark';
 try {
  for(const [page,data] of fixtures){const left=words(viewModule(page).render(data),data);assert.deepEqual(left,[],page);}
  for(const page of proxyTabs){const h=proxyHarness(true,page),d=proxyFixture();d.status.active_connection=d.connections[0];d.status.proxy.reserve_connection=d.connections[1];d.status.connection_test={id:'a',phase:'finished',measured:true,tcp:true,udp:false,restored:true};d.status.channels={gecko:{healthy:true,last_check:'2026-10-06T00:00:00Z',probe:{not_measured:'cancelled'}}};d.status.diagnostics={rounds:1,decisions:1,last_decision:{reason:'fallback',outcome:'applied'},wan:{probe:{measured:true,tcp:true,udp:true}}};h.response.data=d;await h.click(proxyRefresh());await h.pollers[0]();assert.deepEqual(words(h.tree,d),[],page);}
  for(const page of ['overview','rules','transfer']){const h=await routingHarness(page);assert.deepEqual(words(h.tree,h.fixture),[],'routing/'+page);}
 } finally {language=prev;}
});
function proxyRefresh(){return translate('Refresh settings');}
test('English is the source language: views render without a catalog and without Russian',async()=>{
 const prev=language;language='en';
 try {
  const texts=[JSON.stringify(viewModule('overview').render({status:{}})),JSON.stringify(viewModule('settings').render([{options:{}},{}])),JSON.stringify(viewModule('help').render({}))];
  for(const page of proxyTabs)texts.push(proxyHarness(true,page).text());
  for(const page of ['overview','rules','transfer'])texts.push(JSON.stringify((await routingHarness(page)).tree));
  for(const t of texts)assert.doesNotMatch(t,/[А-Яа-яЁё]/);
  assert.match(texts[0],/FLR — status/);assert.match(texts.at(-3),/Routing · overview/);
 } finally {language=prev;}
});

// ---- routing --------------------------------------------------------------
function routingFixture() {
 const rulesets=['local-domains','local-ips','vpn-required','direct-essential','game-platforms','vpn-services','roscom-direct-domains','roscom-direct-ips'].map((name,i)=>({name,class:name.startsWith('local')?'local':name.includes('direct')?'direct':name==='game-platforms'?'games':'general',counts:name==='vpn-services'?{domain:2500}:{domain_suffix:i},total:name==='vpn-services'?2500:i,bytes:10,active:!name.startsWith('roscom'),meta:null,error:''}));
 return {
  policy:{mode:'full_domestic',source:'overlay',overlay_present:true,overlay_error:'',backup_present:true,policy:{status:'synthetic <b>x</b>',version:3,note:'note <img src=x>'},rulesets,custom_rules:{summary:{total:2,enabled:1,vpn:1,direct:0},revision:'rev1',error:''},live:{controller:true,vpn:true,applied_mode:'full_domestic',last_apply:'2026-11-19T00:00:00Z',last_apply_source:'overlay'},limits:{}},
  rules:{revision:'rev1',total:2,matched:2,offset:0,error:'',rules:[{id:'r1',type:'domain',value:'example.com',mode:'vpn',comment:'note <img src=x>',enabled:true},{id:'r2',type:'cidr',value:'192.168.0.0/16',mode:'direct',comment:'',enabled:false,local:true}]},
 };
}
async function routingHarness(page,canWrite=true,respond) {
 const fixture=routingFixture(),transport={calls:[],declarations:[]},b=browser(),pollers=[];
 const entries=Array.from({length:2500},(_,i)=>({kind:'domain',value:'host'+i+'.example.org'}));
 const reply=(request,method)=>{
  const r=request.routing||{};
  if(respond){const custom=respond(request,method);if(custom!==undefined)return custom;}
  switch(request.operation) {
   case 'routing-policy':return {ok:true,data:fixture.policy};
   case 'routing-rules':return {ok:true,data:fixture.rules};
   case 'routing-entries':{const q=(r.query||'').toLowerCase(),m=entries.filter(e=>e.value.includes(q));return {ok:true,data:{ruleset:r.ruleset,source:'overlay',total:entries.length,matched:m.length,offset:r.offset,entries:m.slice(r.offset,r.offset+r.limit)}};}
   default:return {ok:true,data:{apply:{applied:true,source:'overlay',mode:'split'},revision:'rev2'}};
  }
 };
 const flr=api(reply,canWrite,transport,{document:b.document,Blob:b.Blob,URL:b.URL,setTimeout:f=>setImmediate(f)});
 const scope={view:{extend:x=>x},E:luciElement,flr,poll:{add:callback=>pollers.push(callback)},L:{hasViewPermission:()=>canWrite,url:(...p)=>'/cgi-bin/luci/'+p.join('/')},window:b.window,document:b.document};
 const mod=run(fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/routing',page+'.js'),'utf8'),scope,page);
 const tree=mod.render(await mod.load());
 return {tree,fixture,transport,flr,pollers,browser:b.record,nodes:()=>allNodes(tree),text:()=>JSON.stringify(tree),
  find(label){return allNodes(tree).find(n=>n.tag==='button'&&(n.children===label || n.attrs['aria-label']===label));},
  async click(label){const button=this.find(label);assert.ok(button,'missing button '+label);return button.attrs.click({currentTarget:button});},
  requests(){return transport.calls.map(c=>({method:c.method,...JSON.parse(c.request)}));}};
}
test('routing menu adds Overview, Custom rules and Import & export tabs',()=>{
 const menu=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/luci/menu.d/luci-app-flr.json')));
 assert.deepEqual(menu['admin/flr/routing'],{title:'Routing',order:25,action:{type:'firstchild'}});assert.equal(RU.Routing,'Маршрутизация');
 const tabs=Object.keys(menu).filter(k=>k.startsWith('admin/flr/routing/')).sort((a,b)=>menu[a].order-menu[b].order);
 assert.deepEqual(tabs.map(k=>[menu[k].title,menu[k].action.path]),[['Overview','flr/routing/overview'],['Custom rules','flr/routing/rules'],['Import & export','flr/routing/transfer']]);
 for(const k of tabs)assert.ok(fs.existsSync(path.join(root,'htdocs/luci-static/resources/view',menu[k].action.path+'.js')),k);
});
test('routing overview shows the policy and pages ruleset entries without dumping them',async()=>{
 const h=await routingHarness('overview');
 assert.deepEqual(h.requests()[0],{method:'read',operation:'routing-policy'});
 const text=h.text();assert.match(text,/Установлена частная политика/);assert.match(text,/всего 2500 · доменных 2500 · адресных 0/);assert.match(text,/выключен в этом режиме/);assert.match(text,/Резервная копия|резервная копия/);
 assert.equal(h.nodes().some(n=>n.parsedFrom),false,'policy text parsed as HTML');
 await h.click('Просмотреть vpn-services');
 assert.deepEqual(h.requests().at(-1),{method:'read',operation:'routing-entries',routing:{ruleset:'vpn-services',query:'',offset:0,limit:100}});
 const rows=()=>h.nodes().filter(n=>n.tag==='tr'&&n.children.length===2&&n.children[1].attrs&&/flr-value/.test(n.children[1].attrs.class||''));
 assert.equal(rows().length,100,'one page of entries only');assert.match(h.text(),/1–100 из 2500 найденных \(всего 2500\)/);
 await h.click('Следующая страница');assert.equal(h.requests().at(-1).routing.offset,100);assert.match(h.text(),/101–200 из 2500/);
 h.nodes().find(n=>n.attrs&&n.attrs['data-field']==='entry-query').value='host12';await h.click('Найти');
 assert.deepEqual(h.requests().at(-1).routing,{ruleset:'vpn-services',query:'host12',offset:0,limit:100});assert.match(h.text(),/1–100 из 111 найденных/);
 assert.ok(h.requests().every(r=>r.method==='read'),'browsing writes nothing');
 const ro=await routingHarness('overview',false);assert.equal(ro.find('Просмотреть vpn-services').disabled,false,'reading needs no write permission');
});
test('routing mode offers exactly Full proxy, Tunnel and Direct',async()=>{
 const h=await routingHarness('overview'),select=h.nodes().find(n=>n.tag==='select'&&n.attrs['data-field']==='routing_mode');
 assert.ok(select);assert.equal(select.value,'full_domestic');
 assert.deepEqual(Array.from(select.children).filter(o=>!o.disabled).map(o=>[o.attrs.value,o.children[0]]),[['split','Полный прокси'],['tunnel','Туннель'],['direct','Напрямую']]);
 for(const mode of ['split','tunnel','direct']){select.value=mode;await h.click('Сохранить режим маршрутизации');assert.deepEqual(h.requests().filter(r=>r.method==='write').at(-1),{method:'write',operation:'settings',settings:{routing_mode:mode}});}
 for(const mode of ['full','full_domestic','proxy']) {
  const legacy=await routingHarness('overview',true,r=>r.operation==='routing-policy'?{ok:true,data:{...routingFixture().policy,mode}}:undefined);
  const menu=legacy.nodes().find(n=>n.attrs['data-field']==='routing_mode');
  assert.equal(menu.value,mode);
  assert.ok(Array.from(menu.children).find(o=>o.attrs.value===mode)?.disabled);
  await legacy.click('Сохранить режим маршрутизации');
  assert.equal(legacy.requests().some(r=>r.method==='write'),false);
 }
 select.value='everything';const before=h.requests().length;await h.click('Сохранить режим маршрутизации');assert.equal(h.requests().length,before);assert.match(h.transport.notes.at(-1).text,/режим/);
 const unknown=await routingHarness('overview',true,r=>r.operation==='routing-policy'?{ok:true,data:{...routingFixture().policy,mode:'<b>future</b>'}}:undefined),current=unknown.nodes().find(n=>n.tag==='select'&&n.attrs['data-field']==='routing_mode');
 assert.equal(current.value,'<b>future</b>');assert.equal(unknown.nodes().some(n=>n.tag==='b'),false);
 const ro=await routingHarness('overview',false);assert.equal(ro.nodes().find(n=>n.attrs&&n.attrs['data-field']==='routing_mode').disabled,true);assert.equal(ro.find('Сохранить режим маршрутизации').disabled,true);
 const old=await routingHarness('overview',true,r=>r.operation==='routing-policy'?{ok:false,data:null,error:'unknown operation'}:undefined);assert.match(old.text(),/unknown operation/);
});
test('routing overview distinguishes selected Direct from applied Full proxy',async()=>{
 const p=routingFixture().policy;
 const h=await routingHarness('overview',true,r=>r.operation==='routing-policy'?{ok:true,data:{...p,source:'image',mode:'direct',live:{...p.live,applied_mode:'split'}}}:undefined);
 const select=h.nodes().find(n=>n.tag==='select'&&n.attrs['data-field']==='routing_mode');
 assert.equal(select.value,'direct');
 assert.ok(select.attrs['aria-describedby'],'selected mode has no accessible description');
 const description=h.nodes().find(n=>n.attrs.id===select.attrs['aria-describedby']);
 assert.match(description.children.join(''),/через провайдера/);
 assert.match(description.children.join(''),/обычный DNS роутера/);
 assert.match(h.text(),/Действующие соединения сохраняют свои маршруты/);
 assert.match(h.text(),/Полный прокси/);
 assert.match(h.text(),/Ожидает применения/);
 assert.doesNotMatch(h.text(),/всё, кроме локальных назначений, идёт через VPN/);
 select.value='split';select.attrs.change();
 assert.match(description.children.join(''),/через VPN/);
 select.value='tunnel';select.attrs.change();
 assert.match(description.children.join(''),/Собственные правила прямой маршрутизации отключены/);
});
test('routing mode save tracks the applied mode and refreshes the ruleset activity',async()=>{
 const p=routingFixture().policy;
 const h=await routingHarness('overview',true,r=>{
  if(r.operation==='routing-policy')return {ok:true,data:p};
  if(r.operation==='settings'){
   p.mode=r.settings.routing_mode;
   p.live={...p.live,vpn:false,pending:true};
   return {ok:true,data:{routing_mode:p.mode}};
  }
 });
 const directEssential=h.nodes().find(n=>n.attrs['data-ruleset']==='direct-essential');
 assert.match(JSON.stringify(directEssential),/используется/);
 h.nodes().find(n=>n.attrs['data-field']==='routing_mode').value='direct';
 await h.click('Сохранить режим маршрутизации');
 assert.match(h.text(),/Ожидает применения: Напрямую/);
 assert.match(JSON.stringify(directEssential),/используется/);
 p.live={...p.live,vpn:false,applied_mode:'direct',pending:false};
 p.rulesets.find(rs=>rs.name==='direct-essential').active=false;
 assert.equal(h.pollers.length,1,'the status does not get refreshed while the mode is pending');
 await h.pollers[0]();
 assert.match(h.text(),/Активный режим маршрутизации: Напрямую/);
 assert.match(JSON.stringify(directEssential),/выключен в этом режиме/);
 assert.equal(h.nodes().find(n=>n.attrs['data-field']==='routing_mode').children.length,3);
});
test('Direct mode displays saved custom rules as inactive and allows editing them',async()=>{
 const p=routingFixture().policy;
 const h=await routingHarness('rules',true,r=>r.operation==='routing-policy'?{ok:true,data:{...p,mode:'direct',live:{...p.live,vpn:false,applied_mode:'direct'}}}:undefined);
 assert.match(h.text(),/Режим «Напрямую» обходит собственные правила/);
 h.nodes().find(n=>n.attrs['data-field']==='new-value').value='example.org';
 await h.click('Добавить правило');
 assert.equal(h.requests().some(r=>r.operation==='routing-rule-add'),true);
 assert.match(h.transport.notes.map(n=>n.text).join(' '),/Правила сохранены/);
});
test('routing overview follows a pending same-mode policy reload',async()=>{
 const p=routingFixture().policy;
 p.mode='split';
 p.live={...p.live,applied_mode:p.mode,pending:true};
 const h=await routingHarness('overview',true,r=>r.operation==='routing-policy'?{ok:true,data:p}:undefined);
 const status=h.nodes().find(n=>n.tag==='p'&&n.attrs['aria-live']==='polite'&&!n.attrs.id);
 assert.match(status.children.join(''),/Ожидает применения/);
 p.live={...p.live,pending:false,last_apply:'2026-11-19T00:05:00Z'};
 await h.pollers[0]();
 assert.match(status.children.join(''),/Активный режим маршрутизации: Полный прокси/);
 assert.match(h.text(),/Последнее применение: 2026-11-19T00:05:00Z/);
});
test('custom rules: add, toggle, edit and delete carry the revision; conflicts reload the list',async()=>{
 const h=await routingHarness('rules');
 assert.deepEqual(h.requests().slice(0,2).map(r=>r.operation),['routing-rules','routing-policy']);
 assert.match(h.text(),/Это правило перекрывается локальными назначениями/);assert.equal(h.nodes().some(n=>n.parsedFrom),false);
 const field=name=>h.nodes().find(n=>n.attrs&&n.attrs['data-field']===name);
 field('new-value').value=' Example.org ';field('new-mode').value='direct';field('new-comment').value='synthetic';
 await h.click('Добавить правило');
 assert.deepEqual(h.requests().at(-2),{method:'write',operation:'routing-rule-add',routing:{rule:{type:'',value:'Example.org',mode:'direct',comment:'synthetic',enabled:true},revision:'rev1'}});
 assert.equal(h.requests().at(-1).operation,'routing-rules','list reloaded after the change');
 assert.ok(h.transport.notes.some(n=>/Применено к новым соединениям/.test(n.text)));
 let count=h.requests().length;field('new-value').value='2001:db8::1';await h.click('Добавить правило');assert.equal(h.requests().length,count,'IPv6 reached the router');
 field('new-value').value='';await h.click('Добавить правило');assert.equal(h.requests().length,count);
 await h.click('Выключить правило example.com');
 assert.deepEqual(h.requests().at(-2),{method:'write',operation:'routing-rule-update',routing:{id:'r1',rule:{type:'domain',value:'example.com',mode:'vpn',comment:'note <img src=x>',enabled:false},revision:'rev1'}});
 field('edit-r1-value').value='example.net';field('edit-r1-mode').value='direct';await h.click('Сохранить правило example.com');
 assert.deepEqual(h.requests().at(-2).routing,{id:'r1',rule:{type:'domain',value:'example.net',mode:'direct',comment:'note <img src=x>',enabled:true},revision:'rev1'});
 h.browser.confirmReply=false;count=h.requests().length;await h.click('Удалить правило example.com');assert.equal(h.requests().length,count,'delete without confirmation');
 h.browser.confirmReply=true;await h.click('Удалить правило example.com');assert.deepEqual(h.requests().at(-2),{method:'write',operation:'routing-rule-delete',routing:{id:'r1',revision:'rev1'}});
 const c=await routingHarness('rules',true,(r)=>r.operation==='routing-rule-add'?{ok:false,data:null,error:'routing rules changed; refresh before repeating the action'}:undefined);
 c.nodes().find(n=>n.attrs&&n.attrs['data-field']==='new-value').value='example.org';await c.click('Добавить правило');
 assert.equal(c.requests().at(-1).operation,'routing-rules','conflict must reload the rules');
 const ro=await routingHarness('rules',false);
 for(const n of ro.nodes().filter(n=>['input','select','button'].includes(n.tag)&&!['rule-query'].includes(n.attrs['data-field'])&&!['Найти','Предыдущая страница','Следующая страница'].includes(n.children)))assert.equal(n.disabled,true,'writable under read ACL: '+(n.attrs['aria-label']||n.attrs['data-field']||n.children));
});
test('SHA-256 helper matches node crypto',()=>{
 const a=api({ok:true,data:{}});
 for(const n of [0,1,55,56,63,64,65,1000,100003]){const bytes=crypto.randomBytes(n);assert.equal(a.sha256(new Uint8Array(bytes)),crypto.createHash('sha256').update(bytes).digest('hex'),String(n));}
 assert.deepEqual([...a.base64ToBytes(a.bytesToBase64(new Uint8Array([0,255,1,128])))],[0,255,1,128]);
 assert.throws(()=>a.base64ToBytes('<b>'));
});
test('routing export downloads checked chunks; a change in between is refused',async()=>{
 const data=Buffer.from(JSON.stringify({format:'flr-routing-bundle',pad:'x'.repeat(80000)})),sum=crypto.createHash('sha256').update(data).digest('hex'),chunk=32768;
 let changed=false;
 const h=await routingHarness('transfer',true,r=>{if(r.operation!=='routing-export')return undefined;const o=(r.routing&&r.routing.offset)||0,end=Math.min(o+chunk,data.length);if(o&&r.routing.sha256!==sum)return {ok:false,data:null,error:'bad'};return {ok:true,data:{format:'flr-routing-bundle',source:'overlay',size:data.length,sha256:changed&&o?'0'.repeat(64):sum,offset:o,next:end,more:end<data.length,data:data.subarray(o,end).toString('base64'),filename:'flr-routing.json'}};});
 await h.click('Скачать конфигурацию маршрутизации');
 const exports=h.requests().filter(r=>r.operation==='routing-export');
 assert.deepEqual(exports.map(r=>[r.method,(r.routing||{}).offset||0]),[['write',0],['write',32768],['write',65536]]);assert.equal(exports[1].routing.sha256,sum);
 assert.equal(h.browser.downloads.at(-1).name,'flr-routing.json');assert.equal(h.browser.blob.type,'application/json');
 assert.ok(Buffer.from(h.browser.blobParts[0]).equals(data),'downloaded bytes differ');
 changed=true;const downloads=h.browser.downloads.length;await h.click('Скачать конфигурацию маршрутизации');
 assert.equal(h.browser.downloads.length,downloads,'changed export downloaded');assert.match(h.transport.notes.at(-1).text,/изменилась во время экспорта/);
 const ro=await routingHarness('transfer',false);for(const label of ['Скачать конфигурацию маршрутизации','Импортировать файл','Перечитать и применить','Сбросить к политике образа','Восстановить резервную копию'])assert.equal(ro.find(label).disabled,true,label);
});
test('routing import sends size, SHA-256 and ordered chunks within the request limit',async()=>{
 const data=Buffer.from(JSON.stringify({format:'flr-custom-routing-rules',version:1,rules:[],pad:'y'.repeat(70000)})),sum=crypto.createHash('sha256').update(data).digest('hex');
 let failChunk=-1;
 const h=await routingHarness('transfer',true,(r)=>{
  if(r.operation==='routing-import-begin')return {ok:true,data:{staging_id:'0123456789abcdef',size:r.routing.size,chunk_bytes:32768}};
  if(r.operation==='routing-import-chunk')return r.routing.offset===failChunk?{ok:false,data:null,error:'chunk out of order'}:{ok:true,data:{received:r.routing.offset}};
  if(r.operation==='routing-import-commit')return {ok:true,data:{imported:{policy:true,custom_rules:3},apply:{applied:false,pending:'not applied yet; the controller retries every round'}}};
  return undefined;
 });
 const input=h.nodes().find(n=>n.tag==='input'&&n.attrs.type==='file');
 input.files=[{name:'routing.json',size:data.length,arrayBuffer:async()=>data.buffer.slice(data.byteOffset,data.byteOffset+data.length)}];
 h.browser.confirmReply=false;await h.click('Импортировать файл');assert.equal(h.requests().filter(r=>r.method==='write').length,0,'import without confirmation');
 h.browser.confirmReply=true;await h.click('Импортировать файл');
 const writes=h.requests().filter(r=>r.method==='write');
 assert.deepEqual(writes[0],{method:'write',operation:'routing-import-begin',routing:{size:data.length,sha256:sum}});
 const chunks=writes.filter(r=>r.operation==='routing-import-chunk');assert.deepEqual(chunks.map(r=>r.routing.offset),[0,32768,65536]);
 assert.ok(Buffer.concat(chunks.map(r=>Buffer.from(r.routing.data,'base64'))).equals(data));assert.ok(chunks.every(r=>r.routing.staging_id==='0123456789abcdef'));
 assert.deepEqual(writes.at(-1),{method:'write',operation:'routing-import-commit',routing:{staging_id:'0123456789abcdef'}});
 assert.match(h.text(),/Импортировано: политика и наборы правил, собственных правил: 3\./);assert.ok(h.transport.notes.some(n=>/Сохранено, но ещё не применено: not applied yet/.test(n.text)));
 assert.ok(h.transport.calls.every(c=>h.flr.httpRequestBytes(JSON.parse(c.request),'a'.repeat(32),c.method)<=65536),'a chunk exceeds the LuCI request limit');
 failChunk=32768;await h.click('Импортировать файл');
 assert.equal(h.requests().at(-1).operation,'routing-import-abort','failed upload must drop the staged import');assert.match(h.transport.notes.at(-1).text,/chunk out of order/);
 input.files=[{name:'big.json',size:16*1024*1024+1,arrayBuffer:async()=>new ArrayBuffer(1)}];const count=h.requests().length;await h.click('Импортировать файл');assert.equal(h.requests().length,count,'oversized file sent');
});
test('reset and restore need confirmation and send explicit acceptance',async()=>{
 const h=await routingHarness('transfer');
 h.browser.confirmReply=false;await h.click('Сбросить к политике образа');assert.equal(h.requests().filter(r=>r.method==='write').length,0);
 h.browser.confirmReply=true;await h.click('Сбросить к политике образа');assert.deepEqual(h.requests().at(-1),{method:'write',operation:'routing-reset',routing:{accepted:true}});
 await h.click('Восстановить резервную копию');assert.deepEqual(h.requests().at(-1),{method:'write',operation:'routing-restore-backup',routing:{accepted:true}});
 await h.click('Перечитать и применить');assert.deepEqual(h.requests().at(-1),{method:'write',operation:'routing-apply'});
});
test('rpcd ACL needs no change: routing reads use the read method, routing writes the write method',async()=>{
 const h=await routingHarness('overview');assert.ok(h.requests().every(r=>r.method==='read'));
 const acl=JSON.parse(fs.readFileSync(path.join(root,'root/usr/share/rpcd/acl.d/luci-app-flr.json')));
 assert.deepEqual(acl['luci-app-flr'].write.ubus,{'luci.flr':['write']});
});

// ---- RoscomVPN import -----------------------------------------------------
const WHITELIST='https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/refs/heads/main/HAPP/WHITELIST.JSON';
function roscomResult(installed){return {dry_run:!installed,installed,download_path:'vpn-awg',source:WHITELIST,backup_present:installed,apply:installed?{applied:true,source:'overlay',mode:'split'}:undefined,
 report:{name:'Synthetic <img src=x>',rulesets:{'roscom-direct-ips':{total:3,imported:3,counts:{ip_cidr:3}},'local-ips':{total:5,imported:1,counts:{ip_cidr:5}}},categories:[{list:'DirectIp',name:'geoip:direct',entries:3}],
  skipped:[{field:'DirectIp',code:'ipv6',reason:'IPv6: FLR routes IPv4 only',count:2,examples:['2001:db8::/32']},{field:'DirectSites',code:'category_unreadable',args:['truncated <b>data</b>'],reason:'unreadable category: truncated <b>data</b>',count:1},{field:'ProxySites',code:'future_code',reason:'future English reason <img src=x>',count:1}],
  not_applied:[{field:'BlockSites',code:'block_not_applied',reason:'FLR does not block destinations',count:3},{field:'GlobalProxy',code:'global_proxy',reason:'Unmatched traffic follows the configured mode',count:1}],notes:[{code:'note_split_only',text:'DirectSites and DirectIp apply in routing mode split only'},{code:'note_bare_keywords',args:['4'],text:'4 bare entries'}]}};}
test('RoscomVPN preview sends the preset URL as a dry run and shows the report as text',async()=>{
 const h=await routingHarness('transfer',true,r=>r.operation==='routing-roscomvpn-import'?{ok:true,data:{...roscomResult(false),pending:false}}:undefined);
 const url=h.nodes().find(n=>n.attrs&&n.attrs['data-field']==='roscomvpn_url');
 await h.click('Профиль Whitelist');assert.equal(url.value,WHITELIST);
 await h.click('Предпросмотр');
 assert.deepEqual(h.requests().at(-1),{method:'write',operation:'routing-roscomvpn-import',routing:{dry_run:true,url:WHITELIST}});
 assert.equal(h.browser.confirms.length,0,'a preview changes nothing and needs no confirmation');
 const text=h.text();
 assert.match(text,/Только предпросмотр: ничего не изменено/);assert.match(text,/через VPN \(AWG\)/);assert.match(text,/roscom-direct-ips/);
 assert.match(text,/DirectIp: записей 2 — IPv6: FLR маршрутизирует только IPv4/);assert.match(text,/BlockSites: записей 3 — FLR маршрутизирует эти назначения по остальным спискам и выбранному режиму/);assert.match(text,/geoip:direct · 3/);
 assert.match(text,/GlobalProxy: записей 1 — FLR сохраняет выбранный режим маршрутизации/);
 // Codes are translated with their arguments; an unknown code falls back to the router's English text.
 assert.match(text,/категория не читается: truncated <b>data<\/b>/);assert.match(text,/future English reason/);
 assert.match(text,/действуют в режиме «Полный прокси» \(split\)/);assert.match(text,/Записей без префикса: 4;/);
 assert.doesNotMatch(text,/apply in routing mode split only/,'a known note code must be shown translated');
 assert.equal(h.nodes().some(n=>n.parsedFrom),false,'report text parsed as HTML');
 await h.click('Профиль Default');assert.match(url.value,/HAPP\/DEFAULT\.JSON$/);
});
test('RoscomVPN import asks for confirmation that names the replacement and the backup, then polls the job',async()=>{
 let polls=0;
 const h=await routingHarness('transfer',true,r=>{
  if(r.operation==='routing-roscomvpn-import')return {ok:true,data:{pending:true,job:'0123456789abcdef',dry_run:false,download_path:'vpn-awg'}};
  if(r.operation==='routing-roscomvpn-status'){polls++;return {ok:true,data:{job:polls<3?{id:'0123456789abcdef',pending:true,phase:'downloading geoip'}:{id:'0123456789abcdef',pending:false,phase:'done',result:roscomResult(true)}}};}
 });
 h.nodes().find(n=>n.attrs&&n.attrs['data-field']==='roscomvpn_url').value=WHITELIST;
 h.browser.confirmReply=false;await h.click('Импортировать профиль RoscomVPN');
 assert.equal(h.requests().filter(r=>r.operation==='routing-roscomvpn-import').length,0,'import sent without confirmation');
 const question=h.browser.confirms.at(-1);
 assert.match(question,/заменит текущую политику маршрутизации/);assert.match(question,/резервная копия/);assert.match(question,/«Восстановить резервную копию»/);
 h.browser.confirmReply=true;await h.click('Импортировать профиль RoscomVPN');
 const reqs=h.requests();
 assert.deepEqual(reqs.find(r=>r.operation==='routing-roscomvpn-import'),{method:'write',operation:'routing-roscomvpn-import',routing:{accepted:true,url:WHITELIST}});
 assert.deepEqual(reqs.filter(r=>r.operation==='routing-roscomvpn-status').map(r=>r.method),['read','read','read']);
 assert.match(h.text(),/Установлено: прежняя политика сохранена как резервная копия/);assert.match(h.text(),/Резервная копия|резервная копия/);
 assert.ok(h.transport.notes.some(n=>/Применено к новым соединениям/.test(n.text)));
});
test('RoscomVPN failed job and missing input are reported; read-only users cannot start it',async()=>{
 const h=await routingHarness('transfer',true,r=>{
  if(r.operation==='routing-roscomvpn-import')return {ok:true,data:{pending:true,job:'0123456789abcdef'}};
  if(r.operation==='routing-roscomvpn-status')return {ok:true,data:{job:{id:'0123456789abcdef',pending:false,phase:'failed',error:'geoip download failed (vpn-awg): HTTP status 404'}}};
 });
 await h.click('Предпросмотр');assert.match(h.transport.notes.at(-1).text,/HTTPS URL/);assert.equal(h.requests().filter(r=>r.method==='write').length,0);
 h.nodes().find(n=>n.attrs&&n.attrs['data-field']==='roscomvpn_url').value='http://profiles.example.com/x';
 await h.click('Предпросмотр');assert.equal(h.requests().filter(r=>r.method==='write').length,0,'plain HTTP sent');
 h.nodes().find(n=>n.attrs&&n.attrs['data-field']==='roscomvpn_url').value='https://profiles.example.com/x';
 await h.click('Предпросмотр');assert.match(h.transport.notes.at(-1).text,/geoip download failed/);
 const ro=await routingHarness('transfer',false);
 for(const label of ['Предпросмотр','Импортировать профиль RoscomVPN'])assert.equal(ro.find(label).disabled,true,label);
 assert.equal(ro.nodes().find(n=>n.attrs&&n.attrs['data-field']==='roscomvpn_url').disabled,true);
});
test('RoscomVPN profile file goes through the chunked staging, then the import names the staging ID',async()=>{
 const data=Buffer.from('happ://routing/onadd/'+Buffer.from(JSON.stringify({Name:'Edited',DirectSites:['domain:example.com']})).toString('base64')),sum=crypto.createHash('sha256').update(data).digest('hex');
 const h=await routingHarness('transfer',true,r=>{
  if(r.operation==='routing-import-begin')return {ok:true,data:{staging_id:'fedcba9876543210',size:r.routing.size,chunk_bytes:32768}};
  if(r.operation==='routing-import-chunk')return {ok:true,data:{received:r.routing.offset}};
  if(r.operation==='routing-roscomvpn-import')return {ok:true,data:{...roscomResult(false),pending:false,source:'uploaded file'}};
 });
 const input=h.nodes().find(n=>n.tag==='input'&&n.attrs.type==='file'&&/deeplink/.test(n.attrs.accept));
 input.files=[{name:'DEFAULT.DEEPLINK',size:data.length,arrayBuffer:async()=>data.buffer.slice(data.byteOffset,data.byteOffset+data.length)}];
 await h.click('Предпросмотр');
 const writes=h.requests().filter(r=>r.method==='write');
 assert.deepEqual(writes.map(r=>r.operation),['routing-import-begin','routing-import-chunk','routing-roscomvpn-import']);
 assert.deepEqual(writes[0].routing,{size:data.length,sha256:sum});
 assert.deepEqual(writes[2].routing,{dry_run:true,staging_id:'fedcba9876543210'});
 input.files=[{name:'big.json',size:1024*1024+1,arrayBuffer:async()=>new ArrayBuffer(1)}];const count=h.requests().length;await h.click('Предпросмотр');assert.equal(h.requests().length,count,'oversized profile sent');
});
test('LuCI translates every RoscomVPN issue and note code the router emits, with the same English text',()=>{
 const go=fs.readFileSync(path.join(root,'../../runtime/internal/geodata/roscomvpn.go'),'utf8');
 const block=go.slice(go.indexOf('var Reasons = map[string]string{'));const body=block.slice(0,block.indexOf('\n}\n'));
 const goCodes=Object.fromEntries([...body.matchAll(/^\s*"([a-z0-9_]+)":\s*"(.*)",\s*$/gm)].map(m=>[m[1],JSON.parse('"'+m[2]+'"')]));
 const js=fs.readFileSync(path.join(root,'htdocs/luci-static/resources/view/flr/routing/transfer.js'),'utf8');
 const luci=Object.fromEntries([...js.matchAll(/^\s+([a-z0-9_]+):_\('([^']*)'\)/gm)].map(m=>[m[1],m[2]]));
 assert.ok(Object.keys(goCodes).length>=20);
 for(const [code,text] of Object.entries(goCodes)){assert.equal(luci[code],text,code);assert.ok(RU[text],'missing Russian: '+code);}
});
