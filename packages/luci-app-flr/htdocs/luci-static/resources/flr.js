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
  throw new Error(_('The request exceeds the 64 KiB web interface limit. Use an HTTPS URL for a large subscription.'));
 return text;
}
function reply(value) {
 if (!value || typeof value !== 'object' || typeof value.ok !== 'boolean' || !Object.prototype.hasOwnProperty.call(value,'data'))
  throw new Error(_('FLR returned no valid reply. Check the service and retry.'));
 if (!value.ok) throw new Error(typeof value.error === 'string' && value.error ? value.error : _('The FLR operation failed.'));
 return value.data;
}
var families=['awg','hy2','reality','vless','ss2022','wgws'];
// SHA-256 of the import/export bytes. crypto.subtle exists only in secure
// contexts, and LuCI is often opened over plain HTTP on the LAN.
var K256=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256hex(bytes) {
 var l=bytes.length,n=((l+9+63)>>6)<<6,m=new Uint8Array(n),dv=new DataView(m.buffer),w=new Uint32Array(64);
 var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
 m.set(bytes);m[l]=0x80;dv.setUint32(n-8,Math.floor(l/0x20000000));dv.setUint32(n-4,(l*8)>>>0);
 for(var i=0;i<n;i+=64) {
  var t,a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
  for(t=0;t<16;t++)w[t]=dv.getUint32(i+t*4);
  for(t=16;t<64;t++){var x=w[t-15],y=w[t-2];w[t]=(w[t-16]+(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+w[t-7]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10)))|0;}
  for(t=0;t<64;t++){var t1=(h+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K256[t]+w[t])|0,t2=((((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c)))|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
  H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
 }
 return H.map(function(v){return ('00000000'+(v>>>0).toString(16)).slice(-8);}).join('');
}
function bytesToBase64(bytes) {
 var text='';for(var i=0;i<bytes.length;i+=8192)text+=String.fromCharCode.apply(null,Array.prototype.slice.call(bytes.subarray(i,i+8192)));
 return btoa(text);
}
function base64ToBytes(text) {
 if(typeof text!=='string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text))throw new Error(_('FLR returned no valid reply. Check the service and retry.'));
 var binary=atob(text),out=new Uint8Array(binary.length);for(var i=0;i<binary.length;i++)out[i]=binary.charCodeAt(i);return out;
}
var maxRoutingBundle=16*1024*1024;
var fieldSequence=0;
return baseclass.extend({
 families:families,
 familyLabel:function(family){return {awg:'AWG',hy2:'HY2',reality:'VLESS / REALITY',vless:'VLESS / TLS',ss2022:'SS2022 / ShadowTLS',wgws:'WG / WebSocket'}[family] || family;},
 proxySelection:function(mode,family,id) {
  if(mode==='auto')return {mode:'auto'};
  if(mode==='transport' && families.includes(family))return {mode:'transport',family:family};
  if(mode==='connection' && /^[a-z0-9_-]{1,80}$/.test(id || ''))return {mode:'connection',id:id};
  throw new Error(_('Choose a mode and an available protocol or connection.'));
 },
 proxyOrder:function(order,connections) {
  if(!Array.isArray(order) || order.length!==families.length || families.some(function(f){return order.filter(function(x){return x===f;}).length!==1;}))throw new Error(_('The order must list every protocol exactly once.'));
  var copy={families:order.slice(),connections:{}},seen={};
  families.forEach(function(f){if(!Array.isArray(connections[f]))throw new Error(_('Invalid connection order.'));copy.connections[f]=connections[f].map(function(id){if(!/^[a-z0-9_-]{1,80}$/.test(id) || seen[id])throw new Error(_('A connection appears twice in the order.'));seen[id]=true;return id;});});
  return copy;
 },
 style:function(){return E('link',{rel:'stylesheet',href:L.resource('flr.css')});},
 projectURL:'https://github.com/MyHeartRaces/FLR',
 projectLink:function(){return E('p',{class:'flr-project'},[_('FLR source code, releases and documentation:'),' ',E('a',{href:this.projectURL,target:'_blank',rel:'noopener'},this.projectURL.replace('https://',''))]);},
 httpRequestBytes:httpRequestBytes,
 boundedJSON:function(request,method) {return bounded(request,method || 'write');},
 group:function(value) {
  if(new TextEncoder().encode(value).length>80 || /[\r\n\x00]/.test(value) || value.includes('://'))
   throw new Error(_('Group: at most 80 bytes of UTF-8, without line breaks, NUL or URLs.'));
  return value;
 },
 read:async function(request) {return reply(await readRPC(bounded(request,'read')));},
 collectDiagnostics:async function(fetchPage) {
  var output=null,cursor=0,upper=0,bytes=0;
  for(var pages=0;pages<1000;pages++) {
   var page=await fetchPage(output?cursor+':'+upper:'0');
   if(!page || !Array.isArray(page.rounds) || !Array.isArray(page.decisions) || !Number.isSafeInteger(page.next) || !Number.isSafeInteger(page.last_sequence) || page.next<cursor || page.next>page.last_sequence)throw new Error(_('Invalid diagnostics page.'));
   if(!output){upper=page.last_sequence;output={boot:page.boot,source:page.source,version:page.version,last_sequence:upper,dropped_rounds:page.dropped_rounds,dropped_decisions:page.dropped_decisions,dropped_round_sequence:page.dropped_round_sequence,dropped_decision_sequence:page.dropped_decision_sequence,rounds:[],decisions:[]};}
   else if(page.boot!==output.boot || page.source!==output.source || page.version!==output.version || page.last_sequence!==upper)throw new Error(_('The history changed during the download; repeat the export.'));
   ['round','decision'].forEach(function(kind){
    var key='dropped_'+kind+'_sequence',value=page[key],base=output[key];
    if(!Number.isSafeInteger(value) || value<0 || !Number.isSafeInteger(base) || base<0)throw new Error(_('Invalid diagnostics history boundary.'));
    if(value>Math.max(base,cursor))throw new Error(_('The history lost records not yet downloaded; repeat the export.'));
   });
   page.rounds.concat(page.decisions).forEach(function(record){if(!Number.isSafeInteger(record.sequence) || record.sequence<=cursor || record.sequence>page.next)throw new Error(_('Invalid diagnostics cursor.'));});
   bytes+=new TextEncoder().encode(JSON.stringify([page.rounds,page.decisions])).length;
   if(bytes>4*1024*1024)throw new Error(_('The diagnostics history exceeds the 4 MiB limit.'));
   output.rounds=output.rounds.concat(page.rounds);output.decisions=output.decisions.concat(page.decisions);
   if(!page.more)return output;
   if(page.next===cursor)throw new Error(_('The diagnostics download stalled; repeat the export.'));
   cursor=page.next;
  }
  throw new Error(_('Too many diagnostics pages.'));
 },
 write:async function(request) {return reply(await writeRPC(bounded(request,'write')));},
 error:function(error) {ui.addNotification(null,E('p',{},[String(error.message || error)]),'error');},
 notify:function(text) {ui.addNotification(null,E('p',{},[text]),'info');},
 action:function(label,request,after,failed,aria) {
  return E('button',{class:'cbi-button cbi-button-action','aria-label':aria || null,disabled:L.hasViewPermission()?null:true,click:async function(ev) {
   var button=ev.currentTarget;button.disabled=true;
   try {var value=typeof request==='function'?await request():request;var data=await this.write(value);if(after) await after(data);ui.addNotification(null,E('p',{},[data && data.activation_state==='pending'?_('Activation is waiting for the VPN to start. Check the status and LAN/WAN before confirming the rollback.'):data && data.pending?_('The test has started. Wait for the result and for the connection to be restored.'):_('Changes accepted.')]),'info');}
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
  if(selection.mode==='transport')return _('Protocol only · %s').format(this.familyLabel(selection.family));
  if(selection.mode==='connection'){var item=(connections || []).find(function(c){return c.id===selection.id;});return _('Specific connection · %s').format(item?item.name:_('connection missing'));}
  return _('Auto · configured fallback order');
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
  poll.add(async function(){try{var d=await self.read({operation:'connection-list'});if(page.status)page.status(d);if(fingerprint(d)===signature){page.state.generation=d.generation;}else{stale.replaceChildren(E('span',{class:'flr-notice'},_('Settings changed. Refresh them before saving.')));}}catch(e){self.error(e);}},5);
  return E('div',{class:'flr-page'},[self.style(),E('div',{class:'flr-toolbar'},[E('button',{class:'cbi-button',click:async function(){try{await page.refresh();}catch(e){self.error(e);}}},_('Refresh settings')),stale]),body]);
 },
 field:function(label,input) {var id=null;if(input && ['INPUT','SELECT','TEXTAREA'].includes(input.tagName)){id='flr-field-'+(++fieldSequence);input.id=id;}return E('div',{class:'cbi-value'},[E('label',{class:'cbi-value-title',for:id},label),E('div',{class:'cbi-value-field'},input)]);},
 fileText:async function(input,max) {
  var file=input.files && input.files[0];if(!file)throw new Error(_('Choose a file.'));
  if(file.size>max)throw new Error(_('The file exceeds the allowed size.'));
  return await file.text();
 },
 // Routing policy API (docs/ROUTER-API.md): arguments travel in "routing".
 routing:function(operation,args,write) {var request={operation:operation};if(args)request.routing=args;return write?this.write(request):this.read(request);},
 sha256:sha256hex,
 bytesToBase64:bytesToBase64,
 base64ToBytes:base64ToBytes,
 // One effective-configuration export, fetched in chunks and checked whole.
 exportRouting:async function(progress) {
  var page=await this.routing('routing-export',null,true),size=page && page.size,sum=page && page.sha256,parts=[],received=0;
  if(!Number.isSafeInteger(size) || size<1 || size>maxRoutingBundle || !/^[0-9a-f]{64}$/.test(sum || ''))throw new Error(_('FLR returned no valid reply. Check the service and retry.'));
  for(var n=0;n<=maxRoutingBundle/1024;n++) {
   if(page.offset!==received || page.size!==size || page.sha256!==sum)throw new Error(_('The routing configuration changed during the export; start it again.'));
   var bytes=base64ToBytes(page.data);
   parts.push(bytes);received+=bytes.length;if(progress)progress(received,size);
   if(!page.more)break;
   if(page.next!==received || !bytes.length)throw new Error(_('The routing configuration changed during the export; start it again.'));
   page=await this.routing('routing-export',{offset:received,sha256:sum},true);
  }
  if(received!==size)throw new Error(_('The routing configuration changed during the export; start it again.'));
  var all=new Uint8Array(size),at=0;parts.forEach(function(p){all.set(p,at);at+=p.length;});
  if(sha256hex(all)!==sum)throw new Error(_('The export checksum does not match; start it again.'));
  return {bytes:all,filename:/^[A-Za-z0-9_.-]{1,100}$/.test(page.filename || '')?page.filename:'flr-routing.json',source:page.source};
 },
 // Chunked import: begin with size and SHA-256, ordered chunks, commit.
 importRouting:async function(bytes,progress) {
  if(!bytes || !bytes.length || bytes.length>maxRoutingBundle)throw new Error(_('The file is empty or larger than 16 MiB.'));
  var begin=await this.routing('routing-import-begin',{size:bytes.length,sha256:sha256hex(bytes)},true),id=begin && begin.staging_id,chunk=begin && begin.chunk_bytes;
  if(!/^[0-9a-f]{16}$/.test(id || '') || !Number.isSafeInteger(chunk) || chunk<1)throw new Error(_('FLR returned no valid reply. Check the service and retry.'));
  try {
   for(var offset=0;offset<bytes.length;offset+=chunk) {
    await this.routing('routing-import-chunk',{staging_id:id,offset:offset,data:bytesToBase64(bytes.subarray(offset,offset+chunk))},true);
    if(progress)progress(Math.min(offset+chunk,bytes.length),bytes.length);
   }
   return await this.routing('routing-import-commit',{staging_id:id},true);
  } catch(e) {
   try{await this.routing('routing-import-abort',{staging_id:id},true);}catch(ignored){}
   throw e;
  }
 },
 // What a routing change did to the running router, as one line of text.
 applyText:function(apply) {
  if(!apply || typeof apply!=='object')return '';
  if(apply.applied)return _('Applied to new connections; existing connections keep their route.');
  return _('Saved, not applied yet: %s').format(String(apply.pending || ''));
 },
 handleSave:null,handleSaveApply:null,handleReset:null
});
