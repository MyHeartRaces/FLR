'use strict';
'require view';
return view.extend({
 load:function(){window.location.href=L.url('admin', 'flr', 'proxy', 'connections');},
 render:function(){return E('p',{},[E('a',{href:L.url('admin', 'flr', 'proxy', 'connections')},_('Open proxy management'))]);},
 handleSave:null,handleSaveApply:null,handleReset:null
});
