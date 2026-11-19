'use strict';
'require view';
// The Proxy page is split into tabs under admin/flr/proxy/*. This view is not
// in the menu; it keeps old links working and the firmware file list valid.
return view.extend({
 load:function(){window.location.href=L.url('admin', 'flr', 'proxy', 'status');},
 render:function(){return E('p',{},[E('a',{href:L.url('admin', 'flr', 'proxy', 'status')},_('Open proxy status'))]);},
 handleSave:null,handleSaveApply:null,handleReset:null
});
