package main

const notifyWidgetHTML = `
<style>
.gl-notify{position:fixed !important;top:18px;right:18px;bottom:auto;left:auto;z-index:10050;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:none}
.gl-notify-btn{width:46px;height:46px;border:none;border-radius:50%;background:#111;color:#fff;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.25);position:relative}
.gl-notify-btn svg{width:22px;height:22px;display:block;margin:0 auto}
.gl-notify-badge{position:absolute;top:-4px;right:-4px;min-width:18px;height:18px;padding:0 5px;border-radius:999px;background:#dc2626;color:#fff;font-size:11px;line-height:18px;font-weight:700}
.gl-notify-panel{display:none;position:absolute;right:0;top:54px;bottom:auto;width:min(340px,calc(100vw - 36px));max-height:min(420px,calc(100vh - 80px));background:#fff;color:#222;border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.22);overflow:hidden}
.gl-notify-panel.open{display:flex;flex-direction:column}
.gl-notify-head{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;border-bottom:1px solid #eee;font-weight:600}
.gl-notify-head button{border:none;background:none;color:#2563eb;cursor:pointer;font-size:12px}
.gl-notify-list{overflow:auto;max-height:360px}
.gl-notify-item{display:block;padding:12px 14px;text-decoration:none;color:inherit;border-bottom:1px solid #f3f3f3}
.gl-notify-item.unread{background:#f5f9ff}
.gl-notify-item:hover{background:#f7f7f7}
.gl-notify-title{font-size:13px;font-weight:600;margin-bottom:4px}
.gl-notify-body{font-size:12px;color:#666;line-height:1.5;white-space:pre-wrap;word-break:break-word}
.gl-notify-empty{padding:28px 16px;text-align:center;color:#999;font-size:13px}
@media (max-width:1279px){
.gl-notify{top:auto !important;right:16px !important;bottom:calc(18px + env(safe-area-inset-bottom,0px)) !important}
.gl-notify-panel{top:auto !important;bottom:54px !important}
.gl-notify.with-fab{bottom:calc(74px + env(safe-area-inset-bottom,0px)) !important}
}
</style>
<div class="gl-notify" id="glNotify">
  <div class="gl-notify-panel" id="glNotifyPanel">
    <div class="gl-notify-head">通知 <button type="button" id="glNotifyReadAll">全部已读</button></div>
    <div class="gl-notify-list" id="glNotifyList"></div>
  </div>
  <button type="button" class="gl-notify-btn" id="glNotifyBtn" aria-label="通知">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
    <span class="gl-notify-badge" id="glNotifyBadge" style="display:none">0</span>
  </button>
</div>
<script>
(function(){
  var root=document.getElementById('glNotify');
  if(!root) return;
  document.documentElement.appendChild(root);
  var btn=document.getElementById('glNotifyBtn');
  var panel=document.getElementById('glNotifyPanel');
  var list=document.getElementById('glNotifyList');
  var badge=document.getElementById('glNotifyBadge');
  var items=[];
  function esc(s){var d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}
  function setBadge(n){
    if(n>0){badge.style.display='inline-block';badge.textContent=n>99?'99+':String(n);}
    else {badge.style.display='none';}
  }
  function render(){
    if(!items.length){list.innerHTML='<div class="gl-notify-empty">暂无通知</div>';return;}
    list.innerHTML=items.map(function(it){
      return '<a class="gl-notify-item'+(it.read?'':' unread')+'" href="'+esc(it.link||'#')+'" data-id="'+esc(it.id)+'">'+
        '<div class="gl-notify-title">'+esc(it.title)+'</div>'+
        '<div class="gl-notify-body">'+esc(it.body||'')+'</div></a>';
    }).join('');
    list.querySelectorAll('a[data-id]').forEach(function(a){
      a.addEventListener('click',function(){ fetch('/api/notifications/read',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:a.getAttribute('data-id')})}); });
    });
  }
  function load(){
    fetch('/api/notifications',{credentials:'same-origin'}).then(function(res){
      if(res.status===401){root.style.display='none';return;}
      if(!res.ok) return;
      return res.json();
    }).then(function(data){
      if(!data) return;
      root.style.display='block';
      items=data.items||[];
      setBadge(data.unread||0);
      render();
    }).catch(function(){});
  }
  function syncFab(){root.classList.toggle('with-fab',!!document.querySelector('.toc-fab'));}
  if('MutationObserver' in window){new MutationObserver(syncFab).observe(document.body,{childList:true});}
  syncFab();
  btn.addEventListener('click',function(e){e.stopPropagation();panel.classList.toggle('open');});
  document.addEventListener('click',function(e){if(!root.contains(e.target)) panel.classList.remove('open');});
  document.getElementById('glNotifyReadAll').addEventListener('click',function(){
    fetch('/api/notifications/read',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({all:true})})
      .then(function(){load();});
  });
  load();
})();
</script>
`