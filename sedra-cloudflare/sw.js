/* Sedra ERP service worker — network-first so updates always show; cache only as offline fallback. */
const CACHE = 'sedra-v108';
const SHELL = ['/', '/index.html', '/logo.png', '/manifest.json'];
self.addEventListener('install', function(e){
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(SHELL).catch(function(){}); }));
});

self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    try{ var ks = await caches.keys(); await Promise.all(ks.filter(function(k){ return k !== CACHE; }).map(function(k){ return caches.delete(k); })); }catch(_){}
    try{ await self.clients.claim(); }catch(_){}
  })());
});

self.addEventListener('fetch', function(e){
  var req = e.request;
  if(req.method !== 'GET') return;                 /* never touch POST /db, push, etc. */
  var url;
  try{ url = new URL(req.url); }catch(_){ return; }
  if(url.origin !== self.location.origin) return;  /* leave cross-origin (ipwho.is, Firebase…) to the network */

  var isDoc = req.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('/index.html') || url.pathname.endsWith('.html');
  if(isDoc){
    /* network-first: always try to fetch the newest HTML; fall back to cache offline */
    e.respondWith(
      fetch(req).then(function(res){ try{ var copy = res.clone(); caches.open(CACHE).then(function(c){ c.put(req, copy); }).catch(function(){}); }catch(_){} return res; })
        .catch(function(){ return caches.match(req).then(function(m){ return m || caches.match('/index.html'); }); })
    );
    return;
  }
  /* static assets: cache-first, then network (and cache it) */
  e.respondWith(
    caches.match(req).then(function(m){
      return m || fetch(req).then(function(res){ try{ if(res && res.status === 200 && res.type === 'basic'){ var copy = res.clone(); caches.open(CACHE).then(function(c){ c.put(req, copy); }).catch(function(){}); } }catch(_){} return res; }).catch(function(){ return m; });
    })
  );
});

/* Push notifications (payload: {title, body, url}) */
self.addEventListener('push', function(e){
  var d = {};
  try{ d = e.data ? e.data.json() : {}; }catch(_){ try{ d = { body: (e.data && e.data.text()) || '' }; }catch(__){ d = {}; } }
  var title = d.title || 'Sedra Electric';
  var opts = { body: d.body || '', icon: '/logo.png', badge: '/logo.png', data: { url: d.url || '/' }, dir: 'auto' };
  e.waitUntil(self.registration.showNotification(title, opts));
});

self.addEventListener('notificationclick', function(e){
  e.notification.close();
  var url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(cl){
    for(var i = 0; i < cl.length; i++){ if('focus' in cl[i]) return cl[i].focus(); }
    if(self.clients.openWindow) return self.clients.openWindow(url);
  }));
});
