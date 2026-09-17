/* Sedra ERP service worker.
   Network-first for the app document (so a new deploy shows up immediately on next load),
   stale-while-revalidate for other same-origin GET assets. Never touches POST /db.
   Bump CACHE on every meaningful change so old caches are purged on activate. */
const CACHE = 'sedra-v96';

self.addEventListener('install', function(e){
  self.skipWaiting();
});

self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    try{
      const keys = await caches.keys();
      await Promise.all(keys.filter(function(k){ return k !== CACHE; }).map(function(k){ return caches.delete(k); }));
    }catch(err){}
    try{ await self.clients.claim(); }catch(err){}
  })());
});

self.addEventListener('fetch', function(e){
  const req = e.request;
  if(req.method !== 'GET') return;                 // let POST /db etc. go straight to network
  let url;
  try{ url = new URL(req.url); }catch(err){ return; }
  if(url.origin !== self.location.origin) return;  // don't touch cross-origin
  if(url.pathname === '/db') return;

  const isDoc = req.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html';

  if(isDoc){
    // NETWORK-FIRST: always try the network so new deploys appear at once; fall back to cache offline.
    e.respondWith((async function(){
      try{
        const fresh = await fetch(req);
        try{ const c = await caches.open(CACHE); c.put(req, fresh.clone()); }catch(err){}
        return fresh;
      }catch(err){
        return (await caches.match(req)) || (await caches.match('/index.html')) || (await caches.match('/')) || Response.error();
      }
    })());
    return;
  }

  // STATIC ASSETS: stale-while-revalidate.
  e.respondWith((async function(){
    const cached = await caches.match(req);
    const fetchP = fetch(req).then(function(res){
      try{ if(res && res.status === 200 && res.type === 'basic'){ caches.open(CACHE).then(function(c){ c.put(req, res.clone()); }); } }catch(err){}
      return res;
    }).catch(function(){ return null; });
    return cached || (await fetchP) || Response.error();
  })());
});
