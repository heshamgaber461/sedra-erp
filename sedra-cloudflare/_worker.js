// Sedra system — Cloudflare Pages (advanced mode) worker.
// Handles the database proxy at POST /db, and serves all other paths (the app) as static assets.
// The browser talks only to this worker; Cloudflare's edge reaches the Firebase Realtime
// Database, so a network that blocks Firebase doesn't matter. The user's Firebase ID token
// is passed through so the database security rules apply.

const RTDB = 'https://sedra-crm-default-rtdb.firebaseio.com';
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json'
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/db') {
      if (request.method === 'OPTIONS') return new Response('', { headers: CORS });
      if (request.method !== 'POST') return new Response(JSON.stringify({ error: 'POST only' }), { status: 405, headers: CORS });
      try {
        const p = await request.json();
        const method = (p.method || 'GET').toUpperCase();
        let path = p.path || '/.json';
        if (path[0] !== '/') path = '/' + path;
        const rurl = RTDB + path + (path.indexOf('?') >= 0 ? '&' : '?') + 'auth=' + encodeURIComponent(p.token || '');
        const opts = { method };
        if (p.body !== undefined && method !== 'GET' && method !== 'DELETE') {
          opts.headers = { 'Content-Type': 'application/json' };
          opts.body = JSON.stringify(p.body);
        }
        const r = await fetch(rurl, opts);
        const text = await r.text();
        return new Response(text || 'null', { status: r.status, headers: CORS });
      } catch (e) {
        return new Response(JSON.stringify({ error: String(e && e.message || e) }), { status: 500, headers: CORS });
      }
    }

    // everything else → serve the static app
    return env.ASSETS.fetch(request);
  }
};
