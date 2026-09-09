// Sedra system — database proxy (Cloudflare Pages Function).
// Route: /db   (a file at functions/db.js maps to /db on Cloudflare Pages)
// The browser talks only to this function; Cloudflare's edge reaches the Firebase
// Realtime Database, so a network that blocks Firebase doesn't matter.
// The user's Firebase ID token is passed through so the database security rules apply.

const RTDB = 'https://sedra-crm-default-rtdb.firebaseio.com';
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json'
};

export async function onRequest(context) {
  const req = context.request;
  if (req.method === 'OPTIONS') return new Response('', { headers: cors });
  if (req.method !== 'POST') return new Response(JSON.stringify({ error: 'POST only' }), { status: 405, headers: cors });
  try {
    const p = await req.json();
    const method = (p.method || 'GET').toUpperCase();
    let path = p.path || '/.json';
    if (path[0] !== '/') path = '/' + path;
    let url = RTDB + path + (path.indexOf('?') >= 0 ? '&' : '?') + 'auth=' + encodeURIComponent(p.token || '');
    const opts = { method };
    if (p.body !== undefined && method !== 'GET' && method !== 'DELETE') {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(p.body);
    }
    const r = await fetch(url, opts);
    const text = await r.text();
    return new Response(text || 'null', { status: r.status, headers: cors });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e && e.message || e) }), { status: 500, headers: cors });
  }
}
