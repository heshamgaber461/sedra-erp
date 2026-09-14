// Sedra system — Cloudflare Pages (advanced mode) worker.
// DB proxy at POST /db + SERVER-SIDE ACCESS CONTROL.
//
// ── STAGE 2: worker is the ONLY door to the database ───────────────────────────
// The worker authenticates to Firebase with a SERVICE ACCOUNT (admin) token, so
// once the Firebase rules are locked to deny direct client access, the browser can
// no longer reach the DB by bypassing this worker with its own ID token. The user's
// ID token is still sent by the client (as p.token) and is used ONLY to identify
// the caller so this worker can authorize each request by role/department and redact
// sensitive data. Firebase access itself is done with the service-account token.
//
// SAFE FALLBACK (important): if the SA_KEY environment variable is NOT set, or the
// service-account token cannot be minted, the worker falls back to forwarding the
// user's ID token exactly like the previous version. So deploying this file changes
// NOTHING until you (a) add the SA_KEY env var and (b) flip the Firebase rules to
// deny-client. See DEPLOY-STAGE2.txt for the exact, reversible cutover order.
//
// Design note: the app loads the WHOLE DB (large, incl. product images) in one bulk
// read. To stay well under Cloudflare's CPU limits we NEVER parse that bulk blob — it
// passes straight through. Enforcement applies to WRITES (small bodies) and to
// SENSITIVE single-collection reads (small).
//
// KILL SWITCH: set ENFORCE=false to revert to a plain pass-through proxy instantly.

const RTDB = 'https://sedra-crm-default-rtdb.firebaseio.com';
const SUPER_ADMIN = 'heshamgaber461@gmail.com';
const ENFORCE = true;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json'
};

const ROLE_RANK = { 'Viewer':1,'Member':2,'Team Leader':3,'Manager':4,'Director':5,'CEO':6,'CO Founder':7,'Super Admin':8 };

const COMP_FIELDS = ['salary','allowances','iban','socialInsNo','medicalIns','birthDate',
  'docLabourExp','docPassportExp','docPassportNo','docResidenceExp','docUaeIdExp','leaveEntitlement','loanBalance'];
const HR_OWNED = { payslips:1, loans:1, overtimes:1, expclaims:1, warnings:1, appraisals:1, eosb:1, salaryadvance:1 };
const HR_ADMIN = { paySchedule:1, onboarding:1 };
const FIN_COLLS = { journal:1, accounts:1, bills:1, budgets:1, capitals:1, creditnotes:1,
  debitnotes:1, pettycash:1, taxcodes:1, recurring:1, bonds:1, retentions:1 };
const ADMIN_READ = { audit:1, staffEmails:1 };
const ADMIN_WRITE = { rules:1, staffEmails:1, blueprint:1 };
const FX_KEYS = { fxRates:1, fxDate:1, fxManual:1, fxRate:1 };
const HR_WRITE = { payslips:1, loans:1, paySchedule:1, warnings:1, appraisals:1, onboarding:1, eosb:1, salaryadvance:1 };
const EMP_PRIV = ['salary','allowances','role','dept','branches','accessModules','scope','active',
  'iban','socialInsNo','medicalIns','manager','code','title','leaveEntitlement','email'];
const SALES_COLLS = { leads:1, customers:1, contacts:1, quotes:1, activities:1, variations:1, rfqs:1 };

// ───────────────────────── service-account credential layer ─────────────────────
// The DB credential is either the service-account OAuth token (preferred, locks the
// worker as the only door) or, as a fallback, the user's ID token (current behavior).
let SA_KEY_PARSED; // undefined = not tried yet, false = none/invalid, object = parsed key
let SA_TOKEN = null, SA_TOKEN_EXP = 0;

function getSAKey(env){
  if (SA_KEY_PARSED !== undefined) return SA_KEY_PARSED;
  const raw = env && env.SA_KEY;
  if (!raw){ SA_KEY_PARSED = false; return false; }
  try { const k = JSON.parse(raw); SA_KEY_PARSED = (k && k.private_key && k.client_email) ? k : false; }
  catch(e){ SA_KEY_PARSED = false; }
  return SA_KEY_PARSED;
}

function pemToBuf(pem){
  const b = String(pem).replace(/-----BEGIN [^-]+-----/,'').replace(/-----END [^-]+-----/,'').replace(/\s+/g,'');
  const bin = atob(b); const u = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i);
  return u.buffer;
}
function b64url(input){
  let s;
  if (typeof input === 'string') s = btoa(unescape(encodeURIComponent(input)));
  else { let bin=''; const u=new Uint8Array(input); for(let i=0;i<u.length;i++) bin+=String.fromCharCode(u[i]); s=btoa(bin); }
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function getSAToken(env){
  if (SA_TOKEN && Date.now() < SA_TOKEN_EXP) return SA_TOKEN;
  const key = getSAKey(env);
  if (!key) return null;
  try {
    const now = Math.floor(Date.now()/1000);
    const aud = key.token_uri || 'https://oauth2.googleapis.com/token';
    const header = { alg:'RS256', typ:'JWT' };
    const claim  = { iss:key.client_email,
      scope:'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',
      aud, iat:now, exp:now+3600 };
    const unsigned = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(claim));
    const pk = await crypto.subtle.importKey('pkcs8', pemToBuf(key.private_key),
      { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pk, new TextEncoder().encode(unsigned));
    const jwt = unsigned + '.' + b64url(sig);
    const res = await fetch(aud, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion='+encodeURIComponent(jwt) });
    if (!res.ok) return null;
    const j = await res.json();
    if (!j || !j.access_token) return null;
    SA_TOKEN = j.access_token;
    SA_TOKEN_EXP = Date.now() + (((j.expires_in||3600) - 120) * 1000);
    return SA_TOKEN;
  } catch(e){ return null; }
}
// Returns the query param + value to authenticate the RTDB REST call.
async function dbCred(env, userToken){
  const sa = await getSAToken(env);
  return sa ? { param:'access_token', val:sa } : { param:'auth', val:userToken };
}

let EMP_CACHE = null, EMP_TS = 0;
async function getEmployees(cred){
  if (EMP_CACHE && (Date.now() - EMP_TS) < 45000) return EMP_CACHE;
  try{
    const r = await fetch(RTDB + '/employees.json?' + cred.param + '=' + encodeURIComponent(cred.val));
    if(!r.ok) return EMP_CACHE || {};
    EMP_CACHE = (await r.json()) || {}; EMP_TS = Date.now();
    return EMP_CACHE;
  }catch(e){ return EMP_CACHE || {}; }
}

function b64urlToStr(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; return decodeURIComponent(escape(atob(s))); }
function b64urlToU8(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; const bin=atob(s); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); return u; }

// ───────────────────────── Firebase ID-token VERIFICATION ───────────────────────
// SECURITY: we must not trust the email inside a token we haven't verified. A Firebase
// ID token is a JWT signed (RS256) with Google's rotating public keys. We verify the
// signature against those keys and check aud / iss / exp before trusting any claim.
const PROJECT_ID = 'sedra-crm';
const JWK_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let JWK_CACHE = null, JWK_EXP = 0;
async function getGoogleJWKs(){
  if (JWK_CACHE && Date.now() < JWK_EXP) return JWK_CACHE;
  try{
    const r = await fetch(JWK_URL);
    if (!r.ok) return JWK_CACHE; // keep last-good cache if refresh fails
    const j = await r.json();
    const map = {}; (j.keys||[]).forEach(function(k){ if (k && k.kid) map[k.kid] = k; });
    if (Object.keys(map).length){ JWK_CACHE = map; JWK_EXP = Date.now() + 3600*1000; }
    return JWK_CACHE;
  }catch(e){ return JWK_CACHE; }
}
// Returns the verified, lower-cased email, or '' when the token is missing/invalid/expired.
async function verifyIdToken(token){
  try{
    if (!token) return '';
    const parts = token.split('.'); if (parts.length !== 3) return '';
    const header = JSON.parse(b64urlToStr(parts[0]));
    if (header.alg !== 'RS256' || !header.kid) return '';
    const jwks = await getGoogleJWKs(); if (!jwks) return '';
    const jwk = jwks[header.kid]; if (!jwk) return '';
    const key = await crypto.subtle.importKey('jwk',
      { kty:jwk.kty, n:jwk.n, e:jwk.e, alg:'RS256', ext:true },
      { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
    const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToU8(parts[2]), data);
    if (!ok) return '';
    const p = JSON.parse(b64urlToStr(parts[1]));
    const now = Math.floor(Date.now()/1000), skew = 300;
    if (p.aud !== PROJECT_ID) return '';
    if (p.iss !== 'https://securetoken.google.com/' + PROJECT_ID) return '';
    if (!p.sub) return '';
    if (typeof p.exp !== 'number' || p.exp < now - skew) return '';
    if (typeof p.iat === 'number' && p.iat > now + skew) return '';
    return (p.email || '').toLowerCase();
  }catch(e){ return ''; }
}
// (kept for reference; no longer used for authorization — verifyIdToken replaces it)
function tokenEmail(token){
  try{ const p=token.split('.'); if(p.length<2) return ''; return (JSON.parse(b64urlToStr(p[1])).email||'').toLowerCase(); }
  catch(e){ return ''; }
}

function ctxFor(email, employees){
  email=(email||'').toLowerCase();
  if(email===SUPER_ADMIN) return { email, role:'Super Admin', dept:'Management', scope:'all', rank:8, id:null, name:'', comp:true, fin:true, audit:true, admin:true, known:true };
  let rec=null, id=null;
  for(const k in employees){ const e=employees[k]; if(e && (e.email||'').toLowerCase()===email){ rec=e; id=k; break; } }
  const role=(rec&&rec.role)||'Member', dept=(rec&&rec.dept)||'', rank=ROLE_RANK[role]||2, admin=role==='Super Admin';
  return { email, role, dept, scope:(rec&&rec.scope)||'own', rank, id, name:(rec&&rec.name)||'',
    comp: admin||dept==='HR'||dept==='Management'||rank>=ROLE_RANK['Director'],
    fin:  admin||dept==='Finance'||dept==='Accounting'||dept==='Management'||rank>=ROLE_RANK['Director'],
    audit: admin, admin, known:!!rec };
}

function recordIsMine(r, ctx){
  if(!r || typeof r!=='object') return false;
  const em=(r.email||r.ownerEmail||'').toLowerCase();
  if(em && em===ctx.email) return true;
  if(ctx.name && (r.employee===ctx.name||r.name===ctx.name||r.owner===ctx.name||r.emp===ctx.name)) return true;
  if(ctx.id && (r.empId===ctx.id||r.employeeId===ctx.id||r.emp===ctx.id)) return true;
  return false;
}

function redactColl(coll, data, ctx){
  if(!data || typeof data!=='object') return data;
  if(coll==='employees'){
    if(ctx.comp) return data;
    const out={};
    for(const k in data){ const e=data[k];
      if(!e||typeof e!=='object'){ out[k]=e; continue; }
      if(ctx.id && k===ctx.id){ out[k]=e; continue; }
      const c={}; for(const f in e){ if(COMP_FIELDS.indexOf(f)<0) c[f]=e[f]; }
      out[k]=c;
    }
    return out;
  }
  if(ADMIN_READ[coll]) return ctx.admin ? data : {};
  if(FIN_COLLS[coll])  return ctx.fin ? data : {};
  if(HR_ADMIN[coll])   return ctx.comp ? data : {};
  if(HR_OWNED[coll]){
    if(ctx.comp) return data;
    const out={}; for(const k in data){ if(recordIsMine(data[k],ctx)) out[k]=data[k]; } return out;
  }
  return data;
}

function segsOf(path){
  let p=String(path||''); const q=p.indexOf('?'); if(q>=0) p=p.slice(0,q);
  p=p.replace(/\.json$/i,'').replace(/^\/+/,'').replace(/\/+$/,'');
  return p? p.split('/') : [];
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/db') return env.ASSETS.fetch(request);
    if (request.method === 'OPTIONS') return new Response('', { headers: CORS });
    if (request.method !== 'POST') return new Response(JSON.stringify({ error: 'POST only' }), { status: 405, headers: CORS });

    let p; try { p = await request.json(); } catch(e){ return new Response(JSON.stringify({error:'bad json'}),{status:400,headers:CORS}); }
    const method = (p.method || 'GET').toUpperCase();
    let path = p.path || '/.json'; if (path[0] !== '/') path = '/' + path;
    const token = p.token || '';

    // Resolve the DB credential once: service-account token if available, else the
    // caller's ID token (fallback = pre-Stage-2 behavior).
    const cred = await dbCred(env, token);

    const forward = async (body) => {
      const rurl = RTDB + path + (path.indexOf('?')>=0?'&':'?') + cred.param + '=' + encodeURIComponent(cred.val);
      const opts = { method };
      if (body !== undefined && method!=='GET' && method!=='DELETE'){ opts.headers={'Content-Type':'application/json'}; opts.body=JSON.stringify(body); }
      return fetch(rurl, opts);
    };
    const pass = async (body) => { const r=await forward(body); const t=await r.text(); return new Response(t||'null',{status:r.status,headers:CORS}); };
    const deny = (m) => new Response(JSON.stringify({error:'forbidden: '+(m||'not allowed')}),{status:403,headers:CORS});

    // Kill switch: plain pass-through proxy (emergency only).
    if (!ENFORCE) { try { return await pass(p.body); } catch(e){ return new Response(JSON.stringify({error:String(e&&e.message||e)}),{status:500,headers:CORS}); } }

    // SECURITY: authenticate EVERY request. The email is taken from a CRYPTOGRAPHICALLY
    // VERIFIED Firebase ID token — never from an unverified/decoded token, and never
    // defaulting to service-account access when the token is missing. No valid token → denied.
    const email = await verifyIdToken(token);
    if (!email) return new Response(JSON.stringify({error:'forbidden: authentication required'}),{status:401,headers:CORS});

    const segs = segsOf(path);
    const coll = segs[0] || '';
    const id   = segs[1];

    try {
      // ===================== READS =====================
      if (method === 'GET') {
        // bulk read or deep leaf -> pass straight through (never parse the big blob)
        if (segs.length !== 1) return await pass();
        const sensitive = (coll==='employees')||HR_OWNED[coll]||HR_ADMIN[coll]||FIN_COLLS[coll]||ADMIN_READ[coll];
        if (!sensitive) return await pass();

        const ctx = ctxFor(email, await getEmployees(cred));
        // fully denied -> return empty without even fetching
        if (ADMIN_READ[coll] && !ctx.admin) return new Response('{}',{status:200,headers:CORS});
        if (FIN_COLLS[coll]  && !ctx.fin)   return new Response('{}',{status:200,headers:CORS});
        if (HR_ADMIN[coll]   && !ctx.comp)  return new Response('{}',{status:200,headers:CORS});
        // fully allowed -> pass through untouched
        const fullyAllowed = (coll==='employees'&&ctx.comp)||(HR_OWNED[coll]&&ctx.comp)||(HR_ADMIN[coll]&&ctx.comp)||(FIN_COLLS[coll]&&ctx.fin)||(ADMIN_READ[coll]&&ctx.admin);
        if (fullyAllowed) return await pass();
        // needs field-strip / owner-filter (small data)
        const r=await forward(); const text=await r.text();
        if(!r.ok) return new Response(text||'null',{status:r.status,headers:CORS});
        let data; try{ data=JSON.parse(text); }catch(e){ return new Response(text||'null',{status:r.status,headers:CORS}); }
        return new Response(JSON.stringify(redactColl(coll,data,ctx)),{status:200,headers:CORS});
      }

      // ===================== WRITES =====================
      const ctx = ctxFor(email, await getEmployees(cred));

      if (segs.length === 0) return deny('root write');
      if (!id) { if (method !== 'POST' && !ctx.admin) return deny('bulk write requires admin'); }

      if (coll === 'employees') {
        if (ctx.admin || ctx.dept === 'HR') { /* allow */ }
        else if (id && id === ctx.id && method === 'PATCH') {
          const b=p.body||{}, nb={}; for(const f in b){ if(EMP_PRIV.indexOf(f)<0) nb[f]=b[f]; }
          return await pass(nb);
        } else return deny('employees write');
      }
      else if (coll === 'meta') {
        // meta/settings holds access config (hiddenModules, importVisibility, blueprint) -> admin only,
        // EXCEPT the FX-rate cache which any session refreshes.
        const fxOnly = method==='PATCH' && p.body && typeof p.body==='object' && Object.keys(p.body).length>0 && Object.keys(p.body).every(k=>FX_KEYS[k]);
        if (!fxOnly && !ctx.admin) return deny('meta is admin-only');
      }
      else if (ADMIN_WRITE[coll]) { if (!ctx.admin) return deny(coll+' is admin-only'); }
      else if (HR_WRITE[coll])    { if (!ctx.comp) return deny(coll+' is HR/payroll-only'); }
      else if (FIN_COLLS[coll])   { if (!ctx.fin) return deny(coll+' is finance-only'); }
      else if (coll === 'audit')  { if (method!=='POST' && !ctx.admin) return deny('audit is append-only'); }
      else if (coll === 'quotes' && method === 'POST' && !id && ctx.dept === 'Sales' && ctx.rank < ROLE_RANK['Team Leader'] && !ctx.admin && !(p.body && p.body.isRFQ === true)) {
        // Sales reps may REQUEST from the Technical Office (isRFQ) but not build a quote directly.
        return deny('direct quote creation is limited to Sales Team Leader/Manager — send a request to the Technical Office');
      }
      else if (SALES_COLLS[coll] && method==='DELETE' && id) {
        if (!(ctx.admin || ctx.rank>=ROLE_RANK['Manager'] || ctx.scope==='all')) {
          const rr=await fetch(RTDB+'/'+coll+'/'+id+'.json?'+cred.param+'='+encodeURIComponent(cred.val));
          const rec=rr.ok? await rr.json():null;
          if(rec && !recordIsMine(rec,ctx)) return deny('delete others\' record');
        }
      }

      return await pass(p.body);
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e && e.message || e) }), { status: 500, headers: CORS });
    }
  }
};
