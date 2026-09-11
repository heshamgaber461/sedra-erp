// Sedra system — Cloudflare Pages (advanced mode) worker.
// DB proxy at POST /db + SERVER-SIDE ACCESS CONTROL.
// The browser talks only to this worker; the user's Firebase ID token is the DB
// credential AND identifies the caller so this worker can authorize each request
// by role/department and redact sensitive data.
//
// Design note: the app currently loads the WHOLE DB (large, incl. product images)
// in one bulk read. To stay well under Cloudflare's CPU limits we NEVER parse that
// bulk blob — it passes straight through. Enforcement applies to WRITES (small
// bodies) and to SENSITIVE single-collection reads (small). Once the client fetches
// sensitive collections individually (next stage), their redaction here takes effect.
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

let EMP_CACHE = null, EMP_TS = 0;
async function getEmployees(token){
  if (EMP_CACHE && (Date.now() - EMP_TS) < 45000) return EMP_CACHE;
  try{
    const r = await fetch(RTDB + '/employees.json?auth=' + encodeURIComponent(token));
    if(!r.ok) return EMP_CACHE || {};
    EMP_CACHE = (await r.json()) || {}; EMP_TS = Date.now();
    return EMP_CACHE;
  }catch(e){ return EMP_CACHE || {}; }
}

function b64urlToStr(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; return decodeURIComponent(escape(atob(s))); }
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

    const forward = async (body) => {
      const rurl = RTDB + path + (path.indexOf('?')>=0?'&':'?') + 'auth=' + encodeURIComponent(token);
      const opts = { method };
      if (body !== undefined && method!=='GET' && method!=='DELETE'){ opts.headers={'Content-Type':'application/json'}; opts.body=JSON.stringify(body); }
      return fetch(rurl, opts);
    };
    const pass = async (body) => { const r=await forward(body); const t=await r.text(); return new Response(t||'null',{status:r.status,headers:CORS}); };
    const deny = (m) => new Response(JSON.stringify({error:'forbidden: '+(m||'not allowed')}),{status:403,headers:CORS});

    const email = tokenEmail(token);
    if (!ENFORCE || !email) { try { return await pass(p.body); } catch(e){ return new Response(JSON.stringify({error:String(e&&e.message||e)}),{status:500,headers:CORS}); } }

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

        const ctx = ctxFor(email, await getEmployees(token));
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
      const ctx = ctxFor(email, await getEmployees(token));

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
      else if (SALES_COLLS[coll] && method==='DELETE' && id) {
        if (!(ctx.admin || ctx.rank>=ROLE_RANK['Manager'] || ctx.scope==='all')) {
          const rr=await fetch(RTDB+'/'+coll+'/'+id+'.json?auth='+encodeURIComponent(token));
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
