/**
 * qubit-server v1.3.0
 * PostgreSQL-backed: users, sessions, connectors, test plans, stats
 * Email: Mailgun SMTP via nodemailer
 */
'use strict';

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');

// ─── Token Encryption (AES-256-GCM) ──────────────────────────────────────────
// Key is derived from an env secret + a per-installation salt.
// Never exposed outside server.js — frontend never sees cipher text.
function _getEncKey() {
  const secret = process.env.TOKEN_ENCRYPT_SECRET || process.env.JWT_SECRET || 'qubit-default-enc-secret-change-in-prod';
  // Derive a 32-byte key using SHA-256 over the secret + fixed salt
  return crypto.createHash('sha256').update(secret + ':qubit:connector:v1').digest();
}

function encryptToken(plaintext) {
  if (!plaintext) return null;
  const key = _getEncKey();
  const iv  = crypto.randomBytes(12);          // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag  = cipher.getAuthTag();
  // Store as: iv(hex):tag(hex):ciphertext(hex)
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function decryptToken(stored) {
  if (!stored || !stored.includes(':')) return null;
  try {
    const parts = stored.split(':');
    if (parts.length !== 3) return null;
    const iv  = Buffer.from(parts[0], 'hex');
    const tag = Buffer.from(parts[1], 'hex');
    const enc = Buffer.from(parts[2], 'hex');
    const key  = _getEncKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc) + decipher.final('utf8');
  } catch (e) {
    console.warn('[enc] decryptToken failed:', e.message);
    return null;
  }
}
// ─────────────────────────────────────────────────────────────────────────────
const path       = require('path');
const https      = require('https');
const nodemailer = require('nodemailer');
const { Pool }   = require('pg');

require('dotenv').config();

const CONFIG = {
  port:             process.env.PORT || 4000,
  jwtSecret:        process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  allowedDomains:   (process.env.ALLOWED_DOMAINS || 'clearlyrated.com,thoughtminds.io').split(','),
  corsOrigin:       process.env.CORS_ORIGIN || '*',
  googleClientId:   process.env.GOOGLE_CLIENT_ID || '',
  frontendUrl:      (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, ''),
  smtp: {
    host: 'smtp.mailgun.org',
    port: 587,
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'Qubit QA Platform <noreply@qubit.io>',
  },
  inviteExpiryMs:   7 * 24 * 60 * 60 * 1000,
  regTokenExpiryMs: 24 * 60 * 60 * 1000,
  sessionExpiryMs:  7 * 24 * 60 * 60 * 1000,
  mcp: {
    timeout:         parseInt(process.env.MCP_TIMEOUT_MS       || '300000', 10),
    maxRetries:      parseInt(process.env.MCP_MAX_RETRIES      || '5',      10),
    parallelWorkers: parseInt(process.env.MCP_PARALLEL_WORKERS || '3',      10),
  }
};

// PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

async function db(sql, params = []) {
  const client = await pool.connect();
  try { return await client.query(sql, params); }
  finally { client.release(); }
}

async function initDB() {
  await db(`CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await db(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE, created_at BIGINT NOT NULL)`);
  await db(`CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email)`);
  await db(`CREATE TABLE IF NOT EXISTS connectors (email TEXT PRIMARY KEY, data JSONB NOT NULL DEFAULT '{}')`);
  await db(`CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY, email TEXT NOT NULL, invited_by TEXT, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL)`);
  await db(`CREATE INDEX IF NOT EXISTS idx_invites_email ON invites(email)`);
  await db(`CREATE TABLE IF NOT EXISTS test_plans (plan_id TEXT PRIMARY KEY, email TEXT NOT NULL, project TEXT NOT NULL, release TEXT, epics JSONB NOT NULL DEFAULT '[]', summary JSONB, generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await db(`CREATE INDEX IF NOT EXISTS idx_test_plans_email ON test_plans(email)`);
  await db(`CREATE TABLE IF NOT EXISTS stat_events (id SERIAL PRIMARY KEY, email TEXT NOT NULL, stat_type TEXT NOT NULL, recorded_date DATE NOT NULL DEFAULT CURRENT_DATE, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await db(`CREATE INDEX IF NOT EXISTS idx_stat_events_email ON stat_events(email)`);
  await db(`CREATE INDEX IF NOT EXISTS idx_stat_events_date  ON stat_events(recorded_date)`);
  await db(`CREATE TABLE IF NOT EXISTS test_cases (
    tc_id        TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    project      TEXT NOT NULL,
    release      TEXT,
    prefix       TEXT NOT NULL,
    epics        JSONB NOT NULL DEFAULT '[]',
    cases        JSONB NOT NULL DEFAULT '[]',
    totals       JSONB,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await db(`CREATE INDEX IF NOT EXISTS idx_test_cases_email ON test_cases(email)`);
  console.log('[db] Tables ready');
}

// DB helpers
async function getUser(email) {
  const r = await db('SELECT data FROM users WHERE email=$1', [email.toLowerCase()]);
  return r.rows[0] ? r.rows[0].data : null;
}
async function saveUser(user) {
  await db(`INSERT INTO users(email,data) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET data=EXCLUDED.data`, [user.email.toLowerCase(), JSON.stringify(user)]);
}
async function getSession(token) {
  const r = await db('SELECT email,created_at FROM sessions WHERE token=$1', [token]);
  if (!r.rows[0]) return null;
  return { email: r.rows[0].email, createdAt: Number(r.rows[0].created_at) };
}
async function createSession(token, email) {
  await db('INSERT INTO sessions(token,email,created_at) VALUES($1,$2,$3)', [token, email.toLowerCase(), Date.now()]);
}
async function deleteSession(token) { await db('DELETE FROM sessions WHERE token=$1', [token]); }
async function deleteUserSessions(email, exceptToken) {
  if (exceptToken) await db('DELETE FROM sessions WHERE email=$1 AND token!=$2', [email, exceptToken]);
  else await db('DELETE FROM sessions WHERE email=$1', [email]);
}
function getJiraToken(jiraData) {
  if (!jiraData) return null;
  // Support both old unencrypted (apiToken) and new encrypted (apiTokenEnc) storage
  if (jiraData.apiTokenEnc) return decryptToken(jiraData.apiTokenEnc);
  if (jiraData.apiToken)    return jiraData.apiToken;  // legacy plain-text fallback
  return null;
}


// ─── Verify saved connectors at login time ────────────────────────────────────
// Returns a status object safe to send to the client.
// NEVER returns decrypted tokens — only connection state.
// Verify all saved connectors at login time.
// Trusts stored tokens without a live ping — fast, no Jira/GitHub latency on login.
// Live validation only happens via "Test Connection" button.
async function _verifyAndUpdateConnectors(email) {
  const ALL_CONNECTORS = ['jira', 'confluence', 'github', 'figma'];
  const status = {};
  try {
    const data = await getConnectors(email);
    for (const id of ALL_CONNECTORS) {
      const conn = data[id] || {};
      if (conn.connected && (conn.apiTokenEnc || conn.apiToken)) {
        // Token saved — decrypt and return connected without a live ping
        const token = id === 'jira' ? getJiraToken(conn) : (conn.apiTokenEnc ? decryptToken(conn.apiTokenEnc) : conn.apiToken);
        if (!token) {
          // Decrypt failed — key rotation
          status[id] = { connected: false, error: 'token_decrypt_failed', method: 'tok' };
          data[id] = { ...conn, connected: false, lastCheckError: 'decrypt_failed', lastCheckedAt: new Date().toISOString() };
        } else {
          // Token present and decrypts OK — trust it
          status[id] = {
            connected:   true,
            method:      'tok',
            displayName: conn.displayName || null,
            // Connector-specific fields
            ...(id === 'jira' ? { siteUrl: conn.siteUrl, jiraEmail: conn.jiraEmail } : {}),
            ...(id === 'confluence' ? { siteUrl: conn.siteUrl } : {})
          };
        }
      } else {
        // Not connected
        status[id] = { connected: false, method: null };
      }
    }
    // Persist any decrypt-failure state changes
    if (Object.values(status).some(s => s.error === 'token_decrypt_failed')) {
      await saveConnectors(email, data);
    }
  } catch (e) {
    console.error('[connVerify]', e.message);
    ALL_CONNECTORS.forEach(id => { status[id] = { connected: false, method: null }; });
  }
  return status;
}

async function getConnectors(email) {
  const r = await db('SELECT data FROM connectors WHERE email=$1', [email.toLowerCase()]);
  return r.rows[0] ? r.rows[0].data : {};
}
async function saveConnectors(email, data) {
  await db(`INSERT INTO connectors(email,data) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET data=EXCLUDED.data`, [email.toLowerCase(), JSON.stringify(data)]);
}
async function getInvite(token) {
  const r = await db('SELECT * FROM invites WHERE token=$1', [token]);
  if (!r.rows[0]) return null;
  return { email: r.rows[0].email, invitedBy: r.rows[0].invited_by, createdAt: Number(r.rows[0].created_at), expiresAt: Number(r.rows[0].expires_at) };
}
async function saveInvite(token, email, invitedBy, expiresAt) {
  await db('INSERT INTO invites(token,email,invited_by,created_at,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(token) DO NOTHING', [token, email.toLowerCase(), invitedBy || null, Date.now(), expiresAt]);
}
async function deleteInvite(token) { await db('DELETE FROM invites WHERE token=$1', [token]); }
async function findUnexpiredInvite(email) {
  const r = await db('SELECT token,expires_at FROM invites WHERE email=$1 AND expires_at > $2 LIMIT 1', [email.toLowerCase(), Date.now()]);
  return r.rows[0] ? { token: r.rows[0].token, expiresAt: Number(r.rows[0].expires_at) } : null;
}
async function savePlan(planId, email, project, release, epics, summary) {
  await db(`INSERT INTO test_plans(plan_id,email,project,release,epics,summary,generated_at) VALUES($1,$2,$3,$4,$5,$6,NOW())`,
    [planId, email.toLowerCase(), project, release || 'Unscheduled', JSON.stringify(epics), JSON.stringify(summary)]);
}
async function getPlans(email) {
  const r = await db(`SELECT plan_id,project,release,epics,generated_at, (summary->'totals') AS totals FROM test_plans WHERE email=$1 ORDER BY generated_at DESC`, [email.toLowerCase()]);
  return r.rows.map(row => ({ planId: row.plan_id, project: row.project, release: row.release, epics: row.epics, generatedAt: row.generated_at, totals: row.totals }));
}
async function getPlanSummary(planId, email) {
  const r = await db('SELECT summary FROM test_plans WHERE plan_id=$1 AND email=$2', [planId, email.toLowerCase()]);
  return r.rows[0] ? r.rows[0].summary : null;
}
async function saveTestCaseSet(tcId,email,project,release,prefix,epics,cases,totals){
  await db(`INSERT INTO test_cases(tc_id,email,project,release,prefix,epics,cases,totals,generated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW())`,
    [tcId,email.toLowerCase(),project,release||'Unscheduled',prefix,JSON.stringify(epics),JSON.stringify(cases),JSON.stringify(totals)]);
}
async function getTestCasesList(email){
  const r=await db(`SELECT tc_id,project,release,prefix,epics,generated_at,totals FROM test_cases WHERE email=$1 ORDER BY generated_at DESC`,[email.toLowerCase()]);
  return r.rows.map(row=>({tcId:row.tc_id,project:row.project,release:row.release,prefix:row.prefix,epics:row.epics,generatedAt:row.generated_at,totals:row.totals}));
}
async function getTestCaseSet(tcId,email){
  const r=await db('SELECT tc_id,project,release,prefix,epics,cases,totals,generated_at FROM test_cases WHERE tc_id=$1 AND email=$2',[tcId,email.toLowerCase()]);
  if(!r.rows[0])return null;
  const row=r.rows[0];
  return{tcId:row.tc_id,project:row.project,release:row.release,prefix:row.prefix,epics:row.epics,cases:row.cases,totals:row.totals,generatedAt:row.generated_at};
}
async function recordStatEvent(email, statType) {
  await db('INSERT INTO stat_events(email,stat_type) VALUES($1,$2)', [email.toLowerCase(), statType]);
}
async function getStatsForRange(range) {
  const rangeMap = { week: '7 days', month: '1 month', quarter: '3 months', year: '1 year' };
  const interval = rangeMap[range] || '1 month';
  const r = await db(`SELECT email, stat_type, COUNT(*)::int AS cnt, recorded_date::text FROM stat_events WHERE created_at >= NOW() - INTERVAL '${interval}' GROUP BY email, stat_type, recorded_date ORDER BY recorded_date`, []);
  return r.rows;
}
async function getUserCount() {
  const r = await db('SELECT COUNT(*)::int AS cnt FROM users', []);
  return r.rows[0].cnt;
}

function buildChartData(rows, range) {
  const now = new Date();
  let periods = [];
  if (range === 'week') {
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i);
      periods.push({ key: d.toISOString().slice(0,10), label: d.toLocaleString('default', { weekday:'short' }) });
    }
  } else {
    const count = range === 'quarter' ? 12 : range === 'year' ? 12 : 6;
    for (let i = count - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`;
      periods.push({ key, label: d.toLocaleString('default', { month:'short', year:'2-digit' }) });
    }
  }
  const bk = { testPlans:{}, testCases:{}, autoScripts:{} };
  periods.forEach(p => { bk.testPlans[p.key]=0; bk.testCases[p.key]=0; bk.autoScripts[p.key]=0; });
  rows.forEach(row => {
    const dateKey = range === 'week' ? row.recorded_date : row.recorded_date.slice(0,7);
    if (bk[row.stat_type] && bk[row.stat_type][dateKey] !== undefined) bk[row.stat_type][dateKey] += row.cnt;
  });
  return { labels: periods.map(p => p.label), testPlans: periods.map(p => bk.testPlans[p.key]), testCases: periods.map(p => bk.testCases[p.key]), autoScripts: periods.map(p => bk.autoScripts[p.key]) };
}

// Mailgun SMTP
function createTransporter() {
  const { host, port, user, pass } = CONFIG.smtp;
  if (!user || !pass) throw new Error('SMTP not configured. Set SMTP_USER and SMTP_PASS.');
  return nodemailer.createTransport({ host, port, secure:false, auth:{user,pass}, tls:{rejectUnauthorized:false} });
}
function buildRegistrationEmail(toEmail, url) {
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f2f3fb;font-family:'Segoe UI',Arial,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f3fb;padding:40px 16px"><tr><td align="center"><table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 32px rgba(0,0,0,.1)"><tr><td style="background:linear-gradient(135deg,#7c3aed,#ec4899);padding:36px 40px 28px;text-align:center"><h1 style="color:#fff;font-size:24px;font-weight:800;margin:0 0 6px">Qubit QA Platform</h1><p style="color:rgba(255,255,255,.85);font-size:14px;margin:0">Intelligent Test Planning</p></td></tr><tr><td style="padding:40px 40px 32px"><h2 style="color:#0f1017;font-size:20px;font-weight:800;margin:0 0 10px">Complete your registration</h2><p style="color:#5c6278;font-size:14.5px;line-height:1.65;margin:0 0 28px">You requested to create a <strong>Qubit QA Platform</strong> account for <strong style="color:#7c3aed">${toEmail}</strong>.</p><table cellpadding="0" cellspacing="0" width="100%"><tr><td align="center" style="padding:4px 0 32px"><a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;text-decoration:none;font-size:15px;font-weight:700;padding:15px 40px;border-radius:10px">Complete Registration &rarr;</a></td></tr></table><table cellpadding="0" cellspacing="0" width="100%" style="background:#f8f7ff;border:1px solid rgba(124,58,237,.14);border-radius:10px"><tr><td style="padding:18px 22px"><p style="font-size:13px;color:#5c6278;margin:0 0 8px"><strong style="color:#7c3aed">&#9200; Expires in:</strong>&nbsp;24 hours</p><p style="font-size:13px;color:#5c6278;margin:0"><strong style="color:#7c3aed">&#128274; One-time use:</strong>&nbsp;Link invalidates after registration</p></td></tr></table><p style="color:#9498b0;font-size:12px;margin:24px 0 0;word-break:break-all">Button not working? <a href="${url}" style="color:#7c3aed">${url}</a></p></td></tr><tr><td style="background:#f8f7ff;border-top:1px solid #ebe9f8;padding:20px 40px;text-align:center"><p style="color:#9498b0;font-size:12px;margin:0">Automated message — please do not reply.</p></td></tr></table></td></tr></table></body></html>`;
  const text = `Complete your Qubit registration\n\nAccount for: ${toEmail}\nLink (expires 24h): ${url}\n\n— Qubit QA Platform`;
  return { html, text };
}
async function sendRegistrationEmail(toEmail, url) {
  const transporter = createTransporter();
  const { html, text } = buildRegistrationEmail(toEmail, url);
  const info = await transporter.sendMail({ from: CONFIG.smtp.from, to: toEmail, subject: 'Complete your Qubit registration', text, html });
  console.log(`[smtp] Sent → ${toEmail} (${info.messageId})`);
  return info;
}

// Auth helpers
function hashPassword(pwd, email) { return crypto.createHash('sha256').update(pwd+'|qubit-server|'+email.toLowerCase()).digest('hex'); }
function createToken() { return crypto.randomBytes(32).toString('hex'); }
function domainOk(email) { const d=(email||'').split('@')[1]; return CONFIG.allowedDomains.includes((d||'').toLowerCase()); }
function passwordValid(p) { return p.length>=8&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/[0-9]/.test(p)&&/[^A-Za-z0-9]/.test(p); }

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  if (Date.now() - session.createdAt > CONFIG.sessionExpiryMs) { await deleteSession(token); return res.status(401).json({ error: 'Session expired' }); }
  const user = await getUser(session.email);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user; req.token = token; req.session = session;
  next();
}

function verifyGoogleToken(idToken) {
  return new Promise((resolve, reject) => {
    const u = new URL(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
    const req = https.request({ hostname: u.hostname, path: u.pathname+u.search, method:'GET', headers:{Accept:'application/json'} }, res => {
      let raw=''; res.on('data', c => { raw+=c; });
      res.on('end', () => { try { const d=JSON.parse(raw); if(d.error_description||d.error)return reject(new Error(d.error_description||d.error)); if(CONFIG.googleClientId&&d.aud!==CONFIG.googleClientId)return reject(new Error('Token audience mismatch')); resolve(d); } catch(e){reject(e);} });
    });
    req.on('error',reject); req.setTimeout(8000,()=>{req.destroy();reject(new Error('timeout'));}); req.end();
  });
}

class AtlassianClient {
  constructor({ email, apiToken, siteUrl }) { this.email=email; this.apiToken=apiToken; this.siteUrl=siteUrl; this.timeout=CONFIG.mcp.timeout; }
  _auth() { return `Basic ${Buffer.from(`${this.email}:${this.apiToken}`).toString('base64')}`; }
  _req(method, urlPath, body) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlPath, `https://${this.siteUrl}`);
      const opts = { method, hostname:url.hostname, path:url.pathname+url.search, headers:{Authorization:this._auth(),Accept:'application/json','User-Agent':'qubit/1.3'}, timeout:this.timeout };
      if(body){const p=JSON.stringify(body);opts.headers['Content-Type']='application/json';opts.headers['Content-Length']=Buffer.byteLength(p);}
      const r=https.request(opts,res=>{let c=[];res.on('data',d=>c.push(d));res.on('end',()=>{const raw=Buffer.concat(c).toString('utf8');if(res.statusCode>=200&&res.statusCode<300){try{resolve(JSON.parse(raw));}catch{resolve(raw);}}else{const e=new Error(`HTTP ${res.statusCode}: ${raw.slice(0,300)}`);e.statusCode=res.statusCode;reject(e);}});});
      r.on('error',reject);r.on('timeout',()=>{r.destroy();reject(new Error(`Timeout ${this.timeout}ms`));});
      if(body)r.write(JSON.stringify(body));r.end();
    });
  }
  async withRetry(label, fn, max=CONFIG.mcp.maxRetries, onLog) {
    let attempt=0,lastErr;
    while(attempt<max){try{return await fn();}catch(err){attempt++;lastErr=err;if(err.statusCode&&err.statusCode>=400&&err.statusCode<500&&err.statusCode!==429)throw err;const b=Math.min(1000*Math.pow(2,attempt-1),8000);if(onLog)onLog(`⚠ ${label} retry in ${Math.round(b/1000)}s`,'warn');await new Promise(r=>setTimeout(r,b));}}
    throw new Error(`${label} failed after ${max} retries: ${lastErr.message}`);
  }
  async ping() { return this._req('GET','/rest/api/3/myself'); }
  async getIssue(k,fields) { return this._req('GET',`/rest/api/3/issue/${k}${fields?'?fields='+fields.join(','):''}`); }
  async getFields() { return this._req('GET','/rest/api/3/field'); }
  async getChangelog(k) { return this._req('GET',`/rest/api/3/issue/${k}/changelog?maxResults=200`); }
  async searchConfluence(cql) {
    const body={cql,limit:5,expand:'body.storage'};
    return this._req('POST','/wiki/api/v2/pages/search',body).catch(()=>
      this._req('GET','/wiki/rest/api/content/search?cql='+encodeURIComponent(cql)+'&limit=5&expand=body.storage,body.view')
    );
  }
  async getConfluencePage(pageId) {
    return this._req('GET',`/wiki/rest/api/content/${pageId}?expand=body.storage,body.view`).catch(()=>null);
  }
  async searchByJql(jql,fields=['summary','status','issuetype'],maxResults=100) {
    const all=[]; let nextPageToken=null,safety=0;
    do { const p={jql,fields,maxResults}; if(nextPageToken)p.nextPageToken=nextPageToken; const r=await this._req('POST','/rest/api/3/search/jql',p); if(Array.isArray(r.issues))all.push(...r.issues); nextPageToken=r.nextPageToken||null; safety++; if(r.isLast===true||!nextPageToken||safety>=10)break; } while(true);
    return { issues: all };
  }
}

// ─── Jira field helpers ───────────────────────────────────────────────────────
let _fieldMapCache = null;
async function getFieldMap(client) {
  if (_fieldMapCache) return _fieldMapCache;
  try {
    const fields = await client.getFields();
    const map = {};
    (Array.isArray(fields) ? fields : []).forEach(f => {
      if (f.name) map[f.name.toLowerCase()] = f.id;
      if (f.id && f.name) map[f.id] = f.name;
    });
    _fieldMapCache = map;
    return map;
  } catch (e) { console.warn('[fields] Could not fetch field mapping:', e.message); return {}; }
}
function findField(map, patterns) {
  for (const p of patterns) {
    if (map[p]) return map[p];
    for (const k of Object.keys(map)) { if (k.includes(p) && !k.startsWith('customfield_')) return map[k]; }
  }
  return null;
}
function resolveUserField(fields, fieldId) {
  if (!fieldId || !fields[fieldId]) return null;
  const v = fields[fieldId];
  if (v && v.displayName) return v.displayName;
  if (Array.isArray(v) && v[0] && v[0].displayName) return v[0].displayName;
  return null;
}
async function extractEpicRoles(client, epicKey, epicFields, fieldMap) {
  // Detect EM and QA field IDs from field map
  const emId = findField(fieldMap, ['engineering manager','engineering_manager','em','eng manager','eng_manager']);
  const qaId = findField(fieldMap, ['qa validator','qa_validator','quality assurance','tester','qa owner','qa_owner','qa']);

  const engineeringManager = resolveUserField(epicFields, emId) || (epicFields.assignee && epicFields.assignee.displayName) || '—';
  const qaValidator = resolveUserField(epicFields, qaId) || null;

  // Stakeholders: all unique users from changelog (issue history)
  const names = new Set();
  try {
    const cl = await client.getChangelog(epicKey);
    (cl.values || []).forEach(entry => {
      if (entry.author && entry.author.displayName && !/automation|bot|jira/i.test(entry.author.displayName)) {
        names.add(entry.author.displayName);
      }
    });
  } catch (e) { /* changelog optional */ }
  // Always include reporter, assignee, EM, QA
  [epicFields.reporter, epicFields.assignee].forEach(u => { if (u && u.displayName) names.add(u.displayName); });
  if (engineeringManager !== '—') names.add(engineeringManager);
  if (qaValidator) names.add(qaValidator);

  return { engineeringManager, qaValidator, stakeholders: Array.from(names) };
}

function adfToPlainText(adf) {
  if(!adf)return''; if(typeof adf==='string')return adf; if(!adf.content)return'';
  let out='';
  const walk=node=>{if(node.type==='text'&&node.text)out+=node.text;if(node.type==='hardBreak')out+='\n';if(node.type==='paragraph'||node.type==='heading'){(node.content||[]).forEach(walk);out+='\n';}else if(node.type==='bulletList'||node.type==='orderedList'){(node.content||[]).forEach(item=>{out+='• ';(item.content||[]).forEach(walk);out+='\n';});}else if(node.content)node.content.forEach(walk);};
  adf.content.forEach(walk); return out.trim();
}

function extractAcceptanceCriteria(descText) {
  if(!descText)return[];
  const lines=descText.split('\n').map(l=>l.trim()).filter(Boolean),bullets=[];let inAc=false;
  for(const line of lines){if(/^(acceptance criteria|requirements|ac:|scenarios|given|when|then|definition of done)/i.test(line)){inAc=true;continue;}if(inAc){if(/^(#|##|background|notes?|open questions|out of scope|implementation|technical)/i.test(line)){inAc=false;continue;}const m=line.match(/^[•\-\*]\s*(.+)/)||line.match(/^\d+[\.\)]\s*(.+)/);if(m)bullets.push(m[1].trim());}}
  if(bullets.length===0){for(const line of lines){const m=line.match(/^[•\-\*]\s*(.{15,})/);if(m)bullets.push(m[1].trim());if(bullets.length>=12)break;}}
  return bullets.slice(0,15);
}


// ─── Confluence fetch helper ──────────────────────────────────────────────────
function adfOrHtmlToText(pageData) {
  if (!pageData) return '';
  let body = (pageData.body && (pageData.body.storage || pageData.body.view)) || {};
  let raw = body.value || '';
  // Strip HTML tags
  return raw.replace(/<[^>]+>/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, 4000);
}

async function fetchConfluenceForEpic(client, epicKey, onLog) {
  try {
    // Search by epic key in DEV space
    const cql = `space = "DEV" AND title ~ "${epicKey}" AND ancestor = "2164326506"`;
    const results = await client.searchConfluence(cql);
    const pages = results.results || results.results || [];
    if (pages.length === 0) {
      // Fallback: search by text
      const cql2 = `space = "DEV" AND text ~ "${epicKey}" AND ancestor = "2164326506"`;
      const r2 = await client.searchConfluence(cql2);
      const p2 = r2.results || [];
      if (p2.length === 0) {
        if (onLog) onLog(`⚠ No Confluence page found for ${epicKey}`, 'warn');
        return null;
      }
      const page = await client.getConfluencePage(p2[0].id);
      if (onLog) onLog(`✓ Confluence page found: "${p2[0].title}" (via text search)`, 'ok');
      return { title: p2[0].title, content: adfOrHtmlToText(page) };
    }
    const page = await client.getConfluencePage(pages[0].id);
    if (onLog) onLog(`✓ Confluence page found: "${pages[0].title}"`, 'ok');
    return { title: pages[0].title, content: adfOrHtmlToText(page) };
  } catch (e) {
    if (onLog) onLog(`⚠ Confluence fetch failed for ${epicKey}: ${e.message}`, 'warn');
    return null;
  }
}

async function fetchStoriesParallel(client, stories, onLog) {
  const workerCount=Math.min(CONFIG.mcp.parallelWorkers,stories.length),results=new Array(stories.length);let idx=0;
  if(onLog)onLog(`▶ ${workerCount} parallel workers for ${stories.length} stories`,'info');
  const worker=async wid=>{while(idx<stories.length){const i=idx++;if(i>=stories.length)return;const story=stories[i];if(onLog)onLog(`  worker-${wid} → fetching ${story.key}`);try{const d=await client.withRetry(`getIssue(${story.key})`,()=>client.getIssue(story.key,['summary','description','status','priority','assignee']),CONFIG.mcp.maxRetries,onLog);const dt=adfToPlainText(d.fields.description);results[i]={id:d.key,title:d.fields.summary,desc:dt.slice(0,3000),ac:extractAcceptanceCriteria(dt)};if(onLog)onLog(`  worker-${wid} ✓ ${story.key} (${i+1}/${stories.length})`,'ok');}catch(err){if(onLog)onLog(`  worker-${wid} ✗ ${story.key} — ${err.message}`,'err');results[i]={id:story.key,title:(story.fields&&story.fields.summary)||story.key,desc:'(description unavailable)',ac:['Acceptance criteria unavailable']};}}};
  await Promise.all(Array.from({length:workerCount},(_,i)=>worker(i+1)));
  return results;
}

// Express App
const app = express();
app.use(cors({ origin: CONFIG.corsOrigin, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use((req,_,next)=>{console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);next();});

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone, org, role, password, avatar, inviteToken } = req.body || {};
  if(!firstName||!lastName||!email||!org||!role||!password)return res.status(400).json({error:'Missing required fields'});
  if(!domainOk(email))return res.status(403).json({error:`Only ${CONFIG.allowedDomains.join(' / ')} emails allowed`});
  if(!passwordValid(password))return res.status(400).json({error:'Password must be 8+ chars with uppercase, number, symbol'});
  const emailLower=email.toLowerCase();
  if(inviteToken){const invite=await getInvite(inviteToken);if(!invite)return res.status(400).json({error:'Invalid or expired invite link'});if(Date.now()>invite.expiresAt){await deleteInvite(inviteToken);return res.status(400).json({error:'Invite link has expired'});}if(invite.email.toLowerCase()!==emailLower)return res.status(400).json({error:'Email does not match invite'});await deleteInvite(inviteToken);}
  if(await getUser(emailLower))return res.status(409).json({error:'Account already exists'});
  const initials=(firstName[0]+lastName[0]).toUpperCase();
  const user={firstName,lastName,fullName:`${firstName} ${lastName}`,email:emailLower,phone:phone||'',org,role,bio:'',initials,avatar:avatar||{type:'initials'},passwordHash:hashPassword(password,emailLower),createdAt:new Date().toISOString()};
  await saveUser(user);
  const token=createToken();await createSession(token,emailLower);
  const {passwordHash,...pub}=user;res.json({user:pub,token});
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const {email,password}=req.body||{};
  if(!email||!password)return res.status(400).json({error:'Missing credentials'});
  const emailLower=email.toLowerCase();
  const user=await getUser(emailLower);
  if(!user||user.passwordHash!==hashPassword(password,emailLower))return res.status(401).json({error:'Invalid credentials'});
  const token=createToken();await createSession(token,emailLower);
  const {passwordHash,...pub}=user;

  // ── Auto-verify saved connectors (server-side only — tokens never sent to client) ──
  const connStatus = await _verifyAndUpdateConnectors(emailLower);

  res.json({user:pub, token, connectors: connStatus});
});

// GOOGLE SSO
app.post('/api/auth/google', async (req, res) => {
  const {credential}=req.body||{};if(!credential)return res.status(400).json({error:'Google credential required'});
  let payload;try{payload=await verifyGoogleToken(credential);}catch(err){return res.status(401).json({error:`Google verification failed: ${err.message}`});}
  const email=(payload.email||'').toLowerCase();if(!email)return res.status(400).json({error:'No email in Google token'});
  if(!domainOk(email))return res.status(403).json({error:`Only ${CONFIG.allowedDomains.join(' / ')} accounts allowed`});
  let user=await getUser(email);
  if(!user){const fn=payload.given_name||email.split('@')[0],ln=payload.family_name||'';const ini=((fn[0]||'')+(ln[0]||'')).toUpperCase()||'?';user={firstName:fn,lastName:ln,fullName:payload.name||fn,email,phone:'',org:email.split('@')[1],role:'Other',bio:'',initials:ini,avatar:payload.picture?{type:'photo',data:payload.picture}:{type:'initials'},passwordHash:'',googleSub:payload.sub,createdAt:new Date().toISOString()};await saveUser(user);}
  const token=createToken();await createSession(token,email);
  const {passwordHash,...pub}=user;
  const connStatus = await _verifyAndUpdateConnectors(email);
  res.json({user:pub, token, connectors: connStatus});
});

// SELF-SERVICE REGISTER REQUEST
app.post('/api/auth/request-register', async (req, res) => {
  const {email}=req.body||{};if(!email)return res.status(400).json({error:'Email required'});
  const emailLower=email.toLowerCase().trim();
  if(!domainOk(emailLower))return res.status(403).json({error:`Only ${CONFIG.allowedDomains.join(' / ')} emails are allowed`});
  if(await getUser(emailLower))return res.status(409).json({error:'An account already exists for this email. Please sign in.'});
  let tokenVal=null;const ei=await findUnexpiredInvite(emailLower);
  if(ei){tokenVal=ei.token;}else{tokenVal=createToken();await saveInvite(tokenVal,emailLower,null,Date.now()+CONFIG.regTokenExpiryMs);}
  const registrationUrl=`${CONFIG.frontendUrl}/?register=${tokenVal}`;
  try{await sendRegistrationEmail(emailLower,registrationUrl);res.json({ok:true,email:emailLower});}
  catch(err){console.error('[register]',err.message);res.status(500).json({error:'Failed to send registration email: '+err.message});}
});

app.get('/api/auth/register-token/:token', async (req, res) => {
  const invite=await getInvite(req.params.token);if(!invite)return res.status(404).json({error:'Invalid registration link'});
  if(Date.now()>invite.expiresAt){await deleteInvite(req.params.token);return res.status(410).json({error:'Registration link has expired.'});}
  res.json({email:invite.email,expiresAt:invite.expiresAt});
});

// LOGOUT / ME / PROFILE / PASSWORD
app.post('/api/auth/logout', authMiddleware, async (req, res) => { await deleteSession(req.token); res.json({ok:true}); });
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const connStatus = await _verifyAndUpdateConnectors(req.user.email).catch(() => ({}));
  const {passwordHash,...pub}=req.user;
  res.json({user:pub, connectors:connStatus});
});
app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const {firstName,lastName,org,role,phone,bio,avatar}=req.body||{};const user={...req.user};
  if(firstName)user.firstName=firstName;if(lastName)user.lastName=lastName;
  if(firstName&&lastName){user.fullName=`${firstName} ${lastName}`;user.initials=(firstName[0]+lastName[0]).toUpperCase();}
  if(org!==undefined)user.org=org;if(role!==undefined)user.role=role;if(phone!==undefined)user.phone=phone;if(bio!==undefined)user.bio=bio;if(avatar!==undefined)user.avatar=avatar;
  await saveUser(user);const {passwordHash,...pub}=user;res.json({user:pub});
});
app.post('/api/auth/password', authMiddleware, async (req, res) => {
  const {oldPassword,newPassword}=req.body||{};if(!oldPassword||!newPassword)return res.status(400).json({error:'Both old and new password required'});
  const user={...req.user};if(!user||user.passwordHash!==hashPassword(oldPassword,req.user.email))return res.status(401).json({error:'Current password is incorrect'});
  if(!passwordValid(newPassword))return res.status(400).json({error:'New password must be 8+ chars with uppercase, lowercase, number, and symbol'});
  if(oldPassword===newPassword)return res.status(400).json({error:'New password must be different'});
  user.passwordHash=hashPassword(newPassword,req.user.email);await saveUser(user);await deleteUserSessions(req.user.email,req.token);
  res.json({ok:true,message:'Password updated successfully'});
});

// INVITE
app.post('/api/auth/invite', authMiddleware, async (req, res) => {
  const {email}=req.body||{};if(!email)return res.status(400).json({error:'Email required'});
  const emailLower=email.toLowerCase();if(!domainOk(emailLower))return res.status(403).json({error:`Only ${CONFIG.allowedDomains.join(' / ')} emails allowed`});
  if(await getUser(emailLower))return res.status(409).json({error:'User already exists'});
  const ei=await findUnexpiredInvite(emailLower);
  if(ei)return res.json({ok:true,inviteUrl:`${CONFIG.frontendUrl}/?register=${ei.token}`,expiresAt:ei.expiresAt,reused:true});
  const token=createToken();await saveInvite(token,emailLower,req.user.email,Date.now()+CONFIG.inviteExpiryMs);
  res.json({ok:true,inviteUrl:`${CONFIG.frontendUrl}/?register=${token}`,expiresAt:Date.now()+CONFIG.inviteExpiryMs});
});
app.get('/api/auth/invite/:token', async (req, res) => {
  const invite=await getInvite(req.params.token);if(!invite)return res.status(404).json({error:'Invalid invite link'});
  if(Date.now()>invite.expiresAt){await deleteInvite(req.params.token);return res.status(410).json({error:'Invite expired'});}
  res.json({email:invite.email,invitedBy:invite.invitedBy,expiresAt:invite.expiresAt});
});

// STATS DASHBOARD (range-aware)
app.get('/api/stats/dashboard', authMiddleware, async (req, res) => {
  const range=req.query.range||'month';
  const rows=await getStatsForRange(range);
  const chart=buildChartData(rows,range);
  const myRows=await db('SELECT stat_type,COUNT(*)::int AS cnt FROM stat_events WHERE email=$1 GROUP BY stat_type',[req.user.email]);
  const glRows=await db('SELECT stat_type,COUNT(*)::int AS cnt FROM stat_events GROUP BY stat_type',[]);
  const myMap={},glMap={};myRows.rows.forEach(r=>{myMap[r.stat_type]=r.cnt;});glRows.rows.forEach(r=>{glMap[r.stat_type]=r.cnt;});
  const totalUsers=await getUserCount();
  res.json({my:{testPlans:myMap.testPlans||0,testCases:myMap.testCases||0,autoScripts:myMap.autoScripts||0},global:{testPlans:glMap.testPlans||0,testCases:glMap.testCases||0,autoScripts:glMap.autoScripts||0,users:totalUsers},chart,range});
});

// CONNECTORS
app.get('/api/connectors/status', authMiddleware, async (req, res) => {
  // Use _verifyAndUpdateConnectors to get consistent status for all connectors
  const status = await _verifyAndUpdateConnectors(req.user.email).catch(() => ({}));
  // Never return raw or decrypted tokens — only status fields
  res.json({ connectors: status });
});
app.post('/api/connectors/jira/connect', authMiddleware, async (req, res) => {
  const {apiToken,email:jiraEmail,siteUrl}=req.body||{};if(!apiToken||!jiraEmail||!siteUrl)return res.status(400).json({error:'apiToken, email, siteUrl required'});
  const ns=siteUrl.replace(/^https?:\/\//,'').replace(/\/$/,'');const client=new AtlassianClient({email:jiraEmail,apiToken,siteUrl:ns});
  try{const me=await client.ping();const data=await getConnectors(req.user.email);
    data.jira={
      connected:true, method:'token',
      connectedAt:new Date().toISOString(),
      apiTokenEnc:encryptToken(apiToken),  // stored encrypted — never plain text
      jiraEmail, siteUrl:ns,
      accountId:me.accountId, displayName:me.displayName
    };
    await saveConnectors(req.user.email,data);
    res.json({connected:true,method:'token',jiraUser:{accountId:me.accountId,displayName:me.displayName,email:me.emailAddress}});
  }
  catch(err){res.status(401).json({error:`Jira auth failed: ${err.message}`});}
});

// Generic connector connect: stores encrypted token for confluence, github, figma
// Each connector validates differently — currently validates by token presence only.
// Extend per-connector validation as needed.
app.post('/api/connectors/:id/connect', authMiddleware, async (req, res) => {
  const id = req.params.id;
  if (id === 'jira') return res.status(400).json({ error: 'Use /api/connectors/jira/connect' });
  const { apiToken } = req.body || {};
  if (!apiToken) return res.status(400).json({ error: 'apiToken required' });

  // Per-connector validation
  let displayName = null;
  try {
    if (id === 'confluence') {
      // Confluence shares Atlassian auth — reuse Jira token if available, or validate standalone
      const existingData = await getConnectors(req.user.email);
      const jira = existingData.jira || {};
      const siteUrl = jira.siteUrl || 'clearlyrated.atlassian.net';
      const jiraEmail = jira.jiraEmail || req.user.email;
      // Quick ping: list spaces
      const client = new AtlassianClient({ email: jiraEmail, apiToken, siteUrl });
      const result = await client._req('GET', '/wiki/rest/api/space?limit=1').catch(() => null);
      displayName = result ? 'Confluence workspace' : null;
    } else if (id === 'figma') {
      // Validate Figma token via /v1/me
      const figmaRes = await fetch('https://api.figma.com/v1/me', {
        headers: { 'X-Figma-Token': apiToken }
      });
      if (!figmaRes.ok) throw new Error(`Figma auth failed: ${figmaRes.status}`);
      const figmaUser = await figmaRes.json();
      displayName = figmaUser.handle || figmaUser.email || 'Figma user';
    } else if (id === 'github') {
      // Validate GitHub token via /user
      const ghRes = await fetch('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${apiToken}`, 'User-Agent': 'Qubit-QA' }
      });
      if (!ghRes.ok) throw new Error(`GitHub auth failed: ${ghRes.status}`);
      const ghUser = await ghRes.json();
      displayName = ghUser.login || 'GitHub user';
    } else {
      // Unknown connector — store token without validation
      displayName = id + ' user';
    }
  } catch (validationErr) {
    return res.status(401).json({ error: `${id} auth failed: ${validationErr.message}` });
  }

  // Store encrypted
  const data = await getConnectors(req.user.email);
  data[id] = {
    connected:    true,
    method:       'token',
    connectedAt:  new Date().toISOString(),
    apiTokenEnc:  encryptToken(apiToken),
    displayName:  displayName
  };
  await saveConnectors(req.user.email, data);
  res.json({ connected: true, method: 'token', displayName });
});
app.post('/api/connectors/jira/test', authMiddleware, async (req, res) => {
  const data=await getConnectors(req.user.email);const jira=data.jira;if(!jira||!jira.connected)return res.status(400).json({error:'Jira not connected'});
  const steps=[],logStep=(ok,msg)=>steps.push({ok,msg,ts:Date.now()});
  try{const t0=Date.now();logStep(true,`Pinging ${jira.siteUrl}`);const client=new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});const me=await client.ping();logStep(true,`Authenticated as ${me.displayName}`);const p=await client.searchByJql('issuetype = Epic ORDER BY created DESC',['summary'],1);logStep(true,`Probe JQL returned ${p.issues.length} result(s)`);logStep(true,`Latency: ${Date.now()-t0}ms`);res.json({ok:true,steps,latency:Date.now()-t0,jiraUser:me.displayName});}
  catch(err){logStep(false,err.message);res.status(500).json({ok:false,steps,error:err.message});}
});
app.delete('/api/connectors/:id', authMiddleware, async (req, res) => {
  const data=await getConnectors(req.user.email);if(data[req.params.id]){delete data[req.params.id];await saveConnectors(req.user.email,data);}res.json({ok:true});
});

// TEST PLAN GENERATE
app.post('/api/testplan/generate', authMiddleware, async (req, res) => {
  const {projectName,release,epics,context}=req.body||{};
  if(!projectName||!Array.isArray(epics)||epics.length===0)return res.status(400).json({error:'projectName and non-empty epics[] required'});
  const connData=await getConnectors(req.user.email);const jira=connData.jira;
  if(!jira||!jira.connected)return res.status(400).json({error:'Jira connector not configured'});
  res.setHeader('Content-Type','text/event-stream');res.setHeader('Cache-Control','no-cache');res.setHeader('Connection','keep-alive');res.setHeader('X-Accel-Buffering','no');res.flushHeaders();
  const send=(event,data)=>{try{res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);}catch(e){}};
  const log=(msg,level='info')=>send('log',{msg,level,ts:Date.now()});
  const phase=(idx,state,sub)=>send('phase',{idx,state,sub});
  const hb=setInterval(()=>{try{res.write(': heartbeat\n\n');}catch(e){}},15000);
  try {
    log(`╔═══ TEST PLAN GENERATION STARTED ═══`);
    log(`Project: ${projectName} · Epics: ${epics.join(', ')}`);
    const client=new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});
    phase(0,'active','');const me=await client.ping();log(`✓ Authenticated as ${me.displayName}`,'ok');phase(0,'done',`✓ ${me.displayName}`);

    // Fetch Jira field mapping once (used for EM and QA detection)
    let fieldMap = {};
    try { fieldMap = await getFieldMap(client); log(`✓ Field mapping loaded (${Object.keys(fieldMap).length} fields)`,'ok'); }
    catch(e) { log(`⚠ Field mapping unavailable: ${e.message}`,'warn'); }

    phase(1,'active',`0 of ${epics.length}`);const epicsMeta=[];
    for(let i=0;i<epics.length;i++){
      const id=epics[i];log(`──── Epic ${i+1}/${epics.length}: ${id} ────`);
      const epic=await client.withRetry(`getIssue(${id})`,()=>client.getIssue(id,['summary','description','status','assignee','reporter','duedate','priority']),CONFIG.mcp.maxRetries,log);
      const dt=adfToPlainText(epic.fields.description);
      // Enrich roles from Jira fields + changelog
      const roles = await extractEpicRoles(client, id, epic.fields, fieldMap);
      log(`✓ Roles — EM: ${roles.engineeringManager} | QA: ${roles.qaValidator||'—'} | Stakeholders: ${roles.stakeholders.length}`,'ok');
      epicsMeta.push({id,meta:{
        key:epic.key,title:epic.fields.summary,description:dt.slice(0,800),
        status:(epic.fields.status&&epic.fields.status.name)||'Unknown',
        assignee:(epic.fields.assignee&&epic.fields.assignee.displayName)||'Unassigned',
        reporter:(epic.fields.reporter&&epic.fields.reporter.displayName)||'Unknown',
        dueDate:epic.fields.duedate||'TBD',
        priority:(epic.fields.priority&&epic.fields.priority.name)||'Medium',
        engineeringManager:roles.engineeringManager,
        qaValidator:roles.qaValidator,
        stakeholders:roles.stakeholders
      }});
      log(`✓ Epic loaded: ${epicsMeta[epicsMeta.length-1].meta.title}`,'ok');phase(1,'active',`${i+1} of ${epics.length}`);
    }    phase(1,'done',`${epics.length} epics fetched`);phase(2,'active','');
    const slbe={};let totalStories=0;
    for(const em of epicsMeta){const jql=`parent in (${em.id}) AND issuetype = Story`;log(`JQL: "${jql}"`);const sr=await client.withRetry(`searchByJql(${em.id})`,()=>client.searchByJql(jql,['summary','status','issuetype'],100),CONFIG.mcp.maxRetries,log);const issues=sr.issues||[];slbe[em.id]=issues;log(`✓ ${issues.length} stories for ${em.id}`,'ok');issues.forEach(s=>log(`    • ${s.key} — ${s.fields&&s.fields.summary}`));totalStories+=issues.length;}
    phase(2,'done',`${totalStories} stories found`);if(totalStories===0)log(`⚠ No stories found. Check JQL permissions.`,'warn');
    phase(3,'active',`0 of ${totalStories}`);const allEpics=[];let done=0;
    for(const em of epicsMeta){const list=slbe[em.id];const details=list.length>0?await fetchStoriesParallel(client,list,log):[];allEpics.push({id:em.id,meta:em.meta,stories:details});done+=list.length;phase(3,'active',`${done} of ${totalStories}`);}
    phase(3,'done',`${totalStories} stories enriched`);phase(4,'active','saving to database');
    const planId=crypto.randomBytes(8).toString('hex');
    const firstEpicTitle = allEpics[0] && allEpics[0].meta.title ? allEpics[0].meta.title : '';
    const displayName = `${projectName}${firstEpicTitle ? ' — ' + firstEpicTitle : ''}`;
    const summary={
      id:planId, displayName,
      generatedAt:new Date().toISOString(),generatedBy:req.user.email,generatedByName:req.user.fullName,
      project:projectName,release:release||'Unscheduled',context:context||'',
      site:jira.siteUrl,jiraUser:me.displayName,
      epics:allEpics.map(e=>({
        epicKey:e.id, epicTitle:e.meta.title, epicDescription:e.meta.description,
        epicStatus:e.meta.status, epicAssignee:e.meta.assignee, epicReporter:e.meta.reporter,
        epicDueDate:e.meta.dueDate,
        epicEngineeringManager:e.meta.engineeringManager,
        epicQaValidator:e.meta.qaValidator,
        epicStakeholders:e.meta.stakeholders,
        stories:e.stories.map(s=>({storyKey:s.id,storyTitle:s.title,description:s.desc,acceptanceCriteria:s.ac}))
      })),
      totals:{epics:allEpics.length,stories:totalStories,acceptanceCriteria:allEpics.reduce((a,e)=>a+e.stories.reduce((b,s)=>b+s.ac.length,0),0)}
    };
    await savePlan(planId,req.user.email,projectName,release,epics,summary);
    await recordStatEvent(req.user.email,'testPlans');
    log(`✓ Plan saved to database`,'ok');phase(4,'done','saved to database');
    phase(5,'active','synthesizing');phase(5,'done','complete');log(`╚═══ GENERATION COMPLETE ═══`,'ok');
    send('complete',{planId,summary,stats:{epics:summary.totals.epics,stories:summary.totals.stories,scenarios:summary.totals.stories*4,ac:summary.totals.acceptanceCriteria}});
  } catch(err) {
    console.error('[generate] FAILED:',err);
    try{log(`╚═══ FAILED: ${err.message} ═══`,'err');send('error',{error:err.message||'Unknown error'});}catch(e){}
  } finally { clearInterval(hb);try{res.end();}catch(e){} }
});

app.get('/api/testplan/:id/summary', authMiddleware, async (req, res) => {
  const summary=await getPlanSummary(req.params.id,req.user.email);
  if(!summary)return res.status(404).json({error:'Plan not found'});
  res.json(summary);
});
// Fetch most recent test plan that covers ANY of the given epic IDs
app.get('/api/testplan/by-epics', authMiddleware, async (req, res) => {
  const epicIds = (req.query.epics || '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  if (!epicIds.length) return res.status(400).json({ error: 'epics query param required' });
  // Find most recent plan that covers at least one of these epics
  const r = await db(
    `SELECT plan_id, summary FROM test_plans
     WHERE email=$1 AND epics::text ~ ANY($2::text[])
     ORDER BY generated_at DESC LIMIT 1`,
    [req.user.email.toLowerCase(), epicIds.map(id => `"${id}"`)]
  ).catch(() => ({ rows: [] }));
  if (!r.rows[0]) return res.json({ plan: null });
  res.json({ plan: r.rows[0].summary });
});

app.get('/api/testplan/list', authMiddleware, async (req, res) => {
  const plans=await getPlans(req.user.email);res.json({plans});
});


// TEST CASE — GENERATE (SSE: fetch Jira data, frontend generates cases)
app.post('/api/testcase/generate', authMiddleware, async (req, res) => {
  const {projectName,release,epics,prefix}=req.body||{};
  if(!projectName||!Array.isArray(epics)||epics.length===0||!prefix)return res.status(400).json({error:'projectName, epics[], and prefix required'});
  const connData=await getConnectors(req.user.email);const jira=connData.jira;
  if(!jira||!jira.connected)return res.status(400).json({error:'Jira connector not configured'});
  res.setHeader('Content-Type','text/event-stream');res.setHeader('Cache-Control','no-cache');res.setHeader('Connection','keep-alive');res.setHeader('X-Accel-Buffering','no');res.flushHeaders();
  const send=(event,data)=>{try{res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);}catch(e){}};
  const log=(msg,level='info')=>send('log',{msg,level,ts:Date.now()});
  const phase=(idx,state,sub)=>send('phase',{idx,state,sub});
  const hb=setInterval(()=>{try{res.write(': heartbeat\n\n');}catch(e){}},15000);
  try {
    log(`╔═══ TEST CASE GENERATION STARTED ═══`);
    log(`Project: ${projectName} · Prefix: ${prefix} · Epics: ${epics.join(', ')}`);
    const client=new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});
    phase(0,'active','');const me=await client.ping();log(`✓ Authenticated as ${me.displayName}`,'ok');phase(0,'done',`✓ ${me.displayName}`);
    let fieldMap={};
    try{fieldMap=await getFieldMap(client);log(`✓ Field mapping loaded`,'ok');}catch(e){log(`⚠ Field mapping unavailable`,'warn');}
    phase(1,'active',`0 of ${epics.length}`);const epicsMeta=[];
    for(let i=0;i<epics.length;i++){
      const id=epics[i];log(`──── Epic ${i+1}/${epics.length}: ${id} ────`);
      const epic=await client.withRetry(`getIssue(${id})`,()=>client.getIssue(id,['summary','description','status','assignee','reporter','duedate','priority']),CONFIG.mcp.maxRetries,log);
      const dt=adfToPlainText(epic.fields.description);
      const roles=await extractEpicRoles(client,id,epic.fields,fieldMap);
      epicsMeta.push({id,meta:{key:epic.key,title:epic.fields.summary,description:dt.slice(0,800),assignee:(epic.fields.assignee&&epic.fields.assignee.displayName)||'Unassigned',reporter:(epic.fields.reporter&&epic.fields.reporter.displayName)||'Unknown',engineeringManager:roles.engineeringManager,qaValidator:roles.qaValidator,stakeholders:roles.stakeholders}});
      log(`✓ Epic loaded: ${epicsMeta[epicsMeta.length-1].meta.title}`,'ok');phase(1,'active',`${i+1} of ${epics.length}`);
    }
    phase(1,'done',`${epics.length} epics fetched`);
    phase(2,'active','');
    const slbe={};let totalStories=0;
    for(const em of epicsMeta){const jql=`parent in (${em.id}) AND issuetype = Story`;const sr=await client.withRetry(`searchByJql(${em.id})`,()=>client.searchByJql(jql,['summary','status','issuetype'],100),CONFIG.mcp.maxRetries,log);const issues=sr.issues||[];slbe[em.id]=issues;log(`✓ ${issues.length} stories for ${em.id}`,'ok');totalStories+=issues.length;}
    phase(2,'done',`${totalStories} stories found`);if(totalStories===0)log(`⚠ No stories found.`,'warn');
    phase(3,'active',`0 of ${totalStories}`);const allEpics=[];let done=0;
    for(const em of epicsMeta){const list=slbe[em.id];const details=list.length>0?await fetchStoriesParallel(client,list,log):[];allEpics.push({id:em.id,meta:em.meta,stories:details});done+=list.length;phase(3,'active',`${done} of ${totalStories}`);}
    phase(3,'done',`${totalStories} stories enriched`);
    // Phase 4: Fetch Confluence test plans for each epic
    phase(4,'active',`0 of ${epicsMeta.length}`);
    const confluenceByEpic = {};
    for(let ci=0;ci<epicsMeta.length;ci++){
      const em=epicsMeta[ci];
      log(`──── Confluence for ${em.id} ────`);
      const conf = await fetchConfluenceForEpic(client, em.id, log).catch(() => null);
      if(conf){confluenceByEpic[em.id]=conf;log(`✓ Confluence: "${conf.title}"`, 'ok');}
      else{log(`⚠ No Confluence page for ${em.id} — using Jira data only`,'warn');}
      phase(4,'active',`${ci+1} of ${epicsMeta.length}`);
    }
    phase(4,'done',`Confluence fetched for ${Object.keys(confluenceByEpic).length} of ${epicsMeta.length} epics`);
    // Phase 5: Enrich and send to client for generation
    phase(5,'active','Preparing enriched data');
    const enrichedEpics = allEpics.map(e => ({
      ...e,
      confluenceTitle: confluenceByEpic[e.id] ? confluenceByEpic[e.id].title : null,
      confluenceContent: confluenceByEpic[e.id] ? confluenceByEpic[e.id].content : null
    }));
    phase(5,'done','Ready');

    // Phase 6: Fetch existing test plan scenarios for these epics
    phase(5,'active','Fetching test plan scenarios from database...');
    let existingPlanScenarios = null;
    try {
      const epicIds = enrichedEpics.map(e => e.id);
      const planRow = await db(
        `SELECT summary FROM test_plans WHERE email=$1 AND epics::text ~ ANY($2::text[]) ORDER BY generated_at DESC LIMIT 1`,
        [req.user.email.toLowerCase(), epicIds.map(id => `"${id}"`)]
      );
      if (planRow.rows[0] && planRow.rows[0].summary) {
        const planSum = planRow.rows[0].summary;
        const planEpics = planSum.epics || [];
        const storyCount = planEpics.reduce((a, e) => a + (e.stories||[]).length, 0);
        log(`✓ Found test plan "${planSum.project || 'unnamed'}" — ${planEpics.length} epic(s), ${storyCount} story(s)`, 'ok');
        // Log every story title so user can see what scenarios will drive TC generation
        planEpics.forEach(function(e) {
          log(`  Epic ${e.epicKey}: ${e.epicTitle}`, 'ok');
          (e.stories||[]).forEach(function(s) {
            log(`    • Story ${s.storyKey}: ${s.storyTitle}`, 'ok');
          });
        });
        existingPlanScenarios = planEpics.flatMap(e =>
          (e.stories||[]).map(s => ({
            storyKey:   s.storyKey,
            storyTitle: s.storyTitle,
            ac:         s.acceptanceCriteria || []
          }))
        );
        log(`✓ ${existingPlanScenarios.length} stories from test plan will guide test case generation`, 'ok');
      } else {
        log(`⚠ No existing test plan found for these epics — scenarios will be derived from Jira ACs`, 'warn');
      }
    } catch(planErr) {
      log(`⚠ Could not fetch test plan: ${planErr.message} — proceeding with Jira data`, 'warn');
    }
    phase(5,'done','Test plan scenarios loaded');

    log(`╚═══ ALL DATA READY — Sending to client for AI test case generation ═══`,'ok');
    send('complete',{projectName,release,epics,prefix,allEpics:enrichedEpics,totalStories,generatedBy:req.user.fullName,site:jira.siteUrl,confluenceByEpic,existingPlanScenarios});
  }catch(err){console.error('[tc-gen]',err);try{log(`╚═══ FAILED: ${err.message} ═══`,'err');send('error',{error:err.message||'Unknown error'});}catch(e){}}
  finally{clearInterval(hb);try{res.end();}catch(e){}}
});

app.post('/api/testcase/save', authMiddleware, async (req, res) => {
  const {tcId,projectName,release,prefix,epics,cases,totals}=req.body||{};
  if(!tcId||!projectName||!prefix||!Array.isArray(cases))return res.status(400).json({error:'tcId, projectName, prefix, cases[] required'});
  try{
    await saveTestCaseSet(tcId,req.user.email,projectName,release,prefix,epics||[],cases,totals||{});
    await recordStatEvent(req.user.email,'testCases');
    res.json({ok:true,tcId});
  }catch(err){res.status(500).json({error:err.message});}
});

app.get('/api/testcase/list', authMiddleware, async (req, res) => {
  const list=await getTestCasesList(req.user.email);res.json({testCases:list});
});

app.get('/api/testcase/:id', authMiddleware, async (req, res) => {
  const tc=await getTestCaseSet(req.params.id,req.user.email);
  if(!tc)return res.status(404).json({error:'Test case set not found'});
  res.json(tc);
});


// AUTO-VERIFY — called after login to silently validate stored credentials
app.get('/api/connectors/verify', authMiddleware, async (req, res) => {
  const data  = await getConnectors(req.user.email);
  const jira  = data.jira;
  const result = { jiraConnected: false, jiraError: null };

  if (jira && jira.connected) {
    const token = getJiraToken(jira);
    if (!token) {
      result.jiraError = 'Jira API token is missing or could not be decrypted. Please re-enter your token.';
    } else {
      try {
        const client = new AtlassianClient({ email: jira.jiraEmail, apiToken: token, siteUrl: jira.siteUrl });
        await client.ping();
        result.jiraConnected = true;
      } catch (e) {
        const msg = e.message || '';
        if (/401|403|unauthorized|forbidden/i.test(msg)) {
          result.jiraError = 'Jira API token has expired or been revoked. Please reconnect with a new token.';
        } else if (/ENOTFOUND|ECONNREFUSED|network|timeout/i.test(msg)) {
          result.jiraError = 'Cannot reach Jira. Check your network connection and try again.';
        } else {
          result.jiraError = 'Jira connection could not be verified: ' + msg;
        }
        // Mark as disconnected in DB so user must reconnect
        jira.connected = false;
        jira.lastError  = result.jiraError;
        await saveConnectors(req.user.email, data);
      }
    }
  }

  res.json(result);
});

// SMTP TEST
app.get('/api/test/mailgun', async (req, res) => {
  const {host,port,user,pass,from}=CONFIG.smtp;
  const checks={SMTP_HOST:`smtp.mailgun.org`,SMTP_USER:user?`✓ set (${user})`:'✗ NOT SET',SMTP_PASS:pass?`✓ set (${pass.slice(0,6)}…)`:'✗ NOT SET',SMTP_FROM:from?`✓ ${from}`:'✗ NOT SET',FRONTEND_URL:CONFIG.frontendUrl};
  if(!req.query.to)return res.json({status:'config_check',checks,usage:'Add ?to=your@email.com'});
  try{const t=createTransporter();await t.verify();const i=await t.sendMail({from,to:req.query.to,subject:'Qubit SMTP test',text:'SMTP working ✓',html:'<p>SMTP working ✓</p>'});res.json({status:'sent',messageId:i.messageId,checks});}
  catch(err){res.status(500).json({status:'failed',error:err.message,checks});}
});

// HEALTH
app.get('/api/health', (_req, res) => {
  res.json({ok:true,service:'qubit-server',version:'1.3.0',uptimeSec:Math.round(process.uptime()),config:{allowedDomains:CONFIG.allowedDomains,googleClientId:CONFIG.googleClientId||null,database:process.env.DATABASE_URL?'postgresql':'⚠ not set',mcpTimeout:CONFIG.mcp.timeout}});
});

app.use((err,_req,res,_next)=>{console.error('Unhandled error:',err);res.status(500).json({error:'Internal server error',detail:err.message});});

// Start
initDB().then(() => {
  app.listen(CONFIG.port,'0.0.0.0',()=>{
    console.log('─────────────────────────────────────────────────');
    console.log(`  Qubit Server v1.3.0  |  port ${CONFIG.port}`);
    console.log(`  Database  : ${process.env.DATABASE_URL?'PostgreSQL ✓':'⚠ DATABASE_URL not set'}`);
    console.log(`  Frontend  : ${CONFIG.frontendUrl}`);
    console.log(`  SMTP      : smtp.mailgun.org:587 — ${CONFIG.smtp.user||'⚠ not configured'}`);
    console.log('─────────────────────────────────────────────────');
  });
}).catch(err=>{console.error('DB init failed:',err.message);process.exit(1);});
