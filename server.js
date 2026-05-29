/**
 * qubit-server v1.5.0
 * PostgreSQL-backed: users, sessions, connectors, test plans, stats
 * Email: Mailgun SMTP via nodemailer
 * v1.4: Logic-based TC generation, epic summary caching (./epic-cache/)
 * v1.5: TP epic cache (skip Phase 2 JQL + Phase 3 story fetch for cached epics),
 *       SCHEMA_VERSION 3 archive reset, token stats in completion event
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
const fs         = require('fs');
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

// PostgreSQL Pool — Neon free tier cold-starts can take 10–15s
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis:      30000,
  connectionTimeoutMillis: 20000,  // Neon cold-start needs up to 15s
  allowExitOnIdle:         false,
});

async function db(sql, params = []) {
  const client = await pool.connect();
  try { return await client.query(sql, params); }
  finally { client.release(); }
}

// ─── Schema version — bump to wipe archive data on next boot ─────────────────
const SCHEMA_VERSION = 3;

// ─── Epic summary cache (24h TTL, stored in ./epic-cache/) ───────────────────
const EPIC_CACHE_DIR = path.join(__dirname, 'epic-cache');
const EPIC_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
try { if (!fs.existsSync(EPIC_CACHE_DIR)) fs.mkdirSync(EPIC_CACHE_DIR, { recursive: true }); } catch(e) {}

function getEpicCache(epicId) {
  try {
    const f = path.join(EPIC_CACHE_DIR, `${epicId}.json`);
    if (!fs.existsSync(f)) return null;
    const entry = JSON.parse(fs.readFileSync(f, 'utf8'));
    if (Date.now() - new Date(entry.cachedAt).getTime() > EPIC_CACHE_TTL) { fs.unlinkSync(f); return null; }
    return entry;
  } catch(e) { return null; }
}

function setEpicCache(epicId, data) {
  try {
    const entry = { cachedAt: new Date().toISOString(), data };
    fs.writeFileSync(path.join(EPIC_CACHE_DIR, `${epicId}.json`), JSON.stringify(entry), 'utf8');
  } catch(e) { console.warn('[cache] Could not write epic cache:', e.message); }
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
  // Schema version tracking — triggers archive wipe on version bump
  await db(`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  const vRow = await db(`SELECT value FROM schema_meta WHERE key='version'`);
  const currentVer = vRow.rows[0] ? parseInt(vRow.rows[0].value, 10) : 0;
  if (currentVer < SCHEMA_VERSION) {
    await db(`TRUNCATE TABLE test_plans, test_cases, stat_events`);
    await db(`INSERT INTO schema_meta(key,value) VALUES('version','${SCHEMA_VERSION}') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`);
    try {
      if (fs.existsSync(EPIC_CACHE_DIR)) {
        const files = fs.readdirSync(EPIC_CACHE_DIR);
        files.forEach(f => { try { fs.unlinkSync(path.join(EPIC_CACHE_DIR, f)); } catch(e) {} });
        console.log(`[db] Cleared ${files.length} epic-cache file(s)`);
      }
    } catch(e) { console.warn('[db] Could not clear epic-cache:', e.message); }
    console.log(`[db] Archive purged (schema v${currentVer} → v${SCHEMA_VERSION})`);
  }
  console.log('[db] Tables ready');
}

// Retry DB init up to 5 times — handles Neon cold-start delays gracefully
async function initDBWithRetry(attempts = 5, delayMs = 5000) {
  for (let i = 1; i <= attempts; i++) {
    try {
      await initDB();
      return; // success
    } catch (err) {
      console.error(`[db] Init attempt ${i}/${attempts} failed: ${err.message}`);
      if (i < attempts) {
        console.log(`[db] Retrying in ${delayMs/1000}s...`);
        await new Promise(r => setTimeout(r, delayMs));
      } else {
        throw err; // all attempts exhausted
      }
    }
  }
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
  if (!adf) return '';
  if (typeof adf === 'string') return adf;
  if (!adf.content) return '';
  let out = '';

  const walk = (node, prefix) => {
    prefix = prefix || '';
    if (!node) return;

    switch (node.type) {
      case 'text':
        out += node.text || '';
        break;
      case 'hardBreak':
        out += '\n';
        break;
      case 'paragraph':
        (node.content || []).forEach(n => walk(n, prefix));
        out += '\n';
        break;
      case 'heading':
        out += '\n';
        (node.content || []).forEach(n => walk(n, prefix));
        out += '\n';
        break;
      case 'bulletList':
      case 'orderedList':
        (node.content || []).forEach((item, i) => {
          out += prefix + '• ';
          (item.content || []).forEach(n => walk(n, prefix + '  '));
        });
        break;
      case 'listItem':
        (node.content || []).forEach(n => walk(n, prefix));
        break;
      case 'table':
        // Extract table rows as readable text — captures requirement tables like ENG-2955
        (node.content || []).forEach(row => {
          const cells = [];
          (row.content || []).forEach(cell => {
            let cellText = '';
            const orig = out;
            out = '';
            (cell.content || []).forEach(n => walk(n, ''));
            cellText = out.trim();
            out = orig;
            if (cellText) cells.push(cellText);
          });
          if (cells.length > 0) out += cells.join(' | ') + '\n';
        });
        break;
      case 'tableRow':
      case 'tableHeader':
      case 'tableCell':
        (node.content || []).forEach(n => walk(n, prefix));
        break;
      case 'blockquote':
        out += '> ';
        (node.content || []).forEach(n => walk(n, prefix));
        out += '\n';
        break;
      case 'codeBlock':
        (node.content || []).forEach(n => walk(n, prefix));
        out += '\n';
        break;
      case 'rule':
        out += '\n---\n';
        break;
      default:
        if (node.content) node.content.forEach(n => walk(n, prefix));
    }
  };

  adf.content.forEach(node => walk(node, ''));
  return out.trim();
}

// Extract ALL meaningful content from a story description as requirement lines.
// NO heading filtering — every bullet, table row, and meaningful sentence is a requirement.

function extractAcceptanceCriteria(descText) {
  if (!descText) return [];
  const lines = descText.split('\n').map(l => l.trim()).filter(Boolean);
  const bullets = [];
  let inAc = false;

  // Pass 1: look for explicit AC section with common headings
  for (const line of lines) {
    if (/^(acceptance criteria|ac|acceptance|criteria|requirements|test criteria|definition of done|user acceptance|scenarios|given|when|then)/i.test(line.replace(/[:\-\*#•]+$/, '').trim())) {
      inAc = true; continue;
    }
    if (inAc) {
      // Stop at next major section
      if (/^(##|background|notes?|open questions|out of scope|implementation|technical details|design|mockup|non.functional|dependencies|references)/i.test(line)) {
        inAc = false; continue;
      }
      // Grab bullet points
      const m = line.match(/^[•\-\*]\s*(.+)/) || line.match(/^\d+[\.\)]\s*(.+)/);
      if (m && m[1].trim().length > 5) bullets.push(m[1].trim());
    }
  }

  // Pass 2: if nothing found, grab all substantial bullet points from description
  if (bullets.length === 0) {
    for (const line of lines) {
      const m = line.match(/^[•\-\*]\s*(.{10,})/) || line.match(/^\d+[\.\)]\s*(.{10,})/);
      if (m) bullets.push(m[1].trim());
      if (bullets.length >= 25) break;
    }
  }

  // Pass 3: if still nothing, extract sentences that sound like requirements
  if (bullets.length === 0) {
    for (const line of lines) {
      if (/^(the system|user can|user should|it should|should be able|validate|verify|ensure|confirm|when.*then|the.*must|display|show|allow|prevent|enable)/i.test(line) && line.length > 15) {
        bullets.push(line);
      }
      if (bullets.length >= 20) break;
    }
  }

  return bullets.slice(0, 25);
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


// Skip stories whose title explicitly marks them as developer/technical tasks.
// Matches bracket-prefixed labels like [Technical Task], [Dev Task], [Backend Task] etc.
function isDevStory(title) {
  var t = (title || '').trim();
  // Bracket prefix: [Technical Task], [Dev Task], [Backend Task], [Eng Task], etc.
  if (/^\[\s*(technical\s+task|tech\s+task|developer\s+task|dev\s+task|developer\s+story|dev\s+story|backend\s+task|backend\s+story|engineering\s+task|eng\s+task|tech\s+story|implementation\s+task|technical\s+implementation|tech\s+implementation|infra\s+task|infrastructure\s+task|devops\s+task)\s*\]/i.test(t)) return true;
  // Colon prefix: "Technical Task: ", "Dev Task: "
  if (/^(technical\s+task|tech\s+task|developer\s+task|dev\s+task|backend\s+task|engineering\s+task|eng\s+task|implementation\s+task)\s*:/i.test(t)) return true;
  return false;
}

async function fetchStoriesParallel(client, stories, onLog) {
  const workerCount=Math.min(CONFIG.mcp.parallelWorkers,stories.length),results=new Array(stories.length);let idx=0;
  if(onLog)onLog(`▶ ${workerCount} parallel workers for ${stories.length} stories`,'info');

  // Returns the full plain-text description. If very long (>6000 chars), keeps all of it
  // by slicing into meaningful chunks — we never truncate mid-sentence arbitrarily.
  function getFullDesc(plainText) {
    if (!plainText) return '';
    // No hard cap — return everything the story contains
    // Jira descriptions are rarely >10k chars; Claude handles up to 200k tokens
    return plainText.trim();
  }

  const worker=async wid=>{
    while(idx<stories.length){
      const i=idx++;
      if(i>=stories.length)return;
      const story=stories[i];
      if(onLog)onLog(`  worker-${wid} → fetching ${story.key}`);
      try{
        const d=await client.withRetry(
          `getIssue(${story.key})`,
          ()=>client.getIssue(story.key,['summary','description','status','priority','assignee']),
          CONFIG.mcp.maxRetries,onLog
        );
        const dt = adfToPlainText(d.fields.description);
        const fullDesc = dt.trim();
        const extractedAc = extractAcceptanceCriteria(fullDesc); // all content, no heading filter
        results[i]={
          id:    d.key,
          title: d.fields.summary,
          desc:  fullDesc,          // full description text
          ac:    extractedAc        // all requirements extracted from description
        };
        if(onLog)onLog(`  worker-${wid} ✓ ${story.key} — ${fullDesc.length} chars, ${extractedAc.length} requirements (${i+1}/${stories.length})`,'ok');
      }catch(err){
        if(onLog)onLog(`  worker-${wid} ✗ ${story.key} — ${err.message}`,'err');
        results[i]={id:story.key,title:(story.fields&&story.fields.summary)||story.key,desc:'(description unavailable)',ac:[]};
      }
    }
  };

  await Promise.all(Array.from({length:workerCount},(_,i)=>worker(i)));
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
  const hb=setInterval(()=>{try{res.write(': heartbeat\n\n');}catch(e){}},5000);
  try {
    log(`╔═══ TEST PLAN GENERATION STARTED ═══`);
    log(`Project: ${projectName} · Epics: ${epics.join(', ')}`);
    const client=new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});
    phase(0,'active','');const me=await client.ping();log(`✓ Authenticated as ${me.displayName}`,'ok');phase(0,'done',`✓ ${me.displayName}`);

    // Fetch Jira field mapping once (used for EM and QA detection)
    let fieldMap = {};
    try { fieldMap = await getFieldMap(client); log(`✓ Field mapping loaded (${Object.keys(fieldMap).length} fields)`,'ok'); }
    catch(e) { log(`⚠ Field mapping unavailable: ${e.message}`,'warn'); }


    // ── PRE-CHECK: Does archive already have data for these epic IDs? ──────────
    const archiveSummary = {};  // epicId → stored story data from DB
    const ARCHIVE_TTL_DAYS = 7; // use archive if plan was generated within 7 days
    try {
      for (const id of epics) {
        const ar = await db(
          `SELECT summary, generated_at FROM test_plans WHERE email=$1 AND epics::text LIKE $2 ORDER BY generated_at DESC LIMIT 1`,
          [req.user.email.toLowerCase(), `%"${id}"%`]
        ).catch(() => ({ rows: [] }));
        if (ar.rows[0] && ar.rows[0].summary) {
          const planDate = new Date(ar.rows[0].generated_at);
          const ageMs = Date.now() - planDate.getTime();
          if (ageMs < ARCHIVE_TTL_DAYS * 24 * 60 * 60 * 1000) {
            // Find this epic in the archived summary
            const archEpics = ar.rows[0].summary.epics || [];
            const archEpic = archEpics.find(e => (e.epicKey || e.id || '').toUpperCase() === id.toUpperCase());
            if (archEpic && archEpic.stories && archEpic.stories.length > 0) {
              archiveSummary[id] = archEpic;
              log(`✓ [ARCHIVE HIT] ${id} — ${archEpic.stories.length} stories from archive (${planDate.toISOString().slice(0,10)}) — Jira fetch will be skipped`, 'ok');
            }
          }
        }
      }
      const archiveHitCount = Object.keys(archiveSummary).length;
      if (archiveHitCount > 0) {
        log(`ℹ Using archive data for ${archiveHitCount}/${epics.length} epic(s) — only ${epics.length - archiveHitCount} epic(s) need Jira fetch`, 'info');
      }
    } catch(archErr) {
      log(`⚠ Archive pre-check failed (${archErr.message}) — will fetch from Jira`, 'warn');
    }

    phase(1,'active',`0 of ${epics.length}`);const epicsMeta=[];
    let totalCharsProcessed = 0;
    const tpFullyCachedEpics = {}; // epicId → cached data — skip Phases 2 & 3
    let tpCacheHitCount = 0;
    for(let i=0;i<epics.length;i++){
      const id=epics[i];log(`──── Epic ${i+1}/${epics.length}: ${id} ────`);
      // ── Check DB archive first (higher priority than file cache) ────────────
      if (archiveSummary[id]) {
        const archEpic = archiveSummary[id];
        // Convert archive format to epicsMeta format
        const archMeta = {
          id,
          meta: {
            title: archEpic.epicTitle || archEpic.title || id,
            description: archEpic.epicDescription || '',
            status: 'In Progress',
            assignee: archEpic.epicAssignee || '—',
            reporter: archEpic.epicReporter || '—',
            qaTester: archEpic.epicQaValidator || summary?.generatedByName || '—',
            productManager: archEpic.epicReporter || '—',
            engineeringManager: archEpic.epicEngineeringManager || archEpic.epicAssignee || '—',
            stakeholders: archEpic.epicStakeholders || [],
            reviewers: [archEpic.epicReporter].filter(Boolean),
            dueDate: new Date(Date.now()+5*86400000).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'}),
          }
        };
        epicsMeta.push(archMeta);
        // Store as fully cached so phases 2+3 skip too
        tpFullyCachedEpics[id] = {
          epicMeta: archMeta,
          stories: archEpic.stories || [],
          charsProcessed: (archEpic.stories||[]).reduce((n,s)=>n+(s.desc||'').length+(s.ac||[]).join('').length,0),
        };
        tpCacheHitCount++;
        totalCharsProcessed += tpFullyCachedEpics[id].charsProcessed;
        log(`✓ [ARCHIVE] ${id}: ${archEpic.stories.length} stories loaded from archive — Jira skipped`, 'ok');
        phase(1, 'active', `${i+1} of ${epics.length}`);
        continue;
      }
      // ── Check epic cache first ──────────────────────────────────────────────
      const cached = getEpicCache(id);
      if (cached && cached.data && cached.data.stories && cached.data.stories.length >= 0) {
        const cd = cached.data;
        epicsMeta.push(cd.epicMeta);
        tpFullyCachedEpics[id] = cd;
        tpCacheHitCount++;
        totalCharsProcessed += cd.charsProcessed || 0;
        log(`✓ [CACHE HIT] ${id} — epic + ${cd.stories.length} stories from cache (${cached.cachedAt}) — Jira skipped`,'ok');
        phase(1,'active',`${i+1} of ${epics.length}`);
        continue;
      }
      const epic=await client.withRetry(`getIssue(${id})`,()=>client.getIssue(id,['summary','description','status','assignee','reporter','duedate','priority','issuetype']),CONFIG.mcp.maxRetries,log);
      const epicType = epic.fields.issuetype?.name || '';
      if (!['Epic','epic'].includes(epicType) && epicType !== '') {
        log(`✗ ${id} is a "${epicType}", not an Epic — stopping.`,'err');
        send('error',{error:`${id} is a "${epicType}", not an Epic. Only Epic-type issues are supported for test plan generation. Please enter a valid Epic ID (e.g. ENG-2941).`});
        return;
      }
      const dt=adfToPlainText(epic.fields.description);
      totalCharsProcessed += (dt||'').length;
      const roles = await extractEpicRoles(client, id, epic.fields, fieldMap);
      log(`✓ Roles — EM: ${roles.engineeringManager} | QA: ${roles.qaValidator||'—'} | Stakeholders: ${roles.stakeholders.length}`,'ok');
      const epicMeta = {id,meta:{
        key:epic.key,title:epic.fields.summary,description:dt,
        status:(epic.fields.status&&epic.fields.status.name)||'Unknown',
        assignee:(epic.fields.assignee&&epic.fields.assignee.displayName)||'Unassigned',
        reporter:(epic.fields.reporter&&epic.fields.reporter.displayName)||'Unknown',
        dueDate:epic.fields.duedate||'TBD',
        priority:(epic.fields.priority&&epic.fields.priority.name)||'Medium',
        engineeringManager:roles.engineeringManager,
        qaValidator:roles.qaValidator,
        stakeholders:roles.stakeholders
      }};
      epicsMeta.push(epicMeta);
      setEpicCache(id, { epicMeta, charsProcessed: (dt||'').length });
      log(`✓ Epic loaded: ${epicMeta.meta.title}`,'ok');phase(1,'active',`${i+1} of ${epics.length}`);
    }
    phase(1,'done',`${epics.length} epics fetched`);phase(2,'active','');
    const slbe={};let totalStories=0;
    for(const em of epicsMeta){
      // ── Cached epic: skip JQL, use stored story list ────────────────────────
      if (tpFullyCachedEpics[em.id]) {
        const cachedStories = tpFullyCachedEpics[em.id].stories;
        slbe[em.id] = cachedStories.map(s=>({key:s.id,fields:{summary:s.title||''}}));
        totalStories += cachedStories.length;
        log(`✓ [CACHE] ${em.id}: ${cachedStories.length} stories from cache — JQL skipped`,'ok');
        cachedStories.forEach(s=>log(`    • ${s.id} — ${s.title}`));
        continue;
      }
      const jql=`parent in (${em.id}) AND issuetype = Story`;log(`JQL: "${jql}"`);const sr=await client.withRetry(`searchByJql(${em.id})`,()=>client.searchByJql(jql,['summary','status','issuetype'],100),CONFIG.mcp.maxRetries,log);const rawIssues=sr.issues||[];
      const skippedDev=rawIssues.filter(s=>isDevStory(s.fields&&s.fields.summary));
      const issues=rawIssues.filter(s=>!isDevStory(s.fields&&s.fields.summary));
      slbe[em.id]=issues;
      if(!slbe.__skipped) slbe.__skipped={};
      if(skippedDev.length) slbe.__skipped[em.id]=skippedDev.map(s=>({key:s.key,summary:s.fields&&s.fields.summary}));
      log(`✓ ${issues.length} stories for ${em.id}`+(skippedDev.length?` (${skippedDev.length} dev stories skipped)`:''),'ok');
      issues.forEach(s=>log(`    • ${s.key} — ${s.fields&&s.fields.summary}`));
      if(skippedDev.length) skippedDev.forEach(s=>log(`    ⊘ ${s.key} [SKIPPED: Technical Task]`,'warn'));
      totalStories+=issues.length;
    }
    phase(2,'done',`${totalStories} stories found`);if(totalStories===0)log(`⚠ No stories found. Check JQL permissions.`,'warn');
    phase(3,'active',`0 of ${totalStories}`);const allEpics=[];let done=0;
    for(const em of epicsMeta){
      // ── Cached epic: skip story detail fetch ────────────────────────────────
      if (tpFullyCachedEpics[em.id]) {
        const details = tpFullyCachedEpics[em.id].stories;
        allEpics.push({id:em.id,meta:em.meta,stories:details});
        done += details.length;
        log(`✓ [CACHE] ${em.id}: ${details.length} story details from cache — Jira fetch skipped`,'ok');
        phase(3,'active',`${done} of ${totalStories}`);
        continue;
      }
      const list=slbe[em.id];
      const details=list.length>0?await fetchStoriesParallel(client,list,log):[];
      allEpics.push({id:em.id,meta:em.meta,stories:details});
      done+=list.length;
      const storyChars = details.reduce((s,st)=>s+(st.desc||'').length,0);
      totalCharsProcessed += storyChars;
      setEpicCache(em.id, { epicMeta: em, charsProcessed: (em.meta.description||'').length + storyChars, stories: details });
      phase(3,'active',`${done} of ${totalStories}`);
    }
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
        stories:e.stories.map(s=>({storyKey:s.id,storyTitle:s.title,fullDescription:s.desc,acceptanceCriteria:s.ac}))
      })),
      totals:{epics:allEpics.length,stories:totalStories,acceptanceCriteria:allEpics.reduce((a,e)=>a+e.stories.reduce((b,s)=>b+(s.ac&&s.ac.length>0?s.ac.length:1),0),0)}
    };
    await savePlan(planId,req.user.email,projectName,release,epics,summary);
    await recordStatEvent(req.user.email,'testPlans');
    log(`✓ Plan saved to database`,'ok');phase(4,'done','saved to database');
    phase(5,'active','synthesizing');phase(5,'done','complete');log(`╚═══ GENERATION COMPLETE ═══`,'ok');
    const skippedDevList = Object.values(slbe.__skipped||{}).flat();
    const estimatedTokens = Math.round(totalCharsProcessed / 4);
    const totalAcCount = allEpics.reduce((a,e)=>a+e.stories.reduce((b,s)=>b+(s.ac&&s.ac.length>0?s.ac.length:1),0),0);
    const dataStats = { totalCharsProcessed, estimatedTokens, storiesFetched: totalStories, acCount: totalAcCount, cacheHits: tpCacheHitCount };
    log(`✓ Data processed: ~${estimatedTokens.toLocaleString()} tokens (${totalCharsProcessed.toLocaleString()} chars, ${totalStories} stories, ${totalAcCount} ACs, ${tpCacheHitCount} cache hits)`,'ok');
    send('complete',{planId,summary,skippedDevStories:skippedDevList,dataStats,stats:{epics:summary.totals.epics,stories:summary.totals.stories,scenarios:summary.totals.stories*4,ac:summary.totals.acceptanceCriteria}});
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

// DOCX EXPORT — generate proper .docx from planData
app.post('/api/testplan/export-docx', authMiddleware, async (req, res) => {
  const { summary } = req.body || {};
  if (!summary) return res.status(400).json({ error: 'summary required' });
  try {
    // Dynamically require docx (install if needed)
    let docx;
    try { docx = require('docx'); } catch(e) {
      const { execSync } = require('child_process');
      execSync('npm install docx --no-save', { cwd: __dirname, stdio: 'pipe' });
      docx = require('docx');
    }
    const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, AlignmentType, HeadingLevel, BorderStyle, ShadingType, ExternalHyperlink } = docx;

    // Style constants (from clearlyrated-test-plan skill styles.js)
    const S = {
      COLORS: { BRAND_BLUE:'0052CC', TABLE_HEADER:'F4F5F7', ROW_WHITE:'FFFFFF', TEXT_HEADING:'172B4D', TEXT_BODY:'333333',
                MUST_HAVE:'E3FCEF', NICE_TO_HAVE:'FFFAE6', NOT_IN_SCOPE:'FFEBE6',
                STATUS_DONE:'36B37E', STATUS_PENDING:'FF5630', TEXT_LINK:'0052CC' },
      FONTS: { FAMILY:'Calibri', TITLE:40, SUBTITLE:24, H2:28, BODY:20, SMALL:18 },
      TABLES: {
        OVERVIEW: { LABEL:2485, VALUE:7595 },
        SCOPE:    { CATEGORY:1466, CONTENT:8614 },
        SCENARIO: { STORY_ID:1773, DATA_SETUP:1620, DESCRIPTION:6687 },
        MILESTONES:{ MILESTONE:3196, RESPONSIBLE:3290, DATE:1884, STATUS:1710 },
      },
      PAD: { top:56, bottom:56, left:113, right:113 },
      shading(hex){ return { type: ShadingType.CLEAR, color:'auto', fill:hex }; },
      border(){ const b={style:BorderStyle.SINGLE,size:4,color:'C1C7D0'}; return {top:b,bottom:b,left:b,right:b,insideH:b,insideV:b}; },
    };

    function cell(text, opts={}) {
      const { bg=S.COLORS.ROW_WHITE, bold=false, color=S.COLORS.TEXT_BODY, size=S.FONTS.BODY, colSpan, rowSpan, width } = opts;
      const children = Array.isArray(text) ? text : [new Paragraph({ children: [new TextRun({ text: String(text||''), bold, color, size, font: S.FONTS.FAMILY })] })];
      return new TableCell({
        ...(colSpan ? { columnSpan: colSpan } : {}),
        ...(rowSpan ? { rowSpan } : {}),
        ...(width ? { width: { size: width, type: WidthType.DXA } } : {}),
        shading: S.shading(bg),
        borders: S.border(),
        margins: S.PAD,
        children,
      });
    }

    function hdrCell(text, width) {
      return cell(text, { bg: S.COLORS.TABLE_HEADER, bold: true, color: S.COLORS.TEXT_HEADING, size: S.FONTS.BODY, width });
    }

    function sectionHeading(label) {
      const emojiMap = {'Objective':'\u{1F3AF}','Scope':'\u{1F4CB}','Roles and Responsibility':'\u{1F465}','Test Strategy Overview':'\u{1F4CA}',
        'Testing Phases and Cycles':'\u{1F504}','Assumptions':'⚙️','Test Scenarios':'\u{1F50E}','Entry and Exit Criteria':'✅',
        'Test Tools':'\u{1F6E0}️','Test Environment':'\u{1F310}','Milestones and Deadlines':'\u{1F4C5}','Risks and Mitigations':'⚠️',
        'Test Deliverables':'\u{1F4E6}','Reference Materials':'\u{1F4DA}'};
      const emoji = emojiMap[label] || '';
      const bold = label !== 'Reference Materials';
      return new Paragraph({
        heading: HeadingLevel.HEADING_2,
        spacing: { after: 120 },
        children: [new TextRun({ text: (emoji ? emoji + '  ' : '') + label, bold, color: S.COLORS.TEXT_HEADING, size: S.FONTS.H2, font: S.FONTS.FAMILY })],
      });
    }

    function bodyPara(text, bold=false) {
      return new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text, bold, color: S.COLORS.TEXT_BODY, size: S.FONTS.BODY, font: S.FONTS.FAMILY })] });
    }

    function bulletPara(text, level=0) {
      return new Paragraph({ bullet: { level }, spacing: { after: 40 }, children: [new TextRun({ text, color: S.COLORS.TEXT_BODY, size: S.FONTS.BODY, font: S.FONTS.FAMILY })] });
    }

    // Parse summary
    const epics = summary.epics || [];
    const primaryMeta = epics[0] || {};
    const allStories = epics.flatMap(e => (e.stories || []).map(s => ({ ...s, epicId: e.epicKey || e.id })));
    const epicTitle = primaryMeta.epicTitle || primaryMeta.title || 'Test Plan';
    const epicKeys = epics.map(e => e.epicKey || e.id).filter(Boolean);
    const jiraSite = summary.site || 'clearlyrated.atlassian.net';
    const qaTester = epics[0]?.epicQaValidator || summary.generatedByName || summary.generatedBy || 'QA Tester';
    const pm = epics[0]?.epicReporter || '—';
    const em = epics[0]?.epicEngineeringManager || epics[0]?.epicAssignee || '—';
    const today = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
    const dueDate = new Date(Date.now()+5*86400000).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});

    const children = [];

    // §1 Title block
    children.push(new Paragraph({
      spacing: { before: 0, after: 40 },
      shading: S.shading(S.COLORS.BRAND_BLUE),
      children: [new TextRun({ text: 'Test Plan — ' + epicTitle, bold: true, color: S.COLORS.ROW_WHITE, size: S.FONTS.TITLE, font: S.FONTS.FAMILY })],
    }));
    children.push(new Paragraph({
      spacing: { after: 20 },
      shading: S.shading(S.COLORS.BRAND_BLUE),
      children: [new TextRun({ text: 'Epic: ' + epicKeys.join(', ') + '  |  Version: 1.0  |  Status: In Progress', color: 'E8E8E8', size: S.FONTS.SUBTITLE, font: S.FONTS.FAMILY })],
    }));
    children.push(new Paragraph({
      spacing: { after: 160 },
      shading: S.shading(S.COLORS.BRAND_BLUE),
      children: [new TextRun({ text: '\u{1F464} Prepared by: ' + qaTester + '   \u{1F4C5} ' + today, color: 'E8E8E8', size: S.FONTS.BODY, font: S.FONTS.FAMILY })],
    }));

    // Overview table
    const overviewRows = [
      ['Project Name', summary.project || '—'],
      ['Epic', epicKeys.join(', ')],
      ['Description', epics.map(e => e.epicDescription || e.epicTitle || '').join('; ').slice(0, 300) || '—'],
      ['Stakeholders', (epics[0]?.epicStakeholders || [pm, em]).filter(Boolean).join(', ') || '—'],
      ['Reviewers', pm || '—'],
      ['Due Date', dueDate],
      ['QA Tester', qaTester],
      ['Status', 'In Progress'],
    ];
    children.push(new Table({
      width: { size: 10080, type: WidthType.DXA },
      rows: overviewRows.map(([lbl, val]) => new TableRow({ children: [
        cell(lbl, { bg:S.COLORS.TABLE_HEADER, bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, width:S.TABLES.OVERVIEW.LABEL }),
        cell(val, { width:S.TABLES.OVERVIEW.VALUE }),
      ]})),
    }));
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §2 Objective
    children.push(sectionHeading('Objective'));
    children.push(bodyPara(`The objective of this test plan is to ensure comprehensive QA coverage for ${epicKeys.join(', ')}: "${epicTitle}". It defines the scope, strategy, test scenarios, and deliverables for validating all stories, acceptance criteria, and edge cases. The plan follows ClearlyRated's QA framework, prioritizing positive paths, error handling, edge cases, permissions, and regression coverage across affected modules.`));
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §3 Scope
    children.push(sectionHeading('Scope'));
    const scopeData = [
      { bg: S.COLORS.MUST_HAVE, label: 'Must have:', color:'006644' },
      { bg: S.COLORS.NICE_TO_HAVE, label: 'Nice to have:', color:'974F0C' },
      { bg: S.COLORS.NOT_IN_SCOPE, label: 'Not in scope:', color:'BF2600' },
    ];
    const scopeStories = allStories.map(s => s.id + ' — ' + s.title);
    const scopeRows = scopeData.map((row, ri) => new TableRow({ children: [
      cell(row.label, { bg: row.bg, bold:true, color: row.color, width: S.TABLES.SCOPE.CATEGORY }),
      new TableCell({
        width: { size: S.TABLES.SCOPE.CONTENT, type: WidthType.DXA },
        shading: S.shading(S.COLORS.ROW_WHITE),
        borders: S.border(),
        margins: S.PAD,
        children: ri === 0
          ? scopeStories.map(s => bulletPara(s))
          : ri === 1
            ? [bulletPara('Additional accessibility improvements beyond WCAG 2.1 AA baseline'), bulletPara('Performance optimizations for edge-case data volumes')]
            : [bulletPara("Items explicitly outside this epic's boundaries"), bulletPara('Future-release enhancements documented in subsequent epics'), bulletPara('Third-party service internals (only integration points tested)')],
      }),
    ]}));
    children.push(new Table({ width: { size: 10080, type: WidthType.DXA }, rows: scopeRows }));
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §4 Roles
    children.push(sectionHeading('Roles and Responsibility'));
    [['Product Manager', pm],['Engineering Manager', em],['Feature Developer', (epics[0]?.epicAssignee ? epics[0].epicAssignee + ' and Team' : '—')],['Test Developer', qaTester],['Automation Tester', qaTester]].forEach(([role, name]) => {
      children.push(new Paragraph({ spacing: { after: 80 }, children: [
        new TextRun({ text: role + ':  ', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY }),
        new TextRun({ text: name, color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY }),
      ]}));
    });
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §5 Test Strategy
    children.push(sectionHeading('Test Strategy Overview'));
    [
      'The test strategy describes the foundation for how testing will be managed and executed throughout the project. It focuses on iterative testing cycles, strategic planning, and continuous improvement to ensure the highest quality standards.',
      'Agile Methodology: Testing is integrated into each development cycle, with test runs conducted at regular intervals. This approach allows for early detection of issues and continuous validation as new features are developed.',
      'Risk-Based Testing: Testing efforts are prioritized based on risk assessments. High-risk areas are tested extensively within each cycle, ensuring that critical components are thoroughly validated.',
      'Quality Metrics: Success is measured through key quality metrics, including defect rates, test coverage, and performance benchmarks.',
      'Collaboration and Communication: The strategy emphasizes close collaboration across teams, with regular meetings and transparent reporting.',
      'Continuous Improvement: Feedback from each test cycle is used to refine both the product and the testing process.',
    ].forEach(t => children.push(bodyPara(t)));
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §6 Testing Phases
    children.push(sectionHeading('Testing Phases and Cycles'));
    children.push(bodyPara('This project includes below testing phases:'));
    children.push(new Paragraph({ spacing:{after:80}, children:[new TextRun({text:'System Testing', bold:true, color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY}), new TextRun({text:' - To Ensure all functional and non-functional scenarios are covered as per epic', color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    children.push(new Paragraph({ spacing:{after:160}, children:[new TextRun({text:'Regression Testing', bold:true, color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY}), new TextRun({text:' - To Ensure there is no impact on existing functionality of the feature and related navigation modules', color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));

    // §7 Assumptions
    children.push(sectionHeading('Assumptions'));
    ['Testing will be performed in the Dev environment unless otherwise stated.',
     'Defects will be logged in Jira and assigned appropriate severity.',
     'Feature is deployed and accessible in Dev before test execution begins.',
     `Existing ${epicTitle} functionality will continue to work as expected (regression baseline confirmed).`,
     'At least one qualifying test data record exists in each state required by the scenarios prior to execution.',
     'Backend APIs return deterministic, correctly computed responses for all test conditions.',
     'Test data will be prepared and seeded by the QA team before execution begins.',
    ].forEach(a => children.push(bulletPara(a)));
    children.push(new Paragraph({ spacing: { after: 160 } }));

    // §8 Test Scenarios
    children.push(sectionHeading('Test Scenarios'));

    const scenarioRows = [];
    scenarioRows.push(new TableRow({ children: [cell('Must Have', { bg:S.COLORS.MUST_HAVE, bold:true, color:'006644', colSpan:3 })] }));
    scenarioRows.push(new TableRow({ children: [
      hdrCell('Story ID', S.TABLES.SCENARIO.STORY_ID),
      hdrCell('Data Setup Requirement', S.TABLES.SCENARIO.DATA_SETUP),
      hdrCell('Scenario Description', S.TABLES.SCENARIO.DESCRIPTION),
    ]}));

    allStories.forEach(function(s) {
      const ac = s.ac || [];
      const storyAction = (s.title||'').replace(/^(navigation\s*[-:—]\s*|display\s*[-:—]\s*|build\s*[-:—]\s*|render\s*[-:—]\s*|implement\s*[-:—]\s*|create\s*[-:—]\s*)/i,'').trim();

      const posACs = ac.filter(a => !/error|fail|invalid|cannot|must not|block|prevent/.test(a.toLowerCase()));
      const negACs = ac.filter(a => /error|fail|invalid|cannot|must not|block|prevent/.test(a.toLowerCase()));
      const permACs= ac.filter(a => /role|permission|access|admin|manager|hidden|restricted/.test(a.toLowerCase()));
      const edgeACs= ac.filter(a => /max|min|limit|empty|null|zero|boundary/.test(a.toLowerCase()));

      const scenarios = [];

      if (posACs.length > 0 || ac.length > 0) {
        scenarios.push({
          heading: 'Validate ' + storyAction + ' works correctly when feature is accessed in normal state',
          items: (posACs.length > 0 ? posACs : ac).slice(0,6),
          dataSetup: 'Test account configured in Dev environment\nLogin: Account Manager',
        });
      }
      if (negACs.length > 0) {
        scenarios.push({
          heading: 'Validate error handling when invalid conditions or failure states occur for ' + storyAction.toLowerCase(),
          items: negACs.slice(0,5),
          dataSetup: 'Test data with invalid/edge state\nDev environment',
        });
      }
      if (permACs.length > 0) {
        scenarios.push({
          heading: 'Validate ' + storyAction + ' is accessible or restricted correctly when user role is evaluated',
          items: permACs.slice(0,5),
          dataSetup: 'Multiple user roles available: Admin, Manager, Standard User',
        });
      }
      if (edgeACs.length >= 1) {
        scenarios.push({
          heading: 'Validate ' + storyAction + ' handles boundary values correctly when edge-case inputs are provided',
          items: edgeACs.slice(0,4),
          dataSetup: 'Boundary-value test data prepared\nDev environment',
        });
      }
      if (scenarios.length === 0) {
        scenarios.push({
          heading: 'Validate ' + storyAction + ' when feature is exercised in standard conditions',
          items: ['Verify the feature renders without errors', 'Confirm core behaviour matches requirements'],
          dataSetup: 'Test account configured in Dev environment',
        });
      }

      const storyKey = s.id || '';
      const storyTitle = s.title || '';

      scenarios.forEach(function(sc, si) {
        const bulletParas = [
          new Paragraph({ spacing:{after:60}, children:[new TextRun({text:sc.heading, bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})] }),
          ...sc.items.map(item => new Paragraph({ bullet:{level:0}, spacing:{after:40}, children:[new TextRun({text:item.replace(/^[\s•\-→>]+/,'').trim(), color:S.COLORS.TEXT_BODY, size:S.FONTS.BODY, font:S.FONTS.FAMILY})] }))
        ];

        const dataSetupParas = (sc.dataSetup||'').split('\n').map(l => new Paragraph({ spacing:{after:40}, children:[new TextRun({text:l.trim(), color:S.COLORS.TEXT_BODY, size:S.FONTS.SMALL, font:S.FONTS.FAMILY})] }));

        const row = new TableRow({ children: [
          ...(si === 0 ? [new TableCell({
            rowSpan: scenarios.length,
            width:{ size:S.TABLES.SCENARIO.STORY_ID, type:WidthType.DXA },
            shading: S.shading(S.COLORS.TABLE_HEADER),
            borders: S.border(),
            margins: S.PAD,
            children: [
              new Paragraph({ spacing:{after:4}, children:[new TextRun({text: storyKey, bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})] }),
              new Paragraph({ spacing:{after:0}, children:[new TextRun({text: storyTitle, color:S.COLORS.TEXT_BODY, size:S.FONTS.SMALL, font:S.FONTS.FAMILY})] }),
            ],
          })] : []),
          new TableCell({
            width:{ size:S.TABLES.SCENARIO.DATA_SETUP, type:WidthType.DXA },
            shading: S.shading(S.COLORS.TABLE_HEADER),
            borders: S.border(),
            margins: S.PAD,
            children: dataSetupParas,
          }),
          new TableCell({
            width:{ size:S.TABLES.SCENARIO.DESCRIPTION, type:WidthType.DXA },
            shading: S.shading(S.COLORS.ROW_WHITE),
            borders: S.border(),
            margins: S.PAD,
            children: bulletParas,
          }),
        ]});
        scenarioRows.push(row);
      });
    });

    children.push(new Table({ width:{ size:10080, type:WidthType.DXA }, rows: scenarioRows }));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §9 Entry/Exit Criteria
    children.push(sectionHeading('Entry and Exit Criteria'));
    children.push(new Paragraph({ spacing:{after:80}, children:[new TextRun({text:'Entry Criteria:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Test Environment Setup is Complete: The testing environment is fully configured, and all necessary tools and systems are operational.',
     'Test Cases are Reviewed and Approved: All test cases have been reviewed and approved.',
     'New Feature Available for Testing: Access to the new feature is confirmed in the Dev Environment.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{after:80}, children:[new TextRun({text:'Exit Criteria:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['All Critical and High-Priority Defects are Resolved.',
     'Test Cases Executed with a Pass Rate of at least 95%.',
     'Acceptance Criteria Met for User Experience and Performance Standards.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §10 Test Tools
    children.push(sectionHeading('Test Tools'));
    children.push(bodyPara('Test tools are supporting tools which help us perform manual and automation testing, track the progress and manage defects raised during testing.'));
    ['Transportal Server: https://transportal.dev.inavero.xyz/','Pilot Server: https://pilot.dev.inavero.xyz/',
     'Testing Progress: JIRA-Kanban','Defect Management: JIRA','Test Management: Microsoft Excel'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §11 Test Environment
    children.push(sectionHeading('Test Environment'));
    children.push(bodyPara('A test environment is the physical setup that combines specific configurations of these resources to create real-world testing scenarios.'));
    children.push(bulletPara('Browsers: Chrome v131.0 or later'));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §12 Milestones
    children.push(sectionHeading('Milestones and Deadlines'));
    const milestoneData = [
      ['Test Planning and Creation', qaTester, today, 'Done'],
      ['Test Plan Sign-Off', pm, dueDate, 'Pending'],
      ['Test Case Design & Review', qaTester, '—', 'Pending'],
      ['Test Execution', qaTester, '—', 'Pending'],
      ['Defect Resolution', em, '—', 'Pending'],
      ['Test Regression', qaTester, '—', 'Pending'],
      ['Test Closer Report', qaTester, '—', 'Pending'],
    ];
    const mRows = [
      new TableRow({ children: [hdrCell('Milestone',3196), hdrCell('Owner',3290), hdrCell('Deadline',1884), hdrCell('Status',1710)] }),
      ...milestoneData.map(([m,o,d,st]) => new TableRow({ children: [
        cell(m,{width:3196}), cell(o,{width:3290}), cell(d,{width:1884}),
        new TableCell({ width:{size:1710,type:WidthType.DXA}, shading:S.shading(S.COLORS.ROW_WHITE), borders:S.border(), margins:S.PAD,
          children:[new Paragraph({children:[new TextRun({text:st, bold:true, color:st==='Done'?S.COLORS.STATUS_DONE:S.COLORS.STATUS_PENDING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]})]
        })
      ]}))
    ];
    children.push(new Table({ width:{size:10080,type:WidthType.DXA}, rows:mRows }));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §13 Risks
    children.push(sectionHeading('Risks and Mitigations'));
    children.push(new Paragraph({ spacing:{after:80}, children:[new TextRun({text:'Risks:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Potential delays in preparing testing environment or any uncertain issue while accessing those environments.',
     'Unforeseen technical issues such as application not accessible or build issues that could affect the project.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{after:80}, children:[new TextRun({text:'Mitigations:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Allocate extra time in the schedule to account for unforeseen delays in preparations.',
     'Equip the project with backup plans and contingency measures to address potential challenges.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §14 Deliverables
    children.push(sectionHeading('Test Deliverables'));
    children.push(new Paragraph({ spacing:{after:60}, children:[new TextRun({text:'Before Testing:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Test Plan Document: Detailed test plan, including scope, objectives, strategy, and resources.',
     'Test Cases: Specific test cases for each feature, outlining the steps and expected results.',
     'Test Data: Prepared data sets for testing various scenarios.',
     'Test Environment Setup: Configuration of servers, databases, and other necessary components.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{after:60}, children:[new TextRun({text:'During Testing:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Track Progress: Records of all test cases executed, including pass/fail status.',
     'Defect Reports: Documentation of any issues found, including steps to reproduce.',
     'Daily/Weekly Status Reports: Updates on testing progress, including completed tests and open defects.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{after:60}, children:[new TextRun({text:'After Testing:', bold:true, color:S.COLORS.TEXT_HEADING, size:S.FONTS.BODY, font:S.FONTS.FAMILY})]}));
    ['Final Test Report: Summary of testing activities, including overall test coverage and recommendations.',
     'Defect Log: Comprehensive list of all identified defects and their resolution status.',
     'Test Closure Report: Document indicating all planned tests have been completed.'
    ].forEach(t => children.push(bulletPara(t)));
    children.push(new Paragraph({ spacing:{ after:160 } }));

    // §15 References
    children.push(sectionHeading('Reference Materials'));
    children.push(bodyPara('Epic Links:'));
    epicKeys.forEach(k => children.push(bulletPara(k + ': https://' + jiraSite + '/browse/' + k)));
    children.push(bodyPara('Story Links:'));
    allStories.forEach(s => children.push(bulletPara((s.id||'?') + ': https://' + jiraSite + '/browse/' + (s.id||''))));
    children.push(bulletPara('Reference Test Plan: https://clearlyrated.atlassian.net/wiki/spaces/DEV/pages/2972745732'));

    // Build and send the document
    const doc = new Document({
      sections: [{ properties: { page: { margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } }, children }],
    });

    const buffer = await Packer.toBuffer(doc);
    const epicStr = epicKeys.join('_').replace(/[^A-Z0-9_-]/gi, '_') || 'TestPlan';
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="TestPlan_${epicStr}.docx"`);
    res.send(buffer);
  } catch(err) {
    console.error('[docx-export]', err);
    res.status(500).json({ error: 'docx generation failed: ' + err.message });
  }
});



// TEST CASE — GENERATE (SSE: fetch Jira data, frontend generates cases)

// Server-side TC prompt builder — same logic as client but runs on Render with real API key






function buildStorySummary(stories) {
  return stories.map((s, i) => {
    const reqs = (s.ac||[]);
    const reqText = reqs.length > 0
      ? reqs.map((r, ri) => `  ${ri+1}. ${r}`).join('\n')
      : '  (derive all test scenarios from the full description below)';
    return [
      `## Story ${i+1}: ${s.id} — ${s.title}`,
      ``,
      `### Description`,
      (s.desc || '(no description)').slice(0, 800),
      ``,
      `### Requirements (${reqs.length})`,
      reqText
    ].join('\n');
  }).join('\n\n---\n\n');
}

function buildServerTCPrompt(epicTitle, epicId, stories, confluenceContent, confluenceTitle) {
  const storySummary = buildStorySummary(stories);
  const confSection  = confluenceContent
    ? `\n\n---\n\n## Confluence Test Plan: "${confluenceTitle}"\n\n${confluenceContent.slice(0, 2000)}`
    : '\n\n---\n\n## Confluence Test Plan: Not found — use Jira data only';

  return `You are a Senior QA Architect at ClearlyRated with 20+ years of experience.
Generate test cases for: ${epicTitle} (${epicId})

Read every word of every story description. Your test cases must be as specific and detailed as the examples below.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 1: REFERENCE EXAMPLES — MATCH THIS QUALITY EXACTLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

These are real test cases from this codebase. Study the title format, step writing style, and expected result format.

EXAMPLE 1:
Title: "Validate Feature Flag activation, auto-enrollment of accounts and recipients, and NEW badge lifecycle"
Preconditions: "Firm A with flag OFF; Firm B with flag ON; Account B1 (Firm B) has 2 key contacts; no digest sent yet; User C (Firm B) has never opened Settings drawer"
Credentials: "CR Employee, Firm B"
Steps:
  1. Action: "Navigate to Insights > Overview page for Account B1 (Firm B, flag ON)"
     Expected: "Performance Digest card appears below NPS Score card"
  2. Action: "Verify card displays State A: NEW badge, title, sub-text, Subscribe button"
     Expected: "All elements render correctly; card is NOT in Reporting Center"
  3. Action: "Verify key contact auto-population: open Settings drawer via Subscribe button"
     Expected: "Settings drawer opens; both key contacts pre-populated with 'Key Contact' labels and project access summary"
  4. Action: "Close drawer without saving and reopen from card"
     Expected: "Drawer reopens; both key contacts still present; no changes lost"
  5. Action: "Sign out and sign back in as different user (User D, Firm B) who has never opened drawer"
     Expected: "NEW badge visible for User D (tracked per user, not per firm)"
  6. Action: "User D opens Settings drawer for the first time"
     Expected: "Drawer opens; NEW badge disappears immediately on card"
  7. Action: "Return to User C; verify NEW badge still visible (independent state per user)"
     Expected: "User C badge unaffected by User D's action"
  8. Action: "Turn flag OFF for Firm B and verify card disappears"
     Expected: "Card completely hidden for all Firm B users; no UI element present"
  9. Action: "Turn flag back ON and verify settings are restored from before"
     Expected: "Card reappears; frequency, recipients, and configuration preserved"

EXAMPLE 2:
Title: "Validate Settings Drawer frequency configuration, per-audience status summary, and save/error/unsaved-changes behavior"
Preconditions: "Drawer open; Account with Client (active), Talent (suppressed - <5 responses), Employee (no projects); Monthly frequency set"
Credentials: "Account Manager"
Steps:
  1. Action: "Open Settings drawer and locate frequency selector"
     Expected: "Selector shows three options: Weekly, Monthly, Quarterly; Monthly currently selected"
  2. Action: "Verify helper text below Monthly selection reads correctly"
     Expected: "Text: 'Sends on the 3rd working day of each month at 9:30 AM PST. Covers all surveys with a start date in the prior calendar month.'"
  3. Action: "Click on Weekly option in frequency selector"
     Expected: "Weekly becomes selected; helper text updates immediately to Weekly text without page refresh"
  4. Action: "Locate per-audience-type status summary at bottom of drawer"
     Expected: "Summary shows at least three sections: Client (green dot), Talent (red dot), Employee (red dot)"
  5. Action: "Verify Talent status: red dot with 'Not enough responses received in [period]. Not sent.'"
     Expected: "Red dot and exact copy match; distinct from other suppression reasons"
  6. Action: "Attempt to close drawer via X button without saving"
     Expected: "Warning modal: 'You have unsaved changes. Save before closing?' with Save/Discard buttons"
  7. Action: "Click Discard button in warning"
     Expected: "Drawer closes; changes are reverted; next drawer open shows original settings"
  8. Action: "Click Save Settings button after making a change"
     Expected: "Loading indicator appears on button; 'Settings saved.' notification displays"
  9. Action: "Simulate save error: verify error notification"
     Expected: "Error notification: 'Something went wrong. Please try again.' Error persists; user can retry"

EXAMPLE 3:
Title: "Validate Suppression Engine: all five conditions, independent audience-type behavior, AI retry up to 24 hours, and cadence change handling"
Preconditions: "Five test account scenarios, each triggering one suppression condition; flag ON; Monthly cadence for all"
Credentials: "Backend test harness, AM role"
Steps:
  1. Action: "Test Condition 1 (zero surveys): Account A has no surveys with start date in current period"
     Expected: "Digest suppressed silently; no email sent"
  2. Action: "Verify Condition 1 drawer status: open Settings drawer, check Client status shows red dot and text 'No surveys in this period. Not sent.'"
     Expected: "Drawer status correctly reflects suppression reason"
  3. Action: "Test Condition 2 (<5 responses): Account B has 3 responses for surveys in current period"
     Expected: "Digest suppressed silently"
  4. Action: "Verify Condition 2 drawer status: red dot with text 'Not enough responses received in [period]. Not sent.'"
     Expected: "Drawer shows correct copy; distinct from Condition 1"
  5. Action: "Test Condition 5 (AI failure): Account E has 5+ responses but AI Insights generation fails"
     Expected: "Initial send attempt triggers AI retry window"
  6. Action: "Verify AI retry runs up to 24 hours from original scheduled send time"
     Expected: "Retries continue; no send occurs until AI succeeds or window closes"
  7. Action: "Test audience type independence: Account F has Client (5+ responses) and Talent (<5 responses)"
     Expected: "Client digest sends; Talent digest suppressed independently"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 2: STRICT TITLE RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The title MUST describe the complete test scenario in human-readable terms.

✅ GOOD titles:
- "Validate Feature Flag activation, auto-enrollment of accounts and recipients, and NEW badge lifecycle"
- "Validate Settings Drawer frequency configuration, per-audience status summary, and save/error/unsaved-changes behavior"
- "Validate Recipient Management: key contact auto-sync, add/validate/duplicate/no-access flows end-to-end"
- "Validate Email Subject Line signal priority Ranks 1–5, audience type enforcement, no-negative-framing rule, and first-digest edge case"
- "Validate Analytics Logging: email opened, CTA clicked, and feedback submitted events with correct aggregation and no client-facing exposure"
- "Validate role-based visibility and access control for Performance Digest card and Settings Drawer"

❌ BAD titles (NEVER do these):
- "Validate Default state: OFF. Pending confirmation..." — this is raw Jira text, not a title
- "Validate Example: Bill Kane has access to 3 Client..." — quoting examples from the description, not describing the test
- "Validate Visible to: CR Employee..." — incomplete fragment
- "Validate ENG-2942 requirements" — never use story IDs in titles
- "Validate feature works correctly" — too vague

Title formula: "Validate [Feature/Component]: [behavior1], [behavior2], and [behavior3]"
OR: "Validate [complete scenario description that tells the reader exactly what is being tested]"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 3: STEP WRITING RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ACTIONS: Short, specific, one action each. Real UI element names and exact copy from the description.
  ✅ "Navigate to Insights > Overview and locate Performance Digest card in left column"
  ✅ "Click 'Subscribe' button on the Performance Digest card"
  ✅ "Test Condition 2 (<5 responses): Account B has 3 responses for surveys in current period"
  ✅ "Verify Talent status: red dot with 'Not enough responses received in [period]. Not sent.'"
  ✅ "Log out and log in as Admin at Firm C; navigate to Insights > Overview"
  ❌ "Check that the feature works" — too vague
  ❌ "Assert the API returns 200" — technical jargon
  ❌ "Verify via DevTools" — not UI-level

EXPECTED RESULTS: Specific, observable, with exact quoted copy where available.
  ✅ "Settings drawer opens; both key contacts pre-populated with 'Key Contact' labels and project access summary"
  ✅ "Text: 'Sends on the 3rd working day of each month at 9:30 AM PST.'"
  ✅ "Warning modal: 'You have unsaved changes. Save before closing?' with Save/Discard buttons"
  ✅ "Digest suppressed silently; no email sent"
  ❌ "It works correctly" — meaningless
  ❌ "The element is visible" — not specific

STEP COUNT: 12–18 per test case. Up to 20 for multi-condition scenarios.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 4: GROUPING RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Group by what the test case covers — not by story:
- Same screen + same user + same flow = one test case
- Different user role or different account = separate test case  
- Multi-condition test (5 suppression states, 5 subject line ranks) = ONE test case with "Account A:", "Condition 1:", "Recipient A:" prefixes
- Never create one test case per requirement bullet

Expected: 4–10 test cases for a typical epic.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 5: EPIC DATA — read every word
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${storySummary}
${confSection}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT — return ONLY valid JSON array, nothing else
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[
  {
    "title": "Validate [complete scenario description — see good examples above]",
    "category": "Positive Flows",
    "preconditions": "Specific data state; account state; user state — separated by semicolons",
    "credentials": "Exact role (Account Manager / Admin / CR Employee / Various roles / Backend test harness)",
    "storyIds": ["${epicId}"],
    "acRefs": [],
    "steps": [
      {
        "action": "Navigate to [exact page] and [specific action].",
        "expectedResult": "[Exact observable result with quoted copy from the description where available]"
      }
    ]
  }
]`;
}



app.post('/api/testcase/generate', authMiddleware, async (req, res) => {
  const {projectName,release,epics,prefix}=req.body||{};
  if(!projectName||!Array.isArray(epics)||epics.length===0||!prefix)
    return res.status(400).json({error:'projectName, epics[], and prefix required'});

  const connData=await getConnectors(req.user.email);
  const jira=connData.jira;
  if(!jira||!jira.connected)return res.status(400).json({error:'Jira not connected'});

  // SSE setup
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.setHeader('X-Accel-Buffering','no');
  res.flushHeaders();
  const send  = (event,data) => { try{res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);}catch(e){} };
  const log   = (msg,level='info') => send('log',{msg,level,ts:Date.now()});
  const phase = (idx,state,sub)   => send('phase',{idx,state,sub});
  const hb    = setInterval(()=>{ try{res.write(': heartbeat\n\n');}catch(e){} },5000);

  // ─── PHASES ────────────────────────────────────────────────────────────────
  // 0: Authenticate   1: Fetch Epics   2: Find Stories
  // 3: Fetch Stories  4: Fetch Confluence  5: Generate Test Cases (AI)

  try {
    log(`╔═══ TEST CASE GENERATION ═══`);
    log(`Project: ${projectName} | Prefix: ${prefix} | Epics: ${epics.join(', ')}`);

    // ─── Phase 0: Authenticate ───────────────────────────────────────────────
    phase(0,'active','');
    const client = new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});
    const me = await client.ping();
    log(`✓ Authenticated as ${me.displayName}`,'ok');
    phase(0,'done',`${me.displayName}`);

    // ─── Phase 1: Fetch epic metadata ────────────────────────────────────────
    phase(1,'active',`0 of ${epics.length}`);
    const epicsMeta = [];
    for(let i=0;i<epics.length;i++){
      const id=epics[i];
      log(`Fetching epic ${i+1}/${epics.length}: ${id}`);
      const epic=await client.withRetry(`getIssue(${id})`,()=>client.getIssue(id,['summary','description','status','issuetype']),CONFIG.mcp.maxRetries,log);
      const issueType = epic.fields.issuetype?.name || '';
      if (!['Epic','epic'].includes(issueType) && issueType !== '') {
        log(`✗ ${id} is a "${issueType}", not an Epic. Please enter Epic IDs only (e.g. ENG-2941).`,'err');
        send('error',{error:`${id} is a "${issueType}", not an Epic. Only Epic-type issues are supported. Check the Jira issue type and try again.`});
        return;
      }
      epicsMeta.push({id, title: epic.fields.summary});
      log(`✓ ${id}: ${epic.fields.summary} [${issueType||'Epic'}]`,'ok');
      phase(1,'active',`${i+1} of ${epics.length}`);
    }
    phase(1,'done',`${epics.length} epic(s) loaded`);

    // ─── Phase 2: Find stories under each epic ───────────────────────────────
    phase(2,'active','');
    const storyListByEpic = {};
    let totalStories = 0;
    for(const em of epicsMeta){
      const jql=`parent in (${em.id}) AND issuetype = Story ORDER BY created ASC`;
      const sr=await client.withRetry(`stories(${em.id})`,()=>client.searchByJql(jql,['summary','status'],100),CONFIG.mcp.maxRetries,log);
      const rawIssues2=sr.issues||[];
      const skippedDev2=rawIssues2.filter(s=>isDevStory(s.fields&&s.fields.summary));
      storyListByEpic[em.id]=rawIssues2.filter(s=>!isDevStory(s.fields&&s.fields.summary));
      totalStories+=storyListByEpic[em.id].length;
      log(`✓ ${em.id}: ${storyListByEpic[em.id].length} stories`+(skippedDev2.length?` (${skippedDev2.length} technical tasks skipped: ${skippedDev2.map(s=>s.key).join(', ')})`:''),'ok');
    }
    if(totalStories===0){ log(`⚠ No stories found — check epic IDs and Jira permissions`,'warn'); }
    phase(2,'done',`${totalStories} stories found`);

    // ─── Phase 3: Fetch full story details (same as test plan) ───────────────
    // Uses fetchStoriesParallel → each story gets: id, title, desc (full text), ac (extracted requirements)
    phase(3,'active',`0 of ${totalStories}`);
    const allEpics = [];
    let fetched = 0;
    for(const em of epicsMeta){
      const list = storyListByEpic[em.id];
      let stories = [];
      if(list.length>0){
        stories = await fetchStoriesParallel(client, list, log);
        fetched += stories.length;
        phase(3,'active',`${fetched} of ${totalStories}`);
        // Log what we got
        stories.forEach(s => {
          log(`  ${s.id}: ${s.title.slice(0,50)} — ${s.desc.length} chars, ${s.ac.length} requirements`,'ok');
        });
      }
      allEpics.push({id:em.id, title:em.title, stories});
    }
    phase(3,'done',`${totalStories} stories fetched with full descriptions`);

    // ─── Phase 4: Fetch Confluence notes ─────────────────────────────────────
    phase(4,'active','');
    const confluenceByEpic = {};
    for(const em of epicsMeta){
      const conf = await fetchConfluenceForEpic(client, em.id, log).catch(()=>null);
      if(conf){ confluenceByEpic[em.id]=conf; log(`✓ Confluence: "${conf.title}"`,'ok'); }
      else     { log(`  No Confluence page for ${em.id}`,'info'); }
    }
    phase(4,'done',`Confluence: ${Object.keys(confluenceByEpic).length} of ${epicsMeta.length} found`);

    // ─── Phase 5: Generate test cases via Claude AI ───────────────────────────
    // Stories are processed in batches of 3 to keep each prompt manageable.
    // This avoids token truncation which was causing JSON parse failures.
    phase(5,'active','Calling Claude AI...');
    log(`╔═══ AI TEST CASE GENERATION ═══`,'ok');
    const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
    const generatedCases = [];
    const BATCH_SIZE = 2;

    if(!ANTHROPIC_KEY){
      log(`✗ ANTHROPIC_API_KEY not set on Render — cannot generate test cases`,'err');
      log(`  Add it: Render → service → Environment → ANTHROPIC_API_KEY = sk-ant-...`,'warn');
    } else {
      let caseNum = 1;

      for(const epic of allEpics){
        const allStories = epic.stories||[];
        if(!allStories.length){ log(`  Skipping ${epic.id} — no stories`,'warn'); continue; }

        log(`  Epic: ${epic.title||epic.id} — ${allStories.length} stories, processing in batches of ${BATCH_SIZE}`,'ok');

        const confData    = confluenceByEpic[epic.id] || null;
        const confContent = confData ? confData.content : null;
        const confTitle   = confData ? confData.title   : null;

        // Split stories into batches
        const batches = [];
        for(let i=0; i<allStories.length; i+=BATCH_SIZE){
          batches.push(allStories.slice(i, i+BATCH_SIZE));
        }

        for(let bi=0; bi<batches.length; bi++){
          const batchStories = batches[bi];
          const batchIds = batchStories.map(s=>s.id).join(', ');
          log(`  Batch ${bi+1}/${batches.length}: ${batchIds}`,'info');

          const prompt = buildServerTCPrompt(
            epic.title||epic.id,
            epic.id,
            batchStories,
            bi===0 ? confContent : null,  // only include Confluence in first batch
            bi===0 ? confTitle   : null
          );
          log(`  Prompt: ${prompt.length} chars | ${batchStories.length} stories`,'info');

          try {
            const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
              method:'POST',
              headers:{'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
              body: JSON.stringify({
                model:      'claude-sonnet-4-6',
                max_tokens: 16000,
                system:     'You are a QA architect. Respond ONLY with a valid JSON array. No explanation, no preamble, no markdown fences. Start immediately with [ and end with ].',
                messages:   [{role:'user', content: prompt}]
              })
            });

            const aiData = await aiResp.json();
            if(!aiResp.ok) throw new Error(`Anthropic API ${aiResp.status}: ${aiData.error?.message||JSON.stringify(aiData.error)}`);

            const rawText = (aiData.content?.[0]?.text || '').trim();
            log(`  Response: ${rawText.length} chars | tokens: ${aiData.usage?.input_tokens||'?'} in / ${aiData.usage?.output_tokens||'?'} out`,'ok');

            // Robust JSON extraction — handles any whitespace or trailing text
            let cleanRaw = rawText.replace(/^```json\s*/i,'').replace(/^```\s*/,'').replace(/\s*```$/,'').trim();
            const jsonStart = cleanRaw.indexOf('[');
            const jsonEnd   = cleanRaw.lastIndexOf(']');
            if(jsonStart === -1 || jsonEnd === -1 || jsonEnd < jsonStart){
              throw new Error(`No JSON array found. Preview: ${rawText.slice(0,200)}`);
            }
            let jsonStr = cleanRaw.slice(jsonStart, jsonEnd+1);
            // Attempt parse; if truncated, try to repair by closing open objects
            let cases;
            try {
              cases = JSON.parse(jsonStr);
            } catch(parseErr) {
              // Response was truncated — try to recover partial cases
              log(`  ⚠ JSON parse failed (likely truncation), attempting recovery...`,'warn');
              // Find last complete object by splitting on },{ pattern
              const lastComplete = jsonStr.lastIndexOf('},');
              if(lastComplete > jsonStart) {
                try { cases = JSON.parse(jsonStr.slice(0, lastComplete+1) + ']'); }
                catch(e){ cases = []; }
              } else { cases = []; }
            }

            if(!Array.isArray(cases) || !cases.length){
              throw new Error(`Empty or invalid array. Raw: ${rawText.slice(0,200)}`);
            }

            cases.forEach(tc => {
              generatedCases.push({
                caseId:        `${prefix}-${String(caseNum++).padStart(3,'0')}`,
                title:         (tc.title||`Validate ${epic.title||epic.id}`).trim(),
                category:      tc.category || 'Positive Flows',
                preconditions: (tc.preconditions||'').replace(/\n+/g,' ').trim(),
                credentials:   tc.credentials || 'Account Manager',
                stories:       tc.storyIds || batchStories.map(s=>s.id),
                acRefs:        tc.acRefs || [],
                steps:         (tc.steps||[]).map((s,si) => ({
                  stepNum:        si+1,
                  action:         (s.action||'').trim(),
                  expectedResult: (s.expectedResult||s.expected||'').trim()
                }))
              });
            });
            log(`  ✓ Batch ${bi+1}: ${cases.length} test case(s)`,'ok');

          } catch(aiErr) {
            log(`  ✗ Batch ${bi+1} failed: ${aiErr.message}`,'err');
          }
        } // end batch loop
      } // end epic loop
    }

    phase(5,'done',`${generatedCases.length} test cases generated`);
    log(`╚═══ COMPLETE: ${generatedCases.length} test cases ═══`,'ok');
    send('complete',{
      projectName, release, epics, prefix,
      allEpics,
      totalStories,
      generatedBy:    req.user.fullName,
      site:           jira.siteUrl,
      generatedCases
    });

  } catch(err) {
    console.error('[tc-gen]',err);
    try{ log(`✗ FAILED: ${err.message}`,'err'); send('error',{error:err.message||'Unknown error'}); }catch(e){}
  } finally {
    clearInterval(hb);
    try{ res.end(); }catch(e){}
  }
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

// AI test case generation endpoint — calls Anthropic API server-side with API key
app.post('/api/testcase/ai', authMiddleware, async (req, res) => {
  const { prompt } = req.body || {};
  if (!prompt) return res.status(400).json({ error: 'prompt required' });

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not configured on server' });

  try {
    const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
      method:  'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-6',
        max_tokens: 16000,
        messages:   [{ role: 'user', content: prompt }]
      })
    });

    if (!aiResp.ok) {
      const err = await aiResp.text();
      return res.status(aiResp.status).json({ error: 'Anthropic API error: ' + err.slice(0, 200) });
    }

    const data = await aiResp.json();
    const raw  = (data.content && data.content[0] && data.content[0].text) || '';
    res.json({ text: raw });
  } catch (err) {
    res.status(500).json({ error: 'AI generation failed: ' + err.message });
  }
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
  res.json({ok:true,service:'qubit-server',version:'1.5.0',uptimeSec:Math.round(process.uptime()),config:{allowedDomains:CONFIG.allowedDomains,googleClientId:CONFIG.googleClientId||null,database:process.env.DATABASE_URL?'postgresql':'⚠ not set',mcpTimeout:CONFIG.mcp.timeout}});
});

app.use((err,_req,res,_next)=>{console.error('Unhandled error:',err);res.status(500).json({error:'Internal server error',detail:err.message});});

// Start
initDBWithRetry(5, 6000).then(() => {
  app.listen(CONFIG.port,'0.0.0.0',()=>{
    console.log('─────────────────────────────────────────────────');
    console.log(`  Qubit Server v1.3.0  |  port ${CONFIG.port}`);
    console.log(`  Database  : ${process.env.DATABASE_URL?'PostgreSQL ✓':'⚠ DATABASE_URL not set'}`);
    console.log(`  Frontend  : ${CONFIG.frontendUrl}`);
    console.log(`  SMTP      : smtp.mailgun.org:587 — ${CONFIG.smtp.user||'⚠ not configured'}`);
    console.log('─────────────────────────────────────────────────');
  });
}).catch(err=>{
  console.error('DB init failed after all retries:',err.message);
  console.error('Check DATABASE_URL env var and Neon dashboard — server cannot start without DB.');
  process.exit(1);
});
