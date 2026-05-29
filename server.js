/**
 * qubit-server v1.5.0
 * PostgreSQL-backed: users, sessions, connectors, test plans, stats
 * Email: Mailgun SMTP via nodemailer
 * v1.5: Full TP epic cache (skip Phase 2 JQL + Phase 3 story fetch), archive v3 reset,
 *       epic-cache dir wipe on migration, token stats always shown
 */
'use strict';

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const fs         = require('fs');

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

// ─── Epic Summary Cache ───────────────────────────────────────────────────────
// Saves fetched Jira epic data to ./epic-cache/<epicId>.json (not publicly served).
// Checked before each Jira fetch; if fresh (<24h) the cache is used instead.
const EPIC_CACHE_DIR = path.join(__dirname, 'epic-cache');
const EPIC_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
try { if (!fs.existsSync(EPIC_CACHE_DIR)) fs.mkdirSync(EPIC_CACHE_DIR, { recursive: true }); } catch(e) {}

function getEpicCache(epicId) {
  try {
    const file = path.join(EPIC_CACHE_DIR, `${epicId.replace(/[^A-Za-z0-9_-]/g,'_')}.json`);
    if (!fs.existsSync(file)) return null;
    const stat = fs.statSync(file);
    if (Date.now() - stat.mtimeMs > EPIC_CACHE_TTL_MS) return null; // stale
    const raw = fs.readFileSync(file, 'utf8');
    return JSON.parse(raw);
  } catch(e) { return null; }
}

function setEpicCache(epicId, data) {
  try {
    const file = path.join(EPIC_CACHE_DIR, `${epicId.replace(/[^A-Za-z0-9_-]/g,'_')}.json`);
    fs.writeFileSync(file, JSON.stringify({ epicId, cachedAt: new Date().toISOString(), data }), 'utf8');
  } catch(e) { console.warn('[epic-cache] write failed:', e.message); }
}
// ─────────────────────────────────────────────────────────────────────────────
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

// Current schema version — bump to trigger a one-time archive purge on next deploy.
const SCHEMA_VERSION = 3;

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

  // ── Schema version tracking & one-time archive reset ─────────────────────
  await db(`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT)`);
  const vRow = await db(`SELECT value FROM schema_meta WHERE key='version'`);
  const currentVer = vRow.rows[0] ? parseInt(vRow.rows[0].value, 10) : 0;
  if (currentVer < SCHEMA_VERSION) {
    console.log(`[db] Schema migration ${currentVer} → ${SCHEMA_VERSION}: purging archive data…`);
    await db(`TRUNCATE TABLE test_plans RESTART IDENTITY CASCADE`).catch(e => db(`DELETE FROM test_plans`));
    await db(`TRUNCATE TABLE test_cases RESTART IDENTITY CASCADE`).catch(e => db(`DELETE FROM test_cases`));
    await db(`TRUNCATE TABLE stat_events RESTART IDENTITY CASCADE`).catch(e => db(`DELETE FROM stat_events`));
    await db(`INSERT INTO schema_meta(key,value) VALUES('version','${SCHEMA_VERSION}') ON CONFLICT(key) DO UPDATE SET value='${SCHEMA_VERSION}'`);
    // Also clear the epic-cache directory so stale Jira data is not served
    try {
      if (fs.existsSync(EPIC_CACHE_DIR)) {
        const cacheFiles = fs.readdirSync(EPIC_CACHE_DIR);
        cacheFiles.forEach(f => { try { fs.unlinkSync(path.join(EPIC_CACHE_DIR, f)); } catch(e){} });
        console.log(`[db] Cleared ${cacheFiles.length} epic-cache file(s)`);
      }
    } catch(e) { console.warn('[db] Could not clear epic-cache:', e.message); }
    console.log('[db] Archive purged — starting fresh');
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

    phase(1,'active',`0 of ${epics.length}`);const epicsMeta=[];
    let totalCharsProcessed = 0;
    const tpFullyCachedEpics = {}; // epicId → cached data (epic + stories) — skip Phases 2 & 3
    let tpCacheHitCount = 0;
    for(let i=0;i<epics.length;i++){
      const id=epics[i];log(`──── Epic ${i+1}/${epics.length}: ${id} ────`);

      // ── Check epic cache first (require stories — partial cache miss goes to Jira) ──
      const cached = getEpicCache(id);
      if (cached && cached.data && cached.data.stories && cached.data.stories.length >= 0) {
        const cd = cached.data;
        epicsMeta.push(cd.epicMeta);
        tpFullyCachedEpics[id] = cd;
        tpCacheHitCount++;
        log(`✓ [FULL CACHE HIT] ${id} — epic + ${cd.stories.length} stories from cache (${cached.cachedAt}) — Jira fetch skipped`,'ok');
        totalCharsProcessed += cd.charsProcessed || 0;
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
      // Enrich roles from Jira fields + changelog
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
      // Save basic epic metadata to cache (stories added after Phase 3)
      setEpicCache(id, { epicMeta, charsProcessed: (dt||'').length });
      log(`✓ Epic loaded: ${epicMeta.meta.title}`,'ok');phase(1,'active',`${i+1} of ${epics.length}`);
    }
    phase(1,'done',`${epics.length} epics fetched`);phase(2,'active','');
    const slbe={};let totalStories=0;
    for(const em of epicsMeta){
      // ── Fully cached epic: skip JQL, use stored story list ──────────────────
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
      // Store skipped stories for test plan "Notes" section
      if(!slbe.__skipped) slbe.__skipped={};
      if(skippedDev.length) slbe.__skipped[em.id]=skippedDev.map(s=>({key:s.key,summary:s.fields&&s.fields.summary}));
      log(`✓ ${issues.length} stories for ${em.id}`+(skippedDev.length?` (${skippedDev.length} technical task stories skipped: ${skippedDev.map(s=>s.key).join(', ')})`:''),'ok');
      issues.forEach(s=>log(`    • ${s.key} — ${s.fields&&s.fields.summary}`));
      if(skippedDev.length) skippedDev.forEach(s=>log(`    ⊘ ${s.key} — ${s.fields&&s.fields.summary} [SKIPPED: Technical Task]`,'warn'));
      totalStories+=issues.length;
    }
    phase(2,'done',`${totalStories} stories found`);if(totalStories===0)log(`⚠ No stories found. Check JQL permissions.`,'warn');
    phase(3,'active',`0 of ${totalStories}`);const allEpics=[];let done=0;
    for(const em of epicsMeta){
      // ── Fully cached epic: skip story-detail fetch, use cached stories ──────────
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
      // Accumulate story char counts and update cache with full story data
      const storyChars = details.reduce((s,st)=>s+(st.desc||'').length,0);
      totalCharsProcessed += storyChars;
      setEpicCache(em.id, {
        epicMeta: em, charsProcessed: (em.meta.description||'').length + storyChars,
        stories: details
      });
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
    const dataStats = {
      totalCharsProcessed,
      estimatedTokens,
      storiesFetched: totalStories,
      acCount: totalAcCount,
      cacheHits: tpCacheHitCount
    };
    log(`✓ Data processed: ~${estimatedTokens.toLocaleString()} tokens equivalent (${totalCharsProcessed.toLocaleString()} chars, ${totalStories} stories, ${totalAcCount} ACs)`,'ok');
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


// TEST CASE — GENERATE (SSE: fetch Jira data + cache, client-side logic generates cases)
// NOTE: No AI/Anthropic API call is made. The server fetches and enriches all story data,
// then returns it to the client. The frontend buildFallbackCases() function generates the
// test cases using rule-based logic — zero API tokens consumed.






// buildStorySummary and buildServerTCPrompt removed in v1.4.0
// Test case generation is now entirely client-side (buildFallbackCases in index.html)
// Zero API tokens consumed — logic-based rule-driven generation only



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
  // 0: Authenticate   1: Fetch Epics (cache-first)   2: Find Stories
  // 3: Fetch Stories  4: Fetch Confluence             5: Prepare Data for Client
  // 6: [Client-side] Generate Test Cases (Logic — no AI tokens)

  try {
    log(`╔═══ TEST CASE GENERATION ═══`);
    log(`Project: ${projectName} | Prefix: ${prefix} | Epics: ${epics.join(', ')}`);

    // ─── Phase 0: Authenticate ───────────────────────────────────────────────
    phase(0,'active','');
    const client = new AtlassianClient({email:jira.jiraEmail,apiToken:getJiraToken(jira),siteUrl:jira.siteUrl});
    const me = await client.ping();
    log(`✓ Authenticated as ${me.displayName}`,'ok');
    phase(0,'done',`${me.displayName}`);

    // ─── Phase 1: Fetch epic metadata (cache-first) ──────────────────────────
    phase(1,'active',`0 of ${epics.length}`);
    const epicsMeta = [];
    let tcTotalChars = 0;
    const fullCacheHits = [];
    for(let i=0;i<epics.length;i++){
      const id=epics[i];
      log(`Fetching epic ${i+1}/${epics.length}: ${id}`);

      // Check cache — if we have full story data, skip Jira entirely
      const cached = getEpicCache(id);
      if (cached && cached.data && cached.data.stories && cached.data.stories.length > 0) {
        const cd = cached.data;
        epicsMeta.push({ id, title: cd.epicMeta && cd.epicMeta.meta ? cd.epicMeta.meta.title : id });
        fullCacheHits.push({ id, stories: cd.stories, title: cd.epicMeta && cd.epicMeta.meta ? cd.epicMeta.meta.title : id });
        tcTotalChars += cd.charsProcessed || 0;
        log(`✓ [CACHE HIT] ${id} — ${cd.stories.length} stories loaded from cache (${cached.cachedAt})`,'ok');
        phase(1,'active',`${i+1} of ${epics.length}`);
        continue;
      }

      const epic=await client.withRetry(`getIssue(${id})`,()=>client.getIssue(id,['summary','description','status','issuetype']),CONFIG.mcp.maxRetries,log);
      const issueType = epic.fields.issuetype?.name || '';
      if (!['Epic','epic'].includes(issueType) && issueType !== '') {
        log(`✗ ${id} is a "${issueType}", not an Epic. Please enter Epic IDs only (e.g. ENG-2941).`,'err');
        send('error',{error:`${id} is a "${issueType}", not an Epic. Only Epic-type issues are supported. Check the Jira issue type and try again.`});
        return;
      }
      epicsMeta.push({id, title: epic.fields.summary});
      tcTotalChars += (adfToPlainText(epic.fields.description)||'').length;
      log(`✓ ${id}: ${epic.fields.summary} [${issueType||'Epic'}]`,'ok');
      phase(1,'active',`${i+1} of ${epics.length}`);
    }
    phase(1,'done',`${epics.length} epic(s) loaded`);

    // ─── Phase 2: Find stories under each epic ───────────────────────────────
    phase(2,'active','');
    const storyListByEpic = {};
    let totalStories = 0;
    // For cache-hit epics: record story count directly
    fullCacheHits.forEach(ch => {
      storyListByEpic[ch.id] = null; // sentinel: use cached data
      totalStories += ch.stories.length;
      log(`✓ ${ch.id}: ${ch.stories.length} stories (from cache)`,'ok');
    });
    const cacheHitIds = new Set(fullCacheHits.map(c=>c.id));
    for(const em of epicsMeta){
      if(cacheHitIds.has(em.id)) continue;
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

    // ─── Phase 3: Fetch full story details ───────────────────────────────────
    phase(3,'active',`0 of ${totalStories}`);
    const allEpics = [];
    let fetched = 0;
    // Restore cache-hit epics first
    for(const ch of fullCacheHits){
      const emMeta = epicsMeta.find(e=>e.id===ch.id);
      allEpics.push({
        id: ch.id,
        title: ch.title,
        meta: { title: ch.title },
        stories: ch.stories,
        fromCache: true
      });
      fetched += ch.stories.length;
    }
    // Fetch from Jira for non-cache epics
    for(const em of epicsMeta){
      if(cacheHitIds.has(em.id)) continue;
      const list = storyListByEpic[em.id] || [];
      let stories = [];
      if(list.length>0){
        stories = await fetchStoriesParallel(client, list, log);
        fetched += stories.length;
        phase(3,'active',`${fetched} of ${totalStories}`);
        stories.forEach(s => {
          log(`  ${s.id}: ${s.title.slice(0,50)} — ${s.desc.length} chars, ${s.ac.length} requirements`,'ok');
          tcTotalChars += (s.desc||'').length;
        });
      }
      allEpics.push({id:em.id, title:em.title, meta:{ title:em.title }, stories});
      // Save to cache for next time
      const epChars = stories.reduce((sum,s)=>sum+(s.desc||'').length,0);
      setEpicCache(em.id, {
        epicMeta: { id:em.id, meta:{ title:em.title } },
        charsProcessed: epChars,
        stories
      });
    }
    phase(3,'done',`${totalStories} stories fetched`);

    // ─── Phase 4: Fetch Confluence notes ─────────────────────────────────────
    phase(4,'active','');
    const confluenceByEpic = {};
    for(const em of epicsMeta){
      const conf = await fetchConfluenceForEpic(client, em.id, log).catch(()=>null);
      if(conf){
        confluenceByEpic[em.id]=conf;
        log(`✓ Confluence: "${conf.title}"`,'ok');
        // Attach to corresponding epic object for client use
        const ep = allEpics.find(e=>e.id===em.id);
        if(ep){ ep.confluenceContent=conf.content; ep.confluenceTitle=conf.title; }
      } else {
        log(`  No Confluence page for ${em.id}`,'info');
      }
    }
    phase(4,'done',`Confluence: ${Object.keys(confluenceByEpic).length} of ${epicsMeta.length} found`);

    // ─── Phase 5: Prepare enriched data for client-side generation ────────────
    // No AI call — the client uses buildFallbackCases() with the rule-based approach
    // from the clearlyrated-test-case-creation skill (zero API tokens consumed).
    phase(5,'active','Preparing data for client…');
    const totalAcCount = allEpics.reduce((a,e)=>a+e.stories.reduce((b,s)=>b+(s.ac&&s.ac.length>0?s.ac.length:1),0),0);
    const tcEstimatedTokens = Math.round(tcTotalChars / 4);
    log(`✓ Data ready: ${totalStories} stories, ${totalAcCount} ACs, ~${tcEstimatedTokens.toLocaleString()} tokens equivalent`,'ok');
    log(`✓ Test cases will be generated client-side using logic-based rules (0 API tokens)`,'ok');
    phase(5,'done',`${totalStories} stories ready — client generating cases`);

    log(`╚═══ DATA READY — sending to client for generation ═══`,'ok');
    send('complete',{
      projectName, release, epics, prefix,
      allEpics,
      totalStories,
      generatedBy:    req.user.fullName,
      site:           jira.siteUrl,
      generatedCases: [],          // always empty — client generates all cases
      dataStats: {
        totalCharsProcessed: tcTotalChars,
        estimatedTokens:     tcEstimatedTokens,
        storiesFetched:      totalStories,
        acCount:             totalAcCount,
        cacheHits:           fullCacheHits.length,
        apiTokensUsed:       0
      }
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

// v1.4.0: AI endpoint removed — test cases generated client-side via buildFallbackCases()
app.post('/api/testcase/ai', authMiddleware, (_req, res) => {
  res.status(501).json({ error: 'AI generation removed — test cases are now generated client-side using logic-based rules' });
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
