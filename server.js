/**
 * qubit-server — Backend proxy for the Qubit QA platform
 * Email: Mailgun HTTP API (no extra packages — uses built-in https)
 */

'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const https = require('https');

require('dotenv').config();

const CONFIG = {
  port: process.env.PORT || 4000,
  dataDir: process.env.DATA_DIR || path.join(__dirname, 'data'),
  tempDir: process.env.TEMP_DIR || path.join(__dirname, 'tmp'),
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  allowedDomains: (process.env.ALLOWED_DOMAINS || 'clearlyrated.com,thoughtminds.io').split(','),
  corsOrigin: process.env.CORS_ORIGIN || '*',
  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
  // Where your index.html is hosted (Netlify, Vercel, etc.)
  frontendUrl: (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, ''),
  // Mailgun config — set these as environment variables in Render
  mailgun: {
    apiKey:  process.env.MAILGUN_API_KEY  || '',   // Private API Key from Mailgun dashboard
    domain:  process.env.MAILGUN_DOMAIN   || '',   // e.g. crmail.clearlyrated.com
    from:    process.env.MAILGUN_FROM     || 'Qubit QA Platform <noreply@mg.clearlyrated.com>',
    region:  process.env.MAILGUN_REGION   || 'us', // 'us' or 'eu'
  },
  inviteExpiryMs:   7 * 24 * 60 * 60 * 1000,   // 7 days  (team invite)
  regTokenExpiryMs: 24 * 60 * 60 * 1000,        // 24 hours (self-registration)
  mcp: {
    timeout:         parseInt(process.env.MCP_TIMEOUT_MS       || '300000', 10),
    maxRetries:      parseInt(process.env.MCP_MAX_RETRIES      || '5',      10),
    parallelWorkers: parseInt(process.env.MCP_PARALLEL_WORKERS || '3',      10),
  }
};

[CONFIG.dataDir, CONFIG.tempDir].forEach(d => {
  if (!fsSync.existsSync(d)) fsSync.mkdirSync(d, { recursive: true });
});

const DB = {
  usersFile:    path.join(CONFIG.dataDir, 'users.json'),
  sessionsFile: path.join(CONFIG.dataDir, 'sessions.json'),
  connectorsFile: path.join(CONFIG.dataDir, 'connectors.json'),
  planIndexFile:  path.join(CONFIG.dataDir, 'plan-index.json'),
  statsFile:    path.join(CONFIG.dataDir, 'stats.json'),
  invitesFile:  path.join(CONFIG.dataDir, 'invites.json')
};

async function readJson(file, fallback = {}) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch { return fallback; }
}
async function writeJson(file, data) {
  const tmp = file + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
  await fs.rename(tmp, file);
}

// ─── Mailgun HTTP API (no npm package needed) ─────────────────────────────────
function sendMailgunEmail({ to, subject, html, text }) {
  return new Promise((resolve, reject) => {
    const { apiKey, domain, from, region } = CONFIG.mailgun;
    if (!apiKey || !domain) {
      return reject(new Error(
        'Mailgun is not configured. Add MAILGUN_API_KEY and MAILGUN_DOMAIN ' +
        'to your Render environment variables.'
      ));
    }

    // Build URL-encoded form body (Mailgun messages API)
    const params = new URLSearchParams({ from, to, subject, text, html });
    const body = params.toString();

    const hostname = region === 'eu' ? 'api.eu.mailgun.net' : 'api.mailgun.net';
    const auth     = Buffer.from(`api:${apiKey}`).toString('base64');

    const options = {
      hostname,
      path:   `/v3/${domain}/messages`,
      method: 'POST',
      headers: {
        'Authorization':  `Basic ${auth}`,
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 15000,
    };

    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(raw)); } catch { resolve({ id: 'sent' }); }
        } else {
          reject(new Error(`Mailgun API error ${res.statusCode}: ${raw.slice(0, 300)}`));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Mailgun request timed out')); });
    req.write(body);
    req.end();
  });
}

// ─── Registration email template ─────────────────────────────────────────────
function buildRegistrationEmail(toEmail, registrationUrl) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Complete your Qubit registration</title></head>
<body style="margin:0;padding:0;background:#f2f3fb;font-family:'Segoe UI',Arial,sans-serif;-webkit-font-smoothing:antialiased">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f3fb;padding:40px 16px">
  <tr><td align="center">
    <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 32px rgba(0,0,0,.10)">

      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#7c3aed 0%,#a855f7 55%,#ec4899 100%);padding:36px 40px 28px;text-align:center">
        <table cellpadding="0" cellspacing="0" style="margin:0 auto 18px">
          <tr><td style="width:56px;height:56px;background:rgba(255,255,255,.18);border-radius:14px;text-align:center;vertical-align:middle;font-size:28px">&#128737;</td></tr>
        </table>
        <h1 style="color:#ffffff;font-size:24px;font-weight:800;margin:0 0 6px;letter-spacing:-.3px">Qubit QA Platform</h1>
        <p style="color:rgba(255,255,255,.85);font-size:14px;margin:0;font-weight:500">Intelligent Test Planning</p>
      </td></tr>

      <!-- Body -->
      <tr><td style="padding:40px 40px 32px">
        <h2 style="color:#0f1017;font-size:20px;font-weight:800;margin:0 0 10px;letter-spacing:-.2px">Complete your registration</h2>
        <p style="color:#5c6278;font-size:14.5px;line-height:1.65;margin:0 0 28px">
          Hi there,<br><br>
          You requested to create a <strong style="color:#0f1017">Qubit QA Platform</strong> account for
          <strong style="color:#7c3aed">${toEmail}</strong>.
          Click the button below to complete your setup &mdash; it only takes a minute.
        </p>

        <!-- CTA Button -->
        <table cellpadding="0" cellspacing="0" width="100%">
          <tr><td align="center" style="padding:4px 0 32px">
            <a href="${registrationUrl}"
               style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#ffffff;text-decoration:none;font-size:15px;font-weight:700;padding:15px 40px;border-radius:10px;box-shadow:0 4px 18px rgba(124,58,237,.35);letter-spacing:.1px">
              Complete Registration &rarr;
            </a>
          </td></tr>
        </table>

        <!-- Info box -->
        <table cellpadding="0" cellspacing="0" width="100%" style="background:#f8f7ff;border:1px solid rgba(124,58,237,.14);border-radius:10px">
          <tr><td style="padding:18px 22px">
            <p style="font-size:13px;color:#5c6278;margin:0 0 8px"><strong style="color:#7c3aed">&#9200; Expires in:</strong>&nbsp; 24 hours</p>
            <p style="font-size:13px;color:#5c6278;margin:0 0 8px"><strong style="color:#7c3aed">&#128231; For email:</strong>&nbsp; ${toEmail}</p>
            <p style="font-size:13px;color:#5c6278;margin:0"><strong style="color:#7c3aed">&#128274; One-time use:</strong>&nbsp; Link is invalidated after registration</p>
          </td></tr>
        </table>

        <p style="color:#9498b0;font-size:12.5px;line-height:1.65;margin:24px 0 0">
          Didn&apos;t request this? You can safely ignore this email &mdash; no account will be created without completing registration.
        </p>
        <p style="color:#9498b0;font-size:12px;line-height:1.65;margin:12px 0 0;word-break:break-all">
          Button not working? Paste this link into your browser:<br>
          <a href="${registrationUrl}" style="color:#7c3aed">${registrationUrl}</a>
        </p>
      </td></tr>

      <!-- Footer -->
      <tr><td style="background:#f8f7ff;border-top:1px solid #ebe9f8;padding:20px 40px;text-align:center">
        <p style="color:#9498b0;font-size:12px;margin:0 0 4px;font-weight:600">Qubit QA Platform</p>
        <p style="color:#b8bcd0;font-size:11.5px;margin:0">This is an automated message &mdash; please do not reply.</p>
      </td></tr>

    </table>
    <p style="color:#b8bcd0;font-size:11px;text-align:center;margin:16px 0 0">&copy; ${new Date().getFullYear()} Qubit QA Platform. All rights reserved.</p>
  </td></tr>
</table>
</body>
</html>`;

  const text = [
    'Complete your Qubit QA Platform registration',
    '',
    `Hi,`,
    '',
    `You requested to create a Qubit account for ${toEmail}.`,
    `Click the link below to complete registration (expires in 24 hours):`,
    '',
    registrationUrl,
    '',
    "If you didn't request this, you can safely ignore this email.",
    '',
    '— Qubit QA Platform',
  ].join('\n');

  return { html, text };
}

async function sendRegistrationEmail(toEmail, registrationUrl) {
  const { html, text } = buildRegistrationEmail(toEmail, registrationUrl);
  const result = await sendMailgunEmail({
    to:      toEmail,
    subject: 'Complete your Qubit registration',
    html,
    text,
  });
  console.log(`[mailgun] Registration email sent → ${toEmail} (id: ${result.id || 'ok'})`);
  return result;
}


function hashPassword(pwd, email) {
  return crypto.createHash('sha256').update(pwd + '|qubit-server|' + email.toLowerCase()).digest('hex');
}
function createToken() { return crypto.randomBytes(32).toString('hex'); }
function domainOk(email) {
  const d = (email || '').split('@')[1];
  return CONFIG.allowedDomains.includes((d || '').toLowerCase());
}
function passwordValid(p) {
  return p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p);
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  const sessions = await readJson(DB.sessionsFile);
  const session = sessions[token];
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  if (Date.now() - session.createdAt > 7 * 24 * 60 * 60 * 1000) {
    delete sessions[token];
    await writeJson(DB.sessionsFile, sessions);
    return res.status(401).json({ error: 'Session expired' });
  }
  const users = await readJson(DB.usersFile);
  const user = users[session.email];
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  req.token = token;
  req.session = session;
  next();
}

// ─── Stats helpers ──────────────────────────────────────────────────────────
async function recordStat(email, type) {
  const stats = await readJson(DB.statsFile, { global: {}, byUser: {} });
  if (!stats.global) stats.global = {};
  if (!stats.byUser) stats.byUser = {};
  // Global totals
  stats.global[type] = (stats.global[type] || 0) + 1;
  // Per-user totals + history
  if (!stats.byUser[email]) stats.byUser[email] = { testPlans: 0, testCases: 0, autoScripts: 0, history: [] };
  stats.byUser[email][type] = (stats.byUser[email][type] || 0) + 1;
  stats.byUser[email].history.push({ date: new Date().toISOString().slice(0, 10), type });
  // Keep only last 365 history entries per user
  if (stats.byUser[email].history.length > 365) {
    stats.byUser[email].history = stats.byUser[email].history.slice(-365);
  }
  await writeJson(DB.statsFile, stats);
}

function buildChartData(allHistory) {
  // Last 6 months, all users combined
  const now = new Date();
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    months.push({ key: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`, label: d.toLocaleString('default', { month: 'short', year: '2-digit' }) });
  }
  const buckets = { testPlans: {}, testCases: {}, autoScripts: {} };
  months.forEach(m => { buckets.testPlans[m.key] = 0; buckets.testCases[m.key] = 0; buckets.autoScripts[m.key] = 0; });
  allHistory.forEach(({ date, type }) => {
    const mk = date.slice(0, 7);
    if (buckets[type] && buckets[type][mk] !== undefined) buckets[type][mk]++;
  });
  return {
    labels: months.map(m => m.label),
    testPlans: months.map(m => buckets.testPlans[m.key]),
    testCases: months.map(m => buckets.testCases[m.key]),
    autoScripts: months.map(m => buckets.autoScripts[m.key])
  };
}

// ─── Google token verification ───────────────────────────────────────────────
function verifyGoogleToken(idToken) {
  return new Promise((resolve, reject) => {
    const url = `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`;
    const u = new URL(url);
    const opts = { hostname: u.hostname, path: u.pathname + u.search, method: 'GET', headers: { Accept: 'application/json' } };
    const req = https.request(opts, res => {
      let chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (data.error_description || data.error) return reject(new Error(data.error_description || data.error));
          if (CONFIG.googleClientId && data.aud !== CONFIG.googleClientId) return reject(new Error('Token audience mismatch'));
          resolve(data);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Google token verify timeout')); });
    req.end();
  });
}

class AtlassianClient {
  constructor({ email, apiToken, siteUrl }) {
    this.email = email;
    this.apiToken = apiToken;
    this.siteUrl = siteUrl;
    this.timeout = CONFIG.mcp.timeout;
  }
  _authHeader() {
    const b64 = Buffer.from(`${this.email}:${this.apiToken}`).toString('base64');
    return `Basic ${b64}`;
  }
  _request(method, urlPath, body) {
    return new Promise((resolve, reject) => {
      const url = new URL(urlPath, `https://${this.siteUrl}`);
      const opts = {
        method,
        hostname: url.hostname,
        path: url.pathname + url.search,
        headers: {
          Authorization: this._authHeader(),
          Accept: 'application/json',
          'User-Agent': 'qubit-server/1.0'
        },
        timeout: this.timeout
      };
      if (body) {
        const payload = JSON.stringify(body);
        opts.headers['Content-Type'] = 'application/json';
        opts.headers['Content-Length'] = Buffer.byteLength(payload);
      }
      const req = https.request(opts, res => {
        let chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try { resolve(JSON.parse(raw)); } catch { resolve(raw); }
          } else {
            const err = new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 300)}`);
            err.statusCode = res.statusCode;
            reject(err);
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout ${this.timeout}ms`)); });
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }
  async withRetry(label, fn, maxRetries = CONFIG.mcp.maxRetries, onLog) {
    let attempt = 0; let lastErr;
    while (attempt < maxRetries) {
      try { return await fn(); }
      catch (err) {
        attempt++; lastErr = err;
        if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500 && err.statusCode !== 429) throw err;
        const backoff = Math.min(1000 * Math.pow(2, attempt - 1), 8000);
        if (onLog) onLog(`⚠ ${label} attempt ${attempt} failed (${err.message}) — retry in ${Math.round(backoff/1000)}s`, 'warn');
        await new Promise(r => setTimeout(r, backoff));
      }
    }
    throw new Error(`${label} failed after ${maxRetries} retries: ${lastErr.message}`);
  }
  async ping() { return this._request('GET', '/rest/api/3/myself'); }
  async getIssue(issueKey, fields) {
    const fieldParam = fields ? `?fields=${fields.join(',')}` : '';
    return this._request('GET', `/rest/api/3/issue/${issueKey}${fieldParam}`);
  }
  async searchByJql(jql, fields = ['summary', 'status', 'issuetype'], maxResults = 100) {
    const allIssues = [];
    let nextPageToken = null;
    let safetyCounter = 0;
    const maxPages = 10;
    do {
      const payload = { jql, fields, maxResults };
      if (nextPageToken) payload.nextPageToken = nextPageToken;
      const res = await this._request('POST', '/rest/api/3/search/jql', payload);
      if (Array.isArray(res.issues)) allIssues.push(...res.issues);
      nextPageToken = res.nextPageToken || null;
      safetyCounter++;
      if (res.isLast === true) break;
      if (!nextPageToken) break;
      if (safetyCounter >= maxPages) break;
    } while (true);
    return { issues: allIssues };
  }
}

function adfToPlainText(adf) {
  if (!adf) return '';
  if (typeof adf === 'string') return adf;
  if (!adf.content) return '';
  let out = '';
  const walk = node => {
    if (node.type === 'text' && node.text) out += node.text;
    if (node.type === 'hardBreak') out += '\n';
    if (node.type === 'paragraph' || node.type === 'heading') {
      (node.content || []).forEach(walk); out += '\n';
    } else if (node.type === 'bulletList' || node.type === 'orderedList') {
      (node.content || []).forEach(item => {
        out += '• '; (item.content || []).forEach(walk); out += '\n';
      });
    } else if (node.content) node.content.forEach(walk);
  };
  adf.content.forEach(walk);
  return out.trim();
}

function extractAcceptanceCriteria(descText) {
  if (!descText) return [];
  const lines = descText.split('\n').map(l => l.trim()).filter(Boolean);
  const bullets = [];
  let inAcSection = false;
  for (const line of lines) {
    if (/^(acceptance criteria|requirements|ac:|scenarios)/i.test(line)) { inAcSection = true; continue; }
    if (inAcSection) {
      if (/^(#|##|background|notes?|open questions|out of scope)/i.test(line)) { inAcSection = false; continue; }
      const m = line.match(/^[•\-\*]\s*(.+)/) || line.match(/^\d+\.\s*(.+)/);
      if (m) bullets.push(m[1].trim());
    }
  }
  if (bullets.length === 0) {
    for (const line of lines) {
      const m = line.match(/^[•\-\*]\s*(.{15,})/);
      if (m) bullets.push(m[1].trim());
      if (bullets.length >= 8) break;
    }
  }
  return bullets.slice(0, 10);
}

async function fetchStoriesParallel(client, stories, onLog) {
  const workerCount = Math.min(CONFIG.mcp.parallelWorkers, stories.length);
  const results = new Array(stories.length);
  let idx = 0;
  if (onLog) onLog(`▶ ${workerCount} parallel workers for ${stories.length} stories`, 'info');
  const worker = async workerId => {
    while (idx < stories.length) {
      const i = idx++;
      if (i >= stories.length) return;
      const story = stories[i];
      if (onLog) onLog(`  worker-${workerId} → fetching ${story.key}`);
      try {
        const detail = await client.withRetry(`getIssue(${story.key})`,
          () => client.getIssue(story.key, ['summary', 'description', 'status']),
          CONFIG.mcp.maxRetries, onLog);
        const descText = adfToPlainText(detail.fields.description);
        results[i] = {
          id: detail.key,
          title: detail.fields.summary,
          desc: descText.slice(0, 500),
          ac: extractAcceptanceCriteria(descText)
        };
        if (onLog) onLog(`  worker-${workerId} ✓ ${story.key} (${i + 1}/${stories.length})`, 'ok');
      } catch (err) {
        if (onLog) onLog(`  worker-${workerId} ✗ ${story.key} — ${err.message}`, 'err');
        results[i] = {
          id: story.key,
          title: (story.fields && story.fields.summary) || story.key,
          desc: '(description unavailable)',
          ac: ['Acceptance criteria unavailable']
        };
      }
    }
  };
  const workers = [];
  for (let w = 1; w <= workerCount; w++) workers.push(worker(w));
  await Promise.all(workers);
  return results;
}

const app = express();
app.use(cors({ origin: CONFIG.corsOrigin, credentials: true }));
app.use(express.json({ limit: '5mb' }));
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ══════════════════════════════════════════════════════════
// AUTH — REGISTER (supports optional invite token)
// ══════════════════════════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone, org, role, password, avatar, inviteToken } = req.body || {};
  if (!firstName || !lastName || !email || !org || !role || !password) return res.status(400).json({ error: 'Missing required fields' });
  if (!domainOk(email)) return res.status(403).json({ error: `Only ${CONFIG.allowedDomains.join(' / ')} emails allowed` });
  if (!passwordValid(password)) return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, number, symbol' });

  // Validate invite token if provided
  const emailLower = email.toLowerCase();
  if (inviteToken) {
    const invites = await readJson(DB.invitesFile);
    const invite = invites[inviteToken];
    if (!invite) return res.status(400).json({ error: 'Invalid or expired invite link' });
    if (Date.now() > invite.expiresAt) {
      delete invites[inviteToken];
      await writeJson(DB.invitesFile, invites);
      return res.status(400).json({ error: 'Invite link has expired' });
    }
    if (invite.email.toLowerCase() !== emailLower) return res.status(400).json({ error: 'Email does not match invite' });
    // Consume invite
    delete invites[inviteToken];
    await writeJson(DB.invitesFile, invites);
  }

  const users = await readJson(DB.usersFile);
  if (users[emailLower]) return res.status(409).json({ error: 'Account already exists' });
  const initials = (firstName[0] + lastName[0]).toUpperCase();
  const user = {
    firstName, lastName, fullName: `${firstName} ${lastName}`,
    email: emailLower, phone: phone || '', org, role, bio: '', initials,
    avatar: avatar || { type: 'initials' },
    passwordHash: hashPassword(password, emailLower),
    createdAt: new Date().toISOString()
  };
  users[emailLower] = user;
  await writeJson(DB.usersFile, users);
  const token = createToken();
  const sessions = await readJson(DB.sessionsFile);
  sessions[token] = { email: emailLower, createdAt: Date.now() };
  await writeJson(DB.sessionsFile, sessions);
  const { passwordHash, ...publicUser } = user;
  res.json({ user: publicUser, token });
});

// ══════════════════════════════════════════════════════════
// AUTH — LOGIN
// ══════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
  const emailLower = email.toLowerCase();
  const users = await readJson(DB.usersFile);
  const user = users[emailLower];
  if (!user || user.passwordHash !== hashPassword(password, emailLower)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = createToken();
  const sessions = await readJson(DB.sessionsFile);
  sessions[token] = { email: emailLower, createdAt: Date.now() };
  await writeJson(DB.sessionsFile, sessions);
  const { passwordHash, ...publicUser } = user;
  res.json({ user: publicUser, token });
});

// ══════════════════════════════════════════════════════════
// AUTH — GOOGLE SSO
// ══════════════════════════════════════════════════════════
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'Google credential required' });
  let payload;
  try {
    payload = await verifyGoogleToken(credential);
  } catch (err) {
    return res.status(401).json({ error: `Google verification failed: ${err.message}` });
  }
  const email = (payload.email || '').toLowerCase();
  if (!email) return res.status(400).json({ error: 'No email in Google token' });
  if (!domainOk(email)) return res.status(403).json({ error: `Only ${CONFIG.allowedDomains.join(' / ')} accounts allowed` });

  const users = await readJson(DB.usersFile);
  let user = users[email];
  if (!user) {
    // Auto-create user from Google profile
    const firstName = payload.given_name || email.split('@')[0];
    const lastName = payload.family_name || '';
    const initials = ((firstName[0] || '') + (lastName[0] || '')).toUpperCase() || '?';
    user = {
      firstName, lastName, fullName: payload.name || firstName,
      email, phone: '', org: email.split('@')[1], role: 'Other', bio: '', initials,
      avatar: payload.picture ? { type: 'photo', data: payload.picture } : { type: 'initials' },
      passwordHash: '',
      googleSub: payload.sub,
      createdAt: new Date().toISOString()
    };
    users[email] = user;
    await writeJson(DB.usersFile, users);
  }
  const token = createToken();
  const sessions = await readJson(DB.sessionsFile);
  sessions[token] = { email, createdAt: Date.now() };
  await writeJson(DB.sessionsFile, sessions);
  const { passwordHash, ...publicUser } = user;
  res.json({ user: publicUser, token });
});

// ══════════════════════════════════════════════════════════
// AUTH — SELF-SERVICE REGISTRATION REQUEST (sends real email)
// ══════════════════════════════════════════════════════════
app.post('/api/auth/request-register', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const emailLower = email.toLowerCase().trim();
  if (!domainOk(emailLower)) {
    return res.status(403).json({ error: `Only ${CONFIG.allowedDomains.join(' / ')} emails are allowed` });
  }
  const users = await readJson(DB.usersFile);
  if (users[emailLower]) {
    return res.status(409).json({ error: 'An account already exists for this email. Please sign in.' });
  }

  // Reuse existing non-expired token for same email
  const invites = await readJson(DB.invitesFile);
  let token = null;
  const existing = Object.entries(invites).find(([, v]) => v.email === emailLower && Date.now() < v.expiresAt);
  if (existing) {
    token = existing[0];
  } else {
    token = createToken();
    invites[token] = {
      email: emailLower,
      invitedBy: null,
      createdAt: Date.now(),
      expiresAt: Date.now() + CONFIG.regTokenExpiryMs
    };
    await writeJson(DB.invitesFile, invites);
  }

  const registrationUrl = `${CONFIG.frontendUrl}/?register=${token}`;

  try {
    await sendRegistrationEmail(emailLower, registrationUrl);
    console.log(`[register] Email dispatched → ${emailLower}`);
    res.json({ ok: true, email: emailLower });
  } catch (err) {
    console.error('[register] Email send failed:', err.message);
    const is401 = err.message.includes('401');
    res.status(500).json({
      error: is401
        ? 'Mailgun authentication failed (401). Your MAILGUN_API_KEY is wrong — make sure you are using the Private API Key from the Mailgun dashboard, NOT the SMTP password.'
        : 'Failed to send registration email: ' + err.message,
      hint: 'Mailgun dashboard → Settings → API Keys → Private API key (starts with key-...)'
    });
  }
});

app.get('/api/auth/register-token/:token', async (req, res) => {
  const invites = await readJson(DB.invitesFile);
  const invite = invites[req.params.token];
  if (!invite) return res.status(404).json({ error: 'Invalid registration link' });
  if (Date.now() > invite.expiresAt) {
    delete invites[req.params.token];
    await writeJson(DB.invitesFile, invites);
    return res.status(410).json({ error: 'Registration link has expired. Please request a new one.' });
  }
  res.json({ email: invite.email, expiresAt: invite.expiresAt });
});

// ══════════════════════════════════════════════════════════
// AUTH — INVITE (create + verify) — for logged-in users
// ══════════════════════════════════════════════════════════
app.post('/api/auth/invite', authMiddleware, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const emailLower = email.toLowerCase();
  if (!domainOk(emailLower)) return res.status(403).json({ error: `Only ${CONFIG.allowedDomains.join(' / ')} emails allowed` });
  const users = await readJson(DB.usersFile);
  if (users[emailLower]) return res.status(409).json({ error: 'User already exists with this email' });

  const invites = await readJson(DB.invitesFile);
  // Check for existing non-expired invite
  const existing = Object.entries(invites).find(([, v]) => v.email === emailLower && Date.now() < v.expiresAt);
  if (existing) {
    const inviteUrl = `${CONFIG.frontendUrl}/?register=${existing[0]}`;
    return res.json({ ok: true, inviteUrl, expiresAt: invites[existing[0]].expiresAt, reused: true });
  }

  const token = createToken();
  invites[token] = {
    email: emailLower,
    invitedBy: req.user.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + CONFIG.inviteExpiryMs
  };
  await writeJson(DB.invitesFile, invites);
  const inviteUrl = `${CONFIG.frontendUrl}/?register=${token}`;
  console.log(`[invite] ${req.user.email} invited ${emailLower} → ${inviteUrl}`);
  res.json({ ok: true, inviteUrl, expiresAt: invites[token].expiresAt });
});

app.get('/api/auth/invite/:token', async (req, res) => {
  const invites = await readJson(DB.invitesFile);
  const invite = invites[req.params.token];
  if (!invite) return res.status(404).json({ error: 'Invalid invite link' });
  if (Date.now() > invite.expiresAt) {
    delete invites[req.params.token];
    await writeJson(DB.invitesFile, invites);
    return res.status(410).json({ error: 'Invite link has expired' });
  }
  res.json({ email: invite.email, invitedBy: invite.invitedBy, expiresAt: invite.expiresAt });
});

// ══════════════════════════════════════════════════════════
// AUTH — LOGOUT / ME / PROFILE / PASSWORD
// ══════════════════════════════════════════════════════════
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  const sessions = await readJson(DB.sessionsFile);
  delete sessions[req.token];
  await writeJson(DB.sessionsFile, sessions);
  res.json({ ok: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { passwordHash, ...publicUser } = req.user;
  res.json({ user: publicUser });
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const { firstName, lastName, org, role, phone, bio, avatar } = req.body || {};
  const users = await readJson(DB.usersFile);
  const user = users[req.user.email];
  if (firstName) user.firstName = firstName;
  if (lastName) user.lastName = lastName;
  if (firstName && lastName) {
    user.fullName = `${firstName} ${lastName}`;
    user.initials = (firstName[0] + lastName[0]).toUpperCase();
  }
  if (org !== undefined) user.org = org;
  if (role !== undefined) user.role = role;
  if (phone !== undefined) user.phone = phone;
  if (bio !== undefined) user.bio = bio;
  if (avatar !== undefined) user.avatar = avatar;
  await writeJson(DB.usersFile, users);
  const { passwordHash, ...publicUser } = user;
  res.json({ user: publicUser });
});

app.post('/api/auth/password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Both old and new password required' });
  const users = await readJson(DB.usersFile);
  const user = users[req.user.email];
  if (!user || user.passwordHash !== hashPassword(oldPassword, req.user.email)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (!passwordValid(newPassword)) {
    return res.status(400).json({ error: 'New password must be 8+ chars with uppercase, lowercase, number, and symbol' });
  }
  if (oldPassword === newPassword) {
    return res.status(400).json({ error: 'New password must be different from current password' });
  }
  user.passwordHash = hashPassword(newPassword, req.user.email);
  await writeJson(DB.usersFile, users);
  // Invalidate all existing sessions except current
  const sessions = await readJson(DB.sessionsFile);
  Object.keys(sessions).forEach(t => {
    if (sessions[t].email === req.user.email && t !== req.token) delete sessions[t];
  });
  await writeJson(DB.sessionsFile, sessions);
  res.json({ ok: true, message: 'Password updated successfully' });
});

// ══════════════════════════════════════════════════════════
// STATS DASHBOARD
// ══════════════════════════════════════════════════════════
app.get('/api/stats/dashboard', authMiddleware, async (req, res) => {
  const stats = await readJson(DB.statsFile, { global: {}, byUser: {} });
  const myStats = stats.byUser[req.user.email] || { testPlans: 0, testCases: 0, autoScripts: 0, history: [] };
  const globalStats = stats.global || { testPlans: 0, testCases: 0, autoScripts: 0 };

  // Aggregate all-user history for chart
  const allHistory = [];
  Object.values(stats.byUser || {}).forEach(u => (u.history || []).forEach(h => allHistory.push(h)));

  const chart = buildChartData(allHistory);

  // Also count registered users
  const users = await readJson(DB.usersFile);
  const totalUsers = Object.keys(users).length;

  res.json({
    my: { testPlans: myStats.testPlans || 0, testCases: myStats.testCases || 0, autoScripts: myStats.autoScripts || 0 },
    global: { testPlans: globalStats.testPlans || 0, testCases: globalStats.testCases || 0, autoScripts: globalStats.autoScripts || 0, users: totalUsers },
    chart
  });
});

// ══════════════════════════════════════════════════════════
// CONNECTORS
// ══════════════════════════════════════════════════════════
app.get('/api/connectors/status', authMiddleware, async (req, res) => {
  const all = await readJson(DB.connectorsFile);
  const mine = all[req.user.email] || {};
  const safe = {};
  Object.keys(mine).forEach(k => {
    safe[k] = { connected: mine[k].connected, method: mine[k].method, connectedAt: mine[k].connectedAt };
  });
  res.json({ connectors: safe });
});

app.post('/api/connectors/jira/connect', authMiddleware, async (req, res) => {
  const { apiToken, email: jiraEmail, siteUrl } = req.body || {};
  if (!apiToken || !jiraEmail || !siteUrl) return res.status(400).json({ error: 'apiToken, email, siteUrl required' });
  const normalizedSite = siteUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const client = new AtlassianClient({ email: jiraEmail, apiToken, siteUrl: normalizedSite });
  try {
    const me = await client.ping();
    const all = await readJson(DB.connectorsFile);
    if (!all[req.user.email]) all[req.user.email] = {};
    all[req.user.email].jira = {
      connected: true, method: 'token', connectedAt: new Date().toISOString(),
      apiToken, jiraEmail, siteUrl: normalizedSite,
      accountId: me.accountId, displayName: me.displayName
    };
    await writeJson(DB.connectorsFile, all);
    res.json({ connected: true, method: 'token',
      jiraUser: { accountId: me.accountId, displayName: me.displayName, email: me.emailAddress } });
  } catch (err) {
    res.status(401).json({ error: `Jira auth failed: ${err.message}` });
  }
});

app.post('/api/connectors/jira/test', authMiddleware, async (req, res) => {
  const all = await readJson(DB.connectorsFile);
  const jira = (all[req.user.email] || {}).jira;
  if (!jira || !jira.connected) return res.status(400).json({ error: 'Jira not connected' });
  const steps = [];
  const logStep = (ok, msg) => steps.push({ ok, msg, ts: Date.now() });
  try {
    const t0 = Date.now();
    logStep(true, `Pinging ${jira.siteUrl}`);
    const client = new AtlassianClient({ email: jira.jiraEmail, apiToken: jira.apiToken, siteUrl: jira.siteUrl });
    const me = await client.ping();
    logStep(true, `Authenticated as ${me.displayName}`);
    const probe = await client.searchByJql('issuetype = Epic ORDER BY created DESC', ['summary'], 1);
    logStep(true, `Probe JQL returned ${probe.issues.length} result(s)`);
    const latency = Date.now() - t0;
    logStep(true, `Latency: ${latency}ms`);
    res.json({ ok: true, steps, latency, jiraUser: me.displayName });
  } catch (err) {
    logStep(false, err.message);
    res.status(500).json({ ok: false, steps, error: err.message });
  }
});

app.delete('/api/connectors/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const all = await readJson(DB.connectorsFile);
  if (all[req.user.email] && all[req.user.email][id]) {
    delete all[req.user.email][id];
    await writeJson(DB.connectorsFile, all);
  }
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════
// TEST PLAN — GENERATE (with stats recording)
// ══════════════════════════════════════════════════════════
app.post('/api/testplan/generate', authMiddleware, async (req, res) => {
  const { projectName, release, epics, context } = req.body || {};
  if (!projectName || !Array.isArray(epics) || epics.length === 0) return res.status(400).json({ error: 'projectName and non-empty epics[] required' });
  const allConns = await readJson(DB.connectorsFile);
  const jira = (allConns[req.user.email] || {}).jira;
  if (!jira || !jira.connected) return res.status(400).json({ error: 'Jira connector not configured' });
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (event, data) => {
    try {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    } catch (e) { console.error('SSE write failed:', e.message); }
  };
  const log = (msg, level = 'info') => send('log', { msg, level, ts: Date.now() });
  const phase = (idx, state, sub) => send('phase', { idx, state, sub });

  const heartbeat = setInterval(() => {
    try { res.write(': heartbeat\n\n'); } catch (e) {}
  }, 15000);

  try {
    log(`╔═══ TEST PLAN GENERATION STARTED ═══`);
    log(`Project: ${projectName} · Epics: ${epics.join(', ')}`);
    const client = new AtlassianClient({ email: jira.jiraEmail, apiToken: jira.apiToken, siteUrl: jira.siteUrl });
    phase(0, 'active', '');
    const me = await client.ping();
    log(`✓ Authenticated as ${me.displayName}`, 'ok');
    phase(0, 'done', `✓ ${me.displayName}`);
    phase(1, 'active', `0 of ${epics.length}`);
    const epicsMeta = [];
    for (let i = 0; i < epics.length; i++) {
      const id = epics[i];
      log(`──── Epic ${i + 1}/${epics.length}: ${id} ────`);
      const epic = await client.withRetry(`getIssue(${id})`,
        () => client.getIssue(id, ['summary', 'description', 'status', 'assignee', 'reporter', 'duedate', 'priority']),
        CONFIG.mcp.maxRetries, log);
      const descText = adfToPlainText(epic.fields.description);
      const epicData = {
        key: epic.key, title: epic.fields.summary,
        description: descText.slice(0, 800),
        status: (epic.fields.status && epic.fields.status.name) || 'Unknown',
        assignee: (epic.fields.assignee && epic.fields.assignee.displayName) || 'Unassigned',
        reporter: (epic.fields.reporter && epic.fields.reporter.displayName) || 'Unknown',
        dueDate: epic.fields.duedate || 'TBD',
        priority: (epic.fields.priority && epic.fields.priority.name) || 'Medium'
      };
      epicsMeta.push({ id, meta: epicData });
      log(`✓ Epic loaded: ${epicData.title}`, 'ok');
      phase(1, 'active', `${i + 1} of ${epics.length}`);
    }
    phase(1, 'done', `${epics.length} epics fetched`);
    phase(2, 'active', '');
    const storyListByEpic = {};
    let totalStories = 0;
    for (const em of epicsMeta) {
      const jql = `parent in (${em.id}) AND issuetype = Story`;
      log(`JQL: "${jql}"`);
      const searchResult = await client.withRetry(`searchByJql(${em.id})`,
        () => client.searchByJql(jql, ['summary', 'status', 'issuetype'], 100),
        CONFIG.mcp.maxRetries, log);
      const issues = searchResult.issues || [];
      storyListByEpic[em.id] = issues;
      log(`✓ ${issues.length} stories for ${em.id}`, 'ok');
      issues.forEach(s => log(`    • ${s.key} — ${s.fields && s.fields.summary}`));
      totalStories += issues.length;
    }
    phase(2, 'done', `${totalStories} stories found`);

    if (totalStories === 0) {
      log(`⚠ No stories found for the given epics. Check JQL permissions or epic IDs.`, 'warn');
    }

    phase(3, 'active', `0 of ${totalStories}`);
    const allEpics = [];
    let done = 0;
    for (const em of epicsMeta) {
      const list = storyListByEpic[em.id];
      const details = list.length > 0 ? await fetchStoriesParallel(client, list, log) : [];
      allEpics.push({ id: em.id, meta: em.meta, stories: details });
      done += list.length;
      phase(3, 'active', `${done} of ${totalStories}`);
    }
    phase(3, 'done', `${totalStories} stories enriched`);
    phase(4, 'active', 'writing summary.json');
    const planId = crypto.randomBytes(8).toString('hex');
    const summary = {
      id: planId,
      generatedAt: new Date().toISOString(),
      generatedBy: req.user.email,
      project: projectName,
      release: release || 'Unscheduled',
      context: context || '',
      site: jira.siteUrl,
      jiraUser: me.displayName,
      epics: allEpics.map(e => ({
        epicKey: e.id, epicTitle: e.meta.title,
        epicDescription: e.meta.description, epicStatus: e.meta.status,
        epicAssignee: e.meta.assignee, epicReporter: e.meta.reporter,
        epicDueDate: e.meta.dueDate,
        stories: e.stories.map(s => ({
          storyKey: s.id, storyTitle: s.title,
          description: s.desc, acceptanceCriteria: s.ac
        }))
      })),
      totals: {
        epics: allEpics.length, stories: totalStories,
        acceptanceCriteria: allEpics.reduce((a, e) => a + e.stories.reduce((b, s) => b + s.ac.length, 0), 0)
      }
    };
    const summaryFile = path.join(CONFIG.tempDir, `qubit_epic_summary_${planId}.json`);
    await fs.writeFile(summaryFile, JSON.stringify(summary, null, 2));
    log(`✓ Summary file written`, 'ok');
    phase(4, 'done', 'summary.json written');
    const index = await readJson(DB.planIndexFile);
    if (!index[req.user.email]) index[req.user.email] = [];
    index[req.user.email].push({ planId, project: projectName, epics, summaryFile, generatedAt: summary.generatedAt });
    await writeJson(DB.planIndexFile, index);

    // Record stat
    try { await recordStat(req.user.email, 'testPlans'); } catch (e) { console.error('stat record failed:', e.message); }

    phase(5, 'active', 'synthesizing');
    phase(5, 'done', 'complete');
    log(`╚═══ GENERATION COMPLETE ═══`, 'ok');
    send('complete', {
      planId, summary,
      stats: {
        epics: summary.totals.epics, stories: summary.totals.stories,
        scenarios: summary.totals.stories * 3, ac: summary.totals.acceptanceCriteria
      }
    });
  } catch (err) {
    console.error('[generate] FAILED:', err);
    try {
      log(`╚═══ FAILED: ${err.message} ═══`, 'err');
      send('error', { error: err.message || 'Unknown error' });
    } catch (e) { console.error('Final SSE send failed:', e.message); }
  } finally {
    clearInterval(heartbeat);
    try { res.end(); } catch (e) {}
  }
});

app.get('/api/testplan/:id/summary', authMiddleware, async (req, res) => {
  const index = await readJson(DB.planIndexFile);
  const mine = index[req.user.email] || [];
  const plan = mine.find(p => p.planId === req.params.id);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  try {
    const data = await fs.readFile(plan.summaryFile, 'utf8');
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  } catch { res.status(404).json({ error: 'Summary file missing' }); }
});

app.get('/api/testplan/list', authMiddleware, async (req, res) => {
  const index = await readJson(DB.planIndexFile);
  const mine = (index[req.user.email] || []).map(p => ({
    planId: p.planId, project: p.project, epics: p.epics, generatedAt: p.generatedAt
  }));
  res.json({ plans: mine.sort((a, b) => (b.generatedAt > a.generatedAt ? 1 : -1)) });
});

// ══════════════════════════════════════════════════════════
// HEALTH
// ══════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════
// MAILGUN DIAGNOSTIC — GET /api/test/mailgun?to=you@domain.com
// Open this URL in your browser to verify Mailgun is working
// ══════════════════════════════════════════════════════════
app.get('/api/test/mailgun', async (req, res) => {
  const cfg = CONFIG.mailgun;
  const checks = {
    MAILGUN_API_KEY:  cfg.apiKey  ? `✓ set (${cfg.apiKey.slice(0,6)}…)` : '✗ NOT SET',
    MAILGUN_DOMAIN:   cfg.domain  ? `✓ ${cfg.domain}` : '✗ NOT SET',
    MAILGUN_FROM:     cfg.from    ? `✓ ${cfg.from}`   : '✗ NOT SET',
    MAILGUN_REGION:   cfg.region  || 'us (default)',
    FRONTEND_URL:     CONFIG.frontendUrl,
    api_endpoint:     `https://api${cfg.region==='eu'?'.eu':''}.mailgun.net/v3/${cfg.domain}/messages`,
  };

  if (!req.query.to) {
    return res.json({ status: 'config_check', checks, usage: 'Add ?to=your@email.com to send a test email' });
  }

  try {
    const result = await sendMailgunEmail({
      to:      req.query.to,
      subject: 'Qubit — Mailgun test email',
      text:    'If you receive this, Mailgun is configured correctly.',
      html:    '<p style="font-family:sans-serif">If you receive this, <strong>Mailgun is configured correctly ✓</strong></p>',
    });
    res.json({ status: 'sent', messageId: result.id, to: req.query.to, checks });
  } catch (err) {
    res.status(500).json({ status: 'failed', error: err.message, checks,
      fix: err.message.includes('401')
        ? 'Wrong API key. Use Private API Key from Mailgun → Settings → API Keys (NOT the SMTP password)'
        : err.message.includes('404') || err.message.includes('domain')
        ? 'Domain not found. Check MAILGUN_DOMAIN matches exactly what is in your Mailgun account'
        : 'Check all env vars and try again'
    });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true, service: 'qubit-server', version: '1.2.0',
    uptimeSec: Math.round(process.uptime()),
    config: {
      allowedDomains: CONFIG.allowedDomains,
      googleClientId: CONFIG.googleClientId || null,
      googleSsoEnabled: !!CONFIG.googleClientId,
      mcpTimeout: CONFIG.mcp.timeout,
      mcpMaxRetries: CONFIG.mcp.maxRetries,
      mcpParallelWorkers: CONFIG.mcp.parallelWorkers,
      jiraApiVersion: '/rest/api/3/search/jql (new endpoint)'
    }
  });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', detail: err.message });
});

app.listen(CONFIG.port, '0.0.0.0', () => {
  console.log('─────────────────────────────────────');
  console.log('  Qubit Server v1.2.0  |  port', CONFIG.port);
  console.log('  Frontend URL :', CONFIG.frontendUrl);
  console.log('  Mailgun      :', CONFIG.mailgun.apiKey ? `configured (domain: ${CONFIG.mailgun.domain})` : '⚠ NOT configured — set MAILGUN_API_KEY + MAILGUN_DOMAIN');
  console.log('  Google SSO   :', CONFIG.googleClientId ? 'enabled' : 'disabled (set GOOGLE_CLIENT_ID)');
  console.log('  Data dir     :', CONFIG.dataDir);
  console.log('  Allowed domains:', CONFIG.allowedDomains.join(', '));
  console.log('─────────────────────────────────────');
});
