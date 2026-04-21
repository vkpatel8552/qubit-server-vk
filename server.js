/**
 * qubit-server — Backend proxy for the Qubit QA platform
 * Updated: Uses new /rest/api/3/search/jql endpoint (old /search removed by Atlassian Aug 2025)
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
  mcp: {
    timeout: parseInt(process.env.MCP_TIMEOUT_MS || '300000', 10),
    maxRetries: parseInt(process.env.MCP_MAX_RETRIES || '5', 10),
    parallelWorkers: parseInt(process.env.MCP_PARALLEL_WORKERS || '3', 10),
  }
};

[CONFIG.dataDir, CONFIG.tempDir].forEach(d => {
  if (!fsSync.existsSync(d)) fsSync.mkdirSync(d, { recursive: true });
});

const DB = {
  usersFile: path.join(CONFIG.dataDir, 'users.json'),
  sessionsFile: path.join(CONFIG.dataDir, 'sessions.json'),
  connectorsFile: path.join(CONFIG.dataDir, 'connectors.json'),
  planIndexFile: path.join(CONFIG.dataDir, 'plan-index.json')
};

async function readJson(file, fallback = {}) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch { return fallback; }
}
async function writeJson(file, data) {
  const tmp = file + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
  await fs.rename(tmp, file);
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
  /**
   * Uses the NEW /rest/api/3/search/jql endpoint (old /search removed Aug 2025).
   * Handles token-based pagination; aggregates up to ~1000 issues max.
   */
  async searchByJql(jql, fields = ['summary', 'status', 'issuetype'], maxResults = 100) {
    const allIssues = [];
    let nextPageToken = null;
    let safetyCounter = 0;
    const maxPages = 10; // safety cap — prevents infinite loops
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

app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone, org, role, password, avatar } = req.body || {};
  if (!firstName || !lastName || !email || !org || !role || !password) return res.status(400).json({ error: 'Missing required fields' });
  if (!domainOk(email)) return res.status(403).json({ error: `Only ${CONFIG.allowedDomains.join(' / ')} emails allowed` });
  if (!passwordValid(password)) return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, number, symbol' });
  const users = await readJson(DB.usersFile);
  const emailLower = email.toLowerCase();
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

app.post('/api/testplan/generate', authMiddleware, async (req, res) => {
  const { projectName, release, epics, context } = req.body || {};
  if (!projectName || !Array.isArray(epics) || epics.length === 0) return res.status(400).json({ error: 'projectName and non-empty epics[] required' });
  const allConns = await readJson(DB.connectorsFile);
  const jira = (allConns[req.user.email] || {}).jira;
  if (!jira || !jira.connected) return res.status(400).json({ error: 'Jira connector not configured' });
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // disable nginx buffering on Render
  res.flushHeaders();

  const send = (event, data) => {
    try {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    } catch (e) { console.error('SSE write failed:', e.message); }
  };
  const log = (msg, level = 'info') => send('log', { msg, level, ts: Date.now() });
  const phase = (idx, state, sub) => send('phase', { idx, state, sub });

  // Heartbeat keeps the SSE connection alive through proxies
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

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true, service: 'qubit-server', version: '1.1.0',
    uptimeSec: Math.round(process.uptime()),
    config: {
      allowedDomains: CONFIG.allowedDomains,
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
  console.log('  Qubit Server v1.1.0 listening on port', CONFIG.port);
  console.log('  Jira API: /rest/api/3/search/jql (new endpoint)');
  console.log('  Data dir:', CONFIG.dataDir);
  console.log('  Temp dir:', CONFIG.tempDir);
  console.log('  Allowed domains:', CONFIG.allowedDomains.join(', '));
  console.log('─────────────────────────────────────');
});