
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const router = express.Router();

/**
 * User store (in-memory for demo) and token store (memory or Redis).
 * In production, replace users[] with a DB.
 */
const users = []; // { id, username, passwordHash, role }

// ---------------- Token Store (memory or Redis) ----------------
const TOKEN_STORE = (process.env.TOKEN_STORE || '').toLowerCase(); // 'redis' or 'memory' (default)
let tokenStore;

class MemoryTokenStore {
  constructor() { this.map = new Map(); }
  async set(key, value, ttlSec) { this.map.set(key, { value, expiresAt: Date.now() + ttlSec * 1000 }); }
  async get(key) {
    const rec = this.map.get(key);
    if (!rec) return null;
    if (rec.expiresAt <= Date.now()) { this.map.delete(key); return null; }
    return rec.value;
  }
  async del(key) { this.map.delete(key); }
  startJanitor() {
    this._timer = setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.map.entries()) {
        if (v.expiresAt <= now) this.map.delete(k);
      }
    }, 60 * 1000).unref();
  }
}

class RedisTokenStore {
  constructor(url) {
    const { createClient } = require('redis');
    this.client = createClient({ url });
    this.client.on('error', (err) => console.error('[redis] error', err));
    this.connected = this.client.connect();
  }
  async set(key, value, ttlSec) {
    await this.connected;
    await this.client.set(`auth:token:${key}`, JSON.stringify(value), { EX: ttlSec });
  }
  async get(key) {
    await this.connected;
    const s = await this.client.get(`auth:token:${key}`);
    if (!s) return null;
    try { return JSON.parse(s); } catch { return null; }
  }
  async del(key) {
    await this.connected;
    await this.client.del(`auth:token:${key}`);
  }
  startJanitor() { /* Redis handles expiry */ }
}

if (TOKEN_STORE === 'redis' || process.env.REDIS_URL) {
  tokenStore = new RedisTokenStore(process.env.REDIS_URL || 'redis://localhost:6379/0');
} else {
  tokenStore = new MemoryTokenStore();
  tokenStore.startJanitor();
}

// ---------------- Seed default admin (guarded) ----------------
const SEED_DEFAULT_USER = (process.env.SEED_DEFAULT_USER || '').toLowerCase() === 'true';
const DEFAULT_USER = process.env.DEFAULT_USER || 'admin';
const DEFAULT_PASSWORD = process.env.DEFAULT_PASSWORD || 'changeMeNow123!';
const DEFAULT_ROLE = 'admin';

(async () => {
  if (SEED_DEFAULT_USER) {
    const exists = users.find(u => u.username === DEFAULT_USER);
    if (!exists) {
      const passwordHash = await bcrypt.hash(DEFAULT_PASSWORD, 12);
      users.push({ id: '1', username: DEFAULT_USER, passwordHash, role: DEFAULT_ROLE });
      // console.log('Seeded default admin user:', DEFAULT_USER);
    }
  }
})();

const ACCESS_SECONDS = 15 * 60; // 15 minutes

function makeToken(len = 15) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}

async function issueToken(userId) {
  const token = makeToken(15);
  const record = { userId, issuedAt: Date.now() };
  await tokenStore.set(token, record, ACCESS_SECONDS);
  return { token, expiresIn: ACCESS_SECONDS };
}

async function revokeToken(token) {
  await tokenStore.del(token);
}

async function getTokenMeta(token) {
  return await tokenStore.get(token);
}


async function issueServiceToken(username) {
  // Service principals are represented as users with role 'service'.
  if (!username) username = 'service';
  let u = getUserByUsername(username);
  if (!u) {
    u = { id: String(users.length + 1), username, passwordHash: '', role: 'service' };
    users.push(u);
  }
  const out = await issueToken(u.id);
  return out; // { token, expiresIn }
}
function getUserById(id) {
  return users.find(u => u.id === id);
}

function getUserByUsername(username) {
  return users.find(u => u.username === username);
}

// ---------------- Routes ----------------

// Registration (guarded by env; off by default)
router.post('/register', async (req, res) => {
  if ((process.env.ALLOW_REGISTRATION || '').toLowerCase() !== 'true') {
    return res.status(403).json({ error: 'Registration disabled' });
  }
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (getUserByUsername(username)) return res.status(409).json({ error: 'username taken' });
  const passwordHash = await bcrypt.hash(password, 12);
  const user = { id: String(users.length + 1), username, passwordHash, role: role || 'user' };
  users.push(user);
  res.status(201).json({ id: user.id, username: user.username, role: user.role });
});

// Login -> issue 15-char bearer token valid for 15 minutes
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = getUserByUsername(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const { token, expiresIn } = await issueToken(user.id);
  return res.json({ access_token: token, token_type: 'Bearer', expires_in: expiresIn });
});

// Logout -> revoke token
router.post('/logout', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) await revokeToken(token);
  return res.status(204).end();
});

// Me
router.get('/me', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const meta = await getTokenMeta(token);
  if (!meta) return res.status(401).json({ error: 'Unauthorized' });
  const user = getUserById(meta.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  return res.json({ userId: user.id, username: user.username, role: user.role });
});

// Middleware for protected routes
async function requireUser(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const meta = await getTokenMeta(token);
  if (!meta) return res.status(401).json({ error: 'Unauthorized' });
  const user = getUserById(meta.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = { id: user.id, username: user.username, role: user.role };
  next();
}

router.requireUser = requireUser;
router.issueServiceToken = issueServiceToken;

module.exports = router;
