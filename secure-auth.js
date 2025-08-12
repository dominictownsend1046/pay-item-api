
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const router = express.Router();

/**
 * In-memory user store and token store.
 * Replace with a DB for production.
 */
const users = []; // { id, username, passwordHash, role }
const tokens = new Map(); // token -> { userId, expiresAt }

// Seed a default admin user from env (or fallback)
const DEFAULT_USER = process.env.DEFAULT_USER || 'admin';
const DEFAULT_PASSWORD = process.env.DEFAULT_PASSWORD || 'password123';
const DEFAULT_ROLE = 'admin';

(async () => {
  const exists = users.find(u => u.username === DEFAULT_USER);
  if (!exists) {
    const passwordHash = await bcrypt.hash(DEFAULT_PASSWORD, 12);
    users.push({ id: '1', username: DEFAULT_USER, passwordHash, role: DEFAULT_ROLE });
    // console.log('Seeded default admin user:', DEFAULT_USER);
  }
})();

const ACCESS_SECONDS = 15 * 60; // 15 minutes

function makeToken(len = 15) {
  // 15-char URL-safe token (base62-like)
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

function issueToken(userId) {
  const token = makeToken(15);
  const expiresAt = Date.now() + ACCESS_SECONDS * 1000;
  tokens.set(token, { userId, expiresAt });
  return { token, expiresIn: ACCESS_SECONDS };
}

function revokeToken(token) {
  tokens.delete(token);
}

function purgeExpired() {
  const now = Date.now();
  for (const [tok, meta] of tokens.entries()) {
    if (meta.expiresAt <= now) tokens.delete(tok);
  }
}
setInterval(purgeExpired, 60 * 1000).unref();

function getUserById(id) {
  return users.find(u => u.id === id);
}

function getUserByUsername(username) {
  return users.find(u => u.username === username);
}

// Registration (optional; protect in real life)
router.post('/register', async (req, res) => {
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
  const { token, expiresIn } = issueToken(user.id);
  return res.json({ access_token: token, token_type: 'Bearer', expires_in: expiresIn });
});

// Logout -> revoke token
router.post('/logout', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (token) revokeToken(token);
  return res.status(204).end();
});

// Me
router.get('/me', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const meta = tokens.get(token);
  if (!meta || meta.expiresAt <= Date.now()) return res.status(401).json({ error: 'Unauthorized' });
  const user = getUserById(meta.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  return res.json({ userId: user.id, username: user.username, role: user.role, expires_at: meta.expiresAt });
});

// Middleware for protected routes
function requireUser(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const meta = tokens.get(token);
  if (!meta || meta.expiresAt <= Date.now()) return res.status(401).json({ error: 'Unauthorized' });
  const user = getUserById(meta.userId);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  req.user = { id: user.id, username: user.username, role: user.role };
  next();
}

router.requireUser = requireUser;

module.exports = router;
