const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const router = express.Router();
/**
Demo user store (in-memory).
Replace with a DB in production.
 */
const users = []; // { id, username, passwordHash, role }
const JWT_ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || 'change_me_access';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'change_me_refresh';
const ACCESS_TTL_SECONDS = 10 * 60; // 10 minutes
const REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
// Per-route brute-force limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});
// Helpers
function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role || 'user' },
    JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TTL_SECONDS }
  );
}
function issueRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, typ: 'refresh' },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TTL_SECONDS }
  );
}
function setRefreshCookie(res, token) {
  // httpOnly + secure + sameSite=lax to mitigate XSS/CSRF
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: true, // set false only for local http testing if needed
    sameSite: 'lax',
    maxAge: REFRESH_TTL_SECONDS * 1000,
    path: '/auth'
  });
}
function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', { path: '/auth' });
}
// Registration (keep disabled in prod or admin-only)
router.post('/register', async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'username taken' });
  // OWASP: strong hashing with bcrypt (work factor 12+). Argon2id is also fine if available.
  const passwordHash = await bcrypt.hash(password, 12);
  const user = { id: String(users.length + 1), username, passwordHash, role: role || 'user' };
  users.push(user);
  res.status(201).json({ id: user.id, username: user.username, role: user.role });
});
// Login → set refresh cookie + return short-lived access token
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = users.find(u => u.username === username);
  // Vague error message (don’t leak which field failed)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const access = issueAccessToken(user);
  const refresh = issueRefreshToken(user);
  setRefreshCookie(res, refresh);
  res.json({ access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_SECONDS });
});
// Refresh → read refresh cookie and rotate
router.post('/refresh', (req, res) => {
  const token = req.cookies?.refresh_token;
  if (!token) return res.status(401).json({ error: 'No refresh token' });
  try {
    const payload = jwt.verify(token, JWT_REFRESH_SECRET);
    const user = users.find(u => u.id === payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    // Rotate
    const newRefresh = issueRefreshToken(user);
    setRefreshCookie(res, newRefresh);
    const access = issueAccessToken(user);
    res.json({ access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_SECONDS });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
});
// Logout
router.post('/logout', (req, res) => {
  clearRefreshCookie(res);
  res.status(204).end();
});
// Who am I (for the UI)
router.get('/me', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    res.json({ userId: payload.sub, username: payload.username, role: payload.role });
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
});
// Reusable middleware for protected routes (access token)
function requireUser(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    req.user = { id: payload.sub, username: payload.username, role: payload.role };
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
// Export middleware to protect your existing routes
router.requireUser = requireUser;
module.exports = router;
