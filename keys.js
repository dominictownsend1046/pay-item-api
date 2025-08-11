const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const keyStore = [];

function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth === 'Bearer secure_token_123') return next();
  return res.status(403).json({ error: 'Unauthorized' });
}

const MASTER_KEY = (process.env.MASTER_KEY || '').slice(0, 32).padEnd(32, '0');

function encryptSecret(secret) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(MASTER_KEY), iv);
  const enc = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), secretEnc: enc.toString('hex') };
}
function decryptSecret(ivHex, encHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const enc = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.from(MASTER_KEY), iv);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}

router.post('/', authenticate, (req, res) => {
  const { companyId, schemeId, appKey, appSecret } = req.body || {};
  if (!companyId || !schemeId || !appKey || !appSecret) {
    return res.status(400).json({ error: 'companyId, schemeId, appKey, appSecret are required' });
  }
  const { iv, secretEnc } = encryptSecret(appSecret);
  const idx = keyStore.findIndex(k => k.companyId === companyId && k.schemeId === schemeId);
  if (idx >= 0) keyStore[idx] = { companyId, schemeId, appKey, iv, secretEnc };
  else keyStore.push({ companyId, schemeId, appKey, iv, secretEnc });
  return res.status(201).json({ message: 'Saved', companyId, schemeId, appKey });
});

router.get('/', authenticate, (req, res) => {
  const { companyId, schemeId, reveal } = req.query || {};
  if (!companyId || !schemeId) return res.status(400).json({ error: 'companyId and schemeId required' });
  const rec = keyStore.find(k => k.companyId === companyId && k.schemeId === schemeId);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  const payload = { companyId: rec.companyId, schemeId: rec.schemeId, appKey: rec.appKey };
  if (String(reveal) === 'true') {
    payload.appSecret = decryptSecret(rec.iv, rec.secretEnc);
  } else {
    const full = decryptSecret(rec.iv, rec.secretEnc);
    payload.appSecretLast4 = full.slice(-4);
  }
  return res.json(payload);
});

router.post('/exchange', (req, res) => {
  const { companyId, schemeId, appKey, appSecret } = req.body || {};
  if (!companyId || !schemeId || !appKey || !appSecret) {
    return res.status(400).json({ error: 'companyId, schemeId, appKey, appSecret are required' });
  }
  const rec = keyStore.find(k => k.companyId === companyId && k.schemeId === schemeId && k.appKey === appKey);
  if (!rec) return res.status(401).json({ error: 'Invalid credentials' });
  const secret = decryptSecret(rec.iv, rec.secretEnc);
  if (secret !== appSecret) return res.status(401).json({ error: 'Invalid credentials' });
  return res.json({ access_token: 'secure_token_123', token_type: 'Bearer', expires_in: 3600 });
});

module.exports = router;
