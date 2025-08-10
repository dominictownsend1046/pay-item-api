const express = require('express');
const router = express.Router();

// In-memory store for successful POSTs
const dataStore = [];

// Bearer auth middleware (demo)
function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth === 'Bearer secure_token_123') return next();
  return res.status(403).json({ error: 'Unauthorized' });
}

// Validate payload
function validatePayload(body) {
  const required = ['ClientID','SchemeID','EmployeeID','Payitemname','Value','Effectivedate'];
  for (const key of required) {
    if (body[key] === undefined || body[key] === null || body[key] === '') {
      return `${key} is required`;
    }
  }
  if (typeof body.Value !== 'number' || Number.isNaN(body.Value)) return 'Value must be a number';

  const ddmmyyyy = /^\d{2}\/\d{2}\/\d{4}$/;
  if (!ddmmyyyy.test(body.Effectivedate)) return 'Effectivedate must be DD/MM/YYYY';

  return null;
}

// POST /api/payitem
router.post('/', authenticate, (req, res) => {
  const err = validatePayload(req.body || {});
  if (err) return res.status(400).json({ error: err });

  dataStore.push(req.body);
  return res.status(201).json({ message: 'Payitem stored successfully' });
});

// GET /api/payitem?start=YYYY-MM-DD&end=YYYY-MM-DD
router.get('/', authenticate, (req, res) => {
  const { start, end } = req.query || {};
  const startDate = start ? new Date(start) : null;
  const endDate = end ? new Date(end) : null;

  const filtered = dataStore.filter(item => {
    // Convert DD/MM/YYYY -> Date
    const [dd, mm, yyyy] = item.Effectivedate.split('/').map(Number);
    const itemDate = new Date(yyyy, mm - 1, dd);

    if (startDate && itemDate < startDate) return false;
    if (endDate && itemDate > endDate) return false;
    return true;
  });

  res.json(filtered);
});

module.exports = router;
