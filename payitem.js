const express = require('express');
const router = express.Router();
const auth = require('./secure-auth');
// Remove the old `authenticate` that checks for 'secure_token_123'
// Now enforce user auth:
router.post('/', auth.requireUser, (req, res) => {
  // ... existing validation and push
});
router.get('/', auth.requireUser, (req, res) => {
  // ... existing date filtering
});
module.exports = router;

const payitems = [];

function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth === 'Bearer secure_token_123') return next();
  return res.status(403).json({ error: 'Unauthorized' });
}

router.post('/', (req, res) => {
  const { ClientID, SchemeID, EmployeeID, Payitemname, Value, Effectivedate } = req.body || {};
  if (!ClientID || !SchemeID || !EmployeeID || !Payitemname || typeof Value !== 'number' || !Effectivedate) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }
  payitems.push({ ClientID, SchemeID, EmployeeID, Payitemname, Value, Effectivedate });
  res.status(201).json({ message: 'Payitem stored successfully' });
});

router.get('/', (req, res) => {
  const { start, end } = req.query || {};
  let filtered = payitems;
  if (start && end) {
    filtered = filtered.filter(p => {
      const [dd, mm, yyyy] = p.Effectivedate.split('/');
      const d = new Date(`${yyyy}-${mm}-${dd}`);
      return d >= new Date(start) && d <= new Date(end);
    });
  }
  res.json(filtered);
});

module.exports = router;
