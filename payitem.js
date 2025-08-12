const express = require('express');
const router = express.Router();

const payitems = [];


const auth = require('./secure-auth');

router.post('/', auth.requireUser, (req, res) => {
  const { ClientID, SchemeID, EmployeeID, Payitemname, Value, Effectivedate } = req.body || {};
  if (!ClientID || !SchemeID || !EmployeeID || !Payitemname || typeof Value !== 'number' || !Effectivedate) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }
  payitems.push({ ClientID, SchemeID, EmployeeID, Payitemname, Value, Effectivedate });
  res.status(201).json({ message: 'Payitem stored successfully' });
});

router.get('/', auth.requireUser, (req, res) => {
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
