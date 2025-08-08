const express = require('express');
const router = express.Router();

const dataStore = [];

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (auth === 'Bearer secure_token_123') {
    next();
  } else {
    res.status(403).json({ error: 'Unauthorized' });
  }
}

router.post('/', authenticate, (req, res) => {
  const item = req.body;
  dataStore.push(item);
  res.status(201).json({ message: 'Payitem stored successfully' });
});

router.get('/', authenticate, (req, res) => {
  const { start, end } = req.query;
  const filtered = dataStore.filter(item => {
    const [day, month, year] = item.Effectivedate.split('/');
    const itemDate = new Date(`${year}-${month}-${day}`);
    return (!start || new Date(start) <= itemDate) && (!end || itemDate <= new Date(end));
  });
  res.json(filtered);
});

module.exports = router;