const express = require('express');
const router = express.Router();

router.post('/token', (req, res) => {
  const { client_id, client_secret } = req.body;
  if (client_id === 'admin' && client_secret === 'password123') {
    res.json({ access_token: 'secure_token_123' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

module.exports = router;