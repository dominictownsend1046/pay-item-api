const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const payitemRoutes = require('./payitem');
const keysRoutes = require('./keys');

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use('/api/payitem', payitemRoutes);
app.use('/keys', keysRoutes);

app.post('/auth/token', (req, res) => {
  const { client_id, client_secret } = req.body || {};
  if (client_id === 'admin' && client_secret === 'password123') {
    return res.json({ access_token: 'secure_token_123', token_type: 'Bearer', expires_in: 3600 });
  }
  return res.status(401).json({ error: 'Invalid client credentials' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
