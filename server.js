const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const payitemRoutes = require('./payitem');
const keysRoutes = require('./keys');
const authRoutes = require('./secure-auth'); // NEW
const swaggerUi = require('swagger-ui-express');
const swaggerDoc = require('./swagger.json');
const app = express();
// --- Security headers
app.use(helmet({
  contentSecurityPolicy: false, // keep false for dev if embedding swagger-ui
  frameguard: { action: 'deny' }
}));
// --- Parse
app.use(bodyParser.json());
app.use(cookieParser());
// --- CORS (allow frontend origin + cookies)
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));
// --- Global rate limit (tune as needed)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300, // overall cap
  standardHeaders: true,
  legacyHeaders: false
}));
// Routes
app.use('/auth', authRoutes);
app.use('/api/payitem', payitemRoutes);
app.use('/keys', keysRoutes);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
