const express = require('express');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const cors = require('cors');

const authRoutes = require('./auth');
const payitemRoutes = require('./payitem');

const app = express();
app.use(bodyParser.json());
app.use(cors());

app.use('/auth', authRoutes);
app.use('/api/payitem', payitemRoutes);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API running on port ${port}`));
