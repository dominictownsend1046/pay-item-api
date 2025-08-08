const express = require('express');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const authRoutes = require('./auth');
const payitemRoutes = require('./payitem');

const app = express();
app.use(bodyParser.json());

app.use('/auth', authRoutes);
app.use('/api/payitem', payitemRoutes);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(3000, () => console.log('API running on port 3000'));