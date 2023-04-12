// Loads the configuration from config.env to process.env
// require("dotenv").config({ path: "./config.env" });

import express from 'express';
import cors from 'cors';
import apiRoutes from './routes/api.js';

const PORT = process.env.PORT || 5000;
const app = express();

app.use(cors());
app.use(express.json());
app.use(apiRoutes);

// Global error handling
app.use(function (err, _req, res) {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
    console.log(`SharkWire API server is running on port: ${PORT}`);
});