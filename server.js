import express from 'express';
import cors from 'cors';
import apiRoutes from './routes/api.js';

const PORT = process.env.PORT || 5000;
const app = express();

app.use(cors());
app.use(express.json());
app.use(apiRoutes);

app.listen(PORT, () => {
    console.log(`SharkWire API server is running on port: ${PORT}`);
});