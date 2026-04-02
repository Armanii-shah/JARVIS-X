import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import authRouter from './routes/auth.routes.js';
import emailRouter from './routes/email.routes.js';
import alertRouter from './routes/alert.routes.js';
import userRouter from './routes/user.routes.js';
import { startPollingInterval } from './services/polling.service.js';
import errorHandler from './middleware/errorHandler.middleware.js';

const app = express();

app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

app.get('/', (_req, res) => {
  res.json({ message: 'JARVIS-X API is running', status: 'ok' });
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'JARVIS-X Backend',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use('/auth', authRouter);
app.use('/email', emailRouter);
app.use('/alert', alertRouter);
app.use('/user', userRouter);

app.use(errorHandler);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`JARVIS-X Backend running on port ${port}`);
  startPollingInterval();
});

export default app;
