import 'dotenv/config';

// ── Startup env validation ─────────────────────────────────────────────────
const REQUIRED_ENV = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'GMAIL_CLIENT_ID',
  'GMAIL_CLIENT_SECRET',
  'GMAIL_REDIRECT_URI',
  'FRONTEND_URL',
  'PYTHON_SERVICE_URL',
  'PYTHON_API_KEY',  // shared secret — backend proves identity to Python service
];

const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length > 0) {
  console.error(`[Startup] Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

if ((process.env.JWT_SECRET ?? '').length < 32) {
  console.error('[Startup] JWT_SECRET must be at least 32 characters');
  process.exit(1);
}

if ((process.env.ENCRYPTION_KEY ?? '').length < 32) {
  console.error('[Startup] ENCRYPTION_KEY must be at least 32 characters');
  process.exit(1);
}

// ── Imports ────────────────────────────────────────────────────────────────
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { rateLimit } from 'express-rate-limit';
import authRouter from './routes/auth.routes.js';
import emailRouter from './routes/email.routes.js';
import alertRouter from './routes/alert.routes.js';
import userRouter from './routes/user.routes.js';
import blockedRouter from './routes/blocked.routes.js';
import { startPollingInterval } from './services/polling.service.js';
import errorHandler from './middleware/errorHandler.middleware.js';
import { requestIdMiddleware } from './middleware/requestId.middleware.js';

const app = express();

// Add this line near the top, after const app = express();
app.set('trust proxy', 1); // Railway uses proxy

// ── Security headers ───────────────────────────────────────────────────────
app.use(helmet());

// ── CORS ───────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? process.env.FRONTEND_URL ?? '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (server-to-server, curl)
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Rate limiting ──────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests, please try again later.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests, please try again later.' },
});

// ── General middleware ─────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}
app.use(express.json({ limit: '1mb' }));
app.use(requestIdMiddleware); // stamp every request with a correlation ID

// ── Routes ─────────────────────────────────────────────────────────────────
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

app.use('/auth', authLimiter, authRouter);
app.use('/email', apiLimiter, emailRouter);
app.use('/alert', apiLimiter, alertRouter);
app.use('/user', apiLimiter, userRouter);
app.use('/blocked', apiLimiter, blockedRouter);

app.use(errorHandler);

// ── Start ───────────────────────────────────────────────────────────────────
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`JARVIS-X Backend running on port ${port}`);
  startPollingInterval();
});

export default app;
