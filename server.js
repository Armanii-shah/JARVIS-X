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
import paymentRouter from './routes/payment.routes.js';
import contactRouter from './routes/contact.routes.js';
import { startPollingInterval } from './services/polling.service.js';
import { sendWhatsAppAlert } from './services/whatsapp.service.js';
import { makeSecurityCall } from './services/twilio.service.js';
import { triggerAlert } from './services/alert.service.js';
import supabase from './config/supabase.js';
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

app.get('/test-whatsapp', async (_req, res) => {
  const testPhone = '923265521790';
  console.log(`[TestWhatsApp] Firing test message to ${testPhone}`);
  try {
    const result = await sendWhatsAppAlert(
      testPhone,
      95,
      'TEST: Simulated phishing attempt via JARVIS-X debug endpoint',
      'TEST EMAIL — WhatsApp Debug',
      'HIGH'
    );
    console.log('[TestWhatsApp] ✓ Success:', JSON.stringify(result));
    res.json({ success: true, phone: testPhone, result });
  } catch (err) {
    console.error('[TestWhatsApp] ✗ Failed:', err.message);
    res.status(500).json({ success: false, phone: testPhone, error: err.message });
  }
});


// Fire WhatsApp + Voice call together — use ?level=medium|high|critical&phone=923xxxxxxxxx
app.get('/test-alert', async (req, res) => {
  const level = (req.query.level ?? 'high').toUpperCase();
  const phone = req.query.phone ?? null;
  const score = level === 'MEDIUM' ? 55 : level === 'CRITICAL' ? 98 : 85;
  console.log(`[TestAlert] level=${level} score=${score} phone=${phone ?? 'NONE'}`);
  try {
    const result = await triggerAlert(
      'test-user-id',
      null,
      score,
      'TEST: Simulated phishing attempt via JARVIS-X debug endpoint',
      'URGENT! Your account has been hacked - Pay now',
      phone,
      level,
      'attacker@evil.com'
    );
    res.json({ success: true, ...result });
  } catch (err) {
    console.error('[TestAlert] ✗ Failed:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Shows last 5 alert records — tells us if triggerAlert was ever called
app.get('/debug-alerts', async (_req, res) => {
  const { data } = await supabase
    .from('alerts')
    .select('id, type, status, triggered_at, user_id, email_id')
    .order('triggered_at', { ascending: false })
    .limit(5);
  res.json(data ?? []);
});

// Shows env config status (no secrets exposed) + user phones from DB
app.get('/debug-config', async (_req, res) => {
  const { data: users } = await supabase.from('users').select('id, email, phone').not('gmail_token', 'is', null);
  res.json({
    WHATSAPP_TOKEN: !!process.env.WHATSAPP_TOKEN,
    WHATSAPP_PHONE_NUMBER_ID: !!process.env.WHATSAPP_PHONE_NUMBER_ID,
    PYTHON_SERVICE_URL: process.env.PYTHON_SERVICE_URL ?? 'NOT SET',
    users: users?.map(u => ({ email: u.email, phone: u.phone ?? 'NULL' })) ?? [],
  });
});

app.get('/test-call', async (_req, res) => {
  const testPhone = '923265521790';
  console.log(`[TestCall] Making test call to ${testPhone}`);
  try {
    const result = await makeSecurityCall(
      testPhone,
      'TEST EMAIL — Twilio Voice Debug',
      95
    );
    console.log('[TestCall] ✓ Success:', JSON.stringify(result));
    res.json({ success: true, phone: testPhone, result });
  } catch (err) {
    console.error('[TestCall] ✗ Failed:', err.message);
    res.status(500).json({ success: false, phone: testPhone, error: err.message });
  }
});

// Re-fire alert for the most recent high/medium-risk email in DB
// Use: GET /retrigger-latest?phone=923xxxxxxxxx
app.get('/retrigger-latest', async (req, res) => {
  const phone = req.query.phone ?? null;
  try {
    const { data: email, error } = await supabase
      .from('emails')
      .select('*')
      .in('threat_level', ['high', 'medium'])
      .order('scanned_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !email) {
      return res.status(404).json({ success: false, message: 'No high/medium risk email found' });
    }

    console.log(`[RetriggerLatest] Re-alerting: "${email.subject}" score=${email.score} level=${email.threat_level} phone=${phone ?? 'NOT SET'}`);
    const result = await triggerAlert(
      email.user_id,
      email.id,
      email.score,
      `Manual retrigger — score ${email.score}`,
      email.subject || '(No Subject)',
      phone,
      email.threat_level,
      email.sender || email.subject || '(Unknown)'
    );
    res.json({ success: result.success, channel: result.channel, email: email.subject, score: email.score });
  } catch (err) {
    console.error('[RetriggerLatest] Failed:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.use('/auth', authLimiter, authRouter);
app.use('/email', apiLimiter, emailRouter);
app.use('/alert', apiLimiter, alertRouter);
app.use('/user', apiLimiter, userRouter);
app.use('/blocked', apiLimiter, blockedRouter);
app.use('/api/payment', apiLimiter, paymentRouter);
app.use('/contact', apiLimiter, contactRouter);

app.use(errorHandler);

// ── Start ───────────────────────────────────────────────────────────────────
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`JARVIS-X Backend running on port ${port}`);
  startPollingInterval();
});

export default app;
