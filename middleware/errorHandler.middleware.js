const isProd = process.env.NODE_ENV === 'production';

export default function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;

  // Always log full error server-side
  console.error(`[Error] ${req.method} ${req.path} → ${status}: ${err.message}`);
  if (!isProd) console.error(err.stack);

  // Never expose stack traces or internal messages in production
  const message = isProd && status === 500
    ? 'An internal error occurred'
    : err.message;

  res.status(status).json({ success: false, message });
}
