import { randomUUID } from 'crypto';

/**
 * Stamps every request with a unique correlation ID.
 *
 * WHY:
 *   When multiple users hit the API simultaneously, log lines from different
 *   requests get interleaved. By attaching `req.id` here and including it in
 *   every subsequent log statement, you can grep/filter all log lines for a
 *   single request — essential for debugging production issues.
 *
 * USAGE:
 *   All controllers access `req.id` and prefix their log calls with it.
 *   e.g. console.log(`[${req.id}] Scanning emails for user ${req.user.email}`)
 *
 * HEADER:
 *   X-Request-ID is echoed back in the response so clients (and support teams)
 *   can reference a specific request when filing bug reports.
 */
export function requestIdMiddleware(req, res, next) {
  req.id = randomUUID();

  // Echo the ID back so the client/frontend can log it too
  res.setHeader('X-Request-ID', req.id);

  console.log(`[${req.id}] --> ${req.method} ${req.path}`);
  next();
}
