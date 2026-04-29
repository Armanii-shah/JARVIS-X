import { randomUUID } from 'crypto';

// In-memory store: code → { jwt, email, expiresAt }
// Codes are single-use and expire after 60 seconds.
// Safe for single-server deployments (Railway). For multi-instance, swap this
// for a Supabase/Redis-backed store.
const codes = new Map();

const TTL_MS = 60_000; // 60 seconds

export function generateAuthCode(jwt, email) {
  const code = randomUUID();
  codes.set(code, { jwt, email, expiresAt: Date.now() + TTL_MS });
  return code;
}

export function consumeAuthCode(code) {
  const entry = codes.get(code);
  if (!entry) return null;

  codes.delete(code); // single-use: delete immediately

  if (Date.now() > entry.expiresAt) return null; // expired

  return { jwt: entry.jwt, email: entry.email };
}
