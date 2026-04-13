# JARVIS-X Backend Documentation

## Overview

The backend is a **Node.js/Express REST API** (ES modules, Express 5) that serves as the central hub of the JARVIS-X system. It orchestrates Gmail OAuth authentication, background email polling, AI-powered threat analysis, multi-channel alert delivery, and data persistence via Supabase. It communicates with the Python FastAPI service for ML-based email scoring, the Gmail API for email retrieval, VirusTotal for link scanning, and Meta WhatsApp/Vonage/Nodemailer for alert delivery.

**System position:**
```
Frontend (Next.js)
    ↕  REST API (JWT auth)
Node.js / Express Backend
    ↕                ↕               ↕              ↕
Supabase DB    Python AI       Gmail API     Alert Services
(PostgreSQL)   (FastAPI)       (Google)      (WhatsApp / SMS / Email)
                                             VirusTotal (link scan)
```

---

## Table of Contents

1. [File Structure](#1-file-structure)
2. [API Endpoints](#2-api-endpoints)
3. [Database Schema](#3-database-schema)
4. [Environment Variables](#4-environment-variables)
5. [External API Integrations](#5-external-api-integrations)
6. [Authentication & JWT](#6-authentication--jwt)
7. [NPM Dependencies](#7-npm-dependencies)
8. [Middleware](#8-middleware)
9. [Validators & Schemas](#9-validators--schemas)
10. [TODOs, Bugs & Commented-Out Code](#10-todos-bugs--commented-out-code)
11. [Security Implementations](#11-security-implementations)
12. [Email Scanning Flow](#12-email-scanning-flow)
13. [Utility & Helper Functions](#13-utility--helper-functions)
14. [Error Handling](#14-error-handling)

---

## 1. File Structure

```
Backend/
├── server.js                          # Express app entry point — middleware, routes, startup
├── package.json                       # Dependencies, scripts, module type (ES modules)
├── .env                               # Secrets (gitignored)
├── .env.example                       # Template of required env vars
├── JARVIS-X.postman_collection.json   # Postman API test collection
│
├── config/
│   └── supabase.js                    # Supabase client init (service role key — bypasses RLS)
│
├── controllers/
│   ├── auth.controller.js             # OAuth flow: redirect to Google, handle callback, issue JWT
│   ├── email.controller.js            # Scan emails on-demand, return email history
│   ├── alert.controller.js            # Trigger/read/resolve/delete alerts
│   └── user.controller.js             # Get and update user profile
│
├── routes/
│   ├── auth.routes.js                 # GET /auth/gmail, GET /auth/gmail/callback
│   ├── email.routes.js                # POST /email/scan, GET /email/history, POST /email/rescan/:id
│   ├── alert.routes.js                # CRUD on /alert/* routes
│   └── user.routes.js                 # GET/PATCH /user/profile
│
├── middleware/
│   ├── auth.middleware.js             # JWT verification — sets req.user on success
│   ├── errorHandler.middleware.js     # Centralized error handler (last middleware)
│   └── validate.middleware.js         # express-validator runner — returns 400 on failures
│
├── services/
│   ├── gmail.service.js               # Google OAuth helpers: getAuthUrl, getTokens, createAuthClient, refresh
│   ├── email.service.js               # Gmail API: fetch unread emails, mark as read
│   ├── ai.service.js                  # HTTP client for Python AI service — retry logic
│   ├── decision.service.js            # Score → { level, shouldAlert, message } mapping
│   ├── alert.service.js               # Alert cascade orchestrator (WhatsApp → SMS → Email)
│   ├── whatsapp.service.js            # Meta WhatsApp Business Cloud API sender
│   ├── vonage.service.js              # Vonage REST SMS sender (fallback)
│   ├── virustotal.service.js          # VirusTotal URL submit + poll results
│   └── polling.service.js             # Background 30s email polling loop with concurrency guard
│
└── utils/
    ├── encrypt.util.js                # AES-256-CBC encrypt/decrypt for Gmail OAuth tokens
    ├── emailParser.util.js            # Raw Gmail message → { subject, sender, body, links, attachments }
    ├── htmlCleaner.util.js            # HTML → plain text (strip tags, decode entities)
    ├── linkExtractor.util.js          # Regex URL extractor (deduplicating)
    └── attachment.util.js             # MIME part scanner — flags dangerous file extensions
```

---

## 2. API Endpoints

All protected routes require an `Authorization: Bearer <jwt>` header. The JWT is issued by `/auth/gmail/callback` after successful Google OAuth.

---

### Root / Health

#### `GET /`
No auth.

**Response `200`:**
```json
{ "message": "JARVIS-X API is running", "status": "ok" }
```

#### `GET /health`
No auth.

**Response `200`:**
```json
{
  "status": "ok",
  "service": "JARVIS-X Backend",
  "timestamp": "2026-04-09T14:30:45.123Z",
  "uptime": 3600.456
}
```

---

### Authentication — `/auth`

Rate limited: **30 requests / 15 minutes**

#### `GET /auth/gmail`
No auth. Initiates Gmail OAuth flow.

**What it does:**
1. Creates an OAuth2 client with `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, `GMAIL_REDIRECT_URI`
2. Generates a Google authorization URL with:
   - `access_type: 'offline'` → requests a refresh token
   - `prompt: 'consent'` → forces consent screen every time (ensures refresh token is always returned)
   - Scopes:
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/gmail.modify`
     - `https://www.googleapis.com/auth/userinfo.email`
     - `https://www.googleapis.com/auth/userinfo.profile`
3. Redirects browser to Google's consent screen

**Response:** `302 Redirect` to Google OAuth URL

---

#### `GET /auth/gmail/callback`
No auth. Handles the OAuth redirect from Google.

**Query params:**
| Param | Required | Description |
|-------|----------|-------------|
| `code` | Yes | Authorization code provided by Google |

**What it does (step by step):**
1. Extracts `code` from query string
2. Exchanges code for tokens via `getTokens(code)` → returns `{ access_token, refresh_token }`
3. Creates OAuth2 client with tokens and calls `oauth2.userinfo.get()` to retrieve email address
4. Encrypts `{ access_token, refresh_token }` as JSON using AES-256-CBC (`encryptTokenData()`)
5. Upserts user into `users` table:
   ```sql
   INSERT INTO users (email, gmail_token, plan)
   VALUES ($email, $encrypted_token, 'free')
   ON CONFLICT (email) DO UPDATE SET gmail_token = $encrypted_token
   ```
6. Fetches the user's `id` UUID from the database
7. Creates a 7-day JWT:
   ```json
   { "userId": "<uuid>", "email": "user@gmail.com" }
   ```
8. Redirects to frontend: `{FRONTEND_URL}/auth/callback?token=<JWT>&email=<email>`

**Success response:** `302 Redirect` to frontend  
**Error response:** `302 Redirect` to `{FRONTEND_URL}/auth/login?error=authentication_failed` (error detail never exposed to client)

---

### Email — `/email`

Rate limited: **120 requests / 60 seconds**  
All routes require JWT auth.

#### `POST /email/scan`
Manually trigger an email scan for the authenticated user.

**Request body:** None

**What it does:**
1. Decrypts stored Gmail token, creates authenticated Gmail client
2. Fetches unread emails from Gmail: `q = 'newer_than:3d is:unread'`, `maxResults: 20`
3. For each email:
   - Parses raw MIME message → `{ subject, sender, body, links, attachments }`
   - Cleans HTML from body (`cleanHtml()`)
   - Scans all links with VirusTotal (`Promise.allSettled` — failures don't abort)
   - Calls Python AI service at `{PYTHON_SERVICE_URL}/analyze`
   - Makes risk decision from score
   - Inserts row into `emails` table
   - Inserts row into `scans` table (VirusTotal results, score breakdown)
4. Returns all scan results

**Response `200`:**
```json
{
  "success": true,
  "scanned": 5,
  "results": [
    {
      "subject": "Verify your account immediately",
      "sender": "security@paypa1-secure.xyz",
      "score": 85,
      "threatLevel": "HIGH",
      "shouldAlert": true,
      "message": "Threat detected - alert triggered"
    }
  ]
}
```

**Error responses:** `401` (missing/invalid token), `500` (internal error)

---

#### `GET /email/history`
Fetch all previously scanned emails for the authenticated user.

**Request:** No body, no query params

**What it does:**
1. Queries `emails` table: `SELECT * FROM emails WHERE user_id = $userId ORDER BY scanned_at DESC`
2. Returns full array

**Response `200`:**
```json
[
  {
    "id": "3f2a1b4c-...",
    "user_id": "a1b2c3d4-...",
    "subject": "Your invoice is ready",
    "sender_email": "billing@company.com",
    "sender_name": "Company Billing",
    "risk_score": 12,
    "threat_level": "low",
    "received_at": "2026-04-09T08:00:00Z",
    "scanned_at": "2026-04-09T08:00:30Z"
  }
]
```

**Error responses:** `401`, `500`

---

#### `POST /email/rescan/:id`
Re-analyze a previously scanned email with the AI service.

**URL params:**
| Param | Required | Validation |
|-------|----------|-----------|
| `id` | Yes | Must be non-empty |

**What it does:**
1. Validates `id` param
2. Fetches existing email record from `emails` by `id`
3. Calls Python AI service with minimal payload (no body re-fetch from Gmail):
   ```json
   { "subject": "...", "sender": "...", "body": "", "links": [], "attachments": [] }
   ```
4. Gets new score, remaps threat level
5. Updates `emails` row: `UPDATE emails SET risk_score = $score, threat_level = $level WHERE id = $id`

**Response `200`:**
```json
{ "success": true, "newScore": 65, "threatLevel": "MEDIUM" }
```

**Error responses:** `400` (invalid id), `401`, `500`

---

### Alerts — `/alert`

Rate limited: **120 requests / 60 seconds**  
All routes require JWT auth.

#### `POST /alert/trigger`
Trigger a multi-channel alert for a detected threat.

**Request body:**
```json
{
  "emailId":    "3f2a1b4c-...",
  "score":      85,
  "reason":     "Phishing link detected with .xyz domain",
  "subject":    "Urgent: Your account will be suspended",
  "phone":      "923265521790",
  "threatLevel": "HIGH"
}
```

**Validation rules:**

| Field | Rule |
|-------|------|
| `emailId` | Required, non-empty string |
| `score` | Required, integer 0–100 |
| `reason` | Required, non-empty string |
| `subject` | Required, non-empty string |
| `phone` | Required, minimum 10 characters |
| `threatLevel` | Optional |

**What it does — alert cascade:**
1. Validates JWT and request body
2. Calls `triggerAlert()` which attempts channels in order:

   **Step 1 — WhatsApp (Meta Business Cloud API):**
   - Cleans phone: strips `+`, spaces, dashes, parentheses
   - Validates: `/^\d{10,15}$/`
   - Calls `https://graph.facebook.com/v21.0/{WHATSAPP_PHONE_NUMBER_ID}/messages`
   - Message body depends on threat level:
     - `MEDIUM`: *"⚠️ JARVIS-X WARNING — Suspicious Email Detected!..."*
     - `HIGH`: *"🚨 JARVIS-X SECURITY ALERT — Threat Detected!..."*
   - On success → `channel = 'whatsapp'`

   **Step 2 — SMS via Vonage (if WhatsApp fails):**
   - POST to `https://rest.nexmo.com/sms/json`
   - `from: "JARVIS-X"`, same message variants as WhatsApp
   - Checks `messages[0].status === '0'` for success
   - On success → `channel = 'sms'`

   **Step 3 — Email via Nodemailer (if SMS fails):**
   - Uses Gmail SMTP (`GMAIL_USER` / `GMAIL_APP_PASSWORD`)
   - Sends to `ALERT_EMAIL`
   - Subject: `"JARVIS-X SECURITY ALERT: {subject}"`
   - On success → `channel = 'email'`

   **All fail:** `channel = 'none'`, `status = 'failed'`

3. Inserts into `alerts` table:
   ```sql
   INSERT INTO alerts (email_id, user_id, type, status)
   VALUES ($emailId, $userId, $channel, $status)
   ```

**Response `200`:**
```json
{ "success": true, "channel": "whatsapp" }
```
`channel` is one of: `"whatsapp"` | `"sms"` | `"email"` | `"none"`

**Error responses:** `400` (validation failure), `401`, `500`

---

#### `GET /alert/history`
Fetch alerts for the authenticated user.

**Query params:**
| Param | Optional | Description |
|-------|----------|-------------|
| `unread` | Yes | Pass `"true"` to return only unread (non-resolved) alerts |

**What it does:**
1. Base query: `SELECT * FROM alerts WHERE user_id = $userId AND status != 'cleared' ORDER BY created_at DESC`
2. If `?unread=true`: also filters `AND status != 'resolved'`
3. For each alert, fetches the associated email row (`SELECT * FROM emails WHERE id = $emailId`)
4. Normalizes and returns shaped response:

```json
[
  {
    "id": "alert-uuid",
    "user_id": "user-uuid",
    "threat_id": "email-uuid",
    "alert_type": "whatsapp",
    "title": "High Risk Email: Urgent account action required",
    "message": "Suspicious email detected from security@paypa1-secure.xyz",
    "is_sent": true,
    "sent_at": "2026-04-09T10:00:00Z",
    "is_read": false,
    "read_at": null,
    "created_at": "2026-04-09T10:00:00Z"
  }
]
```

Returns `[]` if no alerts exist.

**Error responses:** `401`, `500`

---

#### `PATCH /alert/:id/read`
Mark a single alert as read/resolved.

**URL params:** `id` — alert UUID

**What it does:** `UPDATE alerts SET status = 'resolved' WHERE id = $id`

**Response `200`:**
```json
{ "success": true, "updated": 1 }
```

---

#### `PATCH /alert/mark-all-read`
Mark all of the user's unread alerts as resolved.

**What it does:**
```sql
UPDATE alerts
SET status = 'resolved'
WHERE user_id = $userId
  AND status != 'resolved'
  AND status != 'cleared'
```

**Response `200`:**
```json
{ "success": true, "count": 3 }
```

---

#### `DELETE /alert/:id`
Soft-delete an alert (hide from history).

**URL params:** `id` — alert UUID

**What it does:** Sets `status = 'cleared'` — the alert is excluded from all history queries but not removed from the database.
```sql
UPDATE alerts SET status = 'cleared' WHERE id = $id AND user_id = $userId
```

**Response `200`:**
```json
{ "success": true }
```

---

#### `PATCH /alert/resolve/:id`
Alias for marking alert as read/resolved (identical to `PATCH /alert/:id/read`).

**Response `200`:**
```json
{ "success": true }
```

---

### User — `/user`

Rate limited: **120 requests / 60 seconds**  
All routes require JWT auth.

#### `GET /user/profile`
Fetch the authenticated user's profile.

**What it does:**
```sql
SELECT id, email, phone, plan, created_at
FROM users WHERE id = $userId
```

**Response `200`:**
```json
{
  "id": "a1b2c3d4-...",
  "email": "user@gmail.com",
  "phone": "923265521790",
  "plan": "free",
  "created_at": "2026-01-15T08:30:00Z"
}
```

**Error responses:** `401`, `404` (user not found), `500`

---

#### `PATCH /user/profile`
Update the authenticated user's phone number.

**Request body:**
```json
{ "phone": "923265521790" }
```

**Validation:**
| Field | Rule |
|-------|------|
| `phone` | Optional. If present, must be 10–15 characters. |

**What it does:**
- Only `phone` can be updated via this endpoint (plan changes require a billing system)
- `UPDATE users SET phone = $phone WHERE id = $userId`

**Response `200`:**
```json
{ "success": true }
```

**Error responses:** `400` (validation), `401`, `500`

---

## 3. Database Schema

Hosted on **Supabase (PostgreSQL)**. Backend accesses using the **service role key**, which bypasses all Row Level Security policies.

### `users`

```sql
CREATE TABLE users (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text        NOT NULL UNIQUE,
  phone       text,                          -- Optional; 10-15 digit string for alert delivery
  plan        text        DEFAULT 'free',    -- 'free' | 'pro' | 'enterprise'
  gmail_token text,                          -- AES-256-CBC encrypted JSON: { access_token, refresh_token }
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);
-- Unique index on: email
```

### `emails`

```sql
CREATE TABLE emails (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid        NOT NULL REFERENCES users(id),
  gmail_message_id text,                          -- Gmail API message ID; used for deduplication
  subject          text        NOT NULL,
  sender           text,                          -- Full "Name <email>" string from Gmail header
  sender_email     text,                          -- Extracted email address only
  sender_name      text,                          -- Extracted display name only
  score            numeric(3,1),                  -- 0–100 AI risk score (also referred to as risk_score)
  threat_level     text,                          -- 'low' | 'medium' | 'high'
  received_at      timestamptz,                   -- Email's original receive timestamp
  scanned_at       timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz DEFAULT now()
);
-- Index on: (user_id, scanned_at DESC) — main query pattern
-- Index on: gmail_message_id           — deduplication lookups
-- FK: user_id → users(id)
```

### `scans`

```sql
CREATE TABLE scans (
  id                uuid  PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id          uuid  NOT NULL REFERENCES emails(id),
  virustotal_result jsonb,   -- Array of: { url, malicious, suspicious, result }
  links_checked     text[],  -- All URLs that were submitted to VirusTotal
  score_breakdown   jsonb,   -- { score: number, reason: string } from Python AI service
  created_at        timestamptz DEFAULT now()
);
-- FK: email_id → emails(id)
-- Index on: email_id
```

### `alerts`

```sql
CREATE TABLE alerts (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id   uuid        REFERENCES emails(id),
  user_id    uuid        NOT NULL REFERENCES users(id),
  type       text,                      -- Delivery channel: 'whatsapp' | 'sms' | 'email' | 'none'
  status     text        DEFAULT 'sent', -- 'sent' | 'failed' | 'resolved' | 'cleared'
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);
-- Soft delete: status = 'cleared' hides row from user-facing queries
-- status = 'resolved' means alert was read/acknowledged by user
-- Index on: (user_id, created_at DESC)
-- FK: email_id → emails(id), user_id → users(id)
```

**Inferred relationships:**

```
users (1) ──< emails (many)
users (1) ──< alerts (many)
emails (1) ──< scans  (many)
emails (1) ──< alerts (many)
```

---

## 4. Environment Variables

Validated at startup in `server.js`. Missing required variables or a JWT_SECRET shorter than 32 characters will cause the process to exit with code 1.

| Variable | Required | Purpose |
|----------|----------|---------|
| `SUPABASE_URL` | **Yes** | Supabase project REST URL |
| `SUPABASE_SERVICE_ROLE_KEY` | **Yes** | Service role key — bypasses RLS, full DB access |
| `SUPABASE_ANON_KEY` | No | Loaded but unused (backend always uses service role) |
| `JWT_SECRET` | **Yes** | HMAC-SHA256 secret for signing/verifying JWTs. Minimum 32 characters enforced at startup. |
| `ENCRYPTION_KEY` | **Yes** | AES-256-CBC key for Gmail token encryption. First 32 bytes used. |
| `GMAIL_CLIENT_ID` | **Yes** | Google OAuth 2.0 client ID |
| `GMAIL_CLIENT_SECRET` | **Yes** | Google OAuth 2.0 client secret |
| `GMAIL_REDIRECT_URI` | **Yes** | OAuth callback URL (e.g., `https://jarvis-x-production.up.railway.app/auth/gmail/callback`) |
| `FRONTEND_URL` | **Yes** | Frontend origin for OAuth redirect and CORS (e.g., `https://jarvis-x-frontend.vercel.app`) |
| `PYTHON_SERVICE_URL` | **Yes** | Base URL of Python FastAPI service (e.g., `https://jarvis-x-python.up.railway.app`) |
| `GMAIL_USER` | No | Gmail address used as SMTP sender for alert emails |
| `GMAIL_APP_PASSWORD` | No | Gmail app-specific password (not the account password) |
| `ALERT_EMAIL` | No | Destination email address for alert notifications |
| `WHATSAPP_TOKEN` | No | Meta WhatsApp Business Cloud API bearer token |
| `WHATSAPP_PHONE_NUMBER_ID` | No | WhatsApp Business phone number ID (from Meta developer portal) |
| `WHATSAPP_BUSINESS_ACCOUNT_ID` | No | Meta Business Account ID (loaded in `.env`, not used in code) |
| `VONAGE_API_KEY` | No | Vonage (Nexmo) API key for SMS fallback |
| `VONAGE_API_SECRET` | No | Vonage API secret |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key for link scanning |
| `GEMINI_API_KEY` | No | Loaded in `.env` but unused in backend code |
| `ALLOWED_ORIGINS` | No | Comma-separated list of allowed CORS origins. Defaults to `FRONTEND_URL`. |
| `PORT` | No | HTTP server port. Defaults to `3000`. |
| `NODE_ENV` | No | `'production'` suppresses stack traces in error responses and Morgan logging |
| `DISABLE_POLLING` | No | Referenced in comments; polling is always started regardless of this variable's value |

---

## 5. External API Integrations

### 5.1 Gmail / Google OAuth 2.0

**Library:** `googleapis` npm package  
**Files:** `services/gmail.service.js`, `controllers/auth.controller.js`, `services/polling.service.js`

**OAuth scopes requested:**
- `gmail.readonly` — Read email content
- `gmail.modify` — Mark emails as read (prevents re-processing)
- `userinfo.email` — Get user's Gmail address
- `userinfo.profile` — Get user's name/profile

**Token lifecycle:**
- `access_token` expires in ~1 hour
- `refresh_token` is long-lived and stored encrypted in `users.gmail_token`
- When polling gets a Gmail 401, it calls `refreshAccessToken()`, gets a new `access_token`, re-encrypts both tokens, updates `users.gmail_token`, then retries

**Token storage format:**
```
users.gmail_token = encrypt(JSON.stringify({ access_token, refresh_token }))
```
Stored as `{hex_iv}:{hex_ciphertext}`.

**Gmail query used for polling:**
```
q = "newer_than:3d is:unread"
maxResults = 20
```

**Emails are marked as read immediately** upon fetch, before analysis — this prevents duplicate processing if a subsequent poll runs while the current one is still processing.

---

### 5.2 Python AI Service (FastAPI)

**File:** `services/ai.service.js`  
**Endpoint:** `POST {PYTHON_SERVICE_URL}/analyze`

**Request sent:**
```json
{
  "subject":     "Email subject line",
  "sender":      "sender@example.com",
  "body":        "Cleaned plain-text body",
  "links":       ["https://link1.com", "https://link2.com"],
  "attachments": [{ "name": "invoice.exe", "mimeType": "application/octet-stream" }]
}
```

**Response received:**
```json
{
  "score":       85,
  "reason":      "Fake PayPal domain with .xyz TLD and urgency language",
  "threatLevel": "HIGH"
}
```

**Retry logic:**
- Timeout per attempt: `AbortSignal.timeout(20000)` (20 seconds)
- Retry delays: `[2000ms, 4000ms]` — 3 total attempts
- If all 3 fail: throws `"AI service unavailable after 3 attempts"` — email processing fails for that message

---

### 5.3 VirusTotal

**File:** `services/virustotal.service.js`  
**API version:** v3

**Flow:**
1. `POST https://www.virustotal.com/api/v3/urls` with `url=<encoded>` in body
2. Receive `{ data: { id: "<analysis_id>" } }`
3. Wait 2 seconds (`setTimeout`)
4. `GET https://www.virustotal.com/api/v3/analyses/<analysis_id>`
5. Extract from `attributes.stats`: `malicious` count, `suspicious` count

**Result format per URL:**
```json
{
  "url":         "https://paypa1-secure.xyz/login",
  "malicious":   8,
  "suspicious":  2,
  "result":      "malicious"
}
```
`result` values: `"undetected"` | `"suspicious"` | `"malicious"` | `"unknown"` | `"scan_failed"`

**Error handling:** All links processed via `Promise.allSettled()` — a failed scan for one URL returns `{ result: 'scan_failed' }` and does not abort others.

---

### 5.4 WhatsApp Business Cloud API (Meta)

**File:** `services/whatsapp.service.js`  
**Endpoint:** `POST https://graph.facebook.com/v21.0/{WHATSAPP_PHONE_NUMBER_ID}/messages`  
**Auth:** `Authorization: Bearer {WHATSAPP_TOKEN}`

**Request body:**
```json
{
  "messaging_product": "whatsapp",
  "to":               "923265521790",
  "type":             "text",
  "text":             { "body": "🚨 JARVIS-X SECURITY ALERT\n\nThreat Detected!..." }
}
```

**Phone number cleaning:**
```javascript
const cleanPhone = String(phone)
  .replace(/^\+/, '')          // strip leading +
  .replace(/[\s\-().]/g, '');  // strip spaces, dashes, parens
// Must match /^\d{10,15}$/
```

**Message variants:**
- **HIGH threat:** `🚨 JARVIS-X SECURITY ALERT\n\nThreat Detected!\nSubject: {subject}\nRisk Score: {score}/100\nThreat: {reason}\n\nImmediate action required!`
- **MEDIUM threat:** `⚠️ JARVIS-X WARNING\n\nSuspicious Email Detected!\nSubject: {subject}\nRisk Score: {score}/100\nDetails: {reason}\n\nPlease review.`

**Error handling:** Throws if HTTP status is not OK, or if response JSON contains an `error` field.

---

### 5.5 Vonage SMS (Fallback)

**File:** `services/vonage.service.js`  
**Endpoint:** `POST https://rest.nexmo.com/sms/json`

**Request body:**
```json
{
  "api_key":    "VONAGE_API_KEY",
  "api_secret": "VONAGE_API_SECRET",
  "to":         "923265521790",
  "from":       "JARVIS-X",
  "text":       "JARVIS-X ALERT: Threat detected!..."
}
```

**Success check:** Response must have `messages[0].status === '0'`

---

### 5.6 Nodemailer / Gmail SMTP (Last Resort)

**File:** `services/alert.service.js`

```javascript
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }
});
```

**Email format:**
- To: `ALERT_EMAIL`
- Subject: `"JARVIS-X SECURITY ALERT: {subject}"`
- Body: plaintext with score, reason, and subject

---

### 5.7 Supabase

**File:** `config/supabase.js`

```javascript
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
)
```

- Uses the **service role key** — bypasses all RLS policies
- Singleton client imported across all controllers and services
- No connection pooling configuration — Supabase JS client handles internally

---

## 6. Authentication & JWT

### JWT Creation

Location: `controllers/auth.controller.js`

```javascript
const token = jwt.sign(
  { userId: user.id, email: userEmail },
  process.env.JWT_SECRET,
  { expiresIn: '7d' }
)
```

| Property | Value |
|----------|-------|
| Algorithm | HS256 (default for `jsonwebtoken`) |
| Payload | `{ userId: "<uuid>", email: "user@gmail.com" }` |
| Expiry | 7 days |
| Secret | `JWT_SECRET` env var (≥ 32 chars, enforced at startup) |

### JWT Verification

Location: `middleware/auth.middleware.js`

```javascript
export function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization']
  if (!authHeader) return res.status(401).json({ message: 'No token provided' })

  const token = authHeader.split(' ')[1]   // Extract after "Bearer "
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = { id: decoded.userId, email: decoded.email }
    next()
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' })
  }
}
```

After successful verification, `req.user` is available in all route handlers:
```javascript
req.user.id     // user UUID
req.user.email  // user's Gmail address
```

### Applied To

Middleware is registered at the router level for every protected route group:
```javascript
router.use(authMiddleware)  // in email.routes.js, alert.routes.js, user.routes.js
```

### No Refresh / Logout

- **No refresh token endpoint** — when the 7-day JWT expires, users must re-authenticate via OAuth
- **No logout endpoint** — logout is handled client-side by deleting the `jarvis_token` cookie; the backend has no token blocklist
- **No session storage** — fully stateless

### Gmail Token Refresh (separate from JWT)

When the background polling service receives a Gmail API 401:
1. Fetches user's `gmail_token` from database
2. Calls `refreshAccessToken(encryptedToken)`:
   - Decrypts `{ access_token, refresh_token }`
   - Calls `oauth2Client.refreshAccessToken()` with the refresh token
   - Google returns a new `access_token`
3. Re-encrypts and updates `users.gmail_token` in database
4. Retries the Gmail API call

---

## 7. NPM Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@supabase/supabase-js` | ^2.101.1 | Supabase PostgreSQL client — all DB reads/writes |
| `cors` | ^2.8.6 | Express CORS middleware — origin allowlisting |
| `dotenv` | ^17.3.1 | Loads `.env` file into `process.env` at startup |
| `express` | ^5.2.1 | Web framework — routing, middleware, request/response |
| `express-rate-limit` | ^8.3.2 | Per-route rate limiting (auth: 30/15min, api: 120/60s) |
| `express-validator` | ^7.3.1 | Request body/params/query validation with chainable rules |
| `googleapis` | ^171.4.0 | Google APIs client — Gmail fetch, OAuth2 token exchange |
| `helmet` | ^8.1.0 | Sets secure HTTP response headers (CSP, HSTS, etc.) |
| `jsonwebtoken` | ^9.0.3 | JWT signing (auth callback) and verification (middleware) |
| `morgan` | ^1.10.1 | HTTP access logging — `dev` format, skipped in production |
| `nodemailer` | ^8.0.4 | Gmail SMTP transport — last-resort alert email delivery |
| `nodemon` | ^3.1.14 | *(devDependency)* Auto-restarts server on file changes |

---

## 8. Middleware

Applied in this order in `server.js`:

### 1. `helmet()`
```javascript
app.use(helmet())
```
Automatically sets security-relevant HTTP headers:
- `Content-Security-Policy`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`
- `X-XSS-Protection`
- `Referrer-Policy: no-referrer`

### 2. `cors()`
```javascript
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true)
    cb(new Error(`CORS: origin ${origin} not allowed`))
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}))
```
- Requests with no `Origin` header (server-to-server, curl) are always allowed
- `allowedOrigins` = `ALLOWED_ORIGINS` split by comma, or `[FRONTEND_URL]` as default

### 3. `morgan('dev')`
```javascript
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'))
```
Logs `METHOD /path STATUS response_time_ms` — only in non-production.

### 4. `express.json({ limit: '1mb' })`
Parses JSON request bodies. Rejects bodies larger than 1 MB with `413`.

### 5. `app.set('trust proxy', 1)`
Required for Railway deployment — trusts the first proxy's `X-Forwarded-For` header. Needed for accurate IP-based rate limiting behind Railway's reverse proxy.

### 6. Auth rate limiter (`authLimiter`)
Applied to all `/auth` routes: **30 requests per 15 minutes**.

### 7. API rate limiter (`apiLimiter`)
Applied to `/email`, `/alert`, `/user` routes: **120 requests per 60 seconds**.

### 8. `authMiddleware` (per router)
Verifies `Authorization: Bearer <jwt>`. Sets `req.user` on success. Applied via `router.use(authMiddleware)` in email, alert, and user route files.

### 9. `validate` (per endpoint)
Runs `express-validator` result checks. Returns `400` with field-level error messages if any validator failed.

```javascript
export function validate(req, res, next) {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() })
  }
  next()
}
```

### 10. `errorHandler` (global, last)
```javascript
app.use(errorHandler)
```
Catches all errors thrown by routes. Returns safe error messages — in production, 500 errors return the generic message `"An internal error occurred"` with no stack trace.

---

## 9. Validators & Schemas

All validation uses `express-validator` chains passed as middleware arrays before route handlers.

### `POST /email/rescan/:id`
```javascript
param('id').notEmpty().withMessage('id param is required')
```

### `POST /alert/trigger`
```javascript
body('emailId').notEmpty().withMessage('emailId is required'),
body('score')
  .isInt({ min: 0, max: 100 })
  .withMessage('score must be an integer between 0 and 100'),
body('reason').notEmpty().withMessage('reason is required'),
body('subject').notEmpty().withMessage('subject is required'),
body('phone')
  .notEmpty().withMessage('phone is required')
  .isLength({ min: 10 }).withMessage('phone must be at least 10 characters'),
```

### `PATCH /user/profile`
```javascript
body('phone')
  .optional()
  .isLength({ min: 10, max: 15 })
  .withMessage('phone must be 10-15 digits'),
```

---

## 10. TODOs, Bugs & Commented-Out Code

### Inline Comments (Not Bugs, But Notable)

**`server.js` — proxy trust note:**
```javascript
// Add this line near the top, after const app = express();
app.set('trust proxy', 1); // Railway uses proxy
```
This is implemented but documented as if it were an instruction — suggests it was added as a fix during deployment troubleshooting.

**`polling.service.js` — deduplication comment:**
```javascript
// Duplicate check — gmail_message_id stores the Gmail message ID
const { data: existing } = await supabase
  .from('emails')
  .select('id')
  .eq('gmail_message_id', email.id)
  .single();
```

### Known Gaps (Inferred from Code)

1. **`DISABLE_POLLING` env var is loaded but never checked** — the polling service always starts regardless of this variable being set to `"true"`. The variable has no effect.

2. **`attachment.util.js` is defined but never imported** — `detectAttachments()` exists with a comprehensive dangerous-extension list, but the email parser uses its own inline attachment extraction and ignores this utility.

3. **`linkExtractor.util.js` is defined but not used** — URL extraction is performed inline in `emailParser.util.js` using the same regex. The utility is redundant.

4. **`SUPABASE_ANON_KEY` is loaded but unused** — the backend always uses the service role key.

5. **`GEMINI_API_KEY` is in `.env` but unused** — likely a leftover from exploring Gemini as an alternative AI provider (same pattern as unused Google packages in the Python service).

6. **`POST /email/rescan/:id` sends empty body to AI service** — the rescan endpoint only sends subject and sender; body, links, and attachments are empty. This means the rescan cannot detect new phishing links that were in the original email body.

7. **No logout endpoint** — JWT expiry is 7 days. There is no server-side token revocation, so a stolen token remains valid until expiry.

8. **No explicit `WHATSAPP_BUSINESS_ACCOUNT_ID` usage** — loaded from `.env` but not referenced in any service file.

### No TODO/FIXME Comments Found

The codebase contains zero `// TODO`, `// FIXME`, or `// HACK` comments.

---

## 11. Security Implementations

### CORS

```javascript
origin: (origin, cb) => {
  if (!origin || allowedOrigins.includes(origin)) return cb(null, true)
  cb(new Error(`CORS: origin ${origin} not allowed`))
}
```
- Whitelist-only: origins not in the list are rejected with an error
- Requests without an `Origin` header (server-to-server) are permitted
- Methods: `GET, POST, PATCH, DELETE` only
- Headers: `Content-Type, Authorization` only

### Helmet

Default Helmet configuration provides all of:

| Header | Effect |
|--------|--------|
| `Content-Security-Policy` | Restricts resource loading sources |
| `X-Frame-Options: SAMEORIGIN` | Prevents clickjacking |
| `X-Content-Type-Options: nosniff` | Prevents MIME-type sniffing |
| `Strict-Transport-Security` | Enforces HTTPS |
| `X-XSS-Protection: 0` | Disables browser XSS filter (modern approach) |
| `Referrer-Policy: no-referrer` | Suppresses referrer header |
| `Origin-Agent-Cluster: ?1` | Process isolation hint |

### Rate Limiting

| Route Group | Window | Max Requests | Response on Limit |
|-------------|--------|-------------|-------------------|
| `/auth/*` | 15 minutes | 30 | `{ "success": false, "message": "Too many requests, please try again later." }` |
| `/email/*` `/alert/*` `/user/*` | 60 seconds | 120 | Same message |

Uses `express-rate-limit` with `standardHeaders: true` (returns `RateLimit-*` headers) and `legacyHeaders: false`.

### Gmail Token Encryption

```javascript
// encrypt.util.js
const key = Buffer.from(ENCRYPTION_KEY).subarray(0, 32)
const iv  = crypto.randomBytes(16)
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()])
return `${iv.toString('hex')}:${encrypted.toString('hex')}`
```

- **Algorithm:** AES-256-CBC
- **Key:** First 32 bytes of `ENCRYPTION_KEY`
- **IV:** Randomly generated per encryption (16 bytes)
- **Format stored:** `{hex_iv}:{hex_ciphertext}`
- **What's encrypted:** `JSON.stringify({ access_token, refresh_token })`

### Startup Environment Validation

```javascript
const REQUIRED_ENV = [
  'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET',
  'ENCRYPTION_KEY', 'GMAIL_CLIENT_ID', 'GMAIL_CLIENT_SECRET',
  'GMAIL_REDIRECT_URI', 'FRONTEND_URL', 'PYTHON_SERVICE_URL',
]
const missing = REQUIRED_ENV.filter(k => !process.env[k])
if (missing.length > 0) {
  console.error(`Missing required environment variables: ${missing.join(', ')}`)
  process.exit(1)
}
if ((process.env.JWT_SECRET ?? '').length < 32) {
  console.error('JWT_SECRET must be at least 32 characters')
  process.exit(1)
}
```

Process exits with code 1 on startup if any required variable is absent or JWT_SECRET is too short.

### Input Validation

**Phone number (WhatsApp):**
```javascript
const clean = String(phone).replace(/^\+/, '').replace(/[\s\-().]/g, '')
if (!/^\d{10,15}$/.test(clean)) throw new Error(`Invalid phone number format`)
```

**Email body (sent to AI):**
- HTML stripped via regex before sending to Python service
- Non-ASCII stripped in Python service (double-sanitized)

**Request body size:** Capped at 1 MB by `express.json({ limit: '1mb' })`.

### Error Information Disclosure

```javascript
const message = isProd && status === 500
  ? 'An internal error occurred'
  : err.message
```

In production, 500-level errors return only `"An internal error occurred"` — no stack traces, no internal paths, no database error details.

---

## 12. Email Scanning Flow

### Background Polling (Automatic)

**File:** `services/polling.service.js`  
**Interval:** 30 seconds after each cycle completes (not a fixed cron interval)  
**Concurrency guard:** `isPolling` flag — if a poll is still running when the next timer fires, the new cycle is skipped and rescheduled.

```
Server starts
    → startPollingInterval() called
    → poll() runs immediately
        → startPolling() for all users
        → isPolling = false
    → setTimeout(poll, 30000)
    → poll() runs again...
```

**Polling cycle detail:**

```
1. SELECT id, email, phone FROM users WHERE gmail_token IS NOT NULL

2. For each user (sequential):
   a. createAuthClient(encryptedToken)           → authenticated Gmail API client
   b. Gmail.users.messages.list(                 → fetch unread email IDs
        q = 'newer_than:3d is:unread',
        maxResults = 20
      )
   c. For each message ID (sequential):
      i.   CHECK: SELECT id FROM emails WHERE gmail_message_id = $id
           → skip if already processed (deduplication)
      ii.  Gmail.users.messages.get(id, format='raw') → raw MIME bytes
      iii. Gmail.users.messages.modify(            → mark as read IMMEDIATELY
             { removeLabelIds: ['UNREAD'] }         → prevents duplicate if poll overlaps
           )
      iv.  parseEmail(rawMessage)                  → { subject, sender, body, links, attachments }
      v.   cleanHtml(body)                         → plain text
      vi.  scanLinks(links)                        → VirusTotal results (allSettled)
      vii. analyzeEmail(subject, sender, body,     → { score, reason, threatLevel }
             links, attachments)                      (with 3-attempt retry)
      viii.makeDecision(score)                     → { level, shouldAlert, message }
      ix.  INSERT INTO emails (...)
      x.   INSERT INTO scans (...)
      xi.  IF decision.shouldAlert AND user.phone:
              triggerAlert(emailId, score, reason, subject, phone, level)
                → WhatsApp → SMS → Email cascade
                → INSERT INTO alerts (...)

3. On Gmail 401: refresh access token, retry Gmail call
4. On any error: log, continue to next email / next user
```

### Manual Scan (On-Demand)

Same logic as polling, but triggered via `POST /email/scan` for only the authenticated user. Used by the frontend "Scan Now" button.

---

## 13. Utility & Helper Functions

### `utils/encrypt.util.js`

```javascript
encrypt(text: string) → string        // AES-256-CBC, returns "hex_iv:hex_ciphertext"
decrypt(ivAndData: string) → string   // Decrypts "hex_iv:hex_ciphertext" → plaintext
```

Throws if `ivAndData` doesn't contain `:` separator.

---

### `utils/emailParser.util.js`

```javascript
parseEmail(rawMessage) → { subject, sender, body, links, attachments }
```

- Decodes Gmail's base64url-encoded raw MIME message
- Traverses `payload.parts` recursively to find `text/plain` or `text/html` parts
- Prefers `text/plain`; falls back to `text/html` (which is then HTML-stripped)
- Extracts attachments from MIME parts (filename + mimeType)
- Extracts URLs from body using regex `/https?:\/\/[^\s"'<>)]+/g`

---

### `utils/htmlCleaner.util.js`

```javascript
cleanHtml(html: string) → string
```

Processing pipeline:
1. `/<[^>]+>/g` → replace all HTML tags with space
2. `&amp;` → `&`, `&lt;` → `<`, `&gt;` → `>`, `&nbsp;` → ` `, `&quot;` → `"`
3. `/\s+/g` → single space (collapse whitespace)
4. `.trim()`

---

### `utils/linkExtractor.util.js`

```javascript
extractLinks(text: string) → string[]
```

Regex: `/https?:\/\/[^\s"'<>)]+/g`  
Deduplicates using `new Set([...matches])`.  
**Note:** Defined but not called — email parser has equivalent inline logic.

---

### `utils/attachment.util.js`

```javascript
detectAttachments(parts: MimePart[]) → Array<{ filename, mimeType, isDangerous }>
```

Recursively walks MIME parts. Flags as dangerous if filename ends with:
`.exe .bat .cmd .com .vbs .vbe .ps1 .ps2 .psm1 .psd1 .jar .msi .msp .msix .sh .bash .zsh .scr .pif .reg .js .jse .wsf .wsh .hta .cpl .inf`

**Note:** Defined but not imported anywhere — email parser uses inline attachment extraction.

---

### `services/decision.service.js`

```javascript
makeDecision(score: number) → { level, shouldAlert, message }
```

| Score | level | shouldAlert | message |
|-------|-------|-------------|---------|
| 0 – 40 | `'LOW'` | `false` | `'Email appears safe'` |
| 41 – 60 | `'MEDIUM'` | `true` | `'Email is suspicious'` |
| 61 – 100 | `'HIGH'` | `true` | `'Threat detected - alert triggered'` |

---

### `services/gmail.service.js`

| Function | Purpose |
|----------|---------|
| `getAuthUrl()` | Creates OAuth2 client, generates Google consent screen URL |
| `getTokens(code)` | Exchanges OAuth code for `{ access_token, refresh_token }` |
| `createAuthClient(encryptedToken)` | Decrypts stored token, returns authenticated OAuth2 client |
| `encryptTokenData(tokens)` | Encrypts `{ access_token, refresh_token }` for DB storage |
| `refreshAccessToken(encryptedToken)` | Uses refresh token to get new access token; returns updated encrypted token |

---

## 14. Error Handling

### Centralized Error Handler

`middleware/errorHandler.middleware.js` — registered last in `server.js`:

```javascript
export default function errorHandler(err, req, res, next) {
  const status  = err.status || err.statusCode || 500
  const isProd  = process.env.NODE_ENV === 'production'

  console.error(`[Error] ${req.method} ${req.path} → ${status}: ${err.message}`)
  if (!isProd) console.error(err.stack)

  const message = isProd && status === 500
    ? 'An internal error occurred'
    : err.message

  res.status(status).json({ success: false, message })
}
```

### Supabase Query Errors

```javascript
const { data, error } = await supabase.from('emails').select('*')
if (error) throw new Error(error.message)
```
All Supabase errors are re-thrown as plain `Error` objects, caught by the centralized handler.

### Service Errors (Network / External API)

```javascript
const res = await fetch(url, options)
if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
```
Failed external calls throw errors that bubble up to the error handler or are caught locally.

### AI Service — Retry with Backoff

3 attempts total, delays of 2s and 4s between retries. After all 3 fail, throws:
```
"AI service unavailable after 3 attempts: {lastError.message}"
```

### VirusTotal — Partial Failure Tolerance

```javascript
const results = await Promise.allSettled(links.map(scanLink))
return results.map((r, i) =>
  r.status === 'fulfilled'
    ? r.value
    : { url: links[i], malicious: 0, suspicious: 0, result: 'scan_failed' }
)
```
One failed link scan does not abort analysis of the rest.

### Polling — Per-Email Isolation

In the polling loop, each email is processed in a try-catch. A failure on one email (parse error, AI timeout, etc.) logs the error and continues to the next email, never aborting the user's entire poll cycle.

### Gmail Token Expiry — Auto-Refresh

When Gmail returns 401 during polling, the token refresh flow runs automatically and the API call is retried once with the new access token before giving up.
