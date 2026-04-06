# JARVIS-X — Claude Code Instructions

## Project
AI-powered email security backend. Node.js + Express + Supabase + Gmail OAuth.

## Stack
- Node.js + Express (ES modules only)
- Supabase (PostgreSQL)
- Gmail OAuth 2.0 + AES-256-CBC encryption
- WhatsApp Business Cloud API — Meta Official (primary alert)
- Vonage SMS (fallback alert)
- VirusTotal API (link scanning)
- Python FastAPI (external ML service at PYTHON_SERVICE_URL)

## Coding Rules
- ES modules always (import/export) — never require()
- async/await always — never .then() or callbacks
- try/catch in every async function
- process.env for all secrets — never hardcode
- Single responsibility per file
- No unnecessary comments

## Folder Structure
```
jarvis-x-backend/
├── config/        → supabase.js
├── controllers/   → auth, email, alert, user
├── routes/        → auth, email, alert, user
├── services/      → gmail, email, polling, ai, alert, whatsapp, vonage, virustotal, decision
├── middleware/    → auth.middleware.js
├── utils/         → encrypt.util.js, htmlCleaner.util.js, linkExtractor.util.js, attachment.util.js
└── server.js
```

## Alert Flow
WhatsApp Business Cloud API (primary) → Vonage SMS (fallback) → Email (last resort)
Score > 60 = alert trigger

## ENV Variables
SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REDIRECT_URI,
ENCRYPTION_KEY,
WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID, WHATSAPP_BUSINESS_ACCOUNT_ID,
VONAGE_API_KEY, VONAGE_API_SECRET,
VIRUSTOTAL_API_KEY,
OPENAI_API_KEY,
PYTHON_SERVICE_URL,
PORT