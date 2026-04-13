import { google } from 'googleapis';
import { encrypt, decrypt } from '../utils/encrypt.util.js';

const createOAuthClient = () =>
  new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );

export function getAuthUrl() {
  const client = createOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/gmail.settings.basic',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
    prompt: 'consent',
  });
  return url;
}

export async function getTokens(code) {
  const client = createOAuthClient();
  const { tokens } = await client.getToken(code);
  return tokens;
}

// Decrypt stored token — supports both old (plain access_token string) and new (JSON) format
function decryptTokenData(encryptedToken) {
  const raw = decrypt(encryptedToken);
  try {
    return JSON.parse(raw); // new format: { access_token, refresh_token }
  } catch {
    return { access_token: raw, refresh_token: null }; // old format: just access_token string
  }
}

// Returns an authenticated OAuth2 client from encrypted stored token
export function createAuthClient(encryptedToken) {
  const client = createOAuthClient();
  const { access_token, refresh_token } = decryptTokenData(encryptedToken);
  client.setCredentials({
    access_token,
    ...(refresh_token ? { refresh_token } : {}),
  });
  return client;
}

// Encrypts both tokens as JSON for storage
export function encryptTokenData(tokens) {
  return encrypt(JSON.stringify({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? null,
  }));
}

// Refreshes access token using stored encrypted token
// Returns { encryptedToken, accessToken } on success
export async function refreshAccessToken(encryptedToken) {
  const { refresh_token } = decryptTokenData(encryptedToken);

  if (!refresh_token) {
    throw new Error('No refresh token stored — user must re-authenticate');
  }

  const client = createOAuthClient();
  client.setCredentials({ refresh_token });

  const { credentials } = await client.refreshAccessToken();
  console.log(`[Gmail] Token refreshed successfully`);

  const newEncrypted = encrypt(JSON.stringify({
    access_token: credentials.access_token,
    refresh_token: credentials.refresh_token ?? refresh_token, // keep old refresh_token if not rotated
  }));

  return { encryptedToken: newEncrypted, accessToken: credentials.access_token };
}
