import { google } from 'googleapis';
import { encrypt, decrypt } from '../utils/encrypt.util.js';

const createOAuthClient = () =>
  new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );

export function getAuthUrl() {
  console.log('CLIENT_ID:' + process.env.GMAIL_CLIENT_ID);
  console.log('CLIENT_SECRET exists:' + !!process.env.GMAIL_CLIENT_SECRET);
  console.log('REDIRECT_URI:' + process.env.GMAIL_REDIRECT_URI);
  const client = createOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
    prompt: 'consent',
  });
  console.log('Auth URL:' + url);
  return url;
}

export async function getTokens(code) {
  const client = createOAuthClient();
  const { tokens } = await client.getToken(code);
  return tokens;
}

export async function refreshAccessToken(encryptedToken) {
  const client = createOAuthClient();
  const refreshToken = decrypt(encryptedToken);
  client.setCredentials({ refresh_token: refreshToken });
  const { credentials } = await client.refreshAccessToken();
  return encrypt(credentials.access_token);
}
