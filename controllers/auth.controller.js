import { google } from 'googleapis';
import { getAuthUrl, getTokens } from '../services/gmail.service.js';
import { encrypt } from '../utils/encrypt.util.js';
import supabase from '../config/supabase.js';

export async function gmailAuth(_req, res) {
  try {
    const url = getAuthUrl();
    res.redirect(url);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function gmailCallback(req, res) {
  try {
    const { code } = req.query;
    const tokens = await getTokens(code);

    const oauth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      process.env.GMAIL_REDIRECT_URI
    );
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();
    const email = data.email;

    const encryptedToken = encrypt(tokens.access_token);

    const { error } = await supabase.from('users').upsert({
      email,
      gmail_token: encryptedToken,
      plan: 'free',
    }, { onConflict: 'email' });

    if (error) throw new Error(error.message);

    res.json({ success: true, email });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message, stack: error.stack });
  }
}
