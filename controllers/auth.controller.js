import { google } from 'googleapis';
import jwt from 'jsonwebtoken';
import { getAuthUrl, getTokens, encryptTokenData } from '../services/gmail.service.js';
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
    console.log(`[${req.id}] [Auth] Gmail OAuth callback received`);
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

    const encryptedToken = encryptTokenData(tokens); // stores both access_token + refresh_token

    const { error: upsertError } = await supabase.from('users').upsert({
      email,
      gmail_token: encryptedToken,
      plan: 'free',
    }, { onConflict: 'email' });

    if (upsertError) throw new Error(upsertError.message);

    const { data: user, error: fetchError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (fetchError) throw new Error(fetchError.message);

    const token = jwt.sign(
      { userId: user.id, email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.redirect(
      `${process.env.FRONTEND_URL}/auth/callback?token=${token}&email=${encodeURIComponent(email)}`
    );
  } catch (error) {
    console.error(`[${req.id}] [Auth] Gmail callback error:`, error.message);
    // Never expose internal error details in the redirect URL
    res.redirect(`${process.env.FRONTEND_URL}/auth/login?error=authentication_failed`);
  }
}
