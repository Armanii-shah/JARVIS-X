import { google } from 'googleapis';
import supabase from '../config/supabase.js';
import { decrypt } from '../utils/encrypt.util.js';

export async function fetchNewEmails(userId) {
  const { data: user, error } = await supabase
    .from('users')
    .select('gmail_token')
    .eq('id', userId)
    .single();

  if (error) throw new Error(error.message);

  const accessToken = decrypt(user.gmail_token);

  const auth = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    process.env.GMAIL_REDIRECT_URI
  );
  auth.setCredentials({ access_token: accessToken });

  const gmail = google.gmail({ version: 'v1', auth });

  const listRes = await gmail.users.messages.list({
    userId: 'me',
    q: 'is:unread',
    maxResults: 10,
  });

  const messages = listRes.data.messages || [];

  const emails = await Promise.all(
    messages.map((msg) =>
      gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' })
        .then((res) => res.data)
    )
  );

  return emails;
}
