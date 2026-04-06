import { google } from 'googleapis';
import supabase from '../config/supabase.js';
import { createAuthClient } from './gmail.service.js';

export async function fetchNewEmails(userId) {
  const { data: user, error } = await supabase
    .from('users')
    .select('gmail_token')
    .eq('id', userId)
    .single();

  if (error) throw new Error(error.message);

  const auth = createAuthClient(user.gmail_token);
  const gmail = google.gmail({ version: 'v1', auth });

  const listRes = await gmail.users.messages.list({
    userId: 'me',
    q: 'newer_than:3d is:unread',
    maxResults: 20,
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

export async function markEmailAsRead(userId, messageId) {
  const { data: user, error } = await supabase
    .from('users')
    .select('gmail_token')
    .eq('id', userId)
    .single();

  if (error) throw new Error(error.message);

  const auth = createAuthClient(user.gmail_token);
  const gmail = google.gmail({ version: 'v1', auth });

  await gmail.users.messages.modify({
    userId: 'me',
    id: messageId,
    requestBody: { removeLabelIds: ['UNREAD'] },
  });
}
