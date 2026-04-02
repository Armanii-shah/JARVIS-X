import { fetchNewEmails } from './email.service.js';
import supabase from '../config/supabase.js';

export async function startPolling() {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, email')
    .not('gmail_token', 'is', null);

  if (error) throw new Error(error.message);

  for (const user of users) {
    try {
      console.log('Polling emails for user: ' + user.email);
      await fetchNewEmails(user.id);
    } catch {
    }
  }
}

export function startPollingInterval() {
  console.log('Email polling started - 30s interval');
  const intervalId = setInterval(startPolling, 30000);
  return intervalId;
}
