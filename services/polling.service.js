import { google } from 'googleapis';
import { fetchNewEmails } from './email.service.js';
import { analyzeEmail } from './ai.service.js';
import { makeDecision } from './decision.service.js';
import { triggerAlert } from './alert.service.js';
import { parseEmail } from '../utils/emailParser.util.js';
import { cleanHtml } from '../utils/htmlCleaner.util.js';
import { decrypt } from '../utils/encrypt.util.js';
import supabase from '../config/supabase.js';

export async function startPolling() {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, email')
      .not('gmail_token', 'is', null);

    if (error) throw new Error(error.message);

    for (const user of users) {
      try {
        const emails = await fetchNewEmails(user.id);
        if (!emails || emails.length === 0) continue;

        for (const email of emails) {
          try {
            const { data: existing } = await supabase
              .from('emails')
              .select('id')
              .eq('gmail_message_id', email.id)
              .single();

            if (existing) {
              console.log('Already scanned: ' + email.id);
              continue;
            }

            const parsed = parseEmail(email);
            parsed.body = cleanHtml(parsed.body);

            const analysis = await analyzeEmail(parsed);
            const decision = makeDecision(analysis.score);

            if (decision.shouldAlert) {
              const { data: userData } = await supabase
                .from('users')
                .select('phone')
                .eq('id', user.id)
                .single();

              await triggerAlert(
                user.id,
                null,
                analysis.score,
                analysis.reason,
                parsed.subject,
                userData?.phone || '923265521790'
              );
            }

            await supabase.from('emails').insert({
              user_id: user.id,
              gmail_message_id: email.id,
              subject: parsed.subject,
              sender: parsed.sender,
              score: analysis.score,
              threat_level: analysis.threatLevel,
              scanned_at: new Date().toISOString(),
            });

            const { data: userToken } = await supabase
              .from('users')
              .select('gmail_token')
              .eq('id', user.id)
              .single();

            const auth = new google.auth.OAuth2(
              process.env.GMAIL_CLIENT_ID,
              process.env.GMAIL_CLIENT_SECRET,
              process.env.GMAIL_REDIRECT_URI
            );
            auth.setCredentials({ access_token: decrypt(userToken.gmail_token) });

            const gmail = google.gmail({ version: 'v1', auth });
            await gmail.users.messages.modify({
              userId: 'me',
              id: email.id,
              requestBody: { removeLabelIds: ['UNREAD'] },
            });
            console.log('Marked as read: ' + email.id);

            console.log('Email analyzed: ' + parsed.subject + ' Score: ' + analysis.score);
          } catch (err) {
            console.error('Failed to process email for user ' + user.id + ':', err.message);
          }
        }
      } catch (err) {
        const msg = err.message?.toLowerCase() || '';
        if (msg.includes('401') || msg.includes('invalid authentication') || msg.includes('unauthenticated')) {
          console.log('Gmail token expired for user: ' + user.email + ' — skipping');
          continue;
        }
        console.error('Error polling user ' + user.email + ':', err.message);
      }
    }
  } catch (err) {
    console.error('startPolling crashed:', err.message);
  }
}

export function startPollingInterval() {
  console.log('Email polling started - 30s interval');
  const intervalId = setInterval(startPolling, 30000);
  return intervalId;
}
