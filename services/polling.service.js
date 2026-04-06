import { google } from 'googleapis';
import { fetchNewEmails } from './email.service.js';
import { analyzeEmail } from './ai.service.js';
import { makeDecision } from './decision.service.js';
import { triggerAlert } from './alert.service.js';
import { parseEmail } from '../utils/emailParser.util.js';
import { cleanHtml } from '../utils/htmlCleaner.util.js';
import { createAuthClient, refreshAccessToken } from './gmail.service.js';
import supabase from '../config/supabase.js';

async function processUser(user) {
  console.log(`[Polling] Fetching emails for user: ${user.email}`);

  let emails;
  try {
    emails = await fetchNewEmails(user.id);
  } catch (err) {
    const msg = err.message?.toLowerCase() || '';
    const is401 = msg.includes('401') || msg.includes('invalid authentication') || msg.includes('unauthenticated');

    if (!is401) throw err;

    // Attempt token refresh
    console.log(`[Polling] Token expired for ${user.email} — attempting refresh`);
    const { data: stored } = await supabase.from('users').select('gmail_token').eq('id', user.id).single();

    let newEncryptedToken;
    try {
      const refreshed = await refreshAccessToken(stored.gmail_token);
      newEncryptedToken = refreshed.encryptedToken;
    } catch (refreshErr) {
      console.log(`[Polling] Token refresh failed for user: ${user.email} — ${refreshErr.message}`);
      return;
    }

    // Save refreshed token
    await supabase.from('users').update({ gmail_token: newEncryptedToken }).eq('id', user.id);
    console.log(`[Polling] Token refreshed and saved for: ${user.email}`);

    // Retry with new token
    emails = await fetchNewEmails(user.id);
  }

  if (!emails || emails.length === 0) {
    console.log(`[Polling] No new emails for: ${user.email}`);
    return;
  }

  console.log(`[Polling] Fetched ${emails.length} email(s) for user: ${user.email}`);

  // Create Gmail auth client once for the whole user session
  const { data: userTokenRow } = await supabase
    .from('users')
    .select('gmail_token')
    .eq('id', user.id)
    .single();
  const auth = createAuthClient(userTokenRow.gmail_token);
  const gmail = google.gmail({ version: 'v1', auth });

  for (const email of emails) {
    try {
      // Duplicate check — external_id stores the Gmail message ID
      const { data: existing } = await supabase
        .from('emails')
        .select('id')
        .eq('external_id', email.id)
        .single();

      if (existing) {
        console.log(`[Polling] Already scanned (duplicate): ${email.id}`);
        continue;
      }

      // Mark as read in Gmail IMMEDIATELY — before any processing or alerting.
      // This prevents a concurrent poll from fetching the same email and firing a duplicate alert.
      try {
        await gmail.users.messages.modify({
          userId: 'me',
          id: email.id,
          requestBody: { removeLabelIds: ['UNREAD'] },
        });
        console.log(`[Polling] Marked as read in Gmail: ${email.id}`);
      } catch (markErr) {
        console.error(`[Polling] Failed to mark as read in Gmail: ${markErr.message}`);
      }

      const parsed = parseEmail(email);
      parsed.body = cleanHtml(parsed.body);

      console.log(`[Polling] Analyzing email: "${parsed.subject}"`);

      const analysis = await analyzeEmail(parsed);
      const decision = makeDecision(analysis.score);

      console.log(`[Polling] Score: ${analysis.score}, Level: ${analysis.threatLevel}, ShouldAlert: ${decision.shouldAlert}`);

      // Parse sender into name + email parts (format: "Name <email@domain.com>" or just "email@domain.com")
      const senderRaw = parsed.sender || '';
      const senderEmailMatch = senderRaw.match(/<([^>]+)>/);
      const senderEmail = senderEmailMatch ? senderEmailMatch[1] : senderRaw.trim();
      const senderName = senderEmailMatch ? senderRaw.slice(0, senderRaw.indexOf('<')).trim() : null;

      // Extract received date from Gmail headers (internalDate is ms since epoch)
      const receivedAt = email.internalDate
        ? new Date(Number(email.internalDate)).toISOString()
        : new Date().toISOString();

      console.log(`[DB] Attempting to insert email: "${parsed.subject}"`);

      const { data: insertedEmail, error: insertError } = await supabase
        .from('emails')
        .insert({
          user_id: user.id,
          external_id: email.id,          // Gmail message ID → external_id
          subject: parsed.subject,
          sender_email: senderEmail,      // was 'sender' — table uses sender_email
          sender_name: senderName,        // table has separate sender_name column
          risk_score: analysis.score,     // was 'score' — table uses risk_score
          threat_level: analysis.threatLevel.toLowerCase(), // must be lowercase: low/medium/high
          received_at: receivedAt,        // NOT NULL in table — was missing entirely
          scanned_at: new Date().toISOString(),
        })
        .select('id')
        .single();

      console.log('[DB] Insert result - data:', JSON.stringify(insertedEmail));
      console.log('[DB] Insert error:', JSON.stringify(insertError));

      if (insertError) {
        console.error(`[Polling] Failed to insert email: ${insertError.message} — skipping alert to prevent duplicate`);
        continue;
      }

      if (decision.shouldAlert) {
        const phone = user.phone;
        console.log(`[Polling] User phone: ${phone ?? 'NOT SET'}`);

        if (!phone) {
          console.log(`[Polling] No phone number for user ${user.email}, skipping alert`);
        } else {
          console.log(`[Polling] Triggering alert for: "${parsed.subject}"`);
          await triggerAlert(
            user.id,
            insertedEmail?.id ?? null,
            analysis.score,
            analysis.reason,
            parsed.subject,
            phone,
            analysis.threatLevel
          );
          console.log(`[Polling] Alert triggered successfully`);
        }
      }

      console.log(`[Polling] Done — "${parsed.subject}" | Score: ${analysis.score} | Level: ${analysis.threatLevel}`);
    } catch (err) {
      console.error(`[Polling] Failed to process email for user ${user.email}:`, err.message);
    }
  }
}

export async function startPolling() {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, email, phone')
      .not('gmail_token', 'is', null);

    if (error) throw new Error(error.message);

    console.log(`[Polling] Found ${users?.length ?? 0} user(s) with Gmail connected`);

    for (const user of users) {
      try {
        await processUser(user);
      } catch (err) {
        console.error(`[Polling] Error polling user ${user.email}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[Polling] startPolling crashed:', err.message);
  }
}

export function startPollingInterval() {
  let isPolling = false;

  async function poll() {
    if (isPolling) {
      console.log('[Polling] Previous poll still running, skipping this cycle');
      setTimeout(poll, 30000);
      return;
    }
    isPolling = true;
    try {
      await startPolling();
    } finally {
      isPolling = false;
      setTimeout(poll, 30000);
    }
  }

  console.log('[Polling] Email polling started — 30s interval');
  poll(); // run immediately on start, then every 30s after completion
}
