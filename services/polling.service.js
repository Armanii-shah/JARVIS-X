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
  console.log(`[Polling] ── processUser: ${user.email} | phone: ${user.phone ?? 'NOT SET IN DB'} ──`);

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
      // Duplicate check — scope to this user (SECURITY FIX from previous patch).
      const { data: existing } = await supabase
        .from('emails')
        .select('id')
        .eq('gmail_message_id', email.id)
        .eq('user_id', user.id)
        .single();

      if (existing) {
        // Email is already in our DB (processed successfully in a prior poll) but
        // is still showing as unread in Gmail — this happens when mark-as-read
        // failed or the process crashed after the insert. Clean it up now.
        console.log(`[Polling] Already scanned (duplicate): ${email.id} — marking read in Gmail`);
        await gmail.users.messages.modify({
          userId: 'me',
          id: email.id,
          requestBody: { removeLabelIds: ['UNREAD'] },
        }).catch(err => console.error(`[Polling] Failed to mark duplicate as read: ${err.message}`));
        continue;
      }

      // ─── PARSE ────────────────────────────────────────────────────────────
      // Do all fallible work (parse → AI → DB) BEFORE touching Gmail.
      // If anything here throws, the email stays unread and the next poll retries it.
      const parsed = parseEmail(email);
      parsed.body = cleanHtml(parsed.body);

      const senderRaw = parsed.sender || '';
      const senderEmailMatch = senderRaw.match(/<([^>]+)>/);
      const senderEmail = senderEmailMatch ? senderEmailMatch[1] : senderRaw.trim();
      const senderName = senderEmailMatch ? senderRaw.slice(0, senderRaw.indexOf('<')).trim() : null;

      // Check if sender is blocked — score as 100 / high, skip AI
      const { data: blockRecord } = await supabase
        .from('blocked_emails')
        .select('id')
        .eq('user_id', user.id)
        .eq('sender_email', senderEmail)
        .maybeSingle();

      let analysis;
      if (blockRecord) {
        console.log(`[Polling] Blocked sender detected: ${senderEmail} — scoring 100, skipping AI`);
        analysis = { score: 100, threatLevel: 'high', reason: 'Sender is blocked by user' };
      } else {
        console.log(`[Polling] Analyzing email: "${parsed.subject}"`);
        analysis = await analyzeEmail(parsed);
      }
      const decision = makeDecision(analysis.score);
      const levelEmoji = decision.level === 'HIGH' ? '🔴' : decision.level === 'MEDIUM' ? '🟡' : '🟢';
      console.log(`[Polling] ${levelEmoji} Score: ${analysis.score} | Level: ${decision.level} | ShouldAlert: ${decision.shouldAlert}`);
      console.log(`[Polling] shouldAlert: ${decision.shouldAlert}`);
      if (decision.shouldAlert) {
        const alertLabel = decision.level === 'MEDIUM' ? '⚠️  MEDIUM RISK' : '🚨 HIGH RISK';
        console.log(`[Polling] ${alertLabel} EMAIL — "${parsed.subject}" (score=${analysis.score})`);
      }

      // ─── SAVE TO DATABASE ─────────────────────────────────────────────────
      console.log(`[DB] Attempting to insert email: "${parsed.subject}"`);

      const { data: insertedEmail, error: insertError } = await supabase
        .from('emails')
        .insert({
          user_id: user.id,
          gmail_message_id: email.id,
          subject: parsed.subject,
          sender: parsed.sender || '',
          sender_email: senderEmail,
          sender_name: senderName,
          score: analysis.score,
          threat_level: analysis.threatLevel.toLowerCase(),
          received_at: new Date().toISOString(),
          scanned_at: new Date().toISOString(),
        })
        .select('id')
        .single();

      console.log('[DB] Insert result - data:', JSON.stringify(insertedEmail));
      console.log('[DB] Insert error:', JSON.stringify(insertError));

      if (insertError) {
        // Leave the email unread so the next poll can retry it.
        console.error(`[Polling] DB insert failed for "${parsed.subject}": ${insertError.message} — email stays unread for retry`);
        continue;
      }

      // ─── MARK AS READ IN GMAIL ────────────────────────────────────────────
      // Data is safely persisted. Only now is it safe to remove UNREAD from Gmail.
      // Transactional safety: the permanent side-effect (losing the email from
      // the inbox) happens LAST, after every operation that can fail has succeeded.
      // If this call fails, the email stays unread — next poll finds it via the
      // duplicate check above and cleans it up without re-processing.
      try {
        await gmail.users.messages.modify({
          userId: 'me',
          id: email.id,
          requestBody: { removeLabelIds: ['UNREAD'] },
        });
        console.log(`[Polling] Marked as read in Gmail: ${email.id}`);
      } catch (markErr) {
        // Non-fatal: the email is already saved. The duplicate-check path above
        // will mark it read on the next poll cycle.
        console.error(`[Polling] Failed to mark as read in Gmail (non-fatal, data saved): ${markErr.message}`);
      }

      // ─── TRIGGER ALERT ────────────────────────────────────────────────────
      if (decision.shouldAlert) {
        const phone = user.phone ?? null;
        console.log(`[Polling] 🚨 HIGH RISK EMAIL — score: ${analysis.score}, level: ${analysis.threatLevel}, triggering alert`);
        console.log(`[Polling] User phone: ${phone ?? 'NOT SET'}`);
        console.log(`[Polling] Alert check — user: ${user.email} | phone: ${phone ?? 'NOT SET'}`);
        if (!phone) console.log('[Polling] No phone — all alert channels skipped');

        console.log(`[Polling] Calling triggerAlert now...`);
        const alertResult = await triggerAlert(
          user.id,
          insertedEmail?.id ?? null,
          analysis.score,
          analysis.reason,
          parsed.subject,
          phone,
          analysis.threatLevel,
          senderRaw || parsed.subject
        );
        console.log(`[Polling] triggerAlert result:`, JSON.stringify(alertResult));
        console.log(`[Polling] Alert triggered successfully`);
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
