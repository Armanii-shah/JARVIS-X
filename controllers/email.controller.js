import { google } from 'googleapis';
import { fetchNewEmails, markEmailAsRead } from '../services/email.service.js';
import { parseEmail } from '../utils/emailParser.util.js';
import { cleanHtml } from '../utils/htmlCleaner.util.js';
import { analyzeEmail } from '../services/ai.service.js';
import { makeDecision } from '../services/decision.service.js';
import { scanLinks } from '../services/virustotal.service.js';
import { isSenderBlocked } from '../utils/blockedCheck.util.js';
import { createAuthClient } from '../services/gmail.service.js';
import { triggerAlert } from '../services/alert.service.js';
import supabase from '../config/supabase.js';

export async function scanEmails(req, res) {
  try {
    const userId = req.user.id;
    console.log(`[${req.id}] [Email] scanEmails started for user ${req.user.email}`);
    const rawEmails = await fetchNewEmails(userId);
    console.log(`[${req.id}] [Email] Fetched ${rawEmails.length} new email(s) to scan`);
    const results = [];

    for (const raw of rawEmails) {
      const parsed = parseEmail(raw);
      parsed.body = cleanHtml(parsed.body);

      const senderRaw = parsed.sender || '';
      const senderEmailMatch = senderRaw.match(/<([^>]+)>/);
      const senderEmail = senderEmailMatch ? senderEmailMatch[1] : senderRaw.trim();
      const senderName = senderEmailMatch ? senderRaw.slice(0, senderRaw.indexOf('<')).trim() : null;

      // Skip VirusTotal and AI analysis entirely for blocked senders
      if (senderEmail && await isSenderBlocked(userId, senderEmail)) {
        console.log(`[${req.id}] [Email] Skipping blocked sender: ${senderEmail}`);
        continue;
      }

      const virusTotalResult = await scanLinks(parsed.links);
      const { score, reason } = await analyzeEmail(parsed);
      const decision = makeDecision(score);
      console.log(`[${req.id}] [Email] Scored "${parsed.subject}" → ${score} (${decision.level})`);

      const { data: emailRecord, error: emailError } = await supabase
        .from('emails')
        .insert({
          user_id: userId,
          gmail_message_id: raw.id,
          subject: parsed.subject,
          sender: parsed.sender || '',
          sender_email: senderEmail,
          sender_name: senderName,
          score: score,
          threat_level: decision.level.toLowerCase(),
          received_at: new Date().toISOString(),
          scanned_at: new Date().toISOString(),
        })
        .select('id')
        .single();

      if (emailError) throw new Error(emailError.message);

      // Mark as read in Gmail so polling doesn't re-process this email
      await markEmailAsRead(userId, raw.id).catch(err =>
        console.error(`[${req.id}] Failed to mark email as read:`, err.message)
      );

      const { error: scanError } = await supabase.from('scans').insert({
        email_id: emailRecord.id,
        virustotal_result: virusTotalResult,
        links_checked: parsed.links,
        score_breakdown: { score, reason },
      });

      if (scanError) throw new Error(scanError.message);

      results.push({
        subject: parsed.subject,
        sender: parsed.sender,
        score,
        threatLevel: decision.level,
        shouldAlert: decision.shouldAlert,
        message: decision.message,
      });
    }

    res.json({ success: true, scanned: results.length, results });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function getEmailHistory(req, res) {
  try {
    const userId = req.user.id;
    console.log(`[${req.id}] [Email] getEmailHistory for user ${req.user.email}`);

    const { data, error } = await supabase
      .from('emails')
      .select('*')
      .eq('user_id', userId)
      .order('scanned_at', { ascending: false });

    if (error) throw new Error(error.message);

    const emails = data ?? [];
    const byLevel = emails.reduce((acc, e) => {
      acc[e.threat_level] = (acc[e.threat_level] ?? 0) + 1;
      return acc;
    }, {});
    console.log(`[${req.id}] [Email] Returning ${emails.length} emails — breakdown: ${JSON.stringify(byLevel)}`);

    res.json(emails);
  } catch (error) {
    console.error(`[${req.id}] [Email] getEmailHistory error:`, error.message);
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function getSpamEmails(req, res) {
  try {
    const userId = req.user.id;

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('gmail_token')
      .eq('id', userId)
      .single();

    if (userError || !user?.gmail_token) {
      return res.json([]);
    }

    const auth = createAuthClient(user.gmail_token);
    const gmail = google.gmail({ version: 'v1', auth });

    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: 'in:spam newer_than:7d',
      maxResults: 30,
    });

    const messages = listRes.data.messages || [];
    if (messages.length === 0) return res.json([]);

    const rawEmails = await Promise.all(
      messages.map(msg =>
        gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'full' }).then(r => r.data)
      )
    );

    const results = [];
    for (const raw of rawEmails) {
      try {
        const parsed = parseEmail(raw);
        parsed.body = cleanHtml(parsed.body);

        const senderRaw = parsed.sender || '';
        const senderEmailMatch = senderRaw.match(/<([^>]+)>/);
        const senderEmail = senderEmailMatch ? senderEmailMatch[1] : senderRaw.trim();
        const senderName = senderEmailMatch ? senderRaw.slice(0, senderRaw.indexOf('<')).trim() : null;

        const isBlocked = await isSenderBlocked(userId, senderEmail);
        let score, threatLevel;
        if (isBlocked) {
          score = 100;
          threatLevel = 'high';
        } else {
          const analysis = await analyzeEmail(parsed);
          score = analysis.score;
          threatLevel = analysis.threatLevel.toLowerCase();
        }

        results.push({
          gmail_message_id: raw.id,
          subject: parsed.subject || null,
          sender: parsed.sender || null,
          sender_email: senderEmail || null,
          sender_name: senderName || null,
          score,
          threat_level: threatLevel,
          received_at: raw.internalDate
            ? new Date(parseInt(raw.internalDate)).toISOString()
            : null,
          is_blocked: isBlocked,
        });
      } catch (err) {
        console.error(`[SpamEmails] Failed to process email ${raw.id}:`, err.message);
      }
    }

    res.json(results);
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function rescueEmail(req, res) {
  try {
    const userId = req.user.id;
    const { gmailMessageId } = req.params;

    const { data: user, error: userError } = await supabase
      .from('users')
      .select('gmail_token')
      .eq('id', userId)
      .single();

    if (userError || !user?.gmail_token) {
      return res.status(400).json({ success: false, message: 'Gmail not connected' });
    }

    const auth = createAuthClient(user.gmail_token);
    const gmail = google.gmail({ version: 'v1', auth });

    await gmail.users.messages.modify({
      userId: 'me',
      id: gmailMessageId,
      requestBody: { addLabelIds: ['INBOX'], removeLabelIds: ['SPAM'] },
    });

    console.log(`[Email] Rescued message ${gmailMessageId} from spam to inbox for user ${req.user.email}`);
    res.json({ success: true, message: 'Email moved to inbox' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function retriggerAlert(req, res) {
  try {
    const emailId = req.params.id;
    const userId = req.user.id;
    console.log(`[${req.id}] [Alert] retriggerAlert for email ${emailId} user ${req.user.email}`);

    // Fetch email (scoped to this user)
    const { data: emailRecord, error: fetchError } = await supabase
      .from('emails')
      .select('*')
      .eq('id', emailId)
      .eq('user_id', userId)
      .single();

    if (fetchError || !emailRecord) {
      return res.status(404).json({ success: false, message: 'Email not found' });
    }

    // Fetch user phone
    const { data: userRow } = await supabase
      .from('users')
      .select('phone')
      .eq('id', userId)
      .single();

    const phone = userRow?.phone ?? null;
    console.log(`[${req.id}] [Alert] Retrigger — score=${emailRecord.score} level=${emailRecord.threat_level} phone=${phone ?? 'NOT SET'}`);

    const result = await triggerAlert(
      userId,
      emailRecord.id,
      emailRecord.score,
      `Manual retrigger — original score ${emailRecord.score}`,
      emailRecord.subject || '(No Subject)',
      phone,
      emailRecord.threat_level,
      emailRecord.sender || emailRecord.subject || '(Unknown)'
    );

    res.json({ success: result.success, channel: result.channel, phone, score: emailRecord.score });
  } catch (error) {
    console.error(`[Email] retriggerAlert error:`, error.message);
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function rescanEmail(req, res) {
  try {
    const emailId = req.params.id;
    const userId = req.user.id; // The authenticated user from JWT
    console.log(`[${req.id}] [Email] rescanEmail ${emailId} for user ${req.user.email}`);

    // SECURITY FIX: scope fetch to this user's emails only.
    // Without .eq('user_id', userId), any authenticated user could pass someone
    // else's email UUID and read its subject/sender, then overwrite its score.
    const { data: emailRecord, error: fetchError } = await supabase
      .from('emails')
      .select('*')
      .eq('id', emailId)
      .eq('user_id', userId) // <-- only fetch if it belongs to this user
      .single();

    // If the email doesn't exist OR belongs to a different user, fetchError is set
    if (fetchError) throw new Error(fetchError.message);

    const { score } = await analyzeEmail({
      subject: emailRecord.subject,
      sender: emailRecord.sender_email || '',
      body: '',
      links: [],
      attachments: [],
    });

    const decision = makeDecision(score);

    // SECURITY FIX: scope update to this user's emails only.
    // Without .eq('user_id', userId), any user could update any email's risk score.
    const { error: updateError } = await supabase
      .from('emails')
      .update({ score: score, threat_level: decision.level.toLowerCase() })
      .eq('id', emailId)
      .eq('user_id', userId); // <-- only update if it belongs to this user

    if (updateError) throw new Error(updateError.message);

    res.json({ success: true, newScore: score, threatLevel: decision.level });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}

export async function deleteEmail(req, res) {
  try {
    const userId = req.user.id;
    const { id } = req.params; // Supabase row ID

    // Fetch the email row — verify ownership and get gmail_message_id
    const { data: email, error: fetchError } = await supabase
      .from('emails')
      .select('id, gmail_message_id')
      .eq('id', id)
      .eq('user_id', userId)
      .single();

    if (fetchError || !email) {
      return res.status(404).json({ success: false, message: 'Email not found.' });
    }

    // Trash in Gmail if we have the message ID
    if (email.gmail_message_id) {
      const { data: user } = await supabase
        .from('users')
        .select('gmail_token')
        .eq('id', userId)
        .single();

      if (user?.gmail_token) {
        const auth = createAuthClient(user.gmail_token);
        const gmail = google.gmail({ version: 'v1', auth });
        await gmail.users.messages.trash({ userId: 'me', id: email.gmail_message_id })
          .catch(err => console.warn(`[Email] Gmail trash failed (non-fatal): ${err.message}`));
      }
    }

    // Delete from Supabase
    const { error: deleteError } = await supabase
      .from('emails')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (deleteError) throw new Error(deleteError.message);

    console.log(`[Email] Deleted email ${id} (gmail_message_id: ${email.gmail_message_id}) for user ${userId}`);
    res.json({ success: true });
  } catch (error) {
    console.error('[Email] deleteEmail error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
}
