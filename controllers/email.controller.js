import { fetchNewEmails } from '../services/email.service.js';
import { parseEmail } from '../utils/emailParser.util.js';
import { cleanHtml } from '../utils/htmlCleaner.util.js';
import { analyzeEmail } from '../services/ai.service.js';
import { makeDecision } from '../services/decision.service.js';
import { scanLinks } from '../services/virustotal.service.js';
import { isSenderBlocked } from '../utils/blockedCheck.util.js';
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
          subject: parsed.subject,
          sender_email: senderEmail,
          sender_name: senderName,
          risk_score: score,
          threat_level: decision.level.toLowerCase(),
          received_at: new Date().toISOString(),
          scanned_at: new Date().toISOString(),
        })
        .select('id')
        .single();

      if (emailError) throw new Error(emailError.message);

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

    const { data, error } = await supabase
      .from('emails')
      .select('*')
      .eq('user_id', userId)
      .order('scanned_at', { ascending: false });

    if (error) throw new Error(error.message);

    res.json(data);
  } catch (error) {
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
      .update({ risk_score: score, threat_level: decision.level.toLowerCase() })
      .eq('id', emailId)
      .eq('user_id', userId); // <-- only update if it belongs to this user

    if (updateError) throw new Error(updateError.message);

    res.json({ success: true, newScore: score, threatLevel: decision.level });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
}
