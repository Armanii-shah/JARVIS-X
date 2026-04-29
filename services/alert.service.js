import { sendWhatsAppAlert } from './whatsapp.service.js';
import { makeSecurityCall } from './twilio.service.js';
import supabase from '../config/supabase.js';

async function saveAlert(userId, emailId, channel, status) {
  const { error } = await supabase.from('alerts').insert({
    user_id: userId,
    email_id: emailId,
    type: channel,
    status: status,
    triggered_at: new Date().toISOString(),
  });
  if (error) console.error(`[Alert] Failed to save alert (${channel}): ${error.message}`);
}

export async function triggerAlert(userId, emailId, score, reason, subject, phone, threatLevel) {
  console.log(`[Alert] ======= triggerAlert CALLED =======`);
  console.log(`[Alert] phone: ${phone ?? 'NOT SET'} | score: ${score} | level: ${threatLevel}`);
  console.log(`[Alert] subject: "${subject}"`);

  if (!phone) {
    console.log(`[Alert] No phone — skipping all channels`);
    await saveAlert(userId, emailId, 'none', 'failed');
    return { success: false, channel: 'none' };
  }

  // ── Fire WhatsApp + Voice call in parallel — completely independent ─────────
  const [waResult, callResult] = await Promise.allSettled([
    sendWhatsAppAlert(phone, score, reason, subject, threatLevel),
    makeSecurityCall(phone, subject, score),
  ]);

  const waOk   = waResult.status   === 'fulfilled';
  const callOk = callResult.status === 'fulfilled';

  console.log(`[WhatsApp] ${waOk   ? '✓ delivered'    : `✗ failed: ${waResult.reason?.message}`}`);
  console.log(`[Twilio]   ${callOk ? '✓ call initiated' : `✗ failed: ${callResult.reason?.message}`}`);

  // Persist each channel result independently
  if (waOk)   await saveAlert(userId, emailId, 'whatsapp', 'sent');
  if (callOk) await saveAlert(userId, emailId, 'call',     'sent');
  if (!waOk && !callOk) await saveAlert(userId, emailId, 'none', 'failed');

  const success  = waOk || callOk;
  const channels = [waOk && 'whatsapp', callOk && 'call'].filter(Boolean).join('+') || 'none';

  console.log(`[Alert] ── END — channels: ${channels} | success: ${success} ──`);
  return { success, channel: channels };
}
