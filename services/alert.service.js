import { sendWhatsAppAlert } from './whatsapp.service.js';
import { sendSMS } from './vonage.service.js';
import nodemailer from 'nodemailer';
import supabase from '../config/supabase.js';

async function sendEmailAlert(subject, score, reason) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });

  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: process.env.ALERT_EMAIL,
    subject: 'JARVIS-X SECURITY ALERT: ' + subject,
    text: `Threat Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nReason: ${reason}\n\nTake immediate action!`,
  });
}

async function saveAlert(emailId, userId, channel, status) {
  const { error } = await supabase.from('alerts').insert({
    email_id: emailId,
    user_id: userId,
    type: channel,
    status,
  });
  if (error) {
    console.error(`[Alert] Failed to save alert to DB: ${error.message}`);
  }
}

export async function triggerAlert(userId, emailId, score, reason, subject, phone, threatLevel) {
  console.log(`[Alert] triggerAlert called — userId: ${userId}, emailId: ${emailId}, score: ${score}, phone: ${phone ?? 'NOT SET'}`);

  if (!phone) {
    console.log(`[Alert] No phone number for user ${userId}, skipping WhatsApp/SMS alert`);
    await saveAlert(emailId, userId, 'none', 'failed');
    return { success: false, channel: 'none' };
  }

  let channel;
  let status = 'sent';

  try {
    await sendWhatsAppAlert(phone, score, reason, subject, threatLevel);
    channel = 'whatsapp';
    console.log(`[Alert] WhatsApp sent successfully to ${phone}`);
  } catch (whatsappErr) {
    console.error('[Alert] WhatsApp failed:', whatsappErr.message);
    try {
      await sendSMS(phone, subject, threatLevel);
      channel = 'sms';
      console.log(`[Alert] SMS sent successfully to ${phone}`);
    } catch (smsErr) {
      console.error('[Alert] SMS failed:', smsErr.message);
      try {
        await sendEmailAlert(subject, score, reason);
        channel = 'email';
        console.log('[Alert] Email alert sent successfully');
      } catch (emailErr) {
        console.error('[Alert] Email alert failed:', emailErr.message);
        status = 'failed';
        channel = 'none';
      }
    }
  }

  await saveAlert(emailId, userId, channel, status);
  console.log(`[Alert] Alert recorded — channel: ${channel}, status: ${status}`);
  return { success: status !== 'failed', channel };
}
