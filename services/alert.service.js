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

export async function triggerAlert(userId, emailId, score, reason, subject, phone, threatLevel) {
  let channel;
  let status = 'sent';

  try {
    await sendWhatsAppAlert(phone, score, reason, subject, threatLevel);
    channel = 'whatsapp';
  } catch (whatsappErr) {
    console.error('WhatsApp failed:', whatsappErr.message);
    try {
      await sendSMS(phone, `JARVIS-X ALERT: ${subject} Score: ${score}`);
      channel = 'sms';
    } catch (smsErr) {
      console.error('SMS failed:', smsErr.message);
      try {
        await sendEmailAlert(subject, score, reason);
        channel = 'email';
      } catch (emailErr) {
        console.error('Email failed:', emailErr.message);
        status = 'failed';
        channel = 'none';
      }
    }
  }

  await supabase.from('alerts').insert({
    email_id: emailId,
    user_id: userId,
    type: channel,
    status,
    triggered_at: new Date().toISOString(),
  });

  return { success: status !== 'failed', channel };
}
