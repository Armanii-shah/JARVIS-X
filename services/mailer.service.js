import nodemailer from 'nodemailer';

function createTransporter() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;

  if (!user || !pass) {
    throw new Error('GMAIL_USER or GMAIL_APP_PASSWORD not configured');
  }

  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  });
}

export async function sendContactEmail({ name, email, topic, message }) {
  const transporter = createTransporter();
  const recipient = process.env.ALERT_EMAIL || process.env.GMAIL_USER;

  await transporter.sendMail({
    from: `"JARVIS-X Contact Form" <${process.env.GMAIL_USER}>`,
    to: recipient,
    replyTo: email,
    subject: `[Contact Form] ${topic ? `${topic} — ` : ''}${name}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; background: #f9f9f9; border-radius: 8px;">
        <h2 style="color: #0ea5e9; margin-bottom: 4px;">JARVIS-X — New Contact Message</h2>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 16px 0;" />

        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
          <tr>
            <td style="padding: 8px 0; color: #6b7280; width: 100px; vertical-align: top;"><strong>Name</strong></td>
            <td style="padding: 8px 0; color: #111827;">${name}</td>
          </tr>
          <tr>
            <td style="padding: 8px 0; color: #6b7280; vertical-align: top;"><strong>Email</strong></td>
            <td style="padding: 8px 0;">
              <a href="mailto:${email}" style="color: #0ea5e9;">${email}</a>
            </td>
          </tr>
          ${topic ? `
          <tr>
            <td style="padding: 8px 0; color: #6b7280; vertical-align: top;"><strong>Topic</strong></td>
            <td style="padding: 8px 0; color: #111827;">${topic}</td>
          </tr>` : ''}
        </table>

        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 16px 0;" />

        <p style="color: #6b7280; font-size: 13px; margin-bottom: 8px;"><strong>Message:</strong></p>
        <div style="background: #ffffff; border: 1px solid #e5e7eb; border-radius: 6px; padding: 16px; color: #111827; font-size: 14px; line-height: 1.6; white-space: pre-wrap;">${message}</div>

        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;" />
        <p style="color: #9ca3af; font-size: 12px; text-align: center;">
          Sent via JARVIS-X Contact Form — jarvisxsecurity.com
        </p>
      </div>
    `,
  });
}
