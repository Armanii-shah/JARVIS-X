import { Router } from 'express';
import { sendContactEmail } from '../services/mailer.service.js';

const router = Router();

// POST /contact
router.post('/', async (req, res) => {
  const { name, email, topic, message } = req.body;

  if (!name?.trim() || !email?.trim() || !message?.trim()) {
    return res.status(400).json({ success: false, message: 'name, email and message are required.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email address.' });
  }

  if (message.trim().length > 1000) {
    return res.status(400).json({ success: false, message: 'Message must be under 1000 characters.' });
  }

  try {
    await sendContactEmail({
      name: name.trim(),
      email: email.trim(),
      topic: topic?.trim() || '',
      message: message.trim(),
    });

    console.log(`[Contact] Message received from ${email} — topic: ${topic || 'none'}`);
    return res.json({ success: true, message: 'Message sent successfully.' });
  } catch (err) {
    console.error('[Contact] Failed to send email:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send message. Please try again.' });
  }
});

export default router;
