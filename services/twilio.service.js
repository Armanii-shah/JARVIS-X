import twilio from 'twilio';

export async function makeSecurityCall(phoneNumber, subject, score) {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken  = process.env.TWILIO_AUTH_TOKEN;
  const fromNumber = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !fromNumber) {
    throw new Error('Twilio not configured — TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN or TWILIO_PHONE_NUMBER missing');
  }

  // Normalize: ensure leading +
  const toNumber = phoneNumber.startsWith('+') ? phoneNumber : `+${phoneNumber}`;

  // Sanitize subject for TwiML — strip characters that could break the XML or sound odd
  const safeSubject = (subject ?? 'Unknown Subject')
    .replace(/[<>&"']/g, '')
    .slice(0, 100);

  const safeScore = Math.max(0, Math.min(100, Number(score) || 0));

  const twiml =
    `<Response>` +
    `<Say voice="alice" language="en-US">` +
    `JARVIS-X Security Alert! ` +
    `A high risk email was detected. ` +
    `Subject: ${safeSubject}. ` +
    `Risk Score: ${safeScore} out of 100. ` +
    `Please check your dashboard immediately.` +
    `</Say>` +
    `<Pause length="1"/>` +
    `<Say voice="alice" language="en-US">` +
    `Repeating. Subject: ${safeSubject}. Risk Score: ${safeScore} out of 100.` +
    `</Say>` +
    `</Response>`;

  const client = twilio(accountSid, authToken);

  console.log(`[Twilio] Calling ${toNumber} from ${fromNumber}`);

  const call = await client.calls.create({
    twiml,
    to: toNumber,
    from: fromNumber,
  });

  console.log(`[Twilio] ✓ Call initiated — SID: ${call.sid} | status: ${call.status}`);
  return { success: true, callSid: call.sid, status: call.status };
}
