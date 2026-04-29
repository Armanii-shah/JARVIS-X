export async function sendWhatsAppAlert(phone, score, reason, subject, threatLevel) {
  // ── Token / config checks ────────────────────────────────────────────────
  const token = process.env.WHATSAPP_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

  if (!token) {
    console.error('[WhatsApp] WHATSAPP_TOKEN is missing or empty!');
    throw new Error('WHATSAPP_TOKEN not configured');
  }
  if (!phoneNumberId) {
    console.error('[WhatsApp] WHATSAPP_PHONE_NUMBER_ID is missing or empty!');
    throw new Error('WHATSAPP_PHONE_NUMBER_ID not configured');
  }

  console.log(`[WhatsApp] Token (first 20 chars): ${token.slice(0, 20)}...`);
  console.log(`[WhatsApp] Phone Number ID: ${phoneNumberId}`);

  // Normalize: strip +, spaces, dashes — WhatsApp expects digits only (e.g. 923001234567)
  const cleanPhone = String(phone).replace(/^\+/, '').replace(/[\s\-().]/g, '');
  console.log(`[WhatsApp] Sending to: ${cleanPhone} (raw input: ${phone})`);

  if (!cleanPhone || !/^\d{10,15}$/.test(cleanPhone)) {
    console.error(`[WhatsApp] Phone number failed validation: "${cleanPhone}"`);
    throw new Error(`Invalid phone number format: ${phone}`);
  }

  const url = `https://graph.facebook.com/v21.0/${phoneNumberId}/messages`;
  console.log(`[WhatsApp] API URL: ${url}`);

  // Truncate reason to keep message within WhatsApp's 4096 char limit
  const truncatedReason = reason?.length > 200 ? reason.slice(0, 197) + '...' : (reason ?? 'N/A');

  const lvl = threatLevel?.toUpperCase() ?? 'HIGH';
  const messageBody =
    lvl === 'MEDIUM'
      ? `⚠️ JARVIS-X WARNING\n\nSuspicious Email Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nLevel: MEDIUM\nReason: ${truncatedReason}\n\nMonitor this email carefully.`
      : lvl === 'CRITICAL'
      ? `🆘 JARVIS-X CRITICAL ALERT\n\nCritical Threat Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nLevel: CRITICAL\nReason: ${truncatedReason}\n\nIMMEDIATE ACTION REQUIRED!`
      : `🚨 JARVIS-X SECURITY ALERT\n\nThreat Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nLevel: HIGH\nReason: ${truncatedReason}\n\nTake immediate action!`;

  const requestBody = {
    messaging_product: 'whatsapp',
    to: cleanPhone,
    type: 'text',
    text: { body: messageBody },
  };
  console.log('[WhatsApp] Request body:', JSON.stringify(requestBody));

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
    signal: AbortSignal.timeout(15000),
  });

  console.log(`[WhatsApp] HTTP status: ${res.status} ${res.statusText}`);
  const responseData = await res.json().catch(() => ({}));
  console.log('[WhatsApp] Full API response:', JSON.stringify(responseData, null, 2));

  if (!res.ok || responseData.error) {
    const errCode = responseData.error?.code;
    const errDetail = responseData.error
      ? `code=${errCode} type=${responseData.error.type} msg="${responseData.error.message}"`
      : `HTTP ${res.status}`;
    console.error(`[WhatsApp] API call FAILED: ${errDetail}`);

    if (errCode === 131030) {
      console.error(`[WhatsApp] ──────────────────────────────────────────────────────`);
      console.error(`[WhatsApp] ERROR 131030: Recipient number not verified as test recipient`);
      console.error(`[WhatsApp] The number ${cleanPhone} must be added to your test recipients.`);
      console.error(`[WhatsApp] Fix: developers.facebook.com → Your App → WhatsApp → API Setup`);
      console.error(`[WhatsApp]      Under "To" → click the dropdown → "Manage phone number list"`);
      console.error(`[WhatsApp]      Add: ${cleanPhone} and verify via WhatsApp OTP`);
      console.error(`[WhatsApp] ──────────────────────────────────────────────────────`);
    }

    throw new Error(`WhatsApp API error: ${errDetail}`);
  }

  console.log(`[WhatsApp] Message sent successfully — message_id: ${responseData.messages?.[0]?.id}`);
  return { success: true, messageId: responseData.messages?.[0]?.id };
}
