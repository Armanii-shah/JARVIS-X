export async function sendWhatsAppAlert(phone, score, reason, subject, threatLevel) {
  // Normalize: strip +, spaces, dashes — WhatsApp expects digits only (e.g. 923001234567)
  const cleanPhone = String(phone).replace(/^\+/, '').replace(/[\s\-().]/g, '');
  if (!cleanPhone || !/^\d{10,15}$/.test(cleanPhone)) {
    throw new Error(`Invalid phone number format: ${phone}`);
  }

  const url = `https://graph.facebook.com/v21.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;

  console.log('WhatsApp API URL:', url);
  console.log('WhatsApp Token exists:', !!process.env.WHATSAPP_TOKEN);
  console.log('Phone Number ID:', process.env.WHATSAPP_PHONE_NUMBER_ID);
  console.log('Sending to cleanPhone:', cleanPhone);

  // Truncate reason to keep message within WhatsApp's 4096 char limit
  const truncatedReason = reason?.length > 200 ? reason.slice(0, 197) + '...' : (reason ?? 'N/A');

  const messageBody = threatLevel === 'MEDIUM'
    ? `⚠️ JARVIS-X WARNING\n\nSuspicious Email Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nLevel: MEDIUM\nReason: ${truncatedReason}\n\nMonitor this email carefully.`
    : `🚨 JARVIS-X SECURITY ALERT\n\nThreat Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nLevel: HIGH\nReason: ${truncatedReason}\n\nTake immediate action!`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.WHATSAPP_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to: cleanPhone,
      type: 'text',
      text: { body: messageBody },
    }),
    signal: AbortSignal.timeout(15000),
  });

  const responseData = await res.json().catch(() => ({}));
  console.log('WhatsApp API Response:', JSON.stringify(responseData));

  if (!res.ok || responseData.error) {
    const errMsg = responseData.error?.message ?? responseData.error ?? `HTTP ${res.status}`;
    throw new Error(`WhatsApp API error: ${errMsg}`);
  }

  return { success: true };
}
