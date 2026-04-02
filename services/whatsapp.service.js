export async function sendWhatsAppAlert(phone, score, reason, subject) {
  const url = `https://graph.facebook.com/v18.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`;

  console.log('WhatsApp API URL:', url);
  console.log('WhatsApp Token exists:', !!process.env.WHATSAPP_TOKEN);
  console.log('Phone Number ID:', process.env.WHATSAPP_PHONE_NUMBER_ID);
  console.log('Sending to phone:', phone);

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.WHATSAPP_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to: phone,
      type: 'text',
      text: {
        body: `⚠️ JARVIS-X SECURITY ALERT\n\nThreat Detected!\nEmail: ${subject}\nRisk Score: ${score}/100\nReason: ${reason}\n\nTake immediate action!`,
      },
    }),
  });

  const responseData = await res.json();
  console.log('WhatsApp API Response:', JSON.stringify(responseData));

  if (res.ok) return { success: true };

  throw new Error(JSON.stringify(responseData));
}
