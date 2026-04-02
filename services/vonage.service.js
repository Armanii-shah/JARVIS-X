export async function sendSMS(phone, message) {
  const res = await fetch('https://rest.nexmo.com/sms/json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      api_key: process.env.VONAGE_API_KEY,
      api_secret: process.env.VONAGE_API_SECRET,
      to: phone,
      from: 'JARVIS-X',
      text: message,
    }),
  });

  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.messages?.[0]?.['error-text'] || `Vonage API error: HTTP ${res.status}`);
  }

  return { success: true };
}
