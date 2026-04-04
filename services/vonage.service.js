export async function sendSMS(phone, message, threatLevel) {
  const text = threatLevel === 'MEDIUM'
    ? `JARVIS-X WARNING: Suspicious email detected!\nSubject: ${message}\nMonitor carefully.`
    : `JARVIS-X ALERT: Threat detected!\nSubject: ${message}\nTake immediate action!`;

  console.log('Sending SMS to:', phone);
  console.log('Vonage API Key exists:', !!process.env.VONAGE_API_KEY);

  const res = await fetch('https://rest.nexmo.com/sms/json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      api_key: process.env.VONAGE_API_KEY,
      api_secret: process.env.VONAGE_API_SECRET,
      to: phone,
      from: 'JARVIS-X',
      text,
    }),
  });

  const responseData = await res.json();
  console.log('Vonage Response:', JSON.stringify(responseData));

  if (!res.ok) {
    throw new Error(responseData.messages?.[0]?.['error-text'] || `Vonage API error: HTTP ${res.status}`);
  }

  if (responseData.messages[0].status !== '0') {
    throw new Error(responseData.messages[0]['error-text']);
  }

  return { success: true };
}
