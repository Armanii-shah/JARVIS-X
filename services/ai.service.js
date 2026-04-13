const RETRY_DELAYS = [2000, 4000];

export async function analyzeEmail(emailData) {
  const { subject, sender, body, links, attachments } = emailData;

  const baseUrl = process.env.PYTHON_SERVICE_URL;
  if (!baseUrl) throw new Error('PYTHON_SERVICE_URL is not configured');

  const url = `${baseUrl}/analyze`;
  console.log(`[AI] Calling Python at: ${url}`);

  let lastError;

  for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': process.env.PYTHON_API_KEY,
        },
        body: JSON.stringify({ subject, sender, body, links, attachments }),
        signal: AbortSignal.timeout(20000), // 20s timeout per attempt
      });

      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
      }

      const data = await res.json();

      // Clamp score server-side as a safety net
      const score = Math.max(0, Math.min(100, Number(data.score) || 50));
      const threatLevel = score <= 40 ? 'LOW' : score <= 60 ? 'MEDIUM' : 'HIGH';

      console.log(`[AI] Response: score=${score} level=${threatLevel}`);
      return { score, threatLevel, reason: data.reason ?? 'No reason provided' };
    } catch (error) {
      lastError = error;
      console.error(`[AI] Attempt ${attempt + 1} failed: ${error.message}`);
      if (attempt < RETRY_DELAYS.length) {
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS[attempt]));
      }
    }
  }

  throw new Error(`AI service unavailable after ${RETRY_DELAYS.length + 1} attempts: ${lastError?.message}`);
}
