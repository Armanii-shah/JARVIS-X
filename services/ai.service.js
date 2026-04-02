const RETRY_DELAYS = [2000, 4000];

export async function analyzeEmail(emailData) {
  const { subject, sender, body, links, attachments } = emailData;
  let lastError;

  for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt++) {
    try {
      const res = await fetch(process.env.PYTHON_SERVICE_URL + '/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, sender, body, links, attachments }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json();
      return { score: data.score, threatLevel: data.threatLevel, reason: data.reason };
    } catch (error) {
      lastError = error;
      if (attempt < RETRY_DELAYS.length) {
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS[attempt]));
      }
    }
  }

  throw new Error('AI service unavailable');
}
