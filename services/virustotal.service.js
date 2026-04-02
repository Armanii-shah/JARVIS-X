const VT_BASE = 'https://www.virustotal.com/api/v3';

async function scanLink(url) {
  const submitRes = await fetch(`${VT_BASE}/urls`, {
    method: 'POST',
    headers: {
      'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: `url=${encodeURIComponent(url)}`,
  });

  if (!submitRes.ok) throw new Error(`VT submit failed for ${url}: HTTP ${submitRes.status}`);

  const submitData = await submitRes.json();
  const analysisId = submitData.data.id;

  await new Promise((resolve) => setTimeout(resolve, 2000));

  const resultRes = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
  });

  if (!resultRes.ok) throw new Error(`VT result failed for ${url}: HTTP ${resultRes.status}`);

  const resultData = await resultRes.json();
  const stats = resultData.data.attributes.stats;

  return {
    url,
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    result: resultData.data.attributes.status,
  };
}

export async function scanLinks(links) {
  if (!links || links.length === 0) return [];
  return Promise.all(links.map(scanLink));
}
