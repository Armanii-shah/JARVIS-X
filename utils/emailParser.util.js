const URL_REGEX = /https?:\/\/[^\s"'<>)]+/g;

function decodeBase64Url(data) {
  return Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function extractBody(payload) {
  if (payload.parts) {
    const plainPart = payload.parts.find((p) => p.mimeType === 'text/plain');
    if (plainPart?.body?.data) return decodeBase64Url(plainPart.body.data);

    const htmlPart = payload.parts.find((p) => p.mimeType === 'text/html');
    if (htmlPart?.body?.data) return decodeBase64Url(htmlPart.body.data);

    for (const part of payload.parts) {
      const nested = extractBody(part);
      if (nested) return nested;
    }
  }

  if (payload.body?.data) return decodeBase64Url(payload.body.data);

  return '';
}

function extractAttachments(payload) {
  const attachments = [];

  const scan = (parts = []) => {
    for (const part of parts) {
      if (part.filename && part.filename.length > 0) {
        attachments.push({ name: part.filename, mimeType: part.mimeType });
      }
      if (part.parts) scan(part.parts);
    }
  };

  scan(payload.parts || []);
  return attachments;
}

export function parseEmail(rawMessage) {
  const headers = rawMessage.payload?.headers || [];
  const subject = headers.find((h) => h.name === 'Subject')?.value || '';
  const sender = headers.find((h) => h.name === 'From')?.value || '';

  const body = extractBody(rawMessage.payload || {});
  const links = body.match(URL_REGEX) || [];
  const attachments = extractAttachments(rawMessage.payload || {});

  return { subject, sender, body, links, attachments };
}
