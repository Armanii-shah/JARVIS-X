const DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.zip', '.js', '.sh', '.pdf'];

export function detectAttachments(parts = []) {
  const attachments = [];

  const scan = (parts) => {
    for (const part of parts) {
      if (part.filename && part.filename.length > 0) {
        const ext = part.filename.slice(part.filename.lastIndexOf('.')).toLowerCase();
        attachments.push({
          filename: part.filename,
          mimeType: part.mimeType,
          isDangerous: DANGEROUS_EXTENSIONS.includes(ext),
        });
      }
      if (part.parts) scan(part.parts);
    }
  };

  scan(parts);
  return attachments;
}
