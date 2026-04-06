const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.com', '.vbs', '.vbe',
  '.ps1', '.ps2', '.psm1', '.psd1',
  '.jar', '.msi', '.msp', '.msix',
  '.sh', '.bash', '.zsh',
  '.scr', '.pif', '.reg',
  '.js', '.jse', '.wsf', '.wsh',
  '.hta', '.cpl', '.inf',
]);

export function detectAttachments(parts = []) {
  const attachments = [];

  const scan = (parts) => {
    for (const part of parts) {
      if (part.filename && part.filename.length > 0) {
        const dotIdx = part.filename.lastIndexOf('.');
        const ext = dotIdx !== -1
          ? part.filename.slice(dotIdx).toLowerCase()
          : '';
        attachments.push({
          filename: part.filename,
          mimeType: part.mimeType,
          isDangerous: DANGEROUS_EXTENSIONS.has(ext),
        });
      }
      if (part.parts) scan(part.parts);
    }
  };

  scan(parts);
  return attachments;
}
