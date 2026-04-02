const URL_REGEX = /https?:\/\/[^\s"'<>)]+/g;

export function extractLinks(text) {
  const matches = text.match(URL_REGEX) || [];
  return [...new Set(matches)];
}
