export function makeDecision(score) {
  if (score <= 40) return { level: 'LOW', shouldAlert: false, message: 'Email appears safe' };
  if (score <= 60) return { level: 'MEDIUM', shouldAlert: false, message: 'Email is suspicious' };
  return { level: 'HIGH', shouldAlert: true, message: 'Threat detected - alert triggered' };
}
