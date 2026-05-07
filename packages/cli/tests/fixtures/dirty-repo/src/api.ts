// Logs PII — flagged as GDPR Art.5(1)(f) violation by canned semgrep output.
export function logUser(user: { email: string }) {
  console.log('user:', user.email);
}
