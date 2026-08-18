import fs from 'node:fs';

const worker = fs.readFileSync(new URL('../src/worker.js', import.meta.url), 'utf8');
const security = fs.readFileSync(new URL('../SECURITY_ARCHITECTURE.md', import.meta.url), 'utf8');

const blockers = [];
const warnings = [];

const hasSyncRoutes = /\/sync\/(?:transaction|batch|transactions|reconcile)/.test(worker);
const hasWildcardCors = /access-control-allow-origin["']?\s*:\s*["']\*["']/i.test(worker);
const hasRequestAuth = /authorization|x-kc-signature|x-kc-device|nonce|request-id/i.test(worker);
const hasRegisterBinding = /permitted register|register binding|device.*register/i.test(worker);
const hasRateLimit = /rate.?limit|429/.test(worker);

if (hasSyncRoutes && !hasRequestAuth) {
  blockers.push('Sync/Restore/Reconcile-Routen besitzen keine erkennbare Request-/Geräteauthentifizierung.');
}
if (hasWildcardCors) {
  blockers.push('Produktiv-Gateway verwendet CORS access-control-allow-origin: *.');
}
if (!hasRegisterBinding) {
  warnings.push('Keine statisch erkennbare Geräte-zu-Kassen-Bindung im Gateway-Code.');
}
if (!hasRateLimit) {
  warnings.push('Kein statisch erkennbares Rate-Limit/Flood-Control im Gateway-Code.');
}
if (!/Production is not security-green while an unauthenticated caller can write, reconcile, or restore/i.test(security)) {
  warnings.push('Security Baseline enthält keinen eindeutigen Fail-Closed Release-Satz.');
}

console.log('KC Failover Gateway – TÜV Security Release Gate');
for (const warning of warnings) console.warn('WARN:', warning);
for (const blocker of blockers) console.error('BLOCKER:', blocker);

if (blockers.length) {
  console.error(`Release gesperrt: ${blockers.length} kritische(r) Sicherheitsblocker.`);
  process.exit(1);
}

console.log('PASS: Keine durch diesen Gate-Test erkannten Gateway-Release-Blocker.');
