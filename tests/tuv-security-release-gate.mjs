import fs from 'node:fs';

const worker = fs.readFileSync(new URL('../src/worker.js', import.meta.url), 'utf8');
const security = fs.readFileSync(new URL('../SECURITY_ARCHITECTURE.md', import.meta.url), 'utf8');

const blockers = [];
const warnings = [];

const hasSyncRoutes = /\/sync\/(?:transaction|batch|transactions|ids|reconcile)/.test(worker);
const hasWildcardCors = /access-control-allow-origin["']?\s*:\s*["']\*["']/i.test(worker);
const hasHmacAuth = /HMAC/.test(worker)&&/x-kc-signature/.test(worker)&&/crypto\.subtle\.verify/.test(worker);
const hasDeviceIdentity = /x-kc-device/.test(worker)&&/KC_DEVICE_KEYS_JSON/.test(worker);
const hasTimestamp = /x-kc-timestamp/.test(worker)&&/AUTH_WINDOW_MS/.test(worker);
const hasReplayGuard = /x-kc-nonce/.test(worker)&&/REPLAY_DETECTED/.test(worker)&&/nonceFresh/.test(worker);
const hasRegisterBinding = /registerIds/.test(worker)&&/REGISTER_NOT_ALLOWED/.test(worker)&&/assertRegisterAllowed/.test(worker);
const hasRateLimit = /RATE_LIMIT/.test(worker)&&/RATE_LIMITED/.test(worker)&&/429/.test(worker);
const hasOriginAllowlist = /KC_ALLOWED_ORIGINS/.test(worker)&&/originAllowed/.test(worker)&&!hasWildcardCors;
const protectsDiagnostics = /diagnosticsPath/.test(worker)&&/DIAGNOSTICS_NOT_ALLOWED/.test(worker);
const restoreHasPaging = /function restorePage/.test(worker)&&/after_id/.test(worker)&&/nextCursor/.test(worker)&&/boundedPageLimit/.test(worker)&&/ORDER BY transaction_id ASC/.test(worker);
const reconcileHasChunkContract = /MAX_RECONCILE_IDS\s*=\s*1000/.test(worker)&&/ANY\(\$2::text\[\]\)/.test(worker)&&/\/sync\/ids/.test(worker)&&/mode:"membership"/.test(worker);
const responseLeaksInternalErrors = /json\([^\n]*error:message/.test(worker);

if (hasSyncRoutes && !(hasHmacAuth&&hasDeviceIdentity&&hasTimestamp&&hasReplayGuard)) {
  blockers.push('Sync/Restore/Reconcile-Routen besitzen keine vollständige HMAC-Geräteauthentifizierung mit Zeitfenster und Replay-Schutz.');
}
if (!hasRegisterBinding) {
  blockers.push('Authentifizierte Geräte sind nicht eindeutig auf freigegebene Kassen-IDs gebunden.');
}
if (!hasOriginAllowlist) {
  blockers.push('Browserzugriffe besitzen keine fail-closed Origin-Allowlist.');
}
if (!protectsDiagnostics) {
  warnings.push('Super-GAU-/Diagnoserouten besitzen keine gesonderte Berechtigung.');
}
if (!hasRateLimit) {
  warnings.push('Kein statisch erkennbares Rate-Limit/Flood-Control im Gateway-Code.');
}
if (!restoreHasPaging) {
  warnings.push('Restore besitzt keinen eindeutig nachweisbaren Cursor-/Pagination-Vertrag mit begrenzter Seitengröße.');
}
if (!reconcileHasChunkContract) {
  warnings.push('Reconcile besitzt keinen nachgewiesenen Chunk-/Membership-Vertrag plus paginierte Remote-ID-Liste.');
}
if (responseLeaksInternalErrors) {
  warnings.push('Gateway gibt interne Fehlermeldungstexte teilweise direkt als API-Fehler zurück. Produktionsantworten sollten externe Fehlercodes von internen Details trennen.');
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
