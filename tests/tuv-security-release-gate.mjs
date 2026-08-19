import fs from 'node:fs';

const worker = fs.readFileSync(new URL('../src/worker.js', import.meta.url), 'utf8');
const security = fs.readFileSync(new URL('../SECURITY_ARCHITECTURE.md', import.meta.url), 'utf8');

const blockers = [];
const warnings = [];

const hasSyncRoutes = /\/sync\/(?:transaction|batch|transactions|reconcile)/.test(worker);
const hasWildcardCors = /access-control-allow-origin["']?\s*:\s*["']\*["']/i.test(worker);
const hasHmacAuth = /HMAC/.test(worker)&&/x-kc-signature/.test(worker)&&/crypto\.subtle\.verify/.test(worker);
const hasDeviceIdentity = /x-kc-device/.test(worker)&&/KC_DEVICE_KEYS_JSON/.test(worker);
const hasTimestamp = /x-kc-timestamp/.test(worker)&&/AUTH_WINDOW_MS/.test(worker);
const hasReplayGuard = /x-kc-nonce/.test(worker)&&/REPLAY_DETECTED/.test(worker)&&/nonceFresh/.test(worker);
const hasRegisterBinding = /registerIds/.test(worker)&&/REGISTER_NOT_ALLOWED/.test(worker)&&/assertRegisterAllowed/.test(worker);
const hasRateLimit = /RATE_LIMIT/.test(worker)&&/RATE_LIMITED/.test(worker)&&/429/.test(worker);
const hasOriginAllowlist = /KC_ALLOWED_ORIGINS/.test(worker)&&/originAllowed/.test(worker)&&!hasWildcardCors;
const protectsDiagnostics = /diagnosticsPath/.test(worker)&&/DIAGNOSTICS_NOT_ALLOWED/.test(worker);
const restoreHasFixedLimit = /restoreTransactions[\s\S]*?LIMIT\s+5000/i.test(worker);
const restoreHasCursor = /restoreTransactions[\s\S]*?(cursor|page|offset|after_id|next_cursor)/i.test(worker);
const reconcileCapsInput = /ids\.length\s*>\s*5000/.test(worker);
const reconcileReadsAllRemote = /SELECT\s+transaction_id\s+FROM\s+public\.kc_failover_transactions\s+WHERE\s+register_id=\$1/i.test(worker);
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
if (restoreHasFixedLimit && !restoreHasCursor) {
  warnings.push('Restore ist auf 5000 Datensätze begrenzt, besitzt aber keinen Cursor/Pagination-Vertrag. Vollständige Wiederherstellung großer Journale ist nicht nachgewiesen.');
}
if (reconcileCapsInput && reconcileReadsAllRemote) {
  warnings.push('Reconcile begrenzt die Client-ID-Liste auf 5000, liest serverseitig aber alle IDs der Kasse. Client und Gateway benötigen einen gemeinsamen Paging/Chunking-Vertrag.');
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
