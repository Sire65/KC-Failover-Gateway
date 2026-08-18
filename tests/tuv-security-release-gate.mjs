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
const restoreHasFixedLimit = /restoreTransactions[\s\S]*?LIMIT\s+5000/i.test(worker);
const restoreHasCursor = /restoreTransactions[\s\S]*?(cursor|page|offset|after_id|next_cursor)/i.test(worker);
const reconcileCapsInput = /ids\.length\s*>\s*5000/.test(worker);
const reconcileReadsAllRemote = /SELECT\s+transaction_id\s+FROM\s+public\.kc_failover_transactions\s+WHERE\s+register_id=\$1/i.test(worker);
const responseLeaksInternalErrors = /json\(\{status:"ERROR",error:message\}/.test(worker);

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
