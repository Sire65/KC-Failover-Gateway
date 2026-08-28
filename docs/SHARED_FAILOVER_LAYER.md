# Gemeinsame KC Failover-Schicht

Die Datei `sdk/kc-failover-client.js` ist die gemeinsame Client-Schicht für KC-Fachprogramme.

## Ziel

Alle Fachprogramme verwenden denselben Ablauf:

1. normaler Online-Pfad über den KC Failover Gateway,
2. automatischer Wechsel zwischen Gateway Provider A (Cloudflare) und Provider B (Netlify),
3. bei Ausfall beider Gateways lokale IndexedDB-Outbox,
4. automatisches Replay nach Wiederkehr,
5. Idempotenz und Konflikterkennung über den bereits abgenommenen Neon-Journalpfad,
6. Restore und Reconcile über denselben Adapter.

Die Schicht enthält **keine Datenbank-Zugangsdaten**. Programme erhalten keinen direkten Neon-Connection-String. Neon bleibt serverseitig hinter dem Gateway.

## Einbindung

```js
import { createKCFailoverClient } from './kc-failover-client.js';

const failover = createKCFailoverClient({
  programId: 'kc-dp2',
  instanceId: 'browser'
});

failover.onStatus(status => console.log(status));
await failover.startAutoReplay();
```

### Schreiben

```js
await failover.write({
  entityType: 'shift',
  entityId: shift.id,
  operation: 'UPSERT',
  payload: shift
});
```

Mögliche Ergebnisse: `SYNCED`, `QUEUED`, `CONFLICT`.

### Wiederanlauf

```js
const result = await failover.replay();
```

### Restore

```js
const records = await failover.restore();
```

### Reconcile

```js
const result = await failover.reconcile(localOperationIds);
```

## Integrationsregel

Die Fachlogik bleibt im jeweiligen Programm. Direkte Supabase-Zugriffe werden schrittweise hinter eine kleine Datenzugriffsschicht gelegt. Kritische Schreibvorgänge werden zusätzlich durch `KCFailoverClient` journalisiert. Dadurch kann jedes Programm offline weiterarbeiten und seine ausstehenden Änderungen nach Wiederkehr einer Backend-Verbindung wiederholen.

Nicht jedes Supabase-Feature lässt sich blind auf Neon umleiten. Auth, Storage, Realtime und Edge Functions bleiben eigene Dienste. Die Failover-Schicht ist für **Fachdaten-Schreib-/Sync-/Restore-Pfade** vorgesehen. Für jedes Programm wird deshalb eine kurze Zuordnung definiert, welche Entitäten und Operationen failoverfähig sind.

## Datenschutz

Die bestehende Privacy-Architektur bleibt unverändert. Native rohe Logical Replication wird nicht aktiviert. Die gemeinsame Client-Schicht verwendet ausschließlich den bereits kontrollierten Gateway-/Journalweg.
