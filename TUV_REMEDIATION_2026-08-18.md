# KC Failover Gateway – TÜV Remediation 2026-08-18

## Schutzregel

Diese Audit-Spur verändert keine produktive Infrastruktur. Änderungen bleiben auf `audit/tuv-hardening-2026-08-18`; kein Merge und kein Deployment erfolgen automatisch.

## Audit-Stand

Die zuvor kritischen Gateway-Punkte sind auf der isolierten Audit-Spur technisch umgesetzt und automatisiert geprüft:

- HMAC-SHA-256-Geräteauthentifizierung für `/sync/*`, Restore und Reconcile.
- Geräte-ID, Zeitstempel und Nonce mit Replay-Schutz.
- Geräte-zu-Kassen-Bindung; ein Gerät darf nur freigegebene `registerIds` verwenden.
- Origin-Allowlist statt Wildcard-CORS für Browserzugriffe.
- Per-Gerät Rate-Limit/Flood-Control.
- Gesonderte Berechtigung für Super-GAU-/Diagnoserouten.
- Externe API-Fehler sind von internen Exception-Details getrennt.
- Restore besitzt Cursor-Paging mit begrenzter Seitengröße.
- Reconcile arbeitet als begrenzter Membership-Check und liest Remote-IDs separat paginiert; große lokale ID-Mengen können clientseitig gechunkt werden.

Der aktuelle Audit-Workflow besteht Syntax-/Modulprüfungen, Cloudflare-/Netlify-Adaptervertrag, HMAC-Authentifizierungsregression, Paging-Vertrag und das TÜV-Security-Gate vollständig grün.

## Paging-/Reconcile-Vertrag

- Restore: `/sync/transactions?register_id=...&limit=...&after_id=...`
- Remote-ID-Liste: `/sync/ids?register_id=...&limit=...&after_id=...`
- Standardseitengröße: 500 Datensätze.
- Maximale Seitengröße: 1000 Datensätze.
- Reconcile akzeptiert maximal 1000 IDs je Membership-Anfrage.
- Der Server vergleicht nur die übergebenen IDs (`ANY($2::text[])`) und muss dafür nicht mehr die komplette Remote-ID-Menge einer Kasse in einem einzelnen Reconcile-Aufruf laden.

Damit sind die frühere feste Restore-Grenze von 5000 Datensätzen und der unskalierte Vollvergleich als Audit-Befunde beseitigt.

## Gemeinsamer POS-/Gateway-Vertrag

Der POS-Audit-Zweig besitzt passend dazu:

- HMAC-SHA-256-Signatur für jede `/sync/*`-Anfrage,
- im verschlüsselten Local Vault geschütztes Gerätegeheimnis,
- 1000er Reconcile-Chunks,
- paginierte Remote-ID- und Restore-Abfragen,
- mindestens 60 Sekunden Abstand zwischen automatisch ausgelösten Voll-Reconciles,
- `KC_TX_DIGEST_V1` für neue Failover-Uploads und Digest-Verifikation vor einem Restore-Merge.

Bereits vorhandene Remote-Alttransaktionen ohne neuen Inhaltsdigest bleiben ein Migrationspunkt: Sie dürfen nicht stillschweigend als verifiziert behandelt werden.

## Vor einem späteren produktiven Rollout zwingend erforderlich

Technisches Grün des Audit-Zweigs ist **keine produktive Freigabe**. Vor einem Deployment müssen mindestens folgende Betriebsdaten kontrolliert provisioniert werden:

1. `KC_DEVICE_KEYS_JSON` mit individuellen, ausreichend langen Gerätegeheimnissen und expliziten Kassenbindungen.
2. `KC_ALLOWED_ORIGINS` mit den tatsächlich freigegebenen POS-Ursprüngen.
3. Das korrespondierende Gerätegeheimnis pro Kasse im verschlüsselten Local Vault des POS.
4. Kontrollierte Legacy-Regel für bereits vorhandene Remote-Transaktionen ohne `KC_TX_DIGEST_V1`.
5. Stufenweiser Integrationstest Cloudflare A, Netlify B, Supabase, Neon und Offline-Queue vor jedem Merge/Deployment.

Gerätegeheimnisse dürfen nicht als Quellcode, GitHub-Datei oder Klartext-Konfiguration eingecheckt werden.

## Weitere Live-Prüffunde aus der Read-only-Prüfung

- Supabase `kc-db-mirror-worker` und `kc-db-backup-worker` laufen zwar mit `verify_jwt=false`, prüfen aber jeweils ein separates serverseitiges Mirror-Token vor privilegierten Aktionen.
- `kc-dp-push-test` prüft ein gehashtes System-/Cron-Geheimnis.
- `kc-dp-pilot` verwendet einen langen gehashten Invite-Token als Bearer-Zugang.
- `kc-dp-push-receipt` akzeptiert Receipt-Status ohne JWT; Integrität der Zustellstatus sollte durch einen nicht erratbaren Receipt-Token oder authentifizierte Benutzerbindung gehärtet werden.
- `kc-dp-pilot-admin-resend-once` ist eine einmalige Admin-Hilfsfunktion mit `verify_jwt=false`; nach Verwendung sollte sie vollständig deaktiviert/entfernt werden, statt dauerhaft aktiv zu bleiben.

## Nicht durchgeführt

- Keine Änderung an `main`.
- Kein Cloudflare-/Netlify-Deployment.
- Keine Änderung an Supabase-Funktionen oder RLS.
- Keine Neon-Migration.
- Keine Secret-/Token-Rotation oder Provisionierung.
