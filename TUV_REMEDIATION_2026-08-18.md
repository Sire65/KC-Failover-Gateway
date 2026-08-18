# KC Failover Gateway – TÜV Remediation 2026-08-18

## Schutzregel

Diese Audit-Spur verändert keine produktive Infrastruktur. Änderungen bleiben auf `audit/tuv-hardening-2026-08-18`; kein Merge und kein Deployment erfolgen automatisch.

## Kritische Freigabepunkte

1. Die produktiven `/sync/*`-, Restore- und Reconcile-Routen besitzen im aktuellen Worker keine statisch erkennbare Geräte-/Request-Authentifizierung.
2. Der Worker setzt `Access-Control-Allow-Origin: *`; laut eigener `SECURITY_ARCHITECTURE.md` muss Produktion eine Origin-Allowlist verwenden.
3. Geräte-zu-Kassen-Bindung und Request-Replay-Schutz (Zeitstempel/Nonce) sind im aktuellen Gateway-Code noch nicht nachgewiesen.
4. Rate-/Flood-Control ist im aktuellen Gateway-Code noch nicht nachgewiesen.

## Weitere Architektur-/Skalierungsbefunde

- Restore liefert maximal 5000 Transaktionen, besitzt aber keinen Cursor-/Paging-Vertrag. Eine vollständige Wiederherstellung größerer Kassenjournale ist damit nicht nachgewiesen.
- Reconcile akzeptiert höchstens 5000 lokale IDs, liest serverseitig aber die vollständige Remote-ID-Menge der Kasse. Client und Gateway benötigen einen gemeinsamen Chunking-/Paging-Vertrag.
- Interne Exception-Texte werden teilweise direkt als API-Fehlertext zurückgegeben. Für Produktion sollten stabile externe Fehlercodes und interne Diagnoseinformationen getrennt werden.
- Clientseitig wurde zusätzlich festgestellt, dass Remote-Restore-Datensätze derzeit vor dem lokalen Merge nicht gegen Record-Hash/Prüfkette validiert werden. Dieser Punkt muss gemeinsam mit dem POS-Client gelöst werden.

## Bereits eingeführte Abhilfe auf der Audit-Spur

- `tests/tuv-security-release-gate.mjs` prüft Authentifizierung, Wildcard-CORS sowie nun auch Restore-Paging, Reconcile-Vertragsgrenzen und direkte Fehleroffenlegung.
- `npm run audit:tuv` führt den Gate-Test aus.
- Der Deployment-Workflow führt den TÜV-Gate-Test vor Wrangler-Validierung und vor Deployment aus.
- Die Super-GAU-Matrix-Prüfung wurde von veraltet `3` auf den dokumentierten aktuellen Stand `6` Szenarien korrigiert.
- Der separate Dual-Provider-Regressionsworkflow läuft auf der Audit-Spur nun auch bei Pull Requests gegen `main`, damit Syntax/Adapter-Verträge geprüft werden können, ohne produktiv zu deployen.

Damit kann ein unsicherer Gateway-Stand künftig nicht versehentlich als Security-Green durch die Deployment-Pipeline laufen, sobald diese Änderung nach Prüfung übernommen wird.

## Noch nicht automatisch behoben

Die Geräteauthentifizierung selbst wird bewusst nicht blind in Produktion eingebaut. Sie benötigt ein abgestimmtes Client-/Gateway-Protokoll mit revokierbarer Geräteidentität, Request-Signatur, Zeitstempel, Nonce/Request-ID, Registerbindung und sicherer Provisionierung. Eine halb implementierte Lösung würde die Kassen entweder aussperren oder nur Scheinsicherheit erzeugen.

Auch Paging/Chunking und Restore-Integritätsprüfung werden zunächst als gemeinsamer Client-/Gateway-Vertrag entworfen und getestet. Einseitige Änderungen am Server könnten vorhandene Kassen vom Restore oder Reconcile ausschließen.

## Weitere Live-Prüffunde (nur gelesen)

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
- Keine Secret-/Token-Rotation.
