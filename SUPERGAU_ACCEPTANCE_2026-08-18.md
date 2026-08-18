# KC Failover Gateway – Super-GAU Abnahme

Datum: 18.08.2026
Status: BESTANDEN

## Server-Matrix

Die kombinierte SERVER-SUPER-GAU-MATRIX wurde mit 6/6 Szenarien als PASS ausgeführt.

1. Supabase-Ausfall -> Neon übernimmt -> Supabase Recovery: PASS
2. Neon-Ausfall bei gesundem Supabase: PASS
3. Supabase und Neon ausgefallen -> LOCAL_QUEUE: PASS
4. LOCAL_QUEUE -> Backend-Wiederherstellung -> Replay-Bereitschaft: PASS
5. Replay-Idempotenz -> keine doppelte Transaktion: PASS
6. Konfliktierende Wiederholung -> CONFLICT, Original geschützt: PASS

## Browser-E2E

Der produktive Browser-E2E-Test wurde unter /e2e ausgeführt und mit PASS abgeschlossen.

Geprüfter Ablauf:
- Test-Queue vor Lauf bereinigt
- 3 markierte Testtransaktionen lokal in IndexedDB geschrieben
- Totalausfall simuliert, 3/3 lokal erhalten
- Wiederanlauf und Batch-Replay zum produktiven Gateway erfolgreich
- identischer Batch erneut gesendet, keine Dubletten
- Restore über Gateway erfolgreich, 3/3 wiederhergestellt

Ergebnis: PASS – Browser-E2E bestanden

## Abgenommener Stand

Abnahmebasis vor Dokumentationscommit:
- Commit: 3219821c2cba084d6db2d3d43f476a4b0c60d8bc
- Sicherungsbranch: stable/supergau-pass-2026-08-18
- Netlify-Projekt: kc-failover-gateway
- Produktivdomain: https://kc-failover-gateway.netlify.app
- E2E-Test: https://kc-failover-gateway.netlify.app/e2e

## Wichtige Betriebsregel

Der Sicherungsbranch stable/supergau-pass-2026-08-18 dient als bekannte funktionierende Rückfallbasis. Änderungen an Failover-, Replay-, Routing-, IndexedDB- oder Netlify-Konfigurationen sollten gegen Server-Matrix und Browser-E2E erneut geprüft werden.
