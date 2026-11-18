# Google-Cloud-Projekt für Public CA aufsetzen (ohne Kostenrisiko)

> [English](gcloud.md) | Deutsch

Dieses Dokument beschreibt, wie du ein eigenes Google-Cloud-Projekt für
Zertifikate über Google Trust Services / Public CA anlegst und einen Nutzer
erzeugst, der **nur** External-Account-Keys (EAB) für ACME anlegen darf — und
sonst nichts.

Ziel ist bewusst die kleinste sinnvolle Berechtigung:

- kein `roles/owner`, kein `roles/editor`, keine Projekt-Adminrechte
- kein hinterlegtes Rechnungskonto, damit keine kostenpflichtigen Dienste
  aktiviert werden können
- Public CA selbst ist kostenlos und funktioniert nachweislich ohne Billing

> **Wichtig:** Der Nutzer legt nur EAB-Secrets an. Das eigentliche Zertifikat
> holt danach dein ACME-Client (hier: `dns-persist-01`) — dafür braucht es
> **gar keine** Google-Cloud-Anmeldung mehr. Die EAB-Daten sind der einzige
> Berührungspunkt mit dem Projekt.

## Begriffe

| Begriff                      | Bedeutung                                                                 |
| ---------------------------- | ------------------------------------------------------------------------- |
| Public CA                    | ACME-CA von Google Trust Services, kostenlos, EAB-pflichtig                |
| EAB (External Account Binding) | Schlüsselpaar `keyId` + `b64MacKey`, bindet dein ACME-Konto an das Projekt |
| `roles/publicca.externalAccountKeyCreator` | Einzige Rolle, die zum Erzeugen von EAB-Secrets nötig ist     |

## Schritt 1 — Projekt anlegen (ohne Rechnungskonto)

Als Projekt-Ersteller brauchst du `roles/resourcemanager.projectCreator`
(typischerweise über eine Folder-Rolle oder Owner in der Organisation). Ein
Rechnungskonto ist **nicht** erforderlich.

```bash
gcloud projects create dns-persist-ca --name="dns-persist CA"
gcloud config set project dns-persist-ca
```

Prüfen, dass wirklich kein Billing verknüpft ist:

```bash
gcloud billing projects describe dns-persist-ca
# Erwartet: billingEnabled: false
```

Ohne Rechnungskonto lässt sich kein kostenpflichtiger Dienst aktivieren — das
ist die stärkste Absicherung gegen versehentliche Kosten.

## Schritt 2 — Public-CA-API aktivieren

Das macht der Admin einmalig, damit der eingeschränkte Nutzer später nur noch
Keys ziehen muss (er darf keine APIs aktivieren):

```bash
gcloud services enable publicca.googleapis.com
```

Prüfen:

```bash
gcloud services list --enabled --filter="config.name:publicca.googleapis.com"
```

## Schritt 3 — Nutzer anlegen

### Variante A — menschlicher Nutzer (empfohlen für den Einstieg)

Nimm ein **eigenes** Google-Konto, nicht dein Hauptkonto. Entweder ein
Workspace-Konto in deiner Domain oder ein separates Google-Konto:

```bash
export CERT_USER="acme-certs@example.com"
```

Alternativ ein Dienstkonto, wenn später alles automatisiert läuft
(Variante B):

```bash
gcloud iam service-accounts create acme-certs \
  --display-name="ACME EAB keys"
export CERT_USER="acme-certs@$(gcloud config get-value project).iam.gserviceaccount.com"
```

## Schritt 4 — Minimale Rolle vergeben

```bash
gcloud projects add-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="roles/publicca.externalAccountKeyCreator"
```

Bei einem Dienstkonto entsprechend `--member="serviceAccount:${CERT_USER}"`.

Die Rolle enthält genau eine Berechtigung:
`publicca.externalAccountKeys.create`. Sie erlaubt **kein** Auflisten, kein
Löschen, kein IAM, keine API-Aktivierung und keinen Zugriff auf andere Dienste.

### Noch enger: eigene Rolle

Wenn dir die vordefinierte Rolle zu breit ist (sie ist es praktisch nicht),
baue eine Custom Role mit exakt einer Berechtigung:

```bash
gcloud iam roles create acmeEabOnly \
  --project=dns-persist-ca \
  --title="EAB keys only" \
  --permissions=publicca.externalAccountKeys.create

gcloud projects add-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="projects/dns-persist-ca/roles/acmeEabOnly"
```

## Schritt 5 — Berechtigungen prüfen

Policy ansehen — es darf **nur** der eine Binding-Eintrag für den Nutzer
existieren (plus die Owner deines Admins):

```bash
gcloud projects get-iam-policy dns-persist-ca \
  --flatten="bindings[].members" \
  --format="table(bindings.role:label=ROLE, bindings.members:label=MEMBER)"
```

Gegenprobe als eingeschränkter Nutzer — das muss fehlschlagen:

```bash
gcloud auth login "${CERT_USER}"
gcloud config set project dns-persist-ca
gcloud services list --enabled   # PERMISSION_DENIED / fehlende serviceusage-Rechte
gcloud projects get-iam-policy dns-persist-ca  # PERMISSION_DENIED
```

## Schritt 6 — EAB-Secret erzeugen

```bash
gcloud publicca external-account-keys create --format=json
```

Ausgabe:

```json
{ "b64MacKey": "…", "keyId": "…" }
```

Beides in `config.toml` eintragen:

```toml
eab_kid = "…keyId…"
eab_hmac_key = "…b64MacKey (base64url)…"
```

`config.toml` ist hier git-ignoriert und enthält damit kein Secret im Repo.

### Regeln für EAB-Secrets

- **7 Tage gültig**, danach verfällt das Secret unbenutzt.
- **Einmalig**: Nach der Registrierung des ACME-Kontos ist das Secret
  verbraucht; ein weiterer Account braucht ein neues Secret.
- Pro ACME-Konto ein eigenes Secret — nicht wiederverwenden.
- Das ACME-Konto selbst läuft nicht ab.

## Schritt 7 — Zertifikat holen

```bash
cargo run
```

Der `dns-persist-01`-Record wird einmalig veröffentlicht; danach laufen
Erneuerungen ohne DNS-Änderung und ohne gcloud-Zugriff.

## Betrieb

- **Projekt nicht löschen.** Das löscht alle ACME-Konten; danach sind
  Erneuerungen unmöglich, auch nach `gcloud projects undelete`.
- **Quota teilt sich pro Projekt.** Ein Nutzer mit der Rolle kann bis zu
  100 ACME-Konten pro Stunde anlegen (Limit `newAccount`: 25/min, 100/h).
  Zusätzlich gelten 100 `newOrder`/h und 300 `newAuthz`/h. Ein wildgewordener
  Client kann dir also die Erneuerung anderer Domains im selben Projekt
  blockieren — bei mehreren Domains besser ein Projekt pro Domain.
- **Nutzer deaktivieren statt Key löschen.** EAB-Keys verwaltet nur der
  Admin; zum Sperren reicht es, das Konto zu deaktivieren oder das Binding zu
  entfernen.
- **CAA prüfen.** Falls du CAA-Records nutzt: `0 issue "pki.goog"`.
- **Secret-Ablage.** EAB-Secrets nur in `config.toml`, Secret-Manager oder
  CI-Variablen; nie committen.

## Aufräumen

```bash
gcloud projects remove-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="roles/publicca.externalAccountKeyCreator"

gcloud projects delete dns-persist-ca   # löscht auch alle ACME-Konten
```

## Anti-Patterns

| Anti-Pattern                                   | Warum es weh tut                                              |
| ---------------------------------------------- | ------------------------------------------------------------- |
| `roles/owner` an den Zertifikat-Nutzer         | Darf alles, inkl. kostenpflichtiger Dienste (sofern Billing da) |
| Rechnungskonto verknüpfen „für später“         | Öffnet die Tür zu kostenpflichtigen APIs                      |
| EAB-Secret ins Repo committen                  | 7 Tage gültig, aber ein Leak bindet fremde ACME-Konten an dein Projekt |
| Hauptkonto mit 2FA-Wechsel für Automatisierung | Login-Roulette in Cronjobs                                     |
| Ein Projekt für alle Domains                   | Geteilte Quota — eine Domain blockiert die andere             |

## Weiterführend

- [Public CA Tutorial](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial?hl=de)
- [Public-CA-Quotas](https://docs.cloud.google.com/certificate-manager/docs/quotas#public-ca-request-quotas)
- [ACME Best Practices](https://developers.google.com/public-key-infrastructure/updates/september2025-acme-best-practices)
