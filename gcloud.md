# Set up a Google Cloud project for Public CA (without cost risk)

> English | [Deutsch](gcloud.de.md)

This document describes how to create your own Google Cloud project for
certificates via Google Trust Services / Public CA and create a user that is
allowed to create **only** External Account Keys (EAB) for ACME — and nothing
else.

The goal is deliberately the smallest sensible permission set:

- no `roles/owner`, no `roles/editor`, no project admin rights
- no linked billing account, so no paid services can be enabled
- Public CA itself is free and demonstrably works without billing

> **Important:** The user only creates EAB secrets. Your ACME client (here:
> `dns-persist-01`) then obtains the actual certificate — for that it needs
> **no** Google Cloud login at all anymore. The EAB data is the only point of
> contact with the project.

## Terms

| Term                         | Meaning                                                                  |
| ---------------------------- | ------------------------------------------------------------------------ |
| Public CA                    | ACME CA from Google Trust Services, free, EAB required                   |
| EAB (External Account Binding) | Key pair `keyId` + `b64MacKey`, binds your ACME account to the project |
| `roles/publicca.externalAccountKeyCreator` | The only role needed to create EAB secrets                |

## Step 1 — Create the project (without a billing account)

As the project creator you need `roles/resourcemanager.projectCreator`
(typically via a folder role or Owner in the organization). A billing account
is **not** required.

```bash
gcloud projects create dns-persist-ca --name="dns-persist CA"
gcloud config set project dns-persist-ca
```

Verify that no billing is actually linked:

```bash
gcloud billing projects describe dns-persist-ca
# Expected: billingEnabled: false
```

Without a billing account, no paid service can be enabled — that is the
strongest safeguard against accidental costs.

## Step 2 — Enable the Public CA API

The admin does this once so that the restricted user later only has to fetch
keys (the user is not allowed to enable APIs):

```bash
gcloud services enable publicca.googleapis.com
```

Verify:

```bash
gcloud services list --enabled --filter="config.name:publicca.googleapis.com"
```

## Step 3 — Create the user

### Option A — human user (recommended to get started)

Use a **separate** Google account, not your main account. Either a Workspace
account in your domain or a dedicated Google account:

```bash
export CERT_USER="acme-certs@example.com"
```

Alternatively a service account if everything will run automated later
(Option B):

```bash
gcloud iam service-accounts create acme-certs \
  --display-name="ACME EAB keys"
export CERT_USER="acme-certs@$(gcloud config get-value project).iam.gserviceaccount.com"
```

## Step 4 — Grant the minimal role

```bash
gcloud projects add-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="roles/publicca.externalAccountKeyCreator"
```

For a service account use `--member="serviceAccount:${CERT_USER}"`
accordingly.

The role contains exactly one permission:
`publicca.externalAccountKeys.create`. It allows **no** listing, no deletion,
no IAM, no API activation, and no access to other services.

### Even tighter: a custom role

If the predefined role is too broad for you (in practice it is not), build a
custom role with exactly one permission:

```bash
gcloud iam roles create acmeEabOnly \
  --project=dns-persist-ca \
  --title="EAB keys only" \
  --permissions=publicca.externalAccountKeys.create

gcloud projects add-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="projects/dns-persist-ca/roles/acmeEabOnly"
```

## Step 5 — Check the permissions

Inspect the policy — **only** the one binding entry for the user may exist
(plus your admin's Owner bindings):

```bash
gcloud projects get-iam-policy dns-persist-ca \
  --flatten="bindings[].members" \
  --format="table(bindings.role:label=ROLE, bindings.members:label=MEMBER)"
```

Counter-check as the restricted user — this must fail:

```bash
gcloud auth login "${CERT_USER}"
gcloud config set project dns-persist-ca
gcloud services list --enabled   # PERMISSION_DENIED / missing serviceusage permissions
gcloud projects get-iam-policy dns-persist-ca  # PERMISSION_DENIED
```

## Step 6 — Create an EAB secret

```bash
gcloud publicca external-account-keys create --format=json
```

Output:

```json
{ "b64MacKey": "…", "keyId": "…" }
```

Put both into `config.toml`:

```toml
eab_kid = "…keyId…"
eab_hmac_key = "…b64MacKey (base64url)…"
```

`config.toml` is git-ignored here, so no secret ends up in the repository.

### Rules for EAB secrets

- **Valid for 7 days**, after which the secret expires unused.
- **Single use**: after the ACME account is registered, the secret is used up;
  another account needs a new secret.
- One secret per ACME account — do not reuse.
- The ACME account itself does not expire.

## Step 7 — Obtain the certificate

```bash
cargo run
```

The `dns-persist-01` record is published once; afterwards renewals run
without DNS changes and without gcloud access.

## Operations

- **Do not delete the project.** That deletes all ACME accounts; afterwards
  renewals are impossible, even after `gcloud projects undelete`.
- **Quota is shared per project.** A user with the role can create up to 100
  ACME accounts per hour (limit `newAccount`: 25/min, 100/h). In addition,
  100 `newOrder`/h and 300 `newAuthz`/h apply. A runaway client can therefore
  block renewals of other domains in the same project — for multiple domains,
  prefer one project per domain.
- **Deactivate the user instead of deleting the key.** Only the admin manages
  EAB keys; deactivating the account or removing the binding is enough to
  block it.
- **Check CAA.** If you use CAA records: `0 issue "pki.goog"`.
- **Secret storage.** Keep EAB secrets only in `config.toml`, Secret Manager,
  or CI variables; never commit them.

## Cleanup

```bash
gcloud projects remove-iam-policy-binding dns-persist-ca \
  --member="user:${CERT_USER}" \
  --role="roles/publicca.externalAccountKeyCreator"

gcloud projects delete dns-persist-ca   # also deletes all ACME accounts
```

## Anti-patterns

| Anti-pattern                                     | Why it hurts                                                    |
| ------------------------------------------------ | --------------------------------------------------------------- |
| `roles/owner` for the certificate user           | May do anything, including paid services (if billing exists)    |
| Linking a billing account "for later"            | Opens the door to paid APIs                                     |
| Committing the EAB secret to the repo            | Valid for 7 days, but a leak binds foreign ACME accounts to your project |
| Main account with 2FA dance for automation       | Login roulette in cron jobs                                     |
| One project for all domains                      | Shared quota — one domain blocks the other                      |

## Further reading

- [Public CA tutorial](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial?hl=en)
- [Public CA quotas](https://docs.cloud.google.com/certificate-manager/docs/quotas#public-ca-request-quotas)
- [ACME best practices](https://developers.google.com/public-key-infrastructure/updates/september2025-acme-best-practices)
