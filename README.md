# dns-persist-01 example

[![CI](https://github.com/rmoriz/dns-persist-01-example-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/rmoriz/dns-persist-01-example-rust/actions/workflows/ci.yml)

A small HTTPS server (or certificate-only agent) that gets its certificate with the ACME
`dns-persist-01` challenge from [instant-acme](../instant-acme). The
validation record is derived from your account, the domain and the CA, not
from a per-order token. You publish it **once**; later runs reuse it.

> **Experimental.** `instant-acme` implements
> [draft-ietf-acme-dns-persist-03](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-03)
> and falls back to the draft-01 dialect when the CA does not advertise
> `accountHashPrefix` (raw `accounturi`, `issuer-domain-names`). Google's
> [September 2026 announcement](https://developers.google.com/public-key-infrastructure/updates/september2026-dns-persist-01)
> documents draft-01, so with Google the example writes the raw account URL as
> in Google's own example record.

## Configuration

Copy the bundled template, then edit it:

```console
$ cp config.toml.example config.toml
```

`config.toml.example` is pre-filled with Google Trust Services values:

```toml
domains = ["example.com", "*.example.com"]
contact = "mailto:admin@example.com"

[ca]
directory_url = "https://dv.acme-v02.api.pki.goog/directory"
issuer_domain_name = "pki.goog"
ttl = 3600
eab_kid = "REPLACE_WITH_EAB_KID"
eab_hmac_key = "REPLACE_WITH_BASE64URL_HMAC_KEY"
policy_wildcard = true
```

Change `domains` to names you control and `contact` to your address. The CA
table is Google's documented `dns-persist-01` endpoint and Issuer Domain Name;
`ttl` only affects DNS caching.

Every entry becomes one identifier of the order and one subject alternative
name on the certificate. See [Wildcard certificates](#wildcard-certificates)
for the `*.` syntax.

Google Trust Services requires External Account Binding. Create an EAB
credential in the GTS console, then set `eab_kid` and the base64url
`eab_hmac_key`. If the CA does not require EAB, omit both fields.

[`gcloud.md`](gcloud.md) walks through a cost-free Google Cloud project and an
IAM user that may only create EAB keys.

## First run

The account is created on first use and stored in `state/account.json`. The
order starts with a pending authorization per name, and the server prints the
exact record once (all names of a domain share it), for example:

```text
  Name:  _validation-persist.example.com.
  Type:  TXT
  TTL:   3600
  Value: "pki.goog; accounturi=...; policy=wildcard"
```

Create that TXT record at your DNS provider. When it resolves, press Enter.
The example submits the challenge, waits for validation, finalizes the order,
writes `state/cert.pem` and `state/key.pem`, and starts the HTTPS server.

```console
$ cargo run
```

Open <https://localhost:8443/> (the default certificate is for your configured
domain, so either use that hostname or pass `--resolve`/`-k`):

```console
$ curl --resolve example.com:8443:127.0.0.1 https://example.com:8443/
hello from a dns-persist-01 certificate
```

> **DoH warning:** If you mapped your domain to `127.0.0.1` in `/etc/hosts`,
> a browser configured to use DNS-over-HTTPS bypasses `/etc/hosts` and may not
> reach the local server. In that case use `curl` or a browser that uses the
> system DNS resolver, or open <https://localhost:8443/>.

## Wildcard certificates

A wildcard certificate needs two things: the wildcard name in `domains`, and a
validation record carrying `policy=wildcard`. The record is published at the
base domain, not at the wildcard, and serves the apex order and the wildcard
order alike.

```toml
domains = ["example.com", "*.example.com"]
```

The example adds `policy=wildcard` automatically as soon as `domains` contains
a `*.` entry (`policy_wildcard = true` forces it too), and the first run prints
one record for both names:

```text
  Name:  _validation-persist.example.com.
  Type:  TXT
  TTL:   3600
  Value: "pki.goog; accounturi=...; policy=wildcard"
```

Publish that record and press Enter. The issued certificate then carries both
names:

```console
$ openssl x509 -in state/cert.pem -noout -ext subjectAltName
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:*.example.com
$ curl --resolve foo.example.com:8443:127.0.0.1 https://foo.example.com:8443/
hello from a dns-persist-01 certificate
```

Things worth knowing:

- The draft requires `policy=wildcard` whenever the authorization is a
  wildcard (sections 5 and 6 of
  [draft-ietf-acme-dns-persist-03](https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-03)).
  Without it the record only authorizes the exact name, and the wildcard
  authorization fails validation. Because the record is persistent, publish it
  with the policy from the start instead of adding it later.
- A wildcard certificate covers exactly one label: `foo.example.com` yes,
  `a.b.example.com` no. Add `*.sub.example.com` if you need that, but note the
  record then sits at `_validation-persist.sub.example.com` — this example
  validates every entry at its own record name and does not use the draft's
  `ancestorDomain` to reuse the apex record.
- Only `*.` at the leftmost position is allowed. `domains = ["*.example.com"]`
  without the apex issues a wildcard-only certificate.
- The validation record is a plain TXT record at `_validation-persist`; you do
  not need a wildcard DNS record for validation. You do still need `A`/`AAAA`
  records for the names you actually serve.

## Lifetime and renewal

Certificates are requested with a short lifetime: `certificate_days`, default
`7`. Google Trust Services honours anything from 1 to 90 days and recommends
at least 3. A CA may ignore the request; the setting is only a hint.

While the server runs it checks the stored certificate every
`renew_check_interval_secs` (default `3600`) and orders a replacement as soon
as less than `renew_before_days` remain (default `3`, fractions allowed for
testing). The replacement is swapped into the live TLS configuration, so the
listener and every existing connection stay up while `state/cert.pem` and
`state/key.pem` are rewritten.

`renew_before_days` must be above 0 and below `certificate_days`. A threshold
at or above the requested lifetime would renew on every check.

```toml
certificate_days = 7
renew_before_days = 3
renew_check_interval_secs = 3600
```

Renewals reuse the persisted account and the already published record, so they
run unattended: no DNS change, no prompt. Only if the record has to be
re-authorized and stdin is a terminal does the example print it again and wait
for Enter.

Restarting also does not churn certificates — a stored certificate that still
covers every configured name and is not due for renewal is reused. Delete
`state/account.json` if you want a fresh account; that changes the record, so
you must update DNS again.

Manual re-runs still work and renew on the spot:

```console
$ cargo run < /dev/null
```

Because the record is persistent, that works unattended once it exists.

## Certificate Transparency

After issuing and after every renewal the example prints still-valid
certificates for the configured names from Certificate Transparency:

```text
Still-valid certificates in Certificate Transparency for example.com, *.example.com:
    2026-11-18T01:08:14Z .. 2026-11-20T01:08:14Z  id=18453679703  names=*.example.com,example.com
  → 2026-11-18T01:10:19Z .. 2026-11-25T01:10:19Z  id=18453769867  names=*.example.com,example.com
    2026-09-25T13:38:29Z .. 2026-12-24T13:38:28Z  id=17408030496  names=example.com

  → the certificate this process is serving
```

The green arrow marks the certificate currently in use. It is matched by
certificate hash, serial number or expiry, because Cert Spotter hashes the
precertificate rather than the issued certificate.

This is a lookup, not a substitute for surveillance: an unexpected certificate
is worth investigating, and a certificate missing here only means CT
submission is still in flight.

CT logs have no name index, so the search goes through a service: Cert Spotter
first, crt.sh as fallback. Both are third parties and learn the base domain
names. The unauthenticated Cert Spotter limit is low (10 requests per hour),
so rapid restarts may fall back or fail softly.

Set `ct_lookup = false` to skip the lookup. Failures are warnings and never
affect issuance or renewal. Revoked certificates are listed and marked
`revoked`.

## Certificate-only use and renew hook

Set `serve = false` when only the files in `state_dir` matter, for example
because a reverse proxy or mail server terminates TLS. The process stays
running and keeps renewing; it just does not bind a port.

`renew_hook` names a program that runs after every successful issuance, the
first one included, once the new files are on disk. It runs with the state
directory as working directory and gets:

| Variable | Value |
| --- | --- |
| `DNS_PERSIST_DOMAINS` | configured names, space separated |
| `DNS_PERSIST_CERT` | absolute path of the certificate |
| `DNS_PERSIST_KEY` | absolute path of the private key |
| `DNS_PERSIST_NOT_AFTER` | expiry as RFC 3339 |

```toml
serve = false
renew_hook = "/usr/local/bin/reload-proxy"
```

The hook must be executable, is killed after 60 seconds, and a failure is
logged without failing the renewal. Shell scripts need an executable bit and a
shebang; arguments are not supported, wrap them in the script.

## systemd service

`contrib/systemd/dns-persist-example.service` runs the example as a hardened,
unprivileged service that restarts on failure. It expects the config under
`/etc/dns-persist-example/` and the state under `/var/lib/dns-persist-example/`,
so set `state_dir = "/var/lib/dns-persist-example"` in the config.

```console
$ sudo useradd --system --home /var/lib/dns-persist-example --shell /usr/sbin/nologin dns-persist
$ cargo build --release
$ sudo install -Dm755 target/release/dns-persist-example /usr/local/bin/dns-persist-example
$ sudo install -Dm600 config.toml /etc/dns-persist-example/config.toml
$ sudo install -Dm644 contrib/systemd/dns-persist-example.service /etc/systemd/system/
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now dns-persist-example
$ journalctl -u dns-persist-example -f
```

The unit uses `ProtectHome=yes`, so keep config, state and hook outside home
directories. Binding a port below 1024 needs
`AmbientCapabilities=CAP_NET_BIND_SERVICE` (commented in the unit). Every
config edit needs `systemctl restart dns-persist-example`.

## Files

| Path                 | Contents                                      |
| -------------------- | --------------------------------------------- |
| `state/account.json` | ACME account credentials                      |
| `state/cert.pem`     | Issued certificate chain, replaced on renewal |
| `state/key.pem`      | Certificate private key (mode `0600`)         |

Both secret files are written with mode `0600`. `state/` is git-ignored.

## Testing against Pebble

Pebble implements the draft-01 dialect and advertises no directory metadata.
Set `ca.root_certificate` to Pebble's root CA, `ca.issuer_domain_name` to
`pebble.letsencrypt.org`, and `ca.directory_url` to your Pebble directory. The
account then uses the raw account URL, which Pebble validates.

## Library dependency

The example depends on the `dns-persist-01` branch of
<https://github.com/rmoriz/instant-acme> (the branch behind
[PR #360](https://github.com/djc/instant-acme/pull/360)). Cargo fetches it from
GitHub, so no local checkout is needed.

Google currently serves the draft-01 dialect; the branch includes the
draft-01 compatibility (raw `accounturi` when the directory has no
`accountHashPrefix`, plus the `issuer-domain-names` spelling).

## Options

Pass a different config path as the first argument:

```console
$ cargo run -- other-config.toml
```

Requires Rust 1.88 or newer.

## License

Apache-2.0, the same license as `instant-acme`; see [`LICENSE`](LICENSE).

---

Built with [OpenCode 2](https://opencode.ai) and DeepSeek V4.1 Flash Uncensored (Yeta AI).
