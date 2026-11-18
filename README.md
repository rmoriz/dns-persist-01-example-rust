# dns-persist-01 example

A small HTTPS server that gets its certificate with the ACME
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

`config.toml` is pre-filled with Google Trust Services values:

```toml
domain = "example.com"
contact = "mailto:admin@example.com"

[ca]
directory_url = "https://dv.acme-v02.api.pki.goog/directory"
issuer_domain_name = "pki.goog"
ttl = 3600
eab_kid = "REPLACE_WITH_EAB_KID"
eab_hmac_key = "REPLACE_WITH_BASE64URL_HMAC_KEY"
policy_wildcard = true
```

Change `domain` to a name you control and `contact` to your address. The CA
table is Google's documented `dns-persist-01` endpoint and Issuer Domain Name;
`ttl` only affects DNS caching. `policy_wildcard` also authorizes subdomains.

Google Trust Services requires External Account Binding. Create an EAB
credential in the GTS console, then set `eab_kid` and the base64url
`eab_hmac_key`. If the CA does not require EAB, omit both fields.

## First run

The account is created on first use and stored in `state/account.json`. The
order starts with a pending authorization, and the server prints the exact
record, for example:

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

## Renewals

Run the same command again. The persisted account regenerates the same record,
so the authorization becomes valid without changing DNS. Because the record is
persistent, this also works unattended once it exists:

```console
$ cargo run < /dev/null
```

Delete `state/account.json` if you want a fresh account — that also changes the
record, so you must update DNS again.

## Files

| Path                 | Contents                                     |
| -------------------- | -------------------------------------------- |
| `state/account.json` | ACME account credentials                     |
| `state/cert.pem`     | Issued certificate chain                     |
| `state/key.pem`      | Certificate private key (mode `0600`)        |

Both secret files are written with mode `0600`. `state/` is git-ignored.

## Testing against Pebble

Pebble implements the draft-01 dialect and advertises no directory metadata.
Set `ca.root_certificate` to Pebble's root CA, `ca.issuer_domain_name` to
`pebble.letsencrypt.org`, and `ca.directory_url` to your Pebble directory. The
account then uses the raw account URL, which Pebble validates.

## Library dependency

The example uses `../instant-acme` via a path dependency, on the local
`dns-persist-01` branch. Google currently serves the draft-01 dialect; the
draft-01 compatibility in the library (raw `accounturi` when the directory has
no `accountHashPrefix`, plus the `issuer-domain-names` spelling) lives in that
working tree and is not part of PR #360.

## Options

Pass a different config path as the first argument:

```console
$ cargo run -- other-config.toml
```

Requires Rust 1.88 or newer.
