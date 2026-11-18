//! Minimal HTTPS server that obtains its certificate with the ACME
//! `dns-persist-01` challenge.
//!
//! On the first run the authorization is pending: the example prints the
//! `_validation-persist` TXT record and waits for you to publish it and press
//! Enter. Later runs reuse the persisted account, so the same record is
//! regenerated and the authorization can succeed without changing DNS again.
//!
//! Every name in `domains` becomes an identifier of one order, so an apex name
//! and its wildcard can share a single certificate and a single record.
//!
//! Certificates are requested with a short, configurable lifetime and renewed
//! by the running process once they fall below `renew_before_days`. The TLS
//! configuration is swapped in place, so no restart and no dropped listener.

use std::{
    fmt::Write as _,
    fs,
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use aws_lc_rs::{digest, hmac};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, body::Bytes, service::service_fn};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CryptoProvider, DefaultClient,
    ExternalAccountKey, HmacKey, Identifier, NewAccount, NewOrder, RetryPolicy, SigningAlgorithm,
    challenges::dns_persist01,
};
use rustls::{
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::Deserialize;
use time::{
    OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339,
    macros::format_description,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const DEFAULT_CONFIG_PATH: &str = "config.toml";
const ACCOUNT_FILE: &str = "account.json";

#[derive(Clone, Debug, Deserialize)]
struct Config {
    /// Names for the certificate, e.g. `["example.com", "*.example.com"]`.
    domains: Vec<String>,
    /// Requested certificate lifetime in days (Google allows 1 to 90).
    #[serde(default = "default_certificate_days")]
    certificate_days: u32,
    /// Renew once less than this many days of lifetime remain (fractions allowed).
    #[serde(default = "default_renew_before_days")]
    renew_before_days: f64,
    /// How often the running server checks the certificate lifetime.
    #[serde(default = "default_renew_check_interval_secs")]
    renew_check_interval_secs: u64,
    /// Print still-valid certificates for these names from Certificate Transparency logs.
    #[serde(default = "default_true")]
    ct_lookup: bool,
    #[serde(default)]
    contact: Option<String>,
    #[serde(default = "default_bind")]
    bind: SocketAddr,
    #[serde(default = "default_state_dir")]
    state_dir: PathBuf,
    ca: CaConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct CaConfig {
    directory_url: String,
    issuer_domain_name: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    /// External Account Binding key identifier (required by Google Trust Services).
    #[serde(default)]
    eab_kid: Option<String>,
    /// External Account Binding HMAC key, base64url encoded.
    #[serde(default)]
    eab_hmac_key: Option<String>,
    /// Include `policy=wildcard` so the record also authorizes subdomains.
    #[serde(default)]
    policy_wildcard: bool,
    /// Custom root CA for testing (e.g. Pebble). Public CAs need no override.
    #[serde(default)]
    root_certificate: Option<PathBuf>,
}

fn default_certificate_days() -> u32 {
    7
}

fn default_renew_before_days() -> f64 {
    3.0
}

fn default_renew_check_interval_secs() -> u64 {
    3600
}

fn default_true() -> bool {
    true
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8443".parse().expect("valid default bind address")
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("./state")
}

fn default_ttl() -> u32 {
    3600
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG_PATH.into());
    let config = load_config(&config_path)?;
    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("creating state directory {}", config.state_dir.display()))?;

    let account = load_or_create_account(&config).await?;
    let (cert_pem, key_pem) = match read_cached_certificate(&config)? {
        Some(cached) => cached,
        None => {
            let (cert_pem, key_pem) = obtain_certificate(&account, &config).await?;
            fs::write(config.state_dir.join("cert.pem"), cert_pem.as_bytes())
                .context("writing certificate")?;
            write_secret(&config.state_dir.join("key.pem"), key_pem.as_bytes())?;
            (cert_pem, key_pem)
        }
    };

    tokio::spawn(report_ct(config.clone()));
    let store = Arc::new(CertStore::new(&cert_pem, &key_pem)?);
    tokio::spawn(renewal_loop(account, config.clone(), store.clone()));

    serve(&config, store).await
}

/// Reuse the stored certificate while it still covers every name and is not
/// due for renewal. Any doubt (missing, unreadable, foreign, expiring) results
/// in a fresh order.
fn read_cached_certificate(config: &Config) -> Result<Option<(String, String)>> {
    let cert_path = config.state_dir.join("cert.pem");
    let key_path = config.state_dir.join("key.pem");
    let (Ok(cert_pem), Ok(key_pem)) = (
        fs::read_to_string(&cert_path),
        fs::read_to_string(&key_path),
    ) else {
        return Ok(None);
    };
    let Ok(left) = remaining(&cert_pem) else {
        return Ok(None);
    };
    if renewal_due(left, config.renew_before_days) || !covers(&cert_pem, &config.domains)? {
        return Ok(None);
    }
    println!(
        "reusing certificate from {}, {left:?} of lifetime left",
        cert_path.display()
    );
    Ok(Some((cert_pem, key_pem)))
}

/// Lifetimes left on the leaf certificate in `pem`, or zero when expired.
fn remaining(pem: &str) -> Result<Duration> {
    let not_after = leaf_not_after(pem)?;
    Ok(not_after
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO))
}

/// Whether the certificate expires within `renew_before_days`.
fn renewal_due(remaining: Duration, renew_before_days: f64) -> bool {
    remaining < Duration::from_secs_f64(renew_before_days * 86_400.0)
}

/// Whether the certificate carries exactly the configured DNS names.
fn covers(pem: &str, domains: &[String]) -> Result<bool> {
    let mut wanted = domains.to_vec();
    wanted.sort();
    let mut actual = leaf_dns_names(pem)?;
    actual.sort();
    Ok(actual == wanted)
}

fn leaf(pem: &str) -> Result<x509_parser::certificate::X509Certificate<'static>> {
    let der = load_certs(pem)?
        .into_iter()
        .next()
        .context("certificate PEM contains no certificate")?;
    let owned = der.as_ref().to_vec();
    let leaked: &'static [u8] = Box::leak(owned.into_boxed_slice());
    let (_, cert) = x509_parser::parse_x509_certificate(leaked)
        .map_err(|err| anyhow::anyhow!("parsing certificate: {err}"))?;
    Ok(cert)
}

fn leaf_not_after(pem: &str) -> Result<SystemTime> {
    let cert = leaf(pem)?;
    let unix = cert.validity().not_after.timestamp();
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(unix.max(0) as u64))
}

fn leaf_dns_names(pem: &str) -> Result<Vec<String>> {
    let cert = leaf(pem)?;
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(anyhow::Error::from)?
    else {
        return Ok(Vec::new());
    };
    Ok(san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect())
}

#[derive(Debug)]
struct CertStore {
    current: RwLock<Arc<CertifiedKey>>,
}

impl CertStore {
    fn new(cert_pem: &str, key_pem: &str) -> Result<Self> {
        Ok(Self {
            current: RwLock::new(Arc::new(certified_key(cert_pem, key_pem)?)),
        })
    }

    fn replace(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let key = Arc::new(certified_key(cert_pem, key_pem)?);
        *self.current.write().expect("certificate lock") = key;
        Ok(())
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("certificate lock").clone())
    }
}

fn certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let chain = load_certs(cert_pem)?;
    let key = any_supported_type(&load_key(key_pem)?).context("loading signing key")?;
    Ok(CertifiedKey::new(chain, key))
}

async fn renewal_loop(account: Account, config: Config, store: Arc<CertStore>) {
    let period = Duration::from_secs(config.renew_check_interval_secs);
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let left = match fs::read_to_string(config.state_dir.join("cert.pem")) {
            Ok(pem) => remaining(&pem).unwrap_or(Duration::ZERO),
            Err(err) => {
                eprintln!("renewal check: reading certificate: {err}");
                continue;
            }
        };
        if !renewal_due(left, config.renew_before_days) {
            continue;
        }
        println!("certificate expires in {left:?}, renewing");
        match obtain_certificate(&account, &config).await {
            Ok((cert_pem, key_pem)) => {
                if let Err(err) = store.replace(&cert_pem, &key_pem) {
                    eprintln!("renewal check: preparing new certificate: {err:#}");
                    continue;
                }
                let write = fs::write(config.state_dir.join("cert.pem"), cert_pem.as_bytes())
                    .context("writing certificate")
                    .and_then(|()| {
                        write_secret(&config.state_dir.join("key.pem"), key_pem.as_bytes())
                    });
                match write {
                    Ok(()) => {
                        println!("certificate renewed");
                        report_ct(config.clone()).await;
                    }
                    Err(err) => eprintln!("renewal check: storing certificate: {err:#}"),
                }
            }
            Err(err) => eprintln!("renewal failed: {err:#}"),
        }
    }
}

fn load_config(path: &str) -> Result<Config> {
    let raw = fs::read_to_string(path).with_context(|| {
        format!("reading configuration from {path} (did you copy config.toml.example?)")
    })?;
    let mut config: Config = toml::from_str(&raw).context("parsing configuration")?;

    config.domains = normalize_domains(&config.domains)?;
    if !config.ca.directory_url.starts_with("https://") {
        bail!("ca.directory_url must be an https:// URL");
    }
    if config.ca.issuer_domain_name.is_empty()
        || !config
            .ca
            .issuer_domain_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        bail!("ca.issuer_domain_name is not a valid domain name");
    }
    if config.ca.ttl == 0 {
        bail!("ca.ttl must be greater than zero");
    }
    validate_renewal(config.certificate_days, config.renew_before_days)?;
    if config.renew_check_interval_secs == 0 {
        bail!("renew_check_interval_secs must be greater than zero");
    }
    if config.ca.eab_kid.is_some() != config.ca.eab_hmac_key.is_some() {
        bail!("ca.eab_kid and ca.eab_hmac_key must be set together");
    }

    Ok(config)
}

fn validate_renewal(certificate_days: u32, renew_before_days: f64) -> Result<()> {
    if !(1..=90).contains(&certificate_days) {
        bail!("certificate_days must be between 1 and 90");
    }
    if !(renew_before_days.is_finite() && renew_before_days > 0.0)
        || renew_before_days >= f64::from(certificate_days)
    {
        bail!("renew_before_days must be above 0 and below certificate_days");
    }
    Ok(())
}

fn normalize_domains(raw: &[String]) -> Result<Vec<String>> {
    if raw.is_empty() {
        bail!("config must list at least one entry in domains");
    }
    let mut domains = Vec::with_capacity(raw.len());
    for name in raw {
        let domain = normalize_domain(name)?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    Ok(domains)
}

fn normalize_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let (wildcard, domain) = match trimmed.strip_prefix("*.") {
        Some(domain) => ("*.", domain),
        None => ("", trimmed.as_str()),
    };
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        bail!("domain {raw:?} is not a fully qualified domain name");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            bail!("domain {raw:?} contains an invalid label");
        }
    }
    Ok(format!("{wildcard}{domain}"))
}

async fn load_or_create_account(config: &Config) -> Result<Account> {
    let provider = CryptoProvider::aws_lc_rs();
    let rustls_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let http: Box<dyn instant_acme::HttpClient> = match &config.ca.root_certificate {
        Some(path) => Box::new(DefaultClient::with_pem_root(path, rustls_provider)?),
        None => Box::new(DefaultClient::new(rustls_provider)?),
    };
    let builder = Account::builder(http, provider)?;

    let account_path = config.state_dir.join(ACCOUNT_FILE);
    if account_path.exists() {
        let raw = fs::read(&account_path).context("reading account credentials")?;
        let credentials: AccountCredentials =
            serde_json::from_slice(&raw).context("parsing account credentials")?;
        println!(
            "using existing ACME account from {}",
            account_path.display()
        );
        return Ok(builder.from_credentials(credentials).await?);
    }

    let contact = config
        .contact
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let eab = match (&config.ca.eab_kid, &config.ca.eab_hmac_key) {
        (Some(kid), Some(key)) => Some(ExternalAccountKey::new(
            kid.clone(),
            Box::new(HmacSha256::from_base64(key)?),
        )),
        _ => None,
    };
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.ca.directory_url.clone(),
            eab.as_ref(),
        )
        .await?;

    let serialized = serde_json::to_vec_pretty(&credentials)?;
    write_secret(&account_path, &serialized)?;
    println!(
        "created ACME account, credentials saved to {}",
        account_path.display()
    );
    Ok(account)
}

async fn obtain_certificate(account: &Account, config: &Config) -> Result<(String, String)> {
    let identifiers = config
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect::<Vec<_>>();
    let not_before = time::OffsetDateTime::now_utc();
    let not_after = not_before + time::Duration::days(i64::from(config.certificate_days));
    let mut order = account
        .new_order(
            &NewOrder::new(&identifiers)
                .not_before(not_before)
                .not_after(not_after),
        )
        .await?;
    println!("dns-persist metadata: {:?}", account.dns_persist_metadata());

    // All names of one domain share the same record, so only print it once.
    let mut published: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        let identifier = authorization.identifier().to_string();
        if authorization.status == AuthorizationStatus::Valid {
            println!("authorization for {identifier} is still valid");
            continue;
        }
        if authorization.status != AuthorizationStatus::Pending {
            bail!(
                "authorization for {identifier} is {:?}",
                authorization.status
            );
        }

        let Some(mut challenge) = authorization.dns_persist01() else {
            bail!(
                "CA did not offer dns-persist-01; offered {}: {:?}",
                challenge_types(&authorization).join(", "),
                authorization.challenges
            );
        };
        println!(
            "CA offers issuer domain names: {:?}",
            challenge.issuer_domain_names()
        );
        let response = challenge.response_with_issuer(&config.ca.issuer_domain_name)?;
        let response = if config.ca.policy_wildcard {
            response.with_policy_wildcard()
        } else {
            response
        };
        let record = format!("{}|{}", response.host(), response.rdata());
        if !published.contains(&record) {
            print_record(&response, config.ca.ttl);
            wait_for_enter().await?;
            published.push(record);
        }
        challenge.set_ready().await?;
        println!("challenge submitted, waiting for validation");
    }

    let retry = RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .timeout(Duration::from_secs(120));
    match order.poll_ready(&retry).await? {
        instant_acme::OrderStatus::Ready => {}
        status => bail!("order did not become ready: {status:?}"),
    }

    let key_pem = order.finalize().await?;
    let cert_pem = order.poll_certificate(&retry).await?;
    let lifetime = remaining(&cert_pem).unwrap_or_default();
    println!(
        "certificate issued for {} (lifetime {lifetime:?})",
        config.domains.join(", ")
    );
    Ok((cert_pem, key_pem))
}

fn challenge_types(authorization: &instant_acme::AuthorizationHandle<'_>) -> Vec<&'static str> {
    authorization
        .challenges
        .iter()
        .map(|challenge| match challenge.state {
            instant_acme::ChallengeState::Http01(_) => "http-01",
            instant_acme::ChallengeState::Dns01(_) => "dns-01",
            instant_acme::ChallengeState::TlsAlpn01(_) => "tls-alpn-01",
            instant_acme::ChallengeState::DeviceAttest01(_) => "device-attest-01",
            instant_acme::ChallengeState::DnsPersist01(_) => "dns-persist-01",
            instant_acme::ChallengeState::Unknown => "unknown",
            _ => "unknown",
        })
        .collect()
}

async fn report_ct(config: Config) {
    if !config.ct_lookup {
        return;
    }
    let served = fs::read_to_string(config.state_dir.join("cert.pem"))
        .ok()
        .and_then(|pem| served_identity(&pem).ok());
    if let Err(err) = print_ct_certificates(&config, served.as_ref()).await {
        eprintln!("CT log lookup failed: {err:#}");
    }
}

type CtClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

struct CtEntry {
    id: String,
    names: Vec<String>,
    not_before: String,
    not_after: String,
    fingerprint: String,
    revoked: bool,
}

#[derive(serde::Deserialize)]
struct CertSpotterEntry {
    id: String,
    cert_sha256: String,
    dns_names: Vec<String>,
    not_before: String,
    not_after: String,
    #[serde(default)]
    revoked: bool,
}

#[derive(serde::Deserialize)]
struct CrtShEntry {
    id: u64,
    common_name: Option<String>,
    name_value: String,
    not_before: String,
    not_after: String,
    serial_number: String,
}

/// Print every still-valid certificate that public CT search services know for
/// the configured names. Failures are non-fatal for the caller.
///
/// Certificate Transparency logs themselves have no name index, so a search
/// service is required. Cert Spotter is queried first; crt.sh is the fallback
/// because the unauthenticated Cert Spotter rate limit is low.
async fn print_ct_certificates(config: &Config, served: Option<&ServedCert>) -> Result<()> {
    let mut bases = config
        .domains
        .iter()
        .map(|domain| domain.strip_prefix("*.").unwrap_or(domain).to_owned())
        .collect::<Vec<_>>();
    bases.sort();
    bases.dedup();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("loading native root certificates")?
        .https_only()
        .enable_http1()
        .build();
    let client: CtClient = Client::builder(TokioExecutor::new()).build(connector);

    let now = OffsetDateTime::now_utc();
    let mut seen = std::collections::BTreeSet::new();
    let mut found = Vec::new();
    for base in bases {
        for entry in ct_fetch(&client, &base).await? {
            let (Some(not_before), Some(not_after)) = (
                ct_parse_time(&entry.not_before),
                ct_parse_time(&entry.not_after),
            ) else {
                continue;
            };
            if !ct_is_current(not_before, not_after, now) || !seen.insert(entry.fingerprint.clone())
            {
                continue;
            }
            if !entry
                .names
                .iter()
                .any(|name| ct_name_on_domain(name, &config.domains))
            {
                continue;
            }
            found.push((not_before, not_after, entry));
        }
    }

    found.sort_by_key(|(_, not_after, _)| *not_after);
    println!();
    println!(
        "Still-valid certificates in Certificate Transparency for {}:",
        config.domains.join(", ")
    );
    if found.is_empty() {
        println!("  none");
        println!();
        return Ok(());
    }
    let mut marked = false;
    for (not_before, not_after, entry) in &found {
        let current = served.is_some_and(|served| ct_matches_served(entry, served));
        marked |= current;
        println!(
            "  {}{} .. {}  id={}  names={}{}",
            if current {
                "\x1b[32m\u{2192}\x1b[0m "
            } else {
                "  "
            },
            not_before.format(&Rfc3339)?,
            not_after.format(&Rfc3339)?,
            entry.id,
            entry.names.join(","),
            if entry.revoked { "  revoked" } else { "" },
        );
    }
    if marked {
        println!();
        println!("  \x1b[32m\u{2192}\x1b[0m the certificate this process is serving");
    }
    println!();
    Ok(())
}

/// Identity of the certificate currently being served, used to point at its CT
/// entry. Compared against both the certificate hash and the serial number
/// because the two search services report different fields.
struct ServedCert {
    fingerprint: String,
    serial: String,
    not_after: i64,
}

fn served_identity(pem: &str) -> Result<ServedCert> {
    let der = load_certs(pem)?
        .into_iter()
        .next()
        .context("certificate PEM contains no certificate")?;
    let digest = digest::digest(&digest::SHA256, der.as_ref());
    let mut fingerprint = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        write!(fingerprint, "{byte:02x}")?;
    }
    let leaf = leaf(pem)?;
    Ok(ServedCert {
        fingerprint,
        serial: leaf.raw_serial_as_string().to_ascii_lowercase(),
        not_after: leaf.validity().not_after.timestamp(),
    })
}

fn ct_matches_served(entry: &CtEntry, served: &ServedCert) -> bool {
    fn normalize(value: &str) -> String {
        value.trim_start_matches('0').to_ascii_lowercase()
    }
    entry.fingerprint.eq_ignore_ascii_case(&served.fingerprint)
        || normalize(&entry.fingerprint) == normalize(&served.serial)
        // Cert Spotter hashes the precertificate, which differs from the issued
        // certificate by its SCT extension; certify identity by expiry then.
        || ct_parse_time(&entry.not_after)
            .is_some_and(|not_after| not_after.unix_timestamp() == served.not_after)
}

async fn ct_fetch(client: &CtClient, base: &str) -> Result<Vec<CtEntry>> {
    match ct_fetch_certspotter(client, base).await {
        Ok(entries) => Ok(entries),
        Err(primary) => match ct_fetch_crtsh(client, base).await {
            Ok(entries) => {
                eprintln!("Cert Spotter failed ({primary:#}), fell back to crt.sh");
                Ok(entries)
            }
            Err(fallback) => bail!("Cert Spotter: {primary:#}; crt.sh: {fallback:#}"),
        },
    }
}

async fn ct_fetch_certspotter(client: &CtClient, base: &str) -> Result<Vec<CtEntry>> {
    let uri = format!(
        "https://api.certspotter.com/v1/issuances?domain={base}&include_subdomains=true&expand=dns_names"
    );
    let body = ct_get(client, &uri).await?;
    let entries: Vec<CertSpotterEntry> =
        serde_json::from_slice(&body).with_context(|| format!("parsing {uri}"))?;
    Ok(entries
        .into_iter()
        .map(|entry| CtEntry {
            id: entry.id,
            names: entry.dns_names,
            not_before: entry.not_before,
            not_after: entry.not_after,
            fingerprint: entry.cert_sha256,
            revoked: entry.revoked,
        })
        .collect())
}

async fn ct_fetch_crtsh(client: &CtClient, base: &str) -> Result<Vec<CtEntry>> {
    let uri = format!("https://crt.sh/?q={base}&output=json");
    let body = ct_get(client, &uri).await?;
    let entries: Vec<CrtShEntry> =
        serde_json::from_slice(&body).with_context(|| format!("parsing {uri}"))?;
    Ok(entries
        .into_iter()
        .map(|entry| CtEntry {
            id: entry.id.to_string(),
            names: entry
                .name_value
                .split('\n')
                .chain(entry.common_name.as_deref())
                .map(|name| name.trim().to_owned())
                .collect(),
            not_before: entry.not_before,
            not_after: entry.not_after,
            fingerprint: entry.serial_number,
            revoked: false,
        })
        .collect())
}

async fn ct_get(client: &CtClient, uri: &str) -> Result<Vec<u8>> {
    let request = Request::builder()
        .uri(uri)
        .header("user-agent", "dns-persist-example")
        .body(Full::new(Bytes::new()))?;
    let response = tokio::time::timeout(Duration::from_secs(20), client.request(request))
        .await
        .context("CT request timed out")??;
    if !response.status().is_success() {
        bail!("{uri} answered {}", response.status());
    }
    Ok(response.into_body().collect().await?.to_bytes().to_vec())
}

fn ct_parse_time(raw: &str) -> Option<OffsetDateTime> {
    if let Ok(parsed) = OffsetDateTime::parse(raw.trim(), &Rfc3339) {
        return Some(parsed);
    }
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    PrimitiveDateTime::parse(raw.trim(), &format)
        .ok()
        .map(PrimitiveDateTime::assume_utc)
}

fn ct_is_current(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    not_before <= now && now < not_after
}

fn ct_name_on_domain(name: &str, domains: &[String]) -> bool {
    let name = name.trim().trim_end_matches('.');
    domains.iter().any(|domain| {
        let base = domain.strip_prefix("*.").unwrap_or(domain);
        name == base || name.ends_with(&format!(".{base}"))
    })
}

fn print_record(response: &dns_persist01::Response, ttl: u32) {
    println!();
    println!("Publish this DNS record, then press Enter:");
    println!();
    println!("  Name:  {}", response.host());
    println!("  Type:  TXT");
    println!("  TTL:   {ttl}");
    let chunks = response.rdata_chunks().collect::<Vec<_>>();
    if chunks.len() == 1 {
        println!("  Value: {:?}", chunks[0]);
    } else {
        println!(
            "  Value: (split into {} strings in one record)",
            chunks.len()
        );
        for chunk in chunks {
            println!("         {:?}", chunk);
        }
    }
    println!();
    println!("The record identifies your ACME account and this CA, so it can be");
    println!("reused for renewals. See the README for details.");
    println!();
}

async fn wait_for_enter() -> Result<()> {
    print!("Waiting for DNS record [press Enter] ");
    std::io::stdout().flush()?;
    tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)
    })
    .await?
    .context("reading confirmation from stdin")?;
    Ok(())
}

async fn serve(config: &Config, store: Arc<CertStore>) -> Result<()> {
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store);

    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(config.bind).await?;
    println!(
        "serving https://{} for {}",
        config.bind,
        config.domains.join(", ")
    );

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("TLS handshake with {peer} failed: {err}");
                    return;
                }
            };
            let service = service_fn(handle);
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("connection with {peer} failed: {err}");
            }
        });
    }
}

async fn handle(
    _request: Request<hyper::body::Incoming>,
) -> Result<hyper::Response<Full<Bytes>>, std::convert::Infallible> {
    Ok(hyper::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(
            b"hello from a dns-persist-01 certificate\n",
        )))
        .expect("valid response"))
}

struct HmacSha256(Vec<u8>);

impl HmacSha256 {
    fn from_base64(value: &str) -> Result<Self> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(value.trim())
            .context("ca.eab_hmac_key is not valid base64url")?;
        Ok(Self(bytes))
    }
}

impl HmacKey for HmacSha256 {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        hmac::sign(&key, data).as_ref().to_vec()
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }
}

fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing certificate chain PEM")
}

fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem.as_bytes()))
        .context("parsing private key PEM")?
        .context("no private key in PEM")
}

fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    fs::write(path, data).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use time::Duration as TimeDuration;

    fn self_signed(domains: &[&str], days: i64) -> (String, String) {
        let names: Vec<String> = domains.iter().map(|name| name.to_string()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(5);
        params.not_after = now + TimeDuration::days(days);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn bundled_config_uses_google_values() {
        let config: Config = toml::from_str(include_str!("../config.toml.example")).unwrap();
        assert_eq!(
            config.ca.directory_url,
            "https://dv.acme-v02.api.pki.goog/directory"
        );
        assert_eq!(config.domains, ["example.com", "*.example.com"]);
        assert_eq!(config.certificate_days, 7);
        assert_eq!(config.renew_before_days, 3.0);
        assert_eq!(config.renew_check_interval_secs, 3600);
        assert!(config.ct_lookup);
        assert_eq!(config.ca.issuer_domain_name, "pki.goog");
        assert_eq!(config.ca.ttl, 3600);
        assert_eq!(config.ca.eab_kid.as_deref(), Some("REPLACE_WITH_EAB_KID"));
        assert!(config.ca.policy_wildcard);
    }

    #[test]
    fn normalizes_domains() {
        assert_eq!(normalize_domain(" Example.COM. ").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("*.Example.COM. ").unwrap(),
            "*.example.com"
        );
        assert!(normalize_domain("example").is_err());
        assert!(normalize_domain("-example.com").is_err());
        assert!(normalize_domain("*").is_err());
        assert!(normalize_domain("*.*.example.com").is_err());
        assert!(normalize_domain("foo.*.example.com").is_err());
    }

    #[test]
    fn normalizes_a_domain_list() {
        let raw = [
            " Example.COM. ".to_owned(),
            "*.Example.COM.".to_owned(),
            "www.example.com".to_owned(),
            "*.example.com".to_owned(),
        ];
        assert_eq!(
            normalize_domains(&raw).unwrap(),
            ["example.com", "*.example.com", "www.example.com"]
        );
        assert!(normalize_domains(&[]).is_err());
        assert!(normalize_domains(&["nope".to_owned()]).is_err());
    }

    #[test]
    fn reports_remaining_lifetime() {
        let (cert, _) = self_signed(&["example.com"], 7);
        let left = remaining(&cert).unwrap();
        assert!(left > Duration::from_secs(6 * 86_400));
        assert!(left <= Duration::from_secs(7 * 86_400));

        let (expired, _) = self_signed(&["example.com"], -1);
        assert_eq!(remaining(&expired).unwrap(), Duration::ZERO);
    }

    #[test]
    fn matches_certificate_names() {
        let (cert, _) = self_signed(&["example.com", "*.example.com"], 7);
        let wanted = ["example.com".to_owned(), "*.example.com".to_owned()];
        assert!(covers(&cert, &wanted).unwrap());

        let narrower = ["example.com".to_owned()];
        assert!(!covers(&cert, &narrower).unwrap());

        let wider = [
            "example.com".to_owned(),
            "*.example.com".to_owned(),
            "www.example.com".to_owned(),
        ];
        assert!(!covers(&cert, &wider).unwrap());
    }

    #[test]
    fn renews_below_the_threshold() {
        assert!(renewal_due(Duration::from_secs(13 * 86_400), 14.0));
        assert!(renewal_due(Duration::ZERO, 14.0));
        assert!(renewal_due(Duration::from_secs(30), 14.0));
        assert!(!renewal_due(Duration::from_secs(15 * 86_400), 14.0));
    }

    #[test]
    fn rejects_a_renewal_window_beyond_the_lifetime() {
        assert!(validate_renewal(7, 3.0).is_ok());
        assert!(validate_renewal(7, 0.5).is_ok());
        assert!(validate_renewal(7, 7.0).is_err());
        assert!(validate_renewal(7, 0.0).is_err());
        assert!(validate_renewal(7, f64::NAN).is_err());
        assert!(validate_renewal(0, 1.0).is_err());
        assert!(validate_renewal(91, 3.0).is_err());
    }

    #[test]
    fn renewal_defaults_apply() {
        let config: Config =
            toml::from_str("domains = ['example.com']\n[ca]\ndirectory_url = 'https://ca.example/directory'\nissuer_domain_name = 'ca.example'")
                .unwrap();
        assert_eq!(config.certificate_days, 7);
        assert_eq!(config.renew_before_days, 3.0);
        assert_eq!(config.renew_check_interval_secs, 3600);
        assert!(config.ct_lookup);
    }

    #[test]
    fn ct_names_must_be_on_a_configured_domain() {
        let domains = ["example.com".to_owned(), "*.example.com".to_owned()];
        assert!(ct_name_on_domain("example.com", &domains));
        assert!(ct_name_on_domain("*.example.com", &domains));
        assert!(ct_name_on_domain("www.example.com", &domains));
        assert!(!ct_name_on_domain("example.org", &domains));
        assert!(!ct_name_on_domain("notexample.com", &domains));
    }

    #[test]
    fn ct_entries_need_to_be_valid_now() {
        let now = OffsetDateTime::now_utc();
        assert!(ct_is_current(
            now - TimeDuration::days(1),
            now + TimeDuration::days(1),
            now
        ));
        assert!(!ct_is_current(
            now - TimeDuration::days(3),
            now - TimeDuration::days(1),
            now
        ));
        assert!(!ct_is_current(
            now + TimeDuration::days(1),
            now + TimeDuration::days(3),
            now
        ));
    }

    #[test]
    fn marks_the_served_certificate() {
        let (cert, _) = self_signed(&["example.com"], 7);
        let served = served_identity(&cert).unwrap();
        let mut entry = CtEntry {
            id: "1".to_owned(),
            names: vec!["example.com".to_owned()],
            not_before: String::new(),
            not_after: String::new(),
            fingerprint: served.fingerprint.clone(),
            revoked: false,
        };
        assert!(ct_matches_served(&entry, &served));
        entry.fingerprint = served.serial.clone();
        assert!(ct_matches_served(&entry, &served));
        entry.fingerprint = "deadbeef".to_owned();
        assert!(!ct_matches_served(&entry, &served));

        let not_after = OffsetDateTime::from_unix_timestamp(served.not_after).unwrap();
        entry.not_after = not_after.format(&Rfc3339).unwrap();
        assert!(ct_matches_served(&entry, &served));
    }

    #[test]
    fn ct_timestamps_parse() {
        assert!(ct_parse_time("2026-11-18T00:00:26").is_some());
        assert!(ct_parse_time("2026-11-18T00:00:26Z").is_some());
        assert!(ct_parse_time("not a date").is_none());
    }

    #[test]
    fn defaults_apply() {
        let config: Config =
            toml::from_str("domains = ['example.com']\n[ca]\ndirectory_url = 'https://ca.example/directory'\nissuer_domain_name = 'ca.example'")
                .unwrap();
        assert_eq!(config.bind.port(), 8443);
        assert_eq!(config.ca.ttl, 3600);
    }
}
