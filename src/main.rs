//! Minimal HTTPS server that obtains its certificate with the ACME
//! `dns-persist-01` challenge.
//!
//! On the first run the authorization is pending: the example prints the
//! `_validation-persist` TXT record and waits for you to publish it and press
//! Enter. Later runs reuse the persisted account, so the same record is
//! regenerated and the authorization can succeed without changing DNS again.

use std::{
    fs,
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use aws_lc_rs::hmac;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use http_body_util::Full;
use hyper::{Request, StatusCode, body::Bytes, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CryptoProvider, DefaultClient,
    ExternalAccountKey, HmacKey, Identifier, NewAccount, NewOrder, RetryPolicy, SigningAlgorithm,
    challenges::dns_persist01,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const DEFAULT_CONFIG_PATH: &str = "config.toml";
const ACCOUNT_FILE: &str = "account.json";

#[derive(Debug, Deserialize)]
struct Config {
    domain: String,
    #[serde(default)]
    contact: Option<String>,
    #[serde(default = "default_bind")]
    bind: SocketAddr,
    #[serde(default = "default_state_dir")]
    state_dir: PathBuf,
    ca: CaConfig,
}

#[derive(Debug, Deserialize)]
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
    let (cert_pem, key_pem) = obtain_certificate(&account, &config).await?;

    fs::write(config.state_dir.join("cert.pem"), cert_pem.as_bytes())
        .context("writing certificate")?;
    write_secret(&config.state_dir.join("key.pem"), key_pem.as_bytes())?;

    serve(&config, &cert_pem, &key_pem).await
}

fn load_config(path: &str) -> Result<Config> {
    let raw = fs::read_to_string(path).with_context(|| {
        format!("reading configuration from {path} (did you copy config.toml.example?)")
    })?;
    let mut config: Config = toml::from_str(&raw).context("parsing configuration")?;

    config.domain = normalize_domain(&config.domain)?;
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
    if config.ca.eab_kid.is_some() != config.ca.eab_hmac_key.is_some() {
        bail!("ca.eab_kid and ca.eab_hmac_key must be set together");
    }

    Ok(config)
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
    let identifier = Identifier::Dns(config.domain.clone());
    let mut order = account
        .new_order(&NewOrder::new(std::slice::from_ref(&identifier)))
        .await?;
    println!("dns-persist metadata: {:?}", account.dns_persist_metadata());

    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status == AuthorizationStatus::Valid {
            println!("authorization for {} is still valid", config.domain);
            continue;
        }
        if authorization.status != AuthorizationStatus::Pending {
            bail!(
                "authorization for {} is {:?}",
                config.domain,
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
        print_record(&response, config.ca.ttl);
        wait_for_enter().await?;
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
    println!("certificate issued for {}", config.domain);
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

async fn serve(config: &Config, cert_pem: &str, key_pem: &str) -> Result<()> {
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(config.bind).await?;
    println!("serving https://{} for {}", config.bind, config.domain);

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

    #[test]
    fn bundled_config_uses_google_values() {
        let config: Config = toml::from_str(include_str!("../config.toml.example")).unwrap();
        assert_eq!(
            config.ca.directory_url,
            "https://dv.acme-v02.api.pki.goog/directory"
        );
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
    fn defaults_apply() {
        let config: Config =
            toml::from_str("domain = 'example.com'\n[ca]\ndirectory_url = 'https://ca.example/directory'\nissuer_domain_name = 'ca.example'")
                .unwrap();
        assert_eq!(config.bind.port(), 8443);
        assert_eq!(config.ca.ttl, 3600);
    }
}
