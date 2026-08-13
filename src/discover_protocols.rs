//! Protocol discovery for an `interaction:` initiation (§3.7.4).
//!
//! # TODO: share this with sprucekit-mobile instead of duplicating it
//!
//! This is a copy of `sprucekit-mobile/rust/src/discover_protocols.rs`, taken to
//! unblock the extraction. It should move into `mobile-toolkit` so both crates
//! depend on one implementation. Tracking issue: TODO(file me).
//!
//! Unlike [`crate::big_stack`] — pure infrastructure where a copy is harmless —
//! duplicating this module carries real risk, so treat the copy as temporary:
//!
//! - [`validate_endpoint_url`] is what stops a QR code smuggling a `file:` or
//!   custom-scheme URL into the wallet, and restricts plain `http` to loopback.
//! - [`read_body_capped`] bounds response size (B.4) so a hostile server cannot
//!   exhaust wallet memory.
//! - [`build_http_client`] centralizes TLS, redirect and timeout policy.
//!
//! A fix applied to one copy silently leaves the other exploitable. Worse, both
//! crates validate the *same* URLs, so divergence means one QR code behaves
//! differently depending on which path handles it.
//!
//! **The copy is also currently untested here.** The 165 lines of wiremock tests
//! that cover this logic stayed in sprucekit (vcalm-rs has no `wiremock`
//! dev-dependency yet), so sprucekit's copy is exercised and this one is not.
//! Porting those tests over is the minimum bar for keeping the duplicate; moving
//! the module into `mobile-toolkit` removes the need entirely.
//!
//! When the move happens, the exported `discover_protocols()` wrapper and the
//! `uniffi::Error DiscoveryError` stay in sprucekit (they are FFI surface); only
//! the four helpers below travel. The `uniffi` attributes are already stripped
//! here, since vcalm-rs ships no bindings of its own.

use reqwest::Client;
use reqwest::header::ACCEPT;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// The discovery document returned for an `interaction:` initiation (§3.7.4).
#[derive(serde::Deserialize)]
struct DiscoveryResponse {
    protocols: HashMap<String, String>,
}

#[derive(thiserror::Error, Debug)]
pub enum DiscoveryError {
    /// A transport-level failure (stringified `reqwest::Error`).
    #[error("Network error: {0}")]
    Network(String),

    /// Interaction URL provided is invalid
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// A 5xx (or otherwise non-2xx/4xx) server response.
    #[error("Server returned error status {status}")]
    ServerError { status: u16, body: String },

    /// A response body failed to deserialize (stringified `serde_json::Error`).
    #[error("Failed to deserialize response: {0}")]
    Deserialization(String),

    /// A response body exceeded the configured size cap (B.4).
    #[error("response body exceeded the {limit_bytes}-byte limit")]
    ResponseTooLarge { limit_bytes: u64 },

    /// A non-HTTPS (or non-HTTP-scheme) URL was rejected (§3.7.1 / B.2). Plain
    /// `http` is only accepted for loopback hosts (local development).
    #[error("insecure URL rejected: {0}")]
    InsecureUrl(String),
}

/// Cap on a discovery/exchange response body (B.4: large payloads can trigger
/// DoS incidents — a malicious or broken server must not be able to exhaust the
/// wallet's memory). Generous for any plausible VPR/VP payload.
pub(crate) const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Standalone entry point: no caller-supplied client, so build a fresh one.
pub async fn discover_protocols(
    interaction_url: &str,
) -> Result<HashMap<String, String>, DiscoveryError> {
    let new_client = build_http_client()?;
    discover_protocols_with_client(interaction_url, &new_client).await
}

/// Resolve all protocol exchange URLs from an `interaction:` discovery endpoint.
/// The discovery URL must pass [`validate_endpoint_url`] (HTTPS, or loopback http
/// for local dev — §3.7.1/B.2; also rejects `file:`/other schemes a QR code could smuggle in).
pub(crate) async fn discover_protocols_with_client(
    interaction_url: &str,
    client: &Client,
) -> Result<HashMap<String, String>, DiscoveryError> {
    let interaction_url = Url::parse(interaction_url)
        .map_err(|e| DiscoveryError::InvalidUrl(format!("invalid interaction URL: {e}")))?;
    validate_endpoint_url(&interaction_url)?;

    if let Some((_, version)) = interaction_url.query_pairs().find(|(k, _)| k == "iuv")
        && version != "1"
    {
        return Err(DiscoveryError::InvalidUrl(format!(
            "unsupported interaction URL version: iuv={version} (expected 1)"
        )));
    }

    let resp = client
        .get(interaction_url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| DiscoveryError::Network(e.to_string()))?;

    let status = resp.status();
    let body = read_body_capped(resp).await?;

    if !status.is_success() {
        return Err(DiscoveryError::ServerError {
            status: status.as_u16(),
            body,
        });
    }

    let discovery: DiscoveryResponse =
        serde_json::from_str(&body).map_err(|e| DiscoveryError::Deserialization(e.to_string()))?;

    Ok(discovery.protocols)
}

/// §3.7.1: The interaction URL must be an HTTPS URL that contains an interaction-specific identifier.
/// The URL SHOULD be opaque and require no URL syntax processing before it is fetched by the receiving
/// system — the HTTPS origin is the trust signal the whole interaction model hangs on, and a bearer
/// token must never travel over plaintext. Plain `http` is allowed ONLY for loopback hosts (local
/// development/test servers); every other scheme (`file:`, custom schemes a QR code could smuggle in)
/// is rejected.
///
/// Public so a host can apply the same check to a scanned URL before handing it
/// to VCALM, rather than reimplementing the scheme allowlist.
pub fn validate_endpoint_url(url: &Url) -> Result<(), DiscoveryError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match url.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                Err(DiscoveryError::InsecureUrl(format!(
                    "plain http is only allowed for loopback hosts, got {url}"
                )))
            }
        }
        other => Err(DiscoveryError::InsecureUrl(format!(
            "unsupported URL scheme `{other}`"
        ))),
    }
}

/// Read a response body with a hard size cap (B.4). Checks `Content-Length`
/// first, then enforces the cap while streaming, so a server that lies about
/// (or omits) the length still cannot exhaust memory.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
) -> Result<String, DiscoveryError> {
    if let Some(len) = resp.content_length()
        && len > MAX_RESPONSE_BYTES as u64
    {
        return Err(DiscoveryError::ResponseTooLarge {
            limit_bytes: MAX_RESPONSE_BYTES as u64,
        });
    }

    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| DiscoveryError::Network(e.to_string()))?
    {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(DiscoveryError::ResponseTooLarge {
                limit_bytes: MAX_RESPONSE_BYTES as u64,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf)
        .map_err(|e| DiscoveryError::Deserialization(format!("response body is not UTF-8: {e}")))
}

pub(crate) fn build_http_client() -> Result<Client, DiscoveryError> {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| DiscoveryError::Network(e.to_string()))?;

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restored from `holder_legacy_tests.rs` and rehomed next to the function
    /// it covers.
    ///
    /// This is the sharpest edge of the duplication debt in this module's
    /// header: `validate_endpoint_url` is a security control, and until now the
    /// copy here was the *untested* one of a matched pair. It no longer is.
    ///
    /// Still missing relative to sprucekit: the wiremock tests over
    /// `discover_protocols` itself, plus any coverage of `read_body_capped`'s
    /// size cap. Both need a `wiremock` dev-dependency.
    #[test]
    fn validate_endpoint_url_is_https_or_loopback() {
        let ok = |u: &str| validate_endpoint_url(&Url::parse(u).unwrap()).is_ok();
        assert!(ok("https://verifier.example/exchanges/1"));
        assert!(
            ok("http://127.0.0.1:8080/exchange"),
            "loopback http allowed"
        );
        assert!(ok("http://localhost:8080/exchange"));
        assert!(ok("http://[::1]:8080/exchange"));
        assert!(!ok("http://evil.example/exchange"), "remote http rejected");
        assert!(!ok("file:///etc/passwd"), "non-http scheme rejected");
        assert!(!ok("ftp://example.com/x"));
    }
}
