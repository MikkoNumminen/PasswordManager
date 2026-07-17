//! Google OIDC verification for the public web access path.
//!
//! An ID token here is an alternative bearer credential: it authorizes
//! ciphertext access exactly like the API token and has no role in key
//! derivation. Verification checks the RS256 signature against Google's
//! published JWKS, the issuer, the audience (this deployment's OAuth client
//! id), expiry, and finally that the verified email is on the allowlist.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
/// Do not hammer Google when tokens carry unknown key ids.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

pub struct OidcConfig {
    pub client_id: String,
    /// Lowercased allowed email addresses.
    pub allowed_emails: Vec<String>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    email: Option<String>,
    email_verified: Option<bool>,
}

struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    last_fetch: Option<Instant>,
}

pub struct OidcVerifier {
    config: OidcConfig,
    client: reqwest::Client,
    cache: RwLock<KeyCache>,
}

impl OidcVerifier {
    pub fn new(config: OidcConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building HTTP client for JWKS")?;
        Ok(Self {
            config,
            client,
            cache: RwLock::new(KeyCache {
                keys: HashMap::new(),
                last_fetch: None,
            }),
        })
    }

    /// Verify a Google ID token and return the authorized email.
    pub async fn verify(&self, token: &str) -> Result<String> {
        let header = decode_header(token).context("token is not a JWT")?;
        let kid = header.kid.context("token has no key id")?;
        let key = self.key_for(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
        let data = decode::<GoogleClaims>(token, &key, &validation)
            .context("token verification failed")?;
        check_claims(&data.claims, &self.config.allowed_emails)
    }

    async fn key_for(&self, kid: &str) -> Result<DecodingKey> {
        if let Some(key) = self.cached_key(kid) {
            return Ok(key);
        }
        self.refresh_keys().await?;
        self.cached_key(kid)
            .context("token signed with a key Google does not currently publish")
    }

    fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
        self.cache
            .read()
            .expect("jwks cache lock")
            .keys
            .get(kid)
            .cloned()
    }

    async fn refresh_keys(&self) -> Result<()> {
        {
            let cache = self.cache.read().expect("jwks cache lock");
            if let Some(last) = cache.last_fetch {
                if last.elapsed() < REFRESH_COOLDOWN {
                    return Ok(());
                }
            }
        }
        let jwks: Jwks = self
            .client
            .get(JWKS_URL)
            .send()
            .await
            .context("fetching Google JWKS")?
            .error_for_status()
            .context("Google JWKS endpoint answered with an error")?
            .json()
            .await
            .context("parsing Google JWKS")?;

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            if jwk.kty != "RSA" {
                continue;
            }
            if let Ok(key) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                keys.insert(jwk.kid, key);
            }
        }
        let mut cache = self.cache.write().expect("jwks cache lock");
        cache.keys = keys;
        cache.last_fetch = Some(Instant::now());
        Ok(())
    }
}

/// The signature, issuer, audience, and expiry are already checked. This
/// enforces the deployment policy: a verified email on the allowlist.
fn check_claims(claims: &GoogleClaims, allowed_emails: &[String]) -> Result<String> {
    if claims.email_verified != Some(true) {
        bail!("email is not verified");
    }
    let email = claims
        .email
        .as_deref()
        .context("token carries no email claim")?
        .to_lowercase();
    if !allowed_emails.contains(&email) {
        bail!("email is not on the allowlist");
    }
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(email: Option<&str>, verified: Option<bool>) -> GoogleClaims {
        GoogleClaims {
            email: email.map(str::to_string),
            email_verified: verified,
        }
    }

    fn allowlist() -> Vec<String> {
        vec!["mikko@example.com".to_string()]
    }

    #[test]
    fn allowlisted_verified_email_passes() {
        let email =
            check_claims(&claims(Some("Mikko@Example.com"), Some(true)), &allowlist()).unwrap();
        assert_eq!(email, "mikko@example.com");
    }

    #[test]
    fn unverified_email_fails() {
        assert!(check_claims(
            &claims(Some("mikko@example.com"), Some(false)),
            &allowlist()
        )
        .is_err());
        assert!(check_claims(&claims(Some("mikko@example.com"), None), &allowlist()).is_err());
    }

    #[test]
    fn missing_email_fails() {
        assert!(check_claims(&claims(None, Some(true)), &allowlist()).is_err());
    }

    #[test]
    fn other_email_fails() {
        assert!(check_claims(
            &claims(Some("intruder@example.com"), Some(true)),
            &allowlist()
        )
        .is_err());
    }
}
