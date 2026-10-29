// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr as _;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
pub use http_common::config::ConfigError;
use http_common::config::{jwt_verifier_from_env, parse_var, positive, required_var};

use crate::credentials::Algorithm;

/// Accepted clock skew, either side of server time, for a proof request's
/// timestamp.
pub const PROOF_MAX_SKEW_SECS: u64 = 60;
pub const PROOF_ROOT_REFRESH: std::time::Duration = std::time::Duration::from_secs(30);
/// How stale a ring-root snapshot may be and still verify a proof.
///
/// Twenty missed refreshes. An RPC outage keeps the last snapshot so issuance
/// survives a blip, but a member removed from the ring must stop verifying in
/// bounded time, so past this the proof route fails closed with 503.
pub const PROOF_MAX_ROOT_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// Where credentials come from. Each variant carries only its own
/// configuration, so a deployment of one provider never has to set — or hold —
/// the other's secrets.
#[derive(Clone)]
pub enum ProviderConfig {
    /// Cloudflare Realtime TURN mints both halves, one credential per request.
    Cloudflare {
        /// Names the TURN app. Not a secret — it is in the request path.
        key_id: String,
        api_token: String,
        /// Overrides the Cloudflare API root. No env source: it exists so
        /// tests can point the client at a local stub instead of the live API.
        base_url: Option<String>,
    },
    /// A self-hosted coturn relay in `--use-auth-secret` mode: this service
    /// computes the credential from a secret shared with the relay.
    Coturn {
        /// Raw (base64-decoded) HMAC secret shared with the relay.
        secret: Vec<u8>,
        /// HMAC algorithm for the password (default SHA1, coturn's default).
        algorithm: Algorithm,
        /// Configured on the relay; reserved here — validated, not on the wire.
        realm: String,
        /// ICE server URLs echoed verbatim in every 201 body.
        ice_servers: Vec<String>,
    },
}

impl ProviderConfig {
    /// The `TURN_PROVIDER` literal this variant was selected by.
    pub fn name(&self) -> &'static str {
        match self {
            ProviderConfig::Cloudflare { .. } => "cloudflare",
            ProviderConfig::Coturn { .. } => "coturn",
        }
    }
}

/// Secrets are redacted by hand; the non-secret selectors stay visible.
impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderConfig::Cloudflare {
                key_id, base_url, ..
            } => f
                .debug_struct("Cloudflare")
                .field("key_id", key_id)
                .field("api_token", &"<redacted>")
                .field("base_url", base_url)
                .finish(),
            ProviderConfig::Coturn {
                algorithm,
                realm,
                ice_servers,
                ..
            } => f
                .debug_struct("Coturn")
                .field("secret", &"<redacted>")
                .field("algorithm", algorithm)
                .field("realm", realm)
                .field("ice_servers", ice_servers)
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Credential time-to-live in seconds. Requested of Cloudflare (which may
    /// grant less); used verbatim as the expiry on the coturn path.
    pub ttl_secs: u64,
    /// The credential source (`TURN_PROVIDER`).
    pub provider: ProviderConfig,
    /// Verify-only JWT key material (required; no default — fail closed).
    pub jwt_verifier: jwt_verify::Verifier,
    /// Max requests per authenticated subject per window.
    pub rate_limit: u32,
    pub rate_window: std::time::Duration,
    /// Proof-authorized issuance (`TURN_PROOF_*`); `None` = feature off.
    pub proof: Option<ProofConfig>,
}

/// Provider secrets must never reach logs, spans, or error output, so `Debug`
/// is implemented by hand. (The JWT material is the public verification key.)
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("ttl_secs", &self.ttl_secs)
            .field("provider", &self.provider)
            .field("jwt_verifier", &"<jwt_verifier>")
            .field("rate_limit", &self.rate_limit)
            .field("rate_window", &self.rate_window)
            .field("proof", &self.proof)
            .finish()
    }
}

impl Config {
    /// Read and validate configuration from the environment.
    ///
    /// Fails (rather than defaulting) for the selected provider's own
    /// configuration and the JWT key material (`JWT_JWKS_JSON` or
    /// `JWT_ED25519_PUBLIC_KEY`).
    pub fn from_env() -> Result<Self, ConfigError> {
        let ttl_secs: u64 = positive("TURN_TTL_SECS", parse_var("TURN_TTL_SECS", "1800")?)?;
        let provider = provider_from_env()?;

        let rate_limit: u32 = positive("TURN_RATE_LIMIT", parse_var("TURN_RATE_LIMIT", "30")?)?;
        let rate_window_secs: u64 = positive(
            "TURN_RATE_LIMIT_WINDOW_SECS",
            parse_var("TURN_RATE_LIMIT_WINDOW_SECS", "60")?,
        )?;
        let proof = ProofConfig::from_env()?;
        Ok(Self {
            bind_addr: parse_var("BIND_ADDR", "0.0.0.0:8080")?,
            ttl_secs,
            provider,
            jwt_verifier: jwt_verifier_from_env()?,
            rate_limit,
            rate_window: std::time::Duration::from_secs(rate_window_secs),
            proof,
        })
    }
}

/// Select and read the credential provider from `TURN_PROVIDER`.
///
/// Only the selected provider's variables are read, so neither deployment has
/// to hold the other's secrets. The default is `cloudflare`, which is what this
/// project deploys; `coturn` is for a self-hosted relay.
fn provider_from_env() -> Result<ProviderConfig, ConfigError> {
    let selected: String = parse_var("TURN_PROVIDER", "cloudflare")?;
    match selected.trim() {
        "cloudflare" => {
            // A coturn deployment upgrading into this release would otherwise
            // boot on Cloudflare defaults it never configured and fail at
            // request time. Its own secret being present is unambiguous
            // evidence of intent, so say what to set instead.
            if std::env::var("TURN_SECRET").is_ok_and(|value| !value.trim().is_empty()) {
                return Err(ConfigError::Invalid {
                    key: "TURN_PROVIDER",
                    reason: "TURN_SECRET is set but the provider is cloudflare; \
                             set TURN_PROVIDER=coturn to keep using a self-hosted relay, \
                             or remove TURN_SECRET"
                        .to_string(),
                });
            }
            Ok(ProviderConfig::Cloudflare {
                key_id: required_var("TURN_KEY_ID")?,
                api_token: required_var("TURN_API_TOKEN")?,
                base_url: None,
            })
        }
        "coturn" => {
            let algorithm_raw: String = parse_var("TURN_AUTH_ALGORITHM", "SHA1")?;
            let algorithm =
                Algorithm::from_str(algorithm_raw.trim()).map_err(|()| ConfigError::Invalid {
                    key: "TURN_AUTH_ALGORITHM",
                    reason: format!("expected SHA1|SHA256|SHA384|SHA512, got {algorithm_raw}"),
                })?;
            Ok(ProviderConfig::Coturn {
                secret: decode_secret(&required_var("TURN_SECRET")?)?,
                algorithm,
                realm: validated_realm(&required_var("TURN_REALM")?)?,
                ice_servers: parse_ice_servers(&required_var("ICE_SERVERS")?)?,
            })
        }
        other => Err(ConfigError::Invalid {
            key: "TURN_PROVIDER",
            reason: format!("expected cloudflare|coturn, got {other:?}"),
        }),
    }
}

/// Decode the base64 `TURN_SECRET` (the relay stores it base64-encoded too).
fn decode_secret(raw: &str) -> Result<Vec<u8>, ConfigError> {
    let bytes = BASE64
        .decode(raw.trim())
        .map_err(|_| ConfigError::Invalid {
            key: "TURN_SECRET",
            reason: "invalid base64 encoding".to_string(),
        })?;
    if bytes.is_empty() {
        return Err(ConfigError::Invalid {
            key: "TURN_SECRET",
            reason: "must not be empty".to_string(),
        });
    }
    Ok(bytes)
}

/// The realm constraint: alphanumeric, underscores, dots, hyphens.
fn validated_realm(raw: &str) -> Result<String, ConfigError> {
    let realm = raw.trim();
    let valid = !realm.is_empty()
        && realm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !valid {
        return Err(ConfigError::Invalid {
            key: "TURN_REALM",
            reason: "must contain only alphanumeric characters, underscores, dots, and hyphens"
                .to_string(),
        });
    }
    Ok(realm.to_string())
}

/// Parse the comma-separated `ICE_SERVERS` list.
///
/// Required on the coturn path: there is no upstream to learn the relay
/// addresses from, so an empty list would mint credentials with nothing to use
/// them against and fail silently at the client instead of loudly at boot.
/// Entries are echoed verbatim on the wire, so only shape is checked:
/// non-empty, with a URL scheme separator.
fn parse_ice_servers(raw: &str) -> Result<Vec<String>, ConfigError> {
    if raw.trim().is_empty() {
        return Err(ConfigError::Invalid {
            key: "ICE_SERVERS",
            reason: "must list at least one ICE server URL".to_string(),
        });
    }
    raw.split(',')
        .map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() || !entry.contains(':') {
                return Err(ConfigError::Invalid {
                    key: "ICE_SERVERS",
                    reason: format!("invalid ICE server URL: {entry:?}"),
                });
            }
            Ok(entry.to_string())
        })
        .collect()
}

/// Configuration for proof-authorized issuance. Parsed only when
/// `TURN_PROOF_ENABLED=true`; every deployment-specific authority-bearing
/// value (RPC, genesis, products) is required with no default — fail closed.
#[derive(Clone)]
pub struct ProofConfig {
    pub rpc_url: String,
    /// Genesis hash this deployment is bound to (32-byte hex). Checked
    /// against the connected chain by the root refresher; not part of the
    /// proved message.
    pub genesis: [u8; 32],
    /// Accepted product id → the context a host derives for it. A caller
    /// proves under its own product's context — the only context shape TrUAPI
    /// can express; an unlisted product is refused before verification.
    pub contexts: BTreeMap<String, [u8; 32]>,
    /// Concurrent ring-VRF verifications. Defaults to available CPUs minus
    /// one (floor 1); saturated requests wait briefly, then fail with 503.
    pub concurrency: usize,
}

/// The contexts and identifiers are not secret, but keep `Debug` compact.
impl std::fmt::Debug for ProofConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofConfig")
            .field("rpc_url", &self.rpc_url)
            .field("genesis", &hex::encode(self.genesis))
            .field(
                "contexts",
                &self
                    .contexts
                    .iter()
                    .map(|(product, context)| format!("{product}={}", hex::encode(context)))
                    .collect::<Vec<_>>(),
            )
            .field("concurrency", &self.concurrency)
            .finish()
    }
}

impl ProofConfig {
    /// Parse the `TURN_PROOF_*` family; `Ok(None)` when the feature is off.
    fn from_env() -> Result<Option<Self>, ConfigError> {
        let enabled: bool = parse_var("TURN_PROOF_ENABLED", "false")?;
        if !enabled {
            return Ok(None);
        }
        let concurrency = proof_concurrency(
            &std::env::var("TURN_PROOF_CONCURRENCY").unwrap_or_else(|_| "auto".to_string()),
        )?;
        let suffix: u32 = parse_var("TURN_PROOF_CONTEXT_SUFFIX", "0")?;
        Ok(Some(Self {
            rpc_url: required_var("TURN_PROOF_RPC_URL")?,
            genesis: hex32("TURN_PROOF_GENESIS", &required_var("TURN_PROOF_GENESIS")?)?,
            contexts: contexts(&required_var("TURN_PROOF_PRODUCTS")?, suffix)?,
            concurrency,
        }))
    }
}

fn proof_concurrency(raw: &str) -> Result<usize, ConfigError> {
    if raw.trim().eq_ignore_ascii_case("auto") {
        return Ok(std::thread::available_parallelism()
            .map(|cpus| cpus.get().saturating_sub(1).max(1))
            .unwrap_or(1));
    }
    positive(
        "TURN_PROOF_CONCURRENCY",
        raw.trim()
            .parse::<usize>()
            .map_err(|error| ConfigError::Invalid {
                key: "TURN_PROOF_CONCURRENCY",
                reason: error.to_string(),
            })?,
    )
}

/// Derive one context per accepted product from a comma-separated list.
fn contexts(raw: &str, suffix: u32) -> Result<BTreeMap<String, [u8; 32]>, ConfigError> {
    let mut contexts = BTreeMap::new();
    for entry in raw.split(',') {
        let product = entry.trim();
        if product.is_empty() {
            return Err(ConfigError::Invalid {
                key: "TURN_PROOF_PRODUCTS",
                reason: "contains an empty product id".to_string(),
            });
        }
        contexts.insert(
            product.to_string(),
            crate::proof::context::product_context(product, suffix),
        );
    }
    if contexts.is_empty() {
        return Err(ConfigError::Invalid {
            key: "TURN_PROOF_PRODUCTS",
            reason: "must list at least one product id".to_string(),
        });
    }
    Ok(contexts)
}

/// Decode non-empty hex (with or without `0x`).
fn hex_bytes(key: &'static str, raw: &str) -> Result<Vec<u8>, ConfigError> {
    let bytes =
        hex::decode(raw.trim().trim_start_matches("0x")).map_err(|_| ConfigError::Invalid {
            key,
            reason: "invalid hex encoding".to_string(),
        })?;
    if bytes.is_empty() {
        return Err(ConfigError::Invalid {
            key,
            reason: "must not be empty".to_string(),
        });
    }
    Ok(bytes)
}

fn hex32(key: &'static str, raw: &str) -> Result<[u8; 32], ConfigError> {
    hex_bytes(key, raw)?
        .try_into()
        .map_err(|v: Vec<u8>| ConfigError::Invalid {
            key,
            reason: format!("expected 32 bytes, got {}", v.len()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_base64_secret_and_rejects_garbage() {
        assert_eq!(decode_secret("QUJD").expect("valid"), b"ABC");
        assert!(decode_secret("not base64!").is_err());
        assert!(decode_secret("").is_err());
    }

    #[test]
    fn realm_enforces_the_relay_character_set() {
        assert_eq!(
            validated_realm(" example.org ").expect("valid"),
            "example.org"
        );
        assert!(validated_realm("with space").is_err());
        assert!(validated_realm("").is_err());
    }

    #[test]
    fn ice_servers_split_trim_and_reject_schemeless_entries() {
        assert!(parse_ice_servers("").is_err());
        assert!(parse_ice_servers("  ").is_err());
        assert_eq!(
            parse_ice_servers(" stun:a.example:3478 , turn:b.example:3478?transport=udp ")
                .expect("valid"),
            vec![
                "stun:a.example:3478".to_string(),
                "turn:b.example:3478?transport=udp".to_string(),
            ]
        );
        assert!(parse_ice_servers("stun:a.example:3478,,").is_err());
        assert!(parse_ice_servers("no-scheme").is_err());
    }

    #[test]
    fn products_derive_one_distinct_context_each() {
        let derived = contexts(" vox.dot , game.dot ", 0).expect("valid");
        assert_eq!(
            derived.keys().collect::<Vec<_>>(),
            vec!["game.dot", "vox.dot"]
        );
        assert_ne!(derived["vox.dot"], derived["game.dot"]);
        assert_eq!(
            derived["vox.dot"],
            crate::proof::context::product_context("vox.dot", 0)
        );
        assert_ne!(
            derived["vox.dot"],
            contexts(" vox.dot ", 1).expect("valid")["vox.dot"]
        );
        assert!(contexts("vox.dot,,game.dot", 0).is_err());
        assert!(contexts("", 0).is_err());
    }

    #[test]
    fn proof_concurrency_accepts_auto_or_an_explicit_positive_limit() {
        assert!(proof_concurrency("auto").expect("available CPUs") >= 1);
        assert_eq!(proof_concurrency(" 4 ").expect("explicit limit"), 4);
        assert!(proof_concurrency("0").is_err());
        assert!(proof_concurrency("many").is_err());
    }
}

#[cfg(test)]
mod provider_tests {
    use super::*;

    /// `Config::from_env` reads process-wide state, so these run under one lock
    /// and clear up after themselves.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Env(Vec<&'static str>);

    impl Env {
        fn set(pairs: &[(&'static str, &str)]) -> Self {
            let keys = pairs.iter().map(|(key, _)| *key).collect();
            for (key, value) in pairs {
                std::env::set_var(key, value);
            }
            Env(keys)
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            for key in &self.0 {
                std::env::remove_var(key);
            }
        }
    }

    const SECRET_B64: &str = "ZGV2LXNlY3JldA==";

    #[test]
    fn the_default_provider_is_cloudflare_and_needs_its_own_vars() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[("TURN_KEY_ID", "key"), ("TURN_API_TOKEN", "token")]);
        let provider = provider_from_env().expect("cloudflare");
        assert_eq!(provider.name(), "cloudflare");
        match provider {
            ProviderConfig::Cloudflare { key_id, .. } => assert_eq!(key_id, "key"),
            other => panic!("expected cloudflare, got {other:?}"),
        }
    }

    #[test]
    fn cloudflare_refuses_to_boot_without_its_credentials() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[("TURN_PROVIDER", "cloudflare")]);
        assert!(provider_from_env().is_err());
    }

    #[test]
    fn coturn_reads_only_the_relay_configuration() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[
            ("TURN_PROVIDER", "coturn"),
            ("TURN_SECRET", SECRET_B64),
            ("TURN_REALM", "example.org"),
            ("ICE_SERVERS", "turn:relay.example:3478?transport=udp"),
        ]);
        let provider = provider_from_env().expect("coturn");
        assert_eq!(provider.name(), "coturn");
        match provider {
            ProviderConfig::Coturn {
                secret,
                algorithm,
                realm,
                ice_servers,
            } => {
                assert_eq!(secret, b"dev-secret");
                // Unset `TURN_AUTH_ALGORITHM` keeps coturn's own default.
                assert_eq!(algorithm, Algorithm::Sha1);
                assert_eq!(realm, "example.org");
                assert_eq!(ice_servers, vec!["turn:relay.example:3478?transport=udp"]);
            }
            other => panic!("expected coturn, got {other:?}"),
        }
    }

    /// Nothing upstream supplies the relay addresses on this path, so an
    /// unset `ICE_SERVERS` would mint credentials with nothing to use them
    /// against — a 201 that fails silently at the client.
    #[test]
    fn coturn_refuses_to_boot_without_ice_servers() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[
            ("TURN_PROVIDER", "coturn"),
            ("TURN_SECRET", SECRET_B64),
            ("TURN_REALM", "example.org"),
        ]);
        assert!(provider_from_env().is_err());
    }

    /// The upgrade trap: a relay deployment that sets no `TURN_PROVIDER` would
    /// otherwise default onto Cloudflare and fail at request time.
    #[test]
    fn a_relay_secret_without_the_matching_provider_is_refused_at_boot() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[
            ("TURN_SECRET", SECRET_B64),
            ("TURN_KEY_ID", "key"),
            ("TURN_API_TOKEN", "token"),
        ]);
        let error = provider_from_env().expect_err("must refuse");
        let rendered = error.to_string();
        assert!(rendered.contains("TURN_PROVIDER=coturn"), "{rendered}");
    }

    #[test]
    fn an_unknown_provider_names_the_accepted_values() {
        let _guard = ENV_LOCK.lock().expect("lock");
        let _env = Env::set(&[("TURN_PROVIDER", "twilio")]);
        let rendered = provider_from_env().expect_err("must refuse").to_string();
        assert!(rendered.contains("cloudflare|coturn"), "{rendered}");
    }
}
