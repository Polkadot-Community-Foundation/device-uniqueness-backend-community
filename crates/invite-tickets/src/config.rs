// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

pub use http_common::config::ConfigError;
use http_common::config::{jwt_verifier_from_env, parse_var, positive, required_var};

use crate::tickets::Network;

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Postgres connection string (required; no default). This service's own DB.
    pub database_url: String,
    /// Network literal selecting the `(dim, network)` pools this deployment
    /// serves and stamped into responses.
    pub network: Network,
    /// Verify-only JWT key material (required; no default — fail closed).
    pub jwt_verifier: jwt_verify::Verifier,
    /// Max requests per authenticated subject per window.
    pub rate_limit: u32,
    pub rate_window: Duration,
}

/// The DB password inside `database_url` must never reach logs, spans, or
/// error output — a `{:?}` of the config anywhere would otherwise leak it, so
/// `Debug` is implemented by hand. (The JWT material here is the public
/// verification key; the api bin holds no signing secret at all.)
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("database_url", &"<redacted>")
            .field("network", &self.network)
            .field("jwt_verifier", &"<jwt_verifier>")
            .field("rate_limit", &self.rate_limit)
            .field("rate_window", &self.rate_window)
            .finish()
    }
}

impl Config {
    /// Read and validate configuration from the environment.
    ///
    /// Fails (rather than defaulting) for `INVITE_TICKETS_DATABASE_URL`,
    /// `PEOPLE_NETWORK`, and the JWT key material (`JWT_JWKS_JSON` or
    /// `JWT_ED25519_PUBLIC_KEY`).
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required_var("INVITE_TICKETS_DATABASE_URL")?;

        let network_raw = required_var("PEOPLE_NETWORK")?;
        let network = Network::from_str(&network_raw).map_err(|_| ConfigError::Invalid {
            key: "PEOPLE_NETWORK",
            reason: format!("expected westend2|paseo|polkadot, got {network_raw}"),
        })?;

        let rate_limit: u32 = positive(
            "INVITE_TICKETS_RATE_LIMIT",
            parse_var("INVITE_TICKETS_RATE_LIMIT", "30")?,
        )?;
        let rate_window_secs: u64 = positive(
            "INVITE_TICKETS_RATE_LIMIT_WINDOW_SECS",
            parse_var("INVITE_TICKETS_RATE_LIMIT_WINDOW_SECS", "60")?,
        )?;
        Ok(Self {
            bind_addr: parse_var("BIND_ADDR", "0.0.0.0:8080")?,
            database_url,
            network,
            jwt_verifier: jwt_verifier_from_env()?,
            rate_limit,
            rate_window: Duration::from_secs(rate_window_secs),
        })
    }
}
