// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use http_common::rate_limiter::Config as RateLimiterConfig;
use jwt_verify::Jwt;
use sqlx::PgPool;

use secrecy::ExposeSecret as _;

use crate::auth::key_attest::crl::CrlCache;
use crate::auth::play_integrity::google::GoogleDecoder;
use crate::chain::PeopleChain;
use crate::config::Config;
use crate::device_check;
use http_common::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    /// Postgres pool (challenges, refresh tokens).
    pub pool: PgPool,
    /// People Chain read client.
    pub chain: PeopleChain,
    /// JWT issuer (Ed25519).
    pub jwt: Arc<Jwt>,
    pub config: Arc<Config>,
    /// Per-route rate limiter for the auth handshake.
    pub limiter: RateLimiter,
    /// Cached Android attestation revocation list (fetched lazily).
    pub crl: CrlCache,
    /// Temporary Play Integrity `decodeIntegrityToken` fallback client
    /// (present only while `GOOGLE_CREDENTIALS` is configured).
    pub play_integrity_google: Option<Arc<GoogleDecoder>>,
    /// Apple DeviceCheck client (present only while `DEVICE_CHECK_IOS_ENABLED`).
    pub device_check: Option<Arc<device_check::Client>>,
}

/// Lets the usernames surface use `http-common`'s `AuthSubject` extractor
/// (the frozen 401 trio) against this issuer's own verifying key.
impl http_common::HasJwtVerifier for AppState {
    fn jwt_verifier(&self) -> &jwt_verify::Verifier {
        self.jwt.verifier()
    }
}

impl AppState {
    pub fn new(pool: PgPool, chain: PeopleChain, jwt: Jwt, config: Config) -> Self {
        let limiter = RateLimiter::new(
            RateLimiterConfig::default()
                .set_window_secs(config.auth_rate_window.as_secs())
                .set_max_burst(config.auth_rate_limit),
        )
        .expect("rate limiter config validated during startup");
        let crl = CrlCache::new(
            config.android_crl_url.clone(),
            config.android_crl_cache_ttl,
            config.android_crl_max_stale,
        );
        let play_integrity_google = config.google_credentials.clone().map(|credentials| {
            // The RSA key already parsed during Config::from_env (fail-fast).
            Arc::new(GoogleDecoder::new(credentials).expect("credentials validated at startup"))
        });
        let device_check = config.device_check.clone().map(|dc| {
            // The EC key already parsed during Config::from_env (fail-fast).
            Arc::new(
                device_check::Client::new(
                    dc.team_id,
                    dc.key_id,
                    dc.private_key_pem.expose_secret(),
                    dc.base_url,
                )
                .expect("device check key validated at startup"),
            )
        });
        Self {
            pool,
            chain,
            jwt: Arc::new(jwt),
            config: Arc::new(config),
            limiter,
            crl,
            play_integrity_google,
            device_check,
        }
    }
}
