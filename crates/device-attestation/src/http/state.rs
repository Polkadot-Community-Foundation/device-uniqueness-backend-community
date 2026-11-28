// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use http_common::rate_limiter::Config as RateLimiterConfig;
use jwt_verify::Jwt;
use sqlx::PgPool;

use secrecy::ExposeSecret as _;

use crate::auth::key_attest::crl::CrlCache;
use crate::auth::play_integrity::google::GoogleDecoder;
use crate::chain::asset_hub::AssetHub;
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
    /// Asset Hub read client, for `LiteLabelOwner`. Never submits.
    pub asset_hub: AssetHub,
    /// JWT issuer (Ed25519).
    pub jwt: Arc<Jwt>,
    pub config: Arc<Config>,
    /// Per-route rate limiter for the auth handshake.
    pub limiter: RateLimiter,
    /// Cached Android attestation revocation list (fetched lazily).
    pub crl: CrlCache,
    /// Temporary Play Integrity `decodeIntegrityToken` fallback client
    /// (present only while `GOOGLE_CREDENTIALS` or
    /// `PLAY_INTEGRITY_SERVICE_ACCOUNT` is configured).
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
    pub fn new(
        pool: PgPool,
        chain: PeopleChain,
        asset_hub: AssetHub,
        jwt: Jwt,
        config: Config,
    ) -> Self {
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
        let play_integrity_google = match (
            config.google_credentials.clone(),
            config.play_integrity_service_account.as_deref(),
        ) {
            // The RSA key already parsed during Config::from_env (fail-fast).
            (Some(credentials), _) => Some(Arc::new(
                GoogleDecoder::new(credentials).expect("credentials validated at startup"),
            )),
            // The email already validated during Config::from_env (fail-fast).
            (None, Some(service_account)) => Some(Arc::new(
                GoogleDecoder::impersonating(service_account)
                    .expect("service account validated at startup"),
            )),
            (None, None) => None,
        };
        let self_managed = config.play_integrity_decryption_key.is_some();
        if let Some(decoder) = &play_integrity_google {
            if self_managed {
                tracing::info!(
                    credentials = decoder.label(),
                    "Play Integrity Google decode fallback configured but unused: \
                     self-managed keys take precedence"
                );
            } else {
                tracing::info!(
                    credentials = decoder.label(),
                    "Play Integrity Google decode fallback configured"
                );
                spawn_decoder_check(decoder.clone());
            }
        }
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
            asset_hub,
            jwt: Arc::new(jwt),
            config: Arc::new(config),
            limiter,
            crl,
            play_integrity_google,
            device_check,
        }
    }
}

/// Attempts at the start-up mint, and the pause between them: the GKE metadata
/// server can take a few seconds to answer in a new pod.
const DECODER_CHECK_ATTEMPTS: u32 = 5;
const DECODER_CHECK_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// Mint a keyless Play Integrity token once, in the background, so a missing
/// grant or an unreachable metadata server shows at start-up rather than on
/// the first Android attestation. Never blocks or fails start-up; a key makes
/// no request here.
fn spawn_decoder_check(decoder: Arc<GoogleDecoder>) {
    use crate::auth::play_integrity::google::DecoderCheck;
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::debug!("no async runtime; skipping the Play Integrity decoder check");
        return;
    };
    runtime.spawn(async move {
        match decoder
            .check(DECODER_CHECK_ATTEMPTS, DECODER_CHECK_RETRY)
            .await
        {
            DecoderCheck::NotApplicable => {}
            DecoderCheck::Ready => tracing::info!("Play Integrity decoder token minted"),
            DecoderCheck::Unavailable(reason) => tracing::warn!(
                reason,
                "Play Integrity decoder token unavailable; Android attestations through \
                 the Google fallback fail until it is fixed"
            ),
        }
    });
}
