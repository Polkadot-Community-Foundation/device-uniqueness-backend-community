// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use http_common::{rate_limiter::Config as RateLimiterConfig, RateLimiter};

use crate::config::{Config, ProofConfig};
use crate::credentials::Issuer;
use crate::proof::roots::RootCaches;

/// No database; the only chain-facing state is the proof root cache, refreshed
/// by a background task and absent when the proof feature is off.
#[derive(Clone)]
pub struct AppState {
    /// The credential minter (holds the relay-shared HMAC secret).
    pub issuer: Arc<Issuer>,
    pub verifier: Arc<jwt_verify::Verifier>,
    pub config: Arc<Config>,
    /// Per-subject rate limiter for the authenticated route.
    pub limiter: RateLimiter,
    /// Proof-authorized issuance state; `None` when `TURN_PROOF_ENABLED` is off.
    pub proof: Option<Arc<ProofState>>,
}

pub struct ProofState {
    pub freshness: crate::proof::message::Freshness,
    /// Accepted product id → the context proofs for it must be made under.
    pub contexts: std::collections::BTreeMap<String, [u8; 32]>,
    /// Latest accepted ring roots, isolated by canonical collection.
    pub roots: RootCaches,
    /// Post-verification per-alias limiter (alias = in-memory key only). The
    /// alias is context-derived, so this budget is already per person *and*
    /// product.
    pub alias_limiter: RateLimiter,
    /// Bounded ring-VRF verification slots; excess requests wait briefly.
    pub permits: Arc<tokio::sync::Semaphore>,
    /// Bounds requests waiting for a verification slot.
    pub waiters: Arc<tokio::sync::Semaphore>,
}

/// How long a caller waits for a verification slot before receiving 503.
pub const PERMIT_WAIT: std::time::Duration = std::time::Duration::from_millis(50);
pub const MAX_PERMIT_WAITERS: usize = 64;

impl ProofState {
    /// Assemble proof state over an externally owned root cache (the caller
    /// decides whether a chain refresher feeds it — the bin does, tests don't).
    pub fn new(
        config: &ProofConfig,
        roots: RootCaches,
        alias_limit: u32,
        rate_window: std::time::Duration,
    ) -> Self {
        let alias_limiter: RateLimiter = RateLimiter::new(
            RateLimiterConfig::default()
                .set_window_secs(rate_window.as_secs())
                .set_max_burst(alias_limit),
        )
        .expect("rate limiter config validated during startup");
        Self {
            freshness: crate::proof::message::Freshness::new(crate::config::PROOF_MAX_SKEW_SECS),
            contexts: config.contexts.clone(),
            roots,
            alias_limiter,
            permits: Arc::new(tokio::sync::Semaphore::new(config.concurrency)),
            waiters: Arc::new(tokio::sync::Semaphore::new(MAX_PERMIT_WAITERS)),
        }
    }
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let limiter: RateLimiter = RateLimiter::new(
            RateLimiterConfig::default()
                .set_window_secs(config.rate_window.as_secs())
                .set_max_burst(config.rate_limit),
        )
        .expect("rate limiter config validated during startup");

        let issuer = Issuer::new(
            config.turn_secret.clone(),
            config.algorithm,
            config.ttl_secs,
        );
        let proof = if let Some(ref proof_config) = config.proof {
            Some(Arc::new(ProofState::new(
                proof_config,
                RootCaches::empty(),
                config.rate_limit,
                config.rate_window,
            )))
        } else {
            None
        };
        Self {
            issuer: Arc::new(issuer),
            verifier: Arc::new(config.jwt_verifier.clone()),
            config: Arc::new(config),
            limiter,
            proof,
        }
    }
}

impl http_common::HasJwtVerifier for AppState {
    fn jwt_verifier(&self) -> &jwt_verify::Verifier {
        &self.verifier
    }
}
