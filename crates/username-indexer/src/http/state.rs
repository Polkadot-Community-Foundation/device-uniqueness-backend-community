// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use sqlx::PgPool;

use crate::poc::Poc;
use crate::sync::Freshness;
use crate::PeopleChain;
use http_common::RateLimiter;

/// Cheap-to-clone database and People Chain handles for handlers.
#[derive(Clone)]
pub struct AppState {
    /// Service-owned Postgres pool.
    pub pool: PgPool,
    /// Reconnecting People Chain client.
    pub chain: PeopleChain,
    /// Latest finalized-sync freshness, updated by the resync loop.
    pub freshness: Freshness,
    /// In-memory per-IP rate limiter for the public search route.
    pub limiter: RateLimiter,
    /// The proof-of-compute gate, present only when `POC_ENABLED=true`.
    ///
    /// `None` is the shipping default and means the service behaves exactly as
    /// it did before the gate existed.
    pub poc: Option<Poc>,
}

impl AppState {
    /// Build handler state from connected dependencies and a search limiter.
    ///
    /// The proof-of-compute gate is off; add it with [`AppState::with_poc`].
    pub fn new(
        pool: PgPool,
        chain: PeopleChain,
        freshness: Freshness,
        limiter: RateLimiter,
    ) -> Self {
        Self {
            pool,
            chain,
            freshness,
            limiter,
            poc: None,
        }
    }

    pub fn with_poc(mut self, poc: Poc) -> Self {
        self.poc = Some(poc);
        self
    }
}
