// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use anyhow::Context as _;

use http_common::{rate_limiter, RateLimiter};
use username_indexer::poc::{self, Poc};
use username_indexer::sync::{self, Freshness, FreshnessSnapshot};
use username_indexer::{db, ensure_seeded, routes, AppState, Config, PeopleChain};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("username-indexer");
    http_common::metrics::spawn("username-indexer");

    let config = Config::from_env().context("invalid configuration")?;
    tracing::info!(
        bind = %config.bind_addr,
        people_rpc = %config.people_rpc_url,
        storage_page_size = config.storage_page_size,
        sync_interval_secs = config.sync_interval_secs,
        "starting username-indexer"
    );

    let pool = db::connect(&config.database_url).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url, config.storage_page_size).await?;

    let bind_addr = config.bind_addr;
    let state = build_state(&config, pool.clone(), chain).await?;

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %bind_addr, "username-indexer listening");

    http_common::metrics::spawn_readiness_probe(
        "username-indexer",
        (pool, state.chain.clone()),
        |(p, c)| username_indexer::http::health::probe(p, c),
    );
    axum::serve(listener, routes(state))
        .with_graceful_shutdown(crate::shutdown::drain())
        .await
        .context("server error")?;
    Ok(())
}

/// Everything between "connected" and "ready to serve": the proof-of-compute
/// gate, the finalized bootstrap (or checkpoint resume), the incremental sync
/// task, the puzzle pruner, and the rate limiter.
///
/// Shared with the `all-in-one` role, which needs the identical sequence —
/// duplicating it there would be a second place for the bootstrap-vs-resume
/// decision to drift.
pub async fn build_state(
    config: &Config,
    pool: sqlx::PgPool,
    chain: PeopleChain,
) -> anyhow::Result<AppState> {
    // Resolved before any I/O so a misconfigured gate fails at startup rather
    // than after the finalized bootstrap scan (which can take minutes).
    let poc = build_poc(config)?;

    match username_indexer::try_projection_lock(&pool).await? {
        Some(_lock) => {
            let dropped = username_indexer::clear_speculative(&pool).await?;
            if dropped > 0 {
                tracing::info!(dropped, "cleared speculative rows left by a previous run");
            }
        }
        None => tracing::info!(
            "another instance holds the projection lock; leaving its speculative rows alone"
        ),
    }

    let freshness = Freshness::new();
    match ensure_seeded(&pool, &chain, config.storage_page_size).await? {
        Some(report) => {
            tracing::info!(
                indexed = report.indexed,
                skipped = report.skipped,
                snapshot_number = report.snapshot_number,
                trigger = ?report.trigger,
                "finalized username bootstrap complete"
            );
            freshness.update(FreshnessSnapshot {
                last_finalized_number: report.snapshot_number,
                last_synced_at: time::OffsetDateTime::now_utc(),
                records_indexed: report.indexed,
                decode_failures: report.skipped,
            });
        }
        None => {
            if let Some(snapshot) = sync::checkpoint_freshness(&pool).await? {
                tracing::info!(
                    last_finalized_number = snapshot.last_finalized_number,
                    "existing checkpoint found; resuming incremental sync (skipping full bootstrap)"
                );
                freshness.update(snapshot);
            }
        }
    }
    tokio::spawn(sync::run(
        pool.clone(),
        chain.clone(),
        config.clone(),
        freshness.clone(),
    ));

    let limiter = RateLimiter::new(
        rate_limiter::Config::default()
            .set_window_secs(config.search_rate_limit_window_secs.into())
            .set_max_burst(config.search_rate_limit),
    )
    .expect("rate limiter config validated during startup");
    let mut state = AppState::new(pool.clone(), chain, freshness, limiter);
    if let Some(poc) = poc {
        tracing::info!(
            difficulty_bits = config.poc_difficulty_bits,
            "proof-of-compute gate enabled on public search (a valid JWT also satisfies it)"
        );
        tokio::spawn(prune_spent_puzzles(pool, PRUNE_INTERVAL));
        state = state.with_poc(poc);
    }
    Ok(state)
}

/// Build the proof-of-compute gate when it is enabled.
///
/// Requires verify-only JWT material (`JWT_JWKS_JSON` or
/// `JWT_ED25519_PUBLIC_KEY`) so authenticated callers keep bypassing the puzzle;
/// missing key material is a boot failure rather than a silent gate that would
/// force the shipping apps to mine.
fn build_poc(config: &Config) -> anyhow::Result<Option<Poc>> {
    let Some(secret) = config.poc_hmac_secret.as_deref() else {
        return Ok(None);
    };
    let verifier = http_common::config::jwt_verifier_from_env()
        .context("POC_ENABLED=true requires verify-only JWT material")?;
    Ok(Some(Poc::new(
        poc::derive_secret(secret),
        config.poc_difficulty_bits,
        verifier,
    )))
}

const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Periodically drop spent-puzzle rows whose validity window has passed.
async fn prune_spent_puzzles(pool: sqlx::PgPool, every: Duration) {
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        interval.tick().await;
        match poc::store::prune_expired(&pool).await {
            Ok(0) => {}
            Ok(pruned) => tracing::debug!(pruned, "pruned expired spent puzzles"),
            Err(error) => tracing::warn!(%error, "pruning expired spent puzzles failed"),
        }
    }
}
