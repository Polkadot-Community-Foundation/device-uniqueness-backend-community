// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use anyhow::Context as _;

use notifications::{
    routes, ApnsConfig, ApnsProvider, AppState, Config, FcmConfig, FcmProvider, PushProvider,
    RateLimiter, RateLimiterConfig, UnconfiguredProvider,
};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("notify-relay");
    http_common::metrics::spawn("notify-relay");

    let config = Config::from_env().context("invalid configuration")?;
    tracing::info!(bind = %config.bind_addr, "starting notify-relay");

    let bind_addr = config.bind_addr;
    let state = build_state(config)?;
    http_common::metrics::spawn_readiness_probe(
        "notify-relay",
        state.clone(),
        notifications::http::readiness,
    );

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %bind_addr, "notify-relay listening");

    axum::serve(listener, routes(state))
        .with_graceful_shutdown(crate::shutdown::drain())
        .await
        .context("server error")?;
    Ok(())
}

/// The push providers, the per-subject limiter, and the state they live in.
///
/// Shared with the `all-in-one` role, which needs the identical construction —
/// including the "configured or an explicit stub" decision, which must not be
/// made twice.
pub fn build_state(config: Config) -> anyhow::Result<AppState> {
    let apns = build_apns_provider()?;
    let fcm = build_fcm_provider()?;
    let limiter = RateLimiter::new(
        RateLimiterConfig::default()
            .set_max_burst(config.rate_limit)
            .set_window_secs(config.rate_window.as_secs()),
    )
    .expect("rate limiter config validated during startup");

    tracing::info!(
        limit = config.rate_limit,
        window_secs = config.rate_window.as_secs(),
        "per-subject notify rate limit configured"
    );
    Ok(AppState::new(config.jwt_verifier, apns, fcm, limiter))
}

/// Build the iOS provider: real APNs when configured, else an unconfigured stub.
fn build_apns_provider() -> anyhow::Result<Arc<dyn PushProvider>> {
    match ApnsConfig::from_env().context("invalid APNs configuration")? {
        Some(config) => {
            tracing::info!(
                environment = ?config.environment,
                topic = %config.topic,
                "APNs provider configured"
            );
            Ok(Arc::new(
                ApnsProvider::new(config).context("building APNs provider")?,
            ))
        }
        None => {
            tracing::info!("APNs not configured; iOS pushes will report provider failure");
            Ok(Arc::new(UnconfiguredProvider))
        }
    }
}

/// Build the Android provider: real FCM when configured, else an unconfigured stub.
fn build_fcm_provider() -> anyhow::Result<Arc<dyn PushProvider>> {
    match FcmConfig::from_env().context("invalid FCM configuration")? {
        Some(config) => {
            tracing::info!(project = %config.project_id, "FCM provider configured");
            Ok(Arc::new(
                FcmProvider::new(config).context("building FCM provider")?,
            ))
        }
        None => {
            tracing::info!("FCM not configured; Android pushes will report provider failure");
            Ok(Arc::new(UnconfiguredProvider))
        }
    }
}
