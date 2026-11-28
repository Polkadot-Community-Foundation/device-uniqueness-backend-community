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
            tracing::info!(
                project = %config.project_id,
                credentials = config.credentials.label(),
                "FCM provider configured"
            );
            let provider = Arc::new(FcmProvider::new(config).context("building FCM provider")?);
            spawn_workload_identity_check(provider.clone());
            Ok(provider)
        }
        None => {
            tracing::info!("FCM not configured; Android pushes will report provider failure");
            Ok(Arc::new(UnconfiguredProvider))
        }
    }
}

/// Attempts at the start-up identity check, and the pause between them: the
/// GKE metadata server can take a few seconds to answer in a new pod.
const IDENTITY_CHECK_ATTEMPTS: u32 = 5;
const IDENTITY_CHECK_RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// Log which Google identity a keyless FCM provider sends as, so a missing
/// Workload Identity binding or an unusable token scope shows at boot rather
/// than on the first Android push.
///
/// Runs in the background and never fails start-up: the relay serves iOS and
/// everything else regardless, and Android pushes report provider failure
/// until the identity is fixed. A service-account key makes no request here.
fn spawn_workload_identity_check(provider: Arc<FcmProvider>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        for attempt in 1..=IDENTITY_CHECK_ATTEMPTS {
            match provider.workload_identity().await {
                Ok(None) => return,
                Ok(Some(identity)) if identity.can_send_fcm() => {
                    tracing::info!(
                        email = %identity.email,
                        scopes = ?identity.scopes,
                        "FCM workload identity ready"
                    );
                    return;
                }
                Ok(Some(identity)) => {
                    tracing::warn!(
                        email = %identity.email,
                        scopes = ?identity.scopes,
                        "FCM workload identity's tokens carry no scope FCM accepts; \
                         Android pushes will be rejected"
                    );
                    return;
                }
                Err(error) if attempt == IDENTITY_CHECK_ATTEMPTS => {
                    tracing::warn!(
                        %error,
                        "FCM workload identity unavailable; Android pushes will report \
                         provider failure until it is fixed"
                    );
                }
                Err(_) => tokio::time::sleep(IDENTITY_CHECK_RETRY).await,
            }
        }
    });
}
