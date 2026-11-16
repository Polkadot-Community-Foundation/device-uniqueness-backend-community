// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;
use turn::{routes, AppState, Config};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("turn-api");
    http_common::metrics::spawn("turn-api");

    let config = Config::from_env().context("invalid configuration")?;
    tracing::info!(
        bind = %config.bind_addr,
        ttl_secs = config.ttl_secs,
        provider = config.provider.name(),
        "starting turn-api"
    );

    let bind_addr = config.bind_addr;
    let state = AppState::start(config);
    http_common::metrics::spawn_readiness_probe("turn-api", state.clone(), turn::http::readiness);
    let app = routes(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %bind_addr, "turn-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(crate::shutdown::drain())
        .await
        .context("server error")?;

    Ok(())
}
