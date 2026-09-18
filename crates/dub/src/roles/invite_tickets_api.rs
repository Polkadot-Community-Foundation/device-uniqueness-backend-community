// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;

use invite_tickets::{db, routes, AppState, Config};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("invite-tickets-api");
    http_common::metrics::spawn("invite-tickets-api");

    let config = Config::from_env().context("invalid configuration")?;
    tracing::info!(
        bind = %config.bind_addr,
        network = config.network.as_str(),
        "starting invite-tickets-api"
    );

    let pool = db::connect(&config.database_url).await?;

    let bind_addr = config.bind_addr;
    let state = AppState::new(pool, config);
    http_common::metrics::spawn_readiness_probe(
        "invite-tickets-api",
        state.clone(),
        invite_tickets::http::readiness,
    );
    let app = routes(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %bind_addr, "invite-tickets-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(crate::shutdown::drain())
        .await
        .context("server error")?;

    Ok(())
}
