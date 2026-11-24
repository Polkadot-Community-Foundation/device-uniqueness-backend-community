// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;
use secrecy::ExposeSecret as _;

use device_attestation::chain::asset_hub::AssetHub;
use device_attestation::{db, routes, AppState, Config, Jwt, PeopleChain};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("device-attestation-api");
    http_common::metrics::spawn("device-attestation-api");

    let config = Config::from_env().context("invalid configuration")?;
    tracing::info!(
        bind = %config.bind_addr,
        issuer = %config.jwt_issuer,
        people_rpc = %config.people_rpc_url,
        asset_hub_rpc = %config.asset_hub_rpc_url,
        attestation = config.attestation_mode(),
        "starting device-attestation-api"
    );

    let jwt = Jwt::new(config.jwt_secret.expose_secret(), config.jwt_issuer.clone());
    let pool = db::connect(config.database_url.expose_secret()).await?;
    let chain = PeopleChain::connect(&config.people_rpc_url).await?;
    tracing::info!("connected to People Chain");
    let asset_hub = AssetHub::connect_for_reads(&config.asset_hub_rpc_url).await?;
    tracing::info!("connected to Asset Hub");

    let bind_addr = config.bind_addr;
    let state = AppState::new(pool, chain, asset_hub, jwt, config);
    let probe_state = (
        state.pool.clone(),
        state.chain.clone(),
        state.asset_hub.clone(),
    );
    http_common::metrics::spawn_readiness_probe(
        "device-attestation-api",
        probe_state,
        |(p, c, a)| device_attestation::http::health::api_probe(p, c, a),
    );
    let app = routes(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %bind_addr, "device-attestation-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(crate::shutdown::drain())
        .await
        .context("server error")?;

    Ok(())
}
