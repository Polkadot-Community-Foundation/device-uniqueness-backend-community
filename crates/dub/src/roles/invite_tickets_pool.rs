// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;

use invite_tickets::pool::{self, MaintainerConfig};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("invite-tickets-pool");
    http_common::metrics::spawn("invite-tickets-pool");

    let config = MaintainerConfig::from_env().context("invalid configuration")?;

    // The silent `signal()`, not `drain()`: this role logs its own message.
    // Interrupting between a submission and its inserts is safe — the batch's
    // tickets are simply discarded (never became claimable), which is the
    // failure-path behavior.
    tokio::select! {
        result = pool::run(config) => result,
        _ = crate::shutdown::signal() => {
            tracing::info!("shutdown signal received; stopping maintainer");
            Ok(())
        }
    }
}
