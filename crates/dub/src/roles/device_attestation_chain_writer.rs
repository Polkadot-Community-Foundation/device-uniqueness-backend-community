// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Context as _;

use device_attestation::chain::writer::{self, WriterConfig};

pub async fn run() -> anyhow::Result<()> {
    http_common::telemetry::init("device-attestation-chain-writer");
    http_common::metrics::spawn("device-attestation-chain-writer");

    let config = WriterConfig::from_env()
        .context("invalid device-attestation-chain-writer configuration")?;
    Ok(writer::run(config).await?)
}
