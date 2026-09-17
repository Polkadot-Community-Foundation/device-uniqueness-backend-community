// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use anyhow::Context as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Connect to Postgres and apply embedded migrations.
///
/// Migrations are compiled into the binary (`migrations/`), so a deploy carries
/// its own schema and applies it on boot (advisory-locked, safe across replicas).
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .context("connecting to Postgres")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running database migrations")?;

    Ok(pool)
}
