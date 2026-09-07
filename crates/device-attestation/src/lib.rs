// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

mod auth;
pub mod chain;
pub mod config;
pub mod db;
pub mod device_check;
pub mod dotns;
pub mod eligibility;
pub mod http;
pub mod openapi;
pub mod payment;
pub mod queue;
pub mod usernames;
pub mod widevine;

pub use chain::PeopleChain;
pub use config::Config;
pub use http::routes;
pub use http::state::AppState;
pub use jwt_verify::Jwt;

/// Test-only surface for the live-Postgres suite (`tests/auth_live.rs`); not
/// part of the crate's API.
#[doc(hidden)]
pub use auth::app_attest::store as app_attest_store;

/// Serializes tests that mutate process-global environment variables
/// (`Config::from_env`, `WriterConfig::from_env`): cargo runs `#[test]`s on
/// parallel threads, so unlocked env mutation races across modules.
#[cfg(test)]
pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
