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
pub mod queue;
pub mod signature;
pub mod usernames;
pub mod widevine;

use std::fmt::Debug;

use anyhow::Context;
pub use chain::PeopleChain;
pub use config::Config;
pub use http::routes;
pub use http::state::AppState;
pub use jwt_verify::Jwt;

/// Test-only surface for the live-Postgres suite (`tests/auth_live.rs`); not
/// part of the crate's API.
#[doc(hidden)]
pub use auth::app_attest::store as app_attest_store;
use scale_info::form::PortableForm;
use scale_info::Field;

/// Serializes tests that mutate process-global environment variables
/// (`Config::from_env`, `WriterConfig::from_env`): cargo runs `#[test]`s on
/// parallel threads, so unlocked env mutation races across modules.
#[cfg(test)]
pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The connected used pallet's registration call is not the extrinsic this writer
/// builds.
#[derive(Debug)]
pub(crate) enum Pallet {
    DotnsGateway,
    PeopleLite,
}

impl std::fmt::Display for Pallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DotnsGateway => write!(f, "DotnsGateway::reserve_name"),
            Self::PeopleLite => write!(f, "PeopleLite::attest"),
        }
    }
}

/// The connected used pallet's call is not the extrinsic this writer
/// builds.
#[derive(Debug, thiserror::Error)]
#[error(
    "{pallet} shape mismatch: this writer builds [{expected}], \
     the connected runtime's {pallet} declares [{found}]. This chain runs a different \
     runtime version; point relevant network rpc(PEOPLE_RPC_URL,ASSET_HUB_RPC_URL)."
)]
pub struct PalletCallArgsShapeError {
    /// Pallet used by the call
    pallet: Pallet,
    /// Comma-separated argument names this writer encodes.
    expected: String,
    /// Comma-separated argument names the connected runtime declares.
    found: String,
}

pub(crate) fn extract_call_fields(
    metadata: subxt::ArcMetadata,
    pallet_name: &str,
    call_name: &str,
    vendored: bool,
) -> anyhow::Result<scale_info::Variant<PortableForm>> {
    let vendored = if vendored { "vendored " } else { "" };
    let pallet = metadata
        .pallet_by_name(pallet_name)
        .with_context(|| format!("{vendored}runtime declares no {pallet_name} pallet"))?;
    pallet
        .call_variant_by_name(call_name)
        .cloned()
        .with_context(|| format!("{vendored}{pallet_name} declares no {call_name} call"))
}

/// Checks the pallet call arguments shape
///
/// Names, in order. A positional-only check would accept a runtime that renamed
/// an argument. A set check would accept one that reordered it.
pub(crate) fn check_pallet_call_args(
    reserve_name_fields: &[Field<PortableForm>],
    pallet: Pallet,
    fields: &[Field<PortableForm>],
) -> Result<(), PalletCallArgsShapeError> {
    let extractor = |x: &Field<PortableForm>| {
        x.name
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "<unnamed>".to_owned())
    };
    let matches = fields.len() == reserve_name_fields.len()
        && fields
            .iter()
            .zip(reserve_name_fields)
            .all(|(found, expected)| found.ty == expected.ty && found.name == expected.name);
    if matches {
        return Ok(());
    }
    Err(PalletCallArgsShapeError {
        pallet,
        expected: reserve_name_fields
            .iter()
            .map(extractor)
            .collect::<Vec<_>>()
            .join(", "),
        found: fields.iter().map(extractor).collect::<Vec<_>>().join(", "),
    })
}
