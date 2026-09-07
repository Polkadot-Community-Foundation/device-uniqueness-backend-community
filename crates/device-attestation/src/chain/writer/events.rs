// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{Context as _, Result};
use subxt::{error::DispatchError, extrinsics::ExtrinsicEvents, metadata::ArcMetadata, Config};

use chain_client::batch_item_results;

pub(super) fn check_proxied_call<T: Config>(
    events: &ExtrinsicEvents<T>,
    metadata: &ArcMetadata,
) -> Result<()> {
    for event in events.iter() {
        let event = event.context("decoding events")?;
        if event.pallet_name() != "Proxy" || event.event_name() != "ProxyExecuted" {
            continue;
        }
        check_dispatch_result(event.field_bytes(), metadata)?;
    }
    Ok(())
}

fn check_dispatch_result(field_bytes: &[u8], metadata: &ArcMetadata) -> Result<()> {
    match field_bytes.split_first() {
        Some((0, _)) => Ok(()),
        Some((1, error)) => {
            anyhow::bail!("proxied call failed: {}", describe(error, metadata))
        }
        _ => anyhow::bail!("ProxyExecuted's result is not a Result<(), DispatchError>"),
    }
}

pub(super) fn item_results<T: Config>(
    events: &ExtrinsicEvents<T>,
    metadata: &ArcMetadata,
) -> Result<Vec<Result<(), String>>> {
    let decoded = events
        .iter()
        .collect::<Result<Vec<_>, _>>()
        .context("decoding batch events")?;

    Ok(
        batch_item_results(decoded, |event| (event.pallet_name(), event.event_name()))
            .into_iter()
            .map(|item| item.map_err(|event| describe(event.field_bytes(), metadata)))
            .collect(),
    )
}

pub(super) fn describe(bytes: &[u8], metadata: &ArcMetadata) -> String {
    match DispatchError::decode_from(bytes, metadata.clone()) {
        Ok(DispatchError::Module(module)) => module.details_string(),
        Ok(other) => format!("{other:?}"),
        Err(e) => format!("undecodable dispatch error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::people::runtime_types::sp_runtime::{
        DispatchError as RuntimeDispatchError, ModuleError,
    };
    use subxt::ext::scale_encode::EncodeAsType as _;

    fn encoded(error: RuntimeDispatchError) -> Vec<u8> {
        let metadata = chain_types::metadata_arc();
        let ty = metadata
            .dispatch_error_ty()
            .expect("vendored metadata declares a DispatchError type");
        let mut out = Vec::new();
        error
            .encode_as_type_to(ty, metadata.types(), &mut out)
            .expect("DispatchError encodes against its own declared type");
        out
    }

    fn module_error(index: u8, error: u8) -> Vec<u8> {
        encoded(RuntimeDispatchError::Module(ModuleError {
            index,
            error: [error, 0, 0, 0],
        }))
    }

    #[test]
    fn module_errors_resolve_to_pallet_and_variant_names() {
        let metadata = chain_types::metadata_arc();

        assert_eq!(
            describe(&module_error(62, 1), &metadata),
            "PeopleLite::InvalidAttestationSignature"
        );
        assert_eq!(
            describe(&module_error(62, 3), &metadata),
            "PeopleLite::AlreadyRegistered"
        );
        assert_eq!(
            describe(&encoded(RuntimeDispatchError::BadOrigin), &metadata),
            "BadOrigin"
        );
    }

    #[test]
    fn proxy_failures_are_reported_with_a_named_reason() {
        let metadata = chain_types::metadata_arc();

        check_dispatch_result(&[0], &metadata).expect("Ok result");

        let mut err = vec![1];
        err.extend_from_slice(&module_error(62, 3));
        let reason = check_dispatch_result(&err, &metadata).expect_err("Err result");
        assert_eq!(
            reason.to_string(),
            "proxied call failed: PeopleLite::AlreadyRegistered"
        );

        assert!(check_dispatch_result(&[], &metadata).is_err());
        assert!(check_dispatch_result(&[7], &metadata).is_err());
    }

    #[test]
    fn unresolvable_errors_are_reported_as_such() {
        let rendered = describe(&module_error(200, 1), &chain_types::metadata_arc());
        assert!(
            rendered.starts_with("Unknown pallet error"),
            "unexpected rendering: {rendered}"
        );
    }
}
