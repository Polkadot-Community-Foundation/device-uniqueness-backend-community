// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Signing a v4 extrinsic the way the runtime will decode it.
//!
//! subxt 0.50's `create_signed` builds a v4 signed extrinsic, but picks its
//! transaction extensions from the *highest* extension version the metadata
//! declares. sp-runtime decodes a v4 signed extrinsic with version 0 and
//! nothing else. On a runtime that declares one version the two agree; on one
//! that declares several — both polkadot-test chains do (People: 11 extensions
//! at version 0, 19 at version 1; Asset Hub: 13 and 18) — the extrinsic cannot
//! be decoded, and the node aborts validation with a wasm trap rather than an
//! `InvalidTransaction` verdict.

use subxt::{
    client::{ClientAtBlock, OnlineClientAtBlockImpl},
    config::{transaction_extensions::Params as _, ClientState, TransactionExtensions},
    error::ExtrinsicError,
    ext::frame_decode::extrinsics::{
        encode_v4_signed_with_info_to, encode_v4_signer_payload_with_info, ExtrinsicEncodeError,
        ExtrinsicInfoError, ExtrinsicTypeInfo as _,
    },
    tx::{Payload, Signer, SubmittableTransaction},
    Config,
};

/// The only transaction-extension version sp-runtime reads a v4 signed
/// extrinsic with (`Preamble::Signed` decodes `ExtensionV0`).
const V4_EXTENSION_VERSION: u8 = 0;

/// Build and sign a v4 extrinsic for `call` against the block `at` is pinned
/// to, encoding the version-0 transaction extensions.
///
/// Like `create_signed`, it first checks `call` against the live metadata, so a
/// call whose shape changed since the vendored metadata fails here with
/// `IncompatibleCodegen` instead of being signed and submitted.
pub async fn create_signed_v4<T, Call, S>(
    at: &ClientAtBlock<T, OnlineClientAtBlockImpl<T>>,
    call: &Call,
    signer: &S,
    mut params: <T::TransactionExtensions as TransactionExtensions<T>>::Params,
) -> Result<SubmittableTransaction<T, OnlineClientAtBlockImpl<T>>, ExtrinsicError>
where
    T: Config,
    Call: Payload,
    S: Signer<T>,
{
    let transactions = at.transactions();
    transactions.validate(call)?;
    let account = signer.account_id();

    params.inject_account_nonce(transactions.account_nonce(&account).await?);
    params.inject_block(at.block_number(), at.block_hash());

    let state = ClientState {
        genesis_hash: at
            .genesis_hash()
            .ok_or(ExtrinsicError::GenesisHashNotProvided)?,
        spec_version: at.spec_version(),
        transaction_version: at.transaction_version(),
        metadata: at.metadata(),
    };
    let extensions = <T::TransactionExtensions as TransactionExtensions<T>>::new(&state, params)?;

    let metadata = at.metadata_ref();
    let call_info = metadata
        .extrinsic_call_info_by_name(call.pallet_name(), call.call_name())
        .map_err(info_error)?;
    let signature_info = metadata.extrinsic_signature_info().map_err(info_error)?;
    let extension_info = metadata
        .extrinsic_extension_info(Some(V4_EXTENSION_VERSION))
        .map_err(info_error)?;

    let payload = encode_v4_signer_payload_with_info(
        call.call_data(),
        &extensions,
        metadata.types(),
        &call_info,
        &extension_info,
    )?;
    let signature = signer.sign(&payload);
    let address: T::Address = account.into();

    let mut encoded = Vec::new();
    encode_v4_signed_with_info_to(
        call.call_data(),
        &extensions,
        &address,
        &signature,
        metadata.types(),
        &call_info,
        &signature_info,
        &extension_info,
        &mut encoded,
    )?;

    Ok(transactions.from_bytes(encoded))
}

fn info_error(error: ExtrinsicInfoError<'_>) -> ExtrinsicEncodeError {
    ExtrinsicEncodeError::CannotGetInfo(error.into_owned())
}
