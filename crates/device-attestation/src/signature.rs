// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Account signatures over messages that are not transactions.
//!
//! An individuality runtime that checks these signatures in the personhood
//! signing context exposes that context as the `SigningContext` constant of the
//! pallet that verifies the signature (`PeopleLite` on People, `DotnsGateway`
//! on Asset Hub). The backend reads the constant from the runtime's metadata at
//! the block it is working against and checks in the same form: the
//! context followed by the message when the constant is there, the plain
//! message when it is not. One release works on any network, before and after
//! the runtime upgrade, and switches as soon as the upgrade is enacted.
//!
//! The context is `blake2_256("product/peopl." ++ network_suffix ++ "/" ++
//! "sig/" ++ 28 zero bytes)`, as the runtime's
//! `indiv_support::context::signing_payload` builds it for the personhood
//! product (paritytech/individuality-community#196).

use subxt_signer::sr25519::{verify, PublicKey, Signature};

/// The pallet that verifies `PeopleLite.attest`'s candidate signature.
pub(crate) const PEOPLE_PALLET: &str = "PeopleLite";

/// The pallet that verifies `DotnsGateway.reserve_name`'s candidate signature.
pub(crate) const DOTNS_PALLET: &str = "DotnsGateway";

/// The pallet constant that carries the signing context.
const SIGNING_CONTEXT_CONSTANT: &str = "SigningContext";

/// The message prefix the People Chain reconstructs for `PeopleLite.attest`;
/// `candidateSignature` (and `proofOfOwnership`) cover
/// `POP_REGISTER_PREFIX || candidatePubkey || ringVrfKey`.
pub(crate) const POP_REGISTER_PREFIX: &[u8] = b"pop:people-lite:register using";

/// The message form a runtime accepts for an account signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSignatureForm {
    /// The message alone.
    Plain,
    /// The 32-byte signing context followed by the message.
    InContext([u8; 32]),
}

/// Reads the message form `pallet` accepts for account signatures from
/// `metadata`: in context when the pallet exposes its `SigningContext`
/// constant, plain otherwise.
pub(crate) fn account_signature_form(
    metadata: &subxt::Metadata,
    pallet: &str,
) -> AccountSignatureForm {
    form_from_constant(
        metadata
            .pallet_by_name(pallet)
            .and_then(|pallet| pallet.constant_by_name(SIGNING_CONTEXT_CONSTANT))
            .map(|constant| constant.value()),
    )
}

/// The form a `SigningContext` constant value denotes. A value that is not 32
/// bytes is not a context this backend knows how to apply, so it is read as
/// absent.
fn form_from_constant(value: Option<&[u8]>) -> AccountSignatureForm {
    match value.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
        Some(context) => AccountSignatureForm::InContext(context),
        None => AccountSignatureForm::Plain,
    }
}

/// Verifies that `signer`'s sr25519 key signed `message` in `form`.
///
/// Returns `false` for a signature that is not 64 bytes.
pub(crate) fn verify_account_signature(
    signature: &[u8],
    message: &[u8],
    signer: &[u8; 32],
    form: &AccountSignatureForm,
) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let context: &[u8] = match form {
        AccountSignatureForm::Plain => &[],
        AccountSignatureForm::InContext(context) => context,
    };
    verify(
        &Signature(signature),
        [context, message].concat(),
        &PublicKey(*signer),
    )
}

/// Verifies the caller controls `candidate_pubkey`.
///
/// The candidate's sr25519 key must have signed
/// `POP_REGISTER_PREFIX || candidatePubkey || ringVrfKey` in `signature_form`,
/// the form the People runtime accepts.
pub(crate) fn verify_candidate_signature(
    candidate_pubkey: &[u8; 32],
    candidate_signature: &[u8],
    ring_vrf_key: &[u8],
    signature_form: &AccountSignatureForm,
) -> bool {
    let message = candidate_message(candidate_pubkey, ring_vrf_key);
    verify_account_signature(
        candidate_signature,
        &message,
        candidate_pubkey,
        signature_form,
    )
}

/// Builds the message a candidate signs for `PeopleLite.attest`.
pub(crate) fn candidate_message(candidate_pubkey: &[u8; 32], ring_vrf_key: &[u8]) -> Vec<u8> {
    [POP_REGISTER_PREFIX, candidate_pubkey, ring_vrf_key].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;
    use subxt::config::{substrate::BlakeTwo256, Hasher as _};
    use subxt_signer::sr25519::Keypair;
    use subxt_signer::SecretUri;

    fn alice() -> Keypair {
        Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap()
    }

    /// Builds the personhood signing context on the network with
    /// `network_suffix`, as the runtime does.
    fn signing_context(network_suffix: &[u8]) -> [u8; 32] {
        BlakeTwo256
            .hash(&[b"product/peopl.", network_suffix, b"/sig/", &[0u8; 28]].concat())
            .0
    }

    /// The runtime's personhood signing context on a `paseo` network, from its
    /// `indiv_support::context` test.
    const PERSONHOOD_PASEO: &str =
        "50a0143eac8dc44969947d41ad201c0717c0456425b2631fefdcfbd7b2b23d62";

    #[test]
    fn signing_context_matches_the_runtime() {
        assert_eq!(hex::encode(signing_context(b"paseo")), PERSONHOOD_PASEO);
    }

    #[test]
    fn the_form_follows_the_signing_context_constant() {
        let context = signing_context(b"paseo");
        assert_eq!(
            form_from_constant(Some(&context)),
            AccountSignatureForm::InContext(context)
        );
        assert_eq!(form_from_constant(None), AccountSignatureForm::Plain);
        // A value of another width is not a context this backend applies.
        assert_eq!(
            form_from_constant(Some(&[1u8; 31])),
            AccountSignatureForm::Plain
        );
    }

    #[test]
    fn a_runtime_without_the_constant_takes_the_plain_message() {
        // The vendored People metadata predates the constant.
        let metadata = chain_types::metadata_arc();
        assert!(metadata.pallet_by_name(PEOPLE_PALLET).is_some());
        assert_eq!(
            account_signature_form(&metadata, PEOPLE_PALLET),
            AccountSignatureForm::Plain
        );
        assert_eq!(
            account_signature_form(&metadata, "NoSuchPallet"),
            AccountSignatureForm::Plain
        );
    }

    #[test]
    fn each_form_accepts_only_its_own_message() {
        let keypair = alice();
        let signer = keypair.public_key().0;
        let context = signing_context(b"paseo");
        let in_context_form = AccountSignatureForm::InContext(context);
        let message = b"message";

        let plain = keypair.sign(message).0;
        let in_context = keypair.sign(&[context.as_slice(), message].concat()).0;

        assert!(verify_account_signature(
            &plain,
            message,
            &signer,
            &AccountSignatureForm::Plain
        ));
        assert!(!verify_account_signature(
            &in_context,
            message,
            &signer,
            &AccountSignatureForm::Plain
        ));
        assert!(verify_account_signature(
            &in_context,
            message,
            &signer,
            &in_context_form
        ));
        assert!(!verify_account_signature(
            &plain,
            message,
            &signer,
            &in_context_form
        ));
    }

    #[test]
    fn rejects_other_contexts_and_short_signatures() {
        let keypair = alice();
        let signer = keypair.public_key().0;
        let form = AccountSignatureForm::InContext(signing_context(b"paseo"));
        let message = b"message";

        // A signature in another network's context does not verify.
        let other_network = signing_context(b"testnet");
        let foreign = keypair
            .sign(&[other_network.as_slice(), message].concat())
            .0;
        assert!(!verify_account_signature(&foreign, message, &signer, &form));

        // A signature that is not 64 bytes is rejected, not panicked on.
        assert!(!verify_account_signature(
            &[0u8; 10], message, &signer, &form
        ));
    }

    #[test]
    fn candidate_signature_verifies_control_of_beneficiary() {
        let keypair = alice();
        let candidate = keypair.public_key().0;
        let ring_vrf_key = [7u8; 32];
        let signature = keypair
            .sign(&candidate_message(&candidate, &ring_vrf_key))
            .0;

        let plain = AccountSignatureForm::Plain;
        assert!(verify_candidate_signature(
            &candidate,
            &signature,
            &ring_vrf_key,
            &plain
        ));
        assert!(!verify_candidate_signature(
            &candidate, &signature, &[9u8; 32], &plain
        ));
        let other = Keypair::from_uri(&SecretUri::from_str("//Bob").unwrap())
            .unwrap()
            .public_key()
            .0;
        assert!(!verify_candidate_signature(
            &other,
            &signature,
            &ring_vrf_key,
            &plain
        ));
        assert!(!verify_candidate_signature(
            &candidate,
            &[0u8; 10],
            &ring_vrf_key,
            &plain
        ));
    }
}
