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
//! product.

use subxt::ext::codec::Encode as _;
use subxt_signer::sr25519::{verify, PublicKey, Signature};

use crate::chain::attest::PayloadVersion;

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

/// What `consumerRegistrationSignature` covers: the fields of
/// `PeopleLite.attest`'s consumer registration plus the attester (the
/// runtime's `verifier`, the call's origin).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConsumerRegistration<'a> {
    /// The candidate, who signs.
    pub account: &'a [u8; 32],
    /// The attester authority (`ATTESTER_ACCOUNT`), `attest`'s origin.
    pub verifier: &'a [u8; 32],
    /// The 65-byte communication identifier key.
    pub identifier_key: &'a [u8],
    /// The username base, without the `.` and the discriminator. Format `1`
    /// only.
    pub base: &'a str,
    /// The reserved personhood name, if any. Format `1` only.
    pub reserved_username: Option<&'a str>,
}

/// Builds the message the candidate signs for `attest`'s consumer
/// registration in `version`, as the runtime's
/// `LiteConsumerRegistrationParams::signing_payload` does:
///
/// - `1`: `(account, verifier, identifier_key, base, reserved_username)`
///   SCALE-encoded. The runtime signs the username up to its `.`, so the
///   discriminator the backend picks later is not covered.
/// - `2`: `(account, verifier, identifier_key)` SCALE-encoded.
///
/// `None` when `identifier_key` is not 65 bytes, which the runtime's type
/// cannot hold.
pub(crate) fn consumer_registration_message(
    version: PayloadVersion,
    c: &ConsumerRegistration<'_>,
) -> Option<Vec<u8>> {
    let identifier_key = <&[u8; 65]>::try_from(c.identifier_key).ok()?;
    Some(match version {
        PayloadVersion::V1 => (
            c.account,
            c.verifier,
            identifier_key,
            c.base.as_bytes(),
            c.reserved_username.map(str::as_bytes),
        )
            .encode(),
        PayloadVersion::V2 => (c.account, c.verifier, identifier_key).encode(),
    })
}

/// Verifies `signature` is the candidate's consent to the consumer
/// registration `c` in `version`, in `signature_form`, the form the People
/// runtime accepts. The runtime checks it in the same form as the candidate
/// signature.
///
/// The runtime rejects a bad one only after the transaction has paid its fee,
/// so this is what keeps a claim that can never land out of the outbox.
pub(crate) fn verify_consumer_registration_signature(
    version: PayloadVersion,
    c: &ConsumerRegistration<'_>,
    signature: &[u8],
    signature_form: &AccountSignatureForm,
) -> bool {
    consumer_registration_message(version, c).is_some_and(|message| {
        verify_account_signature(signature, &message, c.account, signature_form)
    })
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
    fn the_form_follows_the_vendored_metadata() {
        // In the vendored polkadot metadata, `PeopleLite` does not expose `SigningContext`.
        let metadata = chain_types::metadata_arc();
        assert!(metadata.pallet_by_name(PEOPLE_PALLET).is_some());
        let form = account_signature_form(&metadata, PEOPLE_PALLET);
        if chain_types::NETWORK == "polkadot" {
            assert_eq!(form, AccountSignatureForm::Plain);
        } else {
            assert!(matches!(form, AccountSignatureForm::InContext(_)));
        }
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

    /// The byte layout the runtime's `signing_payload` SCALE-encodes:
    /// fixed-size accounts and identifier key raw, the base as a
    /// compact-length-prefixed byte string, the reserved name as an `Option`.
    #[test]
    fn consumer_registration_message_matches_the_runtime_encoding() {
        let account = [1u8; 32];
        let verifier = [2u8; 32];
        let identifier_key = [3u8; 65];
        let c = ConsumerRegistration {
            account: &account,
            verifier: &verifier,
            identifier_key: &identifier_key,
            base: "aliceuser",
            reserved_username: Some("alice"),
        };
        let head = [&account[..], &verifier[..], &identifier_key[..]].concat();

        assert_eq!(
            consumer_registration_message(PayloadVersion::V1, &c).unwrap(),
            [&head[..], &[9 << 2], b"aliceuser", &[1, 5 << 2], b"alice"].concat()
        );
        let unreserved = ConsumerRegistration {
            reserved_username: None,
            ..c
        };
        assert_eq!(
            consumer_registration_message(PayloadVersion::V1, &unreserved).unwrap(),
            [&head[..], &[9 << 2], b"aliceuser", &[0]].concat()
        );
        assert_eq!(
            consumer_registration_message(PayloadVersion::V2, &c).unwrap(),
            head,
            "format 2 covers neither the base nor the reserved name"
        );
        assert_eq!(
            consumer_registration_message(
                PayloadVersion::V2,
                &ConsumerRegistration {
                    identifier_key: &[3u8; 64],
                    ..c
                }
            ),
            None,
            "an identifier key the runtime cannot hold has no message"
        );
    }

    #[test]
    fn consumer_registration_signature_binds_every_signed_field() {
        let keypair = alice();
        let account = keypair.public_key().0;
        let verifier = [2u8; 32];
        let identifier_key = [3u8; 65];
        let form = AccountSignatureForm::InContext(signing_context(b"paseo"));
        let c = ConsumerRegistration {
            account: &account,
            verifier: &verifier,
            identifier_key: &identifier_key,
            base: "aliceuser",
            reserved_username: None,
        };
        let sign = |version| {
            let message = consumer_registration_message(version, &c).unwrap();
            keypair
                .sign(&[&signing_context(b"paseo")[..], &message].concat())
                .0
        };
        let v1 = sign(PayloadVersion::V1);
        let v2 = sign(PayloadVersion::V2);
        let verifies = |version, c: &ConsumerRegistration<'_>, signature: &[u8]| {
            verify_consumer_registration_signature(version, c, signature, &form)
        };

        assert!(verifies(PayloadVersion::V1, &c, &v1));
        assert!(verifies(PayloadVersion::V2, &c, &v2));
        assert!(!verifies(PayloadVersion::V2, &c, &v1), "wrong format");
        assert!(!verifies(
            PayloadVersion::V1,
            &ConsumerRegistration {
                base: "mallory",
                ..c
            },
            &v1
        ));
        assert!(!verifies(
            PayloadVersion::V1,
            &ConsumerRegistration {
                reserved_username: Some("alice"),
                ..c
            },
            &v1
        ));
        assert!(
            !verifies(
                PayloadVersion::V2,
                &ConsumerRegistration {
                    verifier: &[9u8; 32],
                    ..c
                },
                &v2
            ),
            "signed for another attester"
        );
        assert!(
            verifies(
                PayloadVersion::V2,
                &ConsumerRegistration {
                    base: "mallory",
                    ..c
                },
                &v2
            ),
            "format 2 does not cover the base"
        );
        assert!(!verify_consumer_registration_signature(
            PayloadVersion::V1,
            &c,
            &v1,
            &AccountSignatureForm::Plain
        ));
        assert!(!verifies(PayloadVersion::V1, &c, &[0u8; 64]), "garbage");
    }
}
