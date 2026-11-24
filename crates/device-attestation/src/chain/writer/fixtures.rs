// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;

use time::OffsetDateTime;

use crate::{
    chain::{asset_hub::ValidityWindow, outbox::Reservation, writer::link::Window},
    dotns,
    signature::AccountSignatureForm,
};

pub(super) const WINDOW: u64 = 259_200;

pub(super) const SKEW: u64 = 30;

pub(super) const SIGNED_AT: i64 = 1_750_000_000;

pub(super) const BOUNDS: ValidityWindow = ValidityWindow {
    max_validity_secs: WINDOW,
    max_future_skew_secs: SKEW,
};

/// The lane context for `attester` within [`BOUNDS`]. The fixture reservation
/// is signed over the plain message.
pub(super) fn ctx(attester: [u8; 32]) -> Window {
    Window {
        window: BOUNDS,
        attester,
        signature_form: AccountSignatureForm::Plain,
    }
}

pub(super) fn reservation() -> Reservation {
    Reservation {
        id: 1,
        full_username: "testing.42".to_string(),
        candidate_account_id: String::new(),
        candidate_signature: vec![1; 64],
        ring_vrf_key: vec![2; 32],
        proof_of_ownership: vec![3; 64],
        consumer_registration_signature: vec![4; 64],
        identifier_key: vec![5; 65],
        reserved_username: None,
        attempt: 0,
        dotns_signature: None,
        dotns_signed_at: None,
        dotns_attempt: 0,
        payload_version: 1,
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

pub(super) fn other_reservation() -> Reservation {
    Reservation {
        id: 2,
        full_username: "second.07".to_string(),
        candidate_signature: vec![11; 64],
        ring_vrf_key: vec![12; 32],
        proof_of_ownership: vec![13; 64],
        consumer_registration_signature: vec![14; 64],
        identifier_key: vec![15; 65],
        reserved_username: Some("second".to_string()),
        ..reservation()
    }
}

/// The attester the People lane fixtures' consumer signatures cover.
pub(super) const PEOPLE_ATTESTER: [u8; 32] = [21u8; 32];

fn people_candidate() -> subxt_signer::sr25519::Keypair {
    subxt_signer::sr25519::Keypair::from_uri(
        &subxt_signer::SecretUri::from_str("//people-writer-test").expect("valid uri"),
    )
    .expect("keypair")
}

/// A reservation whose candidate signed the `PeopleLite.attest` message and
/// the format-1 consumer registration for [`PEOPLE_ATTESTER`] over the plain
/// form, with the candidate's account.
pub(super) fn signed_people_reservation() -> (Reservation, [u8; 32]) {
    let keypair = people_candidate();
    let candidate = keypair.public_key().0;

    let mut r = reservation();
    r.candidate_account_id = subxt::utils::AccountId32(candidate).to_string();
    r.candidate_signature = keypair
        .sign(&crate::signature::candidate_message(
            &candidate,
            &r.ring_vrf_key,
        ))
        .0
        .to_vec();
    sign_people_consumer(&mut r);
    (r, candidate)
}

/// Re-signs `r`'s consumer registration over its fields and payload version
/// now, as [`signed_people_reservation`]'s candidate.
pub(super) fn sign_people_consumer(r: &mut Reservation) {
    let keypair = people_candidate();
    let candidate = keypair.public_key().0;
    let version = crate::chain::attest::PayloadVersion::try_from(r.payload_version)
        .expect("a known payload version");
    let message = crate::signature::consumer_registration_message(
        version,
        &crate::signature::ConsumerRegistration {
            account: &candidate,
            verifier: &PEOPLE_ATTESTER,
            identifier_key: &r.identifier_key,
            base: r.full_username.split_once('.').expect("base.digits").0,
            reserved_username: r.reserved_username.as_deref(),
        },
    )
    .expect("a 65-byte identifier key");
    r.consumer_registration_signature = keypair.sign(&message).0.to_vec();
}

pub(super) fn signed_reservation() -> (Reservation, [u8; 32], [u8; 32]) {
    let keypair = subxt_signer::sr25519::Keypair::from_uri(
        &subxt_signer::SecretUri::from_str("//dotns-writer-test").expect("valid uri"),
    )
    .expect("keypair");
    let candidate = keypair.public_key().0;
    let attester = [11u8; 32];
    let identifier_key = vec![5; 65];

    let message = dotns::reservation_message(
        &candidate,
        &attester,
        b"testing",
        &identifier_key,
        None,
        SIGNED_AT as u64,
    );

    let mut r = reservation();
    r.identifier_key = identifier_key;
    r.dotns_signature = Some(keypair.sign(&message).0.to_vec());
    r.dotns_signed_at = Some(SIGNED_AT);
    (r, candidate, attester)
}
