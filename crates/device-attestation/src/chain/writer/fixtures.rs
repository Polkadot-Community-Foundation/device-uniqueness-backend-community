// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;

use time::OffsetDateTime;

use crate::{
    chain::{asset_hub::ValidityWindow, outbox::Reservation},
    dotns,
};

pub(super) const WINDOW: u64 = 259_200;

pub(super) const SKEW: u64 = 30;

pub(super) const SIGNED_AT: i64 = 1_750_000_000;

pub(super) const BOUNDS: ValidityWindow = ValidityWindow {
    max_validity_secs: WINDOW,
    max_future_skew_secs: SKEW,
};

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
