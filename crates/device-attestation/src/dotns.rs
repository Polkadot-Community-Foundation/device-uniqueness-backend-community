// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use subxt::ext::codec::Encode as _;

/// Message prefix, matching `RESERVE_MSG_PREFIX` in the gateway pallet.
pub const RESERVE_MSG_PREFIX: &[u8] = b"pop:dotns-gateway:reserve";

/// `DotnsGateway::reserve_name`'s argument names, in order, on the runtime this
/// writer targets.
///
/// [`check_reserve_name_shape`] stops the writer if a future runtime changes
/// this contract.
pub const RESERVE_NAME_FIELDS: [&str; 6] = [
    "candidate",
    "candidate_signature",
    "lite_label",
    "chat_key",
    "reserved_base_label",
    "signed_at",
];

/// The connected Asset Hub's `reserve_name` is not the extrinsic this writer
/// builds.
#[derive(Debug, thiserror::Error)]
#[error(
    "DotnsGateway::reserve_name shape mismatch: this writer builds [{expected}], \
     the connected Asset Hub declares [{found}]. This chain runs a different \
     dotns-gateway; point ASSET_HUB_RPC_URL at one with the signed_at variant."
)]
pub struct ReserveNameShapeError {
    /// Comma-separated argument names this writer encodes.
    expected: String,
    /// Comma-separated argument names the connected runtime declares.
    found: String,
}

/// Returns the bytes of a lite label before the first `.`, or the whole label
/// when it has none.
///
/// Mirrors `BaseLabel::lite_base()` in the gateway pallet. Callers building the
/// reservation message pass this. They never pass the full `base.digits` label.
pub fn lite_base(lite_label: &str) -> &str {
    match lite_label.split_once('.') {
        Some((base, _)) => base,
        None => lite_label,
    }
}

/// Builds the payload a candidate signs to authorise a lite-name reservation.
///
/// SCALE tuple of `(prefix, candidate, attester, username_base, chat_key,
/// reserved_base_label, signed_at)`; accounts are raw 32-byte values, byte
/// strings length-prefixed. `attester` is the extrinsic's signed origin — the
/// proxied primary, and the account `GET /api/v1/attester` returns.
pub fn reservation_message(
    candidate: &[u8; 32],
    attester: &[u8; 32],
    username_base: &[u8],
    chat_key: &[u8],
    reserved_base_label: Option<&[u8]>,
    signed_at: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        RESERVE_MSG_PREFIX.len() + 32 + 32 + username_base.len() + chat_key.len() + 48,
    );
    RESERVE_MSG_PREFIX.encode_to(&mut out);
    out.extend_from_slice(candidate);
    out.extend_from_slice(attester);
    username_base.encode_to(&mut out);
    chat_key.encode_to(&mut out);
    reserved_base_label.encode_to(&mut out);
    signed_at.encode_to(&mut out);
    out
}

/// Verifies a stored `dotns.signature` against the reservation payload.
///
/// Returns `false` for anything the pallet would reject as
/// `InvalidAttestationSignature`. That includes a signature that is not 64
/// bytes.
#[allow(clippy::too_many_arguments)]
pub fn verify_reservation_signature(
    signature: &[u8],
    candidate: &[u8; 32],
    attester: &[u8; 32],
    username_base: &[u8],
    chat_key: &[u8],
    reserved_base_label: Option<&[u8]>,
    signed_at: u64,
) -> bool {
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let message = reservation_message(
        candidate,
        attester,
        username_base,
        chat_key,
        reserved_base_label,
        signed_at,
    );
    subxt_signer::sr25519::verify(
        &subxt_signer::sr25519::Signature(signature),
        message,
        &subxt_signer::sr25519::PublicKey(*candidate),
    )
}

/// Whether a reservation signature has aged out of the pallet's validity
/// window (the negation of `now <= signed_at + MaxValiditySeconds`).
///
/// `max_validity_secs` comes from the chain's constant, never configuration:
/// the backend cannot re-sign, so a wrong value burns or discards extrinsics.
pub fn reservation_expired(signed_at: i64, max_validity_secs: u64, now: i64) -> bool {
    let deadline = signed_at.saturating_add_unsigned(max_validity_secs);
    now > deadline
}

/// Checks the connected Asset Hub's `reserve_name` arguments against
/// [`RESERVE_NAME_FIELDS`].
///
/// Names, in order. A positional-only check would accept a runtime that renamed
/// an argument. A set check would accept one that reordered it.
pub fn check_reserve_name_shape<S: AsRef<str>>(fields: &[S]) -> Result<(), ReserveNameShapeError> {
    let matches = fields.len() == RESERVE_NAME_FIELDS.len()
        && fields
            .iter()
            .zip(RESERVE_NAME_FIELDS)
            .all(|(found, expected)| found.as_ref() == expected);
    if matches {
        return Ok(());
    }
    Err(ReserveNameShapeError {
        expected: RESERVE_NAME_FIELDS.join(", "),
        found: fields
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE: &str = "f68c00ac42085e1cc2624a084793d65f83be81149170f6a1460f2cdd3916fc4e";
    const MESSAGE_NONE: &str = "64706f703a646f746e732d676174657761793a72657365727665f68c00ac42085e1cc2624a084793d65f83be81149170f6a1460f2cdd3916fc4e0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028676f6c64656e6e616d650501000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275787b7e8184878a8d909396999c9fa2a5a8abaeb1b4b7babdc00080e14e6800000000";
    const SIGNATURE_NONE: &str = "f6ea04a6f4dcd733f0a092a9a56a95702a351542fc9ea98e8d0025a7e1babf1923c3cbe21d56065daf3321c4955fb01b4e507f4142375168ddf2d6792332e780";
    const MESSAGE_RESERVED: &str = "64706f703a646f746e732d676174657761793a72657365727665f68c00ac42085e1cc2624a084793d65f83be81149170f6a1460f2cdd3916fc4e0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2028676f6c64656e6e616d650501000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275787b7e8184878a8d909396999c9fa2a5a8abaeb1b4b7babdc0013072657365727665646e616d6580e14e6800000000";
    const SIGNATURE_RESERVED: &str = "0099ade38865ebd0a1a2e866f6047dbdbf3d93476213b8ef1f7c30bf0593787b9d46ac9f944ba0a6bcb76db418d1386d89cee2197a13e6f01ab60545896e2287";

    const SIGNED_AT: u64 = 1_750_000_000;
    const RESERVED: &[u8] = b"reservedname";

    fn candidate() -> [u8; 32] {
        decode32(CANDIDATE)
    }

    fn attester() -> [u8; 32] {
        std::array::from_fn(|i| i as u8 + 1)
    }

    fn chat_key() -> Vec<u8> {
        (0..65u32).map(|i| ((i * 3) % 251) as u8).collect()
    }

    fn decode32(value: &str) -> [u8; 32] {
        hex::decode(value)
            .expect("golden vector is hex")
            .try_into()
            .expect("golden vector is 32 bytes")
    }

    fn message(reserved: Option<&[u8]>) -> Vec<u8> {
        reservation_message(
            &candidate(),
            &attester(),
            b"goldenname",
            &chat_key(),
            reserved,
            SIGNED_AT,
        )
    }

    #[test]
    fn reservation_message_matches_the_golden_vectors() {
        assert_eq!(hex::encode(message(None)), MESSAGE_NONE);
        assert_eq!(hex::encode(message(Some(RESERVED))), MESSAGE_RESERVED);
    }

    #[test]
    fn golden_signatures_verify() {
        for (reserved, signature) in [(None, SIGNATURE_NONE), (Some(RESERVED), SIGNATURE_RESERVED)]
        {
            let signature = hex::decode(signature).expect("golden signature is hex");
            assert!(verify_reservation_signature(
                &signature,
                &candidate(),
                &attester(),
                b"goldenname",
                &chat_key(),
                reserved,
                SIGNED_AT,
            ));
        }
    }

    #[test]
    fn every_committed_field_is_load_bearing() {
        let signature = hex::decode(SIGNATURE_NONE).expect("golden signature is hex");
        let good = candidate();
        let attester = attester();
        let chat_key = chat_key();

        let verify = |attester: &[u8; 32], base: &[u8], reserved, signed_at| {
            verify_reservation_signature(
                &signature, &good, attester, base, &chat_key, reserved, signed_at,
            )
        };

        assert!(verify(&attester, b"goldenname", None, SIGNED_AT), "control");
        assert!(!verify(&[9u8; 32], b"goldenname", None, SIGNED_AT));
        assert!(!verify(&attester, b"goldenname.42", None, SIGNED_AT));
        assert!(!verify(&attester, b"goldenname", Some(RESERVED), SIGNED_AT));
        assert!(!verify(&attester, b"goldenname", None, SIGNED_AT + 1));
        assert!(!verify_reservation_signature(
            &[1u8; 63],
            &good,
            &attester,
            b"goldenname",
            &chat_key,
            None,
            SIGNED_AT,
        ));
    }

    #[test]
    fn lite_base_stops_at_the_first_dot() {
        assert_eq!(lite_base("alice.42"), "alice");
        assert_eq!(lite_base("alice"), "alice");
        assert_eq!(lite_base("alice.team.07"), "alice");
    }

    #[test]
    fn expiry_matches_the_pallets_inclusive_bound() {
        const WINDOW: u64 = 259_200;
        assert!(!reservation_expired(1_000, WINDOW, 1_000));
        assert!(!reservation_expired(1_000, WINDOW, 1_000 + WINDOW as i64));
        assert!(reservation_expired(1_000, WINDOW, 1_001 + WINDOW as i64));
        assert!(!reservation_expired(i64::MAX, WINDOW, 1_000));
    }

    #[test]
    fn shape_guard_accepts_current_shape_and_rejects_historical_variant() {
        assert!(check_reserve_name_shape(&RESERVE_NAME_FIELDS).is_ok());

        let historical = [
            "candidate",
            "candidate_signature",
            "ring_vrf_key",
            "proof_of_ownership",
            "lite_label",
            "chat_key",
            "reserved_base_label",
        ];
        let error = check_reserve_name_shape(&historical).expect_err("old shape must be rejected");
        let rendered = error.to_string();
        assert!(rendered.contains("proof_of_ownership"), "{rendered}");
        assert!(rendered.contains("signed_at"), "{rendered}");

        let renamed = [
            "candidate",
            "candidate_signature",
            "lite_label",
            "chat_key",
            "reserved_label",
            "signed_at",
        ];
        assert!(check_reserve_name_shape(&renamed).is_err());

        let reordered = [
            "candidate",
            "candidate_signature",
            "lite_label",
            "chat_key",
            "signed_at",
            "reserved_base_label",
        ];
        assert!(check_reserve_name_shape(&reordered).is_err());
    }
}
