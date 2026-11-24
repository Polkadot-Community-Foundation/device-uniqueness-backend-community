// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use subxt::{
    dynamic::{self, Value},
    tx::DynamicPayload,
    utils::H160,
};

use crate::chain::attest::PayloadVersion;
use crate::chain::outbox::Reservation;

pub(super) fn build_registration_tx(
    r: &Reservation,
    candidate: &[u8; 32],
    proxy_for: Option<&[u8; 32]>,
) -> DynamicPayload<Vec<Value>> {
    match proxy_for {
        Some(real) => {
            let args = vec![
                // real: MultiAddress::Id(attester authority)
                Value::unnamed_variant("Id", [Value::from_bytes(real)]),
                // force_proxy_type: Option<ProxyType> = None (any granted type)
                Value::unnamed_variant("None", []),
                attest_call(r, candidate),
            ];
            dynamic::tx("Proxy", "proxy", args)
        }
        None => dynamic::tx("PeopleLite", "attest", attest_args(r, candidate)),
    }
}

pub(super) fn build_registration_batch_tx(
    rows: &[(&Reservation, [u8; 32])],
    proxy_for: Option<&[u8; 32]>,
) -> DynamicPayload<Vec<Value>> {
    let calls = Value::unnamed_composite(
        rows.iter()
            .map(|(r, candidate)| attest_call(r, candidate))
            .collect::<Vec<_>>(),
    );
    match proxy_for {
        Some(real) => dynamic::tx(
            "Proxy",
            "proxy",
            vec![
                Value::unnamed_variant("Id", [Value::from_bytes(real)]),
                Value::unnamed_variant("None", []),
                force_batch_call(calls),
            ],
        ),
        None => dynamic::tx("Utility", "force_batch", vec![calls]),
    }
}

fn force_batch_call(calls: Value) -> Value {
    Value::unnamed_variant("Utility", [Value::unnamed_variant("force_batch", [calls])])
}

pub(super) fn build_reserve_name_tx(
    r: &Reservation,
    candidate: &[u8; 32],
    proxy_for: Option<&[u8; 32]>,
) -> DynamicPayload<Vec<Value>> {
    match proxy_for {
        Some(real) => {
            let args = vec![
                Value::unnamed_variant("Id", [Value::from_bytes(real)]),
                Value::unnamed_variant("None", []),
                reserve_name_call(r, candidate),
            ];
            dynamic::tx("Proxy", "proxy", args)
        }
        None => dynamic::tx(
            "DotnsGateway",
            "reserve_name",
            reserve_name_args(r, candidate),
        ),
    }
}
pub(super) fn build_reserve_name_batch_tx(
    rows: &[(&Reservation, [u8; 32])],
    proxy_for: Option<&[u8; 32]>,
) -> DynamicPayload<Vec<Value>> {
    let calls = Value::unnamed_composite(
        rows.iter()
            .map(|(r, candidate)| reserve_name_call(r, candidate))
            .collect::<Vec<_>>(),
    );
    match proxy_for {
        Some(real) => dynamic::tx(
            "Proxy",
            "proxy",
            vec![
                Value::unnamed_variant("Id", [Value::from_bytes(real)]),
                Value::unnamed_variant("None", []),
                force_batch_call(calls),
            ],
        ),
        None => dynamic::tx("Utility", "force_batch", vec![calls]),
    }
}

fn reserve_name_call(r: &Reservation, candidate: &[u8; 32]) -> Value {
    Value::unnamed_variant(
        "DotnsGateway",
        [Value::unnamed_variant(
            "reserve_name",
            reserve_name_args(r, candidate),
        )],
    )
}

fn reserve_name_args(r: &Reservation, candidate: &[u8; 32]) -> Vec<Value> {
    let reserved_base_label = match &r.reserved_username {
        Some(name) => Value::unnamed_variant("Some", [Value::from_bytes(name.as_bytes())]),
        None => Value::unnamed_variant("None", []),
    };
    vec![
        Value::from_bytes(candidate),
        sr25519_signature(r.dotns_signature.as_deref().unwrap_or_default()),
        Value::from_bytes(r.full_username.as_bytes()),
        Value::from_bytes(&r.identifier_key),
        reserved_base_label,
        Value::u128(u128::from(
            r.dotns_signed_at.unwrap_or_default().unsigned_abs(),
        )),
    ]
}

fn attest_call(r: &Reservation, candidate: &[u8; 32]) -> Value {
    Value::unnamed_variant(
        "PeopleLite",
        [Value::unnamed_variant("attest", attest_args(r, candidate))],
    )
}

/// `attest`'s arguments in the shape the row's payload version was signed for.
///
/// The People gate passes a row only when its payload version is the one the
/// live runtime's `attest` shape takes (`chain::attest`), so the version
/// decides the shape here. A version the gate would refuse never gets here.
fn attest_args(r: &Reservation, candidate: &[u8; 32]) -> Vec<Value> {
    let mut consumer = vec![
        (
            "signature".to_string(),
            sr25519_signature(&r.consumer_registration_signature),
        ),
        ("account".to_string(), Value::from_bytes(candidate)),
        (
            "identifier_key".to_string(),
            Value::from_bytes(&r.identifier_key),
        ),
    ];
    match PayloadVersion::try_from(r.payload_version) {
        Ok(PayloadVersion::V2) => {}
        // The gate refuses a version it does not know, so only format 1 takes
        // the `Err` arm here; it keeps the shape this builder always had.
        Ok(PayloadVersion::V1) | Err(_) => {
            let reserved_username = match &r.reserved_username {
                Some(name) => Value::unnamed_variant("Some", [Value::from_bytes(name.as_bytes())]),
                None => Value::unnamed_variant("None", []),
            };
            consumer.extend([
                (
                    "username".to_string(),
                    Value::from_bytes(r.full_username.as_bytes()),
                ),
                ("reserved_username".to_string(), reserved_username),
            ]);
        }
    }
    let consumer = Value::named_composite(consumer);
    vec![
        Value::from_bytes(candidate),
        sr25519_signature(&r.candidate_signature),
        Value::from_bytes(&r.ring_vrf_key),
        Value::from_bytes(&r.proof_of_ownership),
        Value::unnamed_variant("Some", [consumer]),
    ]
}

fn sr25519_signature(bytes: &[u8]) -> Value {
    Value::unnamed_variant("Sr25519", [Value::from_bytes(bytes)])
}

/// One `Revive.call` from the signer, with no value transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ContractCall<'a> {
    /// The contract called.
    pub dest: H160,
    /// The `(ref_time, proof_size)` weight limit.
    pub weight_limit: (u64, u64),
    /// The most storage deposit the call may charge, in planck.
    pub storage_deposit_limit: u128,
    /// The ABI calldata.
    pub data: &'a [u8],
}

/// `Utility.force_batch` of `calls`, each a `Revive.call` from the signer
/// itself, never proxied: the signer pays for them.
pub(super) fn build_contract_batch_tx(calls: &[ContractCall<'_>]) -> DynamicPayload<Vec<Value>> {
    let calls = Value::unnamed_composite(calls.iter().map(revive_call).collect::<Vec<_>>());
    dynamic::tx("Utility", "force_batch", vec![calls])
}

/// `Revive.map_account`, which pallet-revive requires of a signed origin before
/// it can call a contract.
pub(super) fn build_map_account_tx() -> DynamicPayload<Vec<Value>> {
    dynamic::tx("Revive", "map_account", Vec::new())
}

fn revive_call(call: &ContractCall<'_>) -> Value {
    let (ref_time, proof_size) = call.weight_limit;
    Value::unnamed_variant(
        "Revive",
        [Value::unnamed_variant(
            "call",
            [
                Value::from_bytes(call.dest.as_bytes()),
                Value::u128(0),
                Value::named_composite([
                    ("ref_time", Value::u128(u128::from(ref_time))),
                    ("proof_size", Value::u128(u128::from(proof_size))),
                ]),
                Value::u128(call.storage_deposit_limit),
                Value::from_bytes(call.data),
            ],
        )],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::attest::AttestShape;
    use crate::chain::writer::fixtures::*;

    #[test]
    fn a_single_row_set_submits_a_bare_attest() {
        let reservation = reservation();
        let candidate = [7; 32];
        let payload = build_registration_tx(&reservation, &candidate, None);

        assert_eq!(payload.pallet_name(), "PeopleLite");
        assert_eq!(payload.call_name(), "attest");
        assert_eq!(payload.call_data(), &attest_args(&reservation, &candidate));
    }

    #[test]
    fn a_multi_row_batch_is_a_force_batch_of_attests_in_claim_order() {
        let (first, second) = (reservation(), other_reservation());
        let (a, b) = ([7; 32], [8; 32]);
        let rows = [(&first, a), (&second, b)];
        let payload = build_registration_batch_tx(&rows, None);

        assert_eq!(payload.pallet_name(), "Utility");
        assert_eq!(payload.call_name(), "force_batch");
        assert_eq!(payload.call_data().len(), 1);
        assert_eq!(
            payload.call_data()[0],
            Value::unnamed_composite([attest_call(&first, &a), attest_call(&second, &b)])
        );
    }

    #[test]
    fn a_proxied_batch_wraps_the_force_batch() {
        let (first, second) = (reservation(), other_reservation());
        let (a, b) = ([7; 32], [8; 32]);
        let rows = [(&first, a), (&second, b)];
        let payload = build_registration_batch_tx(&rows, Some(&[9; 32]));

        assert_eq!(payload.pallet_name(), "Proxy");
        assert_eq!(payload.call_name(), "proxy");
        assert_eq!(
            payload.call_data()[2],
            force_batch_call(Value::unnamed_composite([
                attest_call(&first, &a),
                attest_call(&second, &b)
            ]))
        );
    }

    #[test]
    fn proxied_registration_wraps_attest_directly() {
        let reservation = reservation();
        let candidate = [7; 32];
        let proxy_for = [8; 32];
        let payload = build_registration_tx(&reservation, &candidate, Some(&proxy_for));

        assert_eq!(payload.pallet_name(), "Proxy");
        assert_eq!(payload.call_name(), "proxy");
        assert_eq!(
            payload.call_data()[2],
            attest_call(&reservation, &candidate)
        );
    }

    #[test]
    fn direct_mode_submits_attest_unwrapped() {
        let reservation = reservation();
        let candidate = [7; 32];
        let payload = build_registration_tx(&reservation, &candidate, None);

        assert_eq!(payload.pallet_name(), "PeopleLite");
        assert_eq!(payload.call_name(), "attest");
    }

    #[test]
    fn direct_reservation_targets_the_gateway_pallet() {
        let (r, candidate, _) = signed_reservation();
        let payload = build_reserve_name_tx(&r, &candidate, None);

        let metadata = chain_types::asset_hub::metadata_arc();
        let metadata_pallet = metadata.pallet_by_name("DotnsGateway").unwrap();
        let metadata_call = metadata_pallet
            .call_variant_by_name("reserve_name")
            .unwrap();

        assert_eq!(payload.pallet_name(), "DotnsGateway");
        assert_eq!(payload.call_name(), "reserve_name");
        assert_eq!(payload.call_data().len(), metadata_call.fields.len());
        assert_eq!(payload.call_data(), &reserve_name_args(&r, &candidate));
    }

    #[test]
    fn a_multi_row_dotns_batch_is_a_force_batch_of_reserve_names() {
        let (first, candidate, _) = signed_reservation();
        let mut second = first.clone();
        second.id = 2;
        second.full_username = "second.07".to_string();
        let rows = [(&first, candidate), (&second, candidate)];

        let direct = build_reserve_name_batch_tx(&rows, None);
        assert_eq!(direct.pallet_name(), "Utility");
        assert_eq!(direct.call_name(), "force_batch");
        assert_eq!(
            direct.call_data()[0],
            Value::unnamed_composite([
                reserve_name_call(&first, &candidate),
                reserve_name_call(&second, &candidate)
            ])
        );

        let proxied = build_reserve_name_batch_tx(&rows, Some(&[9; 32]));
        assert_eq!(proxied.pallet_name(), "Proxy");
        assert_eq!(proxied.call_name(), "proxy");
        assert_eq!(
            proxied.call_data()[2],
            force_batch_call(direct.call_data()[0].clone())
        );
    }

    #[test]
    fn proxied_reservation_wraps_reserve_name_directly() {
        let (r, candidate, _) = signed_reservation();
        let proxy_for = [8; 32];
        let payload = build_reserve_name_tx(&r, &candidate, Some(&proxy_for));

        assert_eq!(payload.pallet_name(), "Proxy");
        assert_eq!(payload.call_name(), "proxy");
        assert_eq!(
            payload.call_data()[2],
            Value::unnamed_variant(
                "DotnsGateway",
                [Value::unnamed_variant(
                    "reserve_name",
                    reserve_name_args(&r, &candidate)
                )]
            )
        );
    }

    /// The field names of the consumer registration `attest_args` builds.
    fn consumer_fields(r: &Reservation) -> Vec<String> {
        use subxt::ext::scale_value::{Composite, ValueDef, Variant};

        let args: Vec<Value> = attest_args(r, &[7; 32]);
        let ValueDef::Variant(Variant { name, values }) = &args[4].value else {
            panic!("consumer registration is not an Option");
        };
        assert_eq!(name, "Some", "attest always enrols the consumer");
        let Composite::Unnamed(inner) = values else {
            panic!("Some carries no value");
        };
        let ValueDef::Composite(Composite::Named(fields)) = &inner[0].value else {
            panic!("consumer registration is not a named struct");
        };
        fields.iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn a_version_one_row_sends_the_username() {
        let reservation = reservation();
        assert_eq!(
            reservation.payload_version, 1,
            "the fixture is a format-1 row"
        );
        assert_eq!(
            consumer_fields(&reservation),
            [
                "signature",
                "account",
                "identifier_key",
                "username",
                "reserved_username"
            ],
            "format 1 builds the consumer struct that carries the username and reserved name"
        );
    }

    #[test]
    fn a_version_two_row_sends_no_username() {
        let mut reservation = other_reservation();
        reservation.payload_version = 2;
        // The reserved name stays on the row for the dotNS lane, but `attest`
        // no longer takes it.
        assert!(
            reservation.reserved_username.is_some(),
            "the fixture must carry a reserved name for this test to mean anything"
        );
        assert_eq!(
            consumer_fields(&reservation),
            ["signature", "account", "identifier_key"],
            "format 2 builds the consumer struct without the username or reserved name"
        );
    }

    #[test]
    fn a_version_one_row_matches_the_vendored_call() {
        let metadata = chain_types::metadata_arc();
        let call = metadata
            .pallet_by_name("PeopleLite")
            .expect("vendored runtime has PeopleLite")
            .call_variant_by_name("attest")
            .expect("vendored PeopleLite has attest");
        assert_eq!(
            attest_args(&reservation(), &[7; 32]).len(),
            call.fields.len(),
            "attest_args must build every argument the vendored call declares"
        );
        assert_eq!(
            AttestShape::try_from(&*metadata).expect("vendored attest has a known shape"),
            AttestShape::WithUsername,
            "the vendored runtime takes format 1, which the fixture row carries"
        );
    }

    #[test]
    fn a_contract_batch_is_a_force_batch_of_revive_calls() {
        let data = [1, 2, 3];
        let call = ContractCall {
            dest: H160::repeat_byte(7),
            weight_limit: (10, 20),
            storage_deposit_limit: 30,
            data: &data,
        };

        let payload = build_contract_batch_tx(&[call, call]);

        assert_eq!(payload.pallet_name(), "Utility", "never proxied");
        assert_eq!(
            payload.call_name(),
            "force_batch",
            "one item failing spares the rest"
        );
        assert_eq!(
            payload.call_data(),
            &vec![Value::unnamed_composite([
                revive_call(&call),
                revive_call(&call)
            ])],
            "one Revive.call per settlement, in order"
        );
    }
}
