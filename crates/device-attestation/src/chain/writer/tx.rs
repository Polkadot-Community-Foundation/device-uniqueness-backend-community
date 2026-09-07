// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use subxt::{
    dynamic::{self, Value},
    tx::DynamicPayload,
};

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

fn attest_args(r: &Reservation, candidate: &[u8; 32]) -> Vec<Value> {
    let reserved_username = match &r.reserved_username {
        Some(name) => Value::unnamed_variant("Some", [Value::from_bytes(name.as_bytes())]),
        None => Value::unnamed_variant("None", []),
    };
    let consumer = Value::named_composite(vec![
        (
            "signature".to_string(),
            sr25519_signature(&r.consumer_registration_signature),
        ),
        ("account".to_string(), Value::from_bytes(candidate)),
        (
            "identifier_key".to_string(),
            Value::from_bytes(&r.identifier_key),
        ),
        (
            "username".to_string(),
            Value::from_bytes(r.full_username.as_bytes()),
        ),
        ("reserved_username".to_string(), reserved_username),
    ]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::writer::fixtures::*;
    use crate::dotns;

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

        assert_eq!(payload.pallet_name(), "DotnsGateway");
        assert_eq!(payload.call_name(), "reserve_name");
        assert_eq!(payload.call_data().len(), dotns::RESERVE_NAME_FIELDS.len());
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
}
