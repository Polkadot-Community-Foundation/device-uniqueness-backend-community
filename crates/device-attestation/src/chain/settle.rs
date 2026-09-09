// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! dotNS pending-claim settlement.
//!
//! A gateway-minted lite name is registered from a Root origin, which
//! pallet-revive does not let deploy contracts, so the `DotnsPopController`
//! parks the label as a *pending claim* until a signed origin calls
//! `settlePendingClaims(user, limit)` and deploys the user's `LabelStore`.
//! Nothing in the client apps does that, and an unsettled claim expires out of
//! the store after the controller's reservation window. This lane settles as a
//! third party from the writer's own Asset Hub signer.
//!
//! It is chain-driven rather than outbox-driven on purpose: the gateway's
//! `AccountNames` map is the authoritative list of every account the gateway
//! ever minted for, including names registered by a previous backend, so a
//! pass over it covers everything. A per-process cache keyed on the record's
//! raw value keeps settled accounts from being re-queried; a later full-name
//! claim changes the value and re-arms the check.

use std::collections::HashMap;

use anyhow::Context as _;
use sha3::{Digest as _, Keccak256};
use subxt::dynamic::{At as _, Value};
use subxt::ext::scale_value::ValueDef;
use subxt::tx::DynamicPayload;

/// `keccak256("pendingClaimCountOf(address)")[..4]`.
pub const PENDING_CLAIM_COUNT_OF: [u8; 4] = [0x14, 0x54, 0x68, 0xe7];
/// `keccak256("settlePendingClaims(address,uint256)")[..4]`.
pub const SETTLE_PENDING_CLAIMS: [u8; 4] = [0xb9, 0xeb, 0x52, 0xd4];

/// Mirrors `pallet_revive::AccountId32Mapper::to_address`: an Eth-derived
/// account (trailing 12 bytes all `0xEE`) truncates, everything else hashes.
pub fn to_h160(account: &[u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    if account[20..].iter().all(|b| *b == 0xEE) {
        out.copy_from_slice(&account[..20]);
    } else {
        let hash = Keccak256::digest(account);
        out.copy_from_slice(&hash[12..]);
    }
    out
}

/// Solidity function selector: the first four bytes of `keccak256(signature)`.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

fn abi_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn abi_u256(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Calldata for `pendingClaimCountOf(address)`.
pub fn pending_claim_count_calldata(user: &[u8; 20]) -> Vec<u8> {
    let mut data = PENDING_CLAIM_COUNT_OF.to_vec();
    data.extend_from_slice(&abi_address(user));
    data
}

/// Calldata for `settlePendingClaims(address,uint256)`.
pub fn settle_calldata(user: &[u8; 20], limit: u64) -> Vec<u8> {
    let mut data = SETTLE_PENDING_CLAIMS.to_vec();
    data.extend_from_slice(&abi_address(user));
    data.extend_from_slice(&abi_u256(limit));
    data
}

/// Decodes a single ABI `uint256` return word into a `u64` (saturating on the
/// high bytes, which a claim count never reaches).
pub fn decode_uint(data: &[u8]) -> anyhow::Result<u64> {
    anyhow::ensure!(data.len() >= 32, "ABI word too short: {} bytes", data.len());
    anyhow::ensure!(
        data[..24].iter().all(|b| *b == 0),
        "ABI uint does not fit a u64"
    );
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&data[24..32]);
    Ok(u64::from_be_bytes(tail))
}

/// Weight the dry run says the call needs, plus the storage deposit it charges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallCost {
    pub ref_time: u128,
    pub proof_size: u128,
    pub storage_deposit: u128,
}

/// A decoded `ReviveApi_call` dry run.
#[derive(Debug, Clone)]
pub struct DryRun {
    pub cost: CallCost,
    /// The call's return data when it succeeded; the dispatch error text otherwise.
    pub result: Result<Vec<u8>, String>,
}

/// Pulls the fields this lane needs out of a dynamically decoded
/// `pallet_revive::ContractResult`.
///
/// Runtimes built from polkadot-sdk stable2509 onwards name the weight field
/// `weight_required`; older ones call it `gas_required`. Both shapes are accepted.
pub fn decode_dry_run(value: &Value) -> anyhow::Result<DryRun> {
    let gas = value
        .at("weight_required")
        .or_else(|| value.at("gas_required"))
        .context("ContractResult has neither weight_required nor gas_required")?;
    let ref_time = gas
        .at("ref_time")
        .and_then(|v| v.as_u128())
        .context("weight_required.ref_time")?;
    let proof_size = gas
        .at("proof_size")
        .and_then(|v| v.as_u128())
        .context("weight_required.proof_size")?;
    let deposit = value
        .at("storage_deposit")
        .context("ContractResult has no storage_deposit")?;
    let storage_deposit = match &deposit.value {
        ValueDef::Variant(variant) if variant.name == "Charge" => variant
            .values
            .values()
            .next()
            .and_then(|v| v.as_u128())
            .context("storage_deposit.Charge")?,
        ValueDef::Variant(_) => 0,
        _ => anyhow::bail!("storage_deposit is not a variant"),
    };
    let result = match value.at("result").map(|v| &v.value) {
        Some(ValueDef::Variant(variant)) => variant,
        _ => anyhow::bail!("ContractResult has no result variant"),
    };
    let outcome = if result.name == "Ok" {
        let ok = result.values.values().next().context("empty Ok")?;
        let flags = ok.at("flags").and_then(|v| v.as_u128()).unwrap_or(0);
        let data = ok.at("data").map(composite_bytes).unwrap_or_default();
        if flags & 1 == 1 {
            Err(format!("contract reverted: 0x{}", hex::encode(&data)))
        } else {
            Ok(data)
        }
    } else {
        Err(format!("{:?}", result.values))
    };
    Ok(DryRun {
        cost: CallCost {
            ref_time,
            proof_size,
            storage_deposit,
        },
        result: outcome,
    })
}

/// Flattens a byte-like value: a `Vec<u8>` decodes as a composite of byte
/// primitives, and newtypes such as `H160([u8; 20])` wrap that in one more
/// composite, so nested composites are walked recursively.
pub fn composite_bytes(value: &Value) -> Vec<u8> {
    fn walk(value: &Value, out: &mut Vec<u8>) {
        match &value.value {
            ValueDef::Composite(composite) => {
                for inner in composite.values() {
                    walk(inner, out);
                }
            }
            ValueDef::Primitive(_) => {
                if let Some(b) = value.as_u128() {
                    out.push(b as u8);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// The `Revive.call` extrinsic that settles `user`'s pending claims, sized from
/// a dry run with headroom (weight +25 %, deposit +10 %) so a block's drift in
/// gas accounting does not fail the real submission.
pub fn settle_tx(
    controller: &[u8; 20],
    user: &[u8; 20],
    limit: u64,
    cost: CallCost,
) -> DynamicPayload<Vec<Value>> {
    let gas_limit = Value::named_composite([
        ("ref_time", Value::u128(cost.ref_time + cost.ref_time / 4)),
        (
            "proof_size",
            Value::u128(cost.proof_size + cost.proof_size / 4),
        ),
    ]);
    subxt::dynamic::tx(
        "Revive",
        "call",
        vec![
            Value::from_bytes(controller),
            Value::u128(0),
            gas_limit,
            Value::u128(cost.storage_deposit + cost.storage_deposit / 10),
            Value::from_bytes(settle_calldata(user, limit)),
        ],
    )
}

/// `Revive.map_account()`: a substrate account must map itself once before it
/// can call a contract.
pub fn map_account_tx() -> DynamicPayload<Vec<Value>> {
    subxt::dynamic::tx("Revive", "map_account", Vec::<Value>::new())
}

/// Per-process memory of which `AccountNames` records were already found
/// settled, keyed by the raw record so a changed record is re-checked.
#[derive(Default)]
pub struct SettledCache {
    seen: HashMap<[u8; 32], Vec<u8>>,
}

impl SettledCache {
    pub fn is_settled(&self, account: &[u8; 32], record: &[u8]) -> bool {
        self.seen.get(account).is_some_and(|v| v == record)
    }

    pub fn mark(&mut self, account: [u8; 32], record: Vec<u8>) {
        self.seen.insert(account, record);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_the_solidity_signatures() {
        assert_eq!(
            selector("pendingClaimCountOf(address)"),
            PENDING_CLAIM_COUNT_OF
        );
        assert_eq!(
            selector("settlePendingClaims(address,uint256)"),
            SETTLE_PENDING_CLAIMS
        );
    }

    #[test]
    fn substrate_accounts_map_by_keccak_and_eth_accounts_truncate() {
        // 5DJiwMesedo… (a devnet registrant): keccak(account)[12..] = 0x04e05194…
        let account =
            hex::decode("36ed4eb9287c0605496291b9176f4506911df161b4e4825e211ee75e43973a7f")
                .unwrap();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&account);
        assert_eq!(
            hex::encode(to_h160(&bytes)),
            "04e05194384695d13fbb0b5674340c78ba7ff2cd"
        );

        let mut eth = [0xEE; 32];
        eth[..20].copy_from_slice(&[0xAB; 20]);
        assert_eq!(to_h160(&eth), [0xAB; 20]);
    }

    #[test]
    fn settle_calldata_is_selector_address_limit() {
        let data = settle_calldata(&[0x11; 20], 10);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(&data[..4], &SETTLE_PENDING_CLAIMS);
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &[0x11; 20]);
        assert_eq!(data[67], 10);
    }

    #[test]
    fn uint_words_decode_and_reject_overflow() {
        let mut word = [0u8; 32];
        word[31] = 7;
        assert_eq!(decode_uint(&word).unwrap(), 7);
        word[0] = 1;
        assert!(decode_uint(&word).is_err());
    }

    #[test]
    fn settle_tx_targets_revive_call_with_headroom() {
        let cost = CallCost {
            ref_time: 400,
            proof_size: 80,
            storage_deposit: 1_000,
        };
        let payload = settle_tx(&[0xC0; 20], &[0x11; 20], 10, cost);
        assert_eq!(payload.pallet_name(), "Revive");
        assert_eq!(payload.call_name(), "call");
        let args = payload.call_data();
        assert_eq!(args.len(), 5);
        assert_eq!(
            args[2],
            Value::named_composite([
                ("ref_time", Value::u128(500)),
                ("proof_size", Value::u128(100)),
            ])
        );
        assert_eq!(args[3], Value::u128(1_100));
    }

    #[test]
    fn composite_bytes_flattens_newtype_wrappers() {
        let flat = Value::from_bytes([1u8, 2, 3]);
        assert_eq!(composite_bytes(&flat), vec![1, 2, 3]);
        // H160([u8; 20]) decodes as a composite around the byte composite.
        let wrapped = Value::unnamed_composite([Value::from_bytes([9u8; 20])]);
        assert_eq!(composite_bytes(&wrapped), vec![9u8; 20]);
    }

    fn contract_result(weight_field: &str) -> Value {
        let weight = Value::named_composite([
            ("ref_time", Value::u128(400)),
            ("proof_size", Value::u128(80)),
        ]);
        let ok = Value::named_composite([
            ("flags", Value::u128(0)),
            ("data", Value::from_bytes([0u8; 32])),
        ]);
        Value::named_composite([
            ("weight_consumed", weight.clone()),
            (weight_field, weight),
            (
                "storage_deposit",
                Value::named_variant("Charge", [("0", Value::u128(1_000))]),
            ),
            (
                "max_storage_deposit",
                Value::named_variant("Charge", [("0", Value::u128(1_000))]),
            ),
            ("gas_consumed", Value::u128(7)),
            ("result", Value::named_variant("Ok", [("0", ok)])),
        ])
    }

    #[test]
    fn dry_run_decodes_both_weight_field_names() {
        for field in ["weight_required", "gas_required"] {
            let dry = decode_dry_run(&contract_result(field)).unwrap();
            assert_eq!(dry.cost.ref_time, 400, "{field}");
            assert_eq!(dry.cost.proof_size, 80, "{field}");
            assert_eq!(dry.cost.storage_deposit, 1_000, "{field}");
            assert_eq!(dry.result.unwrap(), vec![0u8; 32]);
        }
    }

    #[test]
    fn cache_forgets_an_account_whose_record_changed() {
        let mut cache = SettledCache::default();
        cache.mark([1; 32], vec![1, 2, 3]);
        assert!(cache.is_settled(&[1; 32], &[1, 2, 3]));
        assert!(!cache.is_settled(&[1; 32], &[9]));
        assert!(!cache.is_settled(&[2; 32], &[1, 2, 3]));
    }
}
