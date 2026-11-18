// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Reads from the dotNS contracts on Asset Hub, made as `ReviveApi_call` dry
//! runs.
//!
//! The gateway forwards a claim's reservation leg to `DotnsPopController`,
//! which reverts, and takes the device name with it, when the bare
//! personhood name already exists on `DotnsRegistrar`, holds a live grant on
//! the name whitelist, or its reservation queue is full. These reads make
//! the same checks before a claim is accepted.
//!
//! A name minted from the gateway's Root origin cannot deploy its owner's
//! `LabelStore`, so the controller keeps it as a pending claim until a signed
//! origin calls `settlePendingClaims`. The chain writer does that; the reads
//! and dry runs it needs are here too.

use anyhow::{bail, ensure, Context as _};
use chain_types::AssetHubConfig;
use sp_crypto_hashing::keccak_256;
use subxt::client::{ClientAtBlock, OnlineClientAtBlockImpl};
use subxt::dynamic::{At as _, Value};
use subxt::ext::scale_value::ValueDef;
use subxt::utils::{AccountId32, H160};

use crate::chain::people::ReservationState;

/// A handle on Asset Hub at one block.
pub(crate) type AssetHubAt = ClientAtBlock<AssetHubConfig, OnlineClientAtBlockImpl<AssetHubConfig>>;

const GATEWAY_PALLET: &str = "DotnsGateway";

/// The `ReturnFlags` bit pallet-revive sets when the contract reverted.
const REVERT_FLAG: u128 = 1;

/// The key `DotnsProtocolRegistry` files the registrar under,
/// `bytes32("registrar")`.
const REGISTRAR_KEY: &[u8] = b"registrar";

/// The key `DotnsProtocolRegistry` files the name whitelist under,
/// `bytes32("nameWhitelist")`. Unset (the zero address) on a network with no
/// whitelist configured.
const NAME_WHITELIST_KEY: &[u8] = b"nameWhitelist";

/// One ABI word.
type Word = [u8; 32];

/// The dotNS contracts the personhood-name check reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Contracts {
    /// `DotnsPopController`, which keeps the reservation queues.
    controller: H160,
    /// `DotnsRegistrar`, which holds every registered second-level name.
    registrar: H160,
    /// `DotnsProtocolRegistry`, read on every check for the name whitelist,
    /// as the controller reads it, so a whitelist configured later counts
    /// without a restart.
    registry: H160,
    /// The namehash of the TLD personhood names sit under.
    tld_node: Word,
    /// `DotnsPopController.MAX_RESERVATION_QUEUE`.
    queue_capacity: u32,
}

impl Contracts {
    /// `DotnsPopController`'s address.
    #[must_use]
    pub(crate) fn controller(&self) -> H160 {
        self.controller
    }

    /// Resolves the contracts from `DotnsGateway::DispatcherAddress`.
    ///
    /// That address is a `RootGatewayDispatcher` forwarding to
    /// `DotnsPopController` (read with `TARGET()`), or the controller itself on
    /// deployments that dropped the dispatcher. The controller's
    /// `protocolRegistry()` then names the registrar and the TLD node.
    pub(crate) async fn resolve(at: &AssetHubAt) -> anyhow::Result<Self> {
        let address = subxt::dynamic::storage::<(), H160>(GATEWAY_PALLET, "DispatcherAddress");
        let dispatcher: H160 = at
            .storage()
            .try_fetch(address, ())
            .await?
            .context("DotnsGateway::DispatcherAddress is not set")?
            .decode()?;

        let controller = match call(at, dispatcher, calldata("TARGET()", &[])).await? {
            Outcome::Returned(data) => address_of(word(&data, 0)?)?,
            Outcome::Reverted(_) => dispatcher,
        };
        let registry = call(at, controller, calldata("protocolRegistry()", &[]))
            .await?
            .returned("DotnsPopController.protocolRegistry()")?;
        let registry = address_of(word(&registry, 0)?)?;

        let (registrar, tld_node, queue_capacity) = tokio::try_join!(
            call(
                at,
                registry,
                calldata("get(bytes32)", &[bytes32_of(REGISTRAR_KEY)])
            ),
            call(at, registry, calldata("tldNode()", &[])),
            call(at, controller, calldata("MAX_RESERVATION_QUEUE()", &[])),
        )?;
        let registrar = registrar.returned("DotnsProtocolRegistry.get(\"registrar\")")?;
        let tld_node = tld_node.returned("DotnsProtocolRegistry.tldNode()")?;
        let queue_capacity =
            queue_capacity.returned("DotnsPopController.MAX_RESERVATION_QUEUE()")?;

        Ok(Self {
            controller,
            registry,
            registrar: address_of(word(&registrar, 0)?)?,
            tld_node: word(&tld_node, 0)?,
            queue_capacity: u32::try_from(uint_of(word(&queue_capacity, 0)?)?)
                .context("MAX_RESERVATION_QUEUE does not fit a u32")?,
        })
    }

    /// The reservation state of the bare personhood name `name`, as
    /// `DotnsPopController` checks it before queueing a reservation.
    ///
    /// The name is unavailable when it exists on the registrar or holds a
    /// live grant on the name whitelist. The queue length counts every slot
    /// in the live window, expired ones included. The controller clears a few
    /// expired slots before it checks, so a queue read as full can still take
    /// one more claim on chain.
    pub(crate) async fn reservation(
        &self,
        at: &AssetHubAt,
        name: &str,
    ) -> anyhow::Result<ReservationState> {
        let labelhash = keccak_256(name.as_bytes());
        let node = node_of(self.tld_node, labelhash);
        let (exists, meta, granted) = tokio::try_join!(
            call(at, self.registrar, calldata("exists(uint256)", &[node])),
            call(
                at,
                self.controller,
                calldata("reservationMeta(bytes32)", &[labelhash])
            ),
            self.granted(at, node),
        )?;
        let exists = exists.returned("DotnsRegistrar.exists")?;
        let meta = meta.returned("DotnsPopController.reservationMeta")?;

        let head = uint_of(word(&meta, 0)?)?;
        let tail = uint_of(word(&meta, 1)?)?;
        Ok(ReservationState {
            personhood_name_unavailable: bool_of(word(&exists, 0)?)? || granted,
            queue_len: u32::try_from(tail.saturating_sub(head)).unwrap_or(u32::MAX),
            queue_capacity: self.queue_capacity,
        })
    }

    /// Whether the name at `node` holds a live grant on the name whitelist,
    /// read as `WhitelistUtils.granteeOf` reads it for the controller.
    ///
    /// No whitelist configured means no grants. A whitelist that reverts on
    /// `granteeOfNode` predates it (dotNS v1.1.0), and so does the controller
    /// that would consult it, so that also reads as no grant.
    async fn granted(&self, at: &AssetHubAt, node: Word) -> anyhow::Result<bool> {
        let whitelist = call(
            at,
            self.registry,
            calldata("get(bytes32)", &[bytes32_of(NAME_WHITELIST_KEY)]),
        )
        .await?
        .returned("DotnsProtocolRegistry.get(\"nameWhitelist\")")?;
        let Some(whitelist) = configured(address_of(word(&whitelist, 0)?)?) else {
            return Ok(false);
        };
        match call(at, whitelist, calldata("granteeOfNode(bytes32)", &[node])).await? {
            Outcome::Returned(grantee) => Ok(configured(address_of(word(&grantee, 0)?)?).is_some()),
            Outcome::Reverted(_) => Ok(false),
        }
    }

    /// How many accounts hold at least one pending claim.
    pub(crate) async fn pending_claim_users(&self, at: &AssetHubAt) -> anyhow::Result<u64> {
        let count = call(
            at,
            self.controller,
            calldata("pendingClaimUserCount()", &[]),
        )
        .await?
        .returned("DotnsPopController.pendingClaimUserCount()")?;
        uint_of(word(&count, 0)?)
    }

    /// One page of the accounts holding a pending claim, from `offset`. The
    /// controller keeps no order across settlements.
    pub(crate) async fn pending_claim_page(
        &self,
        at: &AssetHubAt,
        offset: u64,
        limit: u64,
    ) -> anyhow::Result<Vec<H160>> {
        let page = call(
            at,
            self.controller,
            calldata(
                "pendingClaimUsers(uint256,uint256)",
                &[uint_word(offset), uint_word(limit)],
            ),
        )
        .await?
        .returned("DotnsPopController.pendingClaimUsers")?;
        addresses_of(&page)
    }

    /// Dry-runs `settlePendingClaims(user, limit)` from `origin`, and returns
    /// what submitting it needs, or `None` when it would revert.
    pub(crate) async fn dry_run_settlement(
        &self,
        at: &AssetHubAt,
        origin: AccountId32,
        user: H160,
        limit: u64,
    ) -> anyhow::Result<Option<Settlement>> {
        let data = settlement_calldata(user, limit);
        let dry_run = call_from(at, origin, self.controller, data.clone()).await?;
        match dry_run.outcome {
            Outcome::Returned(_) => Ok(Some(Settlement {
                user,
                data,
                weight: dry_run.weight_required,
                deposit: dry_run.storage_deposit,
            })),
            Outcome::Reverted(revert) => {
                tracing::debug!(
                    user = ?user,
                    revert = %hex::encode(revert),
                    "settlePendingClaims dry run reverted; skipping the account"
                );
                Ok(None)
            }
        }
    }
}

/// `address`, unless it is the zero address Solidity uses for "none".
fn configured(address: H160) -> Option<H160> {
    (address != H160::zero()).then_some(address)
}

/// A settlement the dry run says will go through, and what it costs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settlement {
    /// The account whose pending claims are settled.
    pub user: H160,
    /// The `settlePendingClaims` calldata.
    pub data: Vec<u8>,
    /// The `(ref_time, proof_size)` weight the dry run required.
    pub weight: (u64, u64),
    /// The most storage deposit the dry run charged at any point, in planck.
    pub deposit: u128,
}

/// The `settlePendingClaims(user, limit)` calldata.
#[must_use]
fn settlement_calldata(user: H160, limit: u64) -> Vec<u8> {
    calldata(
        "settlePendingClaims(address,uint256)",
        &[address_word(user), uint_word(limit)],
    )
}

/// The address pallet-revive gives a native account: the first 20 bytes of an
/// Ethereum-derived account, otherwise the last 20 bytes of its keccak hash.
#[must_use]
pub(crate) fn revive_address(account: &[u8; 32]) -> H160 {
    if account[20..] == [0xee; 12] {
        H160::from_slice(&account[..20])
    } else {
        H160::from_slice(&keccak_256(account)[12..])
    }
}

/// How a contract call ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The call returned this ABI-encoded data.
    Returned(Vec<u8>),
    /// The call reverted with this data.
    Reverted(Vec<u8>),
}

impl Outcome {
    /// The returned data, or an error naming `what` when the call reverted.
    fn returned(self, what: &str) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Returned(data) => Ok(data),
            Self::Reverted(data) => bail!("{what} reverted with 0x{}", hex::encode(data)),
        }
    }
}

/// What a dry run reported.
#[derive(Debug, PartialEq, Eq)]
struct DryRun {
    /// How the call ended.
    outcome: Outcome,
    /// The `(ref_time, proof_size)` weight the call required.
    weight_required: (u64, u64),
    /// The most storage deposit the call charged at any point, in planck;
    /// zero when it only refunded.
    storage_deposit: u128,
}

/// Dry-runs a call of `input` on the contract at `dest`, from the zero
/// account, with no value and no limits.
async fn call(at: &AssetHubAt, dest: H160, input: Vec<u8>) -> anyhow::Result<Outcome> {
    Ok(call_from(at, AccountId32([0; 32]), dest, input)
        .await?
        .outcome)
}

/// Dry-runs a call of `input` on the contract at `dest`, from `origin`, with no
/// value and no limits.
async fn call_from(
    at: &AssetHubAt,
    origin: AccountId32,
    dest: H160,
    input: Vec<u8>,
) -> anyhow::Result<DryRun> {
    let value: u128 = 0;
    let gas_limit: Option<Value> = None;
    let storage_deposit_limit: Option<u128> = None;
    let payload = subxt::dynamic::runtime_api_call::<_, Value>(
        "ReviveApi",
        "call",
        (origin, dest, value, gas_limit, storage_deposit_limit, input),
    );
    let result = at
        .runtime_apis()
        .call(payload)
        .await
        .with_context(|| format!("ReviveApi_call to {dest:?}"))?;
    dry_run_of(&result)
}

/// Reads a `ContractResult`.
fn dry_run_of(result: &Value) -> anyhow::Result<DryRun> {
    let weight = result
        .at("weight_required")
        .context("ContractResult has no weight_required field")?;
    let weight_part = |part: &str| {
        weight
            .at(part)
            .and_then(Value::as_u128)
            .and_then(|part| u64::try_from(part).ok())
            .with_context(|| format!("weight_required has no {part}"))
    };
    let weight_required = (weight_part("ref_time")?, weight_part("proof_size")?);
    let deposit = result
        .at("max_storage_deposit")
        .context("ContractResult has no max_storage_deposit field")?;
    let ValueDef::Variant(deposit) = &deposit.value else {
        bail!("ContractResult.max_storage_deposit is not a StorageDeposit");
    };
    let amount = deposit
        .values
        .values()
        .next()
        .and_then(Value::as_u128)
        .context("StorageDeposit carries no amount")?;
    let storage_deposit = match deposit.name.as_str() {
        "Charge" => amount,
        "Refund" => 0,
        other => bail!("StorageDeposit is an unknown variant {other}"),
    };
    Ok(DryRun {
        outcome: outcome_of(result)?,
        weight_required,
        storage_deposit,
    })
}

/// Reads the `result` of a `ContractResult`.
fn outcome_of(result: &Value) -> anyhow::Result<Outcome> {
    let result = result
        .at("result")
        .context("ContractResult has no result field")?;
    let ValueDef::Variant(variant) = &result.value else {
        bail!("ContractResult.result is not a Result");
    };
    match variant.name.as_str() {
        "Ok" => {
            let exec = variant
                .values
                .values()
                .next()
                .context("ContractResult.result is an empty Ok")?;
            let flags = exec
                .at("flags")
                .and_then(|flags| flags.at("bits"))
                .and_then(Value::as_u128)
                .context("ExecReturnValue has no flags.bits field")?;
            let data = bytes_of(
                exec.at("data")
                    .context("ExecReturnValue has no data field")?,
            )?;
            if flags & REVERT_FLAG == 0 {
                Ok(Outcome::Returned(data))
            } else {
                Ok(Outcome::Reverted(data))
            }
        }
        "Err" => bail!("contract call failed: {result}"),
        other => bail!("ContractResult.result is an unknown variant {other}"),
    }
}

/// The bytes of a decoded `Vec<u8>`.
fn bytes_of(value: &Value) -> anyhow::Result<Vec<u8>> {
    let ValueDef::Composite(composite) = &value.value else {
        bail!("expected bytes, found {value}");
    };
    let bytes: Option<Vec<u8>> = composite
        .values()
        .map(|byte| byte.as_u128().and_then(|byte| u8::try_from(byte).ok()))
        .collect();
    bytes.with_context(|| format!("expected bytes, found {value}"))
}

/// ABI calldata: the selector of `signature`, then the argument words.
#[must_use]
fn calldata(signature: &str, args: &[Word]) -> Vec<u8> {
    let mut data = keccak_256(signature.as_bytes())[..4].to_vec();
    for arg in args {
        data.extend_from_slice(arg);
    }
    data
}

/// The `index`th word of ABI-encoded return data.
fn word(data: &[u8], index: usize) -> anyhow::Result<Word> {
    let start = index * 32;
    data.get(start..start + 32)
        .and_then(|word| Word::try_from(word).ok())
        .with_context(|| format!("return data of {} bytes has no word {index}", data.len()))
}

/// An ABI `address` word.
fn address_of(word: Word) -> anyhow::Result<H160> {
    ensure!(
        word[..12] == [0; 12],
        "0x{} is not an address",
        hex::encode(word)
    );
    Ok(H160::from_slice(&word[12..]))
}

/// An ABI `bool` word.
fn bool_of(word: Word) -> anyhow::Result<bool> {
    match uint_of(word)? {
        0 => Ok(false),
        1 => Ok(true),
        other => bail!("{other} is not a bool"),
    }
}

/// An ABI unsigned-integer word that fits a `u64`.
fn uint_of(word: Word) -> anyhow::Result<u64> {
    ensure!(
        word[..24] == [0; 24],
        "0x{} does not fit a u64",
        hex::encode(word)
    );
    let mut low = [0; 8];
    low.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(low))
}

/// `key` as a left-aligned, zero-padded `bytes32`.
#[must_use]
fn bytes32_of(key: &[u8]) -> Word {
    let mut word = [0; 32];
    word[..key.len()].copy_from_slice(key);
    word
}

/// `address` as an ABI `address` word.
#[must_use]
fn address_word(address: H160) -> Word {
    let mut word = [0; 32];
    word[12..].copy_from_slice(address.as_bytes());
    word
}

/// `value` as an ABI `uint256` word.
#[must_use]
fn uint_word(value: u64) -> Word {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// An ABI-encoded `address[]` return value.
fn addresses_of(data: &[u8]) -> anyhow::Result<Vec<H160>> {
    let offset = usize::try_from(uint_of(word(data, 0)?)?).context("array offset")?;
    ensure!(
        offset % 32 == 0,
        "array offset {offset} is not word-aligned"
    );
    let length = usize::try_from(uint_of(word(data, offset / 32)?)?).context("array length")?;
    (0..length)
        .map(|index| address_of(word(data, offset / 32 + 1 + index)?))
        .collect()
}

/// The ENS namehash of the label hashed to `labelhash` under `parent`.
#[must_use]
fn node_of(parent: Word, labelhash: Word) -> Word {
    let mut preimage = [0; 64];
    preimage[..32].copy_from_slice(&parent);
    preimage[32..].copy_from_slice(&labelhash);
    keccak_256(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The word spelled by 64 hex digits.
    fn hex_word(hex: &str) -> Word {
        Word::try_from(hex::decode(hex).expect("valid hex")).expect("32 bytes")
    }

    #[test]
    fn selectors_match_the_contract_abi() {
        // Each expected selector is `cast sig <signature>`.
        let cases = [
            ("TARGET()", "cc1f2afa"),
            ("protocolRegistry()", "7656419f"),
            ("get(bytes32)", "8eaa6ac0"),
            ("tldNode()", "114902c5"),
            ("MAX_RESERVATION_QUEUE()", "afb43603"),
            ("exists(uint256)", "4f558e79"),
            ("reservationMeta(bytes32)", "84991ae7"),
            ("granteeOfNode(bytes32)", "e218419d"),
            ("pendingClaimUserCount()", "19883ddd"),
            ("pendingClaimUsers(uint256,uint256)", "7888eb2a"),
            ("settlePendingClaims(address,uint256)", "b9eb52d4"),
        ];
        for (signature, selector) in cases {
            assert_eq!(
                hex::encode(calldata(signature, &[])),
                selector,
                "{signature}"
            );
        }
    }

    #[test]
    fn calldata_appends_each_argument_word() {
        let data = calldata("exists(uint256)", &[uint_word(7), uint_word(9)]);
        assert_eq!(data.len(), 4 + 64, "a selector then two words");
        assert_eq!(
            word(&data[4..], 1).expect("second word"),
            uint_word(9),
            "argument order"
        );
    }

    #[test]
    fn nodes_hash_like_ens_namehash() {
        // `cast namehash dot` and `cast namehash alice.dot`.
        let dot = node_of([0; 32], keccak_256(b"dot"));
        assert_eq!(
            dot,
            hex_word("3fce7d1364a893e213bc4212792b517ffc88f5b13b86c8ef9c8d390c3a1370ce"),
            "the .dot TLD node"
        );
        assert_eq!(
            node_of(dot, keccak_256(b"alice")),
            hex_word("08354b1272d88341cb6fa2cdd7741a7692cb7a71092ae986752d343b8967b226"),
            "alice.dot"
        );
    }

    #[test]
    fn registry_keys_are_left_aligned() {
        let key = bytes32_of(REGISTRAR_KEY);
        assert_eq!(&key[..9], b"registrar", "the key text leads");
        assert_eq!(key[9..], [0; 23], "zero padding follows");
    }

    #[test]
    fn the_zero_address_is_not_configured() {
        assert_eq!(configured(H160::zero()), None, "zero is none");
        assert_eq!(
            configured(H160::repeat_byte(0xab)),
            Some(H160::repeat_byte(0xab)),
            "any other address is itself"
        );
        let key = bytes32_of(NAME_WHITELIST_KEY);
        assert_eq!(&key[..13], b"nameWhitelist", "the key text leads");
        assert_eq!(key[13..], [0; 19], "zero padding follows");
    }

    #[test]
    fn words_decode_as_their_abi_types() {
        let mut address = [0; 32];
        address[12..].copy_from_slice(&[0xab; 20]);
        assert_eq!(
            address_of(address).expect("an address"),
            H160::repeat_byte(0xab),
            "the low 20 bytes"
        );
        assert!(
            address_of([0xff; 32]).is_err(),
            "high bytes set is no address"
        );
        assert!(bool_of(uint_word(1)).expect("a bool"), "1 is true");
        assert!(!bool_of(uint_word(0)).expect("a bool"), "0 is false");
        assert!(bool_of(uint_word(2)).is_err(), "2 is no bool");
        assert_eq!(uint_of(uint_word(64)).expect("a u64"), 64, "a small uint");
        assert!(uint_of([0xff; 32]).is_err(), "a uint256 past u64");
    }

    #[test]
    fn short_return_data_has_no_word() {
        assert!(word(&[0; 40], 1).is_err(), "40 bytes hold one word");
    }

    #[test]
    fn a_contract_result_reads_as_returned_or_reverted() {
        let result = |bits: u32, data: Vec<u8>| {
            Value::named_composite([(
                "result",
                Value::unnamed_variant(
                    "Ok",
                    [Value::named_composite([
                        (
                            "flags",
                            Value::named_composite([("bits", Value::u128(bits.into()))]),
                        ),
                        ("data", Value::from_bytes(data)),
                    ])],
                ),
            )])
        };
        assert_eq!(
            outcome_of(&result(0, vec![1, 2])).expect("an outcome"),
            Outcome::Returned(vec![1, 2]),
            "no revert flag"
        );
        assert_eq!(
            outcome_of(&result(1, vec![0x28])).expect("an outcome"),
            Outcome::Reverted(vec![0x28]),
            "the revert flag"
        );
        let failed = Value::named_composite([(
            "result",
            Value::unnamed_variant("Err", [Value::unnamed_variant("BadOrigin", [])]),
        )]);
        assert!(
            outcome_of(&failed).is_err(),
            "a dispatch error is no outcome"
        );
    }

    #[test]
    fn a_dry_run_reports_its_weight_and_deposit() {
        let result = |deposit: Value| {
            Value::named_composite([
                (
                    "weight_required",
                    Value::named_composite([
                        ("ref_time", Value::u128(7)),
                        ("proof_size", Value::u128(9)),
                    ]),
                ),
                ("max_storage_deposit", deposit),
                (
                    "result",
                    Value::unnamed_variant(
                        "Ok",
                        [Value::named_composite([
                            ("flags", Value::named_composite([("bits", Value::u128(0))])),
                            ("data", Value::from_bytes([])),
                        ])],
                    ),
                ),
            ])
        };

        let charged = dry_run_of(&result(Value::unnamed_variant("Charge", [Value::u128(5)])))
            .expect("a dry run");
        assert_eq!(charged.weight_required, (7, 9), "ref_time then proof_size");
        assert_eq!(
            charged.storage_deposit, 5,
            "a charge is what the call costs"
        );

        let refunded = dry_run_of(&result(Value::unnamed_variant("Refund", [Value::u128(5)])))
            .expect("a dry run");
        assert_eq!(refunded.storage_deposit, 0, "a refund costs nothing");
    }

    #[test]
    fn an_address_array_decodes_in_order() {
        let mut data = Vec::new();
        data.extend_from_slice(&uint_word(32));
        data.extend_from_slice(&uint_word(2));
        data.extend_from_slice(&address_word(H160::repeat_byte(1)));
        data.extend_from_slice(&address_word(H160::repeat_byte(2)));

        assert_eq!(
            addresses_of(&data).expect("two addresses"),
            vec![H160::repeat_byte(1), H160::repeat_byte(2)],
            "an offset word, a length word, then the elements"
        );
        assert!(
            addresses_of(&data[..96]).is_err(),
            "a length past the data is an error"
        );
    }

    #[test]
    fn settlement_calldata_names_the_user_and_the_limit() {
        let data = settlement_calldata(H160::repeat_byte(0xab), 10);
        assert_eq!(hex::encode(&data[..4]), "b9eb52d4", "the selector");
        assert_eq!(
            address_of(word(&data[4..], 0).expect("a user word")).expect("an address"),
            H160::repeat_byte(0xab),
            "the user"
        );
        assert_eq!(
            uint_of(word(&data[4..], 1).expect("a limit word")).expect("a uint"),
            10,
            "the limit"
        );
    }

    #[test]
    fn revive_addresses_follow_the_account_mapper() {
        let mut eth_derived = [0xee; 32];
        eth_derived[..20].copy_from_slice(&[0x11; 20]);
        assert_eq!(
            revive_address(&eth_derived),
            H160::repeat_byte(0x11),
            "an Ethereum-derived account keeps its address"
        );

        let native = [0x22; 32];
        assert_eq!(
            revive_address(&native),
            H160::from_slice(&keccak_256(&native)[12..]),
            "a native account is the tail of its keccak hash"
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable Asset Hub RPC (ASSET_HUB_RPC_URL, or the Paseo default) \
                with pending claims, and a funded origin (SETTLE_ORIGIN_HEX, 32-byte hex); run \
                with --ignored"]
    async fn a_live_pending_claim_dry_runs_with_a_weight_and_a_deposit() {
        let origin = std::env::var("SETTLE_ORIGIN_HEX").expect("SETTLE_ORIGIN_HEX is required");
        let origin: [u8; 32] = hex::decode(origin.trim_start_matches("0x"))
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let url = std::env::var("ASSET_HUB_RPC_URL")
            .unwrap_or_else(|_| "wss://paseo-asset-hub-next-rpc.polkadot.io".to_string());
        let asset_hub = crate::chain::asset_hub::AssetHub::connect_for_reads(&url)
            .await
            .expect("live Asset Hub RPC");
        let at = asset_hub
            .online()
            .at_current_block()
            .await
            .expect("a block");
        let contracts = asset_hub.dotns_contracts(&at).await.expect("contracts");

        let pending = contracts.pending_claim_users(&at).await.expect("a count");
        let page = contracts
            .pending_claim_page(&at, 0, 3)
            .await
            .expect("a page");
        assert_eq!(
            page.len() as u64,
            pending.min(3),
            "a page holds what is pending, up to its limit"
        );
        let Some(user) = page.first() else {
            return;
        };

        let settlement = contracts
            .dry_run_settlement(&at, AccountId32(origin), *user, 10)
            .await
            .expect("a dry run")
            .expect("a pending account settles");
        assert!(
            settlement.weight.0 > 0,
            "settling costs ref time: {settlement:?}"
        );
        println!(
            "pending={pending} user={user:?} weight={:?} deposit={}",
            settlement.weight, settlement.deposit
        );
    }
}
