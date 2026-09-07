// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! PCF fork: the blob is generated from the public `people-paseo` (products devnet), e.g.
//! `--url wss://people-paseo.rotko.net`. Refresh with:
//! `subxt metadata --url <people-rpc> --pallets System,Balances,Utility,Proxy,People,PeopleLite,Resources,Game,ProofOfInk,Members -f bytes -o crates/chain-types/metadata/people.scale`

use subxt::config::transaction_extensions as tx_ext;

#[allow(clippy::all, missing_docs, rustdoc::all)]
#[subxt::subxt(runtime_metadata_path = "metadata/people.scale")]
pub mod people {}

pub use subxt;

/// The vendored metadata [`people`] is generated from, decoded once.
static METADATA: std::sync::LazyLock<subxt::metadata::ArcMetadata> =
    std::sync::LazyLock::new(|| {
        std::sync::Arc::new(
            subxt::Metadata::decode_from(include_bytes!("../metadata/people.scale"))
                .expect("vendored People Chain metadata decodes"),
        )
    });

/// subxt's own error-decoding entry point
pub fn metadata_arc() -> subxt::metadata::ArcMetadata {
    METADATA.clone()
}

/// Vendored spec_version for people-chain. Asset Hub is dynamically generated
/// so doesn't need this.
pub fn vendored_spec_version() -> u32 {
    static SPEC_VERSION: std::sync::LazyLock<u32> = std::sync::LazyLock::new(|| {
        use subxt::ext::scale_decode::DecodeAsType as _;

        let metadata = metadata_arc();
        let version = metadata
            .pallet_by_name("System")
            .and_then(|pallet| pallet.constant_by_name("Version"))
            .expect("vendored metadata carries System::Version");
        people::runtime_types::sp_version::RuntimeVersion::decode_as_type(
            &mut version.value(),
            version.ty(),
            metadata.types(),
        )
        .expect("System::Version decodes as a RuntimeVersion")
        .spec_version
    });
    *SPEC_VERSION
}

macro_rules! delegating_config {
    ($(#[$meta:meta])* $name:ident => $extensions:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default)]
        pub struct $name(subxt::PolkadotConfig);

        impl subxt::Config for $name {
            type AccountId = <subxt::PolkadotConfig as subxt::Config>::AccountId;
            type Address = <subxt::PolkadotConfig as subxt::Config>::Address;
            type Signature = <subxt::PolkadotConfig as subxt::Config>::Signature;
            type Header = <subxt::PolkadotConfig as subxt::Config>::Header;
            type TransactionExtensions = $extensions<Self>;
            type AssetId = <subxt::PolkadotConfig as subxt::Config>::AssetId;
            type Hasher = <subxt::PolkadotConfig as subxt::Config>::Hasher;

            fn genesis_hash(&self) -> Option<subxt::config::HashFor<Self>> {
                self.0.genesis_hash()
            }

            fn spec_and_transaction_version_for_block_number(
                &self,
                block_number: u64,
            ) -> Option<(u32, u32)> {
                self.0
                    .spec_and_transaction_version_for_block_number(block_number)
            }

            fn metadata_for_spec_version(&self, spec_version: u32) -> Option<subxt::ArcMetadata> {
                self.0.metadata_for_spec_version(spec_version)
            }

            fn set_metadata_for_spec_version(
                &self,
                spec_version: u32,
                metadata: subxt::ArcMetadata,
            ) {
                self.0.set_metadata_for_spec_version(spec_version, metadata);
            }
        }
    };
}

macro_rules! extrinsic_params_builder {
    (
        $(#[$meta:meta])*
        $builder:ident<$config:ty> => $extensions:ident,
        |$mortality:ident, $nonce:ident, $tip:ident| $params:expr
    ) => {
        $(#[$meta])*
        pub struct $builder {
            mortality: tx_ext::CheckMortalityParams<$config>,
            nonce: Option<u64>,
            tip: u128,
        }

        impl $builder {
            pub fn new() -> Self {
                Self {
                    mortality: tx_ext::CheckMortalityParams::immortal(),
                    nonce: None,
                    tip: 0,
                }
            }

            #[must_use]
            pub fn nonce(mut self, nonce: u64) -> Self {
                self.nonce = Some(nonce);
                self
            }

            #[must_use]
            pub fn tip(mut self, tip: u128) -> Self {
                self.tip = tip;
                self
            }

            #[must_use]
            pub fn mortality(mut self, mortality: tx_ext::CheckMortalityParams<$config>) -> Self {
                self.mortality = mortality;
                self
            }

            pub fn build(
                self,
            ) -> <$extensions<$config> as subxt::config::TransactionExtensions<$config>>::Params {
                let $mortality = self.mortality;
                let $nonce = self.nonce.map_or_else(
                    tx_ext::CheckNonceParams::from_chain,
                    tx_ext::CheckNonceParams::with_nonce,
                );
                let $tip = tx_ext::ChargeAssetTxPaymentParams::tip(self.tip);
                $params
            }
        }

        impl Default for $builder {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

delegating_config! {
    PeopleConfig => PeopleTransactionExtensions
}

#[rustfmt::skip]
pub type PeopleTransactionExtensions<T> = (
    Noop<UnitTransactionExtension>,
    Noop<AuthorizeValueTransfer>,
    tx_ext::VerifySignature<T>,
    Noop<AsPerson>,
    Noop<AsProofOfInkParticipant>,
    Noop<ScoreAsParticipant>,
    Noop<GameAsInvited>,
    Noop<PeopleLiteAuth>,
    Noop<AsMember>,
    Noop<AsCoinage>,
    Noop<AsResources>,
    Noop<HonourAuth>,
    Noop<AuthorizeCall>,
    Noop<RestrictOrigins>,
    Noop<CheckNonZeroSender>,
    tx_ext::CheckSpecVersion,
    tx_ext::CheckTxVersion,
    tx_ext::CheckGenesis<T>,
    tx_ext::CheckMortality<T>,
    tx_ext::CheckNonce,
    Noop<CheckWeight>,
    tx_ext::ChargeAssetTxPayment<T>,
    // Declared by `people-paseo` (the PCF products devnet, Paseo People 1004);
    // absent from `next-people-paseo`. Resolved by name, so a runtime without
    // it is unaffected.
    tx_ext::CheckMetadataHash,
    Noop<StorageWeightReclaim>,
);

extrinsic_params_builder! {
    PeopleExtrinsicParamsBuilder<PeopleConfig> => PeopleTransactionExtensions,
    |mortality, nonce, tip| (
        (), (), (), (), (), (), (), (), (), (), (), (), (), (), (), (), (), (),
        mortality, nonce, (), tip, (), (),
    )
}

delegating_config! {
    AssetHubConfig => AssetHubTransactionExtensions
}

#[rustfmt::skip]
pub type AssetHubTransactionExtensions<T> = (
    Noop<UnitTransactionExtension>,
    Noop<AuthorizeValueTransfer>,
    Noop<AuthorizeCall>,
    Noop<AsPgas>,
    Noop<AsRingAlias>,
    Noop<AsScarcity>,
    Noop<AsDotnsGateway>,
    Noop<RestrictOrigins>,
    Noop<CheckNonZeroSender>,
    tx_ext::CheckSpecVersion,
    tx_ext::CheckTxVersion,
    tx_ext::CheckGenesis<T>,
    tx_ext::CheckMortality<T>,
    tx_ext::CheckNonce,
    Noop<CheckWeight>,
    tx_ext::ChargeAssetTxPayment<T>,
    // Declared by the public `asset-hub-paseo` (the PCF products devnet, AH
    // 1000): the claims pallet's unit-payload extension. Not on the `next-`
    // Asset Hubs.
    Noop<PrevalidateAttests>,
    tx_ext::CheckMetadataHash,
    Noop<EthSetOrigin>,
    Noop<StorageWeightReclaim>,
);

extrinsic_params_builder! {
    AssetHubExtrinsicParamsBuilder<AssetHubConfig> => AssetHubTransactionExtensions,
    |mortality, nonce, tip| (
        (), (), (), (), (), (), (), (), (), (), (), (),
        mortality, nonce, (), tip, (), (), (), (),
    )
}

pub trait NoopName {
    const NAME: &'static str;
    const VALUE: &'static [u8] = &[];
}

pub struct Noop<N>(core::marker::PhantomData<fn() -> N>);

impl<N> Clone for Noop<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N> Copy for Noop<N> {}

impl<N: NoopName> core::fmt::Debug for Noop<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Noop").field(&N::NAME).finish()
    }
}

impl<T: subxt::Config, N: NoopName> subxt::config::TransactionExtension<T> for Noop<N> {
    type Decoded = ();
    type Params = ();

    fn new(
        _client: &subxt::config::ClientState<T>,
        _params: Self::Params,
    ) -> Result<Self, subxt::error::TransactionExtensionError> {
        Ok(Self(core::marker::PhantomData))
    }
}

impl<R: subxt::ext::scale_type_resolver::TypeResolver, N: NoopName>
    subxt::ext::frame_decode::extrinsics::TransactionExtension<R> for Noop<N>
{
    const NAME: &'static str = N::NAME;

    fn encode_value_to(
        &self,
        _type_id: R::TypeId,
        _type_resolver: &R,
        out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::frame_decode::extrinsics::TransactionExtensionError> {
        out.extend_from_slice(N::VALUE);
        Ok(())
    }

    fn encode_implicit_to(
        &self,
        _type_id: R::TypeId,
        _type_resolver: &R,
        _out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::frame_decode::extrinsics::TransactionExtensionError> {
        Ok(())
    }
}

macro_rules! noop_names {
    ($($ty:ident $(= $value:expr)?),* $(,)?) => {
        $(
            #[doc = concat!("The `", stringify!($ty), "` transaction extension.")]
            pub struct $ty;

            impl NoopName for $ty {
                const NAME: &'static str = stringify!($ty);
                $(const VALUE: &'static [u8] = $value;)?
            }
        )*
    };
}

noop_names! {
    UnitTransactionExtension,
    AuthorizeValueTransfer = &[0],
    AsPerson = &[0],
    AsProofOfInkParticipant = &[0],
    ScoreAsParticipant = &[0],
    GameAsInvited = &[0],
    PeopleLiteAuth = &[0],
    AsMember = &[0],
    AsCoinage = &[0],
    AsResources = &[0],
    HonourAuth = &[0],
    AuthorizeCall,
    RestrictOrigins = &[0],
    CheckNonZeroSender,
    CheckWeight,
    StorageWeightReclaim,
    AsPgas = &[0],
    AsRingAlias = &[0],
    AsScarcity = &[0],
    AsDotnsGateway = &[0],
    EthSetOrigin,
    PrevalidateAttests,
}

#[cfg(test)]
mod tests {
    use super::*;
    use subxt::storage::Address as _;

    const TUPLE_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "AuthorizeValueTransfer",
        "VerifyMultiSignature",
        "AsPerson",
        "AsProofOfInkParticipant",
        "ScoreAsParticipant",
        "GameAsInvited",
        "PeopleLiteAuth",
        "AsMember",
        "AsCoinage",
        "AsResources",
        "HonourAuth",
        "AuthorizeCall",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "CheckMetadataHash",
        "StorageWeightReclaim",
    ];

    const ASSET_HUB_TUPLE_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "AuthorizeValueTransfer",
        "AuthorizeCall",
        "AsPgas",
        "AsRingAlias",
        "AsScarcity",
        "AsDotnsGateway",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "PrevalidateAttests",
        "CheckMetadataHash",
        "EthSetOrigin",
        "StorageWeightReclaim",
    ];

    struct KnownRuntime {
        env: &'static str,
        spec_name: &'static str,
        spec_version: u32,
        tuple: &'static [&'static str],
        extensions: &'static [&'static str],
    }

    /// What the public `people-paseo` 2004003 (PCF products devnet, Paseo
    /// People 1004) declares, in order. The vendored `people.scale` is
    /// generated from this runtime.
    const PEOPLE_DEVNET_EXTENSIONS: &[&str] = &[
        "AuthorizeValueTransfer",
        "VerifyMultiSignature",
        "AsPerson",
        "AsProofOfInkParticipant",
        "ScoreAsParticipant",
        "GameAsInvited",
        "PeopleLiteAuth",
        "AsMember",
        "AsCoinage",
        "AsResources",
        "HonourAuth",
        "AuthorizeCall",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "CheckMetadataHash",
        "StorageWeightReclaim",
    ];

    /// What the public `asset-hub-paseo` 2004002 (PCF products devnet, AH
    /// 1000) declares, in order.
    const ASSET_HUB_DEVNET_EXTENSIONS: &[&str] = &[
        "AuthorizeValueTransfer",
        "AuthorizeCall",
        "AsPgas",
        "AsRingAlias",
        "AsDotnsGateway",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "PrevalidateAttests",
        "CheckMetadataHash",
        "EthSetOrigin",
        "StorageWeightReclaim",
    ];

    /// What `next-people-paseo` 3000000 declares, in order. paseo-next-v2 and
    /// previewnet upgraded together and their metadata is identical, so one
    /// list covers both.
    const PEOPLE_V3_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "VerifyMultiSignature",
        "AsPerson",
        "AsProofOfInkParticipant",
        "ScoreAsParticipant",
        "GameAsInvited",
        "PeopleLiteAuth",
        "AsMember",
        "AsCoinage",
        "AsResources",
        "HonourAuth",
        "AuthorizeCall",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "StorageWeightReclaim",
    ];

    /// What `next-asset-hub-paseo` 3000000 declares, in order. `AsRingAlias`
    /// is gone and `AsScarcity` took its place; the tuple carries both,
    /// because the runtimes below are still in the list.
    const ASSET_HUB_V3_EXTENSIONS: &[&str] = &[
        "UnitTransactionExtension",
        "AsScarcity",
        "AuthorizeCall",
        "AsPgas",
        "AsDotnsGateway",
        "RestrictOrigins",
        "CheckNonZeroSender",
        "CheckSpecVersion",
        "CheckTxVersion",
        "CheckGenesis",
        "CheckMortality",
        "CheckNonce",
        "CheckWeight",
        "ChargeAssetTxPayment",
        "CheckMetadataHash",
        "EthSetOrigin",
        "StorageWeightReclaim",
    ];

    /// Every runtime a deployment is known to have talked to. The tuples are
    /// the union of these sets, not a snapshot of the newest one: an entry
    /// stays here — and its gate stays in the tuple — so that a binary
    /// pointed at a node that has not upgraded yet can still sign.
    const KNOWN_RUNTIMES: &[KnownRuntime] = &[
        KnownRuntime {
            env: "products-devnet",
            spec_name: "people-paseo",
            spec_version: 2_004_003,
            tuple: TUPLE_EXTENSIONS,
            extensions: PEOPLE_DEVNET_EXTENSIONS,
        },
        KnownRuntime {
            env: "products-devnet asset hub",
            spec_name: "asset-hub-paseo",
            spec_version: 2_004_002,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: ASSET_HUB_DEVNET_EXTENSIONS,
        },
        KnownRuntime {
            env: "paseo-next-v2 / previewnet",
            spec_name: "next-people-paseo",
            spec_version: 3_000_000,
            tuple: TUPLE_EXTENSIONS,
            extensions: PEOPLE_V3_EXTENSIONS,
        },
        KnownRuntime {
            env: "paseo-next-v2 / previewnet asset hub",
            spec_name: "next-asset-hub-paseo",
            spec_version: 3_000_000,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: ASSET_HUB_V3_EXTENSIONS,
        },
        KnownRuntime {
            env: "paseo-next-v2",
            spec_name: "next-people-paseo",
            spec_version: 1_000_030,
            tuple: TUPLE_EXTENSIONS,
            extensions: &[
                "AuthorizeValueTransfer",
                "VerifyMultiSignature",
                "AsPerson",
                "AsProofOfInkParticipant",
                "ScoreAsParticipant",
                "GameAsInvited",
                "PeopleLiteAuth",
                "AsMember",
                "AsCoinage",
                "AsResources",
                "HonourAuth",
                "AuthorizeCall",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "previewnet",
            spec_name: "next-people-paseo",
            spec_version: 1_000_032,
            tuple: TUPLE_EXTENSIONS,
            extensions: &[
                "UnitTransactionExtension",
                "VerifyMultiSignature",
                "AsPerson",
                "AsProofOfInkParticipant",
                "ScoreAsParticipant",
                "GameAsInvited",
                "PeopleLiteAuth",
                "AsMember",
                "AsCoinage",
                "AsResources",
                "HonourAuth",
                "AuthorizeCall",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "paseo-next-v2 asset hub",
            spec_name: "next-asset-hub-paseo",
            spec_version: 2_000_033,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: &[
                "AuthorizeValueTransfer",
                "AuthorizeCall",
                "AsPgas",
                "AsRingAlias",
                "AsDotnsGateway",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "CheckMetadataHash",
                "EthSetOrigin",
                "StorageWeightReclaim",
            ],
        },
        KnownRuntime {
            env: "previewnet asset hub",
            spec_name: "next-asset-hub-paseo",
            spec_version: 2_000_034,
            tuple: ASSET_HUB_TUPLE_EXTENSIONS,
            extensions: &[
                "UnitTransactionExtension",
                "AuthorizeCall",
                "AsPgas",
                "AsRingAlias",
                "AsDotnsGateway",
                "RestrictOrigins",
                "CheckNonZeroSender",
                "CheckSpecVersion",
                "CheckTxVersion",
                "CheckGenesis",
                "CheckMortality",
                "CheckNonce",
                "CheckWeight",
                "ChargeAssetTxPayment",
                "CheckMetadataHash",
                "EthSetOrigin",
                "StorageWeightReclaim",
            ],
        },
    ];

    #[test]
    fn covers_every_known_runtime_extension_set() {
        for runtime in KNOWN_RUNTIMES {
            for name in runtime.extensions {
                assert!(
                    runtime.tuple.contains(name),
                    "{} ({} {}) declares extension {name}, which the tuple cannot satisfy",
                    runtime.env,
                    runtime.spec_name,
                    runtime.spec_version
                );
            }
        }
    }

    #[test]
    fn vendored_metadata_extensions_are_all_in_the_tuple() {
        let metadata = metadata_arc();
        let declared: Vec<&str> = metadata
            .extrinsic()
            .transaction_extensions_to_use_for_encoding()
            .map(|extension| extension.identifier())
            .collect();

        assert!(
            !declared.is_empty(),
            "vendored metadata must declare transaction extensions"
        );
        for name in &declared {
            assert!(
                TUPLE_EXTENSIONS.contains(name),
                "vendored metadata declares extension {name}, which the tuple cannot satisfy"
            );
        }
    }

    #[test]
    fn vendored_metadata_names_the_runtime_it_came_from() {
        assert_eq!(
            vendored_spec_version(),
            2_004_003,
            "the blob's own System::Version is what chain-client logs the live \
             chain against, so refreshing the blob moves this number with it \
             (PCF fork: vendored from the public people-paseo, the products devnet)"
        );
    }

    #[test]
    fn slot_zero_noops_encode_their_runtime_value() {
        assert_eq!(AuthorizeValueTransfer::NAME, "AuthorizeValueTransfer");
        assert_eq!(AuthorizeValueTransfer::VALUE, &[0]);
        assert_eq!(UnitTransactionExtension::NAME, "UnitTransactionExtension");
        assert!(UnitTransactionExtension::VALUE.is_empty());
    }

    #[test]
    fn builds_username_owner_of_query() {
        let query = people::storage().resources().username_owner_of();
        assert_eq!(query.pallet_name(), "Resources");
        assert_eq!(query.entry_name(), "UsernameOwnerOf");
    }

    #[test]
    fn builds_attestation_allowance_query() {
        let query = people::storage().people_lite().attestation_allowance();
        assert_eq!(query.pallet_name(), "PeopleLite");
        assert_eq!(query.entry_name(), "AttestationAllowance");
    }

    #[test]
    fn builds_register_lite_person_call() {
        let username =
            people::runtime_types::bounded_collections::bounded_vec::BoundedVec(b"alice".to_vec());
        let call = people::tx()
            .resources()
            .register_lite_person([0u8; 65], username, None);
        assert_eq!(call.pallet_name(), "Resources");
        assert_eq!(call.call_name(), "register_lite_person");
    }

    #[test]
    fn builds_set_invite_ticket_calls() {
        let ticket = subxt::utils::AccountId32([0u8; 32]);
        let game = people::tx().game().set_invite_ticket(ticket);
        assert_eq!(game.pallet_name(), "Game");
        assert_eq!(game.call_name(), "set_invite_ticket");

        let poi = people::tx().proof_of_ink().set_invite_ticket(ticket);
        assert_eq!(poi.pallet_name(), "ProofOfInk");
        assert_eq!(poi.call_name(), "set_invite_ticket");
    }

    #[test]
    fn builds_available_invites_queries() {
        let game = people::storage().game().available_invites();
        assert_eq!(game.pallet_name(), "Game");
        assert_eq!(game.entry_name(), "AvailableInvites");

        let poi = people::storage().proof_of_ink().available_invites();
        assert_eq!(poi.pallet_name(), "ProofOfInk");
        assert_eq!(poi.entry_name(), "AvailableInvites");
    }

    fn people_metadata() -> subxt::ArcMetadata {
        subxt::Metadata::decode_from(include_bytes!("../metadata/people.scale"))
            .expect("vendored metadata decodes")
            .arc()
    }

    fn offline_client_state() -> subxt::config::ClientState<PeopleConfig> {
        subxt::config::ClientState {
            genesis_hash: subxt::utils::H256::zero(),
            spec_version: 3_000_000,
            transaction_version: 5,
            metadata: people_metadata(),
        }
    }

    #[test]
    fn builder_nonce_flows_into_check_nonce_encoding() {
        let state = offline_client_state();

        fn encode_nonce(
            state: &subxt::config::ClientState<PeopleConfig>,
            params: tx_ext::CheckNonceParams,
        ) -> Vec<u8> {
            use subxt::config::TransactionExtension as _;
            use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

            let mut out = Vec::new();
            tx_ext::CheckNonce::new(state, params)
                .expect("CheckNonce builds offline")
                .encode_value_to(0, state.metadata.types(), &mut out)
                .expect("CheckNonce encodes offline");
            out
        }

        let (.., nonce, _, _, _, _) = PeopleExtrinsicParamsBuilder::new().nonce(7).build();
        assert_eq!(
            encode_nonce(&state, nonce),
            [28],
            "nonce 7 must encode as Compact(7), 7 << 2"
        );

        let (.., nonce, _, _, _, _) = PeopleExtrinsicParamsBuilder::new().build();
        assert_eq!(
            encode_nonce(&state, nonce),
            [0],
            "without an explicit nonce the slot carries none of its own and \
             defers to the nonce subxt injects from the chain"
        );
    }

    #[test]
    fn builder_starts_immortal_with_no_tip() {
        use subxt::config::transaction_extensions::{ChargeAssetTxPayment, CheckMortality};
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();
        let (.., mortality, _, _, tip, _, _) = PeopleExtrinsicParamsBuilder::new().build();

        let mut era = Vec::new();
        CheckMortality::new(&state, mortality)
            .expect("immortal params build offline")
            .encode_value_to(0, state.metadata.types(), &mut era)
            .expect("CheckMortality encodes offline");
        assert_eq!(era, [0], "immortal era is the single zero byte");

        let payment = ChargeAssetTxPayment::new(&state, tip).expect("tip params build offline");
        assert_eq!(payment.tip(), 0, "the builder must not tip by default");
        assert!(payment.asset_id().is_none(), "tip is in the native token");
    }

    #[test]
    fn default_builder_matches_new() {
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();

        let mut encoded = Vec::new();
        for builder in [
            PeopleExtrinsicParamsBuilder::new(),
            PeopleExtrinsicParamsBuilder::default(),
        ] {
            let (.., mortality, nonce, _, tip, _, _) = builder.build();
            let mut out = Vec::new();

            tx_ext::CheckMortality::new(&state, mortality)
                .expect("mortality params build offline")
                .encode_value_to(0, state.metadata.types(), &mut out)
                .expect("CheckMortality encodes offline");
            tx_ext::CheckNonce::new(&state, nonce)
                .expect("CheckNonce builds offline")
                .encode_value_to(0, state.metadata.types(), &mut out)
                .expect("CheckNonce encodes offline");
            tx_ext::ChargeAssetTxPayment::new(&state, tip)
                .expect("tip params build offline")
                .encode_value_to(0, state.metadata.types(), &mut out)
                .expect("ChargeAssetTxPayment encodes offline");

            encoded.push(out);
        }

        assert_eq!(
            encoded[0], encoded[1],
            "`default()` must encode identically to `new()`"
        );
    }

    #[test]
    fn noop_encoders_write_value_bytes_and_empty_implicit() {
        use subxt::config::TransactionExtension as _;
        use subxt::ext::frame_decode::extrinsics::TransactionExtension as _;

        let state = offline_client_state();
        let types = state.metadata.types();

        let authorize =
            Noop::<AuthorizeValueTransfer>::new(&state, ()).expect("noop gates build offline");
        let mut out = vec![0xAA];
        authorize
            .encode_value_to(0, types, &mut out)
            .expect("noop value encodes");
        assert_eq!(out, [0xAA, 0x00], "appends exactly the encoded-None byte");
        authorize
            .encode_implicit_to(0, types, &mut out)
            .expect("noop implicit encodes");
        assert_eq!(out, [0xAA, 0x00], "the implicit part writes nothing");

        let unit =
            Noop::<UnitTransactionExtension>::new(&state, ()).expect("noop gates build offline");
        let mut out = vec![0xAA];
        unit.encode_value_to(0, types, &mut out)
            .expect("noop value encodes");
        unit.encode_implicit_to(0, types, &mut out)
            .expect("noop implicit encodes");
        assert_eq!(out, [0xAA], "a unit-valued gate writes no bytes at all");
    }

    #[test]
    fn config_delegates_caches_to_polkadot_config() {
        use subxt::Config as _;

        let config = PeopleConfig::default();
        assert_eq!(config.genesis_hash(), None);
        assert_eq!(
            config.spec_and_transaction_version_for_block_number(0),
            None
        );
        assert!(config.metadata_for_spec_version(3_000_000).is_none());

        let metadata = people_metadata();
        config.set_metadata_for_spec_version(3_000_000, metadata.clone());
        let cached = config
            .metadata_for_spec_version(3_000_000)
            .expect("registered metadata is readable back");
        assert!(
            std::sync::Arc::ptr_eq(&cached, &metadata),
            "delegation must return the registered Arc"
        );
        assert!(
            config.metadata_for_spec_version(3_000_001).is_none(),
            "registration must not leak to other spec versions"
        );
    }

    #[test]
    fn builds_members_ring_root_queries() {
        let root = people::storage().members().root();
        assert_eq!(root.pallet_name(), "Members");
        assert_eq!(root.entry_name(), "Root");

        let old_roots = people::storage().members().old_roots();
        assert_eq!(old_roots.pallet_name(), "Members");
        assert_eq!(old_roots.entry_name(), "OldRoots");

        let collections = people::storage().members().collections();
        assert_eq!(collections.pallet_name(), "Members");
        assert_eq!(collections.entry_name(), "Collections");
    }
}
