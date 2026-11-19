// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The two shapes of `PeopleLite.attest`, and the payload format each one
//! takes.
//!
//! `attest`'s last argument is an optional `LiteConsumerRegistrationParams`.
//! In the older shape it carries the lite username and an optional reserved
//! personhood name, and the consumer signature covers both. Once the runtime
//! drops usernames from People, the struct is
//! `{ signature, account, identifier_key }` and the signature covers
//! `(account, verifier, identifier_key)`.
//!
//! The backend reads the shape from the runtime's metadata at the block it is
//! working against, as it reads the signing context (`crate::signature`). So
//! one release works before and after the runtime upgrade, and on a network
//! whose runtime has not taken the change yet.

use std::fmt;

use scale_info::PortableRegistry;
use scale_info::TypeDef;
use subxt::Metadata;

/// The pallet that declares the call whose shape this module reads.
const PALLET: &str = "PeopleLite";

/// The call whose shape this module reads.
const CALL: &str = "attest";

/// The consumer struct's fields before the username removal, in order.
const WITH_USERNAME: &[&str] = &[
    "signature",
    "account",
    "identifier_key",
    "username",
    "reserved_username",
];

/// The consumer struct's fields after the username removal, in order.
const WITHOUT_USERNAME: &[&str] = &["signature", "account", "identifier_key"];

/// The shape of `PeopleLite.attest`'s consumer registration argument.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttestShape {
    /// The consumer registration carries `username` and `reserved_username`.
    WithUsername,
    /// The consumer registration carries no username.
    WithoutUsername,
}

impl AttestShape {
    /// The payload format a claim must be signed in for this shape.
    #[must_use]
    pub fn payload_version(self) -> PayloadVersion {
        match self {
            Self::WithUsername => PayloadVersion::V1,
            Self::WithoutUsername => PayloadVersion::V2,
        }
    }

    /// The shape whose consumer struct has exactly `names`, in order.
    #[must_use]
    fn from_field_names(names: &[String]) -> Option<Self> {
        let has_fields = |expected: &[&str]| {
            names
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        };
        if has_fields(WITH_USERNAME) {
            Some(Self::WithUsername)
        } else if has_fields(WITHOUT_USERNAME) {
            Some(Self::WithoutUsername)
        } else {
            None
        }
    }
}

/// Reads the shape from a runtime's metadata. Fails when the runtime has no
/// `PeopleLite.attest`, or when its consumer struct is neither known shape:
/// this backend cannot build that call.
impl TryFrom<&Metadata> for AttestShape {
    type Error = anyhow::Error;

    fn try_from(metadata: &Metadata) -> anyhow::Result<Self> {
        use anyhow::Context as _;

        let call = metadata
            .pallet_by_name(PALLET)
            .with_context(|| format!("runtime declares no {PALLET} pallet"))?
            .call_variant_by_name(CALL)
            .with_context(|| format!("{PALLET} declares no {CALL} call"))?;
        let consumer = call
            .fields
            .last()
            .with_context(|| format!("{PALLET}::{CALL} takes no arguments"))?;
        let names: Vec<String> = consumer_field_names(metadata.types(), consumer.ty.id)
            .with_context(|| {
                format!("{PALLET}::{CALL}'s last argument is not an Option<struct>")
            })?;
        Self::from_field_names(&names).with_context(|| {
            format!(
                "{PALLET}::{CALL}'s consumer registration declares [{}]; this backend builds \
                 [{}] or [{}]",
                names.join(", "),
                WITH_USERNAME.join(", "),
                WITHOUT_USERNAME.join(", "),
            )
        })
    }
}

/// The field names of the struct inside the `Option` whose type is
/// `option_type_id`. `None` when that type is not an `Option` of a struct with
/// named fields.
#[must_use]
fn consumer_field_names(types: &PortableRegistry, option_type_id: u32) -> Option<Vec<String>> {
    let TypeDef::Variant(option) = &types.resolve(option_type_id)?.type_def else {
        return None;
    };
    let some = option
        .variants
        .iter()
        .find(|variant| variant.name == "Some")?;
    let [inner] = some.fields.as_slice() else {
        return None;
    };
    let TypeDef::Composite(params) = &types.resolve(inner.ty.id)?.type_def else {
        return None;
    };
    // An unnamed field makes the whole collection `None`.
    params
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect()
}

/// The format of the payloads a claim's signatures cover, as the client
/// declares it in `payloadVersion`. A signature is not introspectable, so the
/// declaration is the only way to know which message it signs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadVersion {
    /// The consumer signature covers the lite username base and the optional
    /// reserved personhood name. Matches [`AttestShape::WithUsername`].
    V1,
    /// The consumer signature covers `(account, verifier, identifier_key)`
    /// only. Matches [`AttestShape::WithoutUsername`].
    V2,
}

impl TryFrom<u16> for PayloadVersion {
    type Error = String;

    fn try_from(version: u16) -> Result<Self, String> {
        match version {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err("Unsupported payload version. Supported: 1, 2.".to_string()),
        }
    }
}

impl From<PayloadVersion> for u16 {
    fn from(version: PayloadVersion) -> Self {
        match version {
            PayloadVersion::V1 => 1,
            PayloadVersion::V2 => 2,
        }
    }
}

impl fmt::Display for PayloadVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version: u16 = (*self).into();
        write!(formatter, "{version}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn the_vendored_runtime_takes_the_username() {
        let metadata = chain_types::metadata_arc();
        let shape = AttestShape::try_from(&*metadata).expect("vendored attest has a known shape");
        assert_eq!(
            shape,
            AttestShape::WithUsername,
            "the vendored runtime still takes the username in `attest`"
        );
    }

    #[test]
    fn both_known_field_sets_resolve() {
        assert_eq!(
            AttestShape::from_field_names(&names(WITH_USERNAME)),
            Some(AttestShape::WithUsername),
            "the struct before the username removal"
        );
        assert_eq!(
            AttestShape::from_field_names(&names(WITHOUT_USERNAME)),
            Some(AttestShape::WithoutUsername),
            "the struct after the username removal"
        );
    }

    #[test]
    fn an_unknown_field_set_is_refused() {
        // Reordered, partially removed, renamed, and empty: none is a struct
        // this backend knows how to build.
        let unknown: [&[&str]; 4] = [
            &["account", "signature", "identifier_key"],
            &["signature", "account", "identifier_key", "username"],
            &["signature", "account", "communication_key"],
            &[],
        ];
        for fields in unknown {
            assert_eq!(
                AttestShape::from_field_names(&names(fields)),
                None,
                "{fields:?} must not resolve to a shape"
            );
        }
    }

    #[test]
    fn each_shape_names_its_payload_version() {
        assert_eq!(
            AttestShape::WithUsername.payload_version(),
            PayloadVersion::V1,
            "format 1 signs the username"
        );
        assert_eq!(
            AttestShape::WithoutUsername.payload_version(),
            PayloadVersion::V2,
            "format 2 signs no username"
        );
    }

    #[test]
    fn payload_versions_round_trip_through_their_stored_form() {
        for version in [PayloadVersion::V1, PayloadVersion::V2] {
            let stored: u16 = version.into();
            assert_eq!(
                PayloadVersion::try_from(stored),
                Ok(version),
                "{version} must read back from the outbox column"
            );
        }
        for stored in [0, 3] {
            assert!(
                PayloadVersion::try_from(stored).is_err(),
                "{stored} is not a payload version"
            );
        }
    }
}
