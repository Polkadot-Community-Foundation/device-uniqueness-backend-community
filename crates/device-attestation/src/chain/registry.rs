// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;

use super::asset_hub::AssetHub;
use super::people::PeopleChain;
use anyhow::Result;

/// A name a row registers, and the candidate account it registers it to.
pub(crate) type Claim<'a> = (&'a str, [u8; 32]);

/// What a chain shows as registered, for the writer's "already landed" reads.
///
/// Answers are keyed by name and give the owning account, so a caller compares
/// the owner with the claim's candidate. A registry that does not key by name
/// (the People Chain after the username removal) reads by the
/// claim's candidate instead, and never reports a name as owned elsewhere.
pub(crate) trait NameRegistry {
    /// The account the chain shows as registered for `claim`'s name, if any.
    async fn owner(&self, claim: Claim<'_>) -> Result<Option<[u8; 32]>>;

    /// [`Self::owner`] for many claims in one read, keyed by name. A name
    /// absent from the map is unregistered.
    async fn owners(&self, claims: &[Claim<'_>]) -> Result<HashMap<String, [u8; 32]>>;
}

impl NameRegistry for PeopleChain {
    async fn owner(&self, claim: Claim<'_>) -> Result<Option<[u8; 32]>> {
        let (name, _) = claim;
        Ok(self.registered_owners(&[claim]).await?.remove(name))
    }

    async fn owners(&self, claims: &[Claim<'_>]) -> Result<HashMap<String, [u8; 32]>> {
        self.registered_owners(claims).await
    }
}

impl NameRegistry for AssetHub {
    async fn owner(&self, claim: Claim<'_>) -> Result<Option<[u8; 32]>> {
        let (name, _) = claim;
        self.lite_label_owner(name).await
    }

    async fn owners(&self, claims: &[Claim<'_>]) -> Result<HashMap<String, [u8; 32]>> {
        let names: Vec<&str> = claims.iter().map(|(name, _)| *name).collect();
        self.lite_label_owners(&names).await
    }
}
