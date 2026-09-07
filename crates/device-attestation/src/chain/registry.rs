// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashMap;

use super::asset_hub::AssetHub;
use super::people::PeopleChain;
use anyhow::Result;

pub(crate) trait NameRegistry {
    async fn owner(&self, name: &str) -> Result<Option<[u8; 32]>>;

    async fn owners(&self, names: &[&str]) -> Result<HashMap<String, [u8; 32]>>;
}

impl NameRegistry for PeopleChain {
    async fn owner(&self, name: &str) -> Result<Option<[u8; 32]>> {
        self.username_owner(name).await
    }

    async fn owners(&self, names: &[&str]) -> Result<HashMap<String, [u8; 32]>> {
        self.username_owners(names).await
    }
}

impl NameRegistry for AssetHub {
    async fn owner(&self, name: &str) -> Result<Option<[u8; 32]>> {
        self.lite_label_owner(name).await
    }

    async fn owners(&self, names: &[&str]) -> Result<HashMap<String, [u8; 32]>> {
        self.lite_label_owners(names).await
    }
}
