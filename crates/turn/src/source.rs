// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! The credential source behind both issue routes.

use crate::cloudflare;
use crate::config::ProviderConfig;
use crate::credentials::Issuer;

/// One issued credential, in the shape both routes put on the wire.
pub struct Issued {
    pub servers: Vec<String>,
    pub username: String,
    pub password: String,
    pub ttl: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("no credential could be issued")]
pub struct Unavailable;

pub enum Source {
    Cloudflare(cloudflare::Client),
    Coturn {
        issuer: Issuer,
        ice_servers: Vec<String>,
        ttl_secs: u64,
    },
}

impl Source {
    pub fn new(provider: &ProviderConfig, ttl_secs: u64) -> Result<Self, String> {
        match provider {
            ProviderConfig::Cloudflare {
                key_id,
                api_token,
                base_url,
            } => Ok(Source::Cloudflare(cloudflare::Client::new(
                key_id.clone(),
                api_token.clone(),
                ttl_secs,
                base_url.clone(),
            )?)),
            ProviderConfig::Coturn {
                secret,
                algorithm,
                ice_servers,
                // Configured on the relay; never on this wire.
                realm: _,
            } => Ok(Source::Coturn {
                issuer: Issuer::new(secret.clone(), *algorithm, ttl_secs),
                ice_servers: ice_servers.clone(),
                ttl_secs,
            }),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Source::Cloudflare(_) => "cloudflare",
            Source::Coturn { .. } => "coturn",
        }
    }

    pub async fn issue(&self, now_unix: u64) -> Result<Issued, Unavailable> {
        match self {
            Source::Cloudflare(client) => Ok(from_cloudflare(client, now_unix).await?),
            Source::Coturn {
                issuer,
                ice_servers,
                ttl_secs,
            } => {
                let mut id = [0u8; 8];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
                let credentials = issuer.issue(now_unix, id);
                Ok(Issued {
                    servers: ice_servers.clone(),
                    username: credentials.username,
                    password: credentials.password,
                    ttl: *ttl_secs,
                })
            }
        }
    }

    pub async fn issue_for_proof(
        &self,
        now_unix: u64,
        product_id: &str,
        alias: &[u8],
    ) -> Result<Issued, Unavailable> {
        match self {
            Source::Cloudflare(client) => Ok(from_cloudflare(client, now_unix).await?),
            Source::Coturn {
                issuer,
                ice_servers,
                ttl_secs,
            } => {
                let credentials = issuer.issue_for_proof(now_unix, product_id, alias);
                Ok(Issued {
                    servers: ice_servers.clone(),
                    username: credentials.username,
                    password: credentials.password,
                    ttl: *ttl_secs,
                })
            }
        }
    }
}

async fn from_cloudflare(
    client: &cloudflare::Client,
    now_unix: u64,
) -> Result<Issued, Unavailable> {
    let credentials = client.issue(now_unix).await.map_err(|_| Unavailable)?;
    let ttl = credentials.remaining(now_unix);
    Ok(Issued {
        servers: credentials.servers,
        username: credentials.username,
        password: credentials.password,
        ttl,
    })
}
