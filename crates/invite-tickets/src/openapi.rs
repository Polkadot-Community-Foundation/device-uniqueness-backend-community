// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

/// `{ who, dim }` — the claim command.
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct ClaimRequest {
    /// SS58 address to claim a ticket for (any valid SS58 prefix).
    #[schema(example = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty")]
    pub who: String,
    /// DIM to claim a ticket for: `Game` or `ProofOfInk`.
    #[schema(example = "Game")]
    pub dim: String,
}

/// The 200 claim body: the ticket keypair's public half plus the
/// sr25519 signature over the claimant's decoded account id.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct ClaimResponse {
    /// `0x`-hex 32-byte sr25519 public key of the claimed ticket.
    #[serde(rename = "publicKey")]
    #[schema(
        rename = "publicKey",
        example = "0xda8ab326da384dd49d5f12543b58acae730af7388b9348c51af6ee3a0962864d"
    )]
    pub public_key: String,
    /// SS58 address of the inviter that registered the ticket on-chain.
    #[schema(example = "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM")]
    pub inviter: String,
    /// DIM the ticket funds: `Game` or `ProofOfInk`.
    #[schema(example = "Game")]
    pub dim: String,
    /// Network the ticket is registered on: `westend2`, `paseo`, or `polkadot`.
    #[schema(example = "paseo")]
    pub network: String,
    /// SS58 address the ticket was claimed for (echoes `who`).
    #[serde(rename = "claimedBy")]
    #[schema(
        rename = "claimedBy",
        example = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
    )]
    pub claimed_by: String,
    /// Ticket generation time (JS-style ISO, millisecond precision).
    #[serde(rename = "createdAt")]
    #[schema(rename = "createdAt", example = "2026-07-01T10:20:30.400Z")]
    pub created_at: String,
    /// Claim time (JS-style ISO, millisecond precision).
    #[serde(rename = "claimedAt")]
    #[schema(rename = "claimedAt", example = "2026-07-02T11:00:00.000Z")]
    pub claimed_at: String,
    /// `0x`-hex 64-byte sr25519 signature by the ticket key over the raw
    /// 32-byte account id decoded from `who`.
    #[schema(
        example = "0xa4a506e96aff250724590ef9527d8117ea2e9d633e813d22d32ad17e0b5c253c406cb22baf62283c6987f81b9bb55ea75f3bdff0259d84e5c282728043f77c88"
    )]
    pub signature: String,
    /// Tickets still `available` in this `(dim, network)` pool after the claim.
    #[schema(example = 41)]
    pub remaining: i64,
}

/// Adds the shared `bearer_jwt` security scheme referenced by the claim route.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "bearer_jwt",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("Access JWT issued by POST /api/v1/auth/token."))
                    .build(),
            ),
        );
    }
}

/// The invite-tickets OpenAPI document (merged into the workspace reference
/// by `apidoc-gen`).
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "Invitation Tickets",
         description = "Synchronous invitation-credential claims from a pre-staged, \
on-chain-registered sr25519 keypair pool. The route the shipping iOS/Android apps \
call for Game / ProofOfInk credentials.")
    ),
    paths(crate::http::claim_ticket),
    components(schemas(ClaimRequest, ClaimResponse)),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
