// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

/// `{ regionHint? }` — the issue command (the hint is reserved and ignored).
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct IssueRequest {
    /// Optional region hint (reserved for future use; accepted and ignored).
    #[serde(rename = "regionHint")]
    #[schema(rename = "regionHint", example = "eu-west", nullable)]
    pub region_hint: Option<String>,
}

/// The 201 body: an ephemeral TURN credential and the ICE servers to use it
/// against.
///
/// Both fields' provenance depends on the deployment's `TURN_PROVIDER`, and the
/// shape of `username`/`password` differs between them — treat both as opaque
/// strings to stay portable across providers.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)] // documentation-only mirror of the wire shape
pub struct IssueResponse {
    /// The ICE server URLs (`stun:` / `turn:` / `turns:` forms) to negotiate
    /// against. On the Cloudflare provider these are what Cloudflare returned
    /// with the credential, flattened into one list in response order; on the
    /// coturn provider they are the operator's configured `ICE_SERVERS`.
    #[schema(example = json!([
        "stun:stun.cloudflare.com:3478",
        "turn:turn.cloudflare.com:3478?transport=udp",
        "turn:turn.cloudflare.com:3478?transport=tcp",
        "turns:turn.cloudflare.com:5349?transport=tcp"
    ]))]
    pub servers: Vec<String>,
    /// The credential's username. **Opaque — do not parse.** Cloudflare mints
    /// an unstructured value per request; a coturn deployment uses that relay's
    /// REST-API form, `{unixExpiry}:{hexId}`. Neither carries anything
    /// recoverable about the caller.
    #[schema(example = "d2f4a1c6b8e05379")]
    pub username: String,
    /// The matching password. **Opaque — do not parse.** Minted by Cloudflare,
    /// or on the coturn provider the base64 HMAC over `username` under the
    /// relay-shared secret.
    #[schema(example = "9f83b1e6c0a74d25b3f8e1a70c4d69b2")]
    pub password: String,
    /// Seconds of life remaining on this credential. On the coturn provider
    /// always the configured `TURN_TTL_SECS`, since the credential is minted to
    /// order. On the Cloudflare provider the TTL Cloudflare granted, or less if
    /// a cached credential was served because Cloudflare was briefly
    /// unreachable.
    #[schema(example = 1800)]
    pub ttl: u64,
}

/// Adds the shared `bearer_jwt` security scheme referenced by the issue route.
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

/// The turn OpenAPI document (merged into the workspace reference by
/// `apidoc-gen`).
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "TURN",
         description = "Short-lived TURN credentials for WebRTC ICE negotiation. The credential \
source is the deployment's `TURN_PROVIDER`: **Cloudflare Realtime TURN** (the default), which \
mints each credential itself — one per request, so callers are mutually unlinkable, with the \
last response cached and served if Cloudflare is briefly unreachable — or a self-hosted \
**coturn** relay, where this service computes the credential from a secret shared with the \
relay and callers are kept unlinkable by an opaque keyed id instead. Either way nothing is \
persisted. Issuance is authorized either by an access JWT (`/issue`) or, when enabled, by a \
personhood ring-VRF proof over a client-timestamped message (`/issue-with-proof`).")
    ),
    paths(
        crate::http::issue_credentials,
        crate::http::proof_routes::issue_with_proof,
    ),
    components(schemas(
        IssueRequest,
        IssueResponse,
        crate::http::proof_routes::IssueWithProofBody,
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;
