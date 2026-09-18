// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod table;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use http_common::error::not_found;

/// The prefix whose owner answers an empty 404 rather than the JSON body.
///
/// Read out of [`table::TABLE`] rather than written here a second time: the
/// generated edge configs and this runtime fallback must agree about where the
/// notify prefix starts, and one literal is how that stays true.
fn notify_prefix() -> &'static str {
    match table::TABLE
        .iter()
        .find(|row| row.owner == "notify-relay")
        .map(|row| row.matches)
    {
        Some(table::Match::Prefix(prefix)) => prefix,
        // The row is asserted to exist and to be a bare prefix by
        // `the_notify_row_is_a_bare_prefix` below, so this is unreachable in a
        // build that passes its tests.
        _ => "/api/v1/notify",
    }
}

pub struct Surfaces {
    /// Auth, attester, the usernames write surface, JWKS — and the global
    /// fallback owner: the edge's `handle { }` sends everything unclaimed here.
    pub attestation: Router,
    /// Username reads (`/search`) and proof-of-compute issuance.
    pub indexer: Router,
    /// `/api/v1/invitation-ticket/*`. Absent where the network has no invite
    /// pallets; the path then falls through to the catch-all JSON 404.
    #[cfg(invite_tickets)]
    pub invite_tickets: Router,
    /// `/api/v1/turn/*`.
    pub turn: Router,
    /// `/api/v1/notify*` — see the module docs for its distinct 404 dialect.
    pub notifications: Router,
}

/// Merge the surfaces into the public route table.
///
/// The caller adds health, `/docs` and the middleware stack; this function owns
/// only who-answers-what.
pub fn merge(surfaces: Surfaces) -> Router {
    let router = Router::new()
        .merge(surfaces.attestation)
        .merge(surfaces.indexer);
    #[cfg(invite_tickets)]
    let router = router.merge(surfaces.invite_tickets);
    router
        .merge(surfaces.turn)
        .merge(surfaces.notifications)
        .fallback(fallback)
}

/// The service-wide fallback, reproducing the edge's per-prefix ownership for
/// an unmatched path: the notify prefix answers its owner's empty 404, and
/// everything else answers device attestation's JSON 404 body — that service being the
/// edge's catch-all.
async fn fallback(request: Request) -> Response {
    if request.uri().path().starts_with(notify_prefix()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    not_found().await.into_response()
}

#[cfg(test)]
mod tests {
    use super::{notify_prefix, table};

    #[test]
    fn the_notify_row_is_a_bare_prefix() {
        let row = table::TABLE
            .iter()
            .find(|row| row.owner == "notify-relay")
            .expect("the notify row exists");
        assert!(matches!(
            row.matches,
            table::Match::Prefix("/api/v1/notify")
        ));
        assert_eq!(notify_prefix(), "/api/v1/notify");
    }

    #[test]
    fn the_notify_prefix_matches_the_way_the_edge_does() {
        for path in [
            "/api/v1/notify",
            "/api/v1/notify/",
            "/api/v1/notify/bogus",
            "/api/v1/notifyfoo",
        ] {
            assert!(path.starts_with(notify_prefix()), "{path}");
        }
        for path in ["/api/v1/notif", "/api/v1/usernames", "/api/v1/turn/issue"] {
            assert!(!path.starts_with(notify_prefix()), "{path}");
        }
    }
}
