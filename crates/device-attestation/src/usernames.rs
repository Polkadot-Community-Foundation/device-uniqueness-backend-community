// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub mod available;
pub mod error;
pub mod register;

use std::collections::BTreeSet;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{
        header::{HeaderMap, HeaderValue},
        StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use http_common::error::not_found;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::chain::attest::AttestShape;
use crate::chain::outbox;
use crate::chain::people::BaseState;
use crate::chain::people::PeopleAt;
use crate::chain::people::ReservationState;
use crate::http::state::AppState;

use self::error::{UsernamesError, UsernamesResult};

const MIN_BASE_LEN: usize = 6;

/// Maximum base-username length
/// (`MAX_USERNAME_LENGTH - N_USERNAME_DIGITS - 1`).
pub(crate) const MAX_BASE_LEN: usize = 29;

/// Base-username rules, shared by the read and write paths so they can't
/// disagree: length 6..=29, lowercase ASCII letters.
fn is_valid_base(base: &str) -> bool {
    (MIN_BASE_LEN..=MAX_BASE_LEN).contains(&base.len())
        && base.bytes().all(|b| b.is_ascii_lowercase())
}

/// The free discriminators for a base: `1..=99` minus the taken set (`00` is
/// never offered). Shared so availability and registration agree on what's
/// free.
pub(crate) fn available_digits(taken: &BTreeSet<u8>) -> Vec<u8> {
    (1..=99u8).filter(|d| !taken.contains(d)).collect()
}

/// Whether one bare personhood name can be reserved, on each chain a claim
/// reserves it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reservation {
    /// On People, for a runtime that keeps personhood names. `None` after
    /// the username removal took that state out of `Resources`.
    pub people: Option<ReservationState>,
    /// On the dotNS contracts on Asset Hub, which the gateway forwards every
    /// reservation to.
    pub dotns: ReservationState,
}

impl Reservation {
    /// Whether a claim reserving this name would be rejected on chain.
    #[must_use]
    pub fn rejects(&self) -> bool {
        self.dotns.rejects() || self.people.is_some_and(|people| people.rejects())
    }
}

/// Everything about one base that decides whether a claim can land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaimState {
    /// Discriminators `00..=99` taken under this base: on Asset Hub, on People
    /// while its runtime keeps usernames, or by a row still in the outbox.
    pub taken: BTreeSet<u8>,
    /// The bare base as a personhood name.
    pub reservation: Reservation,
}

impl ClaimState {
    /// Whether a claim reserving the bare base would be rejected on chain.
    #[must_use]
    pub fn rejects_reservations(&self) -> bool {
        self.reservation.rejects()
    }
}

/// Folds the reads about one base into one [`ClaimState`]. `people` is `None`
/// when the People runtime keeps no usernames.
#[must_use]
fn claim_state_of(
    people: Option<BaseState>,
    dotns: ReservationState,
    lite_labels: BTreeSet<u8>,
    pending: BTreeSet<u8>,
) -> ClaimState {
    let mut taken = lite_labels;
    taken.extend(pending);
    let people = people.map(|people| {
        taken.extend(&people.taken);
        people.reservation()
    });
    ClaimState {
        taken,
        reservation: Reservation { people, dotns },
    }
}

/// The shape of the connected People runtime's `attest`, which says whether
/// `Resources` still keeps usernames.
pub(crate) fn attest_shape_at(at: &PeopleAt) -> UsernamesResult<AttestShape> {
    AttestShape::try_from(at.metadata_ref()).map_err(UsernamesError::from)
}

pub(crate) async fn claim_state(state: &AppState, base: &str) -> UsernamesResult<ClaimState> {
    let at = state
        .chain
        .online()
        .at_current_block()
        .await
        .map_err(|e| UsernamesError::from(anyhow::Error::from(e)))?;
    let shape = attest_shape_at(&at)?;
    claim_state_at(state, base, &at, shape).await
}

/// [`claim_state`] read at `at`, for a caller that already holds a block
/// handle and has read `shape` from it.
///
/// Asset Hub's `LiteLabelOwner`, the dotNS reservation state of the bare base,
/// and the outbox are always read. People's `Resources::UsernameOwnerOf` and
/// reservation state are read only while `shape` says the runtime still keeps
/// them: names registered there before the dotNS lane existed are not on Asset
/// Hub.
pub(crate) async fn claim_state_at(
    state: &AppState,
    base: &str,
    at: &PeopleAt,
    shape: AttestShape,
) -> UsernamesResult<ClaimState> {
    let (people, dotns, lite_labels, pending) = tokio::try_join!(
        async {
            match shape {
                AttestShape::WithUsername => state
                    .chain
                    .base_state_at(base, at)
                    .await
                    .map(Some)
                    .map_err(UsernamesError::from),
                AttestShape::WithoutUsername => Ok(None),
            }
        },
        async {
            state
                .asset_hub
                .personhood_reservation(base)
                .await
                .map_err(UsernamesError::from)
        },
        async {
            state
                .asset_hub
                .taken_discriminators(base)
                .await
                .map_err(UsernamesError::from)
        },
        async {
            outbox::allocated_discriminators(&state.pool, base)
                .await
                .map_err(UsernamesError::from)
        },
    )?;
    Ok(claim_state_of(people, dotns, lite_labels, pending))
}

/// The reservation state of one bare personhood name: on the dotNS contracts,
/// and on People while its runtime keeps one (`shape`).
pub(crate) async fn reservation_state(
    state: &AppState,
    name: &str,
    shape: AttestShape,
) -> UsernamesResult<Reservation> {
    let (people, dotns) = tokio::try_join!(
        async {
            match shape {
                AttestShape::WithUsername => state
                    .chain
                    .reservation_state(name)
                    .await
                    .map(Some)
                    .map_err(UsernamesError::from),
                AttestShape::WithoutUsername => Ok(None),
            }
        },
        async {
            state
                .asset_hub
                .personhood_reservation(name)
                .await
                .map_err(UsernamesError::from)
        },
    )?;
    Ok(Reservation { people, dotns })
}

/// Subject-keyed rate limit for the authenticated usernames surface (never
/// IP — the CGNAT postmortem). Renders the 429 with `Retry-After`.
pub(crate) async fn check_rate_limit(state: &AppState, subject: &str) -> UsernamesResult<()> {
    let key = format!("/api/v1/usernames:{subject}");
    state
        .limiter
        .allow(key)
        .await
        .map(|_| ())
        .map_err(|err| UsernamesError::RateLimited {
            retry_after_secs: err.wait_time_from(state.limiter.current_time()).as_secs(),
        })
}

/// Parse the request body as JSON, content type ignored. Unparseable → 400.
pub(crate) fn parse_json_body(body: &Bytes) -> UsernamesResult<Value> {
    serde_json::from_slice(body).map_err(|_| UsernamesError::MalformedJson)
}

/// Build the `/usernames` router.
///
/// Method fallbacks keep wrong-method requests on the JSON 404; the collection
/// root also answers CORS preflights.
pub fn router() -> Router<AppState> {
    let root = Router::new()
        .route(
            "/",
            post(register::register)
                .options(collection_preflight)
                .fallback(not_found),
        )
        .layer(axum::middleware::from_fn(allow_any_origin));
    root.route("/available", post(available::check).fallback(not_found))
}

/// Stamp `access-control-allow-origin: *` on every collection-root response,
/// Origin header or not.
async fn allow_any_origin(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The collection-root preflight: `204` with the CORS
/// defaults (the allow-origin header is stamped by [`allow_any_origin`]).
async fn collection_preflight(headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let out = response.headers_mut();
    out.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,HEAD,PUT,POST,DELETE,PATCH"),
    );
    if let Some(requested) = headers.get(axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            requested.clone(),
        );
    }
    out.insert(
        axum::http::header::VARY,
        HeaderValue::from_static("Access-Control-Request-Headers"),
    );
    response
}

/// `{ attester }` — the on-chain attester authority public key.
#[derive(Serialize, ToSchema)]
pub struct AttesterResponse {
    /// `0x`-hex sr25519 public key the backend writes registrations as.
    #[schema(example = "0xe4cd20d6d1e0e119d63a943afd2d7496fbbb0ac8e7cd99c3c5f16b63a68e7432")]
    attester: String,
}

/// `GET /api/v1/attester` — the attester authority public key (`0x`+hex, public).
#[utoipa::path(
    get,
    path = "/api/v1/attester",
    tag = "Discovery",
    responses(
        (status = 200, description = "The on-chain attester account the backend writes as.", body = AttesterResponse,
         example = json!({ "attester": "0xe4cd20d6d1e0e119d63a943afd2d7496fbbb0ac8e7cd99c3c5f16b63a68e7432" }))
    )
)]
pub async fn attester(State(state): State<AppState>) -> Json<AttesterResponse> {
    Json(AttesterResponse {
        attester: format!("0x{}", hex::encode(state.config.attester_account)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn attester_response_keeps_the_mobile_wire_shape() {
        let response = AttesterResponse {
            attester: "0x86aac84d".to_string(),
        };

        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({ "attester": "0x86aac84d" })
        );
    }

    #[test]
    fn base_validation_shared_by_read_and_write_paths() {
        assert!(is_valid_base("alicexyz"));
        assert!(is_valid_base(&"a".repeat(MAX_BASE_LEN)));
        assert!(!is_valid_base("short"));
        assert!(!is_valid_base("Alicexyz"));
        assert!(!is_valid_base("alice123"));
        assert!(!is_valid_base(&"a".repeat(MAX_BASE_LEN + 1)));
    }

    #[test]
    fn available_excludes_taken_and_zero() {
        let taken: BTreeSet<u8> = [1u8, 2, 99].into_iter().collect();
        let available = available_digits(&taken);
        assert!(!available.contains(&0));
        assert!(!available.contains(&1));
        assert!(!available.contains(&99));
        assert!(available.contains(&3));
        assert_eq!(available.len(), 99 - 3);
    }

    fn people(taken: [u8; 2], full_name_owned: bool) -> BaseState {
        BaseState {
            taken: BTreeSet::from(taken),
            full_name_owned,
            queue_len: 0,
            queue_capacity: 10,
        }
    }

    /// The bare name as the dotNS contracts see it, `queue_len` of 64 queued.
    fn dotns(queue_len: u32, unavailable: bool) -> ReservationState {
        ReservationState {
            personhood_name_unavailable: unavailable,
            queue_len,
            queue_capacity: 64,
        }
    }

    #[test]
    fn a_runtime_with_usernames_unions_people_asset_hub_and_the_outbox() {
        let state = claim_state_of(
            Some(people([1, 2], true)),
            dotns(0, false),
            BTreeSet::from([2, 3]),
            BTreeSet::from([4]),
        );

        assert_eq!(
            state.taken,
            BTreeSet::from([1, 2, 3, 4]),
            "a digit taken in any of the three is taken"
        );
        assert!(
            state.rejects_reservations(),
            "People's owned bare name still rejects the reservation leg"
        );
    }

    #[test]
    fn a_runtime_without_usernames_reads_asset_hub_and_the_outbox_only() {
        let state = claim_state_of(
            None,
            dotns(0, false),
            BTreeSet::from([2, 3]),
            BTreeSet::from([4]),
        );

        assert_eq!(
            state.taken,
            BTreeSet::from([2, 3, 4]),
            "Asset Hub and the outbox are the only places a name lives"
        );
        assert_eq!(
            state.reservation.people, None,
            "Resources keeps no personhood-name state after the upgrade"
        );
        assert!(
            !state.rejects_reservations(),
            "a free name on dotNS rejects nothing"
        );
    }

    #[test]
    fn the_dotns_contracts_reject_a_reservation_on_either_runtime() {
        let owned = Reservation {
            people: None,
            dotns: dotns(0, true),
        };
        let full = Reservation {
            people: Some(people([1, 2], false).reservation()),
            dotns: dotns(64, false),
        };
        let open = Reservation {
            people: None,
            dotns: dotns(63, false),
        };

        assert!(owned.rejects(), "a name already on DotnsRegistrar");
        assert!(full.rejects(), "a full DotnsPopController queue");
        assert!(!open.rejects(), "a queue with one slot left");
    }

    #[test]
    fn body_parses_as_json_regardless_of_content_type() {
        assert!(parse_json_body(&Bytes::from_static(b"{\"usernames\":[]}")).is_ok());
        assert!(matches!(
            parse_json_body(&Bytes::from_static(b"{not json")),
            Err(UsernamesError::MalformedJson)
        ));
        assert!(matches!(
            parse_json_body(&Bytes::new()),
            Err(UsernamesError::MalformedJson)
        ));
    }
}
