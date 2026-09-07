// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;

use axum::{
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use http_common::AuthSubject;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::http::state::AppState;

use super::{
    available_digits, base_state,
    error::{FieldError, UsernamesError, UsernamesResult},
    is_valid_base,
};
use crate::chain::people::BaseState;

const MAX_USERNAMES: usize = 100;

/// `{ usernames: [base, ...] }` — bases to validate and check on chain
/// (documentation mirror; the handler validates raw JSON).
#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct AvailableRequest {
    /// Candidate base usernames to validate and check (max 100).
    #[schema(example = json!(["tallesx", "abc"]))]
    usernames: Vec<String>,
}

/// `{ _tag: "v1", value: { base: { status, availableDigits? } } }`.
#[derive(Serialize, ToSchema)]
pub struct AvailableV1Response {
    /// Response schema tag; always `v1`.
    #[serde(rename = "_tag")]
    #[schema(rename = "_tag", example = "v1")]
    tag: &'static str,
    /// Per-base availability, keyed by the requested base username.
    value: BTreeMap<String, NameAvailability>,
}

/// Availability of a single base username.
#[derive(Serialize, ToSchema)]
pub(crate) struct NameAvailability {
    /// `AVAILABLE`, `EXHAUSTED` (nothing claimable under this base), or `INVALID` (fails base rules).
    #[schema(example = "AVAILABLE")]
    status: &'static str,
    /// Free discriminators (`1..=99`); present only when `AVAILABLE`.
    #[serde(rename = "availableDigits", skip_serializing_if = "Option::is_none")]
    #[schema(rename = "availableDigits", example = json!([1, 2, 3]))]
    available_digits: Option<Vec<u8>>,
}

/// Availability for each requested base.
#[utoipa::path(
    post,
    path = "/api/v1/usernames/available",
    tag = "Usernames",
    security(("bearer_jwt" = [])),
    request_body = AvailableRequest,
    responses(
        (status = 200, description = "Per-base availability read from People Chain UsernameOwnerOf \
            plus pending outbox reservations, tagged `{_tag: \"v1\", value}` with availableDigits. \
            `EXHAUSTED` means nothing claimable under this base: no free discriminator, or the \
            bare full-person name is owned or its reservation queue is full — the last two would \
            make a claim carrying `dotns.reservedUsername` fail on chain and take the lite \
            username with it.",
         body = AvailableV1Response,
         example = json!({ "_tag": "v1", "value": {
             "tallesx": { "status": "AVAILABLE", "availableDigits": [1, 2, 3] },
             "takenx": { "status": "EXHAUSTED" },
             "abc": { "status": "INVALID" }
         } })),
        (status = 400, description = "Invalid `usernames`, or malformed JSON.",
         body = serde_json::Value,
         example = json!({
             "error": "The request body contains invalid values.",
             "fields": [{ "field": "usernames", "message": "must contain at most 100 items" }]
         })),
        (status = 401, description = "Missing or invalid bearer token.",
         body = serde_json::Value),
        (status = 429, description = "Subject rate limit exceeded (with `Retry-After`).",
         body = serde_json::Value),
        (status = 500, description = "People Chain failure or reservation-outbox failure.",
         body = serde_json::Value,
         example = json!({ "error": "Internal server error. Please try again." }))
    )
)]
pub async fn check(
    State(state): State<AppState>,
    auth: AuthSubject,
    body: Bytes,
) -> UsernamesResult<Response> {
    super::check_rate_limit(&state, &auth.subject)?;

    let value = super::parse_json_body(&body)?;
    let usernames = validate_usernames(&value)?;

    let mut value_map = BTreeMap::new();
    for base in usernames {
        let availability = availability_for(&state, &base).await?;
        value_map.insert(base, availability);
    }

    let response = AvailableV1Response {
        tag: "v1",
        value: value_map,
    };
    Ok(Json(response).into_response())
}

/// Validate `{usernames: string[≤100]}`.
fn validate_usernames(value: &Value) -> UsernamesResult<Vec<String>> {
    let field = value.as_object().and_then(|o| o.get("usernames"));
    let Some(Value::Array(items)) = field else {
        return Err(UsernamesError::InvalidBody(vec![FieldError {
            message: http_common::error::expected(
                "array",
                http_common::error::received_name(field),
            ),
            field: "usernames".to_string(),
        }]));
    };

    let mut errors = Vec::new();
    let mut usernames = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match item {
            Value::String(s) => usernames.push(s.clone()),
            other => errors.push(FieldError {
                message: http_common::error::expected(
                    "string",
                    http_common::error::type_name(other),
                ),
                field: format!("usernames[{index}]"),
            }),
        }
    }
    if items.len() > MAX_USERNAMES {
        errors.push(FieldError {
            message: http_common::error::at_most_items(MAX_USERNAMES),
            field: "usernames".to_string(),
        });
    }
    if !errors.is_empty() {
        return Err(UsernamesError::InvalidBody(errors));
    }
    Ok(usernames)
}

async fn availability_for(state: &AppState, base: &str) -> UsernamesResult<NameAvailability> {
    if !is_valid_base(base) {
        return Ok(NameAvailability {
            status: "INVALID",
            available_digits: None,
        });
    }

    Ok(availability_of(&base_state(state, base).await?))
}

/// The availability verdict for one base, given everything read about it.
fn availability_of(state: &BaseState) -> NameAvailability {
    // Pool is 01..=99 (00 is never offered); available = pool minus taken.
    let digits = available_digits(&state.taken);
    if digits.is_empty() || state.rejects_reservations() {
        return NameAvailability {
            status: "EXHAUSTED",
            available_digits: None,
        };
    }

    NameAvailability {
        status: "AVAILABLE",
        available_digits: Some(digits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn v1_response_matches_the_documented_shape() {
        let response = AvailableV1Response {
            tag: "v1",
            value: BTreeMap::from([(
                "aliceuser".to_string(),
                NameAvailability {
                    status: "AVAILABLE",
                    available_digits: Some(vec![1, 42, 99]),
                },
            )]),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({
                "_tag": "v1",
                "value": {
                    "aliceuser": {
                        "status": "AVAILABLE",
                        "availableDigits": [1, 42, 99]
                    }
                }
            })
        );
    }

    #[test]
    fn unavailable_names_omit_available_digits() {
        let response = AvailableV1Response {
            tag: "v1",
            value: BTreeMap::from([(
                "short".to_string(),
                NameAvailability {
                    status: "INVALID",
                    available_digits: None,
                },
            )]),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({ "_tag": "v1", "value": { "short": { "status": "INVALID" } } })
        );
    }

    fn base_state(taken: impl IntoIterator<Item = u8>) -> BaseState {
        BaseState {
            taken: taken.into_iter().collect(),
            full_name_owned: false,
            queue_len: 0,
            queue_capacity: 10,
        }
    }

    #[test]
    fn a_base_with_free_digits_is_available() {
        let availability = availability_of(&base_state([1, 2, 3]));
        assert_eq!(availability.status, "AVAILABLE");
        let digits = availability.available_digits.expect("digits");
        assert_eq!(digits.len(), 96);
        assert!(!digits.contains(&1));
    }

    #[test]
    fn a_base_with_no_free_digits_is_exhausted_even_though_00_is_free() {
        let availability = availability_of(&base_state(1..=99));
        assert_eq!(availability.status, "EXHAUSTED");
        assert!(availability.available_digits.is_none());
    }

    #[test]
    fn a_base_whose_reservation_leg_would_be_rejected_is_exhausted() {
        let owned = BaseState {
            full_name_owned: true,
            ..base_state([])
        };
        assert_eq!(availability_of(&owned).status, "EXHAUSTED");

        let queue_full = BaseState {
            queue_len: 10,
            ..base_state([])
        };
        assert_eq!(availability_of(&queue_full).status, "EXHAUSTED");

        let queue_nearly_full = BaseState {
            queue_len: 9,
            ..base_state([])
        };
        assert_eq!(availability_of(&queue_nearly_full).status, "AVAILABLE");
    }

    #[test]
    fn usernames_validation_reports_every_field() {
        let cases = [
            (json!({}), "expected array, received nothing"),
            (
                json!({ "usernames": null }),
                "expected array, received null",
            ),
            (
                json!({ "usernames": "openok" }),
                "expected array, received string",
            ),
        ];
        for (body, expected) in cases {
            match validate_usernames(&body) {
                Err(UsernamesError::InvalidBody(errors)) => {
                    assert_eq!(errors.len(), 1);
                    assert_eq!(errors[0].field, "usernames");
                    assert_eq!(errors[0].message, expected);
                }
                other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
            }
        }

        match validate_usernames(&json!({ "usernames": [5] })) {
            Err(UsernamesError::InvalidBody(errors)) => {
                assert_eq!(errors[0].field, "usernames[0]");
                assert_eq!(errors[0].message, "expected string, received number");
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }

        let hundred_one: Vec<Value> = (0..101).map(|i| json!(format!("user{i}xx"))).collect();
        match validate_usernames(&json!({ "usernames": hundred_one })) {
            Err(UsernamesError::InvalidBody(errors)) => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].message, "must contain at most 100 items");
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }

        assert!(validate_usernames(&json!({ "usernames": [] }))
            .expect("empty array is valid")
            .is_empty());
    }
}
