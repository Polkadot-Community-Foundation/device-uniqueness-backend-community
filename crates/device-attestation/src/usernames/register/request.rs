// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;

use http_common::error::must_match;
use serde::Deserialize;
use serde_json::Value;
use subxt::utils::AccountId32;
use utoipa::ToSchema;

use crate::config::Config;
use crate::signature::{candidate_message, verify_account_signature, AccountSignatureForm};
use crate::usernames::{
    error::{FieldError, UsernamesError},
    MAX_BASE_LEN,
};

const MSG_DIGITS: &str = "Digits must be between 01-99";
const MSG_INVALID_SS58: &str = "Invalid ss58 address.";
const MSG_INVALID_SIGNATURE: &str = "Invalid signature.";
const MAX_DOTNS_LABEL_LEN: usize = 32;
const PATTERN_BASE: &str = "^([a-z]{6,})$";
const PATTERN_HEX_STRING: &str = "^(0x)?[a-fA-F0-9]+$";

/// The flat registration request.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(
    description = "The flat registration request. A missing field or a wrong JSON type is a \
                   `400` naming that field; past that, every format failure is reported at once."
)]
pub struct RegisterRequest {
    /// SS58 beneficiary account that will own the username.
    #[schema(example = "5FbRAkhDvNVecNzHLFxBNXFXNwvBaV69S1W3nfBbnxYypkkT")]
    candidate_account_id: String,
    /// Base username (lowercase ASCII letters, 6..=29 chars).
    #[schema(example = "tallesx")]
    username: String,
    /// Optional two-digit suffix, e.g. `"07"`; random-free if omitted.
    #[serde(default)]
    #[schema(example = "07")]
    preferred_digits: Option<String>,
    /// `0x`-hex 64-byte sr25519 signature proving control of the candidate.
    #[schema(example = "0x...64 bytes...")]
    candidate_signature: String,
    /// `0x`-hex ring VRF key.
    #[schema(example = "0x...")]
    ring_vrf_key: String,
    /// `0x`-hex 64-byte ownership proof.
    #[schema(example = "0x...64 bytes...")]
    proof_of_ownership: String,
    /// `0x`-hex 64-byte consumer registration signature.
    #[schema(example = "0x...64 bytes...")]
    consumer_registration_signature: String,
    /// `0x`-hex 65-byte identifier key.
    #[schema(example = "0x...65 bytes...")]
    identifier_key: String,
    /// The format of the payloads this claim's signatures cover.
    /// An unsupported version is a 400 before anything is stored. Omitted
    /// means `1`, the only format today.
    #[serde(default = "default_payload_version")]
    #[schema(example = 1, minimum = 1, default = 1)]
    payload_version: u16,
    /// Optional single-use registration voucher (the INSTANT lane): bypasses
    /// the PoUD gate and the registration queue. Must be a string when
    /// present; its value is ignored unless `REGISTRATION_VOUCHERS_ENABLED`.
    #[serde(default, rename = "lifetimePoUDVoucher")]
    #[schema(rename = "lifetimePoUDVoucher", example = "base64url-voucher-key")]
    lifetime_poud_voucher: Option<String>,
    /// Optional Android device-uniqueness evidence (Widevine PoUD): leaf-first
    /// base64 DER attestation chain, 2-10 entries, whose leaf key was created
    /// with `attestationChallenge = SHA-256(domain ‖ deviceChallenge ‖
    /// accountKey ‖ deviceId)`. All three evidence fields are present
    /// together or not at all. Supplied fields must match their JSON types;
    /// evidence verification runs only with `WIDEVINE_DEDUP_ENABLED`.
    /// Sent only when the app measured Widevine L1.
    #[serde(default)]
    #[schema(example = json!(["base64-der-leaf", "base64-der-root"]))]
    #[allow(dead_code)] // `widevine::extract` reads the evidence fields.
    attestation_chain: Option<Vec<String>>,
    /// Base64 32-byte single-use challenge from `/auth/challenges`, bound
    /// into the leaf key's attestation challenge.
    #[serde(default)]
    #[schema(example = "base64-32-byte-challenge")]
    #[allow(dead_code)]
    device_challenge: Option<String>,
    /// Base64 32-byte device pseudonym:
    /// `SHA-256("dub/poud/widevine-id/v1" ‖ rawWidevineId)`, computed on the
    /// device — the raw id never leaves it.
    #[serde(default)]
    #[schema(example = "base64-32-byte-device-id")]
    #[allow(dead_code)]
    device_id: Option<String>,
    /// Optional DotNS reservation block.
    #[serde(default)]
    dotns: Option<Dotns>,
}

/// Optional DotNS reservation, parking a base label for later personhood use.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Dotns {
    /// `0x`-hex 64-byte signature.
    #[schema(example = "0x...64 bytes...")]
    signature: String,
    /// Unix timestamp the reservation was signed at, as a JSON integer: a
    /// float is refused even when it is whole (`1780000000.0`).
    #[schema(example = 1780000000i64)]
    signed_at: i64,
    /// The bare personhood name to reserve. Its own name on chain — it need
    /// not be `username`, and availability is checked against *this* name, not
    /// against the base of the lite username in the same claim.
    #[serde(default)]
    #[schema(example = "reservedname")]
    reserved_username: Option<String>,
}

impl RegisterRequest {
    fn decode(body: &Value) -> Result<Self, FieldError> {
        serde_path_to_error::deserialize(body).map_err(|error| {
            let path = error.path().to_string();
            structural_error(&path, error.into_inner().to_string())
        })
    }
}

fn structural_error(path: &str, message: String) -> FieldError {
    let parent = (path != ".").then_some(path);
    let missing = message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.strip_suffix('`'));
    let field = match (parent, missing) {
        (Some(parent), Some(name)) => format!("{parent}.{name}"),
        (None, Some(name)) => name.to_string(),
        (Some(parent), None) => parent.to_string(),
        (None, None) => "body".to_string(),
    };
    FieldError { message, field }
}

#[derive(Default)]
struct Report(Vec<FieldError>);

impl Report {
    fn flag(&mut self, field: &str, message: impl Into<String>) {
        self.0.push(FieldError {
            message: message.into(),
            field: field.to_string(),
        });
    }

    fn check<T>(&mut self, field: &str, checked: Result<T, String>) -> Option<T> {
        checked.map_err(|message| self.flag(field, message)).ok()
    }

    fn check_optional<T>(
        &mut self,
        field: &str,
        checked: Option<Result<T, String>>,
    ) -> Option<Option<T>> {
        checked.map_or(Some(None), |checked| self.check(field, checked).map(Some))
    }
}

struct Hex<const N: usize>([u8; N]);

impl<const N: usize> TryFrom<&str> for Hex<N> {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        let mut bytes = [0u8; N];
        value
            .strip_prefix("0x")
            .filter(|digits| digits.len() == 2 * N)
            .and_then(|digits| hex::decode_to_slice(digits, &mut bytes).ok())
            .map(|()| Self(bytes))
            .ok_or_else(|| format!("Must be a hexadecimal string of exactly {N} bytes."))
    }
}

impl<const N: usize> From<Hex<N>> for Vec<u8> {
    fn from(hex: Hex<N>) -> Self {
        hex.0.to_vec()
    }
}

struct RingVrfKey(Vec<u8>);

impl TryFrom<&str> for RingVrfKey {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        let digits = value.strip_prefix("0x").unwrap_or(value);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(must_match(PATTERN_HEX_STRING));
        }
        // An odd digit count matches the pattern but is not whole bytes. It
        // decodes to an empty key, as it always has, and the candidate
        // signature is then checked against that empty key.
        Ok(Self(hex::decode(digits).unwrap_or_default()))
    }
}

struct BaseName(String);

impl TryFrom<&str> for BaseName {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        if value.len() >= 6 && value.bytes().all(|b| b.is_ascii_lowercase()) {
            Ok(Self(value.to_string()))
        } else {
            Err(must_match(PATTERN_BASE))
        }
    }
}

impl BaseName {
    fn bounded(
        value: &str,
        max_len: usize,
        too_long: impl FnOnce() -> String,
    ) -> Result<Self, String> {
        let name = Self::try_from(value)?;
        if name.0.len() > max_len {
            return Err(too_long());
        }
        Ok(name)
    }
}

struct PreferredDigits(u8);

impl TryFrom<&str> for PreferredDigits {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, String> {
        match value.as_bytes() {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] if [*tens, *ones] != *b"00" => {
                Ok(Self((tens - b'0') * 10 + (ones - b'0')))
            }
            _ => Err(MSG_DIGITS.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PayloadVersion {
    V1,
}

impl TryFrom<u16> for PayloadVersion {
    type Error = String;

    fn try_from(version: u16) -> Result<Self, String> {
        match version {
            1 => Ok(Self::V1),
            _ => Err("Unsupported payload version. Supported: 1.".to_string()),
        }
    }
}

impl From<PayloadVersion> for u16 {
    fn from(version: PayloadVersion) -> Self {
        match version {
            PayloadVersion::V1 => 1,
        }
    }
}

fn default_payload_version() -> u16 {
    1
}

/// The fully-validated registration request, decoded.
pub(super) struct ParsedRegister {
    pub(super) candidate_account_id: String,
    pub(super) username: String,
    pub(super) preferred_digits: Option<u8>,
    pub(super) candidate_signature: Vec<u8>,
    pub(super) ring_vrf_key: Vec<u8>,
    pub(super) proof_of_ownership: Vec<u8>,
    pub(super) consumer_registration_signature: Vec<u8>,
    pub(super) identifier_key: Vec<u8>,
    pub(super) payload_version: PayloadVersion,
    pub(super) voucher: Option<String>,
    pub(super) dotns: Option<ParsedDotns>,
}

pub(super) struct ParsedDotns {
    pub(super) signature: Vec<u8>,
    pub(super) signed_at: i64,
    pub(super) reserved_username: Option<String>,
}

pub(super) fn reserved_name(parsed: &ParsedRegister) -> Option<&str> {
    parsed.dotns.as_ref()?.reserved_username.as_deref()
}

impl Dotns {
    fn validate(&self, config: &Config, r: &mut Report) -> Option<ParsedDotns> {
        let signature = r.check("dotns.signature", Hex::<64>::try_from(&*self.signature));
        let signed_at = r.check(
            "dotns.signedAt",
            match self.signed_at {
                ..0 => Err("must be greater than or equal to 0".to_string()),
                signed_at => Ok(signed_at),
            },
        );
        let reserved_username = r.check_optional(
            "dotns.reservedUsername",
            self.reserved_username.as_deref().map(|name| {
                BaseName::bounded(name, MAX_DOTNS_LABEL_LEN, || {
                    format!(
                        "reservedUsername exceeds the maximum label length: \
                         ({MAX_DOTNS_LABEL_LEN})."
                    )
                })
            }),
        );

        if let Some(signed_at) = signed_at {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let skew = config.dotns_max_future_skew_secs as i64;
            let max_age = config.dotns_intake_freshness_max_age_secs as i64;
            if signed_at > now + skew {
                r.flag(
                    "dotns.signedAt",
                    format!("signedAt is in the future (tolerance {skew}s)."),
                );
            }
            if now - signed_at > max_age {
                r.flag(
                    "dotns.signedAt",
                    format!(
                        "signedAt is older than the intake freshness bound ({max_age}s). \
                         Re-sign with a fresh timestamp and resubmit."
                    ),
                );
            }
        }

        Some(ParsedDotns {
            signature: signature?.into(),
            signed_at: signed_at?,
            reserved_username: reserved_username?.map(|BaseName(name)| name),
        })
    }
}

impl RegisterRequest {
    fn validate(
        &self,
        config: &Config,
        signature_form: &AccountSignatureForm,
    ) -> Result<ParsedRegister, Vec<FieldError>> {
        let mut report = Report::default();
        let r = &mut report;

        let candidate = r.check(
            "candidateAccountId",
            AccountId32::from_str(&self.candidate_account_id)
                .map_err(|_| MSG_INVALID_SS58.to_string()),
        );
        let username = r.check(
            "username",
            BaseName::bounded(&self.username, MAX_BASE_LEN, || {
                format!("Username sum exceeds the maximum length: ({MAX_BASE_LEN}).")
            }),
        );
        let preferred_digits = r.check_optional(
            "preferredDigits",
            self.preferred_digits
                .as_deref()
                .map(PreferredDigits::try_from),
        );
        let candidate_signature = r.check(
            "candidateSignature",
            Hex::<64>::try_from(&*self.candidate_signature),
        );
        let ring_vrf_key = r.check("ringVrfKey", RingVrfKey::try_from(&*self.ring_vrf_key));
        let proof_of_ownership = r.check(
            "proofOfOwnership",
            Hex::<64>::try_from(&*self.proof_of_ownership),
        );
        let consumer_registration_signature = r.check(
            "consumerRegistrationSignature",
            Hex::<64>::try_from(&*self.consumer_registration_signature),
        );
        let identifier_key = r.check("identifierKey", Hex::<65>::try_from(&*self.identifier_key));
        let payload_version = r.check(
            "payloadVersion",
            PayloadVersion::try_from(self.payload_version),
        );
        let dotns = match &self.dotns {
            None => Some(None),
            Some(dotns) => dotns.validate(config, r).map(Some),
        };
        let voucher = self
            .lifetime_poud_voucher
            .clone()
            .filter(|voucher| config.registration_vouchers_enabled && !voucher.is_empty());

        // Signature verification is the one costly check, so it runs only
        // for a request that can still succeed.
        if let (true, Some(candidate), Some(signature), Some(ring), Some(version)) = (
            r.0.is_empty(),
            &candidate,
            &candidate_signature,
            &ring_vrf_key,
            payload_version,
        ) {
            if !verify_candidate_signature(
                version,
                &candidate.0,
                &signature.0,
                &ring.0,
                signature_form,
            ) {
                r.flag("candidateSignature", MSG_INVALID_SIGNATURE);
            }
        }

        match (
            candidate,
            username,
            preferred_digits,
            candidate_signature,
            ring_vrf_key,
            proof_of_ownership,
            consumer_registration_signature,
            identifier_key,
            payload_version,
            dotns,
        ) {
            (
                Some(_),
                Some(BaseName(username)),
                Some(preferred_digits),
                Some(candidate_signature),
                Some(RingVrfKey(ring_vrf_key)),
                Some(proof_of_ownership),
                Some(consumer_registration_signature),
                Some(identifier_key),
                Some(payload_version),
                Some(dotns),
            ) if report.0.is_empty() => Ok(ParsedRegister {
                candidate_account_id: self.candidate_account_id.clone(),
                username,
                preferred_digits: preferred_digits.map(|PreferredDigits(digits)| digits),
                candidate_signature: candidate_signature.into(),
                ring_vrf_key,
                proof_of_ownership: proof_of_ownership.into(),
                consumer_registration_signature: consumer_registration_signature.into(),
                identifier_key: identifier_key.into(),
                payload_version,
                voucher,
                dotns,
            }),
            _ => Err(report.0),
        }
    }
}

pub(super) fn validate_register(
    body: &Value,
    config: &Config,
    signature_form: &AccountSignatureForm,
) -> Result<ParsedRegister, UsernamesError> {
    let request =
        RegisterRequest::decode(body).map_err(|error| UsernamesError::InvalidBody(vec![error]))?;
    request
        .validate(config, signature_form)
        .map_err(UsernamesError::InvalidBody)
}

/// Verifies the caller controls `candidate_pubkey`: the candidate's sr25519
/// key signed the `version` message in `signature_form`, the form the People
/// runtime accepts.
fn verify_candidate_signature(
    version: PayloadVersion,
    candidate_pubkey: &[u8; 32],
    candidate_signature: &[u8],
    ring_vrf_key: &[u8],
    signature_form: &AccountSignatureForm,
) -> bool {
    let message = match version {
        PayloadVersion::V1 => candidate_message(candidate_pubkey, ring_vrf_key),
    };
    verify_account_signature(
        candidate_signature,
        &message,
        candidate_pubkey,
        signature_form,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> crate::config::Config {
        crate::config::Config::test_default()
    }

    fn valid_body() -> serde_json::Value {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key();
        let ring = [7u8; 32];
        let signature = keypair.sign(&candidate_message(&candidate.0, &ring)).0;

        json!({
            "candidateAccountId": candidate.to_account_id().to_string(),
            "username": "aliceuser",
            "candidateSignature": format!("0x{}", hex::encode(signature)),
            "ringVrfKey": format!("0x{}", hex::encode(ring)),
            "proofOfOwnership": format!("0x{}", "03".repeat(64)),
            "consumerRegistrationSignature": format!("0x{}", "04".repeat(64)),
            "identifierKey": format!("0x{}", "05".repeat(65))
        })
    }

    fn validate(
        value: &serde_json::Value,
        config: &Config,
    ) -> Result<ParsedRegister, UsernamesError> {
        validate_register(value, config, &AccountSignatureForm::Plain)
    }

    fn errors_of(value: serde_json::Value) -> Vec<(String, String)> {
        match validate(&value, &config()) {
            Err(UsernamesError::InvalidBody(errors)) => {
                errors.into_iter().map(|e| (e.field, e.message)).collect()
            }
            other => panic!("expected InvalidBody, got {other:?}", other = other.err()),
        }
    }

    fn fields_of(value: serde_json::Value) -> Vec<String> {
        errors_of(value)
            .into_iter()
            .map(|(field, _)| field)
            .collect()
    }

    #[test]
    fn accepts_a_genuinely_signed_request() {
        let parsed = validate(&valid_body(), &config()).expect("valid");
        assert_eq!(parsed.username, "aliceuser");
        assert_eq!(parsed.candidate_signature.len(), 64);
    }

    #[test]
    fn a_missing_field_is_a_structural_error_naming_it() {
        assert_eq!(
            errors_of(json!({})),
            [(
                "candidateAccountId".to_string(),
                "missing field `candidateAccountId`".to_string()
            )]
        );

        let mut body = valid_body();
        body["dotns"] = json!({ "signature": format!("0x{}", "ab".repeat(64)) });
        assert_eq!(
            errors_of(body),
            [(
                "dotns.signedAt".to_string(),
                "missing field `signedAt`".to_string()
            )]
        );
    }

    #[test]
    fn wrong_signature_is_a_400_with_the_captured_message() {
        let mut body = valid_body();
        body["candidateSignature"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [(
                "candidateSignature".to_string(),
                "Invalid signature.".to_string()
            )]
        );
    }

    #[test]
    fn pattern_failed_signature_is_a_400() {
        for bad in ["nothex", &format!("0x{}", "ab".repeat(63))] {
            let mut body = valid_body();
            body["candidateSignature"] = json!(bad);
            assert_eq!(
                errors_of(body),
                [(
                    "candidateSignature".to_string(),
                    "Must be a hexadecimal string of exactly 64 bytes.".to_string()
                )],
                "{bad}"
            );
        }
    }

    #[test]
    fn abort_fields_suppress_the_refinement() {
        let mut body = valid_body();
        body["ringVrfKey"] = json!("nothex!");
        assert_eq!(
            errors_of(body),
            [(
                "ringVrfKey".to_string(),
                http_common::error::must_match(PATTERN_HEX_STRING)
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("Abcdef");
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                http_common::error::must_match(PATTERN_BASE)
            )]
        );
    }

    #[test]
    fn a_wrong_type_stops_at_that_field() {
        let mut body = valid_body();
        body["username"] = json!(6);
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                "invalid type: integer `6`, expected a string".to_string()
            )]
        );

        let mut body = valid_body();
        body["username"] = json!(6);
        body["identifierKey"] = json!(7);
        assert_eq!(
            errors_of(body).len(),
            1,
            "decoding stops at the first mismatch"
        );

        assert_eq!(
            fields_of(json!(["not", "an", "object"])),
            ["body".to_string()]
        );
    }

    #[test]
    fn widevine_evidence_checks_types_even_when_disabled() {
        for (field, value, expected_field) in [
            ("attestationChain", json!(42), "attestationChain"),
            ("attestationChain", json!([42]), "attestationChain[0]"),
            ("deviceChallenge", json!(42), "deviceChallenge"),
            ("deviceId", json!(42), "deviceId"),
        ] {
            let mut body = valid_body();
            body[field] = value;
            assert_eq!(fields_of(body), [expected_field]);
        }

        for evidence in [
            json!(null),
            json!({
                "attestationChain": null,
                "deviceChallenge": null,
                "deviceId": null,
            }),
            json!({
                "attestationChain": ["leaf", "root"],
                "deviceChallenge": "challenge",
                "deviceId": "device",
            }),
        ] {
            let mut body = valid_body();
            if let Some(fields) = evidence.as_object() {
                body.as_object_mut().unwrap().extend(fields.clone());
            }
            assert!(validate(&body, &config()).is_ok());
        }
    }

    #[test]
    fn semantic_failures_are_all_reported_at_once() {
        let mut body = valid_body();
        body["candidateAccountId"] = json!("not-an-address");
        body["username"] = json!("Abcdef");
        body["preferredDigits"] = json!("00");
        body["identifierKey"] = json!("0x00");
        body["dotns"] = json!({ "signature": "0x00", "signedAt": -1 });
        assert_eq!(
            fields_of(body),
            [
                "candidateAccountId",
                "username",
                "preferredDigits",
                "identifierKey",
                "dotns.signature",
                "dotns.signedAt",
            ]
        );
    }

    #[test]
    fn refinement_issues_use_the_captured_messages() {
        let mut body = valid_body();
        body["candidateAccountId"] = json!("not-an-address");
        assert_eq!(
            errors_of(body),
            [(
                "candidateAccountId".to_string(),
                "Invalid ss58 address.".to_string()
            )]
        );

        let mut body = valid_body();
        body["username"] = json!("a".repeat(30));
        assert_eq!(
            errors_of(body),
            [(
                "username".to_string(),
                "Username sum exceeds the maximum length: (29).".to_string()
            )]
        );
    }

    #[test]
    fn preferred_digits_and_identifier_checks_collect_in_field_order() {
        let mut body = valid_body();
        body["preferredDigits"] = json!("00");
        body["identifierKey"] = json!(format!("0x{}", "ab".repeat(64)));
        assert_eq!(
            errors_of(body),
            [
                (
                    "preferredDigits".to_string(),
                    "Digits must be between 01-99".to_string()
                ),
                (
                    "identifierKey".to_string(),
                    "Must be a hexadecimal string of exactly 65 bytes.".to_string()
                ),
            ]
        );
    }

    #[test]
    fn dotns_freshness_uses_the_captured_messages() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let enabled = config();
        let mut future = valid_body();
        future["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now + 700 });
        assert_eq!(
            match validate(&future, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is in the future (tolerance 600s)."
        );

        let mut stale = valid_body();
        stale["dotns"] =
            json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now - 700 });
        assert_eq!(
            match validate(&stale, &enabled) {
                Err(UsernamesError::InvalidBody(errors)) => errors[0].message.clone(),
                other => panic!("{other:?}", other = other.err()),
            },
            "signedAt is older than the intake freshness bound (600s). \
             Re-sign with a fresh timestamp and resubmit."
        );

        let mut valid = valid_body();
        valid["dotns"] = dotns_block(now, Some("reservedname"), &enabled);
        let parsed = validate(&valid, &enabled).expect("valid dotns");
        let dotns = parsed.dotns.expect("dotns parsed");
        assert_eq!(dotns.reserved_username.as_deref(), Some("reservedname"));
    }

    #[test]
    fn only_a_claim_that_asks_for_the_full_name_is_preflighted() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let plain = validate(&valid_body(), &config).expect("valid");
        assert_eq!(
            reserved_name(&plain),
            None,
            "no dotns block means no reservation leg"
        );

        let mut without = valid_body();
        without["dotns"] = dotns_block(now, None, &config);
        assert_eq!(
            reserved_name(&validate(&without, &config).expect("valid")),
            None
        );

        let mut with = valid_body();
        with["dotns"] = dotns_block(now, Some("aliceuser"), &config);
        assert_eq!(
            reserved_name(&validate(&with, &config).expect("valid")),
            Some("aliceuser")
        );
    }

    #[test]
    fn the_reserved_name_is_read_from_the_dotns_block_not_the_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut body = valid_body();
        assert_eq!(body["username"], json!("aliceuser"));
        body["dotns"] = dotns_block(now, Some("reservedname"), &config);

        let parsed = validate(&body, &config).expect("valid");
        assert_eq!(reserved_name(&parsed), Some("reservedname"));
    }

    fn dotns_block(
        signed_at: i64,
        reserved: Option<&str>,
        config: &crate::config::Config,
    ) -> serde_json::Value {
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let message = crate::dotns::reservation_message(
            &keypair.public_key().0,
            &config.attester_account,
            b"aliceuser",
            &[5u8; 65],
            reserved.map(str::as_bytes),
            signed_at as u64,
        );
        let mut block = json!({
            "signature": format!("0x{}", hex::encode(keypair.sign(&message).0)),
            "signedAt": signed_at,
        });
        if let Some(reserved) = reserved {
            block["reservedUsername"] = json!(reserved);
        }
        block
    }

    #[test]
    fn an_unverifiable_dotns_signature_still_yields_a_username() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut junk = valid_body();
        junk["dotns"] = json!({ "signature": format!("0x{}", "ab".repeat(64)), "signedAt": now });
        let parsed = validate(&junk, &config).expect("junk dotns signature is accepted");
        assert_eq!(parsed.username, "aliceuser");
        assert!(
            parsed.dotns.is_some(),
            "the block is stored, so the writer decides its fate"
        );

        let mut other_attester = self::config();
        other_attester.attester_account = [0xbb; 32];
        let mut wrong = valid_body();
        wrong["dotns"] = dotns_block(now, None, &other_attester);
        assert!(validate(&wrong, &config).is_ok());

        let mut reserved_mismatch = valid_body();
        let mut block = dotns_block(now, Some("reservedname"), &config);
        block.as_object_mut().unwrap().remove("reservedUsername");
        reserved_mismatch["dotns"] = block;
        assert!(validate(&reserved_mismatch, &config).is_ok());
    }

    #[test]
    fn a_malformed_dotns_block_is_still_rejected() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let mut too_long = valid_body();
        too_long["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now,
            "reservedUsername": "x".repeat(MAX_DOTNS_LABEL_LEN + 1),
        });
        assert_eq!(
            errors_of(too_long)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.reservedUsername".to_string()]
        );

        let mut stale = valid_body();
        stale["dotns"] = json!({
            "signature": format!("0x{}", "ab".repeat(64)),
            "signedAt": now - 86_400,
        });
        assert_eq!(
            errors_of(stale)
                .into_iter()
                .map(|(pointer, _)| pointer)
                .collect::<Vec<_>>(),
            ["dotns.signedAt".to_string()]
        );
    }

    #[test]
    fn an_oversized_reserved_username_is_rejected_before_the_signature_check() {
        let config = config();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let oversized = "a".repeat(MAX_DOTNS_LABEL_LEN + 1);

        let mut body = valid_body();
        body["dotns"] = dotns_block(now, Some(&oversized), &config);
        assert_eq!(
            errors_of(body),
            [(
                "dotns.reservedUsername".to_string(),
                format!(
                    "reservedUsername exceeds the maximum label length: ({MAX_DOTNS_LABEL_LEN})."
                )
            )]
        );

        let mut at_bound = valid_body();
        let exact = "a".repeat(MAX_DOTNS_LABEL_LEN);
        at_bound["dotns"] = dotns_block(now, Some(&exact), &config);
        assert!(validate(&at_bound, &config).is_ok());
    }

    #[test]
    fn voucher_field_is_ignored_when_the_feature_is_off() {
        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate(&body, &config()).expect("valid");
        assert_eq!(parsed.voucher, None);

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!(42);
        assert_eq!(fields_of(body), ["lifetimePoUDVoucher"]);
    }

    #[test]
    fn voucher_field_is_recognised_when_the_feature_is_on() {
        let mut on = config();
        on.registration_vouchers_enabled = true;

        let mut body = valid_body();
        body["lifetimePoUDVoucher"] = json!("some-voucher-key");
        let parsed = validate(&body, &on).expect("valid");
        assert_eq!(parsed.voucher.as_deref(), Some("some-voucher-key"));

        assert_eq!(validate(&valid_body(), &on).unwrap().voucher, None);
        let mut empty = valid_body();
        empty["lifetimePoUDVoucher"] = json!("");
        assert_eq!(validate(&empty, &on).unwrap().voucher, None);
    }

    #[test]
    fn an_undeclared_payload_version_is_format_one() {
        let parsed = validate(&valid_body(), &config()).expect("valid");
        assert_eq!(parsed.payload_version, PayloadVersion::V1);

        let mut declared = valid_body();
        declared["payloadVersion"] = json!(1);
        let parsed = validate(&declared, &config()).expect("valid");
        assert_eq!(parsed.payload_version, PayloadVersion::V1);
    }

    #[test]
    fn an_unsupported_payload_version_is_a_400_not_an_invalid_signature() {
        for version in [0, 2] {
            let mut body = valid_body();
            body["payloadVersion"] = json!(version);
            assert_eq!(
                errors_of(body),
                [(
                    "payloadVersion".to_string(),
                    "Unsupported payload version. Supported: 1.".to_string()
                )]
            );
        }
    }

    #[test]
    fn a_payload_version_outside_u16_is_a_type_error() {
        for version in [
            json!("1"),
            json!(1.5),
            json!(null),
            json!(-1),
            json!(65_536),
        ] {
            let mut body = valid_body();
            body["payloadVersion"] = version.clone();
            assert_eq!(fields_of(body), ["payloadVersion"], "{version}");
        }
    }

    #[test]
    fn candidate_signature_verifies_control_of_beneficiary() {
        use std::str::FromStr as _;
        use subxt_signer::sr25519::Keypair;
        use subxt_signer::SecretUri;

        let keypair = Keypair::from_uri(&SecretUri::from_str("//Alice").unwrap()).unwrap();
        let candidate = keypair.public_key().0;
        let ring_vrf_key = [7u8; 32];
        let signature = keypair
            .sign(&candidate_message(&candidate, &ring_vrf_key))
            .0;

        let plain = AccountSignatureForm::Plain;
        assert!(verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &signature,
            &ring_vrf_key,
            &plain
        ));
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &signature,
            &[9u8; 32],
            &plain
        ));
        let other = Keypair::from_uri(&SecretUri::from_str("//Bob").unwrap())
            .unwrap()
            .public_key()
            .0;
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &other,
            &signature,
            &ring_vrf_key,
            &plain
        ));
        assert!(!verify_candidate_signature(
            PayloadVersion::V1,
            &candidate,
            &[0u8; 10],
            &ring_vrf_key,
            &plain
        ));
    }
}
