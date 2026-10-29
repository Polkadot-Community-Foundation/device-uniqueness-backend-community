// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

const APPLE_APP_ATTESTATION_ROOT_CA_B64: &str = "\
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\
oyFraWVIyd/dganmrduC1bmTBGwD";

/// The cred-cert extension carrying the expected attestation nonce.
const APPLE_APP_ATTEST_NONCE_OID: &str = "1.2.840.113635.100.8.2";

/// AAGUID for production App Attest keys: `"appattest"` padded with 7 zeroes.
const PROD_AAGUID: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
/// AAGUID for development-environment App Attest keys.
const DEV_AAGUID: [u8; 16] = *b"appattestdevelop";

pub fn apple_root_ca_der() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(APPLE_APP_ATTESTATION_ROOT_CA_B64)
        .expect("pinned root CA decodes")
}

/// Why an attestation or assertion was rejected.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("malformed attestation payload: {0}")]
    Malformed(String),
    #[error("certificate chain rejected: {0}")]
    Chain(String),
    #[error("attestation nonce mismatch")]
    Nonce,
    #[error("key id mismatch")]
    KeyId,
    #[error("no configured App ID matches rpIdHash")]
    AppId,
    #[error("attestation counter is not 0")]
    Counter,
    #[error("unrecognized AAGUID")]
    Aaguid,
    #[error("assertion signature invalid")]
    Signature,
    #[error("assertion sign count did not increase")]
    SignCount,
}

pub struct AttestedKey {
    pub public_key: Vec<u8>,
    pub receipt: Vec<u8>,
}

pub fn verify_attestation(
    attestation: &[u8],
    challenge: &[u8],
    key_id: &[u8],
    app_ids: &[String],
    trusted_root_der: &[u8],
    now_unix: i64,
) -> Result<AttestedKey, AttestError> {
    let doc = decode_attestation(attestation)?;
    let auth = AuthenticatorData::parse(&doc.auth_data)?;

    let (_, root) = X509Certificate::from_der(trusted_root_der)
        .map_err(|e| AttestError::Malformed(format!("root cert: {e}")))?;
    let (_, cred) = X509Certificate::from_der(&doc.cred_cert)
        .map_err(|e| AttestError::Malformed(format!("cred cert: {e}")))?;
    let (_, intermediate) = X509Certificate::from_der(&doc.intermediate_cert)
        .map_err(|e| AttestError::Malformed(format!("intermediate cert: {e}")))?;

    verify_cert(&cred, &intermediate, now_unix)?;
    verify_cert(&intermediate, &root, now_unix)?;

    let mut hasher = Sha256::new();
    hasher.update(&doc.auth_data);
    hasher.update(Sha256::digest(challenge));
    let nonce = hasher.finalize();

    let extension = cred
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == APPLE_APP_ATTEST_NONCE_OID)
        .ok_or(AttestError::Nonce)?;
    let expected = extension
        .value
        .len()
        .checked_sub(32)
        .map(|start| &extension.value[start..])
        .ok_or(AttestError::Nonce)?;
    if expected != nonce.as_slice() {
        return Err(AttestError::Nonce);
    }

    let public_key = cred.public_key().subject_public_key.data.to_vec();
    if Sha256::digest(&public_key).as_slice() != key_id {
        return Err(AttestError::KeyId);
    }
    if auth.credential_id.as_deref() != Some(key_id) {
        return Err(AttestError::KeyId);
    }

    check_app_id(&auth.rp_id_hash, app_ids)?;
    if auth.counter != 0 {
        return Err(AttestError::Counter);
    }
    if auth.aaguid != Some(PROD_AAGUID) && auth.aaguid != Some(DEV_AAGUID) {
        return Err(AttestError::Aaguid);
    }

    Ok(AttestedKey {
        public_key,
        receipt: doc.receipt,
    })
}

pub fn verify_assertion(
    assertion: &[u8],
    client_data_hash: &[u8; 32],
    public_key: &[u8],
    app_ids: &[String],
    prev_sign_count: i64,
) -> Result<i64, AttestError> {
    let (signature_der, auth_data) = decode_assertion(assertion)?;
    let auth = AuthenticatorData::parse(&auth_data)?;

    let mut hasher = Sha256::new();
    hasher.update(&auth_data);
    hasher.update(client_data_hash);
    let nonce = hasher.finalize();

    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| AttestError::Malformed(format!("stored public key: {e}")))?;
    let signature =
        p256::ecdsa::Signature::from_der(&signature_der).map_err(|_| AttestError::Signature)?;
    // Apple signs the nonce as a *message*, so ES256 hashes it again: the signed
    // digest is `SHA256(nonce)`. Verify over the nonce bytes (which re-hashes),
    // not `verify_prehash` (which would treat the nonce as the final digest and
    // reject every genuine assertion).
    key.verify(&nonce, &signature)
        .map_err(|_| AttestError::Signature)?;

    check_app_id(&auth.rp_id_hash, app_ids)?;

    let next = i64::from(auth.counter);
    if next <= prev_sign_count {
        return Err(AttestError::SignCount);
    }
    Ok(next)
}

struct AttestationDoc {
    cred_cert: Vec<u8>,
    intermediate_cert: Vec<u8>,
    receipt: Vec<u8>,
    auth_data: Vec<u8>,
}

/// Decode the CBOR attestation object into its envelope parts.
fn decode_attestation(bytes: &[u8]) -> Result<AttestationDoc, AttestError> {
    let value: ciborium::Value =
        ciborium::from_reader(bytes).map_err(|e| AttestError::Malformed(format!("cbor: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| AttestError::Malformed("attestation is not a map".into()))?;

    let fmt = map_get(map, "fmt")
        .and_then(ciborium::Value::as_text)
        .ok_or_else(|| AttestError::Malformed("missing fmt".into()))?;
    if fmt != "apple-appattest" {
        return Err(AttestError::Malformed(format!("unexpected fmt {fmt:?}")));
    }
    let att_stmt = map_get(map, "attStmt")
        .and_then(ciborium::Value::as_map)
        .ok_or_else(|| AttestError::Malformed("missing attStmt".into()))?;
    let auth_data = map_get(map, "authData")
        .and_then(ciborium::Value::as_bytes)
        .ok_or_else(|| AttestError::Malformed("missing authData".into()))?;
    let receipt = map_get(att_stmt, "receipt")
        .and_then(ciborium::Value::as_bytes)
        .ok_or_else(|| AttestError::Malformed("missing receipt".into()))?;
    let x5c = map_get(att_stmt, "x5c")
        .and_then(ciborium::Value::as_array)
        .ok_or_else(|| AttestError::Malformed("missing x5c".into()))?;

    let [cred, intermediate] = x5c.as_slice() else {
        return Err(AttestError::Malformed(format!(
            "x5c has {} certificates, expected exactly 2",
            x5c.len()
        )));
    };
    let cred_cert = cred
        .as_bytes()
        .cloned()
        .ok_or_else(|| AttestError::Malformed("x5c entry is not bytes".into()))?;
    let intermediate_cert = intermediate
        .as_bytes()
        .cloned()
        .ok_or_else(|| AttestError::Malformed("x5c entry is not bytes".into()))?;

    Ok(AttestationDoc {
        cred_cert,
        intermediate_cert,
        receipt: receipt.clone(),
        auth_data: auth_data.clone(),
    })
}

/// Decode the CBOR assertion into `(signature DER, authenticatorData)`.
fn decode_assertion(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
    let value: ciborium::Value =
        ciborium::from_reader(bytes).map_err(|e| AttestError::Malformed(format!("cbor: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| AttestError::Malformed("assertion is not a map".into()))?;
    let signature = map_get(map, "signature")
        .and_then(ciborium::Value::as_bytes)
        .ok_or_else(|| AttestError::Malformed("missing signature".into()))?;
    let auth_data = map_get(map, "authenticatorData")
        .and_then(ciborium::Value::as_bytes)
        .ok_or_else(|| AttestError::Malformed("missing authenticatorData".into()))?;
    Ok((signature.clone(), auth_data.clone()))
}

fn map_get<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Parsed WebAuthn-style authenticator data.
struct AuthenticatorData {
    rp_id_hash: [u8; 32],
    counter: u32,
    /// Present only in attestations (assertions stop after the counter).
    aaguid: Option<[u8; 16]>,
    credential_id: Option<Vec<u8>>,
}

impl AuthenticatorData {
    fn parse(data: &[u8]) -> Result<Self, AttestError> {
        if data.len() < 37 {
            return Err(AttestError::Malformed(
                "authenticator data too short".into(),
            ));
        }
        let rp_id_hash: [u8; 32] = data[0..32].try_into().expect("32-byte slice");
        let counter = u32::from_be_bytes(data[33..37].try_into().expect("4-byte slice"));

        let (aaguid, credential_id) = if data.len() >= 55 {
            let aaguid: [u8; 16] = data[37..53].try_into().expect("16-byte slice");
            let len = usize::from(u16::from_be_bytes(
                data[53..55].try_into().expect("2-byte slice"),
            ));
            let credential_id = data
                .get(55..55 + len)
                .ok_or_else(|| AttestError::Malformed("credential id out of bounds".into()))?;
            (Some(aaguid), Some(credential_id.to_vec()))
        } else {
            (None, None)
        };

        Ok(Self {
            rp_id_hash,
            counter,
            aaguid,
            credential_id,
        })
    }
}

fn check_app_id(rp_id_hash: &[u8; 32], app_ids: &[String]) -> Result<(), AttestError> {
    let matched = app_ids
        .iter()
        .any(|app_id| Sha256::digest(app_id.as_bytes()).as_slice() == rp_id_hash);
    if matched {
        Ok(())
    } else {
        Err(AttestError::AppId)
    }
}

fn verify_cert(
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
    now_unix: i64,
) -> Result<(), AttestError> {
    crate::auth::x509::check_validity(child, now_unix).map_err(AttestError::Chain)?;
    crate::auth::x509::verify_signed_by(child, parent).map_err(AttestError::Chain)
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer as _;
    use p256::elliptic_curve::Generate as _;
    use rcgen::{BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa, KeyPair};

    use super::*;

    const APP_ID: &str = "27CAKE44.io.pcf.polkadotapp";

    fn app_ids() -> Vec<String> {
        vec![APP_ID.to_string()]
    }

    fn attestation_auth_data(
        app_id: &str,
        counter: u32,
        aaguid: &[u8; 16],
        cred_id: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(app_id.as_bytes()));
        data.push(0x40);
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(aaguid);
        data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        data.extend_from_slice(cred_id);
        data
    }

    fn assertion_auth_data(app_id: &str, counter: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(app_id.as_bytes()));
        data.push(0x40);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    fn cbor_bytes(value: &ciborium::Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).expect("cbor encodes");
        out
    }

    fn assertion_cbor(signature: &[u8], auth_data: &[u8]) -> Vec<u8> {
        cbor_bytes(&ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("signature".into()),
                ciborium::Value::Bytes(signature.to_vec()),
            ),
            (
                ciborium::Value::Text("authenticatorData".into()),
                ciborium::Value::Bytes(auth_data.to_vec()),
            ),
        ]))
    }

    struct TestChain {
        root_der: Vec<u8>,
        int_cert: Certificate,
        int_key: KeyPair,
    }

    impl TestChain {
        fn new() -> Self {
            let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("root key");
            let mut root_params =
                CertificateParams::new(Vec::<String>::new()).expect("root params");
            root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root_cert = root_params.self_signed(&root_key).expect("root cert");

            let int_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("int key");
            let mut int_params = CertificateParams::new(Vec::<String>::new()).expect("int params");
            int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let int_cert = int_params
                .signed_by(&int_key, &root_cert, &root_key)
                .expect("intermediate cert");

            Self {
                root_der: root_cert.der().to_vec(),
                int_cert,
                int_key,
            }
        }

        fn issue_leaf(&self, leaf_key: &KeyPair, nonce: &[u8]) -> Vec<u8> {
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 2, 840, 113635, 100, 8, 2],
                nonce.to_vec(),
            )];
            params
                .signed_by(leaf_key, &self.int_cert, &self.int_key)
                .expect("signed leaf")
                .der()
                .to_vec()
        }

        fn intermediate_der(&self) -> Vec<u8> {
            self.int_cert.der().to_vec()
        }
    }

    struct BuiltAttestation {
        attestation: Vec<u8>,
        key_id: Vec<u8>,
        challenge: Vec<u8>,
        root_der: Vec<u8>,
        public_key: Vec<u8>,
    }

    fn build_attestation(aaguid: &[u8; 16], counter: u32) -> BuiltAttestation {
        let chain = TestChain::new();
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let public_key = leaf_key.public_key_raw().to_vec();
        let key_id = Sha256::digest(&public_key).to_vec();
        let challenge = b"attestation-challenge".to_vec();

        let auth_data = attestation_auth_data(APP_ID, counter, aaguid, &key_id);
        let mut hasher = Sha256::new();
        hasher.update(&auth_data);
        hasher.update(Sha256::digest(&challenge));
        let nonce = hasher.finalize();

        let leaf_der = chain.issue_leaf(&leaf_key, &nonce);
        let attestation = cbor_bytes(&ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("apple-appattest".into()),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("x5c".into()),
                        ciborium::Value::Array(vec![
                            ciborium::Value::Bytes(leaf_der),
                            ciborium::Value::Bytes(chain.intermediate_der()),
                        ]),
                    ),
                    (
                        ciborium::Value::Text("receipt".into()),
                        ciborium::Value::Bytes(b"receipt".to_vec()),
                    ),
                ]),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(auth_data),
            ),
        ]));

        BuiltAttestation {
            attestation,
            key_id,
            challenge,
            root_der: chain.root_der,
            public_key,
        }
    }

    #[test]
    fn attestation_envelope_shape_is_pinned() {
        let built = build_attestation(&DEV_AAGUID, 0);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let ids = app_ids();

        type CborMap = Vec<(ciborium::Value, ciborium::Value)>;
        let mutate = |f: &mut dyn FnMut(&mut CborMap)| {
            let mut value: ciborium::Value =
                ciborium::from_reader(built.attestation.as_slice()).expect("decodes");
            let map = match &mut value {
                ciborium::Value::Map(map) => map,
                _ => panic!("attestation is a map"),
            };
            f(map);
            cbor_bytes(&value)
        };

        let foreign_fmt = mutate(&mut |map| {
            for (k, v) in map.iter_mut() {
                if k.as_text() == Some("fmt") {
                    *v = ciborium::Value::Text("android-key".into());
                }
            }
        });
        assert!(matches!(
            verify_attestation(
                &foreign_fmt,
                &built.challenge,
                &built.key_id,
                &ids,
                &built.root_der,
                now
            ),
            Err(AttestError::Malformed(_))
        ));

        let extra_cert = mutate(&mut |map| {
            for (k, v) in map.iter_mut() {
                if k.as_text() == Some("attStmt") {
                    let ciborium::Value::Map(stmt) = v else {
                        panic!("attStmt map")
                    };
                    for (sk, sv) in stmt.iter_mut() {
                        if sk.as_text() == Some("x5c") {
                            let ciborium::Value::Array(certs) = sv else {
                                panic!("x5c array")
                            };
                            certs.push(ciborium::Value::Bytes(vec![1, 2, 3]));
                        }
                    }
                }
            }
        });
        assert!(matches!(
            verify_attestation(
                &extra_cert,
                &built.challenge,
                &built.key_id,
                &ids,
                &built.root_der,
                now
            ),
            Err(AttestError::Malformed(_))
        ));
    }

    #[test]
    fn attestation_verifies_against_its_root() {
        let built = build_attestation(&DEV_AAGUID, 0);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        let attested = verify_attestation(
            &built.attestation,
            &built.challenge,
            &built.key_id,
            &app_ids(),
            &built.root_der,
            now,
        )
        .expect("valid attestation");
        assert_eq!(attested.public_key, built.public_key);
        assert_eq!(attested.receipt, b"receipt");
    }

    #[test]
    fn attestation_rejects_each_broken_invariant() {
        let built = build_attestation(&DEV_AAGUID, 0);
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let ids = app_ids();

        assert!(matches!(
            verify_attestation(
                &built.attestation,
                b"other",
                &built.key_id,
                &ids,
                &built.root_der,
                now
            ),
            Err(AttestError::Nonce)
        ));
        assert!(matches!(
            verify_attestation(
                &built.attestation,
                &built.challenge,
                &[9u8; 32],
                &ids,
                &built.root_der,
                now
            ),
            Err(AttestError::KeyId)
        ));
        assert!(matches!(
            verify_attestation(
                &built.attestation,
                &built.challenge,
                &built.key_id,
                &["OTHER.app".to_string()],
                &built.root_der,
                now
            ),
            Err(AttestError::AppId)
        ));
        let foreign = TestChain::new();
        assert!(matches!(
            verify_attestation(
                &built.attestation,
                &built.challenge,
                &built.key_id,
                &ids,
                &foreign.root_der,
                now
            ),
            Err(AttestError::Chain(_))
        ));
        let past = 0;
        assert!(matches!(
            verify_attestation(
                &built.attestation,
                &built.challenge,
                &built.key_id,
                &ids,
                &built.root_der,
                past
            ),
            Err(AttestError::Chain(_))
        ));
    }

    #[test]
    fn attestation_rejects_nonzero_counter_and_bad_aaguid() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let ids = app_ids();

        let counter = build_attestation(&DEV_AAGUID, 3);
        assert!(matches!(
            verify_attestation(
                &counter.attestation,
                &counter.challenge,
                &counter.key_id,
                &ids,
                &counter.root_der,
                now
            ),
            Err(AttestError::Counter)
        ));

        let aaguid = build_attestation(b"not-app-attest!!", 0);
        assert!(matches!(
            verify_attestation(
                &aaguid.attestation,
                &aaguid.challenge,
                &aaguid.key_id,
                &ids,
                &aaguid.root_der,
                now
            ),
            Err(AttestError::Aaguid)
        ));
    }

    #[test]
    fn assertion_verifies_and_rejects_tampering() {
        let signing = p256::ecdsa::SigningKey::generate();
        let public_key = signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let client_data_hash = [7u8; 32];
        let auth_data = assertion_auth_data(APP_ID, 5);
        let mut hasher = Sha256::new();
        hasher.update(&auth_data);
        hasher.update(client_data_hash);
        let nonce = hasher.finalize();

        let signature: p256::ecdsa::Signature = signing.sign(&nonce);
        let assertion = assertion_cbor(signature.to_der().as_bytes(), &auth_data);

        let next = verify_assertion(&assertion, &client_data_hash, &public_key, &app_ids(), 0)
            .expect("valid assertion");
        assert_eq!(next, 5);

        assert!(matches!(
            verify_assertion(&assertion, &client_data_hash, &public_key, &app_ids(), 5),
            Err(AttestError::SignCount)
        ));

        assert!(matches!(
            verify_assertion(&assertion, &[8u8; 32], &public_key, &app_ids(), 0),
            Err(AttestError::Signature)
        ));

        assert!(matches!(
            verify_assertion(
                &assertion,
                &client_data_hash,
                &public_key,
                &["OTHER.app".to_string()],
                0
            ),
            Err(AttestError::AppId)
        ));
    }

    #[test]
    fn assertion_rejects_prehash_signed_nonce() {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;

        let signing = p256::ecdsa::SigningKey::generate();
        let public_key = signing
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();

        let client_data_hash = [7u8; 32];
        let auth_data = assertion_auth_data(APP_ID, 5);
        let mut hasher = Sha256::new();
        hasher.update(&auth_data);
        hasher.update(client_data_hash);
        let nonce = hasher.finalize();

        let signature: p256::ecdsa::Signature = signing.sign_prehash(&nonce).expect("signs");
        let assertion = assertion_cbor(signature.to_der().as_bytes(), &auth_data);

        assert!(matches!(
            verify_assertion(&assertion, &client_data_hash, &public_key, &app_ids(), 0),
            Err(AttestError::Signature)
        ));
    }
}
