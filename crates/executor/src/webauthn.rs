//! Minimal WebAuthn verification for ES256 (P-256) passkeys.
//!
//! The cryptography is RustCrypto's `p256`/`sha2`; this module only parses the
//! WebAuthn structures and applies the checks from WebAuthn Level 2, §7.1
//! (registration) and §7.2 (authentication). Attestation statements are not
//! verified: trust in a new credential comes from the one-time enrollment
//! token that only a root shell can mint.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ciborium::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub rp_id: String,
    pub origin: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError(msg.into()))
}

pub fn b64decode(s: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| VerifyError("invalid base64url".into()))
}

pub fn b64encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

fn check_client_data(
    rp: &RelyingParty,
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
) -> Result<(), VerifyError> {
    let cd: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| VerifyError("malformed clientDataJSON".into()))?;
    if cd.typ != expected_type {
        return err(format!("clientData type is {:?}, expected {expected_type:?}", cd.typ));
    }
    // The origin is set by the browser, not by page script, so this is what
    // stops a page on another port of the same host (e.g. T3 Code on :443)
    // from producing a usable approval for this rp_id.
    if cd.origin != rp.origin {
        return err(format!("origin {:?} is not the dashboard origin", cd.origin));
    }
    if cd.cross_origin == Some(true) {
        return err("cross-origin ceremony");
    }
    if b64decode(&cd.challenge)? != expected_challenge {
        return err("challenge does not match this request");
    }
    Ok(())
}

struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_auth_data(data: &[u8]) -> Result<AuthData<'_>, VerifyError> {
    if data.len() < 37 {
        return err("authenticatorData too short");
    }
    Ok(AuthData {
        rp_id_hash: &data[..32],
        flags: data[32],
        sign_count: u32::from_be_bytes(data[33..37].try_into().unwrap()),
        rest: &data[37..],
    })
}

fn check_auth_data(rp: &RelyingParty, ad: &AuthData) -> Result<(), VerifyError> {
    if ad.rp_id_hash != &Sha256::digest(rp.rp_id.as_bytes())[..] {
        return err("rpIdHash mismatch");
    }
    if ad.flags & FLAG_UP == 0 {
        return err("user presence flag not set");
    }
    if ad.flags & FLAG_UV == 0 {
        return err("user verification (Face ID / PIN) was not performed");
    }
    Ok(())
}

pub struct NewCredential {
    pub id: Vec<u8>,
    /// SEC1 uncompressed point (0x04 || x || y).
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub fn verify_registration(
    rp: &RelyingParty,
    credential_id_b64: &str,
    client_data_json_b64: &str,
    attestation_object_b64: &str,
    expected_challenge: &[u8],
) -> Result<NewCredential, VerifyError> {
    let client_data = b64decode(client_data_json_b64)?;
    check_client_data(rp, &client_data, "webauthn.create", expected_challenge)?;

    let att_bytes = b64decode(attestation_object_b64)?;
    let att: Value =
        ciborium::from_reader(att_bytes.as_slice()).map_err(|_| VerifyError("malformed attestationObject".into()))?;
    let auth_data = att
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("authData")))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or_else(|| VerifyError("attestationObject has no authData".into()))?;

    let ad = parse_auth_data(auth_data)?;
    check_auth_data(rp, &ad)?;
    if ad.flags & FLAG_AT == 0 {
        return err("no attested credential data");
    }
    let rest = ad.rest;
    if rest.len() < 18 {
        return err("attested credential data too short");
    }
    let id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    let id = rest.get(18..18 + id_len).ok_or_else(|| VerifyError("credential id truncated".into()))?.to_vec();
    if id != b64decode(credential_id_b64)? {
        return err("credential id does not match authenticator data");
    }
    let cose: Value = ciborium::from_reader(&rest[18 + id_len..])
        .map_err(|_| VerifyError("malformed credential public key".into()))?;
    let public_key = cose_es256_to_sec1(&cose)?;
    Ok(NewCredential { id, public_key, sign_count: ad.sign_count })
}

fn cose_es256_to_sec1(cose: &Value) -> Result<Vec<u8>, VerifyError> {
    let map = cose.as_map().ok_or_else(|| VerifyError("COSE key is not a map".into()))?;
    let get = |label: i64| {
        map.iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(label as i128))
            .map(|(_, v)| v)
    };
    let int = |label| get(label).and_then(Value::as_integer).map(i128::from);
    if int(1) != Some(2) || int(3) != Some(-7) || int(-1) != Some(1) {
        return err("only ES256 (P-256) passkeys are supported");
    }
    let x = get(-2).and_then(Value::as_bytes).filter(|b| b.len() == 32);
    let y = get(-3).and_then(Value::as_bytes).filter(|b| b.len() == 32);
    let (Some(x), Some(y)) = (x, y) else { return err("invalid EC2 coordinates") };
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| VerifyError("public key is not on P-256".into()))?;
    Ok(sec1)
}

/// Returns the authenticator's new signature counter on success.
pub fn verify_assertion(
    rp: &RelyingParty,
    public_key_sec1: &[u8],
    stored_sign_count: u32,
    client_data_json_b64: &str,
    authenticator_data_b64: &str,
    signature_b64: &str,
    expected_challenge: &[u8],
) -> Result<u32, VerifyError> {
    let client_data = b64decode(client_data_json_b64)?;
    check_client_data(rp, &client_data, "webauthn.get", expected_challenge)?;

    let auth_data = b64decode(authenticator_data_b64)?;
    let ad = parse_auth_data(&auth_data)?;
    check_auth_data(rp, &ad)?;

    let key = VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| VerifyError("stored key invalid".into()))?;
    let sig = Signature::from_der(&b64decode(signature_b64)?).map_err(|_| VerifyError("malformed signature".into()))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    key.verify(&signed, &sig).map_err(|_| VerifyError("signature verification failed".into()))?;

    // Synced passkeys (iCloud Keychain) always report 0; only enforce the
    // counter when the authenticator actually maintains one.
    if (ad.sign_count != 0 || stored_sign_count != 0) && ad.sign_count <= stored_sign_count {
        return err("signature counter did not increase (possible cloned authenticator)");
    }
    Ok(ad.sign_count)
}

#[cfg(test)]
pub mod testing {
    //! A software authenticator for tests.
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    pub struct SoftAuthenticator {
        pub key: SigningKey,
        pub id: Vec<u8>,
        pub rp_id: String,
        pub counter: u32,
    }

    impl SoftAuthenticator {
        pub fn new(rp_id: &str) -> Self {
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed)).unwrap();
            Self {
                key: SigningKey::from_bytes(&seed.into()).unwrap(),
                id: seed[..16].to_vec(),
                rp_id: rp_id.into(),
                counter: 0,
            }
        }

        pub fn public_sec1(&self) -> Vec<u8> {
            self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
        }

        pub fn client_data(typ: &str, origin: &str, challenge: &[u8]) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "type": typ, "challenge": b64encode(challenge), "origin": origin, "crossOrigin": false
            }))
            .unwrap()
        }

        fn auth_data(&self, flags: u8, extra: &[u8]) -> Vec<u8> {
            let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            ad.push(flags);
            ad.extend_from_slice(&self.counter.to_be_bytes());
            ad.extend_from_slice(extra);
            ad
        }

        /// (clientDataJSON, attestationObject), both base64url.
        pub fn register(&self, origin: &str, challenge: &[u8]) -> (String, String) {
            let point = self.key.verifying_key().to_encoded_point(false);
            let cose = Value::Map(vec![
                (Value::from(1), Value::from(2)),
                (Value::from(3), Value::from(-7)),
                (Value::from(-1), Value::from(1)),
                (Value::from(-2), Value::Bytes(point.x().unwrap().to_vec())),
                (Value::from(-3), Value::Bytes(point.y().unwrap().to_vec())),
            ]);
            let mut extra = vec![0u8; 16];
            extra.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
            extra.extend_from_slice(&self.id);
            ciborium::into_writer(&cose, &mut extra).unwrap();
            let ad = self.auth_data(FLAG_UP | FLAG_UV | FLAG_AT, &extra);
            let att = Value::Map(vec![
                (Value::from("fmt"), Value::from("none")),
                (Value::from("attStmt"), Value::Map(vec![])),
                (Value::from("authData"), Value::Bytes(ad)),
            ]);
            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att, &mut att_bytes).unwrap();
            (b64encode(&Self::client_data("webauthn.create", origin, challenge)), b64encode(&att_bytes))
        }

        /// (clientDataJSON, authenticatorData, signature), all base64url.
        pub fn assert(&self, origin: &str, challenge: &[u8], flags: u8) -> (String, String, String) {
            let cd = Self::client_data("webauthn.get", origin, challenge);
            let ad = self.auth_data(flags, &[]);
            let mut signed = ad.clone();
            signed.extend_from_slice(&Sha256::digest(&cd));
            let sig: Signature = self.key.sign(&signed);
            (b64encode(&cd), b64encode(&ad), b64encode(sig.to_der().as_bytes()))
        }
    }

    pub const UP_UV: u8 = FLAG_UP | FLAG_UV;
    pub const UP_ONLY: u8 = FLAG_UP;
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn rp() -> RelyingParty {
        RelyingParty { rp_id: "pod042.example.ts.net".into(), origin: "https://pod042.example.ts.net:10000".into() }
    }

    #[test]
    fn registration_round_trip() {
        let auth = SoftAuthenticator::new(&rp().rp_id);
        let challenge = [7u8; 32];
        let (cd, att) = auth.register(&rp().origin, &challenge);
        let cred = verify_registration(&rp(), &b64encode(&auth.id), &cd, &att, &challenge).unwrap();
        assert_eq!(cred.public_key, auth.public_sec1());
        assert_eq!(cred.id, auth.id);
    }

    #[test]
    fn registration_with_wrong_challenge_fails() {
        let auth = SoftAuthenticator::new(&rp().rp_id);
        let (cd, att) = auth.register(&rp().origin, &[1u8; 32]);
        assert!(verify_registration(&rp(), &b64encode(&auth.id), &cd, &att, &[2u8; 32]).is_err());
    }

    #[test]
    fn assertion_checks() {
        let auth = SoftAuthenticator::new(&rp().rp_id);
        let pk = auth.public_sec1();
        let ch = [9u8; 32];
        let ok = |cd: &str, ad: &str, sig: &str, ch: &[u8]| verify_assertion(&rp(), &pk, 0, cd, ad, sig, ch);

        let (cd, ad, sig) = auth.assert(&rp().origin, &ch, UP_UV);
        assert_eq!(ok(&cd, &ad, &sig, &ch), Ok(0));

        // Bound to a different request.
        assert!(ok(&cd, &ad, &sig, &[8u8; 32]).is_err());

        // T3 Code's origin shares the rp_id but must not be accepted.
        let (cd2, ad2, sig2) = auth.assert("https://pod042.example.ts.net", &ch, UP_UV);
        assert!(ok(&cd2, &ad2, &sig2, &ch).unwrap_err().0.contains("origin"));

        // No user verification.
        let (cd3, ad3, sig3) = auth.assert(&rp().origin, &ch, UP_ONLY);
        assert!(ok(&cd3, &ad3, &sig3, &ch).unwrap_err().0.contains("verification"));

        // Signature from a different key.
        let other = SoftAuthenticator::new(&rp().rp_id);
        let (cd4, ad4, sig4) = other.assert(&rp().origin, &ch, UP_UV);
        assert!(ok(&cd4, &ad4, &sig4, &ch).is_err());

        // Tampered clientDataJSON (re-encoded with a different origin) breaks the signature.
        let forged_cd = b64encode(&SoftAuthenticator::client_data("webauthn.get", &rp().origin, &[8u8; 32]));
        assert!(ok(&forged_cd, &ad, &sig, &[8u8; 32]).unwrap_err().0.contains("signature"));
    }
}
