#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use ssi::JWK;
use ssi::claims::data_integrity::CryptosuiteString;
use ssi::claims::jws::JwsSigner;
use ssi::crypto::Algorithm;
use ssi::dids::{DIDKey, DIDResolver};
use ssi::jwk::{ECParams, Params};
use uuid::Uuid;

use crate::engine::SsiEngine;
use crate::holder::VcalmHolder;
use crate::ports::{
    NewCredential, PortError, StoredCredential, VcalmCredentialStore, VcalmLdEngine, VcalmSigner,
    VerifyOutcome,
};

/// The host credential type for tests. Real adapters use
/// `Arc<ParsedCredential>`; here the VC body doubles as its own host object, so
/// assertions can read it back without a downcast.
pub(crate) type TestCredential = Arc<Value>;

/// A stable `did:key` for the test holder. Well-formed so `UriBuf` parsing and
/// DID resolution succeed; no private key is associated with it.
pub(crate) const TEST_HOLDER_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

// --- store ------------------------------------------------------------------

/// In-memory [`VcalmCredentialStore`].
#[derive(Default)]
pub(crate) struct MemoryStore {
    entries: Mutex<HashMap<Uuid, Value>>,
}

impl MemoryStore {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a credential body directly, bypassing the port, and hand back the
    /// [`StoredCredential`] a caller would select for presentation.
    pub(crate) fn seed(&self, body: Value) -> StoredCredential<TestCredential> {
        let id = Uuid::new_v4();
        self.entries.lock().unwrap().insert(id, body.clone());
        StoredCredential {
            id,
            body: body.clone(),
            host: Arc::new(body),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl VcalmCredentialStore for MemoryStore {
    type Credential = TestCredential;

    async fn list_ids(&self) -> Result<Vec<Uuid>, PortError> {
        Ok(self.entries.lock().unwrap().keys().copied().collect())
    }

    async fn get(&self, id: Uuid) -> Result<Option<StoredCredential<Self::Credential>>, PortError> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(&id)
            .map(|body| StoredCredential {
                id,
                body: body.clone(),
                host: Arc::new(body.clone()),
            }))
    }

    async fn add(&self, credential: NewCredential) -> Result<(), PortError> {
        self.entries
            .lock()
            .unwrap()
            .insert(credential.id, credential.body);
        Ok(())
    }
}

/// A [`VcalmSigner`] that reports a stable identity and returns its input as the
/// "signature".
#[derive(Debug, Default)]
pub(crate) struct FakeSigner;

#[async_trait::async_trait]
impl VcalmSigner for FakeSigner {
    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, PortError> {
        Ok(payload)
    }
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
    async fn verification_method(&self) -> String {
        format!("{TEST_HOLDER_DID}#{}", &TEST_HOLDER_DID[8..])
    }
    fn did(&self) -> String {
        TEST_HOLDER_DID.to_string()
    }
    fn cryptosuite(&self) -> CryptosuiteString {
        CryptosuiteString::new("ecdsa-rdfc-2019".to_string())
            .expect("ecdsa-rdfc-2019 is a valid cryptosuite name")
    }
    fn jwk(&self) -> String {
        "{}".into()
    }
}

#[derive(Debug)]
pub(crate) struct P256Signer {
    jwk: JWK,
}

/// An arbitrary valid secp256r1 scalar. Test-only; never used for anything real.
const TEST_KEY_SCALAR: [u8; 32] = [0x11; 32];

impl P256Signer {
    pub(crate) fn new() -> Arc<Self> {
        let key = p256::SecretKey::from_slice(&TEST_KEY_SCALAR).expect("valid secp256r1 scalar");
        Arc::new(Self {
            jwk: JWK::from(Params::EC(ECParams::from(&key))),
        })
    }

    /// The `did:key` this signer authenticates as.
    pub(crate) fn did_key(&self) -> String {
        DIDKey::generate(&self.jwk)
            .expect("a P-256 JWK always yields a did:key")
            .to_string()
    }
}

#[async_trait::async_trait]
impl VcalmSigner for P256Signer {
    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, PortError> {
        let sig = self
            .jwk
            .sign_bytes(&payload)
            .await
            .map_err(|e| PortError::Signing(format!("{e:?}")))?;
        // Raw r‖s in, DER out -- see the note on this type.
        p256::ecdsa::Signature::from_slice(&sig)
            .map(|s| s.to_der().as_bytes().to_vec())
            .map_err(|e| PortError::Signing(format!("{e:?}")))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }

    async fn verification_method(&self) -> String {
        let did = DIDKey::generate(&self.jwk).expect("a P-256 JWK always yields a did:key");
        DIDKey
            .resolve_into_any_verification_method(did.as_did())
            .await
            .expect("did:key resolves offline")
            .expect("did:key always has a verification method")
            .id
            .to_string()
    }

    fn did(&self) -> String {
        self.did_key()
    }

    fn cryptosuite(&self) -> CryptosuiteString {
        CryptosuiteString::new("ecdsa-rdfc-2019".to_string())
            .expect("ecdsa-rdfc-2019 is a valid cryptosuite name")
    }

    fn jwk(&self) -> String {
        serde_json::to_string(&self.jwk.to_public()).expect("a JWK always serializes")
    }
}

/// A [`VcalmLdEngine`] whose verdicts are declared per credential `id` instead
/// of computed from a signature.
#[derive(Default)]
pub(crate) struct ScriptedEngine {
    verdicts: Mutex<HashMap<String, VerifyOutcome>>,
    derive_fails: Mutex<bool>,
    pub(crate) derive_calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl ScriptedEngine {
    pub(crate) fn permissive() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn verdict(self: Arc<Self>, vc_id: &str, outcome: VerifyOutcome) -> Arc<Self> {
        self.verdicts
            .lock()
            .unwrap()
            .insert(vc_id.to_string(), outcome);
        self
    }

    pub(crate) fn fail_derive(self: Arc<Self>) -> Arc<Self> {
        *self.derive_fails.lock().unwrap() = true;
        self
    }

    fn id_of(body: &Value) -> String {
        body.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }
}

#[async_trait::async_trait]
impl VcalmLdEngine for ScriptedEngine {
    async fn verify(
        &self,
        body: &Value,
        _context_map: Option<HashMap<String, String>>,
    ) -> Result<VerifyOutcome, PortError> {
        Ok(self
            .verdicts
            .lock()
            .unwrap()
            .get(&Self::id_of(body))
            .cloned()
            .unwrap_or(VerifyOutcome::Verified))
    }

    async fn derive_selective_disclosure(
        &self,
        body: &Value,
        pointers: Vec<String>,
        _context_map: Option<HashMap<String, String>>,
    ) -> Result<Value, PortError> {
        self.derive_calls
            .lock()
            .unwrap()
            .push((Self::id_of(body), pointers));
        if *self.derive_fails.lock().unwrap() {
            return Err(PortError::Derive("scripted derive failure".into()));
        }
        Ok(body.clone())
    }
}

/// A holder over an empty store and a permissive engine.
pub(crate) async fn test_holder() -> Arc<VcalmHolder<TestCredential>> {
    test_holder_with(MemoryStore::new(), ScriptedEngine::permissive()).await
}

/// A holder over a caller-supplied store and a scripted engine, so a test can
/// seed credentials or declare verification verdicts.
pub(crate) async fn test_holder_with(
    store: Arc<MemoryStore>,
    engine: Arc<ScriptedEngine>,
) -> Arc<VcalmHolder<TestCredential>> {
    VcalmHolder::new_session_with_engine(store, vec![], Arc::new(FakeSigner), None, engine)
        .await
        .expect("holder construction must succeed")
}

pub(crate) async fn test_holder_signed() -> (Arc<VcalmHolder<TestCredential>>, Arc<P256Signer>) {
    let signer = P256Signer::new();
    let holder = VcalmHolder::new_session_with_engine(
        MemoryStore::new(),
        vec![],
        signer.clone(),
        None,
        ScriptedEngine::permissive(),
    )
    .await
    .expect("holder construction must succeed");
    (holder, signer)
}

pub(crate) async fn test_holder_real(
    store: Arc<MemoryStore>,
) -> (Arc<VcalmHolder<TestCredential>>, Arc<P256Signer>) {
    let signer = P256Signer::new();
    let holder = VcalmHolder::new_session(store, vec![], signer.clone(), None)
        .await
        .expect("holder construction must succeed");
    (holder, signer)
}

/// A [`StoredCredential`] built directly, for the few tests that exercise
/// presentation assembly without a store behind it.
pub(crate) fn stored_credential(body: Value) -> StoredCredential<TestCredential> {
    StoredCredential {
        id: Uuid::new_v4(),
        body: body.clone(),
        host: Arc::new(body),
    }
}

/// An offered VC in the shape `accept_offer` expects. Unsigned — the
/// [`ScriptedEngine`] decides its verdict, so no `proof` is needed.
pub(crate) fn offered_vc(id: &str, given_name: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {
                "givenName": "https://schema.org/givenName",
                "PermanentResidentCard": "https://schema.org/PermanentResidentCard"
            }
        ],
        "id": id,
        "type": ["VerifiableCredential", "PermanentResidentCard"],
        "issuer": "https://issuer.example/",
        "credentialSubject": { "id": TEST_HOLDER_DID, "givenName": given_name },
        "proof": { "type": "DataIntegrityProof", "cryptosuite": "ecdsa-rdfc-2019" }
    })
}

/// An offered VC carrying an `ecdsa-sd-2023` BASE proof, which arms the SD gate
/// and routes verification through derive-then-verify.
pub(crate) fn sd_base_offered_vc(id: &str, given_name: &str) -> Value {
    let mut vc = offered_vc(id, given_name);
    vc["proof"] = json!({ "type": "DataIntegrityProof", "cryptosuite": "ecdsa-sd-2023" });
    vc
}

/// A v2 credential subject-bound to the test holder, for QBE matching.
pub(crate) fn v2_credential(given_name: &str) -> Value {
    offered_vc(&format!("urn:uuid:{}", Uuid::new_v4()), given_name)
}

/// Sign an unsecured credential OFFLINE, producing a real `ecdsa-rdfc-2019`
/// issuer proof that [`SsiEngine`] accepts with no network.
pub(crate) async fn sign_offered_vc(signer: &Arc<P256Signer>, claims: Value) -> Value {
    use crate::presentation::VpSigner;
    use ssi::claims::SignatureEnvironment;
    use ssi::claims::vc::v1::JsonCredential;
    use ssi::dids::{AnyDidMethod, VerificationMethodDIDResolver};
    use ssi::json_ld::syntax::{Context, ContextEntry};
    use ssi::json_ld::{ContextLoader, IriRefBuf};
    use ssi::prelude::{AnySuite, CryptographicSuite, ProofOptions};
    use ssi::verification_methods::ProofPurpose;
    use ssi::xsd::DateTimeStamp;

    let glue = VpSigner::new(signer.clone(), None);
    let resolver = VerificationMethodDIDResolver::new(AnyDidMethod::default());
    let vm = glue
        .verification_method_id()
        .await
        .expect("verification method id");

    let mut proof_options = ProofOptions::new(
        DateTimeStamp::now_ms().into(),
        vm.into(),
        ProofPurpose::Assertion,
        Default::default(),
    );
    // VCDM v1 + Data Integrity requires the `data-integrity/v2` context entry or
    // canonicalization/verification fails.
    let di_context = IriRefBuf::new("https://w3id.org/security/data-integrity/v2".into())
        .expect("data-integrity context iri");
    proof_options.context = Some(Context::One(ContextEntry::IriRef(di_context)));

    let env = SignatureEnvironment {
        json_ld_loader: ContextLoader::default(),
        eip712_loader: (),
    };

    // The verify path decodes into the VCDM **v1** JsonCredential, which
    // strictly requires the v1 context — so these fixtures are v1.
    let credential: JsonCredential = serde_json::from_value(claims).expect("valid v1 credential");

    let signed = AnySuite::EcdsaRdfc2019
        .sign_with(
            &env,
            credential,
            resolver,
            &glue,
            proof_options,
            Default::default(),
        )
        .await
        .expect("offered VC must sign offline");
    serde_json::to_value(&signed).expect("serialize signed offered VC")
}

/// A signed full-disclosure offered VC whose proof verifies offline. `id` drives
/// the stable storage id; `given_name` is QBE-matchable.
pub(crate) async fn signed_offered_vc(
    signer: &Arc<P256Signer>,
    id: &str,
    given_name: &str,
) -> Value {
    let did = signer.did_key();
    sign_offered_vc(
        signer,
        json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "givenName": "https://schema.org/givenName",
                    "PermanentResidentCard": "https://schema.org/PermanentResidentCard"
                }
            ],
            "id": id,
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": did,
            "issuanceDate": "2020-01-01T00:00:00Z",
            "credentialSubject": { "givenName": given_name }
        }),
    )
    .await
}

/// A cryptographically-VALID offered VC whose validity period is in the past —
/// the proof verifies but the claims are expired. Drives the
/// [`VerifyOutcome::ClaimsInvalid`] branch with a real credential.
pub(crate) async fn expired_offered_vc(signer: &Arc<P256Signer>, id: &str) -> Value {
    let did = signer.did_key();
    sign_offered_vc(
        signer,
        json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "givenName": "https://schema.org/givenName",
                    "PermanentResidentCard": "https://schema.org/PermanentResidentCard"
                }
            ],
            "id": id,
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": did,
            "issuanceDate": "2019-01-01T00:00:00Z",
            "expirationDate": "2020-01-01T00:00:00Z",
            "credentialSubject": { "givenName": "Expired" }
        }),
    )
    .await
}

/// A PROOF-INVALID offered VC: signed validly, then a signed claim is mutated
/// AFTER signing so the issuer proof no longer matches the document.
pub(crate) async fn proof_invalid_offered_vc(signer: &Arc<P256Signer>, id: &str) -> Value {
    let mut vc = signed_offered_vc(signer, id, "Original").await;
    vc["credentialSubject"]["givenName"] = json!("Tampered");
    vc
}

/// Issue an `ecdsa-sd-2023` BASE-proof VC: fresh P-256 issuer key, `did:key`
/// Multikey VM, `AnySuite::EcdsaSd2023` with the issuer's `mandatory_pointers`.
///
/// A base proof is derivation material — it cannot be verified directly, only
/// `select`ed from. This is the input [`SsiEngine::derive_selective_disclosure`]
/// exists to handle, and the only fixture `ScriptedEngine` cannot fake.
pub(crate) async fn issue_sd_base_proof(unsecured: Value, mandatory_pointers: &[&str]) -> Value {
    use ssi::claims::SignatureEnvironment;
    use ssi::claims::data_integrity::{
        AnyDataIntegrity, AnySignatureOptions, AnySuite, DataIntegrityDocument, ProofConfiguration,
    };
    use ssi::dids::{AnyDidMethod, DIDResolver};
    use ssi::prelude::CryptographicSuite;
    use ssi::verification_methods::SingleSecretSigner;

    let issuer_jwk = JWK::generate_p256();
    let vm = DIDKey::generate_url(&issuer_jwk).expect("did:key Multikey VM");

    let configuration: ProofConfiguration<AnySuite> = serde_json::from_value(json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-sd-2023",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": vm.to_string(),
        "proofPurpose": "assertionMethod"
    }))
    .expect("valid ecdsa-sd-2023 proof configuration");

    let (suite, options) = configuration.into_suite_and_options();
    let input: DataIntegrityDocument =
        serde_json::from_value(unsecured).expect("unsecured DI document");

    let mut sig_options = AnySignatureOptions::default();
    sig_options.mandatory_pointers = mandatory_pointers
        .iter()
        .map(|p| p.parse().expect("valid mandatory JSON pointer"))
        .collect();

    let signed: AnyDataIntegrity = suite
        .sign_with(
            SignatureEnvironment::default(),
            input,
            AnyDidMethod::default().into_vm_resolver(),
            SingleSecretSigner::new(issuer_jwk).into_local(),
            options.cast(),
            sig_options,
        )
        .await
        .expect("ecdsa-sd-2023 base-proof issuance must succeed");

    serde_json::to_value(&signed).expect("serialize signed base-proof VC")
}

/// A V2 PermanentResidentCard with `givenName` + `familyName` under an
/// `ecdsa-sd-2023` base proof (mandatory `/issuer`). `givenName` is the
/// QBE-named field; `familyName` must NOT survive a selective derive.
pub(crate) async fn sd_base_proof_v2(given_name: &str) -> Value {
    issue_sd_base_proof(
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                {
                    "givenName": "https://schema.org/givenName",
                    "familyName": "https://schema.org/familyName",
                    "PermanentResidentCard": "https://schema.org/PermanentResidentCard"
                }
            ],
            "type": ["VerifiableCredential", "PermanentResidentCard"],
            "issuer": "https://issuer.example/",
            "credentialSubject": { "givenName": given_name, "familyName": "Doe" }
        }),
        &["/issuer"],
    )
    .await
}

/// Verify a signed VP end to end against an offline resolver.
pub(crate) async fn verify_vp(
    signed: &ssi::prelude::DataIntegrity<ssi::prelude::AnyJsonPresentation, ssi::prelude::AnySuite>,
) -> bool {
    use ssi::dids::{AnyDidMethod, DIDResolver};
    use ssi::prelude::VerificationParameters;
    let params = VerificationParameters::from_resolver(AnyDidMethod::default().into_vm_resolver());
    signed.verify(&params).await.expect("verify ran").is_ok()
}

/// The first embedded `verifiableCredential`'s proof cryptosuite, from a signed
/// VP's JSON. `Some("ecdsa-sd-2023")` means the SD derive actually happened.
pub(crate) fn embedded_vc_cryptosuite(vp: &Value) -> Option<String> {
    let vc = match &vp["verifiableCredential"] {
        Value::Array(a) => a.first().cloned(),
        v @ Value::Object(_) => Some(v.clone()),
        _ => None,
    }?;
    let proof = match vc.get("proof")? {
        Value::Array(a) => a.first().cloned()?,
        obj @ Value::Object(_) => obj.clone(),
        _ => return None,
    };
    proof
        .get("cryptosuite")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

/// Assertions about the fixtures themselves — everything else in the crate
/// trusts these, so they are checked rather than assumed.
mod fixture_tests {
    use super::*;

    /// The fixtures must genuinely verify, or every test built on them proves
    /// nothing. This is also the **only** coverage in the crate that a real
    /// signature round-trips: sign with `P256Signer`, verify with `SsiEngine`.
    #[tokio::test]
    async fn signed_offered_vc_verifies_offline() {
        let signer = P256Signer::new();
        let vc = signed_offered_vc(&signer, "urn:uuid:offline-1", "Alice").await;

        let outcome = SsiEngine::new()
            .verify(&vc, None)
            .await
            .expect("verification ran");
        assert!(
            matches!(outcome, VerifyOutcome::Verified),
            "a freshly signed fixture must verify offline, got {outcome:?}"
        );
    }

    /// The tampered fixture must fail on the PROOF, not the claims — that is the
    /// distinction `accept_offer` branches on.
    #[tokio::test]
    async fn proof_invalid_offered_vc_fails_proof() {
        let signer = P256Signer::new();
        let vc = proof_invalid_offered_vc(&signer, "urn:uuid:tampered-1").await;

        let outcome = SsiEngine::new()
            .verify(&vc, None)
            .await
            .expect("verification ran");
        assert!(
            matches!(outcome, VerifyOutcome::ProofInvalid { .. }),
            "post-signing mutation must fail the proof, got {outcome:?}"
        );
    }

    /// An expired-but-authentic credential fails on CLAIMS, so `accept_offer`
    /// still stores it. Pins the split against a real credential rather than a
    /// scripted verdict.
    #[tokio::test]
    async fn expired_offered_vc_fails_claims_not_proof() {
        let signer = P256Signer::new();
        let vc = expired_offered_vc(&signer, "urn:uuid:expired-real-1").await;

        let outcome = SsiEngine::new()
            .verify(&vc, None)
            .await
            .expect("verification ran");
        assert!(
            matches!(outcome, VerifyOutcome::ClaimsInvalid { .. }),
            "an expired credential fails claims, not proof, got {outcome:?}"
        );
    }
}
