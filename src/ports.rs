//! Host capabilities that VCALM needs but does not implement.
//!
//! VCALM owns the *protocol*: the vcapi exchange state machine, QueryByExample
//! matching, VP shape, offer classification. It does not own credential storage,
//! key custody, or the JSON-LD/data-integrity machinery. Those belong to the
//! wallet SDK embedding this crate.
//!
//! Each trait here is a **port**: a capability VCALM needs, described without
//! naming any type from the embedding SDK. The embedder supplies an **adapter**
//! implementing it (in `sprucekit-mobile`, over `VdcCollection`,
//! `PresentationSigner`, and `JsonVc`).
//!
//! ## Why plain Rust traits and not `uniffi` callback interfaces
//!
//! These are implemented in Rust by the embedding crate, not in Kotlin/Swift by
//! the host app, so nothing here crosses an FFI boundary. Keeping them free of
//! `uniffi` attributes avoids declaring `custom_type!` shims for
//! `Uuid`/`Algorithm`/`CryptosuiteString`, and leaves VCALM's eventual binding
//! surface as a separate decision.
//!
//! ## How the host's own credential type travels through
//!
//! VCALM matches and derives over a credential's JSON body, but the host's own
//! credential object has to survive the round trip so it can be handed back to
//! the caller unchanged. Rather than erase it to `Arc<dyn Any>` and downcast on
//! the way out, [`VcalmCredentialStore`] carries it as an associated type. The
//! adapter picks the concrete type once (`type Credential = Arc<ParsedCredential>`)
//! and it stays statically known from there — a mismatch is a compile error, not
//! a failed downcast at runtime.
//!
//! `dyn Trait<Credential = C>` is still object-safe, so the holder can keep
//! storing its ports as `Arc<dyn ...>`.

use std::collections::HashMap;

use serde_json::Value as JsonValue;
use ssi::claims::data_integrity::CryptosuiteString;
use ssi::crypto::Algorithm;
use uuid::Uuid;

/// A credential read out of host storage.
///
/// `C` is the host's own credential type, fixed by the adapter via
/// [`VcalmCredentialStore::Credential`].
#[derive(Clone)]
pub struct StoredCredential<C> {
    /// Host-assigned local id. VCALM treats this as opaque except that it must
    /// round-trip: an id from [`VcalmCredentialStore::list_ids`] must be
    /// accepted by [`VcalmCredentialStore::get`].
    pub id: Uuid,

    /// The verifiable credential body. This is what matching inspects (`type`,
    /// `@context`, claim paths) and what selective-disclosure derivation
    /// operates on.
    pub body: JsonValue,

    /// The host's own credential object, passed through untouched.
    pub host: C,
}

impl<C> StoredCredential<C> {
    /// Whether this credential is a W3C JSON-LD VC that VCALM can match against
    /// and present.
    ///
    /// A wallet also holds mdocs, SD-JWTs and other formats that VCALM's
    /// QueryByExample matcher has nothing to say about. Adapters signal those by
    /// setting [`body`](Self::body) to a non-object value (`Null` is the
    /// conventional choice); matching skips them rather than erroring, which
    /// mirrors how the host's `as_json_vc()` returning `None` behaves today.
    pub fn is_json_ld_vc(&self) -> bool {
        self.body.is_object()
    }
}

impl<C> std::fmt::Debug for StoredCredential<C> {
    /// Deliberately omits `body` — wallet contents are sensitive and this type
    /// appears in log-adjacent code paths. See the privacy note in
    /// `holder::matched_credentials`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredential")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The credential formats VCALM knows how to write into storage.
///
/// VCALM only stores full-disclosure W3C JSON-LD VCs today. This is an enum
/// rather than a bare string so that adding a format is a compile error in the
/// adapter instead of a silently unrecognized value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorableFormat {
    /// W3C VCDM with a Data Integrity proof (`ldp_vc`).
    LdpVc,
}

/// A credential VCALM has accepted from an issuer and wants persisted.
///
/// Intentionally minimal: the adapter derives the storage record's credential
/// type and wire payload from `body`, because those encodings are the host's
/// concern and VCALM should not have to agree with it about them.
#[derive(Debug, Clone)]
pub struct NewCredential {
    /// Stable local id, derived by VCALM from issuer + credential id so that
    /// re-accepting the same offer overwrites rather than duplicates. See
    /// `issuance::stable_local_id`.
    pub id: Uuid,

    /// The verifiable credential body to persist.
    pub body: JsonValue,

    /// How `body` should be stored.
    pub format: StorableFormat,
}

/// Outcome of verifying a credential's proof.
///
/// The split between [`ClaimsInvalid`](Self::ClaimsInvalid) and
/// [`ProofInvalid`](Self::ProofInvalid) is load-bearing, not cosmetic:
/// `accept_offer` **stores** a credential whose proof verified but whose validity
/// period failed (surfacing a distinct warning), while a failed *proof* aborts
/// the entire offer atomically and stores nothing. Collapsing these into one
/// "failed" variant would silently turn expired credentials into hard rejections.
/// They correspond to the host's `InvalidCredential::Claims` and
/// `InvalidCredential::Proof`.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// The proof verified and the claims are within their validity period.
    Verified,
    /// The proof verified, but a claim did not hold — typically an expired or
    /// premature validity period. Still storable.
    ClaimsInvalid { reason: String },
    /// The credential's cryptographic proof failed.
    ProofInvalid { reason: String },
    /// The credential uses a proof or envelope this host cannot verify.
    Unsupported { reason: String },
}

/// Credential storage, as VCALM needs it.
///
/// Modelled as list-then-get rather than a single fused call so that VCALM can
/// distinguish a genuinely empty store from one whose entries are dropped during
/// decrypt/parse — the id count is observed before any per-entry failure. That
/// distinction is load-bearing when diagnosing empty-wallet reports.
#[async_trait::async_trait]
pub trait VcalmCredentialStore: Send + Sync {
    /// The host's own credential type, chosen by the adapter.
    ///
    /// VCALM never inspects this; it only carries it back out again.
    type Credential: Clone + Send + Sync + 'static;

    /// Every credential id in the store, before any decrypt or parse is
    /// attempted.
    async fn list_ids(&self) -> Result<Vec<Uuid>, PortError>;

    /// Read one credential. `Ok(None)` means the id is absent; a decrypt or
    /// parse failure is an `Err`, so callers can tell "gone" from "unreadable".
    async fn get(&self, id: Uuid) -> Result<Option<StoredCredential<Self::Credential>>, PortError>;

    /// Persist a credential, overwriting any existing entry with the same id.
    ///
    /// Overwrite-on-duplicate is what makes accepting the same offer twice
    /// idempotent; an implementation that errored on conflict would break offer
    /// retry.
    async fn add(&self, credential: NewCredential) -> Result<(), PortError>;
}

/// The signing key behind the presentations VCALM produces.
///
/// Mirrors the six methods of `sprucekit-mobile`'s `PresentationSigner`, using
/// `ssi` types directly so no SDK type is named. The host app ultimately
/// implements this over platform key custody (Keychain / Android Keystore), so
/// treat every method as potentially reaching a secure element: `sign` is async,
/// and the synchronous accessors must not block.
#[async_trait::async_trait]
pub trait VcalmSigner: Send + Sync + std::fmt::Debug {
    /// Sign `payload`, returning a raw signature. The algorithm must match
    /// [`Self::algorithm`] and the encoding must match what
    /// [`Self::cryptosuite`] expects.
    async fn sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, PortError>;

    /// Signature algorithm, e.g. `ES256`.
    fn algorithm(&self) -> Algorithm;

    /// Verification method identifier for the signing key, embedded in the
    /// proof.
    async fn verification_method(&self) -> String;

    /// DID of the signing key.
    fn did(&self) -> String;

    /// Data Integrity cryptosuite of this signer, e.g. `ecdsa-rdfc-2019`.
    /// Matched against the verifier's advertised `vp_formats_supported`.
    fn cryptosuite(&self) -> CryptosuiteString;

    /// Public JWK of the signing key, as a JSON string.
    fn jwk(&self) -> String;
}

/// JSON-LD and Data Integrity operations, as VCALM consumes them.
///
/// **Most embedders never implement this.** [`crate::engine::SsiEngine`] is the
/// default and is used unless you call
/// [`VcalmHolder::new_session_with_engine`]. Unlike storage and signing, nothing
/// here is host-specific — it is `ssi` calls — so making it mandatory only
/// duplicated work and exported two easy mistakes (the claims/proof split, and
/// the large-stack hop).
///
/// Implement it when you need control the default cannot give: an offline-only
/// resolver (the default resolves `did:web`, which reaches the network), a trust
/// registry, revocation checks, or caching.
///
/// Two obligations if you do:
///
/// * Map an expired/premature credential to [`VerifyOutcome::ClaimsInvalid`] and
///   a bad signature to [`VerifyOutcome::ProofInvalid`]. They are not
///   interchangeable — see those variants.
/// * Run the work on a large-stack thread ([`crate::big_stack::run_async`]).
///   `ssi`'s context expansion overflows iOS's ~512 KB child-thread stack.
///
/// [`VcalmHolder::new_session_with_engine`]: crate::holder::VcalmHolder::new_session_with_engine
#[async_trait::async_trait]
pub trait VcalmLdEngine: Send + Sync {
    /// Verify a credential's proof.
    ///
    /// `context_map` is the host's bundled JSON-LD contexts, passed through from
    /// the holder's constructor.
    /// Implementations must not fetch contexts from the network.
    async fn verify(
        &self,
        body: &JsonValue,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<VerifyOutcome, PortError>;

    /// Derive a selective-disclosure credential revealing only `pointers`.
    ///
    /// `pointers` are RFC 6901 JSON pointers into `body`. An empty `pointers`
    /// means full reveal, which VCALM also uses to verify a base proof by
    /// deriving from it.
    async fn derive_selective_disclosure(
        &self,
        body: &JsonValue,
        pointers: Vec<String>,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<JsonValue, PortError>;
}

/// Failures originating in a host adapter rather than in VCALM's own logic.
///
/// Stringly-typed by design. The host's errors (`VdcCollectionError`,
/// `VerificationError`, `PresentationError`, ...) are richer, but reproducing
/// that hierarchy would put VCALM right back to depending on the SDK's types.
/// VCALM only branches on *which port* failed, so the variant carries the
/// category and the message carries the detail.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PortError {
    #[error("credential storage failed: {0}")]
    Storage(String),

    /// A stored credential could not be decoded into a usable form.
    #[error("could not decode stored credential: {0}")]
    Decode(String),

    #[error("proof verification failed: {0}")]
    Verification(String),

    #[error("selective-disclosure derivation failed: {0}")]
    Derive(String),

    #[error("signing failed: {0}")]
    Signing(String),

    /// The host cannot service this request at all — misconfiguration rather
    /// than a runtime failure. For example, no storage was wired into the
    /// session.
    #[error("host capability unavailable: {0}")]
    Unavailable(String),
}
