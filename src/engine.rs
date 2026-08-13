//! The default [`VcalmLdEngine`]: JSON-LD verification and selective-disclosure
//! derivation, implemented with plain `ssi`.
//!
//! # Why this is not left to the embedder
//!
//! An earlier revision made the engine a required constructor argument, so every
//! host wrote these ~60 lines itself. That was a mistake. Unlike credential
//! storage and key custody — which genuinely belong to the host — verification
//! is just `DataIntegrity::verify` over a resolver, and derivation is
//! `AnyDataIntegrity::select`. Nothing host-specific happens here, and pushing
//! it outwards handed every embedder two traps:
//!
//! * **The claims/proof distinction.** [`VerifyOutcome::ClaimsInvalid`] (expired)
//!   is still storable; [`VerifyOutcome::ProofInvalid`] aborts the whole offer.
//!   Collapsing them turns every expired credential into a hard rejection. That
//!   mapping is now made once, here, correctly.
//! * **The large-stack hop.** `ssi`'s JSON-LD expansion overflows iOS's ~512 KB
//!   child-thread stack, surfacing as `EXC_BAD_ACCESS code=2`. It was previously
//!   documented as the adapter's responsibility — a contract that is easy to read
//!   past and whose penalty is an iOS-only crash. [`SsiEngine`] performs the hop
//!   itself, so nobody can forget it.
//!
//! The trait stays public and [`VcalmHolder::new_session_with_engine`] still
//! accepts an override, because some hosts legitimately need one: notably,
//! `AnyDidMethod::default()` resolves `did:web`, which reaches the network. A
//! host wanting an offline-only resolver, a trust registry, revocation checks or
//! caching supplies its own.
//!
//! [`VcalmHolder::new_session_with_engine`]: crate::holder::VcalmHolder::new_session_with_engine

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::big_stack;
use crate::ports::{PortError, VcalmLdEngine, VerifyOutcome};

/// Build verification parameters over a `did:key`-capable resolver plus the
/// statically bundled JSON-LD contexts, extended with the caller's context map.
///
/// A macro rather than a function because `VerificationParameters`' concrete
/// type is unnameable in practice — it is
/// `VerificationParameters<VerificationMethodDIDResolver<AnyDidMethod, _>, ContextLoader, ()>`
/// with an inference hole in the middle, and erasing the resolver behind
/// `impl DIDResolver` loses the `VerificationMethodResolver` impl that
/// `verify`/`select` require.
macro_rules! verification_params {
    ($context_map:expr) => {{
        use ssi::claims::VerificationParameters;
        use ssi::dids::{AnyDidMethod, DIDResolver};
        use ssi::json_ld::ContextLoader;

        let mut params =
            VerificationParameters::from_resolver(AnyDidMethod::default().into_vm_resolver());
        if let Some(map) = $context_map {
            params = params.with_json_ld_loader(
                ContextLoader::empty()
                    .with_static_loader()
                    .with_context_map_from(map)
                    .map_err(|e| PortError::Verification(format!("context map: {e:?}")))?,
            );
        }
        params
    }};
}

/// The default JSON-LD / Data Integrity engine.
#[derive(Debug, Default)]
pub struct SsiEngine;

impl SsiEngine {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    /// The verification body, run on the large-stack worker by [`Self::verify`].
    async fn verify_inner(
        body: Value,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<VerifyOutcome, PortError> {
        use ssi::prelude::{AnyJsonCredential, AnySuite, DataIntegrity};

        let params = verification_params!(context_map);
        let vc: DataIntegrity<AnyJsonCredential, AnySuite> = serde_json::from_value(body)
            .map_err(|e| PortError::Decode(format!("not a Data Integrity credential: {e}")))?;

        match vc.verify(&params).await {
            Ok(Ok(())) => Ok(VerifyOutcome::Verified),
            // Proof held, a claim did not (expired/premature) — still storable.
            Ok(Err(ssi::claims::Invalid::Claims(e))) => Ok(VerifyOutcome::ClaimsInvalid {
                reason: format!("{e:?}"),
            }),
            Ok(Err(ssi::claims::Invalid::Proof(e))) => Ok(VerifyOutcome::ProofInvalid {
                reason: format!("{e:?}"),
            }),
            Err(e) => Err(PortError::Verification(format!("{e:?}"))),
        }
    }

    /// The derivation body, run on the large-stack worker by
    /// [`Self::derive_selective_disclosure`].
    async fn derive_inner(
        body: Value,
        pointers: Vec<String>,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<Value, PortError> {
        use ssi::claims::data_integrity::{AnyDataIntegrity, AnySelectionOptions};

        let input: AnyDataIntegrity = serde_json::from_value(body)
            .map_err(|e| PortError::Decode(format!("not a Data Integrity credential: {e}")))?;

        // Pointers cross the port as strings; re-validate here, which is where a
        // malformed pointer should be caught.
        let selective_pointers = pointers
            .iter()
            .map(|p| {
                ssi::JsonPointerBuf::new(p.clone())
                    .map_err(|e| PortError::Derive(format!("invalid JSON pointer {p:?}: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let params = verification_params!(context_map);
        let mut options = AnySelectionOptions::default();
        options.selective_pointers = selective_pointers;

        let derived = input
            .select(params, options)
            .await
            .map_err(|e| PortError::Derive(format!("{e:?}")))?;

        serde_json::to_value(&derived)
            .map_err(|e| PortError::Derive(format!("derived credential re-encode: {e}")))
    }
}

#[async_trait::async_trait]
impl VcalmLdEngine for SsiEngine {
    async fn verify(
        &self,
        body: &Value,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<VerifyOutcome, PortError> {
        let body = body.clone();
        big_stack::run_async(move || Self::verify_inner(body, context_map))
            .await
            .map_err(|e| PortError::Verification(format!("large-stack worker: {e}")))?
    }

    async fn derive_selective_disclosure(
        &self,
        body: &Value,
        pointers: Vec<String>,
        context_map: Option<HashMap<String, String>>,
    ) -> Result<Value, PortError> {
        let body = body.clone();
        big_stack::run_async(move || Self::derive_inner(body, pointers, context_map))
            .await
            .map_err(|e| PortError::Derive(format!("large-stack worker: {e}")))?
    }
}
