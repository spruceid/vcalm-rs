//! Signature-encoding normalization for the VP proof.
//!
//! ## Why this lives in VCALM rather than behind a port
//!
//! `ecdsa-rdfc-2019` requires a raw fixed-width `r‖s` signature. Platform key
//! custody (Keychain, Android Keystore) and most Rust signers hand back DER
//! instead, and a DER signature produces a proof that is *structurally valid but
//! fails verification* — a failure that surfaces at the verifier, far from its
//! cause.
//!
//! That made this a poor candidate for delegating to
//! [`crate::ports::VcalmSigner`] implementors. The contract "return raw r‖s, not
//! DER" is easy to read past and impossible to check locally, so every adapter
//! author would have to rediscover it the hard way. VCALM picks the cryptosuite,
//! so VCALM normalizes to what that cryptosuite requires.
//!
//! Copied from `sprucekit-mobile/rust/src/crypto.rs` (minus its `uniffi`
//! attributes, which only mattered when the type crossed the FFI boundary).

/// Curve-specific helpers. Only P-256 is wired, matching the single VP-proof
/// cryptosuite (`ecdsa-rdfc-2019`).
pub struct CryptoCurveUtils(Curve);

enum Curve {
    SecP256R1,
}

impl CryptoCurveUtils {
    /// Utils for the secp256r1 (aka P-256) curve.
    pub fn secp256r1() -> Self {
        Self(Curve::SecP256R1)
    }

    /// Normalize a signature to raw fixed-width `r‖s`.
    ///
    /// Accepts either encoding on the way in — already-raw signatures pass
    /// through unchanged — and returns `None` when the bytes parse as neither,
    /// which the caller surfaces as an unsupported-encoding signing failure
    /// rather than emitting a proof that cannot verify.
    pub fn ensure_raw_fixed_width_signature_encoding(&self, bytes: Vec<u8>) -> Option<Vec<u8>> {
        match self.0 {
            Curve::SecP256R1 => {
                use p256::ecdsa::Signature;
                match (Signature::from_slice(&bytes), Signature::from_der(&bytes)) {
                    (Ok(s), _) | (_, Ok(s)) => Some(s.to_vec()),
                    _ => None,
                }
            }
        }
    }
}
