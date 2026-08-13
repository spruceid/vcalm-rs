//! VCALM — Verifiable Credential API for Lifecycle Management.
//!
//! # Integrating this crate
//!
//! **You must copy the `[patch.crates-io]` block from this crate's `Cargo.toml`
//! into your own workspace root.** Cargo only honours `[patch]` in the top-level
//! manifest, so ours does nothing for you. Without it you resolve `ssi` from
//! crates.io, miss the `fix/multiproof-select-0.14` fix that selective-disclosure
//! derivation depends on, and will likely hit the yanked `core2 0.4.0` on a
//! fresh resolve. See `README.md`.
//!
//! FFI bindings are behind the off-by-default `uniffi` feature. Pure-Rust
//! consumers pay neither the scaffolding nor the exact `uniffi = "=0.31.1"` pin.

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod big_stack;
pub mod common;
pub mod crypto_utils;
pub mod discover_protocols;
pub mod engine;
pub mod error;
pub mod exchange;
pub mod holder;
pub mod issuance;
pub mod matching;
pub mod ports;
pub mod presentation;
#[cfg(test)]
mod tests;

pub use error::*;
pub use exchange::*;
pub use holder::*;
pub use presentation::*;
