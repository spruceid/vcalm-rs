# VCALM extraction checklist

Working doc for pulling VCALM out of `sprucekit-mobile` into `vcalm-rs`. Delete
it before the first release commit if you'd rather not carry it in the repo.

**Guiding constraints**

- `sprucekit-mobile` must not change behaviour. Its Rust API *and* its generated
  Kotlin/Swift bindings are both consumed downstream.
- Changes land in `vcalm-rs` wherever there's a choice.
- Stage 1 leaves `sprucekit-mobile/rust/src/vcalm/` untouched, so the bindings
  are identical by construction. Stage 2 deletes it.

Legend: ☐ to do · ✅ done · ⚠️ decision needed before starting

---

## Done — `vcalm-rs` stands alone

14 modules, **114 tests**, no sprucekit references, `cargo clippy --all-targets
-- -D warnings` clean.

- **Dependency inversion.** `ports.rs` defines `VcalmCredentialStore`,
  `VcalmSigner`, `VcalmLdEngine`. The store's credential type is an associated
  type, so host credentials round-trip statically typed with no downcast.
- **`holder.rs`** rewritten against the ports — `VcalmHolder<C>`, 1,681 lines of
  production code.
- **Copied from sprucekit:** `big_stack.rs` (accepted debt D2),
  `discover_protocols.rs` (open debt D1), `CryptoCurveUtils` → `crypto_utils.rs`.
- **`engine.rs`** — `SsiEngine`, the default `VcalmLdEngine`, plain `ssi`. Runs
  the large-stack hop itself.
- **`tests.rs`** — shared fixtures, matching sprucekit's `src/tests.rs`
  convention. `ScriptedEngine` for state-machine tests, `P256Signer` +
  `SsiEngine` for real crypto.
- **Lockfile + `[patch.crates-io]`** clears the yanked `core2 0.4.0`.
- **`uniffi` is an off-by-default feature**, so pure-Rust consumers avoid the
  exact `=0.31.1` pin.

Two API corrections made along the way, both worth knowing if you read older
notes:

1. `StoredCredential` carries the host credential as an associated type, not
   `Arc<dyn Any>` — mismatches are compile errors, not failed downcasts.
2. `new_session` takes **four** parameters (store, trusted_dids, signer,
   context_map), matching the original minus `keystore`. The engine was briefly
   a required argument; that was over-applying the port pattern, since nothing
   about JSON-LD verification is host-specific.

---

## Debt taken on deliberately

### ⚠️ D1. Share `discover_protocols` instead of duplicating it

Copied to unblock the extraction. Unlike `big_stack` — pure infrastructure where
a copy is harmless — this is security-relevant and should move into
`mobile-toolkit` so both crates run one implementation:

- `validate_endpoint_url` stops a QR code smuggling a `file:`/custom-scheme URL
  into the wallet, and restricts plain `http` to loopback.
- `read_body_capped` bounds response size (B.4) against a hostile server.
- Both crates validate the *same* URLs, so divergence means one QR code behaves
  differently depending on which path handles it.

**Drift has already started.** Clippy rewrote vcalm's copy to use let-chains;
sprucekit is on edition 2021 and cannot even parse that line. The copies are no
longer diffable by eye.

Only `validate_endpoint_url` is covered here; sprucekit still holds the 165 lines
of wiremock tests over `discover_protocols` and `read_body_capped`.

- [ ] File the tracking issue, replace `TODO(file me)` in the module header
- [ ] Do the move (all four helpers are `pub(crate)`, so none are FFI surface),
      **or** port the wiremock tests as an interim

### D2. `big_stack` duplication — accepted

Pure infrastructure, no policy. One hazard: if the 8 MB stack constant is ever
raised, both copies must change, and a mismatch shows up only as an iOS-only
`EXC_BAD_ACCESS`.

### D3. Consumer-facing API — closed

`uniffi` gated behind an off-by-default feature; `stable_local_id`,
`validate_endpoint_url` and `example_matches` promoted to `pub`; `VpSigner::new`
made `pub`. Remaining: `VcalmHolder<C>` is generic, so even with the feature on
there is no exported object — that is the stage 2 facade question below.

---

## Next: finish the repo

- [ ] **Commit.** The repo still has no commits; everything is staged as the
      initial add.
- [ ] `deny.toml` — ⚠️ the license allowlist is canonical in
      `sprucekit-mobile/rust/deny.toml` and already duplicated in four places.
      This makes five; add it to the sync list in sprucekit's `CLAUDE.md`.
- [ ] `.github/workflows/ci.yml` — `cargo check`, `clippy -D warnings`,
      `cargo test`, `cargo deny check licenses`. Also build with
      `--features uniffi`, which nothing currently exercises.
- [ ] `LICENSE-MIT` / `LICENSE-APACHE` (`Cargo.toml` says `MIT OR Apache-2.0`)

`Cargo.lock` **is** committed, unlike oid4vci-rs. Deliberate: cargo ignores a
dependency's lockfile, so it constrains nothing downstream, and without it CI
re-resolves and hits the yanked `core2` again.

---

## Stage 1c — sprucekit side, additive only

### 1. `mobile-toolkit` move (resolves D1)

Move the four `discover_protocols` helpers into `mobile-toolkit`; delete
`vcalm-rs/src/discover_protocols.rs` in favour of it. Sprucekit keeps the
exported `discover_protocols()` and its `uniffi::Error DiscoveryError` as a thin
wrapper, so its bindings don't move.

```bash
cd rust && cargo test
cd rust && ./build-ios.sh
git diff --exit-code rust/MobileSdkRs/Sources/MobileSdkRs/
```

**An empty bindings diff is the proof of no behaviour change** — worth wiring as
a CI gate before anything else lands.

### 2. Adapters behind `#[cfg(test)]`

New `rust/src/vcalm_adapters.rs`. **Two ports, not three** — the engine now
defaults to `vcalm_rs::engine::SsiEngine`:

- `impl VcalmCredentialStore for VdcCollection`, with
  `type Credential = Arc<ParsedCredential>`. `list_ids` → `all_entries`; `get` →
  `get` + `try_into_parsed`; `add` → `add`, building the storage record from
  `NewCredential`'s JSON body.
- A newtype `impl VcalmSigner for …` over `PresentationSigner` — orphan rules
  block a blanket impl, so it must wrap.
- Pass `context::default_ld_json_context()` as `new_session`'s `context_map`.
  **This is required, not optional:** VCALM bundles no JSON-LD contexts, so
  without it every credential whose `@context` is not inline or statically
  bundled in `ssi` fails verification instead of resolving offline.

You do **not** need to implement `VcalmLdEngine` unless sprucekit wants its own
resolver policy. `SsiEngine` already matches what `verify_raw_credential` did for
the `LdpVc` arm (`AnyDidMethod` + `ContextLoader::empty().with_static_loader()`),
maps claims-vs-proof failures correctly, and does the large-stack hop itself.
Note it handles `LdpVc` only — which is all VCALM ever verifies, since offered
entries are bare Data Integrity VCs.

Keep the module `#[cfg(test)]` at first: that proves VCALM works against real
`VdcCollection` storage without shipping anything.

**Run:** `cargo test` in `rust/`, plus the bindings diff again.

---

## Stage 2 — later

### ⚠️ 1. Facade, or accept a binding change

Cheaper than first estimated, because `ToolkitTypes.kt` set the precedent when
`mobile-toolkit` was extracted (#346): a 34-line hand-written typealias file kept
every pre-existing Kotlin import compiling.

Bindings are generated in **library mode** — `uniffi-bindgen generate --library`
reads metadata from the compiled archive and emits one Swift file per UniFFI
crate found. So vcalm's bindings come along free once `mobile-sdk-rs` depends on
`vcalm-rs` with `features = ["uniffi"]`, given a `uniffi.toml` with a distinct
`ffi_module_name`. Swift sees one module either way; only Kotlin gets a new
package.

That leaves, to hand-write in sprucekit:

- a monomorphized `VcalmHolder` wrapper (~150–250 lines) — `VcalmHolder<C>` is
  generic and cannot be a `uniffi::Object`
- concrete `VcalmMatchedCredentials` / `VcalmMatchedCredential`, for the same
  reason
- a ~20-line `VcalmTypes.kt` typealias file; Swift needs nothing

Everything else — `Vpr`, `Query`, `CredentialQuery`, `StepResult`,
`ProblemDetails`, `VcalmError`, `OfferedValidity`, `VcalmOfferedCredential`,
`VcalmRequestedField` — exports from vcalm-rs directly.

### 2. Cut over

- [ ] `vcalm-rs` as a real git dep; promote adapters out of `cfg(test)`
- [ ] Delete `rust/src/vcalm/` and `pub mod vcalm;`
- [ ] Preserve `mobile_sdk_rs::vcalm::*` as a `pub use` re-export for Rust
      consumers
- [ ] Full matrix: `cargo test`, iOS, Android, Flutter

**While stage 2 is pending:** freeze `rust/src/vcalm/` to bugfixes only and route
new VCALM work to `vcalm-rs` — two copies will drift otherwise.
