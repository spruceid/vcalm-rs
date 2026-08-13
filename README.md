# vcalm-rs

Rust implementation of VCALM — Verifiable Credential API for Lifecycle
Management — the holder side of a [VC API][vcapi] `vcapi` exchange.

The crate owns the *protocol*: the exchange state machine, QueryByExample
matching, verifiable-presentation assembly, and offer classification. It does
**not** own credential storage, key custody, or the JSON-LD / Data Integrity
machinery. Those are supplied by the embedding wallet through three traits.

[vcapi]: https://w3c-ccg.github.io/vc-api/

## Integrating

> [!IMPORTANT]
> **Copy the `[patch.crates-io]` block below into your own workspace root.**
> Cargo only honours `[patch]` in the top-level manifest, so the one in this
> crate's `Cargo.toml` does nothing for you as a dependency.

```toml
[dependencies]
vcalm-rs = { git = "https://github.com/spruceid/vcalm-rs", rev = "..." }

# Required. Without it you resolve `ssi` from crates.io and:
#   1. miss the multiproof `select` fix that selective-disclosure derivation
#      depends on -- SD presentations fail to verify, with no compile error; and
#   2. likely fail to resolve at all, because ssi -> ssi-ucan -> libipld ->
#      libipld-core requires the yanked `core2 0.4.0`.
[patch.crates-io]
ssi = { git = "https://github.com/spruceid/ssi", branch = "fix/multiproof-select-0.14" }
ssi-jwk = { git = "https://github.com/spruceid/ssi", branch = "fix/multiproof-select-0.14" }
ssi-jws = { git = "https://github.com/spruceid/ssi", branch = "fix/multiproof-select-0.14" }
```

Requires Rust 1.85+ (edition 2024).

## The three ports

Implement these over your own wallet, then hand them to the holder. VCALM never
names your credential type — [`VcalmCredentialStore::Credential`] is an
associated type, so your credentials travel through and come back out
statically typed, with no downcast.

| Trait | Supplies | Required? |
| --- | --- | --- |
| `VcalmCredentialStore` | `list_ids` / `get` / `add` over your credential store | yes |
| `VcalmSigner` | the holder key that signs the VP (six methods, `ssi` types) | yes |
| `VcalmLdEngine` | proof verification and SD derivation | **no** — defaults to `engine::SsiEngine` |

```rust
use std::sync::Arc;
use vcalm_rs::holder::VcalmHolder;

let holder = VcalmHolder::new_session(
    store,          // Arc<dyn VcalmCredentialStore<Credential = Arc<MyCredential>>>
    vec![],         // trusted DIDs (forward-looking)
    signer,         // Arc<dyn VcalmSigner>
    context_map,    // Option<HashMap<String, String>> — your bundled JSON-LD contexts
).await?;

match holder.clone().start_exchange(scanned_url, None).await? {
    StepResult::Request { .. } => { /* select credentials, submit_presentation */ }
    StepResult::Offer { .. }   => { /* offered_credentials, then accept/reject */ }
    StepResult::Redirect { url } => { /* terminal */ }
    StepResult::Complete       => {}
    StepResult::Problem { .. } => {}
}
```

### JSON-LD contexts

VCALM bundles none. A credential whose `@context` is neither inline nor
statically bundled in `ssi` must be resolvable from the `context_map` you pass,
or verification fails rather than fetching it. Hosts migrating from
`sprucekit-mobile` should pass its `default_ld_json_context()`.

### Overriding the engine

`engine::SsiEngine` handles verification and selective-disclosure derivation, and
runs both on a large-stack thread (`ssi`'s context expansion overflows iOS's
~512 KB child-thread stack, surfacing as `EXC_BAD_ACCESS code=2`). You only need
your own when the default cannot do the job — an offline-only resolver (the
default resolves `did:web`, which reaches the network), a trust registry,
revocation checks, or caching:

```rust
let holder = VcalmHolder::new_session_with_engine(
    store, vec![], signer, context_map, my_engine,
).await?;
```

If you do implement `VcalmLdEngine`, two obligations carry over: run the work on
a large stack, and keep `VerifyOutcome::ClaimsInvalid` (expired — still
storable) distinct from `ProofInvalid` (aborts the offer). Collapsing those turns
every expired credential into a hard rejection.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `uniffi` | off | UniFFI scaffolding plus FFI derives on the wire types |

Leave `uniffi` off unless you are generating bindings. It pins
`uniffi = "=0.31.1"` exactly, and cross-crate UniFFI type unification requires
every crate in the graph to agree on that version.

Note that `VcalmHolder<C>` is generic and so cannot be a `uniffi::Object`.
Enabling the feature exports the records, enums and error type only; the holder
needs a monomorphized wrapper in the consuming crate.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
