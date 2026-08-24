# rhi — repository agent contract

## 1. Scope and operating model

- This file applies to the complete repository unless a nearer `AGENTS.md` is
  stricter.
- This repository owns `rhi`, the standalone Radroots evidence-reconciliation
  and attestation service. Treat canonical event admission, provenance,
  evidence completeness, outcome meaning, identity, persistence, and
  publication as security-critical behavior.
- Keep the repository independently cloneable, buildable, testable,
  packageable, and operable. Do not depend on private repositories, unreachable
  or unlocked artifacts, internal monorepo paths, absolute workstation paths,
  or private harnesses. An unpublished public dependency is allowed only when
  its exact commit is reachable from the governed public Git source and pinned
  by the checked-in source lock.
- All `.github/**` and capsule-local `.act/**` workflow definitions are
  forbidden. Keep validation forge-agnostic, do not depend on a private
  harness, and leave orchestration exclusively to the parent repository's root
  `.act/**` authority.
- Capsule-local human specs, ADRs, runbooks, test plans, and execution evidence
  are not owned here; place that authority under the parent repository's
  `docs/oss/rhi/**`. Standalone machine contracts and ordinary source, test,
  build, package, and operational assets remain capsule-owned.
- Do not add or retain tracked `docs/**`, `.github/**`, or `.act/**` content in
  this capsule. Keep human documentation under the parent authority above and
  machine-enforced declarations under governed standalone contract surfaces.
- RHI does not own worldwide evidence completeness, trade agreement or
  settlement authority, relay storage/tenancy, general SDK generation, hosted
  accounts, telemetry, artifact promotion, or deployment transport.

## 2. Authority and preflight

- Before editing, read this file, `README`, `Cargo.toml`,
  `radroots.service.source-lock.v2.toml`, and the relevant implementation and
  tests. The removed prototype root `config.toml` is not configuration
  authority.
- `.radroots-consumer-root` is the standalone source-lock identity and must
  remain exactly `rhi`. The reserved pre-implementation evidence authority is
  `contracts/services_hardening/evidence_policy.v1.json`, and the reserved
  pre-implementation operator authority is
  `contracts/services_hardening/operator_contract.v1.json`. RHI source and
  configuration must implement their exact source, selector, cursor,
  completion, coverage, digest, publication-independence, route, wire-model,
  identity-role, pagination, mutation, doctor, exit, and TCP semantics;
  prototype source behavior is not permission to reinterpret them.
- Treat checked-in source, tests, configuration, and prototype behavior as
  implementation evidence, not permission to preserve behavior that the active
  requirement removes.
- Do not invent event kinds or tags, evidence-policy fields, source semantics,
  protocol behavior, APIs, dependencies, release processes, identity authority,
  migration behavior, or external integration semantics.
- Inspect `git status --short`, the exact repository root, and nearby tests
  before changing behavior. Preserve unrelated work and stop on an unresolved
  evidence-integrity, identity, or publication conflict.
- Keep changes narrowly scoped and independently reviewable. Do not mix
  unrelated cleanup, speculative abstractions, roadmap work, or compatibility
  scaffolding into a checkpoint.

## 3. Clean-slate service rule

- Do not add or preserve prototype configuration readers, `.env` runtime
  configuration, `RHI_*` runtime selectors, worker paths, JSON/JSONL mutable
  state, prototype config/state importers or migrations, old-path probes,
  aliases, fallbacks, dual readers/writers or event decoders, deprecated
  modules/APIs/re-exports, or old/new feature switches. Offline production
  schema migration must never accept an unreleased prototype format.
- Remove superseded behavior and update every affected Radroots-owned consumer
  directly. Do not hide a breaking change behind a compatibility adapter unless
  an accepted public requirement explicitly requires one.
- Preserve canonical public Nostr interoperability. Clean-slate product
  behavior never authorizes wire drift, ad hoc event kinds/tags, or relaxed
  signature, event-ID, content, or tag validation.
- A breaking config, CLI, state, evidence, report, attestation, admin, error, or
  wire change must update its public machine contracts, examples, tests,
  generated surfaces, source guards, and release qualification in the same
  coherent sequence.

## 4. Canonical admission and provenance

- Bound event bytes, content, tags, per-tag and aggregate tag bytes, extras,
  source results, and authored time before admission. Verify the Nostr event ID
  and signature, registered kind, author, canonical mutation content and ID,
  canonical serialization, mandatory structural tag cardinality/content
  binding, duplicate or conflicting structural tags, and explicit time policy.
- Route accepted trade mutations only through the sealed
  `admit_rhi_trade_mutation_event` boundary. Its wire limits come from the
  validated configuration, its future-time tolerance is explicit with no
  default, and it remains pure; persistence belongs only to the separate typed
  repository transaction introduced by Step 184.
- Persist canonical mutation, every distinct signed event carrying it, and
  every accepted source observation as separate typed facts. Two events for one
  mutation never overwrite one another, and arrival order never selects truth.
- Reject malformed, unsupported, wrong-author, wrong-kind, wrong-ID, wrong-tag,
  excessive-future, conflicting, or oversized input before it creates accepted
  evidence, advances a checkpoint/completion, or increments dirty generation.
- Make exact event replay idempotent. Repeated source observation preserves the
  first bounded provenance fact without multiplying authoritative evidence;
  conflicting content for one mutation ID fails independently of arrival order.
- Persist observation and audit time from the injected wall clock using named
  integer UTC units. Keep event-authored time as distinct untrusted input; never
  label, persist, or reuse it as source observation time.
- Scope checkpoints by stable source plus exact selector/policy. Preserve
  equal-timestamp discovery through overlap and deduplication; never use one
  global authored timestamp as the sole cursor.
- Increment dirty generation only for relevant newly accepted evidence or a
  governing policy change. Duplicate provenance, rejection, and operational
  retry do not dirty a trade.

## 5. Evidence reconciliation, coverage, and outcome

- Persist bounded jobs, attempts, lease ownership/expiry, failure counts,
  source request/completion/cursor evidence, and next-attempt schedules. Use
  compare-and-swap claims, bounded concurrency, renewable/reclaimable leases,
  injected time and jitter, and deterministic crash/reopen recovery.
- Record each source result with exact selector digest, required/optional
  authority, stable request identity, deadline, lookback/cursor, completion
  evidence, accepted-event count, safe outcome code, and bounded timing.
- Derive the bounded canonical per-source request inventory only from an
  unexpired claimed reconciliation lease and the exact normalized evidence
  policy. Attempt, selector, and request identities are domain-separated;
  every deadline is absolute and capped by both configuration and lease
  expiry; result ingestion consumes at most the configured source count plus
  one before rejecting missing, duplicate, reordered, or excess evidence.
- Query every configured source outside write transactions. A timeout,
  unsupported adapter, partial result, raw upstream error, or unknown
  completion never masquerades as success.
- Bind every resumed request to its exact prior authored-time/event-ID cursor,
  subtract the configured overlap for an inclusive query start, canonicalize
  distinct signed-event identities, retain the earliest injected provenance,
  and reject conflicting mutation or signed-event identity reuse before the
  Step 190 commit boundary.
- Freeze the exact accepted mutation, signed-event, provenance, and per-source
  completion inventory in an immutable canonical manifest. Reducers consume a
  canonically ordered immutable set with explicit policy digest, reducer
  version, coverage, and observed-time input; they have no database insertion,
  relay, scheduling, wall-clock, entropy, or network dependency.
- Mint the immutable reconciliation manifest only by consuming a sealed,
  durably confirmed source-commit outcome. Bind each source result to its exact
  selector, completion, cursor, timing, and persisted-inventory digest, and
  bind each observation to the exact canonical signed-event and first-source
  provenance. Do not expose a raw manifest constructor or parser from RHI.
- Keep Step 191 manifest materialization pure and in memory. Step 199 alone
  owns durable manifest persistence; reducers, coverage/outcome, attestation,
  publication, and job finalization retain their ordered owners.
- Reduce only the sealed owned reconciliation manifest. Retain its bounded
  canonical mutation material privately from the confirmed Step 190 commit,
  map its already-governed evidence coverage into the shared reducer input,
  and bind the canonical shared projection digest to the exact manifest and
  evidence-policy digests. Do not accept caller mutation material or add
  SQLite, filesystem, source, relay, task, clock, entropy, or network access.
- Derive claim-specific coverage and outcome only from that sealed projection.
  Missing, partial, unsupported, unavailable, ambiguous, unresolved, or absent
  evidence is `Indeterminate`; evidence absence never becomes `Invalid`.
  Permit `Valid` only for one clean active agreement claim and `Invalid` only
  for one clean cancelled claim. Emit only the fixed stable reason vocabulary.
- Coverage is exactly `Missing`, `Partial`, `ScopeSatisfied`, or `Unsupported`.
  ScopeSatisfied means only that the configured policy was satisfied; optional
  evidence never substitutes for required-source completion.
- Outcome is exactly `Valid`, `Invalid`, or `Indeterminate`. Missing, partial,
  unsupported, unavailable, ambiguous, or unresolved required evidence is
  Indeterminate; absence never becomes invalidity.
- Fence final work by dirty generation and policy digest. A stale worker cannot
  overwrite newer evidence, and CAS loss leaves no partial report, outbox,
  source completion, checkpoint, or job finalization.
- Carry the exact committed attempt and job identities privately through the
  sealed manifest, projection, and evaluation chain. A finalization preflight
  is not commit authority: rerun its exact lease, generation, policy, and
  attempt validator inside the Step 199 atomic transaction before any write.

## 6. Report, attestation, and publication invariants

- Bind every immutable report to contract ID/version, issuer public key, trade
  ID, exact claim mutation ID, policy and manifest digests, reducer
  contract/version, projection digest, outcome and stable reasons, integer UTC
  observation time, attestation method `signed_evidence_snapshot`, statement
  digest, and explicit superseded report/event reference when applicable.
- Construct the canonical domain-separated statement payload from governed
  semantic fields only. Exclude self-referential digest, signature, event ID,
  and derived fields; never invent an encoding, preimage, kind, tag, or query.
- Build and sign through typed governed APIs, then revalidate issuer/author,
  exact unsigned fields, event ID, signature, canonical report binding, and
  applicable Nostr semantics before persistence or publication.
- Construct a signed reconciliation attestation only by consuming the sealed
  finalization fence and the independently verified encrypted service identity.
  Accept authored time and exactly 32 bytes of Schnorr auxiliary randomness
  only through injected authorities. Retain the exact independently verified
  signed JSON bytes and their SHA-256; never rebuild, reserialize, or re-sign
  them after the boundary succeeds.
- Accept an attestation supersession input only when it is derived from a prior
  sealed verified RHI attestation, and rerun the shared report/event binding and
  ordering validator before exposing the successor. This pure signing boundary
  has no SQLite, filesystem, relay, network, task, or publication authority.
- One generation-fenced transaction commits attempt/source results, immutable
  manifest/projection/report, supersession, exact serialized signed event
  bytes/digest, immutable target set and initial outbox when required, accepted
  source completion/checkpoints, and job finalization before relay I/O.
- Publication is explicitly `required` or `disabled`. Retry and recovery submit
  only the committed exact bytes; never deserialize, rebuild, reserialize,
  re-sign, or change targets.
- Distinguish pending, submitted, accepted, rejected, rate-limited,
  auth-required, failed, and unknown target evidence. Submission or lost
  acknowledgement never proves delivery or failure.
- Keep profile and application-handler presence as deterministic durable desired
  state with the same commit-before-I/O and exact-byte retry discipline.

## 7. Configuration, identity, state, and process boundaries

- Load exactly one immutable TOML document with
  `schema = "radroots.rhi.config"` and `schema_version = 1`. Reject unknown
  fields at every object boundary, implicit relays/sources,
  complete-by-default evidence, unsafe defaults, environment overlays,
  includes, interpolation, fragments, stdin configuration for `run`, hot
  reload, and arbitrary leaf flags.
- Parse bootstrap profile, instance, repo-local root, and an optional absolute
  config path once as CLI authority; they are not TOML fields. Human output is
  the default and governed machine output is explicit.
- Keep every real source explicit with a stable ID, required/optional status,
  exact selector, deadline, lookback, overlap/cursor and failure/completion
  policy, and relationship to publication. Bind the complete normalized
  authority in the evidence-policy digest. Add an adapter only for a real,
  qualified evidence source; do not invent a generic source mode.
- Give relays and sources unique stable IDs, canonical URLs, and explicit
  read/write/required authority as applicable. Production public connections
  enforce secure transport, every-answer network policy, and preserved TLS
  SNI/certificate identity; plaintext loopback is simulator-only and is never
  selected implicitly.
- Keep parsing and semantic validation pure: no path creation, identity or
  credential access, SQLite, DNS, network, clocks, entropy, logging setup,
  process mutation, or panic.
- Identity uses only the governed encrypted envelope and separately named
  wrapping credential. Do not add plaintext or adjacent keys, implicit identity,
  or ordinary-run generation/replacement. Validate expected public-key and
  policy bindings before readiness.
- Resolve the wrapping credential only from the validated fixed artifact name
  beneath the same instance's canonical secrets root. The resolver is
  read-existing-only, accepts no caller path or bytes, and supports only
  service-host and repo-local profiles. The governed envelope and credential
  are excluded from state backups.
- Do not read, reseal, import, or migrate prototype or legacy identity-envelope
  formats. Missing, wrong, legacy, or misbound envelopes and wrapping
  credentials fail closed.
- Each instance owns one explicitly initialized `state.sqlite`, retained
  `state.lock`, exclusive instance lock, and one live writer authority. Normal
  `run` opens existing state only and verifies service, instance, source
  generation, schema/migration checksums, identity, and policy metadata before
  readiness. Raw pools, connections, or cloneable write authority never escape
  typed RHI repositories; live clients mutate only through the Unix admin
  boundary and offline state operations must prove that no daemon writer exists.
- Create-new state begins at the shared schema-v1 baseline and applies the
  governed RHI schema-v2 configuration-binding migration, schema-v3
  immutable trade-evidence migration, schema-v4 source-checkpoint and
  dirty-generation migration, schema-v5 bounded reconciliation-job migration,
  and schema-v6 immutable reconciliation-attempt/source-result migration.
  Retain at most 1,024 consecutive
  immutable configuration generations containing only normalized
  config/evidence-policy digests, public identity, exact contract versions,
  injected apply time, and bounded build identity. Persist each canonical
  mutation, independently signed Nostr event, and accepted configured-source
  observation as distinct immutable facts in one SQLx transaction. Exact replay
  is idempotent, conflicts fail closed, observation time remains distinct from
  authored time, and this persistence step must not advance reconciliation
  checkpoints or dirty generation. The composed relay-source ingest path may
  advance only its exact scoped checkpoint after complete EOSE evidence and
  may dirty a trade only for newly inserted mutation or signed-event evidence;
  replayed source observation alone does neither. Never persist raw TOML,
  paths, URLs, credential references, or protected identity material. Ordinary startup must
  use intent-open, discover source generation under retained authority, and
  match the latest durable binding; configuration apply is an exclusive offline
  operation.
- Commit one exact reconciliation-attempt replay inventory only through the
  typed attempt repository. Revalidate the exact live lease, dirty generation,
  evidence policy, and every scoped prior checkpoint before mutation; persist
  evidence, immutable results, the exact ordered fact/provenance inventory
  digest, at most one dirty advance, and eligible checkpoints atomically.
  Incomplete or unsupported results never advance, and committed cursor
  evidence is minted only after durable commit confirmation.
- Never hold a database transaction while waiting for a source, relay, DNS,
  identity provider, clock, entropy, signing, reduction, or backoff.
- Never prune active jobs/outboxes, migration history, current identity/policy
  bindings, evidence required to reproduce a current attestation, immutable
  report/supersession history, or exact signed bytes required for retry/audit.
  Any allowed compaction must be explicit, transactional, bounded, and
  verifiability-preserving.
- Parse the process CLI and initialize the tracing subscriber only in the binary
  composition boundary. Libraries may emit tracing events but must not install
  signal handlers, create Tokio runtimes, call `process::exit`, spawn arbitrary
  executables, or detach authoritative tasks.
- Inject wall time, monotonic time, entropy, transport, identity providers,
  evidence sources, and failpoints. Supervise and join every authoritative task;
  panic, error, or unexpected successful return from a critical task must
  coordinate shutdown and produce a nonzero process result.
- Compose those dependencies only through the sealed runtime-adapter boundary.
  Wall UTC and process-local monotonic observations remain distinct; jitter is
  bounded whole-millisecond full jitter derived only from injected entropy.
  The transport-neutral `radroots_transport` source, subscription, and sink
  traits are the sole generic event I/O SPI. Credential access must precede
  independently verified encrypted-identity access, with no fallback or
  generation. The adapter set owns one private shared `TaskSupervisor` and
  exposes no task handle or concrete transport handle.
- The existing-state runtime foundation must verify durable configuration
  before credential/identity access and must contact no event source,
  subscriber, or publication sink. Its passive initial readiness may prove
  only existing state, durable configuration, and verified identity. Recovery,
  connectivity, listeners, presence desired state, signals, logging, and the
  final supervised graph remain with their later owning checkpoints.
- Library code must not install signals, create a runtime, install logging,
  call process exit, or detach an authoritative task. Those process authorities
  remain exclusively with the final binary checkpoint.
- On startup, reclaim expired reconciliation/publication leases, resume durable
  retry schedules with injected bounded jitter, retain unknown submissions,
  finalize already-proven outcomes idempotently, and scan all authoritative
  relationships. Impossible, corrupt, misbound, orphaned, newer-schema, or
  checksum-invalid state fails closed or enters an explicitly safe
  repair-required state; it is never silently deleted or guessed.
- The first termination signal begins bounded graceful shutdown and preserves
  durable claims and exact publication state; a second signal forces
  termination. Critical-task and shutdown failures remain nonzero.

## 8. Admin, observability, recovery, and secret boundaries

- Parse the CLI once and dispatch only pure/offline bootstrap, a live Unix admin
  client, or the daemon. Config validation/schema and pre-service initialization
  are offline. State init/restore/verify/migrate and initial identity
  provisioning require proof that no writer lock exists.
- Detailed status, redacted effective config, online backup, identity status
  and public export, reconciliation/job/source status, bounded trade/report
  queries, publication/target retry or refresh, metrics snapshot, and presence
  status/refresh use bounded, versioned HTTP/JSON over a permissioned Unix
  socket while live. Do not add TCP admin, browser auth, CORS, direct writable
  CLI fallback, or live direct-SQLite mutation.
- Enforce peer credentials only to the strength qualified for the platform;
  keep Linux Tier-1 and filesystem-permission behavior explicit.
- Bind every mutation to stable operation/correlation identity, idempotent
  replay, conflicting-reuse rejection, typed bounded responses, and explicit
  safe confirmation for destructive or identity-sensitive work. Never unlink
  a live socket owner; remove only a proven stale socket under the resolved
  instance runtime directory.
- Optional TCP operations expose only cached `/livez`, `/readyz`, and
  `/metrics`; requests must not perform SQLite, source, relay, DNS, identity,
  evidence, or credential probes.
- Keep logs as safe structured stderr output. Keep result data on stdout and
  diagnostics on stderr. Use stable bounded public codes/messages, bounded
  metric labels, explicit redaction, and no trade/mutation/event/report IDs or
  arbitrary upstream text as labels.
- Doctor uses bounded active checks with per-check deadlines, safe structured
  required/optional results, and a nonzero result for required failure or
  timeout. It covers paths/permissions, writer lock, schema/integrity/free disk,
  identity/credential, bind/network policy, required source reachability,
  checkpoint plausibility, leases/backlog, publication invariants, and clock
  skew without leaking protected details.
- Keep plaintext keys, decrypted identity, wrapping credentials, tokens, raw
  sensitive evidence, private identifiers, paths, upstream errors, and
  equivalent protected material out of config, logs, status, metrics, audit,
  fixtures, packages, process arguments, environment contracts, error strings,
  and backups. Governed state backups contain neither the encrypted identity
  envelope nor any material needed to unwrap it.
- Backup and restore must preserve writer-lock, manifest, digest, integrity,
  schema, service, instance, identity, policy, permission, fsync, atomic-rename,
  and protected-material-exclusion invariants. Orphaned or impossible state
  fails closed or enters an explicitly safe repair-required state; never delete
  or guess it silently.

## 9. Rust and test discipline

- The final Rust baseline is edition 2024, resolver 3, and Rust/toolchain
  1.97.1. Keep `Cargo.toml`, `rust-toolchain.toml`, and Cargo metadata in exact
  agreement.
- Keep `#![forbid(unsafe_code)]` at crate roots; unsafe code is forbidden. Deny
  broken rustdoc links, `dbg!`, `todo!`, and `unimplemented!` in production.
- Prefer pure transformations, explicit state machines, validated newtypes,
  tagged serialized enums, narrow side-effect boundaries, and private or
  `pub(crate)` visibility.
- Keep every implementation module private and expose intended library names
  only through the curated crate root. Regenerate and byte-compare
  `contracts/api_baselines/rhi.txt` whenever that public surface changes.
- Public errors must use RHI-owned stable classifications with redacted
  Display and Debug output and no raw dependency-owned source chain.
- Use `thiserror` for library/domain errors and `anyhow` only at binary, xtask,
  or one-shot composition boundaries. Avoid production `unwrap`/`expect` and
  environment-dependent `Default`; ordinary `Debug` must never expose secrets.
- Add deterministic positive, negative, exact-boundary, just-over, permutation,
  concurrency, crash/retry, cancellation, saturation, redaction, and public-wire
  interoperability tests for every behavior change. Tests must not depend on
  ambient network or machine-specific state and must contain no real secrets,
  realistic private keys, or sensitive evidence.
- Bound every input, adapter result, queue, pool, worker, lease, retry, query,
  response, deadline, backlog, retention set, and in-memory collection.
- Treat generated files as generated. Update them through the owning command
  and run the corresponding freshness check.
- Keep the native release generator private to `tools/xtask`. It may read
  only an exact clean committed capsule revision and must write only one
  caller-selected external output directory using the closed inventory in
  `contracts/services_hardening/native_release.v1.json`. It must retain
  bounded streaming I/O, deterministic archives, exact mode and durability
  checks, protected-material scanning, and stable path-free errors.
- Standalone package material may include the fixed systemd instance unit,
  config example/schema, native binary/source archives, SBOM, notices,
  provenance input, source lock, checksums, and manifest. It must not include
  parent-owned human docs, credentials, Nix or OCI inputs/outputs, private
  harnesses, signatures, tags, publication, deployment, or generated artifacts
  in the source tree.

## 10. Canonical verification

Through RCLD-RSHR-170, run the standalone native command authority through
extbuild. Do not install, repair, invoke, or require Nix, and do not claim Nix,
NixOS-module, or Nix-produced OCI qualification:

```text
cargo extbuild doctor
cargo extbuild run -- cargo fmt --all --check
cargo extbuild run -- cargo check --workspace --all-targets --locked
cargo extbuild run -- cargo test --workspace --all-targets --locked
cargo extbuild run -- cargo clippy --workspace --all-targets --locked -- -D warnings
cargo extbuild run -- env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --locked
```

The complete release contract also requires locked all-target check and test
with serialized tests, warnings-denied all-target Clippy, warnings-denied
rustdoc, the source-lock and package-boundary tests, and diff hygiene. Run
additional coverage, SQLx freshness, source-lock, package, systemd, SBOM,
checksum, notice, and fresh-install gates when their surfaces change. Nix and
OCI remain deferred and unclaimed through RCLD-RSHR-170. Use narrower commands
only for iteration, and never claim a command passed unless it ran
successfully.

## 11. Commits and irreversible actions

- Format commits as `<scope>: <imperative summary>`, with a blank line and
  `- ` bullets when a body is useful. Split unrelated changes.
- Report the exact files changed, behavior changed, commands run, results,
  unresolved risks, and whether the next checkpoint is safe.
- Do not publish, push, tag, sign, deploy, rotate credentials, change ownership,
  or mutate external runtime state without explicit authorization for that exact
  action.
