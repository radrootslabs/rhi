//! Injected, bounded runtime capability composition.

use core::{fmt, time::Duration};
use std::{error::Error, sync::Arc};

use radroots_service_host::{
    EntropySource, MonotonicClock, MonotonicDeadline, MonotonicTime, SystemEntropy,
    SystemMonotonicClock, SystemWallClock, TaskSupervisor, UnixTimeSeconds, WallClock,
};
use radroots_transport::{EventSink, EventSource, EventSubscriber};

use crate::{
    RhiCredentialResolutionError, RhiDecryptedIdentity, RhiEncryptedIdentityEnvelopeError,
    RhiIdentityEnvelopeBinding, RhiRuntimeContext, RhiWrappingCredential,
    open_rhi_encrypted_identity, resolve_rhi_wrapping_credential,
};

#[cfg(test)]
const RUNTIME_ADAPTER_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_adapters.v1.json");

/// Exact version of the RHI runtime-adapter contract.
pub const RHI_RUNTIME_ADAPTER_CONTRACT_VERSION: u32 = 1;

/// Largest full-jitter ceiling admitted by the RHI v1 configuration contract.
pub const RHI_RUNTIME_JITTER_MAX_MILLISECONDS: u64 = 3_600_000;

/// Maximum entropy draws allowed for one exact unbiased full-jitter sample.
pub const RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS: usize = 16;

/// Stable source-free runtime-adapter failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiRuntimeAdapterErrorKind {
    InvalidJitterBound,
    EntropyUnavailable,
    WallClockUnavailable,
    MonotonicDeadlineInvalid,
    CredentialAccess,
    IdentityAccess,
}

impl RhiRuntimeAdapterErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidJitterBound => "runtime_jitter_bound_invalid",
            Self::EntropyUnavailable => "runtime_entropy_unavailable",
            Self::WallClockUnavailable => "runtime_wall_clock_unavailable",
            Self::MonotonicDeadlineInvalid => "runtime_monotonic_deadline_invalid",
            Self::CredentialAccess => "runtime_credential_access_failed",
            Self::IdentityAccess => "runtime_identity_access_failed",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidJitterBound => "RHI jitter bound is invalid",
            Self::EntropyUnavailable => "RHI entropy source is unavailable",
            Self::WallClockUnavailable => "RHI wall clock is unavailable",
            Self::MonotonicDeadlineInvalid => "RHI monotonic deadline is invalid",
            Self::CredentialAccess => "RHI credential access failed",
            Self::IdentityAccess => "RHI identity access failed",
        }
    }
}

/// One redacted source-free runtime-adapter failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiRuntimeAdapterError {
    kind: RhiRuntimeAdapterErrorKind,
}

impl RhiRuntimeAdapterError {
    const fn new(kind: RhiRuntimeAdapterErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> RhiRuntimeAdapterErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiRuntimeAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeAdapterError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiRuntimeAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiRuntimeAdapterError {}

/// Validated inclusive maximum for one full-jitter sample, in whole milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiJitterBoundMilliseconds(u64);

impl RhiJitterBoundMilliseconds {
    /// Validates a whole-millisecond bound against the complete RHI v1 ceiling.
    pub const fn new(milliseconds: u64) -> Result<Self, RhiRuntimeAdapterError> {
        if milliseconds > RHI_RUNTIME_JITTER_MAX_MILLISECONDS {
            Err(RhiRuntimeAdapterError::new(
                RhiRuntimeAdapterErrorKind::InvalidJitterBound,
            ))
        } else {
            Ok(Self(milliseconds))
        }
    }

    /// Returns the inclusive maximum in whole milliseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One injected full-jitter result, in whole milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiJitterMilliseconds(u64);

impl RhiJitterMilliseconds {
    /// Returns the sampled value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the sampled value as a duration.
    #[must_use]
    pub const fn duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

/// Injected wall-time, monotonic-time, and entropy capabilities.
pub struct RhiTimeEntropyAdapters {
    wall: Arc<dyn WallClock>,
    monotonic: Arc<dyn MonotonicClock>,
    entropy: Arc<dyn EntropySource>,
}

impl RhiTimeEntropyAdapters {
    /// Owns injected adapters without reading a clock or entropy source.
    pub fn new<W, M, E>(wall: W, monotonic: M, entropy: E) -> Self
    where
        W: WallClock + 'static,
        M: MonotonicClock + 'static,
        E: EntropySource + 'static,
    {
        Self {
            wall: Arc::new(wall),
            monotonic: Arc::new(monotonic),
            entropy: Arc::new(entropy),
        }
    }

    /// Constructs the production adapters without reading any value yet.
    #[must_use]
    pub fn system() -> Self {
        Self::new(SystemWallClock, SystemMonotonicClock::new(), SystemEntropy)
    }

    /// Reads one explicit whole-second UTC observation.
    pub fn now_utc(&self) -> Result<UnixTimeSeconds, RhiRuntimeAdapterError> {
        self.wall.now_utc().map_err(|_| {
            RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::WallClockUnavailable)
        })
    }

    pub(crate) fn now_utc_milliseconds(&self) -> Result<u64, RhiRuntimeAdapterError> {
        self.now_utc()?
            .get()
            .checked_mul(1_000)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| {
                RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::WallClockUnavailable)
            })
    }

    /// Reads one observation from the injected process-local monotonic domain.
    #[must_use]
    pub fn now_monotonic(&self) -> MonotonicTime {
        self.monotonic.now_monotonic()
    }

    /// Computes a deadline in the injected monotonic domain without wrapping.
    pub fn deadline_after(
        &self,
        duration: Duration,
    ) -> Result<MonotonicDeadline, RhiRuntimeAdapterError> {
        self.monotonic.deadline_after(duration).map_err(|_| {
            RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::MonotonicDeadlineInvalid)
        })
    }

    /// Samples unbiased full jitter in the inclusive range `0..=maximum`.
    ///
    /// Rejection sampling is capped so an adversarial injected entropy source
    /// cannot keep one scheduler decision pending indefinitely.
    pub fn sample_full_jitter(
        &self,
        maximum: RhiJitterBoundMilliseconds,
    ) -> Result<RhiJitterMilliseconds, RhiRuntimeAdapterError> {
        let range = maximum.get() + 1;
        let rejection_threshold = range.wrapping_neg() % range;
        for _ in 0..RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS {
            let mut bytes = [0_u8; 8];
            self.entropy.fill_bytes(&mut bytes).map_err(|_| {
                RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::EntropyUnavailable)
            })?;
            let product = u128::from(u64::from_be_bytes(bytes)) * u128::from(range);
            let low = u64::try_from(product & u128::from(u64::MAX))
                .expect("masked multiply-high remainder fits u64");
            if low >= rejection_threshold {
                let sampled = u64::try_from(product >> u64::BITS)
                    .expect("multiply-high full-jitter result fits the admitted u64 bound");
                return Ok(RhiJitterMilliseconds(sampled));
            }
        }
        Err(RhiRuntimeAdapterError::new(
            RhiRuntimeAdapterErrorKind::EntropyUnavailable,
        ))
    }
}

impl fmt::Debug for RhiTimeEntropyAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiTimeEntropyAdapters([injected])")
    }
}

/// Transport-neutral capabilities for bounded evidence fetch, live subscription, and publication.
///
/// Construction performs no network, DNS, or TLS operation. The capabilities
/// remain sealed inside RHI so concrete transports and detachable I/O handles
/// do not become public runtime authority.
pub struct RhiTransportAdapters {
    evidence_source: Arc<dyn EventSource>,
    _evidence_subscriber: Arc<dyn EventSubscriber>,
    _publication_sink: Arc<dyn EventSink>,
}

impl RhiTransportAdapters {
    /// Binds the complete transport-neutral capability inventory without I/O.
    #[must_use]
    pub fn new(
        evidence_source: Arc<dyn EventSource>,
        evidence_subscriber: Arc<dyn EventSubscriber>,
        publication_sink: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            evidence_source,
            _evidence_subscriber: evidence_subscriber,
            _publication_sink: publication_sink,
        }
    }

    pub(crate) fn evidence_source(&self) -> &dyn EventSource {
        self.evidence_source.as_ref()
    }
}

impl fmt::Debug for RhiTransportAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiTransportAdapters([sealed])")
    }
}

/// Injected read-existing-only wrapping-credential access.
pub trait RhiCredentialAccess: Send + Sync {
    /// Resolves the configured credential for the exact runtime and identity binding.
    fn resolve_existing(
        &self,
        runtime: &RhiRuntimeContext,
        binding: &RhiIdentityEnvelopeBinding,
    ) -> Result<RhiWrappingCredential, RhiCredentialResolutionError>;
}

/// Injected read-existing-only encrypted-identity access.
pub trait RhiIdentityAccess: Send + Sync {
    /// Opens and independently verifies the exact configured encrypted identity.
    fn open_existing(
        &self,
        binding: &RhiIdentityEnvelopeBinding,
        credential: &RhiWrappingCredential,
    ) -> Result<RhiDecryptedIdentity, RhiEncryptedIdentityEnvelopeError>;
}

/// Canonical credential resolver backed by the governed instance artifact boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalRhiCredentialAccess;

impl RhiCredentialAccess for CanonicalRhiCredentialAccess {
    fn resolve_existing(
        &self,
        runtime: &RhiRuntimeContext,
        binding: &RhiIdentityEnvelopeBinding,
    ) -> Result<RhiWrappingCredential, RhiCredentialResolutionError> {
        resolve_rhi_wrapping_credential(runtime, binding)
    }
}

/// Canonical encrypted-identity opener backed by the governed envelope boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalRhiIdentityAccess;

impl RhiIdentityAccess for CanonicalRhiIdentityAccess {
    fn open_existing(
        &self,
        binding: &RhiIdentityEnvelopeBinding,
        credential: &RhiWrappingCredential,
    ) -> Result<RhiDecryptedIdentity, RhiEncryptedIdentityEnvelopeError> {
        open_rhi_encrypted_identity(binding, credential)
    }
}

/// Ordered credential-then-identity access with no fallback or ambient selector.
pub struct RhiIdentityCredentialAdapters {
    credential: Arc<dyn RhiCredentialAccess>,
    identity: Arc<dyn RhiIdentityAccess>,
}

impl RhiIdentityCredentialAdapters {
    /// Owns injected accessors without reading a credential or identity.
    #[must_use]
    pub fn new(
        credential: Arc<dyn RhiCredentialAccess>,
        identity: Arc<dyn RhiIdentityAccess>,
    ) -> Self {
        Self {
            credential,
            identity,
        }
    }

    /// Constructs the canonical read-existing-only accessors without performing I/O.
    #[must_use]
    pub fn canonical() -> Self {
        Self::new(
            Arc::new(CanonicalRhiCredentialAccess),
            Arc::new(CanonicalRhiIdentityAccess),
        )
    }

    /// Resolves the credential first, then opens and verifies the identity.
    pub fn open_existing(
        &self,
        runtime: &RhiRuntimeContext,
        binding: &RhiIdentityEnvelopeBinding,
    ) -> Result<RhiDecryptedIdentity, RhiRuntimeAdapterError> {
        let credential = self
            .credential
            .resolve_existing(runtime, binding)
            .map_err(|_| {
                RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::CredentialAccess)
            })?;
        self.identity
            .open_existing(binding, &credential)
            .map_err(|_| RhiRuntimeAdapterError::new(RhiRuntimeAdapterErrorKind::IdentityAccess))
    }
}

impl fmt::Debug for RhiIdentityCredentialAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiIdentityCredentialAdapters([sealed])")
    }
}

/// Complete injected RHI foundation adapters with privately join-owned tasks.
///
/// This value creates no runtime, installs no signal or logger, performs no
/// transport or identity I/O, and exposes no task handle or supervisor.
#[must_use = "runtime adapters retain join-owned task authority"]
pub struct RhiRuntimeAdapters {
    time_entropy: RhiTimeEntropyAdapters,
    _transport: RhiTransportAdapters,
    identity_credential: RhiIdentityCredentialAdapters,
    supervisor: TaskSupervisor,
}

impl RhiRuntimeAdapters {
    /// Composes already-constructed injected capabilities without invoking them.
    pub fn new(
        time_entropy: RhiTimeEntropyAdapters,
        transport: RhiTransportAdapters,
        identity_credential: RhiIdentityCredentialAdapters,
    ) -> Self {
        Self {
            time_entropy,
            _transport: transport,
            identity_credential,
            supervisor: TaskSupervisor::new(),
        }
    }

    /// Returns the injected time and entropy boundary.
    #[must_use]
    pub const fn time_entropy(&self) -> &RhiTimeEntropyAdapters {
        &self.time_entropy
    }

    /// Returns the ordered identity and credential boundary.
    #[must_use]
    pub const fn identity_credential(&self) -> &RhiIdentityCredentialAdapters {
        &self.identity_credential
    }

    /// Returns the number of join-owned tasks currently registered.
    #[must_use]
    pub fn supervised_task_count(&self) -> usize {
        self.supervisor.task_count()
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), ()> {
        self.supervisor.request_cancellation();
        self.supervisor
            .supervise()
            .await
            .map(|_| ())
            .map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn supervisor_mut(&mut self) -> &mut TaskSupervisor {
        &mut self.supervisor
    }
}

impl fmt::Debug for RhiRuntimeAdapters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeAdapters")
            .field("time_entropy", &"[injected]")
            .field("transport", &"[sealed]")
            .field("identity_credential", &"[sealed]")
            .field("supervised_task_count", &self.supervised_task_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::{
        future::ready,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use radroots_service_host::{
        EntropyError, HostError, MonotonicClockError, ShutdownPhase, TaskClassification,
        TaskMetadata, TaskName, WallClockError,
    };
    use radroots_transport::{
        BoxFuture, DeliveryReceipt, DeliveryRequest, EventSubscription, FetchPage, FetchRequest,
        SinkFailure, SinkStatus, SourceStatus, SubscriptionRequest,
    };

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedWall(Result<UnixTimeSeconds, WallClockError>);

    impl WallClock for FixedWall {
        fn now_utc(&self) -> Result<UnixTimeSeconds, WallClockError> {
            self.0
        }
    }

    #[derive(Clone, Copy)]
    struct FixedMonotonic(MonotonicTime);

    impl MonotonicClock for FixedMonotonic {
        fn now_monotonic(&self) -> MonotonicTime {
            self.0
        }
    }

    #[derive(Clone, Copy)]
    struct FixedEntropy(Result<u64, EntropyError>);

    impl EntropySource for FixedEntropy {
        fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), EntropyError> {
            let value = self.0?;
            destination.copy_from_slice(&value.to_be_bytes());
            Ok(())
        }
    }

    struct NoIoTransport;

    impl EventSource for NoIoTransport {
        fn status(&self) -> BoxFuture<'_, Result<SourceStatus, radroots_transport::Error>> {
            Box::pin(ready(Err(radroots_transport::Error::UnsupportedOperation)))
        }

        fn fetch(
            &self,
            _request: FetchRequest,
        ) -> BoxFuture<'_, Result<FetchPage, radroots_transport::Error>> {
            Box::pin(ready(Err(radroots_transport::Error::UnsupportedOperation)))
        }
    }

    impl EventSubscriber for NoIoTransport {
        fn subscribe(
            &self,
            _request: SubscriptionRequest,
        ) -> BoxFuture<'_, Result<Box<dyn EventSubscription>, radroots_transport::Error>> {
            Box::pin(ready(Err(radroots_transport::Error::UnsupportedOperation)))
        }
    }

    impl EventSink for NoIoTransport {
        fn status(&self) -> BoxFuture<'_, Result<SinkStatus, radroots_transport::Error>> {
            Box::pin(ready(Err(radroots_transport::Error::UnsupportedOperation)))
        }

        fn deliver(
            &self,
            request: DeliveryRequest,
        ) -> BoxFuture<'_, Result<DeliveryReceipt, SinkFailure>> {
            Box::pin(ready(Err(SinkFailure::invalid_contract(&request))))
        }
    }

    #[test]
    fn runtime_adapter_contract_is_exact_and_defers_process_authority() {
        let contract: serde_json::Value =
            serde_json::from_str(RUNTIME_ADAPTER_CONTRACT).expect("runtime adapter contract");
        assert_eq!(
            contract,
            serde_json::json!({
                "schema": "radroots.rhi.runtime-adapters",
                "schema_version": 1,
                "contract_version": RHI_RUNTIME_ADAPTER_CONTRACT_VERSION,
                "time_entropy": {
                    "wall_time": "injected_whole_second_utc",
                    "monotonic_time": "injected_process_local_domain",
                    "entropy": "injected_complete_fill_or_error",
                    "event_authored_time": "untrusted_input"
                },
                "jitter": {
                    "algorithm": "rejection_sampled_multiply_high_full_jitter",
                    "unit": "milliseconds",
                    "inclusive_minimum": 0,
                    "inclusive_maximum": RHI_RUNTIME_JITTER_MAX_MILLISECONDS,
                    "maximum_entropy_draws": RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS,
                    "wall_clock_derived": false
                },
                "transport": {
                    "contract": "radroots_transport",
                    "evidence_fetch": "EventSource",
                    "evidence_subscription": "EventSubscriber",
                    "publication": "EventSink",
                    "construction_performs_io": false,
                    "concrete_handles_exposed": false
                },
                "identity": {
                    "order": ["credential", "encrypted_identity"],
                    "credential": "read_existing_canonical_instance_artifact",
                    "encrypted_identity": "read_existing_and_independently_verify",
                    "fallback": false,
                    "generation": false
                },
                "tasks": {
                    "supervisor": "radroots_service_host::TaskSupervisor",
                    "join_owned": true,
                    "handles_exposed": false
                },
                "library_exclusions": [
                    "signal_installation",
                    "runtime_creation",
                    "logging_installation",
                    "process_exit",
                    "detached_tasks"
                ]
            })
        );
    }

    #[test]
    fn injected_time_deadline_and_full_jitter_are_exactly_bounded() {
        let now = MonotonicTime::from_duration_since_origin(Duration::from_millis(40));
        let minimum = RhiTimeEntropyAdapters::new(
            FixedWall(Ok(UnixTimeSeconds::new(1_000))),
            FixedMonotonic(now),
            FixedEntropy(Ok(1)),
        );
        assert_eq!(minimum.now_utc().expect("wall").get(), 1_000);
        assert_eq!(minimum.now_monotonic(), now);
        assert_eq!(
            minimum
                .deadline_after(Duration::from_millis(2))
                .expect("deadline")
                .time()
                .duration_since_origin(),
            Duration::from_millis(42)
        );
        let maximum = RhiJitterBoundMilliseconds::new(RHI_RUNTIME_JITTER_MAX_MILLISECONDS)
            .expect("maximum bound");
        assert_eq!(
            minimum.sample_full_jitter(maximum).expect("minimum").get(),
            0
        );

        let upper = RhiTimeEntropyAdapters::new(
            FixedWall(Ok(UnixTimeSeconds::new(1))),
            FixedMonotonic(now),
            FixedEntropy(Ok(u64::MAX)),
        );
        assert_eq!(
            upper.sample_full_jitter(maximum).expect("maximum").get(),
            maximum.get()
        );
        assert_eq!(
            upper
                .sample_full_jitter(RhiJitterBoundMilliseconds::new(0).expect("zero"))
                .expect("zero sample")
                .duration(),
            Duration::ZERO
        );
        assert_eq!(
            RhiJitterBoundMilliseconds::new(RHI_RUNTIME_JITTER_MAX_MILLISECONDS + 1)
                .expect_err("above maximum")
                .kind(),
            RhiRuntimeAdapterErrorKind::InvalidJitterBound
        );

        let rejected = RhiTimeEntropyAdapters::new(
            FixedWall(Ok(UnixTimeSeconds::new(1))),
            FixedMonotonic(now),
            FixedEntropy(Ok(0)),
        );
        assert_eq!(
            rejected
                .sample_full_jitter(RhiJitterBoundMilliseconds::new(2).expect("bound"))
                .expect_err("bounded rejection")
                .kind(),
            RhiRuntimeAdapterErrorKind::EntropyUnavailable
        );
    }

    #[test]
    fn injected_failures_and_deadline_overflow_are_stable_and_source_free() {
        let maximum_time = MonotonicTime::from_duration_since_origin(Duration::MAX);
        let adapters = RhiTimeEntropyAdapters::new(
            FixedWall(Err(WallClockError::BeforeUnixEpoch)),
            FixedMonotonic(maximum_time),
            FixedEntropy(Err(EntropyError::Unavailable)),
        );
        let cases = [
            (
                adapters.now_utc().expect_err("wall").kind(),
                RhiRuntimeAdapterErrorKind::WallClockUnavailable,
            ),
            (
                adapters
                    .deadline_after(Duration::from_millis(1))
                    .expect_err("deadline")
                    .kind(),
                RhiRuntimeAdapterErrorKind::MonotonicDeadlineInvalid,
            ),
            (
                adapters
                    .sample_full_jitter(RhiJitterBoundMilliseconds::new(1).expect("bound"))
                    .expect_err("entropy")
                    .kind(),
                RhiRuntimeAdapterErrorKind::EntropyUnavailable,
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
            let error = RhiRuntimeAdapterError::new(actual);
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
        assert_eq!(
            maximum_time.checked_deadline_after(Duration::from_millis(1)),
            Err(MonotonicClockError::DeadlineOverflow)
        );
    }

    #[tokio::test]
    async fn adapter_set_is_inert_until_invoked_and_owns_joined_tasks() {
        let transport = Arc::new(NoIoTransport);
        let transports = RhiTransportAdapters::new(transport.clone(), transport.clone(), transport);
        let mut adapters = RhiRuntimeAdapters::new(
            RhiTimeEntropyAdapters::new(
                FixedWall(Ok(UnixTimeSeconds::new(1))),
                FixedMonotonic(MonotonicTime::from_duration_since_origin(Duration::ZERO)),
                FixedEntropy(Ok(1)),
            ),
            transports,
            RhiIdentityCredentialAdapters::canonical(),
        );
        assert_eq!(adapters.supervised_task_count(), 0);
        let calls = Arc::new(AtomicUsize::new(0));
        let task_calls = Arc::clone(&calls);
        adapters
            .supervisor_mut()
            .spawn(
                TaskMetadata::new(
                    TaskName::new("adapter_contract_test").expect("task name"),
                    TaskClassification::OneShot,
                    None,
                )
                .expect("metadata"),
                move |_cancel| async move {
                    task_calls.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), HostError>(())
                },
            )
            .expect("register");
        assert_eq!(adapters.supervised_task_count(), 1);
        assert_eq!(
            adapters
                .supervisor_mut()
                .supervise()
                .await
                .expect("joined")
                .len(),
            1
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(adapters.supervised_task_count(), 0);
        assert_eq!(
            format!("{adapters:?}"),
            "RhiRuntimeAdapters { time_entropy: \"[injected]\", transport: \"[sealed]\", identity_credential: \"[sealed]\", supervised_task_count: 0 }"
        );
    }

    #[tokio::test]
    async fn adapter_shutdown_cancels_and_joins_long_lived_tasks() {
        let transport = Arc::new(NoIoTransport);
        let transports = RhiTransportAdapters::new(transport.clone(), transport.clone(), transport);
        let mut adapters = RhiRuntimeAdapters::new(
            RhiTimeEntropyAdapters::new(
                FixedWall(Ok(UnixTimeSeconds::new(1))),
                FixedMonotonic(MonotonicTime::from_duration_since_origin(Duration::ZERO)),
                FixedEntropy(Ok(1)),
            ),
            transports,
            RhiIdentityCredentialAdapters::canonical(),
        );
        let cancellations = Arc::new(AtomicUsize::new(0));
        let task_cancellations = Arc::clone(&cancellations);
        adapters
            .supervisor_mut()
            .spawn(
                TaskMetadata::new(
                    TaskName::new("adapter_cancellation_test").expect("task name"),
                    TaskClassification::Critical,
                    Some(ShutdownPhase::CloseNetwork),
                )
                .expect("metadata"),
                move |cancel| async move {
                    cancel.cancelled().await;
                    task_cancellations.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), HostError>(())
                },
            )
            .expect("register");
        adapters.shutdown().await.expect("joined shutdown");
        assert_eq!(cancellations.load(Ordering::Relaxed), 1);
        assert_eq!(adapters.supervised_task_count(), 0);
    }

    #[test]
    fn all_error_codes_messages_and_debug_are_stable() {
        let cases = [
            (
                RhiRuntimeAdapterErrorKind::InvalidJitterBound,
                "runtime_jitter_bound_invalid",
                "RHI jitter bound is invalid",
            ),
            (
                RhiRuntimeAdapterErrorKind::EntropyUnavailable,
                "runtime_entropy_unavailable",
                "RHI entropy source is unavailable",
            ),
            (
                RhiRuntimeAdapterErrorKind::WallClockUnavailable,
                "runtime_wall_clock_unavailable",
                "RHI wall clock is unavailable",
            ),
            (
                RhiRuntimeAdapterErrorKind::MonotonicDeadlineInvalid,
                "runtime_monotonic_deadline_invalid",
                "RHI monotonic deadline is invalid",
            ),
            (
                RhiRuntimeAdapterErrorKind::CredentialAccess,
                "runtime_credential_access_failed",
                "RHI credential access failed",
            ),
            (
                RhiRuntimeAdapterErrorKind::IdentityAccess,
                "runtime_identity_access_failed",
                "RHI identity access failed",
            ),
        ];
        for (kind, code, message) in cases {
            let error = RhiRuntimeAdapterError::new(kind);
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), message);
            assert_eq!(
                format!("{error:?}"),
                format!("RhiRuntimeAdapterError {{ kind: {kind:?} }}")
            );
            assert!(Error::source(&error).is_none());
        }
    }
}
