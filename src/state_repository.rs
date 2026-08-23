//! Sealed typed capability topology for RHI-owned state repositories.

use core::fmt;

use crate::RhiStateHost;

/// Exact version of the RHI state-repository topology contract.
pub const RHI_STATE_REPOSITORY_CONTRACT_VERSION: u32 = 1;

/// Number of distinct typed repository capabilities in the v1 topology.
pub const RHI_STATE_REPOSITORY_COUNT: usize = 18;

/// Closed mutation class for one governed repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiStateRepositoryWriteClass {
    AppendOnly,
    CompareAndSwap,
    Immutable,
}

impl RhiStateRepositoryWriteClass {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AppendOnly => "append_only",
            Self::CompareAndSwap => "compare_and_swap",
            Self::Immutable => "immutable",
        }
    }
}

/// Closed inventory of RHI repository responsibilities.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiStateRepositoryKind {
    Source,
    SourceCursor,
    SourceCompletion,
    SignedEvent,
    Mutation,
    Provenance,
    DirtyTrade,
    ReconciliationJob,
    ReconciliationAttempt,
    EvidenceManifest,
    Projection,
    Report,
    Supersession,
    SignedAttestationEvent,
    PublicationOutbox,
    PublicationTarget,
    PublicationAttempt,
    DesiredPresence,
}

impl RhiStateRepositoryKind {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        descriptor(self).code
    }

    /// Returns the sole governed backing-table identity.
    #[must_use]
    pub const fn backing_table(self) -> &'static str {
        descriptor(self).backing_table
    }

    /// Returns the closed mutation class.
    #[must_use]
    pub const fn write_class(self) -> RhiStateRepositoryWriteClass {
        descriptor(self).write_class
    }
}

/// Immutable description of one repository capability.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiStateRepositoryDescriptor {
    kind: RhiStateRepositoryKind,
    code: &'static str,
    backing_table: &'static str,
    write_class: RhiStateRepositoryWriteClass,
}

impl RhiStateRepositoryDescriptor {
    const fn new(
        kind: RhiStateRepositoryKind,
        code: &'static str,
        backing_table: &'static str,
        write_class: RhiStateRepositoryWriteClass,
    ) -> Self {
        Self {
            kind,
            code,
            backing_table,
            write_class,
        }
    }

    /// Returns the closed repository kind.
    #[must_use]
    pub const fn kind(self) -> RhiStateRepositoryKind {
        self.kind
    }

    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns the exact governed backing-table identity.
    #[must_use]
    pub const fn backing_table(self) -> &'static str {
        self.backing_table
    }

    /// Returns the repository mutation class.
    #[must_use]
    pub const fn write_class(self) -> RhiStateRepositoryWriteClass {
        self.write_class
    }
}

impl fmt::Debug for RhiStateRepositoryDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateRepositoryDescriptor")
            .field("kind", &self.kind)
            .field("write_class", &self.write_class)
            .finish()
    }
}

use RhiStateRepositoryKind as Kind;
use RhiStateRepositoryWriteClass as Write;

const DESCRIPTORS: [RhiStateRepositoryDescriptor; RHI_STATE_REPOSITORY_COUNT] = [
    RhiStateRepositoryDescriptor::new(
        Kind::Source,
        "source",
        "evidence_reconciliation_sources",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::SourceCursor,
        "source_cursor",
        "relay_checkpoints",
        Write::CompareAndSwap,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::SourceCompletion,
        "source_completion",
        "evidence_reconciliation_sources",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::SignedEvent,
        "signed_event",
        "nostr_events",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::Mutation,
        "mutation",
        "trade_mutations",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::Provenance,
        "provenance",
        "relay_observations",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::DirtyTrade,
        "dirty_trade",
        "trade_dirty_generations",
        Write::CompareAndSwap,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::ReconciliationJob,
        "reconciliation_job",
        "reconciliation_jobs",
        Write::CompareAndSwap,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::ReconciliationAttempt,
        "reconciliation_attempt",
        "evidence_reconciliations",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::EvidenceManifest,
        "evidence_manifest",
        "evidence_manifests",
        Write::Immutable,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::Projection,
        "projection",
        "trade_projections",
        Write::Immutable,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::Report,
        "report",
        "attestation_reports",
        Write::Immutable,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::Supersession,
        "supersession",
        "attestation_reports",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::SignedAttestationEvent,
        "signed_attestation_event",
        "signed_attestation_events",
        Write::Immutable,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::PublicationOutbox,
        "publication_outbox",
        "publication_outbox",
        Write::CompareAndSwap,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::PublicationTarget,
        "publication_target",
        "publication_targets",
        Write::CompareAndSwap,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::PublicationAttempt,
        "publication_attempt",
        "publication_attempts",
        Write::AppendOnly,
    ),
    RhiStateRepositoryDescriptor::new(
        Kind::DesiredPresence,
        "desired_presence",
        "presence_desired_state",
        Write::CompareAndSwap,
    ),
];

const fn descriptor(kind: RhiStateRepositoryKind) -> RhiStateRepositoryDescriptor {
    DESCRIPTORS[kind as usize]
}

/// Returns the exact ordered v1 repository topology.
#[must_use]
pub const fn rhi_state_repository_descriptors()
-> &'static [RhiStateRepositoryDescriptor; RHI_STATE_REPOSITORY_COUNT] {
    &DESCRIPTORS
}

/// Sealed repository family bound to one already-opened RHI state host.
///
/// Construction is available only through [`RhiStateHost::repositories`]:
///
/// ```compile_fail
/// use rhi::RhiStateRepositories;
///
/// let _ = RhiStateRepositories { host: todo!() };
/// ```
///
/// Distinct repository responsibilities cannot be interchanged:
///
/// ```compile_fail
/// use rhi::{RhiMutationRepository, RhiStateRepositories};
///
/// fn wrong(repository: &RhiStateRepositories<'_>) {
///     let _: RhiMutationRepository<'_> = repository.sources();
/// }
/// ```
pub struct RhiStateRepositories<'host> {
    host: &'host RhiStateHost,
}

impl<'host> RhiStateRepositories<'host> {
    pub(crate) const fn new(host: &'host RhiStateHost) -> Self {
        Self { host }
    }

    /// Returns typed source-result access.
    #[must_use]
    pub const fn sources(&self) -> RhiSourceRepository<'host> {
        RhiSourceRepository { host: self.host }
    }

    /// Returns typed source-cursor access.
    #[must_use]
    pub const fn source_cursors(&self) -> RhiSourceCursorRepository<'host> {
        RhiSourceCursorRepository { host: self.host }
    }

    /// Returns typed source-completion access.
    #[must_use]
    pub const fn source_completions(&self) -> RhiSourceCompletionRepository<'host> {
        RhiSourceCompletionRepository { host: self.host }
    }

    /// Returns typed admitted-event access.
    #[must_use]
    pub const fn signed_events(&self) -> RhiSignedEventRepository<'host> {
        RhiSignedEventRepository { host: self.host }
    }

    /// Returns typed canonical-mutation access.
    #[must_use]
    pub const fn mutations(&self) -> RhiMutationRepository<'host> {
        RhiMutationRepository { host: self.host }
    }

    /// Returns typed provenance-observation access.
    #[must_use]
    pub const fn provenance(&self) -> RhiProvenanceRepository<'host> {
        RhiProvenanceRepository { host: self.host }
    }

    /// Returns typed dirty-trade generation access.
    #[must_use]
    pub const fn dirty_trades(&self) -> RhiDirtyTradeRepository<'host> {
        RhiDirtyTradeRepository { host: self.host }
    }

    /// Returns typed reconciliation-job access.
    #[must_use]
    pub const fn reconciliation_jobs(&self) -> RhiReconciliationJobRepository<'host> {
        RhiReconciliationJobRepository { host: self.host }
    }

    /// Returns typed reconciliation-attempt access.
    #[must_use]
    pub const fn reconciliation_attempts(&self) -> RhiReconciliationAttemptRepository<'host> {
        RhiReconciliationAttemptRepository { host: self.host }
    }

    /// Returns typed immutable evidence-manifest access.
    #[must_use]
    pub const fn evidence_manifests(&self) -> RhiEvidenceManifestRepository<'host> {
        RhiEvidenceManifestRepository { host: self.host }
    }

    /// Returns typed immutable projection access.
    #[must_use]
    pub const fn projections(&self) -> RhiProjectionRepository<'host> {
        RhiProjectionRepository { host: self.host }
    }

    /// Returns typed immutable report access.
    #[must_use]
    pub const fn reports(&self) -> RhiReportRepository<'host> {
        RhiReportRepository { host: self.host }
    }

    /// Returns typed append-only supersession access.
    #[must_use]
    pub const fn supersessions(&self) -> RhiSupersessionRepository<'host> {
        RhiSupersessionRepository { host: self.host }
    }

    /// Returns typed immutable signed-attestation-event access.
    #[must_use]
    pub const fn signed_attestation_events(&self) -> RhiSignedAttestationEventRepository<'host> {
        RhiSignedAttestationEventRepository { host: self.host }
    }

    /// Returns typed publication-outbox access.
    #[must_use]
    pub const fn publication_outbox(&self) -> RhiPublicationOutboxRepository<'host> {
        RhiPublicationOutboxRepository { host: self.host }
    }

    /// Returns typed immutable-target workflow access.
    #[must_use]
    pub const fn publication_targets(&self) -> RhiPublicationTargetRepository<'host> {
        RhiPublicationTargetRepository { host: self.host }
    }

    /// Returns typed append-only publication-attempt access.
    #[must_use]
    pub const fn publication_attempts(&self) -> RhiPublicationAttemptRepository<'host> {
        RhiPublicationAttemptRepository { host: self.host }
    }

    /// Returns typed desired-presence access.
    #[must_use]
    pub const fn desired_presence(&self) -> RhiDesiredPresenceRepository<'host> {
        RhiDesiredPresenceRepository { host: self.host }
    }
}

impl fmt::Debug for RhiStateRepositories<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateRepositories")
            .field("mode", &self.host.mode())
            .field("state", &"[sealed]")
            .finish()
    }
}

macro_rules! repository_handle {
    ($name:ident, $kind:ident) => {
        #[doc = "One non-forgeable typed view of an opened RHI state host."]
        pub struct $name<'host> {
            host: &'host RhiStateHost,
        }

        impl $name<'_> {
            /// Returns this repository's closed kind.
            #[must_use]
            pub const fn kind(&self) -> RhiStateRepositoryKind {
                Kind::$kind
            }

            /// Returns this repository's immutable descriptor.
            #[must_use]
            pub const fn descriptor(&self) -> RhiStateRepositoryDescriptor {
                descriptor(self.kind())
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("mode", &self.host.mode())
                    .field("state", &"[sealed]")
                    .finish()
            }
        }
    };
}

repository_handle!(RhiSourceRepository, Source);
repository_handle!(RhiSourceCursorRepository, SourceCursor);
repository_handle!(RhiSourceCompletionRepository, SourceCompletion);
repository_handle!(RhiSignedEventRepository, SignedEvent);
repository_handle!(RhiMutationRepository, Mutation);
repository_handle!(RhiProvenanceRepository, Provenance);
repository_handle!(RhiDirtyTradeRepository, DirtyTrade);
repository_handle!(RhiReconciliationJobRepository, ReconciliationJob);
repository_handle!(RhiReconciliationAttemptRepository, ReconciliationAttempt);
repository_handle!(RhiEvidenceManifestRepository, EvidenceManifest);
repository_handle!(RhiProjectionRepository, Projection);
repository_handle!(RhiReportRepository, Report);
repository_handle!(RhiSupersessionRepository, Supersession);
repository_handle!(RhiSignedAttestationEventRepository, SignedAttestationEvent);
repository_handle!(RhiPublicationOutboxRepository, PublicationOutbox);
repository_handle!(RhiPublicationTargetRepository, PublicationTarget);
repository_handle!(RhiPublicationAttemptRepository, PublicationAttempt);
repository_handle!(RhiDesiredPresenceRepository, DesiredPresence);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_are_closed_unique_and_nonempty() {
        assert_eq!(DESCRIPTORS.len(), RHI_STATE_REPOSITORY_COUNT);
        for (index, descriptor) in DESCRIPTORS.iter().enumerate() {
            assert_eq!(descriptor.kind() as usize, index);
            assert!(!descriptor.code().is_empty());
            assert!(!descriptor.backing_table().is_empty());
            assert_eq!(descriptor.kind().code(), descriptor.code());
            assert_eq!(
                descriptor.kind().backing_table(),
                descriptor.backing_table()
            );
            assert_eq!(descriptor.kind().write_class(), descriptor.write_class());
            assert_eq!(
                descriptor.write_class().code(),
                match descriptor.write_class() {
                    Write::AppendOnly => "append_only",
                    Write::CompareAndSwap => "compare_and_swap",
                    Write::Immutable => "immutable",
                }
            );
            for other in &DESCRIPTORS[index + 1..] {
                assert_ne!(descriptor.kind(), other.kind());
                assert_ne!(descriptor.code(), other.code());
            }
        }
    }
}
