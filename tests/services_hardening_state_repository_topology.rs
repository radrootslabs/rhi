#![forbid(unsafe_code)]

use rhi::{
    RHI_STATE_REPOSITORY_CONTRACT_VERSION, RHI_STATE_REPOSITORY_COUNT, RhiStateRepositoryKind,
    RhiStateRepositoryWriteClass, rhi_state_repository_descriptors,
};
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/state_repository_topology.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const REPOSITORY_SOURCE: &str = include_str!("../src/state_repository.rs");

#[test]
fn machine_contract_and_typed_descriptor_inventory_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("repository contract");
    assert_eq!(contract["schema"], "radroots.rhi.state-repository-topology");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_STATE_REPOSITORY_CONTRACT_VERSION
    );
    assert_eq!(contract["repository_count"], RHI_STATE_REPOSITORY_COUNT);
    assert_eq!(contract["construction"], "sealed_to_open_rhi_state_host");
    assert_eq!(contract["raw_sqlite_authority_exposed"], false);
    assert_eq!(
        contract["deferred_behavior"],
        json!([
            "later_schema_migrations",
            "non_job_repository_crud",
            "backup_restore_and_recovery",
            "network_io",
            "task_supervision"
        ])
    );
    assert_eq!(
        contract
            .as_object()
            .expect("contract object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "schema",
            "schema_version",
            "contract_version",
            "repository_count",
            "construction",
            "raw_sqlite_authority_exposed",
            "repositories",
            "deferred_behavior",
        ]
        .into_iter()
        .collect()
    );

    let descriptors = rhi_state_repository_descriptors();
    let actual = descriptors
        .iter()
        .map(|descriptor| {
            json!({
                "kind": descriptor.code(),
                "backing_table": descriptor.backing_table(),
                "write_class": descriptor.write_class().code(),
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        contract["repositories"]
            .as_array()
            .expect("repository array"),
        &actual
    );
    assert_eq!(descriptors.len(), RHI_STATE_REPOSITORY_COUNT);
    for repository in contract["repositories"]
        .as_array()
        .expect("repository array")
    {
        assert_eq!(
            repository
                .as_object()
                .expect("repository object")
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["kind", "backing_table", "write_class"]
                .into_iter()
                .collect()
        );
    }
}

#[test]
fn repository_kinds_are_closed_ordered_and_cross_bound() {
    use RhiStateRepositoryKind as Kind;
    use RhiStateRepositoryWriteClass as Write;

    let expected = [
        (
            Kind::Source,
            "source",
            "evidence_reconciliation_sources",
            Write::AppendOnly,
        ),
        (
            Kind::SourceCursor,
            "source_cursor",
            "relay_checkpoints",
            Write::CompareAndSwap,
        ),
        (
            Kind::SourceCompletion,
            "source_completion",
            "evidence_reconciliation_sources",
            Write::AppendOnly,
        ),
        (
            Kind::SignedEvent,
            "signed_event",
            "nostr_events",
            Write::AppendOnly,
        ),
        (
            Kind::Mutation,
            "mutation",
            "trade_mutations",
            Write::AppendOnly,
        ),
        (
            Kind::Provenance,
            "provenance",
            "relay_observations",
            Write::AppendOnly,
        ),
        (
            Kind::DirtyTrade,
            "dirty_trade",
            "trade_dirty_generations",
            Write::CompareAndSwap,
        ),
        (
            Kind::ReconciliationJob,
            "reconciliation_job",
            "reconciliation_jobs",
            Write::CompareAndSwap,
        ),
        (
            Kind::ReconciliationAttempt,
            "reconciliation_attempt",
            "evidence_reconciliations",
            Write::AppendOnly,
        ),
        (
            Kind::EvidenceManifest,
            "evidence_manifest",
            "evidence_manifests",
            Write::Immutable,
        ),
        (
            Kind::Projection,
            "projection",
            "trade_projections",
            Write::Immutable,
        ),
        (
            Kind::Report,
            "report",
            "attestation_reports",
            Write::Immutable,
        ),
        (
            Kind::Supersession,
            "supersession",
            "attestation_reports",
            Write::AppendOnly,
        ),
        (
            Kind::SignedAttestationEvent,
            "signed_attestation_event",
            "signed_attestation_events",
            Write::Immutable,
        ),
        (
            Kind::PublicationOutbox,
            "publication_outbox",
            "publication_outbox",
            Write::CompareAndSwap,
        ),
        (
            Kind::PublicationTarget,
            "publication_target",
            "publication_targets",
            Write::CompareAndSwap,
        ),
        (
            Kind::PublicationAttempt,
            "publication_attempt",
            "publication_attempts",
            Write::AppendOnly,
        ),
        (
            Kind::DesiredPresence,
            "desired_presence",
            "presence_desired_state",
            Write::CompareAndSwap,
        ),
    ];
    for (descriptor, (kind, code, table, write_class)) in
        rhi_state_repository_descriptors().iter().zip(expected)
    {
        assert_eq!(descriptor.kind(), kind);
        assert_eq!(descriptor.code(), code);
        assert_eq!(descriptor.backing_table(), table);
        assert_eq!(descriptor.write_class(), write_class);
    }
}

#[test]
fn capabilities_are_private_sealed_and_defer_unowned_behavior() {
    assert!(LIB_SOURCE.contains("mod state_repository;"));
    assert!(!LIB_SOURCE.contains("pub mod state_repository;"));
    assert!(HOST_SOURCE.contains("pub const fn repositories(&self) -> RhiStateRepositories<'_>"));
    for required in [
        "pub const fn sources(&self) -> RhiSourceRepository<'host>",
        "pub const fn source_cursors(&self) -> RhiSourceCursorRepository<'host>",
        "pub const fn source_completions(&self) -> RhiSourceCompletionRepository<'host>",
        "pub const fn signed_events(&self) -> RhiSignedEventRepository<'host>",
        "pub const fn mutations(&self) -> RhiMutationRepository<'host>",
        "pub const fn provenance(&self) -> RhiProvenanceRepository<'host>",
        "pub const fn dirty_trades(&self) -> RhiDirtyTradeRepository<'host>",
        "pub const fn reconciliation_jobs(&self) -> RhiReconciliationJobRepository<'host>",
        "pub const fn reconciliation_attempts(&self) -> RhiReconciliationAttemptRepository<'host>",
        "pub const fn evidence_manifests(&self) -> RhiEvidenceManifestRepository<'host>",
        "pub const fn projections(&self) -> RhiProjectionRepository<'host>",
        "pub const fn reports(&self) -> RhiReportRepository<'host>",
        "pub const fn supersessions(&self) -> RhiSupersessionRepository<'host>",
        "pub const fn signed_attestation_events(&self) -> RhiSignedAttestationEventRepository<'host>",
        "pub const fn publication_outbox(&self) -> RhiPublicationOutboxRepository<'host>",
        "pub const fn publication_targets(&self) -> RhiPublicationTargetRepository<'host>",
        "pub const fn publication_attempts(&self) -> RhiPublicationAttemptRepository<'host>",
        "pub const fn desired_presence(&self) -> RhiDesiredPresenceRepository<'host>",
    ] {
        assert!(REPOSITORY_SOURCE.contains(required), "missing {required}");
    }
    for forbidden in [
        "SqlitePool",
        "SqliteConnection",
        "ServiceSqliteTransaction",
        "sqlx::",
        "rusqlite::",
        "CREATE TABLE",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "std::fs",
        "std::path",
        "std::env",
        "tokio::",
        "nostr::",
        "Deref",
        "AsRef",
    ] {
        assert!(
            !REPOSITORY_SOURCE.contains(forbidden),
            "premature or escaping repository authority {forbidden}"
        );
    }
}
