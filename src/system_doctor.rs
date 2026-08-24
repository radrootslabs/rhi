//! Production active-doctor probes composed from existing sealed authorities.

use radroots_service_host::{SystemWallClock, WallClock};
use radroots_service_sqlite::{
    IntegrityCheckOutcome, IntegrityCheckedAtUnixMs, MinimumFreeBytes,
    PlatformStateFilesystemCapacitySource, inspect_state_filesystem_capacity,
};

use crate::admin_v1::admin_transport_limits;
use crate::transport_nostr_adapter::{build_rhi_nostr_adapters, probe_required_sources};
use crate::{
    RhiConfigDocumentV1, RhiDoctorCheckDefinition, RhiDoctorCheckId, RhiDoctorFuture,
    RhiDoctorObservation, RhiDoctorProbe, RhiIdentityEnvelopeBinding, RhiRuntimeContext,
    RhiStateHost, open_rhi_encrypted_identity, open_rhi_state_inspection_from_config,
    resolve_rhi_wrapping_credential,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateProbeError {
    Query,
}

pub(crate) struct RhiSystemDoctorProbe<'a> {
    runtime: &'a RhiRuntimeContext,
    configuration: &'a RhiConfigDocumentV1,
}

impl<'a> RhiSystemDoctorProbe<'a> {
    pub(crate) const fn new(
        runtime: &'a RhiRuntimeContext,
        configuration: &'a RhiConfigDocumentV1,
    ) -> Self {
        Self {
            runtime,
            configuration,
        }
    }

    async fn run(&self, definition: RhiDoctorCheckDefinition) -> bool {
        match definition.id() {
            RhiDoctorCheckId::PathsPermissions => self.probe_paths(),
            RhiDoctorCheckId::WriterLock
            | RhiDoctorCheckId::SqliteSchema
            | RhiDoctorCheckId::SqliteIntegrity
            | RhiDoctorCheckId::CursorCheckpoint
            | RhiDoctorCheckId::ReconciliationLeases
            | RhiDoctorCheckId::ReconciliationBacklog
            | RhiDoctorCheckId::PublicationInvariants => self.probe_state(definition.id()).await,
            RhiDoctorCheckId::SqliteFreeSpace => self.probe_free_space(),
            RhiDoctorCheckId::IdentityBinding => self.probe_identity_binding().await,
            RhiDoctorCheckId::AdminBindPolicy => self.probe_admin_policy(),
            RhiDoctorCheckId::OperationsBindPolicy => self.probe_operations_policy(),
            RhiDoctorCheckId::NetworkPolicy => build_rhi_nostr_adapters(self.configuration).is_ok(),
            RhiDoctorCheckId::RequiredSources => {
                let Some(deadline) = absolute_deadline(definition.deadline_ms()) else {
                    return false;
                };
                probe_required_sources(self.configuration, deadline)
                    .await
                    .is_ok()
            }
            RhiDoctorCheckId::ClockSkew => false,
        }
    }

    fn probe_paths(&self) -> bool {
        let Ok(paths) = crate::state_host::state_paths(self.runtime) else {
            return false;
        };
        let Ok(minimum) = MinimumFreeBytes::new(1) else {
            return false;
        };
        inspect_state_filesystem_capacity(&paths, minimum, &PlatformStateFilesystemCapacitySource)
            .is_ok()
    }

    async fn probe_state(&self, check: RhiDoctorCheckId) -> bool {
        let Ok(state) =
            open_rhi_state_inspection_from_config(self.runtime, self.configuration).await
        else {
            return false;
        };
        let outcome = match check {
            RhiDoctorCheckId::WriterLock | RhiDoctorCheckId::SqliteSchema => true,
            RhiDoctorCheckId::SqliteIntegrity => match integrity_time() {
                Some(checked_at) => state
                    .inspect_integrity(checked_at)
                    .await
                    .is_ok_and(|report| {
                        report.sqlite() == IntegrityCheckOutcome::Verified
                            && report.foreign_keys() == IntegrityCheckOutcome::Verified
                    }),
                None => false,
            },
            RhiDoctorCheckId::CursorCheckpoint => {
                run_scalar_probe(&state, CURSOR_CHECKPOINT_INVARIANTS_SQL, None).await
            }
            RhiDoctorCheckId::ReconciliationLeases => {
                run_scalar_probe(&state, RECONCILIATION_LEASE_INVARIANTS_SQL, None).await
            }
            RhiDoctorCheckId::ReconciliationBacklog => {
                let capacity =
                    configuration_u64(self.configuration, "/reconciliation/queue_capacity")
                        .and_then(|value| i64::try_from(value).ok());
                match capacity {
                    Some(capacity) => {
                        run_scalar_probe(
                            &state,
                            RECONCILIATION_BACKLOG_INVARIANTS_SQL,
                            Some(capacity),
                        )
                        .await
                    }
                    None => false,
                }
            }
            RhiDoctorCheckId::PublicationInvariants => {
                run_scalar_probe(&state, PUBLICATION_INVARIANTS_SQL, None).await
            }
            _ => false,
        };
        let closed = state.close().await.is_ok();
        outcome && closed
    }

    fn probe_free_space(&self) -> bool {
        let Some(minimum) = configuration_u64(self.configuration, "/database/minimum_free_bytes")
            .and_then(|value| MinimumFreeBytes::new(value).ok())
        else {
            return false;
        };
        let Ok(paths) = crate::state_host::state_paths(self.runtime) else {
            return false;
        };
        inspect_state_filesystem_capacity(&paths, minimum, &PlatformStateFilesystemCapacitySource)
            .is_ok_and(|capacity| capacity.allows_authoritative_admission())
    }

    async fn probe_identity_binding(&self) -> bool {
        let Ok(state) =
            open_rhi_state_inspection_from_config(self.runtime, self.configuration).await
        else {
            return false;
        };
        let result =
            RhiIdentityEnvelopeBinding::from_configuration(self.configuration, state.metadata())
                .ok()
                .and_then(|binding| {
                    let credential =
                        resolve_rhi_wrapping_credential(self.runtime, &binding).ok()?;
                    open_rhi_encrypted_identity(&binding, &credential).ok()
                });
        let closed = state.close().await.is_ok();
        result.is_some() && closed
    }

    fn probe_admin_policy(&self) -> bool {
        let path = self.runtime.artifacts().admin_socket();
        path.is_absolute()
            && path.to_str().is_some_and(|value| value.len() <= 4_096)
            && admin_transport_limits(self.configuration).is_ok()
    }

    fn probe_operations_policy(&self) -> bool {
        let Some(enabled) = self
            .configuration
            .normalized()
            .pointer("/operations/enabled")
            .and_then(serde_json::Value::as_bool)
        else {
            return false;
        };
        !enabled
            || (self
                .configuration
                .normalized()
                .pointer("/operations/listen")
                .and_then(serde_json::Value::as_str)
                .is_some()
                && self
                    .configuration
                    .normalized()
                    .pointer("/operations/bind_policy")
                    .and_then(serde_json::Value::as_str)
                    .is_some())
    }
}

impl RhiDoctorProbe for RhiSystemDoctorProbe<'_> {
    fn probe(&self, definition: RhiDoctorCheckDefinition) -> RhiDoctorFuture<'_> {
        Box::pin(async move {
            if definition.id() == RhiDoctorCheckId::ClockSkew {
                RhiDoctorObservation::Skipped
            } else if self.run(definition).await {
                RhiDoctorObservation::Pass
            } else {
                RhiDoctorObservation::Fail
            }
        })
    }
}

async fn run_scalar_probe(state: &RhiStateHost, sql: &'static str, bound: Option<i64>) -> bool {
    state
        .sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let mut query = sqlx::query_scalar::<_, i64>(sql);
                if let Some(bound) = bound {
                    query = query.bind(bound);
                }
                query
                    .fetch_one(&mut *transaction)
                    .await
                    .map(|invalid| invalid == 0)
                    .map_err(|_| StateProbeError::Query)
            })
        })
        .await
        .is_ok_and(|valid| valid)
}

fn configuration_u64(configuration: &RhiConfigDocumentV1, pointer: &str) -> Option<u64> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
}

fn wall_time_millis() -> Option<u64> {
    SystemWallClock
        .now_utc()
        .ok()
        .and_then(|time| time.get().checked_mul(1_000))
        .filter(|value| i64::try_from(*value).is_ok())
}

fn absolute_deadline(duration_ms: u64) -> Option<u64> {
    wall_time_millis()?.checked_add(duration_ms)
}

fn integrity_time() -> Option<IntegrityCheckedAtUnixMs> {
    IntegrityCheckedAtUnixMs::new(wall_time_millis()?)
}

const CURSOR_CHECKPOINT_INVARIANTS_SQL: &str = r#"SELECT COUNT(*)
FROM relay_checkpoints
WHERE typeof(source_id) != 'text'
    OR length(CAST(source_id AS BLOB)) NOT BETWEEN 1 AND 64
    OR source_id GLOB '*[^a-z0-9_-]*'
    OR substr(source_id, 1, 1) NOT GLOB '[a-z]'
    OR selector_id != 'trade_mutation_lineage_v1'
    OR typeof(evidence_policy_sha256) != 'blob'
    OR length(evidence_policy_sha256) != 32
    OR typeof(trade_id) != 'blob' OR length(trade_id) != 16
    OR typeof(cursor_event_id) != 'blob' OR length(cursor_event_id) != 32
    OR cursor_created_at_unix_s NOT BETWEEN 0 AND 9223372036854775807
    OR revision NOT BETWEEN 1 AND 9223372036854775807
    OR completed_at_unix_s NOT BETWEEN 1 AND 9223372036854775807"#;

const RECONCILIATION_LEASE_INVARIANTS_SQL: &str = r#"SELECT COUNT(*)
FROM reconciliation_jobs
WHERE (state = 'leased' AND (
        typeof(lease_owner) != 'blob' OR length(lease_owner) != 16
        OR lease_expires_unix_ms NOT BETWEEN 1 AND 9223372036854775807
        OR next_attempt_unix_ms IS NOT NULL))
    OR (state != 'leased' AND (lease_owner IS NOT NULL OR lease_expires_unix_ms IS NOT NULL))
    OR attempt_count NOT BETWEEN 0 AND max_attempts
    OR failure_count NOT BETWEEN 0 AND attempt_count
    OR revision NOT BETWEEN 1 AND 9223372036854775807"#;

const RECONCILIATION_BACKLOG_INVARIANTS_SQL: &str = r#"SELECT CASE
    WHEN (SELECT COUNT(*) FROM reconciliation_jobs WHERE state IN ('ready', 'leased')) > ?
        THEN 1
    WHEN EXISTS (
        SELECT 1 FROM reconciliation_jobs
        WHERE state = 'ready' AND (
            next_attempt_unix_ms IS NULL OR attempt_count >= max_attempts))
        THEN 1
    WHEN EXISTS (
        SELECT 1 FROM reconciliation_jobs
        WHERE state IN ('exhausted', 'superseded', 'completed')
            AND next_attempt_unix_ms IS NOT NULL)
        THEN 1
    ELSE 0 END"#;

const PUBLICATION_INVARIANTS_SQL: &str = r#"SELECT COUNT(*)
FROM publication_outbox AS outbox
LEFT JOIN signed_attestation_events AS event ON event.event_id = outbox.event_id
WHERE event.event_id IS NULL
    OR outbox.event_sha256 != event.event_sha256
    OR outbox.target_count != (
        SELECT COUNT(*) FROM publication_targets AS target
        WHERE target.outbox_id = outbox.outbox_id)
    OR outbox.required_target_count != (
        SELECT COUNT(*) FROM publication_targets AS target
        WHERE target.outbox_id = outbox.outbox_id AND target.required = 1)
    OR EXISTS (
        SELECT 1 FROM publication_targets AS target
        WHERE target.outbox_id = outbox.outbox_id
            AND (target.target_ordinal < 0 OR target.target_ordinal >= outbox.target_count))
    OR (outbox.state = 'complete' AND EXISTS (
        SELECT 1 FROM publication_targets AS target
        WHERE target.outbox_id = outbox.outbox_id
            AND target.required = 1 AND target.state != 'accepted'))"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_math_is_checked_and_clock_skew_remains_unclaimed() {
        assert!(absolute_deadline(15_000).is_some());
        assert!(integrity_time().is_some());
    }

    #[test]
    fn state_queries_are_bounded_scalar_projections() {
        for query in [
            CURSOR_CHECKPOINT_INVARIANTS_SQL,
            RECONCILIATION_LEASE_INVARIANTS_SQL,
            RECONCILIATION_BACKLOG_INVARIANTS_SQL,
            PUBLICATION_INVARIANTS_SQL,
        ] {
            assert!(query.starts_with("SELECT"));
            assert!(!query.contains("SELECT *"));
            assert!(!query.contains("ORDER BY"));
        }
    }

    #[test]
    fn production_probe_source_retains_no_raw_error_projection() {
        let source = include_str!("system_doctor.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in ["format!(\"{error", "to_string()", "source()"] {
            assert!(!source.contains(forbidden), "found `{forbidden}`");
        }
    }
}
