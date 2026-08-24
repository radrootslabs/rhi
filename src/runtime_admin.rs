//! State-backed implementation of the final RHI Unix-admin contract.

use core::sync::atomic::{AtomicBool, Ordering};
use std::{path::PathBuf, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use radroots_event::id::TradeId;
use radroots_service_sqlite::BackupCreatedAtUnixMs;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row;

use crate::{
    RhiAdminFuture, RhiAdminHandler, RhiAdminHandlerError, RhiAdminHandlerErrorKind,
    RhiAdminRequestDocument, RhiAdminResponseDocument, RhiAdminRoute, RhiConfigDocumentV1,
    RhiDecryptedIdentity, RhiPresenceDesiredAuthority, RhiPresenceUnixMilliseconds,
    RhiPublicationAuthority, RhiReconciliationJobErrorKind, RhiReconciliationJobPolicy,
    RhiReconciliationUnixMilliseconds, RhiStateHost, RhiStatusReader, RhiTimeEntropyAdapters,
    build_rhi_signed_presence_documents,
    state_admin::{
        AdminJournalOperationError, RhiAdminOperationAdmission, RhiAdminOperationError,
        RhiAdminOperationErrorKind, RhiAdminOperationJournalPolicy, RhiAdminOperationRepository,
        RhiAdminOperationTimeUnixMs,
    },
    state_config,
};

const REPORT_SELECT: &str = r#"SELECT
    length(report.statement_sha256) AS statement_bytes,
    substr(report.statement_sha256, 1, 33) AS statement_sha256,
    length(report.manifest_sha256) AS manifest_bytes,
    substr(report.manifest_sha256, 1, 33) AS manifest_sha256,
    length(report.projection_sha256) AS projection_bytes,
    substr(report.projection_sha256, 1, 33) AS projection_sha256,
    length(report.trade_id) AS trade_id_bytes,
    substr(report.trade_id, 1, 17) AS trade_id,
    length(report.claim_mutation_id) AS claim_bytes,
    substr(report.claim_mutation_id, 1, 33) AS claim_mutation_id,
    length(report.issuer_public_key) AS issuer_bytes,
    substr(report.issuer_public_key, 1, 33) AS issuer_public_key,
    report.outcome,
    length(report.canonical_report) AS canonical_report_bytes,
    substr(report.canonical_report, 1, 16385) AS canonical_report,
    report.observed_at_unix_s,
    CASE WHEN report.supersedes_statement_sha256 IS NULL THEN NULL
         ELSE length(report.supersedes_statement_sha256) END AS supersedes_bytes,
    CASE WHEN report.supersedes_statement_sha256 IS NULL THEN NULL
         ELSE substr(report.supersedes_statement_sha256, 1, 33) END AS supersedes_statement_sha256,
    length(event.event_id) AS event_id_bytes,
    substr(event.event_id, 1, 33) AS event_id,
    manifest.trade_generation,
    length(manifest.evidence_policy_sha256) AS policy_bytes,
    substr(manifest.evidence_policy_sha256, 1, 33) AS evidence_policy_sha256,
    projection.reducer_contract,
    projection.reducer_contract_version,
    (SELECT COUNT(*) FROM evidence_reconciliation_sources AS source
        WHERE source.attempt_id = manifest.attempt_id) AS source_count,
    (SELECT COUNT(*) FROM evidence_reconciliation_sources AS source
        WHERE source.attempt_id = manifest.attempt_id AND source.required = 1
          AND source.completion != 'complete') AS incomplete_required,
    (SELECT COUNT(*) FROM evidence_reconciliation_sources AS source
        WHERE source.attempt_id = manifest.attempt_id AND source.required = 1
          AND source.completion = 'unsupported') AS unsupported_required,
    (SELECT COALESCE(SUM(source.accepted_event_count), 0)
        FROM evidence_reconciliation_sources AS source
        WHERE source.attempt_id = manifest.attempt_id) AS accepted_event_count
FROM attestation_reports AS report
JOIN signed_attestation_events AS event
    ON event.statement_sha256 = report.statement_sha256
JOIN evidence_manifests AS manifest
    ON manifest.manifest_sha256 = report.manifest_sha256
JOIN trade_projections AS projection
    ON projection.projection_sha256 = report.projection_sha256
"#;

const REPORT_ROWS_SUFFIX: &str = r#"WHERE report.trade_id = ? AND report.observed_at_unix_s <= ?
        AND (? IS NULL OR report.outcome = ?)
    ORDER BY report.observed_at_unix_s DESC, report.statement_sha256 DESC
    LIMIT ? OFFSET ?"#;

const CURRENT_REPORT_SUFFIX: &str = r#"WHERE report.trade_id = ?
        AND NOT EXISTS (
            SELECT 1 FROM attestation_reports AS successor
            WHERE successor.supersedes_statement_sha256 = report.statement_sha256
        )
    ORDER BY report.observed_at_unix_s DESC, report.statement_sha256 DESC
    LIMIT 2"#;

const PUBLICATION_BACKLOG_SQL: &str = r#"SELECT
    length(outbox.outbox_id) AS outbox_id_bytes,
    substr(outbox.outbox_id, 1, 33) AS outbox_id,
    length(event.statement_sha256) AS statement_bytes,
    substr(event.statement_sha256, 1, 33) AS statement_sha256,
    length(outbox.event_id) AS event_id_bytes,
    substr(outbox.event_id, 1, 33) AS event_id,
    length(outbox.event_sha256) AS event_sha256_bytes,
    substr(outbox.event_sha256, 1, 33) AS event_sha256,
    outbox.state AS outbox_state,
    outbox.next_attempt_unix_ms,
    COALESCE(MAX(target.attempt_count), 0) AS attempt_count,
    CASE
        WHEN outbox.state = 'pending' THEN 'pending'
        WHEN outbox.state = 'leased' THEN 'submitted'
        WHEN outbox.state = 'complete' THEN 'accepted'
        WHEN SUM(CASE WHEN target.state = 'auth_required' THEN 1 ELSE 0 END) > 0 THEN 'auth_required'
        WHEN SUM(CASE WHEN target.state = 'rate_limited' THEN 1 ELSE 0 END) > 0 THEN 'rate_limited'
        WHEN SUM(CASE WHEN target.state = 'rejected' THEN 1 ELSE 0 END) > 0 THEN 'rejected'
        WHEN SUM(CASE WHEN target.state = 'failed' THEN 1 ELSE 0 END) > 0 THEN 'failed'
        ELSE 'unknown'
    END AS public_state
FROM publication_outbox AS outbox
JOIN signed_attestation_events AS event ON event.event_id = outbox.event_id
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
WHERE outbox.updated_at_unix_ms <= ?
GROUP BY outbox.outbox_id
HAVING (? IS NULL OR public_state = ?)
ORDER BY outbox.updated_at_unix_ms DESC, outbox.outbox_id DESC
LIMIT ? OFFSET ?"#;

const PUBLICATION_TARGETS_SQL: &str = r#"SELECT
    length(target.outbox_id) AS outbox_id_bytes,
    substr(target.outbox_id, 1, 33) AS outbox_id,
    target.relay_id, target.state, target.attempt_count,
    (SELECT MAX(attempt.finished_at_unix_ms)
        FROM publication_attempts AS attempt
        WHERE attempt.outbox_id = target.outbox_id
          AND attempt.target_ordinal = target.target_ordinal) AS last_attempt_unix_ms
FROM publication_targets AS target
WHERE target.updated_at_unix_ms <= ?
  AND (? IS NULL OR target.outbox_id = ?)
  AND (? IS NULL OR target.state = ?)
ORDER BY target.updated_at_unix_ms DESC, target.outbox_id DESC, target.target_ordinal
LIMIT ? OFFSET ?"#;

pub(crate) struct RuntimeAdminHandler {
    pub(crate) state: Arc<RhiStateHost>,
    pub(crate) configuration: Arc<RhiConfigDocumentV1>,
    pub(crate) identity: Arc<RhiDecryptedIdentity>,
    pub(crate) publication: Arc<RhiPublicationAuthority>,
    pub(crate) presence: Arc<RhiPresenceDesiredAuthority>,
    pub(crate) status: RhiStatusReader,
    pub(crate) accepting_mutations: Arc<AtomicBool>,
    pub(crate) cursor_key: [u8; 32],
    pub(crate) time_entropy: RhiTimeEntropyAdapters,
}

impl RuntimeAdminHandler {
    async fn handle_inner(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        if request.route().is_mutation() && !self.accepting_mutations.load(Ordering::Acquire) {
            return Err(failure(RhiAdminHandlerErrorKind::Unavailable));
        }
        match request.route() {
            RhiAdminRoute::Status => {
                let snapshot = self.status.snapshot();
                let value = serde_json::from_slice(snapshot.detailed_status_json())
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                response(request.route(), value)
            }
            RhiAdminRoute::EffectiveConfig => RhiAdminResponseDocument::from_canonical_bytes(
                request.route(),
                self.configuration.effective().canonical_json().as_bytes(),
            )
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal)),
            RhiAdminRoute::IdentityStatus | RhiAdminRoute::IdentityPublic => {
                self.identity(&request).await
            }
            RhiAdminRoute::StateStatus => self.state_status(request.route()).await,
            RhiAdminRoute::StateBackup => self.backup(request).await,
            RhiAdminRoute::MetricsSnapshot => self.metrics_snapshot(request.route()),
            RhiAdminRoute::ReconciliationStatus => self.reconciliation_status(request).await,
            RhiAdminRoute::ReconciliationJobs => self.reconciliation_jobs(request).await,
            RhiAdminRoute::ReconciliationRefresh => self.reconciliation_refresh(request).await,
            RhiAdminRoute::Sources => self.sources(request).await,
            RhiAdminRoute::TradeProjection => self.trade_projection(request).await,
            RhiAdminRoute::TradeReportCurrent => self.trade_report_current(request).await,
            RhiAdminRoute::TradeReports => self.trade_reports(request).await,
            RhiAdminRoute::PublicationBacklog => self.publication_backlog(request).await,
            RhiAdminRoute::PublicationTargets => self.publication_targets(request).await,
            RhiAdminRoute::PublicationRetry => self.publication_retry(request).await,
            RhiAdminRoute::PresenceDesired => self.presence_desired(request.route()).await,
            RhiAdminRoute::PresenceRender => self.presence_render(request).await,
            RhiAdminRoute::PresenceRefresh => self.presence_refresh(request).await,
        }
    }

    async fn identity(
        &self,
        request: &RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(request)?;
        if model.pointer("/role").and_then(Value::as_str) != Some("service") {
            return Err(failure(RhiAdminHandlerErrorKind::Internal));
        }
        let generation = current_generation(&self.state).await?;
        let value = if request.route() == RhiAdminRoute::IdentityPublic {
            json!({
                "generation": generation,
                "public_key": self.identity.public_identity().as_hex(),
                "role": "service",
            })
        } else {
            json!({
                "available": true,
                "configured": true,
                "generation": generation,
                "provider": "encrypted_file",
                "public_key": self.identity.public_identity().as_hex(),
                "reason_codes": [],
                "role": "service",
            })
        };
        response(request.route(), value)
    }

    async fn state_status(
        &self,
        route: RhiAdminRoute,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        response(
            route,
            json!({
                "backup_eligible": true,
                "generation": current_generation(&self.state).await?,
                "integrity": "verified",
                "reason_codes": [],
                "schema_version": self.state.metadata().initial_database_metadata().state_schema_version().get(),
                "writer_lock": "held_by_daemon",
            }),
        )
    }

    fn metrics_snapshot(
        &self,
        route: RhiAdminRoute,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let snapshot = self.status.operations_cache().snapshot();
        let mut metrics = Map::new();
        for sample in snapshot.metrics().samples() {
            let mut key = sample.name().as_str().to_owned();
            for label in sample.labels() {
                key.push('_');
                key.push_str(label.value());
            }
            let value = match sample.value() {
                radroots_service_host::MetricValue::Counter(value) => value,
                radroots_service_host::MetricValue::Gauge(value) => {
                    u64::try_from(value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
                }
            };
            if metrics.insert(key, Value::from(value)).is_some() {
                return Err(failure(RhiAdminHandlerErrorKind::Internal));
            }
        }
        response(
            route,
            json!({
                "captured_at_utc": self.now_seconds()?,
                "metrics": metrics,
            }),
        )
    }

    async fn backup(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let expected_generation = required_u64(&model, "/expected_generation")?;
        let generation = current_generation(&self.state).await?;
        if expected_generation != generation {
            return Err(failure(RhiAdminHandlerErrorKind::Conflict));
        }
        let now_ms = self.now_millis()?;
        let prepared = match RhiAdminOperationRepository::new(&self.state)
            .prepare_admin_operation(&request, operation_time(now_ms)?)
            .await
            .map_err(map_journal_error)?
        {
            RhiAdminOperationAdmission::ExactReplay(response) => return Ok(response),
            RhiAdminOperationAdmission::Prepared(prepared) => prepared,
        };
        let target = model
            .pointer("/target_path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
        let manifest = self
            .state
            .capture_online_backup(
                &target,
                BackupCreatedAtUnixMs::new(now_ms)
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
            )
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Unavailable))?;
        let completed_ms = self.now_millis()?;
        let completed_seconds = completed_ms / 1_000;
        let completed = response(
            request.route(),
            json!({
                "completed_at_utc": completed_seconds,
                "manifest_digest": lower_hex(manifest.digest().as_bytes()),
                "operation_id": required_operation_id(&request)?,
                "snapshot_generation": generation,
            }),
        )?;
        RhiAdminOperationRepository::new(&self.state)
            .complete_admin_operation(
                &prepared,
                &completed,
                operation_time(completed_ms)?,
                RhiAdminOperationJournalPolicy::seven_days(),
            )
            .await
            .map_err(map_journal_error)?;
        Ok(completed)
    }

    async fn presence_desired(
        &self,
        route: RhiAdminRoute,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let desired = self
            .state
            .repositories()
            .desired_presence()
            .current()
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
            .ok_or_else(|| failure(RhiAdminHandlerErrorKind::NotFound))?;
        let (state, digests) = self.presence_state(desired.generation()).await?;
        response(
            route,
            json!({
                "document_digests": digests,
                "generation": desired.generation(),
                "reason_codes": [],
                "state": if desired.mode().code() == "disabled" { "disabled" } else { state },
            }),
        )
    }

    async fn presence_render(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let expected = required_u64(&model, "/expected_generation")?;
        let desired = self
            .state
            .repositories()
            .desired_presence()
            .commit(&self.presence)
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        if desired.state().generation() != expected {
            return Err(failure(RhiAdminHandlerErrorKind::Conflict));
        }
        let now_ms = self.now_millis()?;
        let prepared = match RhiAdminOperationRepository::new(&self.state)
            .prepare_admin_operation(&request, operation_time(now_ms)?)
            .await
            .map_err(map_journal_error)?
        {
            RhiAdminOperationAdmission::ExactReplay(response) => return Ok(response),
            RhiAdminOperationAdmission::Prepared(prepared) => prepared,
        };
        let documents = build_rhi_signed_presence_documents(
            desired,
            &self.presence,
            &self.identity,
            self.time_entropy
                .now_utc()
                .map_err(|_| failure(RhiAdminHandlerErrorKind::Unavailable))?,
            self.time_entropy.entropy(),
        )
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Unavailable))?;
        let digests = presence_document_digests(&documents);
        self.state
            .repositories()
            .presence_outbox()
            .commit_signed_presence(
                &documents,
                RhiPresenceUnixMilliseconds::new(now_ms)
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
            )
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let completed_ms = self.now_millis()?;
        let completed = response(
            request.route(),
            json!({
                "document_digests": digests,
                "generation": expected,
                "operation_id": required_operation_id(&request)?,
            }),
        )?;
        RhiAdminOperationRepository::new(&self.state)
            .complete_admin_operation(
                &prepared,
                &completed,
                operation_time(completed_ms)?,
                RhiAdminOperationJournalPolicy::seven_days(),
            )
            .await
            .map_err(map_journal_error)?;
        Ok(completed)
    }

    fn now_millis(&self) -> Result<u64, RhiAdminHandlerError> {
        self.time_entropy
            .now_utc_milliseconds()
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Unavailable))
    }

    fn now_seconds(&self) -> Result<u64, RhiAdminHandlerError> {
        self.time_entropy
            .now_utc()
            .map(|value| value.get())
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Unavailable))
    }

    async fn read_dirty_generation(&self, trade: TradeId) -> Result<u64, RhiAdminHandlerError> {
        self.state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        "SELECT generation FROM trade_dirty_generations WHERE trade_id = ? LIMIT 2",
                    )
                    .bind(trade.as_bytes().as_slice())
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                    if rows.len() != 1 {
                        return Err(if rows.is_empty() {
                            failure(RhiAdminHandlerErrorKind::NotFound)
                        } else {
                            failure(RhiAdminHandlerErrorKind::Internal)
                        });
                    }
                    row_u64(&rows[0], "generation")
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
    }

    async fn current_report_row(
        &self,
        trade: TradeId,
    ) -> Result<sqlx::sqlite::SqliteRow, RhiAdminHandlerError> {
        self.state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let sql = format!("{REPORT_SELECT}{CURRENT_REPORT_SUFFIX}");
                    // Both fragments are private compile-time constants; no caller data enters SQL.
                    let rows = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                        .bind(trade.as_bytes().as_slice())
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                    if rows.len() != 1 {
                        return Err(if rows.is_empty() {
                            failure(RhiAdminHandlerErrorKind::NotFound)
                        } else {
                            failure(RhiAdminHandlerErrorKind::Internal)
                        });
                    }
                    Ok(rows.into_iter().next().expect("one row was established"))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
    }

    fn cursor_or_new(
        &self,
        model: &Value,
        route: RhiAdminRoute,
        query_digest: [u8; 32],
        new_snapshot: u64,
    ) -> Result<(u64, u32), RhiAdminHandlerError> {
        model
            .pointer("/cursor")
            .and_then(Value::as_str)
            .map(|cursor| self.decode_cursor(route, cursor, query_digest))
            .transpose()
            .map(|cursor| cursor.unwrap_or((new_snapshot, 0)))
    }

    fn encode_cursor(
        &self,
        route: RhiAdminRoute,
        snapshot: u64,
        offset: u32,
        query_digest: [u8; 32],
    ) -> String {
        encode_runtime_cursor(&self.cursor_key, route, snapshot, offset, query_digest)
    }

    fn decode_cursor(
        &self,
        route: RhiAdminRoute,
        encoded: &str,
        query_digest: [u8; 32],
    ) -> Result<(u64, u32), RhiAdminHandlerError> {
        decode_runtime_cursor(&self.cursor_key, route, encoded, query_digest)
    }
}

impl RhiAdminHandler for RuntimeAdminHandler {
    fn handle<'a>(&'a self, request: RhiAdminRequestDocument) -> RhiAdminFuture<'a> {
        Box::pin(async move { self.handle_inner(request).await })
    }
}

fn presence_document_digests(documents: &crate::RhiSignedPresenceDocuments) -> Map<String, Value> {
    documents
        .documents()
        .iter()
        .map(|document| {
            (
                document.kind().code().to_owned(),
                Value::String(lower_hex(document.signed_event_sha256())),
            )
        })
        .collect()
}

fn request_model(request: &RhiAdminRequestDocument) -> Result<Value, RhiAdminHandlerError> {
    serde_json::from_slice(request.model_bytes())
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, RhiAdminHandlerError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
}

fn required_operation_id(request: &RhiAdminRequestDocument) -> Result<&str, RhiAdminHandlerError> {
    request
        .operation_id()
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
}

fn operation_time(value: u64) -> Result<RhiAdminOperationTimeUnixMs, RhiAdminHandlerError> {
    RhiAdminOperationTimeUnixMs::new(value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

async fn current_generation(state: &RhiStateHost) -> Result<u64, RhiAdminHandlerError> {
    state_config::current_generation(state)
        .await
        .map(u64::from)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

fn response(
    route: RhiAdminRoute,
    value: Value,
) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
    let bytes =
        serde_json::to_vec(&value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    RhiAdminResponseDocument::from_canonical_bytes(route, &bytes)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

fn map_journal_error(error: RhiAdminOperationError) -> RhiAdminHandlerError {
    failure(match error.kind() {
        RhiAdminOperationErrorKind::OperationConflict => {
            RhiAdminHandlerErrorKind::OperationIdConflict
        }
        RhiAdminOperationErrorKind::ResourceExhausted => RhiAdminHandlerErrorKind::Unavailable,
        RhiAdminOperationErrorKind::OperationOutcomeUnknown
        | RhiAdminOperationErrorKind::CommitOutcomeUnknown => RhiAdminHandlerErrorKind::Unavailable,
        RhiAdminOperationErrorKind::InvalidMode
        | RhiAdminOperationErrorKind::InvalidInput
        | RhiAdminOperationErrorKind::Binding
        | RhiAdminOperationErrorKind::Transaction => RhiAdminHandlerErrorKind::Internal,
    })
}

const fn failure(kind: RhiAdminHandlerErrorKind) -> RhiAdminHandlerError {
    RhiAdminHandlerError::new(kind)
}

fn lower_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn parse_trade_id(value: &str) -> Result<TradeId, RhiAdminHandlerError> {
    TradeId::parse(value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

fn parse_digest(value: &str) -> Result<[u8; 32], RhiAdminHandlerError> {
    if value.len() != 64
        || value
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high =
            hex_nibble(chunk[0]).ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
        let low =
            hex_nibble(chunk[1]).ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn page_limit(model: &Value) -> Result<u16, RhiAdminHandlerError> {
    model
        .pointer("/limit")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (1..=200).contains(value))
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
}

fn query_digest(model: &Value) -> Result<[u8; 32], RhiAdminHandlerError> {
    let mut model = model.clone();
    model
        .as_object_mut()
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?
        .remove("cursor");
    let bytes =
        serde_json::to_vec(&model).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    Ok(Sha256::digest(bytes).into())
}

fn cursor_authenticator(key: &[u8; 32], payload: &[u8]) -> Hmac<Sha256> {
    let mut digest = Hmac::<Sha256>::new_from_slice(key).expect("SHA-256 HMAC accepts every key");
    digest.update(b"radroots.rhi.admin_cursor.v1\0");
    digest.update(
        &u64::try_from(payload.len())
            .expect("cursor payload length fits u64")
            .to_be_bytes(),
    );
    digest.update(payload);
    digest
}

fn cursor_tag(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    cursor_authenticator(key, payload)
        .finalize()
        .into_bytes()
        .into()
}

fn encode_runtime_cursor(
    key: &[u8; 32],
    route: RhiAdminRoute,
    snapshot: u64,
    offset: u32,
    query_digest: [u8; 32],
) -> String {
    let mut bytes = Vec::with_capacity(78);
    bytes.push(1);
    bytes.push(route_code(route));
    bytes.extend_from_slice(&snapshot.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(&query_digest);
    let tag = cursor_tag(key, &bytes);
    bytes.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_runtime_cursor(
    key: &[u8; 32],
    route: RhiAdminRoute,
    encoded: &str,
    query_digest: [u8; 32],
) -> Result<(u64, u32), RhiAdminHandlerError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::InvalidCursor))?;
    if bytes.len() != 78
        || bytes[0] != 1
        || bytes[1] != route_code(route)
        || bytes[14..46] != query_digest
    {
        return Err(failure(RhiAdminHandlerErrorKind::InvalidCursor));
    }
    cursor_authenticator(key, &bytes[..46])
        .verify_slice(&bytes[46..])
        .map_err(|_| failure(RhiAdminHandlerErrorKind::InvalidCursor))?;
    let snapshot = u64::from_be_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| failure(RhiAdminHandlerErrorKind::InvalidCursor))?,
    );
    let offset = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| failure(RhiAdminHandlerErrorKind::InvalidCursor))?,
    );
    Ok((snapshot, offset))
}

const fn route_code(route: RhiAdminRoute) -> u8 {
    match route {
        RhiAdminRoute::Status => 0,
        RhiAdminRoute::EffectiveConfig => 1,
        RhiAdminRoute::IdentityStatus => 2,
        RhiAdminRoute::IdentityPublic => 3,
        RhiAdminRoute::StateStatus => 4,
        RhiAdminRoute::StateBackup => 5,
        RhiAdminRoute::MetricsSnapshot => 6,
        RhiAdminRoute::ReconciliationStatus => 7,
        RhiAdminRoute::ReconciliationJobs => 8,
        RhiAdminRoute::ReconciliationRefresh => 9,
        RhiAdminRoute::Sources => 10,
        RhiAdminRoute::TradeProjection => 11,
        RhiAdminRoute::TradeReportCurrent => 12,
        RhiAdminRoute::TradeReports => 13,
        RhiAdminRoute::PublicationBacklog => 14,
        RhiAdminRoute::PublicationTargets => 15,
        RhiAdminRoute::PublicationRetry => 16,
        RhiAdminRoute::PresenceDesired => 17,
        RhiAdminRoute::PresenceRender => 18,
        RhiAdminRoute::PresenceRefresh => 19,
    }
}

fn row_u64(row: &sqlx::sqlite::SqliteRow, name: &str) -> Result<u64, RhiAdminHandlerError> {
    row.try_get::<i64, _>(name)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
        .and_then(|value| {
            u64::try_from(value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
        })
}

fn optional_nonnegative_i64(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> Result<Option<u64>, RhiAdminHandlerError> {
    row.try_get::<Option<i64>, _>(name)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
        .map(|value| u64::try_from(value).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal)))
        .transpose()
}

fn exact_blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    value: &str,
    length: &str,
) -> Result<[u8; N], RhiAdminHandlerError> {
    if row_u64(row, length)? != N as u64 {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    row.try_get::<Vec<u8>, _>(value)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
        .try_into()
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
}

fn optional_exact_blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    value: &str,
    length: &str,
) -> Result<Option<[u8; N]>, RhiAdminHandlerError> {
    let length = row
        .try_get::<Option<i64>, _>(length)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    match length {
        None => {
            if row
                .try_get::<Option<Vec<u8>>, _>(value)
                .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
                .is_some()
            {
                return Err(failure(RhiAdminHandlerErrorKind::Internal));
            }
            Ok(None)
        }
        Some(length) if length == N as i64 => row
            .try_get::<Option<Vec<u8>>, _>(value)
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
            .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?
            .try_into()
            .map(Some)
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal)),
        Some(_) => Err(failure(RhiAdminHandlerErrorKind::Internal)),
    }
}

fn bounded_blob(
    row: &sqlx::sqlite::SqliteRow,
    value: &str,
    length: &str,
    maximum: usize,
) -> Result<Box<[u8]>, RhiAdminHandlerError> {
    let length = row_u64(row, length)?;
    if length == 0 || length > maximum as u64 {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    let bytes = row
        .try_get::<Vec<u8>, _>(value)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    if bytes.len() as u64 != length {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    Ok(bytes.into_boxed_slice())
}

fn job_summary(row: &sqlx::sqlite::SqliteRow) -> Result<Value, RhiAdminHandlerError> {
    let job_id = exact_blob::<32>(row, "job_id", "job_id_bytes")?;
    let trade_id = exact_blob::<16>(row, "trade_id", "trade_id_bytes")?;
    let attempt_count = row_u64(row, "attempt_count")?;
    let state = row
        .try_get::<&str, _>("state")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let state = match state {
        "ready" if attempt_count == 0 => "pending",
        "ready" => "retry_scheduled",
        "leased" => "leased",
        "completed" => "completed",
        "exhausted" | "superseded" => "failed",
        _ => return Err(failure(RhiAdminHandlerErrorKind::Internal)),
    };
    let mut value = json!({
        "attempt_count": attempt_count,
        "dirty_generation": row_u64(row, "input_generation")?,
        "job_id": lower_hex(&job_id),
        "reason_codes": [],
        "scheduled_at_utc": row_u64(row, "created_at_unix_ms")? / 1_000,
        "state": state,
        "trade_id": lower_hex(&trade_id),
    });
    if let Some(expires) = optional_nonnegative_i64(row, "lease_expires_unix_ms")? {
        value["lease_expires_at_utc"] = Value::from(expires / 1_000);
    }
    Ok(value)
}

struct ConfiguredSourceSummary {
    source_id: Box<str>,
    required: bool,
}

fn configured_source_summaries(
    configuration: &RhiConfigDocumentV1,
) -> Result<Vec<ConfiguredSourceSummary>, RhiAdminHandlerError> {
    let sources = configuration
        .normalized()
        .pointer("/evidence/sources")
        .and_then(Value::as_array)
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
    if sources.is_empty() || sources.len() > 16 {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    sources
        .iter()
        .map(|source| {
            let source_id = source
                .pointer("/source_id")
                .and_then(Value::as_str)
                .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
            let required = source
                .pointer("/required")
                .and_then(Value::as_bool)
                .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
            Ok(ConfiguredSourceSummary {
                source_id: source_id.into(),
                required,
            })
        })
        .collect()
}

fn request_trade_id(request: &RhiAdminRequestDocument) -> Result<TradeId, RhiAdminHandlerError> {
    request
        .parameter("trade_id")
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
        .and_then(parse_trade_id)
}

fn contract_outcome_to_db(value: &str) -> Result<&'static str, RhiAdminHandlerError> {
    match value {
        "Valid" => Ok("valid"),
        "Invalid" => Ok("invalid"),
        "Indeterminate" => Ok("indeterminate"),
        _ => Err(failure(RhiAdminHandlerErrorKind::Internal)),
    }
}

fn db_outcome_to_contract(value: &str) -> Result<&'static str, RhiAdminHandlerError> {
    match value {
        "valid" => Ok("Valid"),
        "invalid" => Ok("Invalid"),
        "indeterminate" => Ok("Indeterminate"),
        _ => Err(failure(RhiAdminHandlerErrorKind::Internal)),
    }
}

fn report_coverage(row: &sqlx::sqlite::SqliteRow) -> Result<&'static str, RhiAdminHandlerError> {
    let source_count = row_u64(row, "source_count")?;
    let incomplete = row_u64(row, "incomplete_required")?;
    let unsupported = row_u64(row, "unsupported_required")?;
    let accepted = row_u64(row, "accepted_event_count")?;
    if source_count == 0 {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    Ok(if unsupported > 0 {
        "Unsupported"
    } else if incomplete > 0 && accepted == 0 {
        "Missing"
    } else if incomplete > 0 {
        "Partial"
    } else {
        "ScopeSatisfied"
    })
}

fn report_detail(row: &sqlx::sqlite::SqliteRow) -> Result<Value, RhiAdminHandlerError> {
    let canonical = bounded_blob(row, "canonical_report", "canonical_report_bytes", 16_384)?;
    let mut report: Value = serde_json::from_slice(&canonical)
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let object = report
        .as_object_mut()
        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?;
    let statement = lower_hex(&exact_blob::<32>(
        row,
        "statement_sha256",
        "statement_bytes",
    )?);
    let manifest = lower_hex(&exact_blob::<32>(row, "manifest_sha256", "manifest_bytes")?);
    let projection = lower_hex(&exact_blob::<32>(
        row,
        "projection_sha256",
        "projection_bytes",
    )?);
    let trade = lower_hex(&exact_blob::<16>(row, "trade_id", "trade_id_bytes")?);
    let claim = lower_hex(&exact_blob::<32>(row, "claim_mutation_id", "claim_bytes")?);
    let issuer = lower_hex(&exact_blob::<32>(row, "issuer_public_key", "issuer_bytes")?);
    let policy = lower_hex(&exact_blob::<32>(
        row,
        "evidence_policy_sha256",
        "policy_bytes",
    )?);
    let observed = row_u64(row, "observed_at_unix_s")?;
    let generation = row_u64(row, "trade_generation")?;
    let outcome = row
        .try_get::<&str, _>("outcome")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let reducer_contract = row
        .try_get::<&str, _>("reducer_contract")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let reducer_version = row_u64(row, "reducer_contract_version")?;
    let required_matches = [
        ("report_id", statement.as_str()),
        ("evidence_manifest_digest", manifest.as_str()),
        ("projection_digest", projection.as_str()),
        ("trade_id", trade.as_str()),
        ("claim_mutation_id", claim.as_str()),
        ("issuer_pubkey", issuer.as_str()),
        ("evidence_policy_digest", policy.as_str()),
        ("reducer_contract_id", reducer_contract),
    ]
    .into_iter()
    .all(|(field, expected)| object.get(field).and_then(Value::as_str) == Some(expected));
    if !required_matches
        || object.get("trade_generation").and_then(Value::as_u64) != Some(generation)
        || object.get("observed_at_unix_s").and_then(Value::as_u64) != Some(observed)
        || object
            .get("reducer_contract_version")
            .and_then(Value::as_u64)
            != Some(reducer_version)
        || object.get("outcome").and_then(Value::as_str) != Some(outcome)
        || object.get("statement_digest").and_then(Value::as_str) != Some(statement.as_str())
    {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    let supersedes =
        optional_exact_blob::<32>(row, "supersedes_statement_sha256", "supersedes_bytes")?;
    match supersedes {
        Some(value)
            if object.get("supersedes_report_id").and_then(Value::as_str)
                == Some(lower_hex(&value).as_str()) => {}
        None if object
            .get("supersedes_report_id")
            .is_some_and(Value::is_null) =>
        {
            object.remove("supersedes_report_id");
            object.remove("supersedes_event_id");
        }
        _ => return Err(failure(RhiAdminHandlerErrorKind::Internal)),
    }
    object.remove("statement_digest");
    object.insert(
        "attestation_event_id".to_owned(),
        Value::String(lower_hex(&exact_blob::<32>(
            row,
            "event_id",
            "event_id_bytes",
        )?)),
    );
    object.insert(
        "coverage".to_owned(),
        Value::String(report_coverage(row)?.to_owned()),
    );
    object.insert(
        "outcome".to_owned(),
        Value::String(db_outcome_to_contract(outcome)?.to_owned()),
    );
    Ok(report)
}

fn report_summary(row: &sqlx::sqlite::SqliteRow) -> Result<Value, RhiAdminHandlerError> {
    let supersedes =
        optional_exact_blob::<32>(row, "supersedes_statement_sha256", "supersedes_bytes")?;
    let outcome = row
        .try_get::<&str, _>("outcome")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let mut value = json!({
        "attestation_event_id": lower_hex(&exact_blob::<32>(row, "event_id", "event_id_bytes")?),
        "claim_mutation_id": lower_hex(&exact_blob::<32>(row, "claim_mutation_id", "claim_bytes")?),
        "coverage": report_coverage(row)?,
        "observed_at_utc": row_u64(row, "observed_at_unix_s")?,
        "outcome": db_outcome_to_contract(outcome)?,
        "report_id": lower_hex(&exact_blob::<32>(row, "statement_sha256", "statement_bytes")?),
        "trade_id": lower_hex(&exact_blob::<16>(row, "trade_id", "trade_id_bytes")?),
    });
    if let Some(supersedes) = supersedes {
        value["supersedes_report_id"] = Value::String(lower_hex(&supersedes));
    }
    Ok(value)
}

fn publication_summary(row: &sqlx::sqlite::SqliteRow) -> Result<Value, RhiAdminHandlerError> {
    let state = row
        .try_get::<&str, _>("public_state")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    if !matches!(
        state,
        "pending"
            | "submitted"
            | "accepted"
            | "rejected"
            | "rate_limited"
            | "auth_required"
            | "failed"
            | "unknown"
    ) {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    let mut value = json!({
        "attempt_count": row_u64(row, "attempt_count")?,
        "event_id": lower_hex(&exact_blob::<32>(row, "event_id", "event_id_bytes")?),
        "exact_bytes_digest": lower_hex(&exact_blob::<32>(row, "event_sha256", "event_sha256_bytes")?),
        "reason_codes": if state == "failed" || state == "unknown" { vec!["publication_blocked"] } else { Vec::<&str>::new() },
        "report_id": lower_hex(&exact_blob::<32>(row, "statement_sha256", "statement_bytes")?),
        "state": state,
        "workflow_id": lower_hex(&exact_blob::<32>(row, "outbox_id", "outbox_id_bytes")?),
    });
    if let Some(next) = optional_nonnegative_i64(row, "next_attempt_unix_ms")? {
        value["next_attempt_at_utc"] = Value::from(next / 1_000);
    }
    Ok(value)
}

fn publication_target_summary(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Value, RhiAdminHandlerError> {
    let target = row
        .try_get::<&str, _>("relay_id")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    let state = row
        .try_get::<&str, _>("state")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
    if target.is_empty()
        || target.len() > 64
        || !matches!(
            state,
            "pending"
                | "submitted"
                | "accepted"
                | "rejected"
                | "rate_limited"
                | "auth_required"
                | "failed"
                | "unknown"
        )
    {
        return Err(failure(RhiAdminHandlerErrorKind::Internal));
    }
    let mut value = json!({
        "attempt_count": row_u64(row, "attempt_count")?,
        "reason_codes": if state == "failed" || state == "unknown" { vec!["publication_target_failed"] } else { Vec::<&str>::new() },
        "state": state,
        "target_id": target,
        "workflow_id": lower_hex(&exact_blob::<32>(row, "outbox_id", "outbox_id_bytes")?),
    });
    if let Some(last) = optional_nonnegative_i64(row, "last_attempt_unix_ms")? {
        value["last_attempt_at_utc"] = Value::from(last / 1_000);
    }
    Ok(value)
}

fn operation_row_u64(
    row: &sqlx::sqlite::SqliteRow,
    name: &str,
) -> Result<u64, AdminJournalOperationError> {
    row.try_get::<i64, _>(name)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(AdminJournalOperationError::Binding)
}

fn operation_exact_blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    value: &str,
    length: &str,
) -> Result<[u8; N], AdminJournalOperationError> {
    if operation_row_u64(row, length)? != N as u64 {
        return Err(AdminJournalOperationError::Binding);
    }
    row.try_get::<Vec<u8>, _>(value)
        .map_err(|_| AdminJournalOperationError::Binding)?
        .try_into()
        .map_err(|_| AdminJournalOperationError::Binding)
}

fn presence_kind(row: &sqlx::sqlite::SqliteRow) -> Result<&str, RhiAdminHandlerError> {
    match row
        .try_get::<&str, _>("document_kind")
        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?
    {
        kind @ ("service_profile" | "application_handler") => Ok(kind),
        _ => Err(failure(RhiAdminHandlerErrorKind::Internal)),
    }
}

fn operation_presence_kind(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<&str, AdminJournalOperationError> {
    match row
        .try_get::<&str, _>("document_kind")
        .map_err(|_| AdminJournalOperationError::Binding)?
    {
        kind @ ("service_profile" | "application_handler") => Ok(kind),
        _ => Err(AdminJournalOperationError::Binding),
    }
}

// Domain-route methods are kept below the transport-independent common boundary.
impl RuntimeAdminHandler {
    async fn reconciliation_status(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let policy_digest = lower_hex(self.state.metadata().evidence_policy_digest().as_bytes());
        let value = self
            .state
            .sqlite_host()
            .transaction(|transaction| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"SELECT
                            (SELECT COUNT(*) FROM trade_dirty_generations) AS dirty_count,
                            COUNT(CASE WHEN state = 'ready' AND attempt_count = 0 THEN 1 END) AS pending_count,
                            COUNT(CASE WHEN state = 'ready' AND attempt_count > 0 THEN 1 END) AS retry_count,
                            COUNT(CASE WHEN state = 'leased' THEN 1 END) AS leased_count,
                            COUNT(CASE WHEN state = 'completed' THEN 1 END) AS completed_count,
                            COUNT(CASE WHEN state IN ('exhausted', 'superseded') THEN 1 END) AS failed_count,
                            MIN(CASE WHEN state = 'ready' THEN created_at_unix_ms END) AS oldest_pending_ms,
                            (SELECT COUNT(*) FROM evidence_reconciliation_sources
                                WHERE required = 1 AND completion != 'complete') AS required_failures
                        FROM reconciliation_jobs"#,
                    )
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                    let mut counts = Map::new();
                    for (code, column) in [
                        ("pending", "pending_count"),
                        ("retry_scheduled", "retry_count"),
                        ("leased", "leased_count"),
                        ("completed", "completed_count"),
                        ("failed", "failed_count"),
                    ] {
                        counts.insert(code.to_owned(), Value::from(row_u64(&row, column)?));
                    }
                    let mut value = json!({
                        "dirty_trade_count": row_u64(&row, "dirty_count")?,
                        "job_counts": counts,
                        "policy_digest": policy_digest,
                        "required_source_failures": row_u64(&row, "required_failures")?,
                    });
                    if let Some(value_ms) = optional_nonnegative_i64(&row, "oldest_pending_ms")? {
                        value["oldest_pending_at_utc"] = Value::from(value_ms / 1_000);
                    }
                    Ok::<Value, RhiAdminHandlerError>(value)
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        response(request.route(), value)
    }

    async fn reconciliation_jobs(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = page_limit(&model)?;
        let state_filter = model
            .pointer("/state")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let trade_filter = model
            .pointer("/trade_id")
            .and_then(Value::as_str)
            .map(parse_trade_id)
            .transpose()?
            .map(|trade| trade.as_bytes().to_vec());
        let query_digest = query_digest(&model)?;
        let (snapshot, offset) =
            self.cursor_or_new(&model, request.route(), query_digest, self.now_millis()?)?;
        let fetch_limit = i64::from(limit) + 1;
        let offset_i64 = i64::from(offset);
        let rows = self
            .state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    sqlx::query(
                        r#"SELECT
                            length(job_id) AS job_id_bytes, substr(job_id, 1, 33) AS job_id,
                            length(trade_id) AS trade_id_bytes, substr(trade_id, 1, 17) AS trade_id,
                            state, attempt_count, input_generation, created_at_unix_ms,
                            lease_expires_unix_ms
                        FROM reconciliation_jobs
                        WHERE updated_at_unix_ms <= ?
                          AND (? IS NULL OR
                            (? = 'pending' AND state = 'ready' AND attempt_count = 0) OR
                            (? = 'retry_scheduled' AND state = 'ready' AND attempt_count > 0) OR
                            (? = 'leased' AND state = 'leased') OR
                            (? = 'completed' AND state = 'completed') OR
                            (? = 'failed' AND state IN ('exhausted', 'superseded')))
                          AND (? IS NULL OR trade_id = ?)
                        ORDER BY updated_at_unix_ms DESC, job_id DESC
                        LIMIT ? OFFSET ?"#,
                    )
                    .bind(
                        i64::try_from(snapshot)
                            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                    )
                    .bind(state_filter.as_deref())
                    .bind(state_filter.as_deref())
                    .bind(state_filter.as_deref())
                    .bind(state_filter.as_deref())
                    .bind(state_filter.as_deref())
                    .bind(state_filter.as_deref())
                    .bind(trade_filter.as_deref())
                    .bind(trade_filter.as_deref())
                    .bind(fetch_limit)
                    .bind(offset_i64)
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let has_more = rows.len() > usize::from(limit);
        let items = rows
            .iter()
            .take(usize::from(limit))
            .map(job_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let mut value = json!({"items":items,"snapshot_generation":snapshot});
        if has_more {
            value["next_cursor"] = Value::String(
                self.encode_cursor(
                    request.route(),
                    snapshot,
                    offset
                        .checked_add(u32::from(limit))
                        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?,
                    query_digest,
                ),
            );
        }
        response(request.route(), value)
    }

    async fn reconciliation_refresh(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let trade = model
            .pointer("/trade_id")
            .and_then(Value::as_str)
            .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
            .and_then(parse_trade_id)?;
        let expected = required_u64(&model, "/expected_dirty_generation")?;
        let actual = self.read_dirty_generation(trade).await?;
        if actual != expected {
            return Err(failure(RhiAdminHandlerErrorKind::Conflict));
        }
        let now_ms = self.now_millis()?;
        let prepared = match RhiAdminOperationRepository::new(&self.state)
            .prepare_admin_operation(&request, operation_time(now_ms)?)
            .await
            .map_err(map_journal_error)?
        {
            RhiAdminOperationAdmission::ExactReplay(response) => return Ok(response),
            RhiAdminOperationAdmission::Prepared(prepared) => prepared,
        };
        let policy = RhiReconciliationJobPolicy::from_configuration(&self.configuration)
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let outcome = self
            .state
            .repositories()
            .reconciliation_jobs()
            .schedule_trade(
                trade,
                policy,
                RhiReconciliationUnixMilliseconds::new(now_ms)
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
            )
            .await
            .map_err(|error| match error.kind() {
                RhiReconciliationJobErrorKind::DirtyGenerationConflict => {
                    failure(RhiAdminHandlerErrorKind::Conflict)
                }
                RhiReconciliationJobErrorKind::QueueFull => {
                    failure(RhiAdminHandlerErrorKind::Unavailable)
                }
                _ => failure(RhiAdminHandlerErrorKind::Internal),
            })?;
        let job = outcome.job();
        let completed_ms = self.now_millis()?;
        let completed = response(
            request.route(),
            json!({
                "dirty_generation": job.input_generation(),
                "job_id": lower_hex(job.id().as_bytes()),
                "operation_id": required_operation_id(&request)?,
                "trade_id": lower_hex(job.trade_id().as_bytes()),
            }),
        )?;
        RhiAdminOperationRepository::new(&self.state)
            .complete_admin_operation(
                &prepared,
                &completed,
                operation_time(completed_ms)?,
                RhiAdminOperationJournalPolicy::seven_days(),
            )
            .await
            .map_err(map_journal_error)?;
        Ok(completed)
    }
    async fn sources(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = page_limit(&model)?;
        let required_filter = model.pointer("/required").and_then(Value::as_bool);
        let completion_filter = model
            .pointer("/completion")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let sources = configured_source_summaries(&self.configuration)?;
        let query_digest = query_digest(&model)?;
        let (snapshot, offset) =
            self.cursor_or_new(&model, request.route(), query_digest, self.now_millis()?)?;
        let snapshot_sql =
            i64::try_from(snapshot).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let rows = self
            .state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let mut items = Vec::with_capacity(sources.len());
                    for source in sources {
                        let attempt = sqlx::query(
                            r#"SELECT completion, finished_unix_ms
                            FROM evidence_reconciliation_sources
                            WHERE source_id = ? AND finished_unix_ms <= ?
                            ORDER BY finished_unix_ms DESC, attempt_id DESC, request_id DESC
                            LIMIT 1"#,
                        )
                        .bind(source.source_id.as_ref())
                        .bind(snapshot_sql)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                        let completion = attempt
                            .as_ref()
                            .map(|row| {
                                row.try_get::<&str, _>("completion")
                                    .map(str::to_owned)
                                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
                            })
                            .transpose()?
                            .unwrap_or_else(|| "incomplete_unknown".to_owned());
                        if required_filter.is_some_and(|required| required != source.required)
                            || completion_filter
                                .as_deref()
                                .is_some_and(|expected| expected != completion)
                        {
                            continue;
                        }
                        let checkpoint = sqlx::query(
                            r#"SELECT cursor_created_at_unix_s,
                                length(cursor_event_id) AS event_id_bytes,
                                substr(cursor_event_id, 1, 33) AS cursor_event_id
                            FROM relay_checkpoints
                            WHERE source_id = ? AND completed_at_unix_s <= ?
                            ORDER BY completed_at_unix_s DESC, trade_id DESC
                            LIMIT 1"#,
                        )
                        .bind(source.source_id.as_ref())
                        .bind(snapshot_sql / 1_000)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                        let mut value = json!({
                            "completion": completion,
                            "reason_codes": [],
                            "required": source.required,
                            "source_id": source.source_id,
                        });
                        if let Some(row) = attempt.as_ref() {
                            value["last_attempt_at_utc"] =
                                Value::from(row_u64(row, "finished_unix_ms")? / 1_000);
                        }
                        if let Some(row) = checkpoint.as_ref() {
                            value["cursor"] = json!({
                                "created_at_unix_seconds": row_u64(row, "cursor_created_at_unix_s")?,
                                "event_id_lowercase_hex": lower_hex(&exact_blob::<32>(row, "cursor_event_id", "event_id_bytes")?),
                            });
                        }
                        items.push(value);
                    }
                    Ok::<Vec<Value>, RhiAdminHandlerError>(items)
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let start =
            usize::try_from(offset).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        if start > rows.len() {
            return Err(failure(RhiAdminHandlerErrorKind::InvalidCursor));
        }
        let end = start.saturating_add(usize::from(limit)).min(rows.len());
        let items = rows[start..end].to_vec();
        let mut value = json!({"items":items,"snapshot_generation":snapshot});
        if end < rows.len() {
            value["next_cursor"] = Value::String(self.encode_cursor(
                request.route(),
                snapshot,
                u32::try_from(end).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                query_digest,
            ));
        }
        response(request.route(), value)
    }
    async fn trade_projection(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let trade = request_trade_id(&request)?;
        let row = self.current_report_row(trade).await?;
        let report = report_detail(&row)?;
        response(
            request.route(),
            json!({
                "coverage": report["coverage"].clone(),
                "dirty_generation": report["trade_generation"].clone(),
                "manifest_digest": report["evidence_manifest_digest"].clone(),
                "observed_at_utc": report["observed_at_unix_s"].clone(),
                "outcome": report["outcome"].clone(),
                "policy_digest": report["evidence_policy_digest"].clone(),
                "projection_digest": report["projection_digest"].clone(),
                "reason_codes": report["reason_codes"].clone(),
                "trade_id": report["trade_id"].clone(),
            }),
        )
    }
    async fn trade_report_current(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let row = self.current_report_row(request_trade_id(&request)?).await?;
        response(request.route(), report_detail(&row)?)
    }
    async fn trade_reports(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = page_limit(&model)?;
        let trade = request_trade_id(&request)?;
        let outcome = model
            .pointer("/outcome")
            .and_then(Value::as_str)
            .map(contract_outcome_to_db)
            .transpose()?
            .map(str::to_owned);
        let query_digest = query_digest(&model)?;
        let (snapshot, offset) =
            self.cursor_or_new(&model, request.route(), query_digest, self.now_seconds()?)?;
        let trade_bytes = trade.as_bytes().to_vec();
        let fetch_limit = i64::from(limit) + 1;
        let offset_i64 = i64::from(offset);
        let snapshot_sql =
            i64::try_from(snapshot).map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let rows = self
            .state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let sql = format!("{REPORT_SELECT}{REPORT_ROWS_SUFFIX}");
                    // Both fragments are private compile-time constants; all filters remain bound.
                    sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                        .bind(trade_bytes)
                        .bind(snapshot_sql)
                        .bind(outcome.as_deref())
                        .bind(outcome.as_deref())
                        .bind(fetch_limit)
                        .bind(offset_i64)
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let has_more = rows.len() > usize::from(limit);
        let items = rows
            .iter()
            .take(usize::from(limit))
            .map(report_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let mut value = json!({"items":items,"snapshot_generation":snapshot});
        if has_more {
            value["next_cursor"] = Value::String(
                self.encode_cursor(
                    request.route(),
                    snapshot,
                    offset
                        .checked_add(u32::from(limit))
                        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?,
                    query_digest,
                ),
            );
        }
        response(request.route(), value)
    }
    async fn publication_backlog(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = page_limit(&model)?;
        let state_filter = model
            .pointer("/state")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let query_digest = query_digest(&model)?;
        let (snapshot, offset) =
            self.cursor_or_new(&model, request.route(), query_digest, self.now_millis()?)?;
        let rows = self
            .state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    sqlx::query(PUBLICATION_BACKLOG_SQL)
                        .bind(
                            i64::try_from(snapshot)
                                .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                        )
                        .bind(state_filter.as_deref())
                        .bind(state_filter.as_deref())
                        .bind(i64::from(limit) + 1)
                        .bind(i64::from(offset))
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let has_more = rows.len() > usize::from(limit);
        let items = rows
            .iter()
            .take(usize::from(limit))
            .map(publication_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let mut value = json!({"items":items,"snapshot_generation":snapshot});
        if has_more {
            value["next_cursor"] = Value::String(
                self.encode_cursor(
                    request.route(),
                    snapshot,
                    offset
                        .checked_add(u32::from(limit))
                        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?,
                    query_digest,
                ),
            );
        }
        response(request.route(), value)
    }
    async fn publication_targets(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let limit = page_limit(&model)?;
        let state_filter = model
            .pointer("/state")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let workflow = model
            .pointer("/workflow_id")
            .and_then(Value::as_str)
            .map(parse_digest)
            .transpose()?
            .map(Vec::from);
        let query_digest = query_digest(&model)?;
        let (snapshot, offset) =
            self.cursor_or_new(&model, request.route(), query_digest, self.now_millis()?)?;
        let rows = self
            .state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    sqlx::query(PUBLICATION_TARGETS_SQL)
                        .bind(
                            i64::try_from(snapshot)
                                .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                        )
                        .bind(workflow.as_deref())
                        .bind(workflow.as_deref())
                        .bind(state_filter.as_deref())
                        .bind(state_filter.as_deref())
                        .bind(i64::from(limit) + 1)
                        .bind(i64::from(offset))
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
        let has_more = rows.len() > usize::from(limit);
        let items = rows
            .iter()
            .take(usize::from(limit))
            .map(publication_target_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let mut value = json!({"items":items,"snapshot_generation":snapshot});
        if has_more {
            value["next_cursor"] = Value::String(
                self.encode_cursor(
                    request.route(),
                    snapshot,
                    offset
                        .checked_add(u32::from(limit))
                        .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))?,
                    query_digest,
                ),
            );
        }
        response(request.route(), value)
    }
    async fn publication_retry(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let workflow = model
            .pointer("/workflow_id")
            .and_then(Value::as_str)
            .ok_or_else(|| failure(RhiAdminHandlerErrorKind::Internal))
            .and_then(parse_digest)?;
        let expected = required_u64(&model, "/expected_generation")?;
        let now_ms = self.now_millis()?;
        let operation_id = required_operation_id(&request)?.to_owned();
        let route = request.route();
        let expected_target_count = self.publication.targets().len();
        RhiAdminOperationRepository::new(&self.state)
            .execute_database_admin_operation(
                &request,
                operation_time(now_ms)?,
                RhiAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    Box::pin(async move {
                        let rows = sqlx::query(
                            r#"SELECT state, revision, target_count,
                                length(event_sha256) AS event_sha256_bytes,
                                substr(event_sha256, 1, 33) AS event_sha256
                            FROM publication_outbox WHERE outbox_id = ? LIMIT 2"#,
                        )
                        .bind(workflow.as_slice())
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        if rows.len() != 1 {
                            return Err(if rows.is_empty() {
                                AdminJournalOperationError::Conflict
                            } else {
                                AdminJournalOperationError::Binding
                            });
                        }
                        let row = &rows[0];
                        let state = row
                            .try_get::<&str, _>("state")
                            .map_err(|_| AdminJournalOperationError::Binding)?;
                        let revision = operation_row_u64(row, "revision")?;
                        let target_count = operation_row_u64(row, "target_count")?;
                        let event_sha256 = operation_exact_blob::<32>(
                            row,
                            "event_sha256",
                            "event_sha256_bytes",
                        )?;
                        if state != "blocked"
                            || revision != expected
                            || usize::try_from(target_count).ok() != Some(expected_target_count)
                        {
                            return Err(AdminJournalOperationError::Conflict);
                        }
                        sqlx::query(
                            r#"UPDATE publication_targets
                            SET state = 'pending', revision = revision + 1,
                                next_attempt_unix_ms = ?, updated_at_unix_ms = ?
                            WHERE outbox_id = ? AND state != 'accepted'"#,
                        )
                        .bind(i64::try_from(now_ms).map_err(|_| AdminJournalOperationError::InvalidInput)?)
                        .bind(i64::try_from(now_ms).map_err(|_| AdminJournalOperationError::InvalidInput)?)
                        .bind(workflow.as_slice())
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        let changed = sqlx::query(
                            r#"UPDATE publication_outbox
                            SET state = 'pending', revision = revision + 1,
                                next_attempt_unix_ms = ?, updated_at_unix_ms = ?
                            WHERE outbox_id = ? AND state = 'blocked' AND revision = ?"#,
                        )
                        .bind(i64::try_from(now_ms).map_err(|_| AdminJournalOperationError::InvalidInput)?)
                        .bind(i64::try_from(now_ms).map_err(|_| AdminJournalOperationError::InvalidInput)?)
                        .bind(workflow.as_slice())
                        .bind(i64::try_from(expected).map_err(|_| AdminJournalOperationError::InvalidInput)?)
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        if changed.rows_affected() != 1 {
                            return Err(AdminJournalOperationError::Conflict);
                        }
                        response(
                            route,
                            json!({
                                "exact_bytes_digest": lower_hex(&event_sha256),
                                "generation": expected.checked_add(1).ok_or(AdminJournalOperationError::InvalidInput)?,
                                "operation_id": operation_id,
                                "target_count": target_count,
                                "workflow_id": lower_hex(&workflow),
                            }),
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .map_err(map_journal_error)
    }
    async fn presence_refresh(
        &self,
        request: RhiAdminRequestDocument,
    ) -> Result<RhiAdminResponseDocument, RhiAdminHandlerError> {
        let model = request_model(&request)?;
        let expected = required_u64(&model, "/expected_generation")?;
        let operation_id = required_operation_id(&request)?.to_owned();
        let now_ms = self.now_millis()?;
        let route = request.route();
        RhiAdminOperationRepository::new(&self.state)
            .execute_database_admin_operation(
                &request,
                operation_time(now_ms)?,
                RhiAdminOperationJournalPolicy::seven_days(),
                move |transaction| {
                    Box::pin(async move {
                        let desired = sqlx::query(
                            r#"SELECT generation, enabled, target_count
                            FROM presence_desired_state WHERE singleton = 1 LIMIT 2"#,
                        )
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        if desired.len() != 1 {
                            return Err(AdminJournalOperationError::Binding);
                        }
                        let generation = operation_row_u64(&desired[0], "generation")?;
                        let enabled = operation_row_u64(&desired[0], "enabled")?;
                        let target_count = operation_row_u64(&desired[0], "target_count")?;
                        if generation != expected || enabled != 1 {
                            return Err(AdminJournalOperationError::Conflict);
                        }
                        let rows = sqlx::query(
                            r#"SELECT document_kind,
                                length(event_sha256) AS event_sha256_bytes,
                                substr(event_sha256, 1, 33) AS event_sha256,
                                state
                            FROM presence_outbox
                            WHERE desired_generation = ?
                            ORDER BY document_kind LIMIT 3"#,
                        )
                        .bind(
                            i64::try_from(expected)
                                .map_err(|_| AdminJournalOperationError::InvalidInput)?,
                        )
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        if rows.is_empty() || rows.len() > 2 {
                            return Err(AdminJournalOperationError::Conflict);
                        }
                        let mut digests = Map::new();
                        for row in &rows {
                            let kind = operation_presence_kind(row)?;
                            let digest = operation_exact_blob::<32>(
                                row,
                                "event_sha256",
                                "event_sha256_bytes",
                            )?;
                            if digests
                                .insert(kind.to_owned(), Value::String(lower_hex(&digest)))
                                .is_some()
                            {
                                return Err(AdminJournalOperationError::Binding);
                            }
                        }
                        let changed = sqlx::query(
                            r#"UPDATE presence_outbox
                            SET state = 'pending', revision = revision + 1,
                                next_attempt_unix_ms = ?, updated_at_unix_ms = ?
                            WHERE desired_generation = ? AND state = 'blocked'"#,
                        )
                        .bind(
                            i64::try_from(now_ms)
                                .map_err(|_| AdminJournalOperationError::InvalidInput)?,
                        )
                        .bind(
                            i64::try_from(now_ms)
                                .map_err(|_| AdminJournalOperationError::InvalidInput)?,
                        )
                        .bind(
                            i64::try_from(expected)
                                .map_err(|_| AdminJournalOperationError::InvalidInput)?,
                        )
                        .execute(&mut *transaction)
                        .await
                        .map_err(|_| AdminJournalOperationError::Storage)?;
                        if changed.rows_affected() == 0
                            || changed.rows_affected() as usize > rows.len()
                        {
                            return Err(AdminJournalOperationError::Conflict);
                        }
                        response(
                            route,
                            json!({
                                "document_digests": digests,
                                "generation": expected,
                                "operation_id": operation_id,
                                "state": "pending",
                                "target_count": target_count,
                            }),
                        )
                        .map_err(|_| AdminJournalOperationError::Binding)
                    })
                },
            )
            .await
            .map_err(map_journal_error)
    }

    async fn presence_state(
        &self,
        generation: u64,
    ) -> Result<(&'static str, Map<String, Value>), RhiAdminHandlerError> {
        self.state
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        r#"SELECT document_kind, state,
                            length(event_sha256) AS event_sha256_bytes,
                            substr(event_sha256, 1, 33) AS event_sha256
                        FROM presence_outbox
                        WHERE desired_generation = ?
                        ORDER BY document_kind LIMIT 3"#,
                    )
                    .bind(
                        i64::try_from(generation)
                            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                    )
                    .fetch_all(&mut *transaction)
                    .await
                    .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?;
                    if rows.len() > 2 {
                        return Err(failure(RhiAdminHandlerErrorKind::Internal));
                    }
                    let mut digests = Map::new();
                    let mut states = Vec::with_capacity(rows.len());
                    for row in &rows {
                        let kind = presence_kind(row)?;
                        let digest = exact_blob::<32>(row, "event_sha256", "event_sha256_bytes")?;
                        if digests
                            .insert(kind.to_owned(), Value::String(lower_hex(&digest)))
                            .is_some()
                        {
                            return Err(failure(RhiAdminHandlerErrorKind::Internal));
                        }
                        states.push(
                            row.try_get::<&str, _>("state")
                                .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))?,
                        );
                    }
                    let state = if rows.is_empty() {
                        "dirty"
                    } else if states.contains(&"leased") {
                        "submitted"
                    } else if states.contains(&"pending") {
                        "pending"
                    } else if states.contains(&"blocked") {
                        "failed"
                    } else if states.iter().all(|state| *state == "complete") {
                        "accepted"
                    } else if states.iter().all(|state| *state == "superseded") {
                        "dirty"
                    } else {
                        "unknown"
                    };
                    Ok::<(&'static str, Map<String, Value>), RhiAdminHandlerError>((state, digests))
                })
            })
            .await
            .map_err(|_| failure(RhiAdminHandlerErrorKind::Internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_are_bounded_authenticated_and_bound_to_route_filters_and_key() {
        let key = [0x11; 32];
        let query = [0x22; 32];
        let cursor = encode_runtime_cursor(
            &key,
            RhiAdminRoute::ReconciliationJobs,
            u64::MAX,
            u32::MAX,
            query,
        );
        assert_eq!(cursor.len(), 104);
        assert!(!cursor.contains('='));
        assert_eq!(
            decode_runtime_cursor(&key, RhiAdminRoute::ReconciliationJobs, &cursor, query)
                .expect("exact cursor"),
            (u64::MAX, u32::MAX)
        );

        for result in [
            decode_runtime_cursor(
                &[0x12; 32],
                RhiAdminRoute::ReconciliationJobs,
                &cursor,
                query,
            ),
            decode_runtime_cursor(&key, RhiAdminRoute::Sources, &cursor, query),
            decode_runtime_cursor(&key, RhiAdminRoute::ReconciliationJobs, &cursor, [0x23; 32]),
        ] {
            assert_eq!(
                result.expect_err("mismatched cursor binding").kind(),
                RhiAdminHandlerErrorKind::InvalidCursor
            );
        }

        let mut tampered = cursor.into_bytes();
        tampered[20] = if tampered[20] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII cursor");
        assert_eq!(
            decode_runtime_cursor(&key, RhiAdminRoute::ReconciliationJobs, &tampered, query,)
                .expect_err("tampered cursor")
                .kind(),
            RhiAdminHandlerErrorKind::InvalidCursor
        );
    }
}
