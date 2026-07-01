#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::OnceCell;

const RHI_PROCESSED_JOB_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiProcessedJobStatus {
    Processing,
    ReceiptPublished,
    Completed,
    Failed,
}

impl RhiProcessedJobStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::ReceiptPublished => "receipt_published",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self, RhiProcessedJobStoreError> {
        match value {
            "processing" => Ok(Self::Processing),
            "receipt_published" => Ok(Self::ReceiptPublished),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(RhiProcessedJobStoreError::InvalidStatus(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RhiProcessedJobState {
    pub request_id: String,
    pub request_kind: u32,
    pub request_hash: String,
    pub customer_pubkey: String,
    pub status: RhiProcessedJobStatus,
    #[serde(default)]
    pub receipt_event_id: Option<String>,
    #[serde(default)]
    pub result_event_id: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    pub created_timestamp: u32,
    #[serde(default)]
    pub completed_timestamp: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RhiProcessedJobClaim {
    Execute,
    InProgress,
    RecoverResult { receipt_event_id: String },
    Completed,
}

#[derive(Clone, Debug)]
pub struct RhiProcessedJobStore {
    pool: SqlitePool,
    file_backed: bool,
    schema_ready: Arc<OnceCell<()>>,
}

#[derive(Debug, Error)]
pub enum RhiProcessedJobStoreError {
    #[error("invalid rhi processed-job store path: {0}")]
    InvalidPath(PathBuf),
    #[error("unsupported rhi processed-job store schema version: {0}")]
    UnsupportedSchemaVersion(i64),
    #[error("rhi processed-job store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rhi processed-job sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("duplicate conflicting processed job")]
    DuplicateConflictingJob,
    #[error("duplicate conflicting receipt")]
    DuplicateConflictingReceipt,
    #[error("missing processed-job claim: {0}")]
    MissingProcessedJobClaim(String),
    #[error("invalid rhi processed-job status: {0}")]
    InvalidStatus(String),
    #[error("invalid rhi processed-job stored value: {0}")]
    InvalidStoredValue(&'static str),
}

impl RhiProcessedJobStore {
    pub fn open_memory() -> Result<Self, RhiProcessedJobStoreError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?;
        Ok(Self::from_options(options, false, 1))
    }

    pub async fn open_file(path: impl AsRef<Path>) -> Result<Self, RhiProcessedJobStoreError> {
        let path = path.as_ref();
        if path.file_name().is_none() {
            return Err(RhiProcessedJobStoreError::InvalidPath(path.to_path_buf()));
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let store = Self::from_options(options, true, 5);
        store.ensure_schema().await?;
        Ok(store)
    }

    pub async fn claim_job(
        &self,
        job: &RhiProcessedJobState,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<RhiProcessedJobClaim, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        let claim_expires_at_ms = now_ms.saturating_add(lease_ms.max(1));
        let mut tx = self.pool.begin().await?;
        let inserted = insert_claimed_job(&mut tx, job, now_ms, claim_expires_at_ms).await?;
        if inserted {
            tx.commit().await?;
            return Ok(RhiProcessedJobClaim::Execute);
        }

        let Some(existing) = select_job(&mut tx, job.request_id.as_str()).await? else {
            return Err(RhiProcessedJobStoreError::MissingProcessedJobClaim(
                job.request_id.clone(),
            ));
        };
        ensure_processed_job_matches(&existing, job)?;
        let claim = claim_for_existing_job(&mut tx, existing, now_ms, claim_expires_at_ms).await?;
        tx.commit().await?;
        Ok(claim)
    }

    pub async fn mark_receipt_published(
        &self,
        job: &RhiProcessedJobState,
        receipt_event_id: &str,
        now_ms: i64,
    ) -> Result<RhiProcessedJobState, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        let mut tx = self.pool.begin().await?;
        let Some(mut existing) = select_job(&mut tx, job.request_id.as_str()).await? else {
            return Err(RhiProcessedJobStoreError::MissingProcessedJobClaim(
                job.request_id.clone(),
            ));
        };
        ensure_processed_job_matches(&existing, job)?;
        ensure_receipt_matches(&existing, receipt_event_id)?;
        existing.status = RhiProcessedJobStatus::ReceiptPublished;
        existing.receipt_event_id = Some(receipt_event_id.to_owned());
        update_job(&mut tx, &existing, now_ms, None).await?;
        tx.commit().await?;
        Ok(existing)
    }

    pub async fn mark_completed(
        &self,
        job: &RhiProcessedJobState,
        receipt_event_id: &str,
        result_event_id: &str,
        completed_timestamp: u32,
        now_ms: i64,
    ) -> Result<RhiProcessedJobState, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        let mut tx = self.pool.begin().await?;
        let Some(mut existing) = select_job(&mut tx, job.request_id.as_str()).await? else {
            return Err(RhiProcessedJobStoreError::MissingProcessedJobClaim(
                job.request_id.clone(),
            ));
        };
        ensure_processed_job_matches(&existing, job)?;
        ensure_receipt_matches(&existing, receipt_event_id)?;
        existing.status = RhiProcessedJobStatus::Completed;
        existing.receipt_event_id = Some(receipt_event_id.to_owned());
        existing.result_event_id = Some(result_event_id.to_owned());
        existing.completed_timestamp = Some(completed_timestamp);
        update_job(&mut tx, &existing, now_ms, None).await?;
        tx.commit().await?;
        Ok(existing)
    }

    pub async fn get_job(
        &self,
        request_id: &str,
    ) -> Result<Option<RhiProcessedJobState>, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        let mut tx = self.pool.begin().await?;
        let job = select_job(&mut tx, request_id).await?;
        tx.commit().await?;
        Ok(job)
    }

    pub async fn pragma_busy_timeout(&self) -> Result<i64, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        query_i64(&self.pool, "PRAGMA busy_timeout").await
    }

    pub async fn pragma_journal_mode(&self) -> Result<String, RhiProcessedJobStoreError> {
        self.ensure_schema().await?;
        query_string(&self.pool, "PRAGMA journal_mode").await
    }

    fn from_options(
        options: SqliteConnectOptions,
        file_backed: bool,
        max_connections: u32,
    ) -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_lazy_with(options);
        Self {
            pool,
            file_backed,
            schema_ready: Arc::new(OnceCell::new()),
        }
    }

    async fn ensure_schema(&self) -> Result<(), RhiProcessedJobStoreError> {
        self.schema_ready
            .get_or_try_init(|| async {
                configure_connection(&self.pool, self.file_backed).await?;
                apply_schema(&self.pool).await
            })
            .await?;
        Ok(())
    }
}

async fn configure_connection(
    pool: &SqlitePool,
    file_backed: bool,
) -> Result<(), RhiProcessedJobStoreError> {
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(pool)
        .await?;
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(pool)
        .await?;
    if file_backed {
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn apply_schema(pool: &SqlitePool) -> Result<(), RhiProcessedJobStoreError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS rhi_processed_job_schema(
            schema_id INTEGER PRIMARY KEY CHECK(schema_id = 1),
            version INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    let existing_version: Option<i64> =
        sqlx::query("SELECT version FROM rhi_processed_job_schema WHERE schema_id = 1")
            .fetch_optional(pool)
            .await?
            .map(|row| row.try_get("version"))
            .transpose()?;
    match existing_version {
        Some(version) if version == RHI_PROCESSED_JOB_SCHEMA_VERSION => {}
        Some(version) => return Err(RhiProcessedJobStoreError::UnsupportedSchemaVersion(version)),
        None => {
            sqlx::query("INSERT INTO rhi_processed_job_schema(schema_id, version) VALUES (1, ?)")
                .bind(RHI_PROCESSED_JOB_SCHEMA_VERSION)
                .execute(pool)
                .await?;
        }
    }
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS rhi_processed_jobs(
            request_id TEXT PRIMARY KEY,
            request_kind INTEGER NOT NULL,
            request_hash TEXT NOT NULL,
            customer_pubkey TEXT NOT NULL,
            status TEXT NOT NULL,
            receipt_event_id TEXT,
            result_event_id TEXT,
            error_code TEXT,
            created_timestamp INTEGER NOT NULL,
            completed_timestamp INTEGER,
            claim_expires_at_ms INTEGER,
            inserted_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS rhi_processed_jobs_status_idx
            ON rhi_processed_jobs(status)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS rhi_processed_jobs_receipt_event_idx
            ON rhi_processed_jobs(receipt_event_id)
            WHERE receipt_event_id IS NOT NULL",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS rhi_processed_jobs_result_event_idx
            ON rhi_processed_jobs(result_event_id)
            WHERE result_event_id IS NOT NULL",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_claimed_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job: &RhiProcessedJobState,
    now_ms: i64,
    claim_expires_at_ms: i64,
) -> Result<bool, RhiProcessedJobStoreError> {
    let changed = sqlx::query(
        "INSERT INTO rhi_processed_jobs(
            request_id,
            request_kind,
            request_hash,
            customer_pubkey,
            status,
            receipt_event_id,
            result_event_id,
            error_code,
            created_timestamp,
            completed_timestamp,
            claim_expires_at_ms,
            inserted_at_ms,
            updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(request_id) DO NOTHING",
    )
    .bind(job.request_id.as_str())
    .bind(i64::from(job.request_kind))
    .bind(job.request_hash.as_str())
    .bind(job.customer_pubkey.as_str())
    .bind(RhiProcessedJobStatus::Processing.as_str())
    .bind(job.receipt_event_id.as_deref())
    .bind(job.result_event_id.as_deref())
    .bind(job.error_code.as_deref())
    .bind(i64::from(job.created_timestamp))
    .bind(job.completed_timestamp.map(i64::from))
    .bind(claim_expires_at_ms)
    .bind(now_ms)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(changed == 1)
}

async fn select_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: &str,
) -> Result<Option<RhiProcessedJobState>, RhiProcessedJobStoreError> {
    sqlx::query(
        "SELECT
            request_id,
            request_kind,
            request_hash,
            customer_pubkey,
            status,
            receipt_event_id,
            result_event_id,
            error_code,
            created_timestamp,
            completed_timestamp
        FROM rhi_processed_jobs
        WHERE request_id = ?",
    )
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(job_from_row)
    .transpose()
}

async fn claim_for_existing_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    existing: RhiProcessedJobState,
    now_ms: i64,
    claim_expires_at_ms: i64,
) -> Result<RhiProcessedJobClaim, RhiProcessedJobStoreError> {
    if existing.status == RhiProcessedJobStatus::Completed && existing.result_event_id.is_some() {
        return Ok(RhiProcessedJobClaim::Completed);
    }
    if let Some(receipt_event_id) = existing.receipt_event_id.clone() {
        return Ok(RhiProcessedJobClaim::RecoverResult { receipt_event_id });
    }

    let current_claim_expires_at_ms: Option<i64> =
        sqlx::query("SELECT claim_expires_at_ms FROM rhi_processed_jobs WHERE request_id = ?")
            .bind(existing.request_id.as_str())
            .fetch_one(&mut **tx)
            .await?
            .try_get("claim_expires_at_ms")?;
    if existing.status == RhiProcessedJobStatus::Processing
        && current_claim_expires_at_ms.is_some_and(|expires_at_ms| expires_at_ms > now_ms)
    {
        return Ok(RhiProcessedJobClaim::InProgress);
    }

    let changed = sqlx::query(
        "UPDATE rhi_processed_jobs
            SET status = ?,
                claim_expires_at_ms = ?,
                updated_at_ms = ?
            WHERE request_id = ?
              AND (
                status != ?
                OR claim_expires_at_ms IS NULL
                OR claim_expires_at_ms <= ?
              )",
    )
    .bind(RhiProcessedJobStatus::Processing.as_str())
    .bind(claim_expires_at_ms)
    .bind(now_ms)
    .bind(existing.request_id.as_str())
    .bind(RhiProcessedJobStatus::Processing.as_str())
    .bind(now_ms)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed == 1 {
        Ok(RhiProcessedJobClaim::Execute)
    } else {
        Ok(RhiProcessedJobClaim::InProgress)
    }
}

async fn update_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job: &RhiProcessedJobState,
    now_ms: i64,
    claim_expires_at_ms: Option<i64>,
) -> Result<(), RhiProcessedJobStoreError> {
    sqlx::query(
        "UPDATE rhi_processed_jobs
            SET request_kind = ?,
                request_hash = ?,
                customer_pubkey = ?,
                status = ?,
                receipt_event_id = ?,
                result_event_id = ?,
                error_code = ?,
                created_timestamp = ?,
                completed_timestamp = ?,
                claim_expires_at_ms = ?,
                updated_at_ms = ?
            WHERE request_id = ?",
    )
    .bind(i64::from(job.request_kind))
    .bind(job.request_hash.as_str())
    .bind(job.customer_pubkey.as_str())
    .bind(job.status.as_str())
    .bind(job.receipt_event_id.as_deref())
    .bind(job.result_event_id.as_deref())
    .bind(job.error_code.as_deref())
    .bind(i64::from(job.created_timestamp))
    .bind(job.completed_timestamp.map(i64::from))
    .bind(claim_expires_at_ms)
    .bind(now_ms)
    .bind(job.request_id.as_str())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn ensure_processed_job_matches(
    existing: &RhiProcessedJobState,
    incoming: &RhiProcessedJobState,
) -> Result<(), RhiProcessedJobStoreError> {
    if existing.request_kind != incoming.request_kind
        || existing.request_hash != incoming.request_hash
        || existing.customer_pubkey != incoming.customer_pubkey
    {
        return Err(RhiProcessedJobStoreError::DuplicateConflictingJob);
    }
    Ok(())
}

fn ensure_receipt_matches(
    existing: &RhiProcessedJobState,
    receipt_event_id: &str,
) -> Result<(), RhiProcessedJobStoreError> {
    if existing
        .receipt_event_id
        .as_ref()
        .is_some_and(|existing| existing != receipt_event_id)
    {
        return Err(RhiProcessedJobStoreError::DuplicateConflictingReceipt);
    }
    Ok(())
}

fn job_from_row(row: SqliteRow) -> Result<RhiProcessedJobState, RhiProcessedJobStoreError> {
    Ok(RhiProcessedJobState {
        request_id: row.try_get("request_id")?,
        request_kind: u32_from_i64(row.try_get("request_kind")?, "request_kind")?,
        request_hash: row.try_get("request_hash")?,
        customer_pubkey: row.try_get("customer_pubkey")?,
        status: RhiProcessedJobStatus::parse(row.try_get::<String, _>("status")?.as_str())?,
        receipt_event_id: row.try_get("receipt_event_id")?,
        result_event_id: row.try_get("result_event_id")?,
        error_code: row.try_get("error_code")?,
        created_timestamp: u32_from_i64(row.try_get("created_timestamp")?, "created_timestamp")?,
        completed_timestamp: row
            .try_get::<Option<i64>, _>("completed_timestamp")?
            .map(|value| u32_from_i64(value, "completed_timestamp"))
            .transpose()?,
    })
}

fn u32_from_i64(value: i64, field: &'static str) -> Result<u32, RhiProcessedJobStoreError> {
    u32::try_from(value).map_err(|_| RhiProcessedJobStoreError::InvalidStoredValue(field))
}

async fn query_i64(pool: &SqlitePool, sql: &str) -> Result<i64, RhiProcessedJobStoreError> {
    let row = sqlx::query(sql).fetch_one(pool).await?;
    Ok(row.try_get(0)?)
}

async fn query_string(pool: &SqlitePool, sql: &str) -> Result<String, RhiProcessedJobStoreError> {
    let row = sqlx::query(sql).fetch_one(pool).await?;
    Ok(row.try_get(0)?)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RhiProcessedJobClaim, RhiProcessedJobState, RhiProcessedJobStatus, RhiProcessedJobStore,
        RhiProcessedJobStoreError,
    };

    fn job(request_id: &str) -> RhiProcessedJobState {
        RhiProcessedJobState {
            request_id: request_id.to_owned(),
            request_kind: 5322,
            request_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            customer_pubkey: "customer".to_owned(),
            status: RhiProcessedJobStatus::Processing,
            receipt_event_id: None,
            result_event_id: None,
            error_code: None,
            created_timestamp: 1_700_000_000,
            completed_timestamp: None,
        }
    }

    #[tokio::test]
    async fn processed_job_store_claims_updates_and_reopens_completed_jobs() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let path = tempdir.path().join("processed_jobs.sqlite");
        let store = RhiProcessedJobStore::open_file(path.as_path())
            .await
            .expect("store");
        assert_eq!(store.pragma_busy_timeout().await.expect("timeout"), 5000);
        assert_eq!(
            store.pragma_journal_mode().await.expect("journal"),
            "wal".to_owned()
        );
        let job = job("request-1");

        assert_eq!(
            store.claim_job(&job, 1_000, 10_000).await.expect("claim"),
            RhiProcessedJobClaim::Execute
        );
        let published = store
            .mark_receipt_published(&job, "receipt-1", 1_100)
            .await
            .expect("receipt");
        assert_eq!(published.status, RhiProcessedJobStatus::ReceiptPublished);
        let completed = store
            .mark_completed(&job, "receipt-1", "result-1", 1_700_000_001, 1_200)
            .await
            .expect("complete");
        assert_eq!(completed.status, RhiProcessedJobStatus::Completed);

        let reopened = RhiProcessedJobStore::open_file(path.as_path())
            .await
            .expect("reopen");
        let stored = reopened
            .get_job("request-1")
            .await
            .expect("stored")
            .expect("job");
        assert_eq!(stored.status, RhiProcessedJobStatus::Completed);
        assert_eq!(stored.receipt_event_id.as_deref(), Some("receipt-1"));
        assert_eq!(stored.result_event_id.as_deref(), Some("result-1"));
    }

    #[tokio::test]
    async fn processed_job_store_prevents_unexpired_duplicate_claims_and_reclaims_expired_claims() {
        let store = RhiProcessedJobStore::open_memory().expect("store");
        let job = job("request-2");

        assert_eq!(
            store.claim_job(&job, 10, 100).await.expect("first claim"),
            RhiProcessedJobClaim::Execute
        );
        assert_eq!(
            store
                .claim_job(&job, 20, 100)
                .await
                .expect("duplicate claim"),
            RhiProcessedJobClaim::InProgress
        );
        assert_eq!(
            store
                .claim_job(&job, 111, 100)
                .await
                .expect("expired claim"),
            RhiProcessedJobClaim::Execute
        );
    }

    #[tokio::test]
    async fn processed_job_store_rejects_conflicting_duplicate_jobs() {
        let store = RhiProcessedJobStore::open_memory().expect("store");
        let job = job("request-3");
        store.claim_job(&job, 10, 100).await.expect("claim");
        let mut conflicting = job.clone();
        conflicting.request_hash =
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();

        let error = store
            .claim_job(&conflicting, 111, 100)
            .await
            .expect_err("conflicting job");
        assert!(matches!(
            error,
            RhiProcessedJobStoreError::DuplicateConflictingJob
        ));
    }

    #[tokio::test]
    async fn processed_job_store_rejects_conflicting_receipt_updates() {
        let store = RhiProcessedJobStore::open_memory().expect("store");
        let job = job("request-4");
        store.claim_job(&job, 10, 100).await.expect("claim");
        store
            .mark_receipt_published(&job, "receipt-1", 20)
            .await
            .expect("receipt");

        let error = store
            .mark_receipt_published(&job, "receipt-2", 30)
            .await
            .expect_err("conflicting receipt");
        assert!(matches!(
            error,
            RhiProcessedJobStoreError::DuplicateConflictingReceipt
        ));
    }
}
