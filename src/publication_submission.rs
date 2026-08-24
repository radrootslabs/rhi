//! Exact committed publication bytes for later relay submission.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{ServiceSqliteTransaction, ServiceSqliteTransactionError};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;

use crate::RhiPublicationOutboxRepository;

/// Exact version of the committed publication submission contract.
pub const RHI_PUBLICATION_SUBMISSION_CONTRACT_VERSION: u32 = 1;

const SIGNED_EVENT_BYTES_MAXIMUM: usize = 32_768;

const READ_COMMITTED_PUBLICATION_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox.outbox_id) = 'blob' AND length(outbox.outbox_id) = 32
        THEN outbox.outbox_id ELSE NULL END AS outbox_id,
    CASE WHEN typeof(outbox.event_id) = 'blob' AND length(outbox.event_id) = 32
        THEN outbox.event_id ELSE NULL END AS outbox_event_id,
    CASE WHEN typeof(outbox.event_sha256) = 'blob' AND length(outbox.event_sha256) = 32
        THEN outbox.event_sha256 ELSE NULL END AS outbox_event_sha256,
    CASE WHEN typeof(event.event_id) = 'blob' AND length(event.event_id) = 32
        THEN event.event_id ELSE NULL END AS event_id,
    CASE WHEN typeof(event.event_sha256) = 'blob' AND length(event.event_sha256) = 32
        THEN event.event_sha256 ELSE NULL END AS event_sha256,
    CASE
        WHEN typeof(event.canonical_event_json) = 'blob'
            AND length(event.canonical_event_json) BETWEEN 1 AND 32768
        THEN event.canonical_event_json
        ELSE NULL
    END AS exact_signed_event_bytes
FROM publication_outbox AS outbox
LEFT JOIN signed_attestation_events AS event ON event.event_id = outbox.event_id
WHERE outbox.outbox_id = ?
LIMIT 2"#;

/// Stable source-free committed-publication read failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPublicationSubmissionErrorKind {
    NotFound,
    Binding,
    Storage,
}

impl RhiPublicationSubmissionErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "publication_submission_not_found",
            Self::Binding => "publication_submission_binding_invalid",
            Self::Storage => "publication_submission_storage_failed",
        }
    }
}

/// Redacted source-free committed-publication read failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPublicationSubmissionError {
    kind: RhiPublicationSubmissionErrorKind,
}

impl RhiPublicationSubmissionError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPublicationSubmissionErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPublicationSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPublicationSubmissionErrorKind::NotFound => {
                "RHI committed publication was not found"
            }
            RhiPublicationSubmissionErrorKind::Binding => {
                "RHI committed publication binding is invalid"
            }
            RhiPublicationSubmissionErrorKind::Storage => {
                "RHI committed publication could not be read"
            }
        })
    }
}

impl fmt::Debug for RhiPublicationSubmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationSubmissionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPublicationSubmissionError {}

/// Stable opaque identity of one immutable publication outbox.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPublicationOutboxId([u8; 32]);

impl RhiPublicationOutboxId {
    pub(crate) const fn from_committed_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiPublicationOutboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPublicationOutboxId([redacted])")
    }
}

/// Sealed exact event bytes read from one immutable committed outbox.
///
/// This value is durable evidence, not a relay claim or lease. Later
/// submission code may borrow [`Self::exact_signed_event_bytes`] but must not
/// parse, rebuild, reserialize, or re-sign it.
///
/// ```compile_fail
/// use rhi::{RhiCommittedPublication, RhiPublicationOutboxId};
///
/// let _forged = RhiCommittedPublication {
///     outbox_id: RhiPublicationOutboxId::from_committed_bytes([0; 32]),
///     event_id: [0; 32],
///     event_sha256: [0; 32],
///     exact_signed_event_bytes: Box::new([]),
/// };
/// ```
#[must_use = "committed publication bytes must be submitted exactly or deliberately discarded"]
pub struct RhiCommittedPublication {
    outbox_id: RhiPublicationOutboxId,
    event_id: [u8; 32],
    event_sha256: [u8; 32],
    exact_signed_event_bytes: Box<[u8]>,
}

impl RhiCommittedPublication {
    #[cfg(test)]
    pub(crate) fn test_fixture(
        outbox_id: RhiPublicationOutboxId,
        event_id: [u8; 32],
        event_sha256: [u8; 32],
        exact_signed_event_bytes: Box<[u8]>,
    ) -> Self {
        Self {
            outbox_id,
            event_id,
            event_sha256,
            exact_signed_event_bytes,
        }
    }

    /// Returns the immutable outbox identity.
    #[must_use]
    pub const fn outbox_id(&self) -> RhiPublicationOutboxId {
        self.outbox_id
    }

    /// Returns the independently verified Nostr event identifier.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Returns the SHA-256 digest of the exact stored signed-event bytes.
    #[must_use]
    pub const fn event_sha256(&self) -> &[u8; 32] {
        &self.event_sha256
    }

    /// Returns the exact committed signed-event bytes without transformation.
    #[must_use]
    pub const fn exact_signed_event_bytes(&self) -> &[u8] {
        &self.exact_signed_event_bytes
    }
}

impl fmt::Debug for RhiCommittedPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiCommittedPublication([redacted])")
    }
}

impl RhiPublicationOutboxRepository<'_> {
    /// Reads the exact committed signed bytes for one immutable outbox.
    ///
    /// The operation performs one bounded read-only SQLx transaction and no
    /// JSON/event decoding, signing, relay, network, filesystem, clock,
    /// entropy, or task operation. Repeated reads and reads after reopen
    /// return the same bytes or fail closed.
    pub async fn read_committed_publication(
        &self,
        outbox_id: RhiPublicationOutboxId,
    ) -> Result<RhiCommittedPublication, RhiPublicationSubmissionError> {
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { read_committed(transaction, outbox_id).await })
            })
            .await
            .map_err(map_transaction_error)
    }
}

pub(crate) async fn read_committed(
    transaction: &mut ServiceSqliteTransaction<'_>,
    requested_outbox_id: RhiPublicationOutboxId,
) -> Result<RhiCommittedPublication, ReadError> {
    let rows = sqlx::query(READ_COMMITTED_PUBLICATION_SQL)
        .bind(requested_outbox_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ReadError::Storage)?;
    let [row] = rows.as_slice() else {
        return if rows.is_empty() {
            Err(ReadError::NotFound)
        } else {
            Err(ReadError::Binding)
        };
    };
    let outbox_id = blob32(row, "outbox_id")?;
    let outbox_event_id = blob32(row, "outbox_event_id")?;
    let outbox_event_sha256 = blob32(row, "outbox_event_sha256")?;
    let event_id = blob32(row, "event_id")?;
    let event_sha256 = blob32(row, "event_sha256")?;
    let exact_signed_event_bytes = row
        .try_get::<Option<Vec<u8>>, _>("exact_signed_event_bytes")
        .map_err(|_| ReadError::Binding)?
        .ok_or(ReadError::Binding)?;
    if outbox_id != *requested_outbox_id.as_bytes()
        || outbox_event_id != event_id
        || outbox_event_sha256 != event_sha256
        || exact_signed_event_bytes.is_empty()
        || exact_signed_event_bytes.len() > SIGNED_EVENT_BYTES_MAXIMUM
        || <[u8; 32]>::from(Sha256::digest(&exact_signed_event_bytes)) != event_sha256
    {
        return Err(ReadError::Binding);
    }
    Ok(RhiCommittedPublication {
        outbox_id: RhiPublicationOutboxId::from_committed_bytes(outbox_id),
        event_id,
        event_sha256,
        exact_signed_event_bytes: exact_signed_event_bytes.into_boxed_slice(),
    })
}

fn blob32(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<[u8; 32], ReadError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| ReadError::Binding)?
        .ok_or(ReadError::Binding)?
        .try_into()
        .map_err(|_| ReadError::Binding)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    NotFound,
    Binding,
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<ReadError>,
) -> RhiPublicationSubmissionError {
    failure(match error.operation_error().copied() {
        Some(ReadError::NotFound) => RhiPublicationSubmissionErrorKind::NotFound,
        Some(ReadError::Binding) => RhiPublicationSubmissionErrorKind::Binding,
        Some(ReadError::Storage) | None => RhiPublicationSubmissionErrorKind::Storage,
    })
}

const fn failure(kind: RhiPublicationSubmissionErrorKind) -> RhiPublicationSubmissionError {
    RhiPublicationSubmissionError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_and_capabilities_are_redacted() {
        for kind in [
            RhiPublicationSubmissionErrorKind::NotFound,
            RhiPublicationSubmissionErrorKind::Binding,
            RhiPublicationSubmissionErrorKind::Storage,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.code().starts_with("publication_submission_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("relay-primary"));
            assert!(!rendered.contains("SELECT"));
        }
        let id = RhiPublicationOutboxId::from_committed_bytes([0x51; 32]);
        assert_eq!(format!("{id:?}"), "RhiPublicationOutboxId([redacted])");
    }
}
