//! Fixed, zeroizing bootstrap documents consumed only from standard input.

use std::io::Read;

use zeroize::Zeroizing;

use crate::RhiEncryptedIdentityProvisioningMaterial;

pub(crate) const RHI_IDENTITY_PROVISIONING_DOCUMENT_BYTES: usize = 117;
const RHI_IDENTITY_PROVISIONING_MAGIC: &[u8; 4] = b"RHIP";
const RHI_IDENTITY_PROVISIONING_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RhiBootstrapDocumentError {
    Io,
    InvalidLength,
    InvalidHeader,
    InvalidMaterial,
}

pub(crate) fn read_identity_provisioning_document(
    mut reader: impl Read,
) -> Result<RhiEncryptedIdentityProvisioningMaterial, RhiBootstrapDocumentError> {
    let mut document = Zeroizing::new([0_u8; RHI_IDENTITY_PROVISIONING_DOCUMENT_BYTES + 1]);
    let mut length = 0_usize;
    while length < document.len() {
        match reader.read(&mut document[length..]) {
            Ok(0) => break,
            Ok(read) => length = length.saturating_add(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RhiBootstrapDocumentError::Io),
        }
    }
    if length != RHI_IDENTITY_PROVISIONING_DOCUMENT_BYTES {
        return Err(RhiBootstrapDocumentError::InvalidLength);
    }
    if &document[..4] != RHI_IDENTITY_PROVISIONING_MAGIC
        || document[4] != RHI_IDENTITY_PROVISIONING_VERSION
    {
        return Err(RhiBootstrapDocumentError::InvalidHeader);
    }
    let mut identity_secret = [0_u8; 32];
    let mut data_key = [0_u8; 32];
    let mut envelope_nonce = [0_u8; 24];
    let mut wrapping_nonce = [0_u8; 24];
    identity_secret.copy_from_slice(&document[5..37]);
    data_key.copy_from_slice(&document[37..69]);
    envelope_nonce.copy_from_slice(&document[69..93]);
    wrapping_nonce.copy_from_slice(&document[93..117]);
    RhiEncryptedIdentityProvisioningMaterial::new(
        identity_secret,
        data_key,
        envelope_nonce,
        wrapping_nonce,
    )
    .map_err(|_| RhiBootstrapDocumentError::InvalidMaterial)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn document() -> [u8; RHI_IDENTITY_PROVISIONING_DOCUMENT_BYTES] {
        let mut document = [0_u8; RHI_IDENTITY_PROVISIONING_DOCUMENT_BYTES];
        document[..4].copy_from_slice(RHI_IDENTITY_PROVISIONING_MAGIC);
        document[4] = RHI_IDENTITY_PROVISIONING_VERSION;
        document[5..37].copy_from_slice(&[1; 32]);
        document[37..69].copy_from_slice(&[2; 32]);
        document[69..93].copy_from_slice(&[3; 24]);
        document[93..117].copy_from_slice(&[4; 24]);
        document
    }

    #[test]
    fn exact_document_is_admitted_and_bounds_are_fail_closed() {
        let valid = document();
        let material = read_identity_provisioning_document(Cursor::new(valid))
            .expect("exact provisioning document");
        assert_eq!(
            format!("{material:?}"),
            "RhiEncryptedIdentityProvisioningMaterial([redacted])"
        );
        assert_eq!(
            read_identity_provisioning_document(Cursor::new(&valid[..116])).unwrap_err(),
            RhiBootstrapDocumentError::InvalidLength
        );
        let mut trailing = valid.to_vec();
        trailing.push(0);
        assert_eq!(
            read_identity_provisioning_document(Cursor::new(trailing)).unwrap_err(),
            RhiBootstrapDocumentError::InvalidLength
        );
    }
}
