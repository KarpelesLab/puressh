//! `internal`: USB / NFC authenticators through libfido2.

use super::SkError;

/// libfido2.
pub(super) struct Fido2Provider;

impl Fido2Provider {
    pub(super) fn open() -> Result<super::external::ExternalProvider, SkError> {
        Err(SkError::Provider(
            "internal security key support not enabled".into(),
        ))
    }
}
