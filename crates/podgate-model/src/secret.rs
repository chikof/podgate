//! The skew-protection signing key.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The HMAC key for session cookies: the snapshot's `skew_secret`. Never printed: `Debug` hides it.
///
/// Any string deserializes; the daemon's snapshot compiler refuses one shorter than
/// [`Self::MIN_LEN`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkewSecret(String);

impl fmt::Debug for SkewSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SkewSecret([redacted])")
    }
}

impl SkewSecret {
    /// Shortest secret the compiler accepts, in bytes.
    pub const MIN_LEN: usize = 16;

    /// Wraps `secret`; length is checked when the snapshot is compiled.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Whether the secret is long enough to key the cookie HMAC.
    #[must_use]
    pub fn is_long_enough(&self) -> bool {
        self.0.len() >= Self::MIN_LEN
    }

    /// The key bytes, for the HMAC.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
