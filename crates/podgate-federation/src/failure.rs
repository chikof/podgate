//! Why a pull failed, as a closed set. Never peer text: a hostile peer cannot put words in the
//! operator's view through an error.

use serde::Serialize;

/// The class of a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// No connection, or it broke.
    Connect,
    /// The TLS handshake failed: a certificate the pinned CA does not vouch for, a name that does
    /// not match, or the peer refused the hub's certificate.
    Tls,
    /// The pull did not finish within its deadline.
    Timeout,
    /// An answer that is not `200`, a redirect included.
    Status,
    /// More bytes or more entries than the caps allow.
    TooLarge,
    /// Not the documented shape, not in order, or no progress.
    Malformed,
    /// A `format_version` this hub does not read.
    UnsupportedFormat,
    /// The catalog changed under the pull twice.
    Unstable,
}

impl ErrorClass {
    /// The class as it is logged and shown.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Timeout => "timeout",
            Self::Status => "status",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::UnsupportedFormat => "unsupported_format",
            Self::Unstable => "unstable",
        }
    }
}

/// A failed pull: its class, the status number when there was one, and the format the peer
/// named when it was readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The class.
    pub class: ErrorClass,
    /// The HTTP status, for [`ErrorClass::Status`].
    pub http_status: Option<u16>,
    /// The `format_version` the peer sent, for [`ErrorClass::UnsupportedFormat`].
    pub peer_format: Option<u32>,
}

impl Failure {
    /// A failure of `class`.
    #[must_use]
    pub fn new(class: ErrorClass) -> Self {
        Self {
            class,
            http_status: None,
            peer_format: None,
        }
    }

    /// A [`ErrorClass::Status`] failure.
    #[must_use]
    pub fn status(code: u16) -> Self {
        Self {
            http_status: Some(code),
            ..Self::new(ErrorClass::Status)
        }
    }
}

impl From<crate::wire::ParseError> for Failure {
    fn from(error: crate::wire::ParseError) -> Self {
        match error {
            crate::wire::ParseError::UnsupportedFormat(version) => Self {
                peer_format: Some(version),
                ..Self::new(ErrorClass::UnsupportedFormat)
            },
            _ => Self::new(ErrorClass::Malformed),
        }
    }
}
