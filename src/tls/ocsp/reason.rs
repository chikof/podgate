//! Why a certificate gets no staple, one variant per `podgate_ocsp_rejected_total{reason}`.

use std::fmt;

/// Why a staple was not made or not kept. Fetch failures, setup problems and every verification
/// step share one list so the counter is one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// The chain has no issuer certificate that issued the leaf.
    NoIssuer,
    /// A must-staple certificate names no OCSP responder.
    NoResponder,
    /// No app claims a host of the certificate, so no address policy can be chosen.
    Unowned,
    /// The responder URL is not `http` or `https`, or is otherwise unusable.
    Scheme,
    /// `OCSP_ALLOWED_HOSTS` does not list the responder host.
    HostNotAllowed,
    /// The responder host could not be turned into an address.
    Unresolved,
    /// The upstream address policy refuses the responder's address.
    Policy,
    /// The connection or the exchange failed.
    Connect,
    /// The exchange ran past the timeout.
    Timeout,
    /// The responder answered something other than a plain `200`-class response (a redirect
    /// included).
    HttpStatus,
    /// The response is over the size cap.
    Oversized,
    /// The response is not `application/ocsp-response`.
    ContentType,
    /// The HTTP response is malformed.
    HttpMalformed,
    /// The body is not a well-formed OCSP response.
    Malformed,
    /// The response status is not `successful`.
    NotSuccessful,
    /// The response is not a `BasicOCSPResponse`.
    NotBasic,
    /// The response does not hold exactly one single response.
    ResponseCount,
    /// The response is for another serial number.
    WrongSerial,
    /// The response is for another issuer, or uses a hash this proxy does not know.
    WrongIssuer,
    /// The certificate is revoked.
    Revoked,
    /// The responder does not know the certificate.
    UnknownStatus,
    /// `thisUpdate` is in the future.
    NotYetValid,
    /// `nextUpdate` has passed.
    Expired,
    /// The response has no `nextUpdate`.
    NoNextUpdate,
    /// The signature does not verify.
    BadSignature,
    /// The signer is neither the issuer nor a delegated responder the issuer authorized.
    ResponderNotAuthorized,
    /// The signature algorithm is not one the crypto provider verifies.
    UnsupportedAlgorithm,
}

impl Reason {
    /// Every reason, in the order the metrics list them.
    pub const ALL: [Self; 27] = [
        Self::NoIssuer,
        Self::NoResponder,
        Self::Unowned,
        Self::Scheme,
        Self::HostNotAllowed,
        Self::Unresolved,
        Self::Policy,
        Self::Connect,
        Self::Timeout,
        Self::HttpStatus,
        Self::Oversized,
        Self::ContentType,
        Self::HttpMalformed,
        Self::Malformed,
        Self::NotSuccessful,
        Self::NotBasic,
        Self::ResponseCount,
        Self::WrongSerial,
        Self::WrongIssuer,
        Self::Revoked,
        Self::UnknownStatus,
        Self::NotYetValid,
        Self::Expired,
        Self::NoNextUpdate,
        Self::BadSignature,
        Self::ResponderNotAuthorized,
        Self::UnsupportedAlgorithm,
    ];

    /// The label value of `podgate_ocsp_rejected_total`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoIssuer => "no_issuer",
            Self::NoResponder => "no_responder",
            Self::Unowned => "unowned",
            Self::Scheme => "scheme",
            Self::HostNotAllowed => "host_not_allowed",
            Self::Unresolved => "unresolved",
            Self::Policy => "policy",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::HttpStatus => "http_status",
            Self::Oversized => "oversized",
            Self::ContentType => "content_type",
            Self::HttpMalformed => "http_malformed",
            Self::Malformed => "malformed",
            Self::NotSuccessful => "not_successful",
            Self::NotBasic => "not_basic",
            Self::ResponseCount => "response_count",
            Self::WrongSerial => "wrong_serial",
            Self::WrongIssuer => "wrong_issuer",
            Self::Revoked => "revoked",
            Self::UnknownStatus => "unknown_status",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::NoNextUpdate => "no_next_update",
            Self::BadSignature => "bad_signature",
            Self::ResponderNotAuthorized => "responder_not_authorized",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
        }
    }

    pub(super) fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|known| *known == self)
            .unwrap_or_default()
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
