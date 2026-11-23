//! What a limit that counts in the shared store counts by: the source of a request, as `quota`
//! and `ai_token_limit` both write it.
//!
//! A source is `ip`, `header` or `host` (exactly as for `rate_limit`) or a `jwt_claim`: a claim a
//! `jwt_auth` earlier in the chain copies into a header with `forward_claims`. The client's own
//! copy of that header never counts: `jwt_auth` removes it before it verifies. A request with no
//! value counts under one shared source, which limits more, never less.

use http::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::compile::Invalid;
use crate::middleware::RequestCx;
use crate::middleware::limits::{IpSource, Source, SourceConfig};
use crate::ratelimit_store::quota::SourceId;

/// What an absent header counts as: a client cannot leave a limit by omitting the value.
const ABSENT: &[u8] = b"-";

/// A `source` as written in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(in crate::middleware) enum QuotaSource {
    /// The client address under an `ipStrategy`.
    Ip(IpSource),
    /// The first value of a request header.
    Header(String),
    /// The host of the request; only `true` is valid.
    Host(bool),
    /// A verified claim of a token, copied into a header by a `jwt_auth` earlier in the chain.
    JwtClaim(String),
}

impl QuotaSource {
    /// The source as `rate_limit` writes it, or `None` for a claim.
    fn common(&self) -> Option<SourceConfig> {
        match self {
            Self::Ip(ip) => Some(SourceConfig::Ip(ip.clone())),
            Self::Header(name) => Some(SourceConfig::Header(name.clone())),
            Self::Host(on) => Some(SourceConfig::Host(*on)),
            Self::JwtClaim(_) => None,
        }
    }

    fn describe(&self) -> Value {
        match self {
            Self::JwtClaim(claim) => json!({ "jwt_claim": claim }),
            other => other
                .common()
                .map_or(Value::Null, |common| common.describe()),
        }
    }
}

/// How a compiled limit finds the source of a request.
#[derive(Debug)]
enum Keyed {
    Common(Source),
    /// A claim and the header a `jwt_auth` copies it into, known once the chain is.
    Claim {
        claim: Box<str>,
        header: Option<HeaderName>,
    },
}

/// A source and how to read it from a request.
#[derive(Debug)]
pub(in crate::middleware) struct Keying {
    config: QuotaSource,
    keyed: Keyed,
}

impl Keying {
    /// Compiles `source`. `who` names the middleware kind in an error.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` when the source is malformed.
    pub(in crate::middleware) fn compile(source: QuotaSource, who: &str) -> Result<Self, Invalid> {
        let invalid = |message: &dyn std::fmt::Display| {
            Invalid::new("invalid_middleware", format!("{who}: {message}"))
        };
        let keyed = match (source.common(), &source) {
            (Some(common), _) => Keyed::Common(Source::compile(&common).map_err(|e| invalid(&e))?),
            (None, QuotaSource::JwtClaim(claim)) if !claim.is_empty() => Keyed::Claim {
                claim: claim.as_str().into(),
                header: None,
            },
            (None, _) => return Err(invalid(&"`source.jwt_claim` must name a claim")),
        };
        Ok(Self {
            config: source,
            keyed,
        })
    }

    /// The claim this limit counts by, when its source is one.
    pub(in crate::middleware) fn claim(&self) -> Option<&str> {
        match &self.keyed {
            Keyed::Claim { claim, .. } => Some(&**claim),
            Keyed::Common(_) => None,
        }
    }

    /// Gives a claim source the header its claim is copied into.
    pub(in crate::middleware) fn bind(&mut self, found: HeaderName) {
        if let Keyed::Claim { header, .. } = &mut self.keyed {
            *header = Some(found);
        }
    }

    /// The id of the source of the request in `cx`.
    pub(in crate::middleware) fn id(&self, cx: &RequestCx<'_>) -> SourceId {
        let request = cx.session.req_header();
        match &self.keyed {
            Keyed::Common(source) => source.with_material(request, cx.forwarded, SourceId::of),
            Keyed::Claim { header, .. } => SourceId::of(
                header
                    .as_ref()
                    .and_then(|name| request.headers.get(name))
                    .map_or(ABSENT, HeaderValue::as_bytes),
            ),
        }
    }

    /// The source as explain and the counter's fingerprint write it.
    pub(in crate::middleware) fn describe(&self) -> Value {
        self.config.describe()
    }

    /// Whether `other` counts by another source.
    pub(in crate::middleware) fn differs(&self, other: &Self) -> bool {
        self.config != other.config
    }
}
