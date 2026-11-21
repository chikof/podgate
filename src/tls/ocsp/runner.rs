//! Running one fetch: parse the responder URL, check it against `OCSP_ALLOWED_HOSTS` and the
//! upstream address policy of every tenant the certificate belongs to, ask the responder over
//! the same connect path health probes and error pages use, and verify what comes back.
//!
//! The limits are the spec's: `http` or `https` only, no redirect (a `3xx` is a failed fetch),
//! 5 seconds for connect, request and response together, a request under 512 bytes, a response
//! of at most 64 KiB whose `Content-Type` is `application/ocsp-response`. The policy is asked
//! about the exact IP before it is dialled, on every attempt.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use pingora::upstreams::peer::HttpPeer;

use super::metrics;
use super::reason::Reason;
use super::responder::{AllowedHosts, Responder};
use super::staples::{Job, Outcome};
use super::verify::{MAX_RESPONSE, verify};
use crate::middleware::errors::fetch::{Failure, Fetcher, Limits, Query};
use crate::service::upstream_policy::UpstreamPolicy;

/// Connect, request and response together.
pub const TIMEOUT: Duration = Duration::from_secs(5);

const CONTENT_TYPE: &str = "application/ocsp-response";

/// Runs [`Job`]s. Cheap to clone; clones share the connector.
#[derive(Debug, Clone)]
pub struct Runner {
    fetcher: Fetcher,
    policy: UpstreamPolicy,
    allowed: AllowedHosts,
}

impl Runner {
    /// A runner that dials only what `policy` permits and `allowed` lists.
    #[must_use]
    pub fn new(policy: UpstreamPolicy, allowed: AllowedHosts) -> Self {
        Self {
            fetcher: Fetcher::default(),
            policy,
            allowed,
        }
    }

    /// Fetches and verifies the staple for `job`.
    pub async fn run(&self, job: &Job) -> Outcome {
        match self.attempt(job).await {
            Ok(verified) => Outcome::Verified(verified),
            Err(reason) => Outcome::Failed(reason),
        }
    }

    async fn attempt(&self, job: &Job) -> Result<super::verify::Verified, Reason> {
        let tenants = job.scope().tenants().ok_or(Reason::Unowned)?;
        let responder = Responder::parse(job.identity().responder())?;
        if !self.allowed.permits(responder.host()) {
            return Err(Reason::HostNotAllowed);
        }
        let ip = responder.address().ok_or(Reason::Unresolved)?;
        for tenant in &tenants {
            self.policy.check(tenant, ip).map_err(|_| Reason::Policy)?;
        }
        let _running = metrics::fetch_started();
        let peer = HttpPeer::new(
            SocketAddr::new(ip, responder.port()),
            responder.tls(),
            responder.host().to_owned(),
        );
        let path = responder.target(job.identity().request());
        let authority = responder.authority();
        let query = Query {
            host: &authority,
            accept: CONTENT_TYPE,
            path: &path,
        };
        let limits = Limits {
            max_body: MAX_RESPONSE,
            timeout: TIMEOUT,
        };
        let tenant = tenants.first().copied().unwrap_or_default();
        let fetched = Box::pin(
            self.fetcher
                .fetch(peer, &self.policy, tenant, &query, limits),
        )
        .await
        .map_err(|failure| reason_of(&failure))?;
        let media_type = fetched
            .content_type
            .as_ref()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !media_type.is_some_and(|media| media.eq_ignore_ascii_case(CONTENT_TYPE)) {
            return Err(Reason::ContentType);
        }
        let issuer = job.issuer_der().ok_or(Reason::NoIssuer)?;
        verify(&fetched.body, job.identity(), issuer, SystemTime::now())
    }
}

fn reason_of(failure: &Failure) -> Reason {
    match *failure {
        Failure::Policy => Reason::Policy,
        Failure::NotInet | Failure::Connect(_) | Failure::Io(_) => Reason::Connect,
        Failure::Timeout => Reason::Timeout,
        Failure::Status(_) => Reason::HttpStatus,
        Failure::TooLarge => Reason::Oversized,
        Failure::Malformed(_) => Reason::HttpMalformed,
    }
}
