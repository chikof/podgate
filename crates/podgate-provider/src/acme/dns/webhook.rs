//! The webhook solver: `POST <url>/present` and `POST <url>/cleanup` with `{"fqdn", "value"}`.
//!
//! The contract is that of lego's `httpreq` provider (`fqdn` is the challenge name with a trailing
//! dot, `value` the TXT value), which cert-manager style webhooks and small bridges to DNS APIs
//! speak. The call carries `Authorization: Bearer <token>`. Any `2xx` is success. A timeout, a
//! connection error, `408`, `425`, `429` and `5xx` are retried by the caller; any other status is a
//! refusal that retrying will not change.
//!
//! The upstream address policy does not apply: the operator wrote the URL. The answer's body is
//! read up to 64 KiB and dropped, never logged, because a hostile or confused endpoint could
//! echo the request headers back.

use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::json;
use tokio::time::timeout;

use super::Failure;
use crate::acme::Secret;

/// Most of an answer's body that is read.
const MAX_BODY: usize = 64 * 1024;

type Http = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A configured webhook.
pub(super) struct Webhook {
    base: Box<str>,
    token: Secret,
    wait: Duration,
    client: Http,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("url", &self.base)
            .finish_non_exhaustive()
    }
}

impl Webhook {
    /// A client of `url` that sends `token` and gives each call `wait`.
    ///
    /// # Errors
    ///
    /// The reason the platform's root certificates cannot be loaded.
    pub(super) fn new(url: &str, token: Secret, wait: Duration) -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            base: url.trim_end_matches('/').into(),
            token,
            wait,
            client: Client::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(connector),
        })
    }

    /// Calls `action` (`present` or `cleanup`) for `fqdn` and `value`.
    pub(super) async fn call(&self, action: &str, fqdn: &str, value: &str) -> Result<(), Failure> {
        let uri: Uri = format!("{}/{action}", self.base)
            .parse()
            .map_err(|_| Failure::Permanent("the webhook URL is not a URL".into()))?;
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", self.token.expose()))
            .map_err(|_| Failure::Permanent("the bearer token is not a header value".into()))?;
        bearer.set_sensitive(true);
        let body = json!({ "fqdn": fqdn, "value": value }).to_string();
        let request = Request::post(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, bearer)
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Failure::Permanent("cannot build the webhook request".into()))?;
        let status = timeout(self.wait, async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|err| Failure::Retry(format!("the webhook is unreachable ({err})")))?;
            let status = response.status();
            let mut body = response.into_body();
            let mut read = 0;
            while let Some(frame) = body.frame().await {
                let Ok(frame) = frame else { break };
                read += frame.data_ref().map_or(0, Bytes::len);
                if read > MAX_BODY {
                    break;
                }
            }
            Ok::<_, Failure>(status)
        })
        .await
        .map_err(|_| Failure::Retry("the webhook did not answer in time".into()))??;
        if status.is_success() {
            Ok(())
        } else if status.is_server_error()
            || [
                StatusCode::REQUEST_TIMEOUT,
                StatusCode::TOO_EARLY,
                StatusCode::TOO_MANY_REQUESTS,
            ]
            .contains(&status)
        {
            Err(Failure::Retry(format!("the webhook answered {status}")))
        } else {
            Err(Failure::Permanent(format!("the webhook answered {status}")))
        }
    }
}
