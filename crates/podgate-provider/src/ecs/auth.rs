//! Credentials and request signing.
//!
//! [`Chain`] finds AWS credentials the way the AWS SDKs do, in this order, and keeps them until
//! shortly before they expire:
//!
//! 1. the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`);
//! 2. the shared credentials file (`AWS_SHARED_CREDENTIALS_FILE`, else `~/.aws/credentials`) and
//!    the profile `AWS_PROFILE`, else `default`;
//! 3. a web identity (`AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`), exchanged at STS;
//! 4. the ECS task role (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `..._FULL_URI`);
//! 5. the EC2 instance profile, over IMDSv2.
//!
//! A step that is not configured is skipped; a step that is configured and fails ends the chain
//! with that error, so a broken task role is not hidden behind an instance profile. Credentials
//! are never read from the provider's configuration file.
//!
//! [`sign`] is AWS Signature Version 4, written against `ring` (already in the build for TLS):
//! the algorithm is a few HMACs, and the SDK crates for it bring a large tree. It is checked
//! against the published AWS test vector below and against the fake server of the tests, which
//! recomputes every signature.
//!
//! No credential is ever in an error text, a log line or a `Debug` print: [`Secret`] redacts, and
//! the errors here name the key or the endpoint, never a value.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::HeaderValue;
use http::{Method, Request, Uri};
use http_body_util::Full;
use ring::{digest, hmac};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;

use super::client::{Endpoint, Http, HttpError, encode};
use super::model::{leaf, leaves};
use crate::acme::Secret;

/// Credentials are fetched again this long before they expire.
const REFRESH_MARGIN: u64 = 300;

/// How long credentials from the shared file count as current: the file may be rotated.
const FILE_TTL: u64 = 900;

/// The longest a credential endpoint may take. Off AWS, the instance metadata address does not
/// answer at all, and the chain must go on.
const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(3);

const TRIED: &str = "the environment, the shared credentials file, a web identity, the ECS task role and the EC2 instance profile";

/// Why no credentials could be had.
#[derive(Debug, Error)]
pub(super) enum AuthError {
    /// Every step of the chain was skipped.
    #[error(
        "no AWS credentials: tried {TRIED}; set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, write a credentials file, or run with a role"
    )]
    None,
    /// A step is configured wrongly.
    #[error("AWS credentials: {0}")]
    Invalid(Box<str>),
    /// A step is configured and its endpoint failed.
    #[error("AWS credentials from {provider}: {why}")]
    Fetch {
        provider: &'static str,
        why: Box<str>,
    },
}

/// What requests are signed with. Every part is a [`Secret`], so nothing prints it.
#[derive(Debug, Clone)]
pub(super) struct Credentials {
    access_key: Secret,
    secret_key: Secret,
    session_token: Option<Secret>,
    /// Unix seconds after which they must be fetched again; `None` for ones that never expire.
    valid_until: Option<u64>,
}

impl Credentials {
    pub(super) fn new(
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
        valid_until: Option<u64>,
    ) -> Self {
        Self {
            access_key: Secret::new(access_key),
            secret_key: Secret::new(secret_key),
            session_token: session_token.filter(|t| !t.is_empty()).map(Secret::new),
            valid_until,
        }
    }

    /// Every part that must never reach a log: what an error text is cleaned of.
    pub(super) fn secrets(&self) -> impl Iterator<Item = &str> {
        [
            Some(&self.access_key),
            Some(&self.secret_key),
            self.session_token.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(Secret::expose)
        .filter(|text| !text.is_empty())
    }

    fn fresh(&self, now: u64) -> bool {
        self.valid_until
            .is_none_or(|until| until > now.saturating_add(REFRESH_MARGIN))
    }
}

/// Seconds since the Unix epoch.
pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

// ---- Signature Version 4 ----------------------------------------------------------------------

/// What a signature covers.
pub(super) struct Signing<'a> {
    pub(super) region: &'a str,
    /// The signing name of the service: `ecs`, `ec2`.
    pub(super) service: &'a str,
    pub(super) method: &'a str,
    /// The `Host` header, with the port when it is not the default.
    pub(super) host: &'a str,
    /// The URI path, already encoded.
    pub(super) path: &'a str,
    /// The query string, already encoded and sorted; usually empty.
    pub(super) query: &'a str,
    /// The headers to sign next to `host`, `x-amz-date` and the session token.
    pub(super) headers: &'a [(&'a str, &'a str)],
    pub(super) body: &'a [u8],
    /// Unix seconds.
    pub(super) now: u64,
}

/// The headers a signed request carries besides the ones that were signed from the caller's list.
pub(super) struct Signed {
    /// `x-amz-date`, `x-amz-security-token` when there is a token, and `authorization`.
    pub(super) headers: Vec<(String, String)>,
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn sha256(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
}

/// Signs a request: AWS Signature Version 4 with the `Authorization` header.
#[must_use]
pub(super) fn sign(credentials: &Credentials, request: &Signing<'_>) -> Signed {
    let (date, time) = amz_stamp(request.now);
    let stamp = format!("{date}T{time}Z");
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
        .collect();
    headers.push(("host".to_owned(), request.host.to_owned()));
    headers.push(("x-amz-date".to_owned(), stamp.clone()));
    if let Some(token) = &credentials.session_token {
        headers.push(("x-amz-security-token".to_owned(), token.expose().to_owned()));
    }
    for (_, value) in &mut headers {
        *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        request.method,
        request.path,
        request.query,
        sha256(request.body)
    );
    let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        sha256(canonical.as_bytes())
    );
    let seed = format!("AWS4{}", credentials.secret_key.expose());
    let by_date = hmac_sha256(seed.as_bytes(), date.as_bytes());
    let by_region = hmac_sha256(by_date.as_ref(), request.region.as_bytes());
    let by_service = hmac_sha256(by_region.as_ref(), request.service.as_bytes());
    let key = hmac_sha256(by_service.as_ref(), b"aws4_request");
    let signature = hex(hmac_sha256(key.as_ref(), to_sign.as_bytes()).as_ref());
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        credentials.access_key.expose()
    );
    let mut out = vec![("x-amz-date".to_owned(), stamp)];
    if let Some(token) = &credentials.session_token {
        out.push(("x-amz-security-token".to_owned(), token.expose().to_owned()));
    }
    out.push(("authorization".to_owned(), authorization));
    Signed { headers: out }
}

// ---- time -------------------------------------------------------------------------------------

/// The days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `("20150830", "123600")` for the Unix time `secs`.
fn amz_stamp(secs: u64) -> (String, String) {
    let secs = i64::try_from(secs).unwrap_or(0);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let in_day = secs.rem_euclid(86_400);
    (
        format!("{year:04}{month:02}{day:02}"),
        format!(
            "{:02}{:02}{:02}",
            in_day / 3600,
            in_day % 3600 / 60,
            in_day % 60
        ),
    )
}

/// The Unix time of `2026-11-21T12:00:00Z`, with an optional fraction and `Z` or `+00:00`.
fn parse_instant(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let rest = text.get(19..)?;
    let rest = match rest.strip_prefix('.') {
        Some(fraction) => fraction.trim_start_matches(|c: char| c.is_ascii_digit()),
        None => rest,
    };
    if rest != "Z" && rest != "+00:00" {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).ok()
}

// ---- the chain --------------------------------------------------------------------------------

/// The partition's DNS suffix of a region.
pub(super) fn dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    }
}

/// The JSON document the container credentials endpoint and IMDS answer with.
#[derive(Deserialize)]
struct Document {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "Token", default)]
    token: Option<String>,
    #[serde(rename = "Expiration", default)]
    expiration: Option<String>,
    #[serde(rename = "Code", default)]
    code: Option<String>,
}

/// Finds credentials and keeps them current.
pub(super) struct Chain {
    env: BTreeMap<String, String>,
    http: Http,
    region: Box<str>,
    cached: Mutex<Option<Arc<Credentials>>>,
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The environment holds the keys: nothing of it is shown.
        f.debug_struct("Chain")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl Chain {
    /// A chain that reads `env` (the process's environment, or a test's).
    pub(super) fn new(env: BTreeMap<String, String>, http: Http, region: &str) -> Self {
        Self {
            env,
            http,
            region: region.into(),
            cached: Mutex::new(None),
        }
    }

    fn var(&self, name: &str) -> Option<&str> {
        self.env
            .get(name)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// The current credentials: the cached ones, or a fresh walk of the chain when they are
    /// missing or about to expire.
    pub(super) async fn get(&self) -> Result<Arc<Credentials>, AuthError> {
        let mut cached = self.cached.lock().await;
        if let Some(credentials) = cached.as_ref()
            && credentials.fresh(unix_now())
        {
            return Ok(Arc::clone(credentials));
        }
        let loaded = Arc::new(self.load().await?);
        *cached = Some(Arc::clone(&loaded));
        Ok(loaded)
    }

    async fn load(&self) -> Result<Credentials, AuthError> {
        if let Some(found) = self.environment()? {
            return Ok(found);
        }
        if let Some(found) = self.shared_file().await? {
            return Ok(found);
        }
        if let Some(found) = self.web_identity().await? {
            return Ok(found);
        }
        if let Some(found) = self.container().await? {
            return Ok(found);
        }
        if let Some(found) = self.instance_profile().await? {
            return Ok(found);
        }
        Err(AuthError::None)
    }

    fn environment(&self) -> Result<Option<Credentials>, AuthError> {
        match (
            self.var("AWS_ACCESS_KEY_ID"),
            self.var("AWS_SECRET_ACCESS_KEY"),
        ) {
            (Some(access), Some(secret)) => Ok(Some(Credentials::new(
                access,
                secret,
                self.var("AWS_SESSION_TOKEN"),
                None,
            ))),
            (None, None) => Ok(None),
            _ => Err(AuthError::Invalid(
                "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together".into(),
            )),
        }
    }

    async fn shared_file(&self) -> Result<Option<Credentials>, AuthError> {
        let profile = self.var("AWS_PROFILE");
        let path = match self.var("AWS_SHARED_CREDENTIALS_FILE") {
            Some(path) => PathBuf::from(path),
            None => match self.var("HOME") {
                Some(home) => PathBuf::from(home).join(".aws/credentials"),
                None => return Ok(None),
            },
        };
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && profile.is_none() => {
                return Ok(None);
            }
            Err(err) => {
                return Err(AuthError::Invalid(
                    format!("cannot read the credentials file {}: {err}", path.display()).into(),
                ));
            }
        };
        let wanted = profile.unwrap_or("default");
        let mut in_profile = false;
        let mut found = false;
        let (mut access, mut secret, mut token) = (None, None, None);
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let name = name.trim();
                in_profile = name.strip_prefix("profile ").unwrap_or(name).trim() == wanted;
                found |= in_profile;
            } else if in_profile && let Some((key, value)) = line.split_once('=') {
                let value = value.trim();
                match key.trim() {
                    "aws_access_key_id" => access = Some(value.to_owned()),
                    "aws_secret_access_key" => secret = Some(value.to_owned()),
                    "aws_session_token" => token = Some(value.to_owned()),
                    _ => {}
                }
            }
        }
        match (access, secret) {
            (Some(access), Some(secret)) if !access.is_empty() && !secret.is_empty() => {
                Ok(Some(Credentials::new(
                    &access,
                    &secret,
                    token.as_deref(),
                    Some(unix_now() + FILE_TTL),
                )))
            }
            _ if found || profile.is_some() => Err(AuthError::Invalid(
                format!(
                    "the profile {wanted:?} in {} needs aws_access_key_id and aws_secret_access_key",
                    path.display()
                )
                .into(),
            )),
            _ => Ok(None),
        }
    }

    async fn web_identity(&self) -> Result<Option<Credentials>, AuthError> {
        const WHAT: &str = "the web identity (STS)";
        let (file, role) = match (
            self.var("AWS_WEB_IDENTITY_TOKEN_FILE"),
            self.var("AWS_ROLE_ARN"),
        ) {
            (Some(file), Some(role)) => (file, role),
            (None, None) => return Ok(None),
            _ => {
                return Err(AuthError::Invalid(
                    "AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN must be set together".into(),
                ));
            }
        };
        let token = tokio::fs::read_to_string(file)
            .await
            .map_err(|err| AuthError::Fetch {
                provider: WHAT,
                why: format!("cannot read AWS_WEB_IDENTITY_TOKEN_FILE {file}: {err}").into(),
            })?;
        let endpoint = match self.var("AWS_ENDPOINT_URL_STS") {
            Some(address) => address.to_owned(),
            None => format!("https://sts.{}.{}", self.region, dns_suffix(&self.region)),
        };
        let endpoint = Endpoint::parse(&endpoint)
            .map_err(|why| AuthError::Invalid(format!("the STS endpoint {why}").into()))?;
        let session = self.var("AWS_ROLE_SESSION_NAME").unwrap_or("podgate");
        let form = format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={}&RoleSessionName={}&WebIdentityToken={}",
            encode(role),
            encode(session),
            encode(token.trim())
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/", endpoint.base()))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(form)))
            .map_err(|err| AuthError::Fetch {
                provider: WHAT,
                why: err.to_string().into(),
            })?;
        let body = self.fetch(WHAT, request).await?;
        let found = leaves(&String::from_utf8_lossy(&body));
        let field = |name: &str| leaf(&found, &format!("Credentials/{name}"));
        let (Some(access), Some(secret)) = (field("AccessKeyId"), field("SecretAccessKey")) else {
            return Err(AuthError::Fetch {
                provider: WHAT,
                why: "the answer holds no credentials".into(),
            });
        };
        Ok(Some(Credentials::new(
            access,
            secret,
            field("SessionToken"),
            Some(field("Expiration").and_then(parse_instant).unwrap_or(0)),
        )))
    }

    async fn container(&self) -> Result<Option<Credentials>, AuthError> {
        const WHAT: &str = "the ECS task role";
        let uri = match (
            self.var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),
            self.var("AWS_CONTAINER_CREDENTIALS_FULL_URI"),
        ) {
            (Some(relative), _) if relative.starts_with('/') => {
                format!("http://169.254.170.2{relative}")
            }
            (Some(_), _) => {
                return Err(AuthError::Invalid(
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must start with /".into(),
                ));
            }
            (None, Some(full)) => {
                container_uri(full).map_err(|why| AuthError::Invalid(why.into()))?;
                full.to_owned()
            }
            (None, None) => return Ok(None),
        };
        let token = match self.var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            Some(file) => Some(
                tokio::fs::read_to_string(file)
                    .await
                    .map_err(|err| AuthError::Fetch {
                        provider: WHAT,
                        why: format!(
                            "cannot read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE {file}: {err}"
                        )
                        .into(),
                    })?
                    .trim()
                    .to_owned(),
            ),
            None => self
                .var("AWS_CONTAINER_AUTHORIZATION_TOKEN")
                .map(str::to_owned),
        };
        let mut request = Request::get(uri);
        if let Some(token) = token {
            request = request.header("authorization", sensitive(&token, WHAT)?);
        }
        let request = request
            .body(Full::new(Bytes::new()))
            .map_err(|err| AuthError::Fetch {
                provider: WHAT,
                why: err.to_string().into(),
            })?;
        let body = self.fetch(WHAT, request).await?;
        document(WHAT, &body).map(Some)
    }

    async fn instance_profile(&self) -> Result<Option<Credentials>, AuthError> {
        const WHAT: &str = "the EC2 instance profile";
        if self
            .var("AWS_EC2_METADATA_DISABLED")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return Ok(None);
        }
        let base = self
            .var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
            .unwrap_or("http://169.254.169.254")
            .trim_end_matches('/');
        let wrap = |err: http::Error| AuthError::Fetch {
            provider: WHAT,
            why: err.to_string().into(),
        };
        let token_request = Request::builder()
            .method(Method::PUT)
            .uri(format!("{base}/latest/api/token"))
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .body(Full::new(Bytes::new()))
            .map_err(wrap)?;
        // Off EC2 nothing answers at that address: the chain is simply at its end.
        let token = match self.fetch(WHAT, token_request).await {
            Ok(token) => String::from_utf8_lossy(&token).trim().to_owned(),
            Err(AuthError::Fetch { why, .. }) if why.starts_with("cannot reach") => {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        let get = |path: &str| -> Result<Request<Full<Bytes>>, AuthError> {
            Request::get(format!(
                "{base}/latest/meta-data/iam/security-credentials/{path}"
            ))
            .header("x-aws-ec2-metadata-token", sensitive(&token, WHAT)?)
            .body(Full::new(Bytes::new()))
            .map_err(wrap)
        };
        let roles = self.fetch(WHAT, get("")?).await?;
        let roles = String::from_utf8_lossy(&roles);
        let Some(role) = roles.lines().map(str::trim).find(|line| !line.is_empty()) else {
            return Err(AuthError::Fetch {
                provider: WHAT,
                why: "the instance has no instance profile".into(),
            });
        };
        let body = self.fetch(WHAT, get(&encode(role))?).await?;
        document(WHAT, &body).map(Some)
    }

    /// One request to a credential endpoint. A failure names the endpoint's status or the
    /// transport problem, and never quotes what the endpoint said.
    async fn fetch(
        &self,
        provider: &'static str,
        request: Request<Full<Bytes>>,
    ) -> Result<Bytes, AuthError> {
        let response = self
            .http
            .send(request, ENDPOINT_TIMEOUT)
            .await
            .map_err(|err| AuthError::Fetch {
                provider,
                why: match err {
                    HttpError::Timeout => "cannot reach it: no answer in time".into(),
                    HttpError::TooLarge => "the answer is too large".into(),
                    HttpError::Transport(why) => format!("cannot reach it: {why}").into(),
                },
            })?;
        if (200..300).contains(&response.status) {
            Ok(response.body)
        } else {
            Err(AuthError::Fetch {
                provider,
                why: format!("it answered {}", response.status).into(),
            })
        }
    }
}

fn sensitive(value: &str, provider: &'static str) -> Result<HeaderValue, AuthError> {
    let mut value = HeaderValue::from_str(value).map_err(|_| AuthError::Fetch {
        provider,
        why: "a header value is not valid".into(),
    })?;
    value.set_sensitive(true);
    Ok(value)
}

/// The credentials of the JSON the task role endpoint and IMDS answer with.
fn document(provider: &'static str, body: &[u8]) -> Result<Credentials, AuthError> {
    // The parser's own error would quote the offending value: the text says only what is wrong.
    let document: Document = serde_json::from_slice(body).map_err(|_| AuthError::Fetch {
        provider,
        why: "the answer is not a credentials document".into(),
    })?;
    if document
        .code
        .as_deref()
        .is_some_and(|code| code != "Success")
    {
        return Err(AuthError::Fetch {
            provider,
            why: "the answer reports a failure".into(),
        });
    }
    Ok(Credentials::new(
        &document.access_key_id,
        &document.secret_access_key,
        document.token.as_deref(),
        Some(
            document
                .expiration
                .as_deref()
                .and_then(parse_instant)
                .unwrap_or(0),
        ),
    ))
}

/// `AWS_CONTAINER_CREDENTIALS_FULL_URI` must be `https`, or `http` to a loopback or the
/// container credential addresses AWS documents: credentials never cross a network in clear.
fn container_uri(text: &str) -> Result<(), String> {
    let uri: Uri = text
        .parse()
        .map_err(|_| "AWS_CONTAINER_CREDENTIALS_FULL_URI is not a URL".to_owned())?;
    match uri.scheme_str() {
        Some("https") => Ok(()),
        Some("http") => {
            let host = uri.host().unwrap_or_default();
            let local = host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| {
                        ip.is_loopback()
                            || ip == IpAddr::from([169, 254, 170, 2])
                            || ip == IpAddr::from([169, 254, 170, 23])
                            || ip == IpAddr::from([0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23])
                    });
            if local {
                Ok(())
            } else {
                Err(
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI over http must name a loopback address"
                        .to_owned(),
                )
            }
        }
        _ => Err("AWS_CONTAINER_CREDENTIALS_FULL_URI must be an http or https URL".to_owned()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn matches_the_published_get_vanilla_vector() {
        // The AWS Signature Version 4 test suite, `get-vanilla`.
        let credentials = Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            None,
        );
        let signed = sign(
            &credentials,
            &Signing {
                region: "us-east-1",
                service: "service",
                method: "GET",
                host: "example.amazonaws.com",
                path: "/",
                query: "",
                headers: &[],
                body: b"",
                now: 1_440_938_160,
            },
        );
        let authorization = signed
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.as_str());
        assert_eq!(
            authorization,
            Some(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            )
        );
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(
            amz_stamp(1_440_938_160),
            ("20150830".to_owned(), "123600".to_owned())
        );
        assert_eq!(amz_stamp(0), ("19700101".to_owned(), "000000".to_owned()));
        assert_eq!(
            amz_stamp(951_782_400),
            ("20000229".to_owned(), "000000".to_owned())
        );
        assert_eq!(parse_instant("2015-08-30T12:36:00Z"), Some(1_440_938_160));
        assert_eq!(
            parse_instant("2015-08-30T12:36:00.987Z"),
            Some(1_440_938_160)
        );
        assert_eq!(
            parse_instant("2015-08-30T12:36:00+00:00"),
            Some(1_440_938_160)
        );
        assert_eq!(parse_instant("2015-08-30T12:36:00+02:00"), None);
        assert_eq!(parse_instant("soon"), None);
        for days in [-1_i64, 0, 59, 60, 365, 10_957, 20_000, 47_482] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
        }
    }

    #[test]
    fn container_endpoints_never_cross_a_network_in_clear() {
        assert!(container_uri("https://creds.example.com/x").is_ok());
        assert!(container_uri("http://127.0.0.1:8080/x").is_ok());
        assert!(container_uri("http://169.254.170.23/x").is_ok());
        assert!(container_uri("http://[::1]:8080/x").is_ok());
        assert!(container_uri("http://creds.example.com/x").is_err());
        assert!(container_uri("http://10.0.0.1/x").is_err());
        assert!(container_uri("ftp://127.0.0.1/x").is_err());
    }

    #[test]
    fn credentials_never_print() {
        let credentials = Credentials::new("AKIAEXAMPLE", "sekrit-key", Some("sekrit-token"), None);
        let shown = format!("{credentials:?}");
        for secret in credentials.secrets() {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
