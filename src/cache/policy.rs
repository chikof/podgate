//! What may be stored and for how long: `Cache-Control` parsing, freshness, `Vary` and tags.
//!
//! Pure functions over header maps, no I/O and no clock reads (the caller passes `now`), so the
//! whole table is unit-tested. The rules follow RFC 9111 for a shared cache, with the stricter
//! defaults the spec asks for: no heuristic freshness, no stored responses to requests that
//! carry credentials, and nothing a response marks `private` or `no-store`.

use std::time::{Duration, SystemTime};

use http::header::{CACHE_CONTROL, DATE, EXPIRES, HeaderMap, HeaderName, SET_COOKIE, VARY};

/// What happens to a response that sets a cookie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(from = "bool")]
pub(crate) enum SetCookie {
    /// The response is not stored.
    #[default]
    Refuse,
    /// The response is stored without its `Set-Cookie` headers.
    Strip,
}

impl From<bool> for SetCookie {
    fn from(strip: bool) -> Self {
        if strip { Self::Strip } else { Self::Refuse }
    }
}

/// Whether a request that carries a `Cookie` header may use the cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(from = "bool")]
pub(crate) enum RequestCookies {
    /// The request bypasses the cache: it may be personalised.
    #[default]
    Bypass,
    /// The cookie is ignored: the page is the same for every visitor.
    Ignore,
}

impl From<bool> for RequestCookies {
    fn from(ignore: bool) -> Self {
        if ignore { Self::Ignore } else { Self::Bypass }
    }
}

/// Whether a client's `Cache-Control: no-cache` (or `max-age=0`, `Pragma: no-cache`) is obeyed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(from = "bool")]
pub(crate) enum ClientControl {
    /// Ignored: obeying it would let any client turn the cache into an amplifier.
    #[default]
    Ignore,
    /// Obeyed: the request goes to the upstream and refreshes the entry.
    Respect,
}

impl From<bool> for ClientControl {
    fn from(respect: bool) -> Self {
        if respect { Self::Respect } else { Self::Ignore }
    }
}

/// Whether entries are shared between the revisions of an app.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(from = "bool")]
pub(crate) enum Revisions {
    /// Every revision has its own entries: a rollout never serves one release's page to another.
    #[default]
    Separate,
    /// All revisions share one entry.
    Shared,
}

impl From<bool> for Revisions {
    fn from(shared: bool) -> Self {
        if shared { Self::Shared } else { Self::Separate }
    }
}

/// Whether the query string is sorted before it is part of the key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(from = "bool")]
pub(crate) enum Query {
    /// The query is part of the key as sent.
    #[default]
    AsSent,
    /// The query parameters are sorted, so `?a=1&b=2` and `?b=2&a=1` are one entry.
    Sorted,
}

impl From<bool> for Query {
    fn from(sorted: bool) -> Self {
        if sorted { Self::Sorted } else { Self::AsSent }
    }
}

/// What one `cache` middleware lets the policy decide.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Statuses that may be stored.
    pub(crate) statuses: Box<[u16]>,
    /// Freshness for a response that names none; `None` stores only explicit freshness.
    pub(crate) default_ttl: Option<u64>,
    /// The longest an entry stays fresh, seconds.
    pub(crate) max_ttl: u64,
    /// The longest `stale-while-revalidate` honoured, seconds.
    pub(crate) max_stale_while_revalidate: u64,
    /// The longest `stale-if-error` honoured, seconds.
    pub(crate) max_stale_if_error: u64,
    /// What happens to a `Set-Cookie` response.
    pub(crate) set_cookie: SetCookie,
}

/// The directives of a `Cache-Control` header (all lines of it) that the cache acts on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Directives {
    pub(crate) max_age: Option<u64>,
    pub(crate) s_maxage: Option<u64>,
    flags: u8,
    pub(crate) stale_while_revalidate: Option<u64>,
    pub(crate) stale_if_error: Option<u64>,
}

const NO_STORE: u8 = 1;
const NO_CACHE: u8 = 2;
const PRIVATE: u8 = 4;
/// `must-revalidate` or `proxy-revalidate`.
const MUST_REVALIDATE: u8 = 8;

/// The most RFC 9111 allows a delta-seconds to mean: larger values are capped to it.
const MAX_DELTA: u64 = 2_147_483_648;

fn delta_seconds(value: &str) -> Option<u64> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(value.parse().unwrap_or(MAX_DELTA).min(MAX_DELTA))
}

impl Directives {
    /// Parses every `Cache-Control` line of `headers`. A `no-cache` or `private` that names
    /// fields is read as the whole-response form (the stricter reading); an invalid `max-age`
    /// or `s-maxage` means zero (already stale); an invalid extension is ignored.
    #[must_use]
    pub(crate) fn parse(headers: &HeaderMap) -> Self {
        let mut found = Self::default();
        for value in headers.get_all(CACHE_CONTROL) {
            let Ok(text) = value.to_str() else {
                // Not text: nothing can be trusted about it, so nothing may be stored.
                found.flags |= NO_STORE;
                continue;
            };
            for directive in split_directives(text) {
                let (name, argument) = match directive.split_once('=') {
                    Some((name, argument)) => (name.trim(), Some(argument)),
                    None => (directive.trim(), None),
                };
                if name.eq_ignore_ascii_case("max-age") {
                    found.max_age = Some(argument.and_then(delta_seconds).unwrap_or(0));
                } else if name.eq_ignore_ascii_case("s-maxage") {
                    found.s_maxage = Some(argument.and_then(delta_seconds).unwrap_or(0));
                } else if name.eq_ignore_ascii_case("no-store") {
                    found.flags |= NO_STORE;
                } else if name.eq_ignore_ascii_case("no-cache") {
                    found.flags |= NO_CACHE;
                } else if name.eq_ignore_ascii_case("private") {
                    found.flags |= PRIVATE;
                } else if name.eq_ignore_ascii_case("must-revalidate")
                    || name.eq_ignore_ascii_case("proxy-revalidate")
                {
                    found.flags |= MUST_REVALIDATE;
                } else if name.eq_ignore_ascii_case("stale-while-revalidate") {
                    found.stale_while_revalidate = argument.and_then(delta_seconds);
                } else if name.eq_ignore_ascii_case("stale-if-error") {
                    found.stale_if_error = argument.and_then(delta_seconds);
                }
            }
        }
        found
    }

    /// `no-store`.
    pub(crate) fn no_store(&self) -> bool {
        self.flags & NO_STORE != 0
    }

    /// `no-cache`: a stored response must be revalidated before every use.
    pub(crate) fn no_cache(&self) -> bool {
        self.flags & NO_CACHE != 0
    }

    /// `private`.
    pub(crate) fn private(&self) -> bool {
        self.flags & PRIVATE != 0
    }

    /// `must-revalidate` or `proxy-revalidate`: a stale entry may never be served unchecked.
    pub(crate) fn must_revalidate(&self) -> bool {
        self.flags & MUST_REVALIDATE != 0
    }
}

/// Splits a `Cache-Control` value at the commas outside quoted strings.
fn split_directives(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let mut quoted = false;
        let mut end = rest.len();
        for (at, byte) in rest.bytes().enumerate() {
            match byte {
                b'"' => quoted = !quoted,
                b',' if !quoted => {
                    end = at;
                    break;
                }
                _ => {}
            }
        }
        let (directive, tail) = rest.split_at(end);
        rest = tail.strip_prefix(',').unwrap_or("");
        Some(directive)
    })
    .filter(|directive| !directive.trim().is_empty())
}

/// How long an entry is fresh and how long it may be served stale, in seconds, counted from the
/// moment the origin generated the response (an `Age` header makes that earlier than now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lifetimes {
    pub(crate) fresh: u64,
    pub(crate) stale_while_revalidate: u64,
    pub(crate) stale_if_error: u64,
}

/// The freshness `headers` and `directives` grant, or `None` when the response names none and
/// `settings` has no default. `no-cache` and zero freshness give `fresh == 0`: stored only to be
/// revalidated.
#[must_use]
pub(crate) fn lifetimes(
    settings: &Settings,
    directives: &Directives,
    headers: &HeaderMap,
    now: SystemTime,
) -> Option<Lifetimes> {
    let explicit = directives
        .s_maxage
        .or(directives.max_age)
        .or_else(|| expires_in(headers, now));
    // `no-cache` is stored to be revalidated before every use, so it needs no freshness.
    let fresh = if directives.no_cache() {
        0
    } else {
        explicit.or(settings.default_ttl)?.min(settings.max_ttl)
    };
    // A response that must be checked, or that is checked every time, is never served stale.
    let strict = directives.must_revalidate() || directives.no_cache();
    let allowance = |asked: Option<u64>, cap: u64| {
        if strict {
            0
        } else {
            asked.unwrap_or(0).min(cap)
        }
    };
    Some(Lifetimes {
        fresh,
        stale_while_revalidate: allowance(
            directives.stale_while_revalidate,
            settings.max_stale_while_revalidate,
        ),
        stale_if_error: allowance(directives.stale_if_error, settings.max_stale_if_error),
    })
}

/// Seconds from the response's `Date` (else `now`) to its `Expires`; zero for a date that is
/// invalid or already past, which RFC 9111 says to treat as stale.
fn expires_in(headers: &HeaderMap, now: SystemTime) -> Option<u64> {
    let expires = headers.get(EXPIRES)?;
    let Some(expires) = expires
        .to_str()
        .ok()
        .and_then(|text| httpdate::parse_http_date(text).ok())
    else {
        return Some(0);
    };
    let date = headers
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| httpdate::parse_http_date(text).ok())
        .unwrap_or(now);
    Some(
        expires
            .duration_since(date)
            .map_or(0, |span: Duration| span.as_secs()),
    )
}

/// The `Age` header: how old the response already was when it reached the cache.
#[must_use]
pub(crate) fn initial_age(headers: &HeaderMap) -> u64 {
    headers
        .get(http::header::AGE)
        .and_then(|value| value.to_str().ok())
        .and_then(delta_seconds)
        .unwrap_or(0)
}

/// Why a response is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Skip {
    /// The status is not one the middleware stores.
    Status,
    /// `Cache-Control: no-store`.
    NoStore,
    /// `Cache-Control: private`.
    Private,
    /// The response sets a cookie.
    SetCookie,
    /// `Vary: *`: nothing can say which requests the response fits.
    VaryStar,
    /// The response grants no freshness and no default applies.
    NoFreshness,
    /// It would be stored only to be revalidated, but it has no validator.
    NoValidator,
    /// The tag header is over the limits, so a purge by tag could miss the entry.
    Tags,
    /// A request header the response varies on is too long to key on.
    Variant,
}

/// What the policy decided to keep of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) lifetimes: Lifetimes,
    /// The `Vary` header names, lowercase, sorted, without duplicates.
    pub(crate) vary: Vec<Box<str>>,
    /// `Set-Cookie` headers are removed from the stored copy.
    pub(crate) strip_cookies: bool,
    /// Purge tags from the tag header.
    pub(crate) tags: Vec<Box<str>>,
}

/// Most tags an entry may carry.
pub(crate) const MAX_TAGS: usize = 16;
/// Longest tag, bytes.
pub(crate) const MAX_TAG_BYTES: usize = 128;
/// Most `Vary` names an entry may key on.
const MAX_VARY_NAMES: usize = 8;
/// Longest request header value a variant is keyed on, bytes.
const MAX_VARIANT_VALUE: usize = 256;

/// Decides whether `status` and `headers` may be stored: the response as the client will get it.
///
/// `tag_header` names the header whose value lists purge tags (it is not removed here).
///
/// # Errors
///
/// The [`Skip`] reason when the response is not stored.
pub(crate) fn judge(
    settings: &Settings,
    status: u16,
    headers: &HeaderMap,
    tag_header: Option<&HeaderName>,
    now: SystemTime,
) -> Result<Plan, Skip> {
    if !settings.statuses.contains(&status) {
        return Err(Skip::Status);
    }
    let directives = Directives::parse(headers);
    if directives.no_store() {
        return Err(Skip::NoStore);
    }
    if directives.private() {
        return Err(Skip::Private);
    }
    let sets_cookie = headers.contains_key(SET_COOKIE);
    if sets_cookie && settings.set_cookie == SetCookie::Refuse {
        return Err(Skip::SetCookie);
    }
    let vary = vary_names(headers)?;
    let lifetimes = lifetimes(settings, &directives, headers, now).ok_or(Skip::NoFreshness)?;
    if lifetimes.fresh <= initial_age(headers) && !has_validator(headers) {
        // Already stale when it arrives and nothing to revalidate it with.
        return Err(Skip::NoValidator);
    }
    let tags = match tag_header {
        Some(name) => tags_of(headers, name)?,
        None => Vec::new(),
    };
    Ok(Plan {
        lifetimes,
        vary,
        strip_cookies: sets_cookie,
        tags,
    })
}

/// Whether the response carries a validator a conditional request can use.
#[must_use]
pub(crate) fn has_validator(headers: &HeaderMap) -> bool {
    headers.contains_key(http::header::ETAG) || headers.contains_key(http::header::LAST_MODIFIED)
}

/// The names of a response's `Vary`: lowercase, sorted, unique.
fn vary_names(headers: &HeaderMap) -> Result<Vec<Box<str>>, Skip> {
    let mut names: Vec<Box<str>> = Vec::new();
    for value in headers.get_all(VARY) {
        let Ok(text) = value.to_str() else {
            return Err(Skip::VaryStar);
        };
        for name in text
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            if name == "*" {
                return Err(Skip::VaryStar);
            }
            names.push(name.to_ascii_lowercase().into());
        }
    }
    names.sort();
    names.dedup();
    if names.len() > MAX_VARY_NAMES {
        return Err(Skip::Variant);
    }
    Ok(names)
}

/// The tags in the header called `name`: separated by commas or whitespace.
fn tags_of(headers: &HeaderMap, name: &HeaderName) -> Result<Vec<Box<str>>, Skip> {
    let mut tags: Vec<Box<str>> = Vec::new();
    for value in headers.get_all(name) {
        let Ok(text) = value.to_str() else {
            return Err(Skip::Tags);
        };
        for tag in text
            .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
            .filter(|tag| !tag.is_empty())
        {
            if tag.len() > MAX_TAG_BYTES {
                return Err(Skip::Tags);
            }
            if !tags.iter().any(|known| &**known == tag) {
                tags.push(tag.into());
            }
        }
    }
    if tags.len() > MAX_TAGS {
        return Err(Skip::Tags);
    }
    Ok(tags)
}

/// The key part of a request for the header names a response varies on: one line per name.
///
/// `None` when a value is too long to key on, so the response is not stored for that request.
/// `accept-encoding` is canonicalised (lowercase, sorted, `q=1` dropped), every other value is
/// used as sent with its lines joined by a comma.
#[must_use]
pub(crate) fn variant(request: &HeaderMap, names: &[Box<str>]) -> Option<Box<str>> {
    let mut out = String::new();
    for name in names {
        out.push_str(name);
        out.push(':');
        let mut joined = String::new();
        for value in request.get_all(&**name) {
            let text = value.to_str().ok()?;
            if !joined.is_empty() {
                joined.push_str(", ");
            }
            joined.push_str(text.trim());
        }
        if joined.len() > MAX_VARIANT_VALUE {
            return None;
        }
        if &**name == "accept-encoding" {
            joined = canonical_codings(&joined);
        }
        out.push_str(&joined);
        out.push('\n');
    }
    Some(out.into())
}

/// `gzip, deflate;q=0.5, BR;q=1.0` becomes `br,deflate;q=0.5,gzip`.
fn canonical_codings(value: &str) -> String {
    let mut codings: Vec<String> = value
        .split(',')
        .map(|coding| {
            let mut parts = coding.split(';');
            let token = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let quality = parts
                .filter_map(|part| part.trim().strip_prefix("q="))
                .map(|quality| quality.trim().to_owned())
                .next();
            match quality.as_deref() {
                None | Some("1" | "1.0" | "1.00" | "1.000") => token,
                Some(quality) => format!("{token};q={quality}"),
            }
        })
        .filter(|coding| !coding.is_empty())
        .collect();
    codings.sort();
    codings.dedup();
    codings.join(",")
}

#[cfg(test)]
mod test {
    use http::HeaderValue;

    use super::*;

    fn settings() -> Settings {
        Settings {
            statuses: Box::new([200, 203, 204, 301, 308, 404, 410]),
            default_ttl: None,
            max_ttl: 86_400,
            max_stale_while_revalidate: 60,
            max_stale_if_error: 300,
            set_cookie: SetCookie::Refuse,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    fn judged(status: u16, pairs: &[(&str, &str)]) -> Result<Plan, Skip> {
        judge(
            &settings(),
            status,
            &headers(pairs),
            None,
            SystemTime::now(),
        )
    }

    #[test]
    fn s_maxage_beats_max_age_beats_expires() {
        let now = httpdate::parse_http_date("Mon, 02 Jan 2006 15:04:05 GMT").expect("date");
        let both = Directives::parse(&headers(&[("cache-control", "max-age=10, s-maxage=20")]));
        let fresh =
            |d: &Directives, h: &HeaderMap| lifetimes(&settings(), d, h, now).map(|l| l.fresh);
        assert_eq!(fresh(&both, &HeaderMap::new()), Some(20));
        let age = Directives::parse(&headers(&[("cache-control", "max-age=10")]));
        let with_expires = headers(&[("expires", "Mon, 02 Jan 2006 15:05:05 GMT")]);
        assert_eq!(fresh(&age, &with_expires), Some(10));
        assert_eq!(
            fresh(&Directives::default(), &with_expires),
            Some(60),
            "Expires counts from now when there is no Date"
        );
        let dated = headers(&[
            ("date", "Mon, 02 Jan 2006 15:04:00 GMT"),
            ("expires", "Mon, 02 Jan 2006 15:04:30 GMT"),
        ]);
        assert_eq!(fresh(&Directives::default(), &dated), Some(30));
        assert_eq!(fresh(&Directives::default(), &HeaderMap::new()), None);
    }

    #[test]
    fn an_invalid_expires_or_max_age_is_stale_not_ignored() {
        let now = SystemTime::now();
        let bad_expires = headers(&[("expires", "0")]);
        assert_eq!(
            lifetimes(&settings(), &Directives::default(), &bad_expires, now).map(|l| l.fresh),
            Some(0)
        );
        let bad_age = Directives::parse(&headers(&[("cache-control", "max-age=soon")]));
        assert_eq!(bad_age.max_age, Some(0));
    }

    #[test]
    fn default_ttl_applies_only_when_nothing_is_explicit_and_max_ttl_caps_all() {
        let mut with_default = settings();
        with_default.default_ttl = Some(30);
        let none = Directives::default();
        let now = SystemTime::now();
        assert_eq!(
            lifetimes(&with_default, &none, &HeaderMap::new(), now).map(|l| l.fresh),
            Some(30)
        );
        let long = Directives::parse(&headers(&[("cache-control", "max-age=999999999")]));
        assert_eq!(
            lifetimes(&with_default, &long, &HeaderMap::new(), now).map(|l| l.fresh),
            Some(86_400)
        );
    }

    #[test]
    fn stale_allowances_are_capped_and_vanish_with_must_revalidate_or_no_cache() {
        let now = SystemTime::now();
        let open = Directives::parse(&headers(&[(
            "cache-control",
            "max-age=5, stale-while-revalidate=600, stale-if-error=9999",
        )]));
        let got = lifetimes(&settings(), &open, &HeaderMap::new(), now).expect("fresh");
        assert_eq!((got.stale_while_revalidate, got.stale_if_error), (60, 300));
        let strict = Directives::parse(&headers(&[(
            "cache-control",
            "max-age=5, stale-while-revalidate=30, must-revalidate",
        )]));
        let got = lifetimes(&settings(), &strict, &HeaderMap::new(), now).expect("fresh");
        assert_eq!((got.stale_while_revalidate, got.stale_if_error), (0, 0));
    }

    #[test]
    fn storability_table() {
        let fresh = ("cache-control", "max-age=60");
        assert!(judged(200, &[fresh]).is_ok());
        assert_eq!(judged(500, &[fresh]), Err(Skip::Status));
        assert_eq!(judged(206, &[fresh]), Err(Skip::Status));
        assert_eq!(
            judged(200, &[("cache-control", "max-age=60, no-store")]),
            Err(Skip::NoStore)
        );
        assert_eq!(
            judged(200, &[("cache-control", "private, max-age=60")]),
            Err(Skip::Private)
        );
        assert_eq!(
            judged(200, &[fresh, ("set-cookie", "a=b")]),
            Err(Skip::SetCookie)
        );
        assert_eq!(judged(200, &[fresh, ("vary", "*")]), Err(Skip::VaryStar));
        assert_eq!(
            judged(200, &[fresh, ("vary", "Accept-Encoding, *")]),
            Err(Skip::VaryStar)
        );
        assert_eq!(judged(200, &[]), Err(Skip::NoFreshness));
        assert_eq!(
            judged(200, &[("cache-control", "no-cache")]),
            Err(Skip::NoValidator)
        );
        let revalidated = judged(200, &[("cache-control", "no-cache"), ("etag", "\"a\"")])
            .expect("no-cache with a validator is stored");
        assert_eq!(revalidated.lifetimes.fresh, 0);
    }

    #[test]
    fn set_cookie_is_stripped_when_allowed() {
        let mut allowed = settings();
        allowed.set_cookie = SetCookie::Strip;
        let plan = judge(
            &allowed,
            200,
            &headers(&[("cache-control", "max-age=60"), ("set-cookie", "a=b")]),
            None,
            SystemTime::now(),
        )
        .expect("stored");
        assert!(plan.strip_cookies);
    }

    #[test]
    fn tags_split_on_commas_and_spaces_and_are_bounded() {
        let name = HeaderName::from_static("cache-tag");
        let ok = headers(&[("cache-control", "max-age=60"), ("cache-tag", "a, b  c,a")]);
        let plan = judge(&settings(), 200, &ok, Some(&name), SystemTime::now()).expect("stored");
        assert_eq!(plan.tags, vec!["a".into(), "b".into(), "c".into()]);
        let many = (0..17)
            .map(|n| format!("t{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let over = headers(&[("cache-control", "max-age=60"), ("cache-tag", &many)]);
        assert_eq!(
            judge(&settings(), 200, &over, Some(&name), SystemTime::now()),
            Err(Skip::Tags)
        );
        let long = "x".repeat(129);
        let over = headers(&[("cache-control", "max-age=60"), ("cache-tag", &long)]);
        assert_eq!(
            judge(&settings(), 200, &over, Some(&name), SystemTime::now()),
            Err(Skip::Tags)
        );
    }

    #[test]
    fn variant_keys_follow_vary_and_canonicalise_accept_encoding() {
        let names: Vec<Box<str>> = vec!["accept-encoding".into(), "accept-language".into()];
        let one = headers(&[
            ("accept-encoding", "gzip, deflate;q=1.0"),
            ("accept-language", "en"),
        ]);
        let two = headers(&[
            ("accept-encoding", "deflate,GZIP"),
            ("accept-language", "en"),
        ]);
        let other = headers(&[("accept-encoding", "gzip"), ("accept-language", "en")]);
        assert_eq!(variant(&one, &names), variant(&two, &names));
        assert_ne!(variant(&one, &names), variant(&other, &names));
        assert_eq!(variant(&one, &[]).as_deref(), Some(""));
        let long = headers(&[("accept-language", &"x".repeat(300))]);
        assert_eq!(variant(&long, &names), None);
    }

    #[test]
    fn cache_control_quoted_commas_do_not_split() {
        let parsed = Directives::parse(&headers(&[(
            "cache-control",
            "private=\"a, b\", max-age=5, no-store",
        )]));
        assert!(parsed.private() && parsed.no_store());
        assert_eq!(parsed.max_age, Some(5));
    }
}
