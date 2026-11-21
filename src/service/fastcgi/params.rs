//! The parameters a request carries to the application: the CGI variables podgate decides, and
//! `HTTP_*` from the request headers under the rules that close httpoxy and the underscore and
//! collision tricks. A snapshot's `env` entries are checked here too.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use http::header::{CONTENT_LENGTH, CONTENT_TYPE, COOKIE, TRANSFER_ENCODING};
use http::{HeaderMap, Version};
use pingora::http::RequestHeader;

use super::protocol;

/// Most bytes of parameters one request sends; beyond it the request is refused with `431`.
pub(super) const MAX_PARAMS_BYTES: usize = 64 * 1024;

/// Most `env` entries a service declares.
pub(super) const MAX_ENV_ENTRIES: usize = 32;

/// Longest `env` value, in bytes.
const MAX_ENV_VALUE: usize = 4096;

/// Names a snapshot's `env` may never set: the variables podgate decides, and the ones PHP reads
/// its configuration from.
const RESERVED_NAMES: [&str; 14] = [
    "AUTH_TYPE",
    "DOCUMENT_ROOT",
    "DOCUMENT_URI",
    "GATEWAY_INTERFACE",
    "HTTPS",
    "PATH",
    "PHPRC",
    "QUERY_STRING",
    "REDIRECT_STATUS",
    "TMPDIR",
    "HOME",
    "IFS",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// Prefixes of names a snapshot's `env` may never set.
const RESERVED_PREFIXES: [&str; 10] = [
    "HTTP_", "SCRIPT_", "PATH_", "REQUEST_", "SERVER_", "REMOTE_", "CONTENT_", "PHP_", "LD_",
    "DYLD_",
];

/// Why a parameter set is refused.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// A header value holds a NUL or another control character.
    BadValue(String),
    /// The parameters pass [`MAX_PARAMS_BYTES`].
    TooLarge,
}

/// Where the script is and how the request path splits around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Script {
    /// The file the application runs: its real path under the operator's root.
    pub filename: String,
    /// The URL path of the script (`/app/index.php`).
    pub name: String,
    /// What follows the script in the request path (`/extra/segments`), decoded; empty for none.
    pub path_info: String,
    /// The operator's root, resolved.
    pub document_root: String,
}

/// What the parameters are built from.
pub(super) struct Cgi<'a> {
    /// The request as it goes to the application.
    pub request: &'a RequestHeader,
    /// The script the request resolved to.
    pub script: &'a Script,
    /// The host the client asked for, lowercase, without a port.
    pub server_name: &'a str,
    /// The port the client reached.
    pub server_port: u16,
    /// The resolved client address.
    pub remote_addr: IpAddr,
    /// Whether the client's connection is TLS.
    pub https: bool,
    /// The body's length when it is known: declared, or buffered.
    pub content_length: Option<u64>,
    /// The snapshot's `env` entries, already checked by [`check_env`].
    pub env: &'a [(Box<str>, Box<str>)],
}

fn value_is_clean(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| *byte == b'\t' || (*byte >= 0x20 && *byte != 0x7f))
}

/// `HTTP_X_FOO` for `x-foo`; `None` for a name with anything but letters, digits and `-`.
fn http_name(name: &str) -> Option<String> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(format!(
        "HTTP_{}",
        name.to_ascii_uppercase().replace('-', "_")
    ))
}

/// The `HTTP_*` parameters of `headers`.
///
/// Dropped: `Proxy` (httpoxy: `HTTP_PROXY` is the variable many HTTP clients read as their proxy
/// setting), a name with an underscore, and every name whose `HTTP_*` form another header also
/// produces (`X-Foo` and `X_Foo` both give `HTTP_X_FOO`, and the application cannot tell which one
/// it got, so neither is passed). `Content-Type` and `Content-Length` are separate variables, and
/// `Transfer-Encoding` describes framing the application never sees.
fn http_params(headers: &HeaderMap) -> Result<Vec<(String, Vec<u8>)>, Refused> {
    let mut produced: HashMap<String, u8> = HashMap::new();
    for name in headers.keys() {
        if let Some(mapped) = http_name(&name.as_str().replace('_', "-")) {
            let count = produced.entry(mapped).or_default();
            *count = count.saturating_add(1);
        }
    }
    let mut out = Vec::new();
    for name in headers.keys() {
        let text = name.as_str();
        if text == "proxy"
            || text.contains('_')
            || name == CONTENT_TYPE
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
        {
            continue;
        }
        let Some(mapped) = http_name(text) else {
            continue;
        };
        if produced.get(&mapped).copied().unwrap_or(0) != 1 {
            continue;
        }
        let separator: &[u8] = if name == COOKIE { b"; " } else { b", " };
        let mut joined = Vec::new();
        for value in headers.get_all(name) {
            let bytes = value.as_bytes();
            if !value_is_clean(bytes) {
                return Err(Refused::BadValue(text.to_owned()));
            }
            if !joined.is_empty() {
                joined.extend_from_slice(separator);
            }
            joined.extend_from_slice(bytes);
        }
        out.push((mapped, joined));
    }
    Ok(out)
}

fn protocol_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Every parameter of the request, in the order they are sent.
///
/// # Errors
///
/// [`Refused::BadValue`] for a header value with a control character, [`Refused::TooLarge`] when
/// the whole set passes [`MAX_PARAMS_BYTES`].
pub(super) fn pairs(cgi: &Cgi<'_>) -> Result<Vec<(String, Vec<u8>)>, Refused> {
    let request = cgi.request;
    let script = cgi.script;
    let text = |name: &str, value: &str| (name.to_owned(), value.as_bytes().to_vec());
    let mut out = vec![
        text("GATEWAY_INTERFACE", "CGI/1.1"),
        text("SERVER_SOFTWARE", "podgate"),
        text("SERVER_PROTOCOL", protocol_name(request.version)),
        text("REQUEST_METHOD", request.method.as_str()),
        text(
            "REQUEST_URI",
            request
                .uri
                .path_and_query()
                .map_or_else(|| request.uri.path(), http::uri::PathAndQuery::as_str),
        ),
        text("QUERY_STRING", request.uri.query().unwrap_or("")),
        text("SCRIPT_NAME", &script.name),
        text("SCRIPT_FILENAME", &script.filename),
        text("DOCUMENT_ROOT", &script.document_root),
        text(
            "DOCUMENT_URI",
            &format!("{}{}", script.name, script.path_info),
        ),
        text("SERVER_NAME", cgi.server_name),
        text("SERVER_PORT", &cgi.server_port.to_string()),
        text("REMOTE_ADDR", &cgi.remote_addr.to_string()),
    ];
    if !script.path_info.is_empty() {
        // No PATH_TRANSLATED: with `cgi.fix_pathinfo = 0` PHP-FPM takes the script from it when
        // PATH_INFO is set, and refuses `<root>/<path info>` as a script nobody asked for.
        out.push(text("PATH_INFO", &script.path_info));
    }
    if cgi.https {
        out.push(text("HTTPS", "on"));
    }
    if let Some(kind) = request.headers.get(CONTENT_TYPE) {
        if !value_is_clean(kind.as_bytes()) {
            return Err(Refused::BadValue("content-type".to_owned()));
        }
        out.push(("CONTENT_TYPE".to_owned(), kind.as_bytes().to_vec()));
    }
    if let Some(length) = cgi.content_length {
        out.push(text("CONTENT_LENGTH", &length.to_string()));
    }
    out.extend(http_params(&request.headers)?);
    out.extend(cgi.env.iter().map(|(name, value)| text(name, value)));
    Ok(out)
}

/// Encodes `pairs` as the content of `FCGI_PARAMS`.
///
/// # Errors
///
/// [`Refused::TooLarge`] when the encoding passes [`MAX_PARAMS_BYTES`].
pub(super) fn encode(pairs: &[(String, Vec<u8>)]) -> Result<Vec<u8>, Refused> {
    let mut out = Vec::new();
    for (name, value) in pairs {
        protocol::encode_pair(&mut out, name.as_bytes(), value);
        if out.len() > MAX_PARAMS_BYTES {
            return Err(Refused::TooLarge);
        }
    }
    Ok(out)
}

/// The `env` entries of a service: name and value.
pub(super) type Env = Vec<(Box<str>, Box<str>)>;

/// Checks the `env` of a service and returns it sorted by name.
///
/// A name matches `^[A-Z][A-Z0-9_]{0,63}$` and is neither one of the variables podgate sets nor
/// one of the groups they come in (`HTTP_`, `SCRIPT_`, `PATH_`, `REQUEST_`, `SERVER_`, `REMOTE_`,
/// `CONTENT_`), and nothing PHP reads its own configuration from (`PHP_*`, `PHPRC`, which covers
/// `PHP_INI_SCAN_DIR`) or the dynamic loader reads (`LD_*`). A value has no control character.
///
/// # Errors
///
/// A message naming the first entry that is refused.
pub(super) fn check_env(env: &BTreeMap<String, String>) -> Result<Env, String> {
    if env.len() > MAX_ENV_ENTRIES {
        return Err(format!("env has more than {MAX_ENV_ENTRIES} entries"));
    }
    let mut out = Vec::with_capacity(env.len());
    for (name, value) in env {
        let bytes = name.as_bytes();
        let shape = bytes.len() <= 64
            && bytes.first().is_some_and(u8::is_ascii_uppercase)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_');
        if !shape {
            return Err(format!(
                "env name {name:?} does not match ^[A-Z][A-Z0-9_]{{0,63}}$"
            ));
        }
        if RESERVED_NAMES.contains(&name.as_str())
            || RESERVED_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
        {
            return Err(format!(
                "env name {name} is one podgate or PHP decides: a service cannot set it"
            ));
        }
        if value.len() > MAX_ENV_VALUE || !value_is_clean(value.as_bytes()) {
            return Err(format!(
                "env {name} has a value over {MAX_ENV_VALUE} bytes or with a control character"
            ));
        }
        out.push((Box::from(name.as_str()), Box::from(value.as_str())));
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;

    fn script() -> Script {
        Script {
            filename: "/srv/php/t/app.php".into(),
            name: "/app.php".into(),
            path_info: "/a/b".into(),
            document_root: "/srv/php/t".into(),
        }
    }

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("POST", b"/app.php/a/b?x=1", None).expect("request");
        for (name, value) in headers {
            request
                .append_header(name.to_string(), *value)
                .expect("header");
        }
        request
    }

    fn params(
        request: &RequestHeader,
        env: &[(Box<str>, Box<str>)],
    ) -> Result<Vec<(String, String)>, Refused> {
        let script = script();
        let cgi = Cgi {
            request,
            script: &script,
            server_name: "a.test",
            server_port: 443,
            remote_addr: "203.0.113.9".parse().expect("address"),
            https: true,
            content_length: Some(3),
            env,
        };
        pairs(&cgi).map(|pairs| {
            pairs
                .into_iter()
                .map(|(name, value)| (name, String::from_utf8_lossy(&value).into_owned()))
                .collect()
        })
    }

    fn get<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn standard_variables_follow_the_script() {
        let request = request(&[("content-type", "text/plain")]);
        let params = params(&request, &[]).expect("params");
        for (name, value) in [
            ("REQUEST_METHOD", "POST"),
            ("REQUEST_URI", "/app.php/a/b?x=1"),
            ("QUERY_STRING", "x=1"),
            ("SCRIPT_NAME", "/app.php"),
            ("SCRIPT_FILENAME", "/srv/php/t/app.php"),
            ("PATH_INFO", "/a/b"),
            ("DOCUMENT_ROOT", "/srv/php/t"),
            ("SERVER_NAME", "a.test"),
            ("SERVER_PORT", "443"),
            ("REMOTE_ADDR", "203.0.113.9"),
            ("HTTPS", "on"),
            ("CONTENT_TYPE", "text/plain"),
            ("CONTENT_LENGTH", "3"),
            ("GATEWAY_INTERFACE", "CGI/1.1"),
        ] {
            assert_eq!(get(&params, name), Some(value), "{name}");
        }
    }

    #[test]
    fn the_proxy_header_never_becomes_a_parameter() {
        let request = request(&[("proxy", "http://evil:8080"), ("x-ok", "1")]);
        let params = params(&request, &[]).expect("params");
        assert_eq!(get(&params, "HTTP_PROXY"), None);
        assert_eq!(get(&params, "HTTP_X_OK"), Some("1"));
    }

    #[test]
    fn underscore_and_colliding_names_are_dropped() {
        let request = request(&[
            ("x_foo", "underscore"),
            ("x-foo", "hyphen"),
            ("x-bar", "kept"),
            ("x_only", "underscore alone"),
        ]);
        let params = params(&request, &[]).expect("params");
        assert_eq!(get(&params, "HTTP_X_FOO"), None, "both spellings go");
        assert_eq!(get(&params, "HTTP_X_ONLY"), None);
        assert_eq!(get(&params, "HTTP_X_BAR"), Some("kept"));
    }

    #[test]
    fn repeated_headers_join_and_cookies_join_with_a_semicolon() {
        let request = request(&[
            ("x-a", "1"),
            ("x-a", "2"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
        ]);
        let params = params(&request, &[]).expect("params");
        assert_eq!(get(&params, "HTTP_X_A"), Some("1, 2"));
        assert_eq!(get(&params, "HTTP_COOKIE"), Some("a=1; b=2"));
    }

    #[test]
    fn control_characters_are_not_clean() {
        assert!(value_is_clean(b"plain value\twith a tab"));
        for bad in [&b"a\x00b"[..], b"a\x01b", b"a\x1fb", b"a\x7fb", b"a\r\nb"] {
            assert!(!value_is_clean(bad), "{bad:?}");
        }
    }

    #[test]
    fn env_follows_the_standard_variables() {
        let env =
            check_env(&BTreeMap::from([("APP_ENV".to_owned(), "prod".to_owned())])).expect("env");
        let request = request(&[]);
        let params = params(&request, &env).expect("params");
        assert_eq!(get(&params, "APP_ENV"), Some("prod"));
    }

    #[test]
    fn env_names_are_validated() {
        let entry = |name: &str, value: &str| {
            check_env(&BTreeMap::from([(name.to_owned(), value.to_owned())])).map(drop)
        };
        for good in ["APP_ENV", "A", "X9_Y"] {
            assert!(entry(good, "v").is_ok(), "{good}");
        }
        for bad in [
            "app_env",
            "1A",
            "",
            "HTTP_PROXY",
            "SCRIPT_FILENAME",
            "PATH_INFO",
            "REQUEST_URI",
            "SERVER_NAME",
            "REMOTE_ADDR",
            "CONTENT_TYPE",
            "PHP_INI_SCAN_DIR",
            "PHP_VALUE",
            "PHPRC",
            "QUERY_STRING",
            "HTTPS",
            "LD_PRELOAD",
            "PATH",
            "A-B",
        ] {
            assert!(entry(bad, "v").is_err(), "{bad}");
        }
        assert!(entry(&"A".repeat(65), "v").is_err());
        assert!(entry("OK", "a\u{1}b").is_err());
    }

    #[test]
    fn encoding_over_the_cap_is_too_large() {
        let big = vec![("X".to_owned(), vec![b'a'; MAX_PARAMS_BYTES])];
        assert_eq!(encode(&big), Err(Refused::TooLarge));
        assert!(encode(&[("X".to_owned(), b"a".to_vec())]).is_ok());
    }
}
