//! The portal's view of an OpenAPI document: what a viewer is shown instead of the
//! stored text.
//!
//! The stored document may carry what its author never meant to publish: example values that hold
//! tokens, `servers` with internal addresses and default credentials, vendor extensions. The
//! view is an allow list over the OpenAPI structure: [`project`] knows the keywords of each kind
//! of object and copies only those, so a keyword added to OpenAPI later is withheld until the
//! list names it. Names of properties, paths, responses and the like are data, never keywords,
//! and stay whatever they are called. Every string that stays goes through [`scrub`], which
//! replaces what looks like a credential.
//!
//! The projection only removes or shortens, so it is never larger than the stored text.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

/// What replaces a credential-shaped text.
const REDACTED: &str = "[redacted]";

/// Deepest nesting the walk follows; the stored document is bounded below this.
const MAX_DEPTH: usize = 80;

/// What a position of the document holds.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Root,
    Info,
    Contact,
    License,
    ExternalDocs,
    Tag,
    PathItem,
    Operation,
    Parameter,
    RequestBody,
    Response,
    Header,
    MediaType,
    Encoding,
    Schema,
    Discriminator,
    SecurityScheme,
    OauthFlow,
    Components,
    /// A map from names to objects of the given kind: the names are data.
    Map(&'static Kind),
    /// A list of objects of the given kind.
    List(&'static Kind),
    /// A map from names to strings, or to lists of strings (scopes, discriminator mapping).
    Text,
}

const SCHEMA: Kind = Kind::Schema;
const PATH_ITEM: Kind = Kind::PathItem;
const PARAMETER: Kind = Kind::Parameter;
const REQUEST_BODY: Kind = Kind::RequestBody;
const RESPONSE: Kind = Kind::Response;
const HEADER: Kind = Kind::Header;
const MEDIA_TYPE: Kind = Kind::MediaType;
const ENCODING: Kind = Kind::Encoding;
const SECURITY_SCHEME: Kind = Kind::SecurityScheme;
const OAUTH_FLOW: Kind = Kind::OauthFlow;
const TAG: Kind = Kind::Tag;

/// The keywords of `kind` that stay, and what each holds. A keyword not listed is dropped.
fn keywords(kind: Kind) -> &'static [(&'static str, Kind)] {
    const T: Kind = Kind::Text;
    match kind {
        Kind::Root => &[
            ("openapi", T),
            ("info", Kind::Info),
            ("tags", Kind::List(&TAG)),
            ("paths", Kind::Map(&PATH_ITEM)),
            ("components", Kind::Components),
            ("security", Kind::List(&Kind::Text)),
            ("externalDocs", Kind::ExternalDocs),
        ],
        Kind::Info => &[
            ("title", T),
            ("version", T),
            ("summary", T),
            ("description", T),
            ("termsOfService", T),
            ("contact", Kind::Contact),
            ("license", Kind::License),
        ],
        Kind::Contact => &[("name", T), ("url", T), ("email", T)],
        Kind::License => &[("name", T), ("identifier", T), ("url", T)],
        Kind::ExternalDocs => &[("description", T), ("url", T)],
        Kind::Tag => &[
            ("name", T),
            ("description", T),
            ("externalDocs", Kind::ExternalDocs),
        ],
        Kind::PathItem => &[
            ("$ref", T),
            ("summary", T),
            ("description", T),
            ("parameters", Kind::List(&PARAMETER)),
            ("get", Kind::Operation),
            ("put", Kind::Operation),
            ("post", Kind::Operation),
            ("delete", Kind::Operation),
            ("options", Kind::Operation),
            ("head", Kind::Operation),
            ("patch", Kind::Operation),
            ("trace", Kind::Operation),
        ],
        Kind::Operation => &[
            ("tags", T),
            ("summary", T),
            ("description", T),
            ("externalDocs", Kind::ExternalDocs),
            ("operationId", T),
            ("parameters", Kind::List(&PARAMETER)),
            ("requestBody", Kind::RequestBody),
            ("responses", Kind::Map(&RESPONSE)),
            ("deprecated", T),
            ("security", Kind::List(&Kind::Text)),
        ],
        Kind::Parameter => &[
            ("$ref", T),
            ("name", T),
            ("in", T),
            ("description", T),
            ("required", T),
            ("deprecated", T),
            ("allowEmptyValue", T),
            ("style", T),
            ("explode", T),
            ("allowReserved", T),
            ("schema", Kind::Schema),
            ("content", Kind::Map(&MEDIA_TYPE)),
        ],
        Kind::RequestBody => &[
            ("$ref", T),
            ("description", T),
            ("content", Kind::Map(&MEDIA_TYPE)),
            ("required", T),
        ],
        Kind::Response => &[
            ("$ref", T),
            ("description", T),
            ("headers", Kind::Map(&HEADER)),
            ("content", Kind::Map(&MEDIA_TYPE)),
        ],
        Kind::Header => &[
            ("$ref", T),
            ("description", T),
            ("required", T),
            ("deprecated", T),
            ("style", T),
            ("explode", T),
            ("schema", Kind::Schema),
            ("content", Kind::Map(&MEDIA_TYPE)),
        ],
        Kind::MediaType => &[("schema", Kind::Schema), ("encoding", Kind::Map(&ENCODING))],
        Kind::Encoding => &[
            ("contentType", T),
            ("headers", Kind::Map(&HEADER)),
            ("style", T),
            ("explode", T),
            ("allowReserved", T),
        ],
        Kind::Schema => &[
            ("$ref", T),
            ("type", T),
            ("format", T),
            ("title", T),
            ("description", T),
            ("enum", T),
            ("const", T),
            ("multipleOf", T),
            ("maximum", T),
            ("exclusiveMaximum", T),
            ("minimum", T),
            ("exclusiveMinimum", T),
            ("maxLength", T),
            ("minLength", T),
            ("pattern", T),
            ("maxItems", T),
            ("minItems", T),
            ("uniqueItems", T),
            ("maxProperties", T),
            ("minProperties", T),
            ("required", T),
            ("nullable", T),
            ("readOnly", T),
            ("writeOnly", T),
            ("deprecated", T),
            ("items", Kind::Schema),
            ("prefixItems", Kind::List(&SCHEMA)),
            ("properties", Kind::Map(&SCHEMA)),
            ("additionalProperties", Kind::Schema),
            ("allOf", Kind::List(&SCHEMA)),
            ("anyOf", Kind::List(&SCHEMA)),
            ("oneOf", Kind::List(&SCHEMA)),
            ("not", Kind::Schema),
            ("discriminator", Kind::Discriminator),
            ("externalDocs", Kind::ExternalDocs),
            ("$defs", Kind::Map(&SCHEMA)),
        ],
        Kind::Discriminator => &[("propertyName", T), ("mapping", Kind::Text)],
        Kind::SecurityScheme => &[
            ("$ref", T),
            ("type", T),
            ("description", T),
            ("name", T),
            ("in", T),
            ("scheme", T),
            ("bearerFormat", T),
            ("flows", Kind::Map(&OAUTH_FLOW)),
        ],
        // Only the scope names and what they mean; the URLs of an OAuth flow are not shown.
        Kind::OauthFlow => &[("scopes", Kind::Text)],
        Kind::Components => &[
            ("schemas", Kind::Map(&SCHEMA)),
            ("responses", Kind::Map(&RESPONSE)),
            ("parameters", Kind::Map(&PARAMETER)),
            ("requestBodies", Kind::Map(&REQUEST_BODY)),
            ("headers", Kind::Map(&HEADER)),
            ("securitySchemes", Kind::Map(&SECURITY_SCHEME)),
            ("pathItems", Kind::Map(&PATH_ITEM)),
        ],
        Kind::Map(_) | Kind::List(_) | Kind::Text => &[],
    }
}

/// The view of a stored document: `None` when `source` is not a JSON object.
#[must_use]
pub(super) fn project(source: &str) -> Option<Value> {
    let Value::Object(document) = serde_json::from_str(source).ok()? else {
        return None;
    };
    Some(object(&document, Kind::Root, 0))
}

/// The members of `map` that `kind` keeps.
fn object(map: &Map<String, Value>, kind: Kind, depth: usize) -> Value {
    let mut kept = Map::new();
    if depth > MAX_DEPTH {
        return Value::Object(kept);
    }
    for (name, value) in map {
        let Some((_, inner)) = keywords(kind).iter().find(|(known, _)| known == name) else {
            continue;
        };
        if let Some(value) = member(value, *inner, depth + 1) {
            kept.insert(name.clone(), value);
        }
    }
    Value::Object(kept)
}

/// One member whose position holds `kind`.
fn member(value: &Value, kind: Kind, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    Some(match (kind, value) {
        (Kind::Map(inner), Value::Object(map)) => Value::Object(
            map.iter()
                .filter_map(|(name, value)| {
                    member(value, *inner, depth + 1).map(|view| (name.clone(), view))
                })
                .collect(),
        ),
        (Kind::List(inner), Value::Array(items)) => Value::Array(
            items
                .iter()
                .filter_map(|item| member(item, *inner, depth + 1))
                .collect(),
        ),
        // A map of strings or of lists of strings.
        (Kind::Text, Value::Object(map)) => Value::Object(
            map.iter()
                .map(|(name, value)| (name.clone(), text(value, depth + 1)))
                .collect(),
        ),
        (Kind::Text, other) => text(other, depth),
        (kind, Value::Object(map)) => object(map, kind, depth),
        // A boolean schema (OpenAPI 3.1): `additionalProperties: false`.
        (Kind::Schema, Value::Bool(flag)) => Value::Bool(*flag),
        _ => return None,
    })
}

/// A value of plain data: strings are scrubbed, containers are walked, the rest stays.
fn text(value: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    match value {
        Value::String(text) => Value::String(scrub(text).into_owned()),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| text(item, depth + 1)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, item)| (name.clone(), text(item, depth + 1)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The patterns of [`scrub`]. A heuristic: it catches the shapes credentials are pasted in, not a
/// secret written as prose.
static SHAPES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let shapes: [(&str, &str); 7] = [
        // A PEM block, up to its end line or the end of the text.
        (
            r"-----BEGIN [A-Z0-9 ]+-----(?s:.*?)(?:-----END [A-Z0-9 ]+-----|$)",
            REDACTED,
        ),
        // A JSON Web Token.
        (
            r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*",
            REDACTED,
        ),
        // A long credential after an authentication scheme.
        (
            r"(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{16,}",
            "$1 [redacted]",
        ),
        // The password in `scheme://user:password@host`.
        (
            r"([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@",
            "${1}[redacted]@",
        ),
        // The keys of the common providers.
        (r"\bAKIA[0-9A-Z]{16}\b", REDACTED),
        (r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", REDACTED),
        (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", REDACTED),
    ];
    shapes
        .into_iter()
        .filter_map(|(pattern, replacement)| {
            Regex::new(pattern).ok().map(|regex| (regex, replacement))
        })
        .collect()
});

/// `text` with every credential-shaped part replaced by `[redacted]`.
#[must_use]
pub(super) fn scrub(text: &str) -> Cow<'_, str> {
    let mut current = Cow::Borrowed(text);
    for (regex, replacement) in SHAPES.iter() {
        if regex.is_match(&current) {
            current = Cow::Owned(regex.replace_all(&current, *replacement).into_owned());
        }
    }
    current
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn view(document: &Value) -> Value {
        project(&document.to_string()).expect("a view")
    }

    #[test]
    fn project_removes_servers_examples_and_extensions() {
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "Pets", "version": "1", "x-internal": "yes", "description": "d"},
            "servers": [{"url": "https://10.0.0.7:8443", "variables": {"token": {"default": "s3cret"}}}],
            "x-owner": "team-a",
            "webhooks": {"w": {}},
            "paths": {
                "/pets": {
                    "servers": [{"url": "http://internal"}],
                    "x-rate": 5,
                    "get": {
                        "summary": "list",
                        "x-codegen": "x",
                        "callbacks": {"c": {}},
                        "parameters": [{
                            "name": "q", "in": "query", "example": "s3cret-example",
                            "examples": {"a": {"value": "s3cret"}},
                            "schema": {"type": "string", "default": "s3cret-default", "example": "s3cret-schema"}
                        }],
                        "responses": {"200": {
                            "description": "ok",
                            "links": {"l": {}},
                            "content": {"application/json": {
                                "example": {"token": "s3cret"},
                                "examples": {"e": {"value": "s3cret"}},
                                "schema": {"type": "object", "properties": {
                                    "example": {"type": "string", "example": "s3cret"},
                                    "default": {"type": "string"}
                                }}
                            }}
                        }}
                    }
                }
            },
            "components": {
                "examples": {"e": {"value": "s3cret"}},
                "securitySchemes": {
                    "oauth": {"type": "oauth2", "x-a": 1, "flows": {"authorizationCode": {
                        "authorizationUrl": "https://internal/auth",
                        "tokenUrl": "https://internal/token",
                        "scopes": {"read": "read pets"}
                    }}},
                    "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://internal/.well-known"},
                    "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
                }
            }
        });
        let shown = view(&document);
        let text = shown.to_string();
        for gone in [
            "s3cret",
            "internal",
            "10.0.0.7",
            "x-internal",
            "x-owner",
            "x-codegen",
            "webhooks",
            "callbacks",
            "links",
            "servers",
            "openIdConnectUrl",
            "tokenUrl",
        ] {
            assert!(!text.contains(gone), "{gone} survived: {text}");
        }
        assert_eq!(shown["info"]["title"], "Pets");
        assert_eq!(shown["paths"]["/pets"]["get"]["summary"], "list");
        assert_eq!(
            shown["components"]["securitySchemes"]["oauth"]["flows"]["authorizationCode"]["scopes"]
                ["read"],
            "read pets"
        );
        assert_eq!(
            shown["components"]["securitySchemes"]["bearer"]["bearerFormat"],
            "JWT"
        );
        assert!(text.len() <= document.to_string().len());
    }

    #[test]
    fn project_keeps_names_that_look_like_keywords() {
        let document = json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1"},
            "paths": {"/example": {"get": {"responses": {"default": {"description": "x"}}}}},
            "components": {"schemas": {
                "examples": {"type": "object", "properties": {
                    "example": {"type": "string"}, "servers": {"type": "string"},
                    "default": {"type": "integer"}, "x-id": {"type": "string"}
                }}
            }}
        });
        let shown = view(&document);
        assert!(shown["paths"]["/example"]["get"]["responses"]["default"].is_object());
        let props = &shown["components"]["schemas"]["examples"]["properties"];
        for name in ["example", "servers", "default", "x-id"] {
            assert!(props[name].is_object(), "{name}");
        }
    }

    #[test]
    fn project_refuses_what_is_not_an_object() {
        assert!(project("[]").is_none());
        assert!(project("nope").is_none());
        assert!(project("{}").is_some());
    }

    #[test]
    fn scrub_redacts_pem_jwt_bearer_and_url_password() {
        let pem = format!(
            "see -----BEGIN PRIVATE {}-----\nMIIEvQIBADANBgkq\n-----END PRIVATE {}----- ok",
            "KEY", "KEY"
        );
        assert_eq!(scrub(&pem), "see [redacted] ok");
        let cut = "-----BEGIN CERTIFICATE-----\nAAAA";
        assert_eq!(scrub(cut), "[redacted]");
        let jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ4In0", "c2lnbmF0dXJl"].join(".");
        assert_eq!(scrub(&format!("token {jwt} here")), "token [redacted] here");
        let credential = "x".repeat(24);
        assert_eq!(
            scrub(&format!("Authorization: Bearer {credential}")),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(scrub("basic dXNlcjpwYXNzd29yZDEyMzQ1"), "basic [redacted]");
        assert_eq!(
            scrub("postgres://app:hunter2hunter2@db.internal/x"),
            "postgres://app:[redacted]@db.internal/x"
        );
        let aws = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        assert_eq!(scrub(&format!("key {aws} end")), "key [redacted] end");
        let github = format!("{}{}", "ghp_", "a".repeat(36));
        assert_eq!(scrub(&github), "[redacted]");
    }

    #[test]
    fn scrub_leaves_prose_alone() {
        for text in [
            "Send the token in the Authorization header as Bearer <token>.",
            "Returns a list of pets.",
            "Use Basic auth.",
            "https://api.example.com/v1/pets?limit=10",
            "user:password",
            "A Token is required",
        ] {
            assert_eq!(scrub(text), text);
        }
    }
}
