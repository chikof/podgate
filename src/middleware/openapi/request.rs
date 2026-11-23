//! Checks one request against a [`Document`]: the operation, the parameters, the media type and
//! the JSON body. Pure: it reads a borrowed view of the request and returns a verdict, so the
//! Pingora hook only reads the session and writes the answer.

use std::borrow::Cow;

use http::header::{CONTENT_TYPE, COOKIE};
use http::{HeaderMap, Method};
use serde_json::{Number, Value, json};

use super::document::{Delimiter, Document, Location, Operation, Parameter, PathTemplate};
use super::schema::{MAX_STEPS, MAX_VIOLATIONS, Run, SchemaId};
use super::strict_json;

/// One thing wrong with a request. It never holds a value from the request, only where the
/// problem is and what the document says about it (and a JSON pointer into the body, which holds
/// the client's own key names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Violation {
    /// `path`, `method`, `query`, `header`, `cookie` or `body`.
    pub(super) location: &'static str,
    /// The parameter the problem is in.
    pub(super) name: Option<Box<str>>,
    /// A JSON pointer into the body, `""` for the whole body.
    pub(super) pointer: Option<String>,
    pub(super) message: Cow<'static, str>,
}

impl Violation {
    pub(super) fn plain(location: &'static str, message: &'static str) -> Self {
        Self {
            location,
            name: None,
            pointer: None,
            message: Cow::Borrowed(message),
        }
    }

    pub(super) fn to_json(&self) -> Value {
        let mut out = json!({ "in": self.location, "message": &*self.message });
        if let Some(name) = &self.name {
            out["name"] = Value::from(&**name);
        }
        if let Some(pointer) = &self.pointer {
            out["pointer"] = Value::from(pointer.as_str());
        }
        out
    }
}

/// Why a request does not fit: the status to answer with and what to say.
#[derive(Debug)]
pub(super) struct Refusal {
    pub(super) status: u16,
    /// For the access log.
    pub(super) reason: &'static str,
    /// The methods the path has, for a `405`.
    pub(super) allow: Option<Box<str>>,
    pub(super) violations: Vec<Violation>,
    /// There were more violations than are listed.
    pub(super) truncated: bool,
}

impl Refusal {
    pub(super) fn one(status: u16, reason: &'static str, violation: Violation) -> Self {
        Self {
            status,
            reason,
            allow: None,
            violations: vec![violation],
            truncated: false,
        }
    }

    fn too_complex() -> Self {
        Self::one(
            400,
            "openapi_too_complex",
            Violation::plain("body", "the request is too complex to check"),
        )
    }
}

/// What the check reads of a request.
#[derive(Debug, Clone, Copy)]
pub(super) struct Head<'a> {
    pub(super) method: &'a Method,
    /// The normalized path.
    pub(super) path: &'a str,
    pub(super) query: Option<&'a str>,
    pub(super) headers: &'a HeaderMap,
    /// The request has a body.
    pub(super) body_present: bool,
    /// Its declared length, when it has one.
    pub(super) declared: Option<u64>,
    /// The largest JSON body that is checked.
    pub(super) max_body: u32,
}

/// A request that fits an operation so far. Holds only the document and what is left to check.
#[derive(Debug)]
pub(super) struct Admitted<'d> {
    document: &'d Document,
    body: Option<SchemaId>,
    work: u32,
}

#[derive(Default)]
struct Collector {
    items: Vec<Violation>,
    more: bool,
}

impl Collector {
    fn push(&mut self, violation: Violation) {
        if self.items.len() >= MAX_VIOLATIONS {
            self.more = true;
        } else {
            self.items.push(violation);
        }
    }

    fn extend(&mut self, found: (Vec<Violation>, bool)) {
        for violation in found.0 {
            self.push(violation);
        }
        self.more |= found.1;
    }
}

/// The essence of a `Content-Type`: `type/subtype`, parameters dropped.
fn essence(value: &str) -> &str {
    value.split(';').next().unwrap_or_default().trim()
}

/// What a decoder says about a path segment: `None` when it is not UTF-8 or a bad escape.
fn percent_decode(raw: &str) -> Option<Cow<'_, str>> {
    if !raw.contains('%') {
        return Some(Cow::Borrowed(raw));
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
            out.push(u8::try_from(high << 4 | low).ok()?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

/// The values a text could stand for, most specific first: an integer, a number, a boolean, the
/// string. A parameter is valid when its schema takes one of them.
fn candidates(text: &str) -> Vec<Value> {
    let mut out = Vec::with_capacity(4);
    if let Ok(int) = text.parse::<i64>() {
        out.push(Value::from(int));
    } else if let Ok(int) = text.parse::<u64>() {
        out.push(Value::from(int));
    }
    if text
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_digit() || matches!(first, b'-' | b'+' | b'.'))
        && let Ok(float) = text.parse::<f64>()
        && let Some(number) = Number::from_f64(float)
    {
        out.push(Value::Number(number));
    }
    match text {
        "true" => out.push(Value::Bool(true)),
        "false" => out.push(Value::Bool(false)),
        _ => {}
    }
    out.push(Value::String(text.to_owned()));
    out
}

/// The bytes a held body may cost once parsed: its text plus a worst-case 64 bytes for each
/// value (a `serde_json::Value` is far larger than the text it came from).
pub(super) fn parse_cost(body: &[u8]) -> u64 {
    let structural = body
        .iter()
        .filter(|byte| matches!(byte, b'[' | b'{' | b','))
        .count();
    u64::try_from(body.len())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(structural)
                .unwrap_or(u64::MAX)
                .saturating_mul(64),
        )
}

impl Document {
    /// Checks everything of a request except the body's content.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] to answer with: `404`, `405`, `415`, `413`, `400`.
    pub(super) fn check_head(&self, head: &Head<'_>) -> Result<Admitted<'_>, Refusal> {
        let Some(template) = self.find(head.path) else {
            return Err(Refusal::one(
                404,
                "openapi_unknown_path",
                Violation::plain("path", "no path of the API description matches"),
            ));
        };
        let Some(operation) = template.operation(head.method) else {
            return Err(Refusal {
                allow: Some(template.allow.clone()),
                ..Refusal::one(
                    405,
                    "openapi_method",
                    Violation::plain("method", "the path has no operation for this method"),
                )
            });
        };
        let mut admitted = Admitted {
            document: self,
            body: None,
            work: MAX_STEPS,
        };
        admitted.body = admitted.check_media(operation, head)?;
        if admitted.body.is_some()
            && head
                .declared
                .is_some_and(|declared| declared > u64::from(head.max_body))
        {
            return Err(Refusal::one(
                413,
                "openapi_body_too_large",
                Violation::plain("body", "the body is larger than the API description allows"),
            ));
        }
        admitted.check_parameters(template, operation, head)?;
        if head.body_present || !operation.body.as_ref().is_some_and(|body| body.required) {
            return Ok(admitted);
        }
        Err(Refusal::one(
            400,
            "openapi_body",
            Violation::plain("body", "the request body is required"),
        ))
    }
}

impl<'d> Admitted<'d> {
    /// The schema the held body is checked against, when the request has a body to check.
    pub(super) fn body_schema(&self) -> Option<SchemaId> {
        self.body
    }

    /// The media type and body presence: the schema to hold and check, if any.
    fn check_media(
        &self,
        operation: &'d Operation,
        head: &Head<'_>,
    ) -> Result<Option<SchemaId>, Refusal> {
        if !head.body_present {
            return Ok(None);
        }
        let Some(declared) = &operation.body else {
            return Err(Refusal::one(
                400,
                "openapi_body",
                Violation::plain("body", "the operation takes no request body"),
            ));
        };
        let content_type = head
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(essence);
        let Some(content_type) = content_type else {
            return Err(Refusal::one(
                415,
                "openapi_media_type",
                Violation {
                    name: Some(Box::from("content-type")),
                    ..Violation::plain(
                        "header",
                        "a Content-Type that the API description lists is required",
                    )
                },
            ));
        };
        let chosen = declared
            .media
            .iter()
            .filter_map(|media| {
                media
                    .range
                    .specificity(content_type)
                    .map(|rank| (rank, media))
            })
            .max_by_key(|(rank, _)| *rank)
            .map(|(_, media)| media);
        match chosen {
            None => Err(Refusal::one(
                415,
                "openapi_media_type",
                Violation {
                    name: Some(Box::from("content-type")),
                    ..Violation::plain(
                        "header",
                        "the API description does not list this media type",
                    )
                },
            )),
            Some(media) if media.json => Ok(media.schema),
            Some(_) => Ok(None),
        }
    }

    fn check_parameters(
        &mut self,
        template: &PathTemplate,
        operation: &Operation,
        head: &Head<'_>,
    ) -> Result<(), Refusal> {
        let mut found = Collector::default();
        for parameter in &operation.parameters {
            match parameter.location {
                Location::Path => {}
                Location::Query => {
                    let occurrences: Vec<Cow<'_, str>> = head
                        .query
                        .map(|query| {
                            form_urlencoded::parse(query.as_bytes())
                                .filter(|(key, _)| *key == *parameter.name)
                                .map(|(_, value)| value)
                                .collect()
                        })
                        .unwrap_or_default();
                    self.check_parameter(parameter, &occurrences, &mut found)?;
                }
                Location::Header => {
                    let mut occurrences = Vec::new();
                    let mut readable = true;
                    for value in head.headers.get_all(&*parameter.name) {
                        match value.to_str() {
                            Ok(text) => occurrences.push(Cow::Borrowed(text)),
                            Err(_) => readable = false,
                        }
                    }
                    if readable {
                        self.check_parameter(parameter, &occurrences, &mut found)?;
                    } else {
                        found.push(not_text(parameter));
                    }
                }
                Location::Cookie => {
                    let occurrences: Vec<Cow<'_, str>> = head
                        .headers
                        .get_all(COOKIE)
                        .iter()
                        .filter_map(|value| value.to_str().ok())
                        .flat_map(|line| line.split(';'))
                        .filter_map(|pair| pair.trim().split_once('='))
                        .filter(|(key, _)| *key == &*parameter.name)
                        .map(|(_, value)| Cow::Borrowed(value))
                        .collect();
                    self.check_parameter(parameter, &occurrences, &mut found)?;
                }
            }
        }
        self.check_path_parameters(template, operation, head, &mut found)?;
        if found.items.is_empty() {
            return Ok(());
        }
        Err(Refusal {
            status: 400,
            reason: "openapi_parameter",
            allow: None,
            violations: found.items,
            truncated: found.more,
        })
    }

    fn check_path_parameters(
        &mut self,
        template: &PathTemplate,
        operation: &Operation,
        head: &Head<'_>,
        found: &mut Collector,
    ) -> Result<(), Refusal> {
        let mut captured: Vec<(&Parameter, &str)> = Vec::new();
        template.walk(head.path, &mut |name, raw| {
            if let Some(parameter) = operation
                .parameters
                .iter()
                .find(|parameter| parameter.location == Location::Path && *parameter.name == *name)
            {
                captured.push((parameter, raw));
            }
        });
        for (parameter, raw) in captured {
            match percent_decode(raw) {
                Some(text) => {
                    self.check_parameter(parameter, std::slice::from_ref(&text), found)?;
                }
                None => found.push(Violation {
                    name: Some(parameter.name.clone()),
                    ..Violation::plain("path", "is not valid text")
                }),
            }
        }
        Ok(())
    }

    /// Checks the occurrences of one parameter.
    fn check_parameter(
        &mut self,
        parameter: &Parameter,
        occurrences: &[Cow<'_, str>],
        found: &mut Collector,
    ) -> Result<(), Refusal> {
        let place = parameter.location.word();
        let violation = |message: &'static str| Violation {
            name: Some(parameter.name.clone()),
            ..Violation::plain(place, message)
        };
        if occurrences.is_empty() {
            if parameter.required {
                found.push(violation("is required"));
            }
            return Ok(());
        }
        let Some(schema) = parameter.schema else {
            return Ok(());
        };
        let schemas = &self.document.schemas;
        if schemas.is_list(schema) {
            let tokens: Vec<&str> = match (parameter.delimiter, occurrences) {
                (Delimiter::Repeated, all) => all.iter().map(|text| &**text).collect(),
                (_, [one]) if one.is_empty() => Vec::new(),
                (delimiter, [one]) => one
                    .split(match delimiter {
                        Delimiter::Space => ' ',
                        Delimiter::Pipe => '|',
                        _ => ',',
                    })
                    .collect(),
                (_, _) => {
                    found.push(violation("is given more than once"));
                    return Ok(());
                }
            };
            let item_schema = schemas.item_schema(schema);
            let mut items = Vec::with_capacity(tokens.len());
            for token in tokens {
                let mut chosen = None;
                if let Some(item_schema) = item_schema {
                    for candidate in candidates(token) {
                        let mut run = Run::new(self.work, place, None);
                        let ok = schemas.valid(item_schema, &candidate, &mut run);
                        self.work = run.left();
                        if run.exhausted() {
                            return Err(Refusal::too_complex());
                        }
                        if ok {
                            chosen = Some(candidate);
                            break;
                        }
                    }
                }
                items.push(chosen.unwrap_or_else(|| Value::String(token.to_owned())));
            }
            let value = Value::Array(items);
            let mut run = Run::new(self.work, place, Some(&*parameter.name));
            schemas.check(schema, &value, &mut run);
            self.work = run.left();
            if run.exhausted() {
                return Err(Refusal::too_complex());
            }
            found.extend(run.into_found());
            return Ok(());
        }
        let [text] = occurrences else {
            found.push(violation("is given more than once"));
            return Ok(());
        };
        let mut first_failure = None;
        for candidate in candidates(text) {
            let mut run = Run::new(self.work, place, Some(&*parameter.name));
            schemas.check(schema, &candidate, &mut run);
            self.work = run.left();
            if run.exhausted() {
                return Err(Refusal::too_complex());
            }
            let (violations, more) = run.into_found();
            if violations.is_empty() {
                return Ok(());
            }
            first_failure.get_or_insert((violations, more));
        }
        if let Some(failure) = first_failure {
            found.extend(failure);
        }
        Ok(())
    }

    /// Parses and checks the held JSON body.
    ///
    /// # Errors
    ///
    /// The `400` [`Refusal`] for a body that is not JSON, repeats a key, breaks its schema or is
    /// too much to check.
    pub(super) fn check_body(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let Some(schema) = self.body else {
            return Ok(());
        };
        let value = strict_json::parse(bytes).map_err(|refused| {
            Refusal::one(
                400,
                "openapi_body",
                Violation {
                    pointer: Some(String::new()),
                    ..Violation::plain("body", refused.message())
                },
            )
        })?;
        let mut run = Run::new(self.work, "body", None);
        self.document.schemas.check(schema, &value, &mut run);
        self.work = run.left();
        if run.exhausted() {
            return Err(Refusal::too_complex());
        }
        let (violations, truncated) = run.into_found();
        if violations.is_empty() {
            return Ok(());
        }
        Err(Refusal {
            status: 400,
            reason: "openapi_body",
            allow: None,
            violations,
            truncated,
        })
    }
}

fn not_text(parameter: &Parameter) -> Violation {
    Violation {
        name: Some(parameter.name.clone()),
        ..Violation::plain(parameter.location.word(), "is not valid text")
    }
}
