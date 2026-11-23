//! The parsed OpenAPI document of an `openapi` middleware: the one type change 0135 (the API
//! catalog) reads. It holds what request validation needs and nothing of the original text:
//! `info`, the path templates with their operations, and the compiled schemas.

use std::fmt;
use std::io::{self, Write};

use http::Method;
use serde_json::{Map, Value};

use super::build::{Builder, bad, unsupported};
use super::schema::{Dialect, SchemaId, Schemas};
use crate::compile::Invalid;

/// Largest serialized `document`.
pub(super) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
/// Largest total of the `document`s of one app.
pub(super) const MAX_APP_BYTES: usize = 4 * 1024 * 1024;
/// Most `openapi` middlewares of one app.
pub(super) const MAX_PER_APP: usize = 16;
/// Deepest nesting of the document.
pub(super) const MAX_NESTING: u32 = 64;
/// Most paths.
const MAX_PATHS: usize = 1_000;
/// Most operations.
const MAX_OPERATIONS: usize = 4_000;
/// Most parameters of one operation, path level included.
const MAX_PARAMETERS: usize = 64;
/// Most compiled schemas.
pub(super) const MAX_NODES: usize = 20_000;
/// Most nodes one schema expands to once every `$ref` is followed.
pub(super) const MAX_EXPANDED: u32 = 20_000;
/// Most patterns.
pub(super) const MAX_PATTERNS: usize = 256;
/// Deepest schema nesting, counting every `$ref` hop.
pub(super) const MAX_SCHEMA_DEPTH: u32 = 64;
/// Longest `info.title` or `info.version`.
const MAX_INFO: usize = 512;
/// Longest path template.
const MAX_TEMPLATE: usize = 1_024;

const METHODS: [(&str, Method); 8] = [
    ("get", Method::GET),
    ("put", Method::PUT),
    ("post", Method::POST),
    ("delete", Method::DELETE),
    ("options", Method::OPTIONS),
    ("head", Method::HEAD),
    ("patch", Method::PATCH),
    ("trace", Method::TRACE),
];

/// Where a parameter is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Location {
    Path,
    Query,
    Header,
    Cookie,
}

impl Location {
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
        }
    }
}

/// How a list is written in a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Delimiter {
    /// `a=1&a=2`: one occurrence per item.
    Repeated,
    Comma,
    Space,
    Pipe,
}

/// One compiled parameter.
#[derive(Debug, Clone)]
pub(super) struct Parameter {
    /// Lowercase for a header.
    pub(super) name: Box<str>,
    pub(super) location: Location,
    pub(super) required: bool,
    pub(super) delimiter: Delimiter,
    pub(super) schema: Option<SchemaId>,
}

/// A media range of a request body: `application/json`, `text/*`, `*/*`.
#[derive(Debug)]
pub(super) struct MediaRange {
    kind: Box<str>,
    subtype: Box<str>,
}

impl MediaRange {
    pub(super) fn parse(text: &str) -> Option<Self> {
        let essence = text.split(';').next()?.trim().to_ascii_lowercase();
        let (kind, subtype) = essence.split_once('/')?;
        let valid = |part: &str| !part.is_empty() && !part.contains(['/', ' ', '\t']);
        (valid(kind) && valid(subtype) && (kind != "*" || subtype == "*")).then(|| Self {
            kind: Box::from(kind),
            subtype: Box::from(subtype),
        })
    }

    pub(super) fn is_json(&self) -> bool {
        &*self.kind == "application"
            && (&*self.subtype == "json" || self.subtype.ends_with("+json"))
    }

    /// How specifically this range names `essence` (`type/subtype`, case-insensitive): 2 exact,
    /// 1 `type/*`, 0 `*/*`; `None` for no match.
    pub(super) fn specificity(&self, essence: &str) -> Option<u8> {
        let (kind, subtype) = essence.split_once('/')?;
        if &*self.kind == "*" {
            return Some(0);
        }
        if !self.kind.eq_ignore_ascii_case(kind) {
            return None;
        }
        if &*self.subtype == "*" {
            return Some(1);
        }
        self.subtype.eq_ignore_ascii_case(subtype).then_some(2)
    }
}

/// One media type of a request body.
#[derive(Debug)]
pub(super) struct Media {
    pub(super) range: MediaRange,
    pub(super) json: bool,
    pub(super) schema: Option<SchemaId>,
}

/// A request body declaration.
#[derive(Debug)]
pub(super) struct RequestBody {
    pub(super) required: bool,
    pub(super) media: Box<[Media]>,
}

/// One operation of a path.
#[derive(Debug)]
pub(super) struct Operation {
    pub(super) method: Method,
    pub(super) parameters: Box<[Parameter]>,
    pub(super) body: Option<RequestBody>,
}

#[derive(Debug)]
enum Piece {
    Literal(Box<str>),
    Param(Box<str>),
}

#[derive(Debug)]
enum Segment {
    Literal(Box<str>),
    Param(Box<str>),
    /// `{name}.json`: literals and parameters in one segment.
    Mixed(Box<[Piece]>),
}

/// Matches `text` against the pieces of a mixed segment, calling `sink` with each parameter.
fn mixed<'p>(pieces: &[Piece], text: &'p str, sink: &mut impl FnMut(&str, &'p str)) -> bool {
    let mut rest = text;
    let mut index = 0;
    while let Some(piece) = pieces.get(index) {
        match piece {
            Piece::Literal(literal) => {
                let Some(after) = rest.strip_prefix(&**literal) else {
                    return false;
                };
                rest = after;
            }
            Piece::Param(name) => {
                let Some(first) = rest.chars().next().map(char::len_utf8) else {
                    return false;
                };
                let taken = match pieces.get(index + 1) {
                    None => rest.len(),
                    Some(Piece::Literal(next)) if index + 2 == pieces.len() => {
                        if rest.len() >= first + next.len() && rest.ends_with(&**next) {
                            rest.len() - next.len()
                        } else {
                            return false;
                        }
                    }
                    Some(Piece::Literal(next)) => {
                        match rest.get(first..).and_then(|tail| tail.find(&**next)) {
                            Some(found) => first + found,
                            None => return false,
                        }
                    }
                    Some(Piece::Param(_)) => return false,
                };
                let (value, after) = rest.split_at(taken);
                sink(name, value);
                rest = after;
            }
        }
        index += 1;
    }
    rest.is_empty()
}

/// One path of the document with its operations.
#[derive(Debug)]
pub(super) struct PathTemplate {
    text: Box<str>,
    segments: Box<[Segment]>,
    /// The methods the path has, as an `Allow` header value.
    pub(super) allow: Box<str>,
    pub(super) operations: Box<[Operation]>,
}

impl PathTemplate {
    /// Whether `path` fits, calling `sink` with each parameter name and its raw text.
    pub(super) fn walk<'p>(&self, path: &'p str, sink: &mut impl FnMut(&str, &'p str)) -> bool {
        if self.segments.is_empty() {
            return path == "/";
        }
        let Some(rest) = path.strip_prefix('/') else {
            return false;
        };
        let mut parts = rest.split('/');
        for segment in &self.segments {
            let Some(part) = parts.next() else {
                return false;
            };
            let fits = match segment {
                Segment::Literal(literal) => **literal == *part,
                Segment::Param(name) => {
                    !part.is_empty() && {
                        sink(name, part);
                        true
                    }
                }
                Segment::Mixed(pieces) => mixed(pieces, part, sink),
            };
            if !fits {
                return false;
            }
        }
        parts.next().is_none()
    }

    pub(super) fn operation(&self, method: &Method) -> Option<&Operation> {
        self.operations
            .iter()
            .find(|operation| operation.method == *method)
    }

    fn templated(&self) -> usize {
        self.segments
            .iter()
            .filter(|segment| !matches!(segment, Segment::Literal(_)))
            .count()
    }
}

/// A parsed OpenAPI document: what an `openapi` middleware enforces and what the API catalog
/// shows. It keeps no copy of the document text.
pub struct Document {
    title: Box<str>,
    version: Box<str>,
    dialect: Dialect,
    /// Fewest templated segments first, document order within.
    pub(super) templates: Box<[PathTemplate]>,
    pub(super) schemas: Schemas,
    operations: usize,
}

impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("title", &self.title)
            .field("version", &self.version)
            .field("dialect", &self.dialect)
            .field("paths", &self.templates.len())
            .field("operations", &self.operations)
            .finish_non_exhaustive()
    }
}

impl Document {
    /// `info.title`.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// `info.version`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The schema dialect: OpenAPI 3.0 or 3.1.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// How many operations (method and path) the document describes.
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.operations
    }

    /// Every operation as its method and path template.
    pub fn operations(&self) -> impl Iterator<Item = (&Method, &str)> {
        self.templates.iter().flat_map(|template| {
            template
                .operations
                .iter()
                .map(move |operation| (&operation.method, &*template.text))
        })
    }

    /// The path template that fits `path`: fewest templated segments first.
    pub(super) fn find(&self, path: &str) -> Option<&PathTemplate> {
        self.templates
            .iter()
            .find(|template| template.walk(path, &mut |_, _| {}))
    }

    /// Parses and compiles `document`.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` for a document that is wrong, over a cap or names a remote or cyclic
    /// `$ref`; `unsupported_setting` for a construct podgate does not enforce.
    pub fn compile(document: &Map<String, Value>) -> Result<Self, Invalid> {
        let dialect = match document.get("openapi").and_then(Value::as_str) {
            Some(version) if version.starts_with("3.0.") => Dialect::V30,
            Some(version) if version.starts_with("3.1.") => Dialect::V31,
            _ => {
                return Err(bad(
                    "#/openapi",
                    "openapi is a 3.0.x or 3.1.x version string",
                ));
            }
        };
        if !document
            .values()
            .all(|value| within(value, MAX_NESTING - 1))
        {
            return Err(bad(
                "#",
                format!("the document nests deeper than {MAX_NESTING}"),
            ));
        }
        if let Some(declared) = document.get("jsonSchemaDialect")
            && !matches!(
                declared.as_str(),
                Some(
                    "https://spec.openapis.org/oas/3.1/dialect/base"
                        | "https://json-schema.org/draft/2020-12/schema"
                )
            )
        {
            return Err(unsupported(
                "#/jsonSchemaDialect",
                "only the OpenAPI 3.1 base dialect (JSON Schema 2020-12) is supported",
            ));
        }
        let info = document.get("info").and_then(Value::as_object);
        let text = |key: &str| {
            info.and_then(|info| info.get(key))
                .and_then(Value::as_str)
                .filter(|text| text.len() <= MAX_INFO)
                .map(Box::<str>::from)
                .ok_or_else(|| {
                    bad(
                        "#/info",
                        format!("info.{key} is a string of at most {MAX_INFO} bytes"),
                    )
                })
        };
        let (title, version) = (text("title")?, text("version")?);
        let Some(Value::Object(paths)) = document.get("paths") else {
            return Err(bad("#/paths", "the document has `paths`"));
        };
        if paths.len() > MAX_PATHS {
            return Err(bad(
                "#/paths",
                format!("the document has over {MAX_PATHS} paths"),
            ));
        }
        let mut builder = Builder::new(document, dialect);
        let mut templates = Vec::with_capacity(paths.len());
        let mut operations = 0_usize;
        for (template, item) in paths {
            let at = format!("#/paths/{}", template.replace('~', "~0").replace('/', "~1"));
            let compiled = path_item(&mut builder, template, item, &at)?;
            operations += compiled.operations.len();
            if operations > MAX_OPERATIONS {
                return Err(bad(
                    "#/paths",
                    format!("the document has over {MAX_OPERATIONS} operations"),
                ));
            }
            templates.push(compiled);
        }
        templates.sort_by_key(PathTemplate::templated);
        Ok(Self {
            title,
            version,
            dialect,
            templates: templates.into_boxed_slice(),
            schemas: Schemas {
                nodes: builder.finish(),
                dialect,
            },
            operations,
        })
    }
}

/// Whether `value` nests at most `left` containers deep.
fn within(value: &Value, left: u32) -> bool {
    match value {
        Value::Array(items) => left > 0 && items.iter().all(|item| within(item, left - 1)),
        Value::Object(map) => left > 0 && map.values().all(|item| within(item, left - 1)),
        _ => true,
    }
}

/// The serialized size of `value`, counted without building the text.
pub(super) fn serialized_len(value: &Map<String, Value>) -> usize {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // A `Map` always serializes; counting never fails.
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// The segments of a path template and the parameter names it holds.
struct Parsed {
    segments: Box<[Segment]>,
    names: Vec<Box<str>>,
}

fn template_segments(template: &str, at: &str) -> Result<Parsed, Invalid> {
    if !template.starts_with('/') || template.len() > MAX_TEMPLATE {
        return Err(bad(
            at,
            format!("a path starts with `/` and is at most {MAX_TEMPLATE} bytes"),
        ));
    }
    let mut segments = Vec::new();
    let mut names: Vec<Box<str>> = Vec::new();
    if template != "/" {
        for part in template[1..].split('/') {
            if part.is_empty() {
                return Err(bad(at, "a path has no empty segment"));
            }
            let mut pieces = Vec::new();
            let mut rest = part;
            while !rest.is_empty() {
                match rest.find(['{', '}']) {
                    None => {
                        pieces.push(Piece::Literal(literal(rest, at)?));
                        rest = "";
                    }
                    Some(open) if rest.as_bytes().get(open) == Some(&b'{') => {
                        if open > 0 {
                            pieces.push(Piece::Literal(literal(&rest[..open], at)?));
                        }
                        let tail = &rest[open + 1..];
                        let Some(close) = tail.find('}') else {
                            return Err(bad(at, "a `{` is never closed"));
                        };
                        let name = &tail[..close];
                        if name.is_empty() || name.contains('{') {
                            return Err(bad(at, "a path parameter has a name"));
                        }
                        if names.iter().any(|seen| **seen == *name) {
                            return Err(bad(at, format!("the path names {name} twice")));
                        }
                        names.push(Box::from(name));
                        pieces.push(Piece::Param(Box::from(name)));
                        rest = &tail[close + 1..];
                    }
                    Some(_) => return Err(bad(at, "a `}` has no `{`")),
                }
            }
            let segment = match pieces.as_slice() {
                [Piece::Literal(text)] => Segment::Literal(text.clone()),
                [Piece::Param(name)] => Segment::Param(name.clone()),
                _ => {
                    if pieces
                        .windows(2)
                        .any(|pair| matches!(pair, [Piece::Param(_), Piece::Param(_)]))
                    {
                        return Err(bad(at, "two parameters touch in one segment"));
                    }
                    Segment::Mixed(pieces.into_boxed_slice())
                }
            };
            segments.push(segment);
        }
    }
    Ok(Parsed {
        segments: segments.into_boxed_slice(),
        names,
    })
}

/// A literal as the entry stage normalizes a request path, so the two compare equal.
fn literal(text: &str, at: &str) -> Result<Box<str>, Invalid> {
    let slashed = format!("/{text}");
    let normalized = crate::router::path::normalize(&slashed)
        .map_err(|err| bad(at, format!("the path {text:?} cannot be matched: {err}")))?;
    Ok(Box::from(normalized.trim_start_matches('/')))
}

fn parameters<'d>(
    builder: &mut Builder<'d>,
    node: Option<&'d Value>,
    at: &str,
) -> Result<Vec<Parameter>, Invalid> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = node else {
        return Err(bad(at, "parameters is a list"));
    };
    if list.len() > MAX_PARAMETERS {
        return Err(bad(at, format!("over {MAX_PARAMETERS} parameters")));
    }
    let mut out: Vec<Parameter> = Vec::with_capacity(list.len());
    for (index, item) in list.iter().enumerate() {
        let item_at = format!("{at}/{index}");
        if let Some(parameter) = builder.parameter(item, &item_at)? {
            if out
                .iter()
                .any(|seen| seen.location == parameter.location && seen.name == parameter.name)
            {
                return Err(bad(&item_at, "a parameter is declared twice"));
            }
            out.push(parameter);
        }
    }
    Ok(out)
}

fn path_item<'d>(
    builder: &mut Builder<'d>,
    template: &str,
    item: &'d Value,
    at: &str,
) -> Result<PathTemplate, Invalid> {
    let Value::Object(item) = item else {
        return Err(bad(at, "a path item is an object"));
    };
    if item.contains_key("$ref") {
        return Err(unsupported(at, "a $ref on a path item is not supported"));
    }
    let Parsed { segments, names } = template_segments(template, at)?;
    let shared = parameters(builder, item.get("parameters"), &format!("{at}/parameters"))?;
    let mut operations = Vec::new();
    let mut allow = Vec::new();
    for (key, method) in METHODS {
        let Some(node) = item.get(key) else {
            continue;
        };
        let op_at = format!("{at}/{key}");
        let Value::Object(node) = node else {
            return Err(bad(&op_at, "an operation is an object"));
        };
        let own = parameters(
            builder,
            node.get("parameters"),
            &format!("{op_at}/parameters"),
        )?;
        let mut merged = shared.clone();
        for parameter in own {
            match merged
                .iter_mut()
                .find(|seen| seen.location == parameter.location && seen.name == parameter.name)
            {
                Some(slot) => *slot = parameter,
                None => merged.push(parameter),
            }
        }
        if merged.len() > MAX_PARAMETERS {
            return Err(bad(&op_at, format!("over {MAX_PARAMETERS} parameters")));
        }
        for parameter in &merged {
            if parameter.location == Location::Path
                && !names.iter().any(|name| **name == *parameter.name)
            {
                return Err(bad(
                    &op_at,
                    format!(
                        "the path parameter {} is not in the path template",
                        parameter.name
                    ),
                ));
            }
        }
        let body = node
            .get("requestBody")
            .map(|body| builder.request_body(body, &format!("{op_at}/requestBody")))
            .transpose()?;
        allow.push(method.as_str().to_owned());
        operations.push(Operation {
            method,
            parameters: merged.into_boxed_slice(),
            body,
        });
    }
    Ok(PathTemplate {
        text: Box::from(template),
        segments,
        allow: allow.join(", ").into_boxed_str(),
        operations: operations.into_boxed_slice(),
    })
}
