//! The single-writer guard, and `GET /v1/snapshot/version`.
//!
//! One writer owns the snapshot of a node (invariant 1 of `docs/architecture.md`). A push names
//! itself with the header `podgate-writer: <name>` (1 to 64 characters of `[a-z0-9._-]`).
//!
//! - The first accepted push pins its writer to the live snapshot: a name, or none when it sent
//!   no header. Existing clients that send no name keep working until another writer shows up.
//! - A later push from another name, or with no name while one is pinned, or with a name while
//!   none is, is refused with `409` and changes nothing. Plans are checked the same way.
//! - `?takeover=true` on a push replaces the pinned writer. It is the operator's act, and it
//!   needs a name: it is logged at warn level and goes out as the event `writer_changed`.
//! - The pin belongs to the live snapshot of this process: auto-revert restores an earlier
//!   snapshot but not an earlier writer (the writer did not change, podgate undid its push), and a
//!   restart empties the table, so the next writer pins again. Nothing is written to disk.
//!
//! The check, the apply and the pin are one step: [`Writer::begin`] takes the push gate, and the
//! [`Push`] it returns carries the gate into the blocking task that applies the snapshot, so a
//! client that disconnects mid-compile cannot leave a snapshot live with another writer's pin.

use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{FromRequestParts, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::AppState;
use crate::error::AppError;
use crate::events::{EventFeed, EventKind};

/// The request header that names the writer.
pub(super) const HEADER: &str = "podgate-writer";

/// Longest writer name, in characters.
const MAX_NAME_LEN: usize = 64;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/snapshot/version", get(get_version))
}

/// `200 {"version": N, "writer": "<name>"|null, "boot_id": "..."}`: the live version (`0` before
/// the first snapshot), who owns it, and the id of this run of the process.
async fn get_version(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "version": state.table().load().version(),
        "writer": state.writer().name().as_deref(),
        "boot_id": state.events().boot_id(),
    }))
}

/// Who a push says it is, from its header and query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Claim {
    name: Option<Arc<str>>,
    takeover: bool,
}

impl Claim {
    fn parse(headers: &HeaderMap, query: Option<&str>) -> Result<Self, AppError> {
        let mut values = headers.get_all(HEADER).iter();
        let name = match (values.next(), values.next()) {
            (None, _) => None,
            (Some(value), None) => Some(name(value.to_str().unwrap_or_default())?),
            (Some(_), Some(_)) => {
                return Err(AppError::BadRequest(format!("send {HEADER} once").into()));
            }
        };
        let takeover = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .find(|(key, _)| key == "takeover")
            .map_or(Ok(false), |(_, value)| match &*value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(AppError::BadRequest("takeover is true or false".into())),
            })?;
        if takeover && name.is_none() {
            return Err(AppError::BadRequest(
                format!("takeover needs the writer's name in {HEADER}").into(),
            ));
        }
        Ok(Self { name, takeover })
    }
}

/// A valid writer name.
fn name(value: &str) -> Result<Arc<str>, AppError> {
    let valid = (1..=MAX_NAME_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if valid {
        Ok(value.into())
    } else {
        Err(AppError::BadRequest(
            format!("{HEADER} is 1 to {MAX_NAME_LEN} characters of a-z, 0-9, `.`, `_` and `-`")
                .into(),
        ))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Claim {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, AppError> {
        Self::parse(&parts.headers, parts.uri.query())
    }
}

/// What the pin holds.
#[derive(Debug, Clone, Default)]
enum Pin {
    /// No snapshot was accepted yet: the next push pins its writer.
    #[default]
    Free,
    /// The owner of the live snapshot; `None` when its first push sent no name.
    Held(Option<Arc<str>>),
}

#[derive(Debug, Default)]
struct Inner {
    pin: Mutex<Pin>,
    // Held from the check to the pin, so two pushes cannot both be admitted by an old state.
    gate: Arc<AsyncMutex<()>>,
}

/// Who owns the live snapshot. Cheap to clone; every clone is the same pin.
#[derive(Debug, Clone, Default)]
pub(super) struct Writer {
    inner: Arc<Inner>,
}

impl Writer {
    /// The owner's name, `None` when nobody or an unnamed writer owns the snapshot.
    pub(super) fn name(&self) -> Option<Arc<str>> {
        match &*self.pin() {
            Pin::Held(name) => name.clone(),
            Pin::Free => None,
        }
    }

    /// Whether `claim` may push, for a plan, which pins nothing.
    pub(super) fn check(&self, claim: &Claim) -> Result<(), AppError> {
        self.decide(claim).map(drop)
    }

    /// Admits `claim` and holds the push gate until [`Push::accepted`] or the drop of the
    /// returned [`Push`]: nothing else can push, or be admitted, meanwhile.
    pub(super) async fn begin(&self, claim: Claim) -> Result<Push, AppError> {
        let gate = Arc::clone(&self.inner.gate).lock_owned().await;
        let admission = self.decide(&claim)?;
        Ok(Push {
            _gate: gate,
            writer: self.clone(),
            claim,
            admission,
        })
    }

    /// [`Admission::Same`] when `claim` is the owner or the first writer, [`Admission::Takeover`]
    /// when it replaces another owner; the refusal otherwise.
    fn decide(&self, claim: &Claim) -> Result<Admission, AppError> {
        match &*self.pin() {
            Pin::Free => Ok(Admission::Same),
            Pin::Held(owner) if *owner == claim.name => Ok(Admission::Same),
            Pin::Held(owner) if claim.takeover => Ok(Admission::Takeover {
                from: owner.clone(),
            }),
            Pin::Held(owner) => Err(AppError::WriterOwned {
                writer: owner.as_deref().map(Box::from),
            }),
        }
    }

    fn pin(&self) -> std::sync::MutexGuard<'_, Pin> {
        self.inner
            .pin
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// What the pin allows a claim to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Admission {
    /// The claim is the owner, or the first writer: nothing changes hands.
    Same,
    /// An operator takes the snapshot over from `from`.
    Takeover { from: Option<Arc<str>> },
}

/// An admitted push, holding the gate. Move it into the task that applies the snapshot and call
/// [`Self::accepted`] right after the apply succeeds; dropping it pins nothing.
#[derive(Debug)]
pub(super) struct Push {
    _gate: OwnedMutexGuard<()>,
    writer: Writer,
    claim: Claim,
    admission: Admission,
}

impl Push {
    /// Pins the claim's writer to the snapshot that just went live. A takeover is logged and
    /// reported to the control plane as `writer_changed`.
    pub(super) fn accepted(self, events: &EventFeed) {
        *self.writer.pin() = Pin::Held(self.claim.name.clone());
        if let (Admission::Takeover { from }, Some(to)) = (self.admission, self.claim.name) {
            tracing::warn!(from = ?from, to = &*to, "snapshot writer taken over");
            events.emit(EventKind::WriterChanged {
                from: from.as_deref().map(Box::from),
                to: Box::from(&*to),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use axum::http::HeaderValue;

    use super::*;

    fn claim(name: Option<&str>, takeover: bool) -> Claim {
        Claim {
            name: name.map(Arc::from),
            takeover,
        }
    }

    fn pinned(owner: Option<&str>) -> Writer {
        let writer = Writer::default();
        *writer.pin() = Pin::Held(owner.map(Arc::from));
        writer
    }

    #[test]
    fn a_free_pin_admits_anyone() {
        let writer = Writer::default();
        assert!(matches!(
            writer.decide(&claim(None, false)),
            Ok(Admission::Same)
        ));
        assert!(matches!(
            writer.decide(&claim(Some("a"), false)),
            Ok(Admission::Same)
        ));
        assert_eq!(writer.name(), None);
    }

    #[test]
    fn a_pinned_pin_admits_only_its_owner() {
        let named = pinned(Some("a"));
        assert!(matches!(
            named.decide(&claim(Some("a"), false)),
            Ok(Admission::Same)
        ));
        for other in [claim(Some("b"), false), claim(None, false)] {
            match named.decide(&other) {
                Err(AppError::WriterOwned { writer }) => assert_eq!(writer.as_deref(), Some("a")),
                refused => panic!("{refused:?}"),
            }
        }
        let unnamed = pinned(None);
        assert!(matches!(
            unnamed.decide(&claim(None, false)),
            Ok(Admission::Same)
        ));
        assert!(matches!(
            unnamed.decide(&claim(Some("a"), false)),
            Err(AppError::WriterOwned { writer: None })
        ));
    }

    #[test]
    fn only_a_takeover_replaces_the_owner() {
        let writer = pinned(Some("a"));
        match writer.decide(&claim(Some("b"), true)) {
            Ok(Admission::Takeover { from }) => assert_eq!(from.as_deref(), Some("a")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            writer.decide(&claim(Some("a"), true)),
            Ok(Admission::Same)
        ));
        assert_eq!(writer.name().as_deref(), Some("a"));
    }

    #[tokio::test]
    async fn an_accepted_push_pins_and_a_dropped_one_does_not() {
        let (writer, events) = (Writer::default(), EventFeed::new());
        drop(
            writer
                .begin(claim(Some("a"), false))
                .await
                .expect("admitted"),
        );
        assert_eq!(writer.name(), None);
        let push = writer
            .begin(claim(Some("a"), false))
            .await
            .expect("admitted");
        push.accepted(&events);
        assert_eq!(writer.name().as_deref(), Some("a"));
        let push = writer
            .begin(claim(Some("b"), true))
            .await
            .expect("takeover");
        push.accepted(&events);
        assert_eq!(writer.name().as_deref(), Some("b"));
        let seen = events
            .poll(0, std::time::Duration::ZERO)
            .await
            .expect("poll");
        assert_eq!(seen.len(), 1, "only the takeover is an event: {seen:?}");
    }

    #[tokio::test]
    async fn the_gate_serializes_pushes() {
        let writer = Writer::default();
        let first = writer
            .begin(claim(Some("a"), false))
            .await
            .expect("admitted");
        let second = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            writer.begin(claim(Some("b"), false)),
        )
        .await;
        assert!(second.is_err(), "a second push waits for the first");
        drop(first);
        assert!(writer.begin(claim(Some("b"), false)).await.is_ok());
    }

    #[test]
    fn claims_are_read_from_the_header_and_the_query() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            Claim::parse(&headers, None).expect("none"),
            claim(None, false)
        );
        headers.insert(HEADER, HeaderValue::from_static("podkit-agent"));
        assert_eq!(
            Claim::parse(&headers, Some("x=1&takeover=true")).expect("named"),
            claim(Some("podkit-agent"), true)
        );
        for bad in ["", "UPPER", "has space", "a/b", &"x".repeat(65)] {
            headers.insert(HEADER, HeaderValue::from_str(bad).expect("header value"));
            assert!(Claim::parse(&headers, None).is_err(), "{bad:?}");
        }
        headers.insert(HEADER, HeaderValue::from_static("a"));
        headers.append(HEADER, HeaderValue::from_static("b"));
        assert!(Claim::parse(&headers, None).is_err(), "two names");
        headers.remove(HEADER);
        assert!(
            Claim::parse(&headers, Some("takeover=true")).is_err(),
            "no name"
        );
        headers.insert(HEADER, HeaderValue::from_static("a"));
        assert!(Claim::parse(&headers, Some("takeover=yes")).is_err());
    }
}
