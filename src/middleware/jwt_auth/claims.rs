//! The claim rules of `jwt_auth`: time, issuer, audience and required claims, on a clock the
//! caller passes in, and the text a claim becomes when it is copied into a header.
//!
//! The standard checks run first and answer `401`; the required claims run last and answer
//! `403`, because a token that passes all of the standard checks is a real credential of a
//! caller who may not do this.

use serde_json::{Map, Value};

use super::verify::Failure;

/// A required claim: its name and the values of which one must match.
pub(super) type Requirement = (Box<str>, Box<[Value]>);

/// The claim rules of one middleware.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Rules {
    pub(super) issuer: Option<Box<str>>,
    pub(super) audiences: Box<[Box<str>]>,
    /// Claim name and the values of which one must match, in name order.
    pub(super) required: Box<[Requirement]>,
    pub(super) leeway_secs: u64,
    pub(super) max_token_age_secs: Option<u64>,
}

fn number(claims: &Map<String, Value>, name: &str) -> Result<Option<f64>, Failure> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or(Failure::Malformed),
        Some(_) => Err(Failure::Malformed),
    }
}

/// Whether the claim `have` is one of `want`, or, when it is a list (roles, scopes as an
/// array), holds one of them.
fn matches(have: &Value, want: &[Value]) -> bool {
    match have {
        Value::Array(items) => items.iter().any(|item| want.contains(item)),
        other => want.contains(other),
    }
}

impl Rules {
    /// Checks `claims` at `now` (seconds since the epoch).
    ///
    /// # Errors
    ///
    /// The first [`Failure`]: `exp` missing or past, `nbf` or `iat` in the future, `iat` too old,
    /// the wrong issuer or audience, then [`Failure::ClaimsForbidden`].
    pub(super) fn check(&self, claims: &Map<String, Value>, now: f64) -> Result<(), Failure> {
        #[allow(
            clippy::cast_precision_loss,
            reason = "the leeway is at most 300 seconds"
        )]
        let leeway = self.leeway_secs as f64;
        let exp = number(claims, "exp")?.ok_or(Failure::MissingExp)?;
        if now >= exp + leeway {
            return Err(Failure::Expired);
        }
        if let Some(nbf) = number(claims, "nbf")?
            && now + leeway < nbf
        {
            return Err(Failure::NotYetValid);
        }
        let iat = number(claims, "iat")?;
        if let Some(iat) = iat
            && iat > now + leeway
        {
            return Err(Failure::IssuedInFuture);
        }
        if let Some(max_age) = self.max_token_age_secs {
            #[allow(
                clippy::cast_precision_loss,
                reason = "an age in seconds is far below 2^53"
            )]
            let max_age = max_age as f64;
            match iat {
                Some(iat) if now - iat <= max_age + leeway => {}
                _ => return Err(Failure::TooOld),
            }
        }
        if let Some(issuer) = &self.issuer
            && claims.get("iss").and_then(Value::as_str) != Some(issuer)
        {
            return Err(Failure::BadIssuer);
        }
        if !self.audiences.is_empty() {
            let accepted = |audience: &str| self.audiences.iter().any(|want| **want == *audience);
            let ok = match claims.get("aud") {
                Some(Value::String(audience)) => accepted(audience),
                Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).any(accepted),
                _ => false,
            };
            if !ok {
                return Err(Failure::BadAudience);
            }
        }
        for (name, want) in &self.required {
            if !claims.get(&**name).is_some_and(|have| matches(have, want)) {
                return Err(Failure::ClaimsForbidden);
            }
        }
        Ok(())
    }
}

/// The text of a claim as a header value: a string as it is, a number or a boolean as JSON
/// writes it, a list of those joined with `, `. Anything else (an object, `null`, a list that
/// holds one) is not forwarded.
pub(super) fn header_text(value: &Value) -> Option<String> {
    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        }
    }
    match value {
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .map(scalar)
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join(", ")),
        other => scalar(other),
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn rules() -> Rules {
        Rules {
            issuer: None,
            audiences: Box::new([]),
            required: Box::new([]),
            leeway_secs: 30,
            max_token_age_secs: None,
        }
    }

    fn claims(value: &Value) -> Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    const NOW: f64 = 1_000_000.0;

    #[test]
    fn jwt_expired_401() {
        let rules = Rules {
            leeway_secs: 0,
            ..rules()
        };
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW + 1.0})), NOW),
            Ok(())
        );
        // exp is the first instant the token is no longer valid.
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW})), NOW),
            Err(Failure::Expired)
        );
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW - 5.0})), NOW),
            Err(Failure::Expired)
        );
        assert_eq!(
            rules.check(&claims(&json!({})), NOW),
            Err(Failure::MissingExp)
        );
        assert_eq!(
            rules.check(&claims(&json!({"exp": "tomorrow"})), NOW),
            Err(Failure::Malformed)
        );
    }

    #[test]
    fn jwt_nbf_in_future_401() {
        let rules = Rules {
            leeway_secs: 0,
            ..rules()
        };
        let token = |nbf: f64| claims(&json!({"exp": NOW + 100.0, "nbf": nbf}));
        assert_eq!(rules.check(&token(NOW), NOW), Ok(()));
        assert_eq!(
            rules.check(&token(NOW + 1.0), NOW),
            Err(Failure::NotYetValid)
        );
        let iat = claims(&json!({"exp": NOW + 100.0, "iat": NOW + 1.0}));
        assert_eq!(rules.check(&iat, NOW), Err(Failure::IssuedInFuture));
    }

    #[test]
    fn jwt_leeway_applies() {
        let rules = rules();
        // 30 seconds of leeway in both directions.
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW - 29.0})), NOW),
            Ok(())
        );
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW - 30.0})), NOW),
            Err(Failure::Expired)
        );
        let early = |nbf: f64| claims(&json!({"exp": NOW + 100.0, "nbf": nbf, "iat": nbf}));
        assert_eq!(rules.check(&early(NOW + 30.0), NOW), Ok(()));
        assert_eq!(
            rules.check(&early(NOW + 31.0), NOW),
            Err(Failure::NotYetValid)
        );
    }

    #[test]
    fn max_token_age_checks_iat() {
        let rules = Rules {
            max_token_age_secs: Some(60),
            leeway_secs: 0,
            ..rules()
        };
        let token = |iat: f64| claims(&json!({"exp": NOW + 1000.0, "iat": iat}));
        assert_eq!(rules.check(&token(NOW - 60.0), NOW), Ok(()));
        assert_eq!(rules.check(&token(NOW - 61.0), NOW), Err(Failure::TooOld));
        // No iat at all cannot be shown to be young.
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW + 1000.0})), NOW),
            Err(Failure::TooOld)
        );
    }

    #[test]
    fn jwt_wrong_issuer_401() {
        let rules = Rules {
            issuer: Some("https://idp".into()),
            ..rules()
        };
        let token = |iss: Value| claims(&json!({"exp": NOW + 100.0, "iss": iss}));
        assert_eq!(rules.check(&token(json!("https://idp")), NOW), Ok(()));
        for bad in [json!("https://evil"), json!(["https://idp"]), json!(null)] {
            assert_eq!(rules.check(&token(bad), NOW), Err(Failure::BadIssuer));
        }
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW + 100.0})), NOW),
            Err(Failure::BadIssuer)
        );
    }

    #[test]
    fn jwt_wrong_audience_401() {
        let rules = Rules {
            audiences: Box::new(["api".into(), "web".into()]),
            ..rules()
        };
        let token = |aud: Value| claims(&json!({"exp": NOW + 100.0, "aud": aud}));
        assert_eq!(rules.check(&token(json!("web")), NOW), Ok(()));
        assert_eq!(rules.check(&token(json!(["x", "api"])), NOW), Ok(()));
        for bad in [json!("x"), json!(["x", "y"]), json!([]), json!(7)] {
            assert_eq!(rules.check(&token(bad), NOW), Err(Failure::BadAudience));
        }
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW + 100.0})), NOW),
            Err(Failure::BadAudience)
        );
    }

    #[test]
    fn jwt_required_claims_403() {
        let rules = Rules {
            required: Box::new([
                ("role".into(), Box::new([json!("admin"), json!("ops")])),
                ("tier".into(), Box::new([json!(2)])),
            ]),
            ..rules()
        };
        let token = |extra: Value| {
            let mut all = json!({"exp": NOW + 100.0});
            all.as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            claims(&all)
        };
        assert_eq!(
            rules.check(&token(json!({"role": "ops", "tier": 2})), NOW),
            Ok(())
        );
        assert_eq!(
            rules.check(&token(json!({"role": ["dev", "admin"], "tier": 2})), NOW),
            Ok(())
        );
        for bad in [
            json!({"role": "dev", "tier": 2}),
            json!({"role": "ops"}),
            json!({"role": "ops", "tier": "2"}),
            json!({"tier": 2}),
        ] {
            assert_eq!(rules.check(&token(bad), NOW), Err(Failure::ClaimsForbidden));
        }
        // A token that fails a standard check is a 401 even when its claims are wrong too.
        assert_eq!(
            rules.check(&claims(&json!({"exp": NOW - 100.0})), NOW),
            Err(Failure::Expired)
        );
    }

    #[test]
    fn claims_become_header_text() {
        assert_eq!(header_text(&json!("ann")).as_deref(), Some("ann"));
        assert_eq!(header_text(&json!(42)).as_deref(), Some("42"));
        assert_eq!(header_text(&json!(true)).as_deref(), Some("true"));
        assert_eq!(header_text(&json!(["a", 1])).as_deref(), Some("a, 1"));
        for none in [json!(null), json!({}), json!([]), json!([{"a": 1}])] {
            assert_eq!(header_text(&none), None);
        }
    }
}
