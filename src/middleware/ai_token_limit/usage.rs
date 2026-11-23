//! What a model says it used, and what to charge when it says nothing usable.
//!
//! A `usage` object is read in the two shapes OpenAI-compatible servers speak: chat completions
//! (`prompt_tokens`, `completion_tokens`, `total_tokens`) and the Responses API (`input_tokens`,
//! `output_tokens`, `total_tokens`). The model is not trusted to refund itself: a field that is
//! negative, fractional, not a number or over [`MAX_TOKENS`] is unusable, never clamped, and a
//! total below the sum of its own parts is raised to the sum.

use serde_json::Value;

use crate::ratelimit_store::quota::MAX_LIMIT;

/// The most tokens one answer may be charged: the most a counter takes in one call.
pub(super) const MAX_TOKENS: u64 = MAX_LIMIT;

/// Bytes of an exchange that one estimated token stands for.
const BYTES_PER_TOKEN: u64 = 4;

/// What a model reported, split the way the metrics split it. The three add up to what is
/// charged: between 1 and [`MAX_TOKENS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Reported {
    /// Tokens of the prompt.
    pub(super) prompt: u64,
    /// Tokens of the completion.
    pub(super) completion: u64,
    /// Tokens of a total that came with no split, or that the parts do not account for.
    pub(super) other: u64,
}

impl Reported {
    /// The amount to charge.
    pub(super) fn total(self) -> u64 {
        self.prompt
            .saturating_add(self.completion)
            .saturating_add(self.other)
    }
}

/// A count field as a token number: a JSON integer from 0 to [`MAX_TOKENS`].
fn count(usage: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    let value = names.iter().find_map(|name| usage.get(*name))?;
    // `as_u64` is `None` for a negative number, a fraction, a string and `null`.
    value.as_u64().filter(|tokens| *tokens <= MAX_TOKENS)
}

/// The usable report in a `usage` value, `None` when there is none: the caller then estimates.
pub(super) fn reported(usage: &Value) -> Option<Reported> {
    let usage = usage.as_object()?;
    let prompt = count(usage, &["prompt_tokens", "input_tokens"]);
    let completion = count(usage, &["completion_tokens", "output_tokens"]);
    let total = count(usage, &["total_tokens"]);
    let found = match (prompt, completion, total) {
        (Some(prompt), Some(completion), total) => {
            let parts = prompt + completion;
            let other = total.map_or(0, |total| total.saturating_sub(parts));
            Reported {
                prompt,
                completion,
                other,
            }
        }
        (_, _, Some(total)) => Reported {
            other: total,
            ..Reported::default()
        },
        _ => return None,
    };
    // A zero report for a real exchange is a model not counting; an over-cap one is absurd.
    (1..=MAX_TOKENS).contains(&found.total()).then_some(found)
}

/// One token per four bytes of the exchange, rounded up, at least 1 and at most [`MAX_TOKENS`].
pub(super) fn estimate(request_bytes: u64, response_bytes: u64) -> u64 {
    request_bytes
        .saturating_add(response_bytes)
        .div_ceil(BYTES_PER_TOKEN)
        .clamp(1, MAX_TOKENS)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn report(usage: &Value) -> Option<(u64, u64, u64)> {
        reported(usage).map(|found| (found.prompt, found.completion, found.other))
    }

    #[test]
    fn ai_usage_chat_shape() {
        let usage = json!({"prompt_tokens": 11, "completion_tokens": 31, "total_tokens": 42});
        assert_eq!(report(&usage), Some((11, 31, 0)));
        assert_eq!(reported(&usage).map(Reported::total), Some(42));
    }

    #[test]
    fn ai_usage_responses_shape() {
        let usage = json!({"input_tokens": 5, "output_tokens": 7, "total_tokens": 12});
        assert_eq!(report(&usage), Some((5, 7, 0)));
        let parts_only = json!({"input_tokens": 5, "output_tokens": 7});
        assert_eq!(report(&parts_only), Some((5, 7, 0)));
    }

    #[test]
    fn ai_usage_total_only() {
        assert_eq!(report(&json!({"total_tokens": 9})), Some((0, 0, 9)));
    }

    #[test]
    fn ai_usage_negative_float_or_absurd_is_unusable() {
        for usage in [
            json!({"total_tokens": -5}),
            json!({"total_tokens": 12.5}),
            json!({"total_tokens": "12"}),
            json!({"total_tokens": null}),
            json!({"total_tokens": (1_u64 << 40) + 1}),
            json!({"total_tokens": 18_446_744_073_709_551_615_u64}),
            json!({"prompt_tokens": -100, "completion_tokens": 50}),
            json!({"prompt_tokens": 1.5, "completion_tokens": 2}),
            json!("42"),
            json!([1, 2]),
            json!({}),
        ] {
            assert_eq!(reported(&usage), None, "{usage}");
        }
        // A bad total next to good parts is the parts, not a refund.
        let bad_total = json!({"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": -1});
        assert_eq!(report(&bad_total), Some((10, 20, 0)));
        let at_cap = json!({"total_tokens": 1_u64 << 40});
        assert_eq!(report(&at_cap), Some((0, 0, 1 << 40)));
    }

    #[test]
    fn ai_usage_zero_is_unusable() {
        assert_eq!(reported(&json!({"total_tokens": 0})), None);
        assert_eq!(
            reported(&json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})),
            None
        );
    }

    #[test]
    fn ai_usage_total_cannot_undercut_its_parts() {
        let usage = json!({"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 1});
        assert_eq!(report(&usage), Some((100, 50, 0)));
        let more = json!({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 10});
        assert_eq!(report(&more), Some((1, 1, 8)));
    }

    #[test]
    fn ai_estimate_is_one_token_per_four_bytes() {
        assert_eq!(estimate(0, 0), 1);
        assert_eq!(estimate(3, 0), 1);
        assert_eq!(estimate(4, 0), 1);
        assert_eq!(estimate(5, 0), 2);
        assert_eq!(estimate(100, 60), 40);
        assert_eq!(estimate(u64::MAX, u64::MAX), MAX_TOKENS);
    }
}
