//! Precompressed sidecar files: `app.js.br` and `app.js.gz` next to `app.js`, chosen by the
//! client's `Accept-Encoding`.

/// An encoding a sidecar file can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Encoding {
    /// Brotli, `file.br`.
    Brotli,
    /// Gzip, `file.gz`.
    Gzip,
}

impl Encoding {
    /// The encoding called `name` in a snapshot (`br` or `gzip`).
    #[must_use]
    pub(super) fn parse(name: &str) -> Option<Self> {
        match name {
            "br" => Some(Self::Brotli),
            "gzip" => Some(Self::Gzip),
            _ => None,
        }
    }

    /// The `Content-Encoding` token.
    #[must_use]
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
        }
    }

    /// The file name suffix of the sidecar.
    #[must_use]
    pub(super) fn suffix(self) -> &'static str {
        match self {
            Self::Brotli => ".br",
            Self::Gzip => ".gz",
        }
    }
}

/// The quality `accept` gives `token`: its own `q`, else the `*` entry's, else `0`.
fn quality(accept: &[&str], token: &str) -> u16 {
    let mut named = None;
    let mut star = None;
    for item in accept.iter().flat_map(|value| value.split(',')) {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or_default().trim();
        let q = parts
            .find_map(|param| {
                let (key, value) = param.split_once('=')?;
                key.trim().eq_ignore_ascii_case("q").then(|| value.trim())
            })
            .map_or(Some(1000), thousandths);
        let Some(q) = q else { continue };
        if coding.eq_ignore_ascii_case(token) {
            named = Some(q);
        } else if coding == "*" {
            star = Some(q);
        }
    }
    named.or(star).unwrap_or(0)
}

/// A `q` value (`0` to `1`, up to three decimals) in thousandths; `None` when malformed.
fn thousandths(text: &str) -> Option<u16> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let scaled: u16 = format!("{fraction:0<3}").parse().ok()?;
    match whole {
        "0" => Some(scaled),
        "1" if scaled == 0 => Some(1000),
        _ => None,
    }
}

/// The encodings of `offered` (the site's list, in its order of preference) the client accepts,
/// best first: by the client's quality, then by the site's order.
#[must_use]
pub(super) fn acceptable(offered: &[Encoding], accept: &[&str]) -> Vec<Encoding> {
    let mut chosen: Vec<(u16, Encoding)> = offered
        .iter()
        .map(|encoding| (quality(accept, encoding.token()), *encoding))
        .filter(|(q, _)| *q > 0)
        .collect();
    chosen.sort_by_key(|(q, _)| std::cmp::Reverse(*q));
    chosen.into_iter().map(|(_, encoding)| encoding).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    const BOTH: [Encoding; 2] = [Encoding::Brotli, Encoding::Gzip];

    fn pick(accept: &[&str]) -> Vec<Encoding> {
        acceptable(&BOTH, accept)
    }

    #[test]
    fn the_site_order_breaks_ties_and_the_client_quality_wins() {
        assert_eq!(pick(&["gzip, br"]), [Encoding::Brotli, Encoding::Gzip]);
        assert_eq!(
            pick(&["br;q=0.5, gzip"]),
            [Encoding::Gzip, Encoding::Brotli]
        );
        assert_eq!(pick(&["gzip"]), [Encoding::Gzip]);
    }

    #[test]
    fn refused_missing_and_wildcard_encodings() {
        assert_eq!(pick(&["br;q=0, gzip"]), [Encoding::Gzip]);
        assert!(pick(&["identity"]).is_empty());
        assert!(pick(&[]).is_empty());
        assert_eq!(pick(&["*"]), BOTH);
        assert_eq!(pick(&["*;q=0, gzip"]), [Encoding::Gzip]);
        assert!(pick(&["br;q=banana"]).is_empty());
    }
}
