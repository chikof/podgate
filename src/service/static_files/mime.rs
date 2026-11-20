//! The built-in `Content-Type` table: the extension decides, nothing is sniffed.

/// The media type of a file with `extension` (lowercase, no dot); `application/octet-stream` for
/// an unknown one. Text types name `charset=utf-8`.
#[must_use]
pub(super) fn content_type(extension: Option<&str>) -> &'static str {
    match extension.unwrap_or_default() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" | "text" | "log" => "text/plain; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" | "xsl" => "application/xml",
        "atom" => "application/atom+xml",
        "rss" => "application/rss+xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "apng" => "image/apng",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "br" => "application/x-brotli",
        "tar" => "application/x-tar",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known_extensions_have_types_and_unknown_ones_are_opaque() {
        assert_eq!(content_type(Some("html")), "text/html; charset=utf-8");
        assert_eq!(content_type(Some("wasm")), "application/wasm");
        assert_eq!(content_type(Some("weird")), "application/octet-stream");
        assert_eq!(content_type(None), "application/octet-stream");
    }
}
