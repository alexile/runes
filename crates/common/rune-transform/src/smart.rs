//! Heuristic peeling of layered encodings.

/// Most layers [`smart_decode`] peels.
pub const SMART_DECODE_MAX_DEPTH: usize = 8;

/// One layer peeled by [`smart_decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SmartDecodeStep {
    /// The decoder that produced this layer: `"base64_decode"`,
    /// `"url_decode"` or `"hex_decode"`.
    pub transform: String,
    /// The printable text it produced.
    pub output: String,
}

/// Peel layered base64, URL and hex encodings off `input`.
///
/// Each round tries base64 (either alphabet), then percent-decoding, then
/// hex, and keeps the first result that is different, valid UTF-8 and
/// printable. It stops when nothing changes or after
/// [`SMART_DECODE_MAX_DEPTH`] layers, and returns the layers in order.
///
/// ```
/// use rune_transform::smart_decode;
///
/// // base64( url( "name=John Doe" ) )
/// let steps = smart_decode("bmFtZSUzREpvaG4lMjBEb2U=");
/// let names: Vec<&str> = steps.iter().map(|s| s.transform.as_str()).collect();
/// assert_eq!(names, ["base64_decode", "url_decode"]);
/// assert_eq!(steps[1].output, "name=John Doe");
/// ```
#[must_use]
pub fn smart_decode(input: &str) -> Vec<SmartDecodeStep> {
    let mut steps: Vec<SmartDecodeStep> = Vec::new();
    for _ in 0..SMART_DECODE_MAX_DEPTH {
        let current = steps.last().map_or(input, |step| step.output.as_str());
        let Some((transform, output)) = try_one_layer(current) else {
            break;
        };
        steps.push(SmartDecodeStep {
            transform: transform.to_owned(),
            output,
        });
    }
    steps
}

/// A layer decoder: `Some(text)` when the input looks like its encoding.
type LayerFn = fn(&str) -> Option<String>;

/// The first layer decoder that yields different printable text.
fn try_one_layer(text: &str) -> Option<(&'static str, String)> {
    let layers: [(&'static str, LayerFn); 3] = [
        ("base64_decode", try_base64),
        ("url_decode", try_url),
        ("hex_decode", try_hex),
    ];
    layers.iter().find_map(|&(name, decode)| {
        decode(text)
            .filter(|decoded| decoded != text && is_printable(decoded))
            .map(|decoded| (name, decoded))
    })
}

/// Base64 (standard or URL-safe), when the text only uses its alphabet.
fn try_base64(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let alphabet_only = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '-' | '_' | '='));
    if trimmed.len() < 4 || !alphabet_only {
        return None;
    }
    String::from_utf8(rune_base64::decode(trimmed).ok()?).ok()
}

/// Percent-decoding, when the text has a `%`.
fn try_url(text: &str) -> Option<String> {
    if !text.contains('%') {
        return None;
    }
    rune_url_encode::decode(text).ok()
}

/// Hex, when the text is an even run of hex digits.
fn try_hex(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() < 2 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    String::from_utf8(rune_hex::decode(trimmed).ok()?).ok()
}

/// Non-empty and free of control characters other than `\t`, `\n`, `\r`.
fn is_printable(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_layers() {
        let inner = "name=John Doe";
        let url = rune_url_encode::encode(inner);
        let outer = rune_base64::encode(url.as_bytes());
        let steps = smart_decode(&outer);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].transform, "base64_decode");
        assert_eq!(steps[0].output, url);
        assert_eq!(steps[1].transform, "url_decode");
        assert_eq!(steps[1].output, inner);
    }

    #[test]
    fn hex_layer_and_plain_text() {
        let steps = smart_decode("48656c6c6f2c20776f726c6421");
        assert_eq!(
            steps.first().map(|s| s.output.as_str()),
            Some("Hello, world!")
        );
        assert_eq!(smart_decode("plain text, nothing to peel"), Vec::new());
        assert_eq!(smart_decode(""), Vec::new());
    }

    #[test]
    fn depth_is_bounded() {
        let mut value = "a b".to_owned();
        for _ in 0..20 {
            value = rune_url_encode::encode(&value);
        }
        assert_eq!(smart_decode(&value).len(), SMART_DECODE_MAX_DEPTH);
    }
}
