//! Text normalisation and shingling.
//!
//! A *shingle* is a run of `k` consecutive tokens. Hashing shingles rather
//! than single tokens keeps word order in the signature, so "admin login
//! failed" and "login failed admin" no longer look identical.

use crate::Error;
use crate::hash::Fnv;

/// What a token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TokenKind {
    /// Maximal runs of Unicode alphanumeric characters. Punctuation and
    /// whitespace separate tokens and are dropped.
    #[default]
    Words,
    /// Single characters, after whitespace runs collapse to one space.
    /// Suits short or non-space-delimited text.
    Chars,
}

/// How [`shingles`] turns text into features.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShingleOptions {
    /// Token unit.
    pub kind: TokenKind,
    /// Tokens per shingle (`k`). Must be at least 1.
    pub size: usize,
    /// Lowercase tokens before hashing.
    pub lowercase: bool,
    /// Treat the input as HTML: drop tags, comments and the contents of
    /// `<script>` and `<style>`, and decode common entities. Only the
    /// visible text is shingled.
    pub strip_html: bool,
}

impl Default for ShingleOptions {
    /// Word 3-shingles, lowercased, HTML untouched.
    fn default() -> Self {
        Self {
            kind: TokenKind::Words,
            size: 3,
            lowercase: true,
            strip_html: false,
        }
    }
}

impl ShingleOptions {
    /// Sets [`ShingleOptions::kind`].
    #[must_use]
    pub const fn with_kind(mut self, kind: TokenKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets [`ShingleOptions::size`].
    #[must_use]
    pub const fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Sets [`ShingleOptions::lowercase`].
    #[must_use]
    pub const fn with_lowercase(mut self, lowercase: bool) -> Self {
        self.lowercase = lowercase;
        self
    }

    /// Sets [`ShingleOptions::strip_html`].
    #[must_use]
    pub const fn with_strip_html(mut self, strip_html: bool) -> Self {
        self.strip_html = strip_html;
        self
    }

    pub(crate) const fn validate(&self) -> Result<(), Error> {
        if self.size == 0 {
            return Err(Error::InvalidParameter {
                name: "size",
                reason: "shingle size must be at least 1",
            });
        }
        Ok(())
    }
}

/// Hashes every `k`-token shingle of `text` to a 64-bit feature.
///
/// Shingles are returned in document order, duplicates included, so
/// [`SimHasher`](crate::SimHasher) can weight repeated shingles. A text
/// with fewer than `k` tokens yields a single shingle of all its tokens;
/// a text with no tokens yields nothing.
///
/// ```
/// use rune_simhash::{ShingleOptions, shingles};
///
/// let s = shingles("The quick brown fox", &ShingleOptions::default().with_size(2))?;
/// assert_eq!(s.len(), 3); // "the quick", "quick brown", "brown fox"
/// # Ok::<(), rune_simhash::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::InvalidParameter`] if [`ShingleOptions::size`] is 0.
pub fn shingles(text: &str, options: &ShingleOptions) -> Result<Vec<u64>, Error> {
    options.validate()?;
    let stripped;
    let text = if options.strip_html {
        stripped = strip_html(text);
        stripped.as_str()
    } else {
        text
    };
    let tokens = tokenize(text, options);
    Ok(hash_windows(&tokens, options.size))
}

fn tokenize(text: &str, options: &ShingleOptions) -> Vec<String> {
    let fold = |s: &str| {
        if options.lowercase {
            s.to_lowercase()
        } else {
            s.to_owned()
        }
    };
    match options.kind {
        TokenKind::Words => text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(fold)
            .collect(),
        TokenKind::Chars => {
            let mut out = Vec::new();
            let mut pending_space = false;
            for word in text.split_whitespace() {
                if pending_space {
                    out.push(" ".to_owned());
                }
                let word = fold(word);
                out.extend(word.chars().map(String::from));
                pending_space = true;
            }
            out
        }
    }
}

fn hash_windows(tokens: &[String], k: usize) -> Vec<u64> {
    let hash = |window: &[String]| {
        let mut h = Fnv::new();
        for t in window {
            h.write(t.as_bytes());
            // 0xFF never occurs in UTF-8, so it separates tokens unambiguously.
            h.write(&[0xFF]);
        }
        h.finish()
    };
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < k {
        return vec![hash(tokens)];
    }
    tokens.windows(k).map(hash).collect()
}

/// Reduces HTML to its visible text.
///
/// This is a forgiving scanner, not a parser: it never fails, drops
/// everything between `<` and `>`, skips comments and the bodies of
/// `<script>`/`<style>`, and decodes the entities that matter for
/// tokenisation (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&#39;`,
/// `&nbsp;` and numeric references). Tags become whitespace so adjacent
/// cells or list items do not merge into one word.
///
/// ```
/// let text = rune_simhash::strip_html("<p>Not&nbsp;found</p><script>x()</script>");
/// assert_eq!(text.split_whitespace().collect::<Vec<_>>(), ["Not", "found"]);
/// ```
#[must_use]
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(lt) = rest.find(['<', '&']) {
        out.push_str(&rest[..lt]);
        rest = &rest[lt..];
        if rest.starts_with('&') {
            let (decoded, used) = decode_entity(rest);
            out.push_str(decoded.as_deref().unwrap_or("&"));
            rest = &rest[used..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            out.push(' ');
            continue;
        }
        let tag_end = rest.find('>').map_or(rest.len(), |i| i + 1);
        let tag = &rest[..tag_end];
        rest = &rest[tag_end..];
        out.push(' ');
        for raw in ["script", "style"] {
            if opens(tag, raw) {
                rest = skip_raw_text(rest, raw);
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether `tag` (e.g. `<script src=x>`) opens element `name`.
fn opens(tag: &str, name: &str) -> bool {
    let inner = &tag[1..];
    inner.len() >= name.len()
        && inner.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes())
        && inner[name.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_ascii_whitespace())
}

/// Skips past the closing `</name ...>` of a raw-text element.
fn skip_raw_text<'a>(rest: &'a str, name: &str) -> &'a str {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while let Some(off) = rest[i..].find("</") {
        let start = i + off + 2;
        let end = start + name.len();
        if end <= bytes.len() && bytes[start..end].eq_ignore_ascii_case(name.as_bytes()) {
            return rest[end..].find('>').map_or("", |gt| &rest[end + gt + 1..]);
        }
        i = start;
    }
    ""
}

/// Decodes the entity at the start of `s`. Returns the text and the bytes
/// consumed (1 when it is not a recognised entity).
fn decode_entity(s: &str) -> (Option<String>, usize) {
    let Some(semi) = s.get(..s.len().min(12)).and_then(|w| w.find(';')) else {
        return (None, 1);
    };
    let name = &s[1..semi];
    let decoded = match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => name.strip_prefix('#').and_then(|num| {
            let code = num
                .strip_prefix(['x', 'X'])
                .map_or_else(|| num.parse().ok(), |hex| u32::from_str_radix(hex, 16).ok());
            code.and_then(char::from_u32)
        }),
    };
    decoded.map_or((None, 1), |c| (Some(c.to_string()), semi + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        tokenize(text, &ShingleOptions::default())
    }

    #[test]
    fn word_tokens_fold_case_and_drop_punctuation() {
        assert_eq!(
            words("Hello, WORLD! 404—Not_found"),
            ["hello", "world", "404", "not", "found"]
        );
    }

    #[test]
    fn char_tokens_collapse_whitespace() {
        let opts = ShingleOptions::default().with_kind(TokenKind::Chars);
        assert_eq!(tokenize("  aB \n c ", &opts), ["a", "b", " ", "c"]);
    }

    #[test]
    fn shingle_counts() {
        let o = ShingleOptions::default();
        assert_eq!(shingles("a b c d e", &o).unwrap().len(), 3);
        assert_eq!(shingles("a b", &o).unwrap().len(), 1);
        assert_eq!(shingles("  ,, ", &o).unwrap(), [] as [u64; 0]);
        assert!(shingles("a", &o.with_size(0)).is_err());
    }

    #[test]
    fn token_boundaries_are_unambiguous() {
        let o = ShingleOptions::default().with_size(2);
        assert_ne!(shingles("ab c", &o).unwrap(), shingles("a bc", &o).unwrap());
    }

    #[test]
    fn order_matters() {
        let o = ShingleOptions::default();
        assert_ne!(
            shingles("admin login failed", &o).unwrap(),
            shingles("login failed admin", &o).unwrap()
        );
    }

    #[test]
    fn strips_tags_scripts_comments_and_entities() {
        let html = "<html><head><style>p { color: red }</style><SCRIPT type=x>if (a<b) go();</script \
                    ></head><body><!-- hidden --><p>Page&nbsp;not&#32;found &amp; &#x41;&bogus;</p>\
                    <td>a</td><td>b</td></body>";
        let text = strip_html(html);
        assert_eq!(
            text.split_whitespace().collect::<Vec<_>>(),
            ["Page", "not", "found", "&", "A&bogus;", "a", "b"]
        );
    }

    #[test]
    fn strip_html_handles_truncated_input() {
        assert_eq!(strip_html("a <b").trim(), "a");
        assert_eq!(strip_html("a <!-- b").trim(), "a");
        assert_eq!(strip_html("a <script>b").trim(), "a");
        assert_eq!(strip_html("&").trim(), "&");
        assert_eq!(strip_html("&#xFFFFFFFF;"), "&#xFFFFFFFF;");
        assert_eq!(strip_html("<scripty>x</scripty>").trim(), "x");
    }
}
