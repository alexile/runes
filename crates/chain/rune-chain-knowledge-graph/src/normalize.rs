//! Text clean-up for names coming out of an LLM.
//!
//! Everything here treats its input as untrusted: control characters are
//! dropped, whitespace is collapsed, and nothing allocates more than a small
//! multiple of the (already capped) input.

/// Words ignored when matching a query against entity names.
const STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "did", "do", "does", "for", "from", "has",
    "have", "how", "in", "is", "it", "of", "on", "or", "that", "the", "this", "to", "was", "were",
    "what", "when", "where", "which", "who", "whom", "why", "with",
];

/// Collapse runs of whitespace into one space, drop control characters and
/// trim the ends. This is the display form of a name.
pub fn clean_display(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_space = false;
    for c in raw.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
        } else if !c.is_control() {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    out
}

/// The resolution key of an entity name: lowercase alphanumeric tokens
/// joined by single spaces. `"Acme Corp."`, `"acme  corp"` and `"ACME-Corp"`
/// all map to `"acme corp"`.
///
/// Returns an empty string when the name has no alphanumeric characters.
pub fn entity_key(name: &str) -> String {
    tokens(name).collect::<Vec<_>>().join(" ")
}

/// Lowercase alphanumeric tokens of `text`, in order.
pub fn tokens(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_lowercase)
}

/// Whether `token` is too common to identify an entity on its own.
pub fn is_stopword(token: &str) -> bool {
    STOPWORDS.binary_search(&token).is_ok()
}

/// Normalise a relation or type label to `lower_snake_case`.
///
/// Alphanumeric characters are lowercased, whitespace, `-`, `.` and `/`
/// become `_`, everything else is dropped, and repeated or edge underscores
/// are removed. Returns an empty string when nothing usable is left.
pub fn label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if (c.is_whitespace() || matches!(c, '_' | '-' | '.' | '/'))
            && !out.is_empty()
            && !out.ends_with('_')
        {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Cut `s` to at most `max_chars` characters, on a character boundary.
pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    s.char_indices().nth(max_chars).map_or(s, |(i, _)| &s[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopwords_are_sorted_for_binary_search() {
        assert!(STOPWORDS.windows(2).all(|w| w[0] < w[1]));
        assert!(is_stopword("the"));
        assert!(!is_stopword("acme"));
    }

    #[test]
    fn display_form_collapses_whitespace_and_drops_controls() {
        assert_eq!(clean_display("  Acme \n\t Corp\u{0007} "), "Acme Corp");
        assert_eq!(clean_display("\u{0000}"), "");
    }

    #[test]
    fn keys_ignore_case_and_punctuation() {
        assert_eq!(entity_key("Acme Corp."), "acme corp");
        assert_eq!(entity_key("ACME-corp"), "acme corp");
        assert_eq!(entity_key("  acme   corp "), "acme corp");
        assert_eq!(entity_key("Zoë Ångström"), "zoë ångström");
        assert_eq!(entity_key("..."), "");
    }

    #[test]
    fn labels_become_snake_case() {
        assert_eq!(label("Works At"), "works_at");
        assert_eq!(label("is-capital-of"), "is_capital_of");
        assert_eq!(label("__born__in__"), "born_in");
        assert_eq!(label("founded!"), "founded");
        assert_eq!(label("<>"), "");
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_chars("héllo", 2), "hé");
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(truncate_chars("abc", 0), "");
    }
}
