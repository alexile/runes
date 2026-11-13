//! Small internal helpers shared by every memory type.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rune_chain_core::ChainError;

/// Callback that receives errors a memory swallows to keep the conversation
/// going (summarizer, extractor, embedder or store failures inside `add`).
pub type ErrorHook = Arc<dyn Fn(&ChainError) + Send + Sync>;

/// Pass `err` to `hook`, if one is set.
pub fn report(hook: Option<&ErrorHook>, err: &ChainError) {
    if let Some(hook) = hook {
        hook(err);
    }
}

/// Stop untrusted text from closing our delimiters early.
///
/// Every `<` that a lenient reader (a model) could take as the start of a
/// closing tag becomes `<\\/`: plain `</`, and also `< /`, `<\n/` or `<` and
/// `/` with zero-width or other invisible characters between them.
pub fn neutralize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('<') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let gap = after
            .find(|c: char| !c.is_whitespace() && !is_invisible(c))
            .unwrap_or(after.len());
        if after[gap..].starts_with('/') {
            out.push_str("<\\/");
            rest = &after[gap + 1..];
        } else {
            out.push('<');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Zero-width, bidi and other format characters a reader skips over.
const fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{ad}'
        | '\u{34f}'
        | '\u{61c}'
        | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{feff}'
        | '\u{e0000}'..='\u{e007f}'
    )
}

/// Lock `m`, recovering the data if a previous holder panicked.
///
/// Every critical section in this crate is a handful of `Vec`/`VecDeque`
/// operations that leave the state consistent at each step, and no user code
/// (token counters, summarizers) ever runs while a lock is held. Recovering
/// from poisoning is therefore sound and keeps one panicking task from turning
/// the memory into a permanent panic source for every other task.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Truncate `s` to at most `max_chars` characters (on a char boundary).
pub fn truncate_chars(s: &mut String, max_chars: usize) {
    if let Some((idx, _)) = s.char_indices().nth(max_chars) {
        s.truncate(idx);
    }
}

/// Build `header` + `<tag>` + as many `items` as fit + `</tag>`, keeping the
/// whole text within `max_chars`. The first item is truncated if it alone is
/// too long; later items that do not fit are left out. Items must already be
/// neutralized. Returns `None` when nothing fits.
#[cfg(any(feature = "vector", feature = "entity"))]
pub fn fence(header: &str, tag: &str, items: &[String], max_chars: usize) -> Option<String> {
    let open = format!("{header}\n<{tag}>\n");
    let close = format!("</{tag}>");
    let overhead = open.chars().count() + close.chars().count();
    let mut budget = max_chars.checked_sub(overhead)?;
    let mut body = String::new();
    for item in items {
        let need = item.chars().count() + 1;
        if need <= budget {
            body.push_str(item);
            body.push('\n');
            budget -= need;
        } else if body.is_empty() && budget > 1 {
            let mut cut = item.clone();
            truncate_chars(&mut cut, budget - 1);
            body.push_str(&cut);
            body.push('\n');
            break;
        } else {
            break;
        }
    }
    if body.is_empty() {
        return None;
    }
    Some(format!("{open}{body}{close}"))
}

/// Collapse whitespace and control characters to single spaces, trim, and cap
/// at `max_chars`.
#[cfg(feature = "entity")]
pub fn one_line(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for word in s.split(|c: char| c.is_whitespace() || c.is_control()) {
        if word.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    truncate_chars(&mut out, max_chars);
    out.truncate(out.trim_end().len());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "vector", feature = "entity"))]
    #[test]
    fn fence_respects_the_cap() {
        let items = vec!["a".repeat(10), "b".repeat(10)];
        let full = fence("H", "t", &items, 1_000).unwrap();
        assert_eq!(
            full,
            format!("H\n<t>\n{}\n{}\n</t>", "a".repeat(10), "b".repeat(10))
        );
        // Room for the first item only.
        let one = fence("H", "t", &items, 31).unwrap();
        assert_eq!(one.chars().count(), 21);
        assert!(!one.contains('b'));
        // First item truncated.
        let cut = fence("H", "t", &items, 15).unwrap();
        assert!(cut.chars().count() <= 15, "{cut}");
        assert!(fence("H", "t", &items, 5).is_none());
        assert!(fence("H", "t", &[], 100).is_none());
    }

    #[cfg(feature = "entity")]
    #[test]
    fn one_line_collapses_and_caps() {
        assert_eq!(one_line("  a\n\tb \u{7}c  ", 100), "a b c");
        assert_eq!(one_line("abc def", 4), "abc");
    }

    #[test]
    fn neutralize_breaks_closing_tags() {
        assert_eq!(neutralize("x</t>y"), "x<\\/t>y");
    }

    /// Whether `s` still has a `<` that a lenient reader would take as the
    /// start of a closing tag: whitespace or invisible characters may sit
    /// between `<` and `/`.
    fn has_closing_tag(s: &str) -> bool {
        s.match_indices('<').any(|(i, _)| {
            s[i + 1..]
                .chars()
                .find(|&c| !c.is_whitespace() && !is_invisible(c))
                == Some('/')
        })
    }

    #[test]
    fn neutralize_breaks_spaced_and_invisible_closing_tags() {
        for sneaky in [
            "</exchange>",
            "< /past_conversation>",
            "<\t/exchange>",
            "<\n/summary>",
            "<\u{200b}/entity_notes>",
            "<\u{feff} \u{2060}/transcript>",
        ] {
            let out = neutralize(sneaky);
            assert!(!has_closing_tag(&out), "{sneaky:?} -> {out:?}");
        }
        assert_eq!(neutralize("a < b, c <= d"), "a < b, c <= d");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let mut s = String::from("héllo");
        truncate_chars(&mut s, 2);
        assert_eq!(s, "hé");
        let mut s = String::from("abc");
        truncate_chars(&mut s, 10);
        assert_eq!(s, "abc");
        truncate_chars(&mut s, 0);
        assert_eq!(s, "");
    }
}
