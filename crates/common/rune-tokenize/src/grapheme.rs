//! Dependency-free approximation of extended grapheme cluster boundaries.
//!
//! Truncation and chunking only ever cut text at a position where
//! [`is_boundary`] holds, so no cut lands inside a UTF-8 sequence, between a
//! base character and its combining marks, inside a CR LF pair, inside an emoji
//! ZWJ sequence or modifier sequence, or between the two halves of a flag.
//!
//! This is a compact subset of the UAX #29 rules (GB3–GB5, GB9, GB11, GB12/13)
//! with the combining-mark ranges of the common scripts. It never cuts inside a
//! `char`; at worst it allows a cut a full segmenter would not.

use alloc::vec::Vec;

const ZWJ: char = '\u{200D}';

/// `true` for characters that attach to the preceding character
/// (combining marks, variation selectors, emoji modifiers, joiners, tags).
pub fn is_extend(c: char) -> bool {
    let u = u32::from(c);
    matches!(
        u,
        0x0300..=0x036F
            | 0x0483..=0x0489
            | 0x0591..=0x05BD
            | 0x05BF
            | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5
            | 0x05C7
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0670
            | 0x06D6..=0x06DC
            | 0x06DF..=0x06E4
            | 0x06E7..=0x06E8
            | 0x06EA..=0x06ED
            | 0x0D81..=0x0D83
            | 0x0DCA
            | 0x0DCF..=0x0DDF
            | 0x0DF2..=0x0DF3
            | 0x0E31
            | 0x0E34..=0x0E3A
            | 0x0E47..=0x0E4E
            | 0x0EB1
            | 0x0EB4..=0x0EBC
            | 0x0EC8..=0x0ECE
            | 0x1160..=0x11FF
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x200C..=0x200D
            | 0x20D0..=0x20FF
            | 0x302A..=0x302F
            | 0x3099..=0x309A
            | 0xFE00..=0xFE0F
            | 0xFE20..=0xFE2F
            | 0x1F3FB..=0x1F3FF
            | 0xE0020..=0xE007F
            | 0xE0100..=0xE01EF
    ) || is_indic_mark(u)
}

/// Devanagari through Malayalam share the ISCII-derived block layout, so their
/// signs, vowel signs, nukta and virama sit at the same offsets in each block.
const fn is_indic_mark(u: u32) -> bool {
    if u < 0x0900 || u > 0x0D7F {
        return false;
    }
    matches!(
        u & 0x7F,
        0x00..=0x03 | 0x3A..=0x3C | 0x3E..=0x4F | 0x51..=0x57 | 0x62..=0x63
    )
}

/// Rough `Extended_Pictographic`: the emoji and pictograph blocks.
const fn is_pictographic(c: char) -> bool {
    matches!(
        c,
        '\u{00A9}' | '\u{00AE}' | '\u{203C}'..='\u{3299}' | '\u{1F000}'..='\u{1FAFF}'
    )
}

const fn is_regional_indicator(c: char) -> bool {
    matches!(c, '\u{1F1E6}'..='\u{1F1FF}')
}

const fn is_control(c: char) -> bool {
    matches!(c, '\r' | '\n') || c.is_ascii_control()
}

/// `true` if `text` may be cut at byte offset `i` without splitting a
/// character or (approximately) a grapheme cluster. `0` and `text.len()` are
/// always boundaries; offsets past the end never are.
pub fn is_boundary(text: &str, i: usize) -> bool {
    if i == 0 || i == text.len() {
        return true;
    }
    if !text.is_char_boundary(i) {
        return false;
    }
    let (before, after) = text.split_at(i);
    let (Some(prev), Some(next)) = (before.chars().next_back(), after.chars().next()) else {
        return true;
    };
    let ri_run = if is_regional_indicator(prev) && is_regional_indicator(next) {
        before
            .chars()
            .rev()
            .take_while(|&c| is_regional_indicator(c))
            .count()
    } else {
        0
    };
    breaks_between(prev, next, ri_run)
}

/// The pair rules; `ri_run` is the number of regional indicators ending at
/// `prev` (only consulted when both sides are regional indicators).
fn breaks_between(prev: char, next: char, ri_run: usize) -> bool {
    if prev == '\r' && next == '\n' {
        return false;
    }
    if is_control(prev) || is_control(next) || next.is_whitespace() {
        return true;
    }
    if is_extend(next) || (prev == ZWJ && is_pictographic(next)) {
        return false;
    }
    if is_regional_indicator(prev) && is_regional_indicator(next) {
        return ri_run.is_multiple_of(2);
    }
    true
}

/// Largest boundary `<= i` (clamped to `text.len()`).
pub fn floor(text: &str, i: usize) -> usize {
    let mut i = i.min(text.len());
    while !is_boundary(text, i) {
        i -= 1;
    }
    i
}

/// All interior boundaries of `text` (excluding 0, including `text.len()`),
/// ascending.
pub fn boundaries(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut ri_run = 0usize;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        ri_run = if is_regional_indicator(c) {
            ri_run + 1
        } else {
            0
        };
        let end = i + c.len_utf8();
        match chars.peek() {
            Some(&(_, next)) if !breaks_between(c, next, ri_run) => {}
            _ => out.push(end),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combining_mark_stays_attached() {
        let s = "e\u{301}x";
        assert!(!is_boundary(s, 1));
        assert!(is_boundary(s, 3));
        assert_eq!(floor(s, 1), 0);
    }

    #[test]
    fn crlf_is_one_cluster() {
        assert!(!is_boundary("a\r\nb", 2));
        assert!(is_boundary("a\r\nb", 3));
    }

    #[test]
    fn zwj_sequence_is_not_split() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert_eq!(boundaries(family), [family.len()]);
    }

    #[test]
    fn flags_split_in_pairs() {
        let flags = "\u{1F1EB}\u{1F1F7}\u{1F1E9}\u{1F1EA}"; // FR DE
        assert_eq!(boundaries(flags), [8, 16]);
    }

    #[test]
    fn devanagari_vowel_sign_attaches() {
        let s = "\u{0915}\u{093F}"; // कि
        assert_eq!(boundaries(s), [s.len()]);
    }
}
