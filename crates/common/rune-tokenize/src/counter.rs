//! Token counting: the pluggable [`TokenCounter`] trait and the built-in
//! heuristic [`TokenizerProfile`]s.

use core::fmt;
use core::str::FromStr;

use crate::chat::ChatOverhead;

/// Anything that can count the tokens in a string.
///
/// Every budget, truncation and chunking helper in this crate is generic over
/// a `TokenCounter`, so an exact tokenizer (tiktoken, a `tokenizers` BPE, a
/// provider's count endpoint behind a cache, …) can replace the heuristics.
/// Closures `Fn(&str) -> usize` implement it, and so does every
/// [`TokenizerProfile`].
///
/// Counters should be roughly monotone: a longer prefix of a text should not
/// count fewer tokens than a shorter one. The helpers rely on that for their
/// binary searches, and re-check the final result against the counter.
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{TokenCounter, TokenizerProfile};
///
/// // Plug in any exact tokenizer as a closure:
/// let words = |s: &str| s.split_whitespace().count();
/// assert_eq!(words.count_tokens("one two three"), 3);
///
/// // Or use a model-family heuristic:
/// let gpt4o = TokenizerProfile::O200k;
/// assert!(gpt4o.count_tokens("Hello, world!") >= 3);
/// ```
pub trait TokenCounter {
    /// Number of tokens `text` encodes to.
    fn count_tokens(&self, text: &str) -> usize;
}

impl<F> TokenCounter for F
where
    F: Fn(&str) -> usize + ?Sized,
{
    fn count_tokens(&self, text: &str) -> usize {
        self(text)
    }
}

/// A heuristic token counter tuned for one tokenizer family.
///
/// None of these ship a vocabulary: they classify text into runs (ASCII words,
/// digit groups, punctuation, whitespace, CJK, other scripts, emoji and other
/// symbols) and charge each run what that family's BPE typically spends on it.
/// They are meant for budgeting and lean towards over-counting; for exact
/// numbers plug a real tokenizer in through [`TokenCounter`].
///
/// [`TokenizerProfile::Simple`] (the default) is the crate's original rule,
/// `⌈chars / 4⌉`, identical to [`estimate`](crate::estimate).
///
/// # Example
///
/// ```rust
/// use rune_tokenize::{TokenCounter, TokenizerProfile};
///
/// let profile = TokenizerProfile::for_model("claude-sonnet-4-5").unwrap_or_default();
/// assert_eq!(profile, TokenizerProfile::Claude);
///
/// // CJK costs far more per character than English prose:
/// let en = profile.count_tokens("hello world");
/// let zh = profile.count_tokens("你好世界你好世界");
/// assert!(zh > en);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TokenizerProfile {
    /// `⌈chars / 4⌉`, the original rule of thumb. Fast and model-agnostic.
    #[default]
    Simple,
    /// `cl100k_base`: GPT-4, GPT-3.5-turbo, `text-embedding-3-*`.
    Cl100k,
    /// `o200k_base`: GPT-4o, GPT-4.1, GPT-5, o-series reasoning models.
    O200k,
    /// Anthropic Claude models. The tokenizer is not public; these figures
    /// are deliberately conservative (about 3.5 English chars per token).
    Claude,
    /// Llama 3 / 4 (128k tiktoken-style vocabulary).
    Llama3,
    /// Llama 2, Mistral 7B / Mixtral and other 32k `SentencePiece`
    /// vocabularies (single-digit numbers, byte fallback for rare characters).
    Llama2,
}

/// Costs in thousandths of a token.
struct Params {
    /// Characters of an ASCII/Latin word covered by its first token.
    word_head: usize,
    /// Cost of each further word character.
    word_tail: usize,
    /// Digits merged into one token.
    digit_group: usize,
    /// Cost per ASCII punctuation character (a run costs at least one token).
    punct: usize,
    /// Cost per newline inside a whitespace run.
    newline: usize,
    /// Cost per other whitespace character inside a run.
    space: usize,
    /// Cost per CJK / Hangul / kana / fullwidth character.
    cjk: usize,
    /// Cost per character of Indic, Thai, Lao, Tibetan, Myanmar, Khmer.
    complex: usize,
    /// Cost per character of other alphabets (Cyrillic, Greek, Arabic, …).
    other_letter: usize,
    /// Cost per UTF-8 byte of emoji, symbols and combining marks.
    symbol_byte: usize,
}

const CL100K: Params = Params {
    word_head: 6,
    word_tail: 300,
    digit_group: 3,
    punct: 500,
    newline: 500,
    space: 125,
    cjk: 1050,
    complex: 1000,
    other_letter: 450,
    symbol_byte: 500,
};

const O200K: Params = Params {
    word_head: 7,
    word_tail: 280,
    digit_group: 3,
    punct: 500,
    newline: 500,
    space: 125,
    cjk: 750,
    complex: 450,
    other_letter: 300,
    symbol_byte: 400,
};

const CLAUDE: Params = Params {
    word_head: 5,
    word_tail: 330,
    digit_group: 3,
    punct: 550,
    newline: 500,
    space: 250,
    cjk: 1100,
    complex: 900,
    other_letter: 450,
    symbol_byte: 500,
};

const LLAMA3: Params = Params {
    word_head: 6,
    word_tail: 300,
    digit_group: 3,
    punct: 500,
    newline: 500,
    space: 125,
    cjk: 900,
    complex: 700,
    other_letter: 350,
    symbol_byte: 450,
};

const LLAMA2: Params = Params {
    word_head: 5,
    word_tail: 400,
    digit_group: 1,
    punct: 700,
    newline: 1000,
    space: 500,
    cjk: 1600,
    complex: 1500,
    other_letter: 600,
    symbol_byte: 900,
};

impl TokenizerProfile {
    /// Every built-in profile, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Simple,
        Self::Cl100k,
        Self::O200k,
        Self::Claude,
        Self::Llama3,
        Self::Llama2,
    ];

    /// Pick a profile from a model identifier such as `gpt-4o-mini`,
    /// `claude-opus-4-1`, `meta-llama/Llama-3.1-8B` or `mistral-7b-instruct`.
    /// Matching is case-insensitive; returns `None` for unknown families.
    ///
    /// ```rust
    /// use rune_tokenize::TokenizerProfile;
    ///
    /// assert_eq!(TokenizerProfile::for_model("GPT-4o"), Some(TokenizerProfile::O200k));
    /// assert_eq!(TokenizerProfile::for_model("gpt-4-turbo"), Some(TokenizerProfile::Cl100k));
    /// assert_eq!(TokenizerProfile::for_model("Meta-Llama-3-8B"), Some(TokenizerProfile::Llama3));
    /// assert_eq!(TokenizerProfile::for_model("my-model"), None);
    /// ```
    #[must_use]
    pub fn for_model(model: &str) -> Option<Self> {
        let has = |needle: &str| contains_ignore_ascii_case(model, needle);
        let starts = |prefix: &str| {
            model
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        };
        if has("claude") {
            Some(Self::Claude)
        } else if has("gpt-4o")
            || has("gpt-4.1")
            || has("gpt-4.5")
            || has("gpt-5")
            || has("gpt-oss")
            || starts("o1")
            || starts("o3")
            || starts("o4")
        {
            Some(Self::O200k)
        } else if has("gpt-4") || has("gpt-3.5") || has("text-embedding") {
            Some(Self::Cl100k)
        } else if has("llama-3") || has("llama3") || has("llama-4") || has("llama4") {
            Some(Self::Llama3)
        } else if has("llama-2") || has("llama2") || has("mistral") || has("mixtral") {
            Some(Self::Llama2)
        } else {
            None
        }
    }

    /// Short lowercase name, accepted back by [`FromStr`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Cl100k => "cl100k",
            Self::O200k => "o200k",
            Self::Claude => "claude",
            Self::Llama3 => "llama3",
            Self::Llama2 => "llama2",
        }
    }

    /// Typical chat-format overhead for this family (role markers, separators,
    /// reply priming). See [`count_chat`](crate::count_chat).
    #[must_use]
    pub const fn chat_overhead(self) -> ChatOverhead {
        match self {
            Self::Simple => ChatOverhead::new(4, 1, 3),
            Self::Cl100k | Self::O200k => ChatOverhead::OPENAI,
            Self::Claude => ChatOverhead::new(5, 1, 3),
            Self::Llama3 => ChatOverhead::new(4, 1, 5),
            Self::Llama2 => ChatOverhead::new(6, 1, 1),
        }
    }

    const fn params(self) -> Option<&'static Params> {
        match self {
            Self::Simple => None,
            Self::Cl100k => Some(&CL100K),
            Self::O200k => Some(&O200K),
            Self::Claude => Some(&CLAUDE),
            Self::Llama3 => Some(&LLAMA3),
            Self::Llama2 => Some(&LLAMA2),
        }
    }
}

impl TokenCounter for TokenizerProfile {
    fn count_tokens(&self, text: &str) -> usize {
        self.params()
            .map_or_else(|| text.chars().count().div_ceil(4), |p| heuristic(text, p))
    }
}

impl fmt::Display for TokenizerProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when a string names no known [`TokenizerProfile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProfileError;

impl fmt::Display for ParseProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unknown tokenizer profile (expected simple, cl100k, o200k, claude, llama3, llama2 or a known model name)",
        )
    }
}

impl core::error::Error for ParseProfileError {}

impl FromStr for TokenizerProfile {
    type Err = ParseProfileError;

    /// Accepts a profile [`name`](TokenizerProfile::name) (also `cl100k_base`,
    /// `o200k_base`) or anything [`for_model`](TokenizerProfile::for_model)
    /// recognises.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        for p in Self::ALL {
            if s.eq_ignore_ascii_case(p.name()) {
                return Ok(p);
            }
        }
        if s.eq_ignore_ascii_case("cl100k_base") {
            return Ok(Self::Cl100k);
        }
        if s.eq_ignore_ascii_case("o200k_base") {
            return Ok(Self::O200k);
        }
        Self::for_model(s).ok_or(ParseProfileError)
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Word,
    Digit,
    Punct,
    Space,
    Cjk,
    Complex,
    OtherLetter,
    Symbol,
}

fn classify(c: char) -> Class {
    if c.is_ascii_alphabetic() {
        return Class::Word;
    }
    if c.is_ascii_digit() {
        return Class::Digit;
    }
    if c.is_ascii_punctuation() {
        return Class::Punct;
    }
    if c.is_whitespace() {
        return Class::Space;
    }
    let u = u32::from(c);
    match u {
        0x00C0..=0x024F if c.is_alphabetic() => Class::Word,
        0x1100..=0x11FF
        | 0x2E80..=0x9FFF
        | 0xA960..=0xA97F
        | 0xAC00..=0xD7FF
        | 0xF900..=0xFAFF
        | 0xFF00..=0xFFEF
        | 0x20000..=0x3FFFF => Class::Cjk,
        0x0900..=0x0DFF | 0x0E00..=0x0FFF | 0x1000..=0x109F | 0x1780..=0x17FF => Class::Complex,
        _ if c.is_alphabetic() || c.is_numeric() => Class::OtherLetter,
        _ => Class::Symbol,
    }
}

fn heuristic(text: &str, p: &Params) -> usize {
    let mut milli: usize = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let class = classify(c);
        let cost = match class {
            Class::Word | Class::Digit | Class::Punct | Class::Space => {
                let mut len = 1usize;
                let mut newlines = usize::from(c == '\n');
                while let Some(&n) = chars.peek() {
                    if classify(n) != class {
                        break;
                    }
                    len += 1;
                    newlines += usize::from(n == '\n');
                    chars.next();
                }
                match class {
                    Class::Word => 1000usize.saturating_add(
                        len.saturating_sub(p.word_head).saturating_mul(p.word_tail),
                    ),
                    Class::Digit => len.div_ceil(p.digit_group).saturating_mul(1000),
                    Class::Punct => len.saturating_mul(p.punct).max(1000),
                    _ if len == 1 && c == ' ' => 0,
                    _ => newlines
                        .saturating_mul(p.newline)
                        .saturating_add((len - newlines).saturating_mul(p.space))
                        .max(1000),
                }
            }
            Class::Cjk => p.cjk,
            Class::Complex => p.complex,
            Class::OtherLetter => p.other_letter,
            Class::Symbol => c.len_utf8() * p.symbol_byte,
        };
        milli = milli.saturating_add(cost);
    }
    milli.div_ceil(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_matches_legacy_estimate() {
        for s in ["", "a", "hell", "hello", "hello world", "日本語"] {
            assert_eq!(TokenizerProfile::Simple.count_tokens(s), crate::estimate(s));
        }
    }

    #[test]
    fn english_sentence_is_close_to_cl100k() {
        // cl100k_base encodes this to 10 tokens.
        let n =
            TokenizerProfile::Cl100k.count_tokens("The quick brown fox jumps over the lazy dog.");
        assert!((9..=12).contains(&n), "{n}");
        // "Hello", ",", " world", "!"
        assert_eq!(TokenizerProfile::Cl100k.count_tokens("Hello, world!"), 4);
    }

    #[test]
    fn empty_is_zero_for_every_profile() {
        for p in TokenizerProfile::ALL {
            assert_eq!(p.count_tokens(""), 0);
        }
    }

    #[test]
    fn digits_group_by_family() {
        assert_eq!(TokenizerProfile::Cl100k.count_tokens("123456"), 2);
        assert_eq!(TokenizerProfile::Llama2.count_tokens("123456"), 6);
    }

    #[test]
    fn cjk_costs_more_than_ascii_per_char() {
        let p = TokenizerProfile::Cl100k;
        assert!(p.count_tokens("日本語の文章です") >= 8);
        assert!(p.count_tokens("abcdefgh") <= 3);
    }

    #[test]
    fn indentation_and_newlines_cost_tokens() {
        let p = TokenizerProfile::Cl100k;
        assert!(p.count_tokens("a\n\n\n\nb") > p.count_tokens("a b"));
    }

    #[test]
    fn model_lookup() {
        use TokenizerProfile as P;
        assert_eq!(P::for_model("claude-3-5-haiku"), Some(P::Claude));
        assert_eq!(P::for_model("o3-mini"), Some(P::O200k));
        assert_eq!(P::for_model("gpt-3.5-turbo"), Some(P::Cl100k));
        assert_eq!(P::for_model("text-embedding-3-small"), Some(P::Cl100k));
        assert_eq!(P::for_model("Mixtral-8x7B"), Some(P::Llama2));
        assert_eq!(P::for_model("llama4-scout"), Some(P::Llama3));
        assert_eq!(P::for_model(""), None);
    }

    #[test]
    fn parse_round_trips() {
        for p in TokenizerProfile::ALL {
            assert_eq!(p.name().parse::<TokenizerProfile>(), Ok(p));
            assert_eq!(alloc::format!("{p}"), p.name());
        }
        assert_eq!("O200K_BASE".parse(), Ok(TokenizerProfile::O200k));
        assert_eq!("gpt-4o".parse(), Ok(TokenizerProfile::O200k));
        assert_eq!("nope".parse::<TokenizerProfile>(), Err(ParseProfileError));
    }

    #[test]
    fn closures_are_counters() {
        let bytes = |s: &str| s.len();
        assert_eq!(bytes.count_tokens("abc"), 3);
        let dynamic: &dyn TokenCounter = &TokenizerProfile::Simple;
        assert_eq!(dynamic.count_tokens("abcd"), 1);
    }
}
