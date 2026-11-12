use std::fmt;

use crate::error::LoadError;

/// Longest accepted pattern, in characters.
const MAX_PATTERN_CHARS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    /// `?`: one character other than `/`.
    One,
    /// `[...]`: one character other than `/` in (or, negated, not in) the ranges.
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
    /// `*`: any run of characters other than `/`.
    Star,
    /// `**/`: nothing, or any run of characters ending in `/`.
    AnyDirs,
    /// `**` not followed by `/`: anything at all.
    AnyPath,
}

/// A small, dependency-free glob pattern for directory walks.
///
/// Syntax:
///
/// - `*` matches any run of characters except `/`;
/// - `?` matches one character except `/`;
/// - `[abc]`, `[a-z]`, `[!a-z]` (or `[^a-z]`) match one character from a set;
/// - `**/` matches zero or more whole directories, and a trailing `**`
///   matches everything below;
/// - `\x` matches `x` literally.
///
/// A pattern **without** a `/` is matched against the file name only (like
/// `.gitignore`), so `*.md` finds Markdown at any depth. A pattern with a `/`
/// is matched against the whole `/`-separated path relative to the walk root.
///
/// Matching runs in `O(pattern × path)` time with no backtracking, so
/// hostile patterns cannot blow up.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::Glob;
///
/// let md = Glob::new("*.md").unwrap();
/// assert!(md.matches("docs/guide/intro.md"));
///
/// let docs = Glob::new("docs/**/*.txt").unwrap();
/// assert!(docs.matches("docs/a.txt"));
/// assert!(docs.matches("docs/x/y/b.txt"));
/// assert!(!docs.matches("src/a.txt"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: String,
    tokens: Vec<Token>,
    name_only: bool,
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Glob").field(&self.pattern).finish()
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

fn invalid(pattern: &str, reason: &'static str) -> LoadError {
    LoadError::InvalidPattern {
        pattern: pattern.to_string(),
        reason,
    }
}

impl Glob {
    /// Parse a pattern.
    pub fn new(pattern: &str) -> Result<Self, LoadError> {
        if pattern.is_empty() {
            return Err(invalid(pattern, "empty pattern"));
        }
        if pattern.chars().count() > MAX_PATTERN_CHARS {
            return Err(invalid(pattern, "pattern longer than 1024 characters"));
        }
        let chars: Vec<char> = pattern.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '*' if chars.get(i + 1) == Some(&'*') => {
                    if chars.get(i + 2) == Some(&'/') {
                        tokens.push(Token::AnyDirs);
                        i += 3;
                    } else {
                        tokens.push(Token::AnyPath);
                        i += 2;
                    }
                }
                '*' => {
                    tokens.push(Token::Star);
                    i += 1;
                }
                '?' => {
                    tokens.push(Token::One);
                    i += 1;
                }
                '[' => {
                    let (token, next) = parse_class(&chars, i + 1)
                        .ok_or_else(|| invalid(pattern, "unterminated character class"))?;
                    tokens.push(token);
                    i = next;
                }
                '\\' => {
                    let c = *chars
                        .get(i + 1)
                        .ok_or_else(|| invalid(pattern, "trailing backslash"))?;
                    tokens.push(Token::Literal(c));
                    i += 2;
                }
                c => {
                    tokens.push(Token::Literal(c));
                    i += 1;
                }
            }
        }
        Ok(Self {
            pattern: pattern.to_string(),
            tokens,
            name_only: !pattern.contains('/'),
        })
    }

    /// The pattern as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Match a `/`-separated relative path (or, for a pattern without `/`,
    /// the path's last component).
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        let subject = if self.name_only {
            path.rsplit('/').next().unwrap_or(path)
        } else {
            path
        };
        let text: Vec<char> = subject.chars().collect();
        let n = text.len();
        // cur[j]: the tokens so far match text[..j].
        let mut cur = vec![false; n + 1];
        cur[0] = true;
        for token in &self.tokens {
            let mut next = vec![false; n + 1];
            match token {
                Token::Literal(c) => {
                    for j in 0..n {
                        next[j + 1] = cur[j] && text[j] == *c;
                    }
                }
                Token::One => {
                    for j in 0..n {
                        next[j + 1] = cur[j] && text[j] != '/';
                    }
                }
                Token::Class { negated, ranges } => {
                    for j in 0..n {
                        let c = text[j];
                        let hit = ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi);
                        next[j + 1] = cur[j] && c != '/' && hit != *negated;
                    }
                }
                Token::Star => {
                    let mut run = false;
                    for j in 0..=n {
                        run |= cur[j];
                        next[j] = run;
                        if j < n && text[j] == '/' {
                            run = false;
                        }
                    }
                }
                Token::AnyPath => {
                    let mut run = false;
                    for j in 0..=n {
                        run |= cur[j];
                        next[j] = run;
                    }
                }
                Token::AnyDirs => {
                    let mut seen = false;
                    for j in 0..=n {
                        next[j] = cur[j] || (seen && j > 0 && text[j - 1] == '/');
                        seen |= cur[j];
                    }
                }
            }
            cur = next;
        }
        cur[n]
    }
}

/// Parse a class body starting after `[`; returns the token and the index
/// after the closing `]`.
fn parse_class(chars: &[char], mut i: usize) -> Option<(Token, usize)> {
    let negated = matches!(chars.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let c = *chars.get(i)?;
        if c == ']' && !first {
            return Some((Token::Class { negated, ranges }, i + 1));
        }
        first = false;
        let lo = if c == '\\' {
            i += 1;
            *chars.get(i)?
        } else {
            c
        };
        i += 1;
        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&c| c != ']') {
            let hi = *chars.get(i + 1)?;
            ranges.push((lo.min(hi), lo.max(hi)));
            i += 2;
        } else {
            ranges.push((lo, lo));
        }
    }
}
