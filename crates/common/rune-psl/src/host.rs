//! Domain name normalization for lookups and rules.

use crate::{Error, punycode};

/// Longest name in characters, without the trailing dot (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 253;
/// Longest label in characters (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// A normalized name in two forms that share their label structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// The name as given, lowercased, without its trailing dot. A-labels
    /// stay A-labels and U-labels stay U-labels.
    pub text: String,
    /// The lookup key: like `text`, but every `xn--` label decoded to
    /// Unicode, the form the list's rules are kept in.
    pub key: String,
    /// Byte offset of each label in `text`, left to right.
    pub text_starts: Vec<usize>,
    /// Byte offset of each label in `key`, left to right.
    pub key_starts: Vec<usize>,
}

impl Name {
    /// Number of labels (at least one).
    pub const fn labels(&self) -> usize {
        self.text_starts.len()
    }

    /// Byte offset in `text` where the last `count` labels start.
    pub fn text_suffix_start(&self, count: usize) -> usize {
        self.labels()
            .checked_sub(count)
            .and_then(|index| self.text_starts.get(index))
            .copied()
            .unwrap_or(0)
    }

    /// The last `count` labels of `key`.
    pub fn key_suffix(&self, count: usize) -> &str {
        let start = self
            .labels()
            .checked_sub(count)
            .and_then(|index| self.key_starts.get(index))
            .copied()
            .unwrap_or(0);
        self.key.get(start..).unwrap_or_default()
    }
}

/// Validates and normalizes a domain name.
///
/// One trailing dot is dropped. ASCII letters are lowercased and must be
/// letters, digits, `-` or `_`; other characters are lowercased with
/// Unicode's simple rules and must not be whitespace or control characters.
/// With `numeric_tld_ok` unset, an all-digit right-most label (an IPv4
/// address) is an error.
pub fn normalize(input: &str, numeric_tld_ok: bool) -> Result<Name, Error> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty() {
        return Err(Error::Empty);
    }
    let mut text = String::with_capacity(name.len());
    for (index, ch) in name.char_indices() {
        if ch.is_ascii() {
            if !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')) {
                return Err(Error::InvalidChar { ch, index });
            }
            text.push(ch.to_ascii_lowercase());
        } else {
            if ch.is_whitespace() || ch.is_control() {
                return Err(Error::InvalidChar { ch, index });
            }
            text.extend(ch.to_lowercase());
        }
    }
    // Measured after lowercasing, which can expand a character (`İ`), so
    // that a normalized name always normalizes again.
    let chars = text.chars().count();
    if chars > MAX_NAME_LEN {
        return Err(Error::TooLong { len: chars });
    }

    let mut key = String::with_capacity(text.len());
    let mut text_starts = Vec::new();
    let mut key_starts = Vec::new();
    let mut offset = 0;
    for label in text.split('.') {
        if label.is_empty() {
            return Err(Error::EmptyLabel);
        }
        let len = label.chars().count();
        if len > MAX_LABEL_LEN {
            return Err(Error::LabelTooLong { len });
        }
        if !key.is_empty() {
            key.push('.');
        }
        text_starts.push(offset);
        key_starts.push(key.len());
        offset += label.len() + 1;
        match label.strip_prefix("xn--") {
            Some(encoded) => {
                let decoded = punycode::decode(encoded)
                    .map(|decoded| decoded.chars().flat_map(char::to_lowercase).collect())
                    .filter(|decoded: &String| is_u_label(decoded))
                    .ok_or_else(|| Error::InvalidPunycode {
                        label: label.to_owned(),
                    })?;
                key.push_str(&decoded);
            }
            None => key.push_str(label),
        }
    }
    let key_chars = key.chars().count();
    if key_chars > MAX_NAME_LEN {
        return Err(Error::TooLong { len: key_chars });
    }
    let last = text.rsplit('.').next().unwrap_or_default();
    if !numeric_tld_ok && last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::NumericTld);
    }
    Ok(Name {
        text,
        key,
        text_starts,
        key_starts,
    })
}

/// Whether a decoded `xn--` label is one a U-label could have been given
/// as, so that the key normalizes to itself: at least one non-ASCII
/// character (Punycode of plain ASCII is never an A-label), no whitespace or
/// control characters, not itself starting with `xn--`, and at most 63
/// characters.
fn is_u_label(decoded: &str) -> bool {
    !decoded.is_ascii()
        && !decoded.starts_with("xn--")
        && decoded.chars().count() <= MAX_LABEL_LEN
        && decoded.chars().all(|ch| {
            if ch.is_ascii() {
                ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')
            } else {
                !(ch.is_whitespace() || ch.is_control())
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_trailing_dot_and_a_labels() {
        let name = normalize("WWW.Xn--85X722F.公司.CN.", false).unwrap();
        assert_eq!(name.text, "www.xn--85x722f.公司.cn");
        assert_eq!(name.key, "www.食狮.公司.cn");
        assert_eq!(name.labels(), 4);
        assert_eq!(name.key_suffix(2), "公司.cn");
        assert_eq!(
            &name.text[name.text_suffix_start(3)..],
            "xn--85x722f.公司.cn"
        );
        assert_eq!(name.key_suffix(9), name.key);
    }

    #[test]
    fn lowercases_unicode() {
        assert_eq!(normalize("ÉCOLE.fr", false).unwrap().text, "école.fr");
    }

    #[test]
    fn rejects_malformed_names() {
        assert_eq!(normalize("", false), Err(Error::Empty));
        assert_eq!(normalize(".", false), Err(Error::Empty));
        assert_eq!(normalize(".com", false), Err(Error::EmptyLabel));
        assert_eq!(normalize("a..com", false), Err(Error::EmptyLabel));
        assert_eq!(normalize("a.com..", false), Err(Error::EmptyLabel));
        assert_eq!(
            normalize("a b.com", false),
            Err(Error::InvalidChar { ch: ' ', index: 1 })
        );
        assert_eq!(
            normalize("a.com\u{3000}", false),
            Err(Error::InvalidChar {
                ch: '\u{3000}',
                index: 5
            })
        );
        assert_eq!(normalize("10.0.0.1", false), Err(Error::NumericTld));
        assert!(normalize("10.0.0.1", true).is_ok());
        assert!(matches!(
            normalize("::1", false),
            Err(Error::InvalidChar { ch: ':', .. })
        ));
        assert_eq!(
            normalize("xn--9.com", false),
            Err(Error::InvalidPunycode {
                label: "xn--9".to_owned()
            })
        );
        // Regression: `xn--` decodes to an
        // empty label.
        assert_eq!(
            normalize("a.xn--", false),
            Err(Error::InvalidPunycode {
                label: "xn--".to_owned()
            })
        );
        // Regression: a decoded label that is
        // itself an A-label.
        assert!(matches!(
            normalize("www.xn--xn--85x71b-nfx", false),
            Err(Error::InvalidPunycode { .. })
        ));
        // Plain ASCII in Punycode is not an A-label.
        assert!(matches!(
            normalize("xn--abc-.com", false),
            Err(Error::InvalidPunycode { .. })
        ));
        // Regression: `xn--a` decodes to the control U+0080.
        assert_eq!(
            normalize("xn--a.com", false),
            Err(Error::InvalidPunycode {
                label: "xn--a".to_owned()
            })
        );
    }

    #[test]
    fn enforces_length_limits_in_characters() {
        let label = "a".repeat(63);
        assert!(normalize(&format!("{label}.com"), false).is_ok());
        assert_eq!(
            normalize(&format!("a{label}.com"), false),
            Err(Error::LabelTooLong { len: 64 })
        );
        let long = [label.as_str(); 4].join(".");
        assert_eq!(normalize(&long, false), Err(Error::TooLong { len: 255 }));
        // 63 three-byte characters are fine: limits count characters.
        assert!(normalize(&format!("{}.cn", "公".repeat(63)), false).is_ok());
    }
}
