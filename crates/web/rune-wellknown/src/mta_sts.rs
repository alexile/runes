//! MTA-STS policies (RFC 8461 §3.2).

use std::fmt;

use crate::Error;

/// Largest policy body RFC 8461 §3.3 lets senders accept.
pub const MTA_STS_MAX_LEN: usize = 64 * 1024;

/// The largest `max_age` RFC 8461 §3.2 allows: about one year.
pub const MTA_STS_MAX_AGE_LIMIT: u64 = 31_557_600;

/// What a sending MTA does when a receiving MX fails validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mode {
    /// Refuse delivery to MX hosts that fail validation.
    Enforce,
    /// Deliver anyway, but report failures (TLSRPT).
    Testing,
    /// No active policy.
    None,
}

impl Mode {
    /// The value as written in a policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Testing => "testing",
            Self::None => "none",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed `/.well-known/mta-sts.txt` policy.
///
/// ```
/// use rune_wellknown::{MtaStsPolicy, Mode};
///
/// let p = MtaStsPolicy::parse(
///     "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n",
/// )?;
/// assert_eq!(p.mode, Mode::Enforce);
/// assert!(p.matches_mx("mail.example.com."));
/// assert!(p.matches_mx("a.example.net"));
/// assert!(!p.matches_mx("a.b.example.net"));
/// # Ok::<(), rune_wellknown::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MtaStsPolicy {
    /// The policy mode.
    pub mode: Mode,
    /// Allowed MX host patterns (`mail.example.com` or `*.example.net`).
    pub mx: Vec<String>,
    /// How long senders may cache the policy, in seconds.
    pub max_age: u64,
    /// Fields this crate does not interpret, in order.
    pub extensions: Vec<(String, String)>,
}

impl MtaStsPolicy {
    /// Parses a policy body. `version: STSv1`, `mode` and `max_age` are
    /// required and may appear once; `mx` is required unless the mode is
    /// `none`. Unknown fields are kept in [`MtaStsPolicy::extensions`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MTA_STS_MAX_LEN {
            return Err(Error::TooLarge {
                limit: MTA_STS_MAX_LEN,
            });
        }
        let err = |line: usize, message: String| Error::InvalidMtaSts { line, message };
        let mut version = None;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();
        let mut extensions = Vec::new();
        for (i, raw) in text.split('\n').enumerate() {
            let line = i + 1;
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = raw.trim_end_matches([' ', '\t']);
            if trimmed.is_empty() {
                continue;
            }
            let Some((key, value)) = trimmed.split_once(':') else {
                return Err(err(line, "expected `key: value`".to_owned()));
            };
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            {
                return Err(err(line, format!("invalid field name {key:?}")));
            }
            let value = value.trim_start_matches([' ', '\t']);
            let once = |slot: bool| {
                if slot {
                    Err(err(line, format!("{key} appears more than once")))
                } else {
                    Ok(())
                }
            };
            match key {
                "version" => {
                    once(version.is_some())?;
                    if value != "STSv1" {
                        return Err(err(line, format!("unsupported version {value:?}")));
                    }
                    version = Some(());
                }
                "mode" => {
                    once(mode.is_some())?;
                    mode = Some(match value {
                        "enforce" => Mode::Enforce,
                        "testing" => Mode::Testing,
                        "none" => Mode::None,
                        _ => return Err(err(line, format!("invalid mode {value:?}"))),
                    });
                }
                "max_age" => {
                    once(max_age.is_some())?;
                    let n = (!value.is_empty()
                        && value.len() <= 10
                        && value.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| value.parse::<u64>().ok())
                    .flatten()
                    .filter(|n| *n <= MTA_STS_MAX_AGE_LIMIT)
                    .ok_or_else(|| err(line, format!("invalid max_age {value:?}")))?;
                    max_age = Some(n);
                }
                "mx" => {
                    if !is_mx_pattern(value) {
                        return Err(err(line, format!("invalid mx pattern {value:?}")));
                    }
                    mx.push(value.to_ascii_lowercase());
                }
                _ => extensions.push((key.to_owned(), value.to_owned())),
            }
        }
        let end = text.split('\n').count();
        if version.is_none() {
            return Err(err(end, "version is missing".to_owned()));
        }
        let mode = mode.ok_or_else(|| err(end, "mode is missing".to_owned()))?;
        let max_age = max_age.ok_or_else(|| err(end, "max_age is missing".to_owned()))?;
        if mx.is_empty() && mode != Mode::None {
            return Err(err(end, "mx is missing".to_owned()));
        }
        Ok(Self {
            mode,
            mx,
            max_age,
            extensions,
        })
    }

    /// Whether `host` matches one of the `mx` patterns (RFC 8461 §4.1): an
    /// exact name, or `*.` matching exactly one leftmost label. A trailing
    /// dot and letter case are ignored.
    #[must_use]
    pub fn matches_mx(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        self.mx.iter().any(|p| {
            p.strip_prefix("*.").map_or_else(
                || host == *p,
                |suffix| {
                    host.split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
                },
            )
        })
    }
}

impl fmt::Display for MtaStsPolicy {
    /// The canonical policy text, with `\r\n` line endings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version: STSv1\r\nmode: {}\r\n", self.mode)?;
        for mx in &self.mx {
            write!(f, "mx: {mx}\r\n")?;
        }
        write!(f, "max_age: {}\r\n", self.max_age)?;
        for (k, v) in &self.extensions {
            write!(f, "{k}: {v}\r\n")?;
        }
        Ok(())
    }
}

/// A hostname, optionally with a leading `*.` wildcard label.
fn is_mx_pattern(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8461_example() {
        // RFC 8461 §3.2.
        let p = MtaStsPolicy::parse(
            "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\n\
             mx: backupmx.example.com\r\nmax_age: 604800\r\n",
        )
        .unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert_eq!(p.max_age, 604_800);
        assert_eq!(p.mx.len(), 3);
        assert!(p.matches_mx("BackupMX.example.com"));
        assert!(!p.matches_mx("example.net"));
        assert_eq!(MtaStsPolicy::parse(&p.to_string()), Ok(p));
    }

    #[test]
    fn none_mode_needs_no_mx() {
        let p =
            MtaStsPolicy::parse("version: STSv1\nmode: none\nmax_age: 86400\nfoo: bar\n").unwrap();
        assert_eq!(p.mode, Mode::None);
        assert_eq!(p.extensions, [("foo".to_owned(), "bar".to_owned())]);
    }

    #[test]
    fn errors() {
        for text in [
            "",
            "mode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv2\nmode: enforce\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: strict\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 31557601\n",
            "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: -1\n",
            "version: STSv1\nmode: enforce\nmode: none\nmx: a.example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: a..example\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: *.*.example\nmax_age: 1\n",
            "version: STSv1\nmode enforce\n",
        ] {
            assert!(MtaStsPolicy::parse(text).is_err(), "{text:?}");
        }
        assert!(matches!(
            MtaStsPolicy::parse(&"x".repeat(MTA_STS_MAX_LEN + 1)),
            Err(Error::TooLarge { .. })
        ));
    }
}
