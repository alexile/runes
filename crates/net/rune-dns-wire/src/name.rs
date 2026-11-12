//! Domain names (RFC 1035 §3.1).

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// Longest label, in octets (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Longest name in wire form, in octets, length bytes and the terminating
/// root label included (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// An absolute domain name: a sequence of labels ending at the root.
///
/// Labels are arbitrary octets (RFC 2181 §11), kept exactly as received:
/// equality and hashing are case-sensitive, so a decoded message re-encodes
/// to the same names. Use [`Name::eq_ignore_ascii_case`] or
/// [`Name::to_ascii_lowercase`] to compare names the way DNS does
/// (RFC 4343).
///
/// The text form ([`Name::from_ascii`], [`Display`](fmt::Display)) is the
/// RFC 1035 §5.1 presentation format without the trailing dot: labels
/// separated by `.`, with `\.`, `\\` and `\DDD` escapes. The root is `.`.
///
/// ```
/// use rune_dns_wire::Name;
///
/// let name: Name = "WWW.Example.com.".parse()?;
/// assert_eq!(name.to_string(), "WWW.Example.com");
/// assert_eq!(name.label_count(), 3);
/// assert!(name.eq_ignore_ascii_case(&"www.example.COM".parse()?));
/// assert!(name.is_subdomain_of(&"example.com".parse()?));
/// assert_eq!(name.wire_len(), 17);
/// # Ok::<(), rune_dns_wire::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    /// Uncompressed wire form: length-prefixed labels, then a zero octet.
    wire: Vec<u8>,
}

impl Name {
    /// The root name, `.`.
    #[must_use]
    pub fn root() -> Self {
        Self { wire: vec![0] }
    }

    /// Builds a name from its labels, most specific first.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] for an empty label, [`Error::LabelTooLong`]
    /// for one over 63 octets, [`Error::NameTooLong`] if the name exceeds
    /// 255 octets.
    pub fn from_labels<I, L>(labels: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let mut builder = Builder::default();
        for label in labels {
            builder.push(label.as_ref())?;
        }
        Ok(builder.finish())
    }

    /// Parses the presentation format: `www.example.com`, with an optional
    /// trailing dot, and `\.`, `\\` and `\DDD` escapes. `.` is the root.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] for an empty name or label or a bad escape,
    /// [`Error::LabelTooLong`] and [`Error::NameTooLong`] for oversize
    /// input.
    pub fn from_ascii(text: &str) -> Result<Self, Error> {
        if text == "." {
            return Ok(Self::root());
        }
        if text.is_empty() {
            return Err(Error::InvalidName {
                reason: "empty name",
            });
        }
        let mut builder = Builder::default();
        let mut label = Vec::new();
        let mut bytes = text.bytes();
        let mut trailing_dot = false;
        while let Some(byte) = bytes.next() {
            trailing_dot = false;
            match byte {
                b'.' => {
                    builder.push(&label)?;
                    label.clear();
                    trailing_dot = true;
                }
                b'\\' => label.push(unescape(&mut bytes)?),
                _ => label.push(byte),
            }
        }
        if !trailing_dot {
            builder.push(&label)?;
        }
        Ok(builder.finish())
    }

    /// Builds a name from uncompressed wire bytes that are known to be
    /// valid. Used by the decoder.
    pub(crate) const fn from_wire_unchecked(wire: Vec<u8>) -> Self {
        Self { wire }
    }

    /// The uncompressed wire form: length-prefixed labels, then a zero
    /// octet.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Length of the uncompressed wire form, at most [`MAX_NAME_LEN`].
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Whether this is the root name.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// The labels, most specific first, without the empty root label.
    #[must_use]
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.wire }
    }

    /// Number of labels, not counting the root.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Compares two names ignoring ASCII case (RFC 4343).
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }

    /// A copy with ASCII letters lowercased.
    #[must_use]
    pub fn to_ascii_lowercase(&self) -> Self {
        Self {
            wire: self.wire.to_ascii_lowercase(),
        }
    }

    /// Whether `self` equals `zone` or lies below it, ignoring ASCII case.
    /// Every name is a subdomain of the root.
    #[must_use]
    pub fn is_subdomain_of(&self, zone: &Self) -> bool {
        let own = self.label_count();
        let theirs = zone.label_count();
        if theirs > own {
            return false;
        }
        let suffix = self.labels().skip(own - theirs);
        suffix
            .zip(zone.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// The name with its first label removed, or `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let first = usize::from(*self.wire.first()?);
        if first == 0 {
            return None;
        }
        self.wire.get(first + 1..).map(|rest| Self {
            wire: rest.to_vec(),
        })
    }
}

impl FromStr for Name {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::from_ascii(text)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for (index, label) in self.labels().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            for &byte in label {
                match byte {
                    b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                        write!(f, "\\{}", char::from(byte))?;
                    }
                    0x21..=0x7e => write!(f, "{}", char::from(byte))?,
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

/// Iterator over the labels of a [`Name`], from [`Name::labels`].
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&len, tail) = self.rest.split_first()?;
        let len = usize::from(len);
        if len == 0 {
            self.rest = &[];
            return None;
        }
        let label = tail.get(..len)?;
        self.rest = tail.get(len..).unwrap_or_default();
        Some(label)
    }
}

/// Accumulates labels into a name's wire form, enforcing the limits.
#[derive(Default)]
pub struct Builder {
    wire: Vec<u8>,
}

impl Builder {
    pub fn push(&mut self, label: &[u8]) -> Result<(), Error> {
        if label.is_empty() {
            return Err(Error::InvalidName {
                reason: "empty label",
            });
        }
        let len = u8::try_from(label.len())
            .ok()
            .filter(|&len| usize::from(len) <= MAX_LABEL_LEN)
            .ok_or(Error::LabelTooLong { len: label.len() })?;
        // Room is needed for this label and the terminating root octet.
        if self.wire.len() + 1 + label.len() + 1 > MAX_NAME_LEN {
            return Err(Error::NameTooLong);
        }
        self.wire.push(len);
        self.wire.extend_from_slice(label);
        Ok(())
    }

    pub fn finish(mut self) -> Name {
        self.wire.push(0);
        Name { wire: self.wire }
    }
}

/// Reads the rest of an escape after `\`: `\DDD` or `\X`.
fn unescape(bytes: &mut core::str::Bytes<'_>) -> Result<u8, Error> {
    let bad = Error::InvalidName {
        reason: "bad escape",
    };
    let first = bytes.next().ok_or_else(|| bad.clone())?;
    if !first.is_ascii_digit() {
        return Ok(first);
    }
    let mut value = u32::from(first - b'0');
    for _ in 0..2 {
        let digit = bytes
            .next()
            .filter(u8::is_ascii_digit)
            .ok_or_else(|| bad.clone())?;
        value = value * 10 + u32::from(digit - b'0');
    }
    u8::try_from(value).map_err(|_| bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays() {
        let name = Name::from_ascii("www.example.com").unwrap();
        assert_eq!(name.as_wire(), b"\x03www\x07example\x03com\x00");
        assert_eq!(name, Name::from_ascii("www.example.com.").unwrap());
        assert_eq!(name.to_string(), "www.example.com");
        assert_eq!(Name::root().to_string(), ".");
        assert_eq!(Name::from_ascii(".").unwrap(), Name::root());
        assert!(Name::root().is_root());
        assert_eq!(Name::root().labels().count(), 0);
    }

    #[test]
    fn escapes_round_trip() {
        let name = Name::from_labels([&b"a.b"[..], b"c\\d", b"\x00\xff ", b"x"]).unwrap();
        let text = name.to_string();
        assert_eq!(text, "a\\.b.c\\\\d.\\000\\255\\032.x");
        assert_eq!(Name::from_ascii(&text).unwrap(), name);
        assert_eq!(Name::from_ascii("\\065b").unwrap().to_string(), "Ab");
    }

    #[test]
    fn rejects_bad_text() {
        for bad in ["", "a..b", ".a", "a\\", "a\\25", "a\\256", "a\\2x5", ".."] {
            assert!(
                matches!(Name::from_ascii(bad), Err(Error::InvalidName { .. })),
                "{bad:?}"
            );
        }
        let long_label = "a".repeat(64);
        assert_eq!(
            Name::from_ascii(&long_label),
            Err(Error::LabelTooLong { len: 64 })
        );
        assert!(Name::from_ascii(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn enforces_255_octets() {
        // 4 labels of 63 octets = 4 * 64 + 1 = 257 octets: too long.
        let label = "a".repeat(63);
        let four = [label.as_str(); 4].join(".");
        assert_eq!(Name::from_ascii(&four), Err(Error::NameTooLong));
        // 3 * 64 + 62 + 1 = 255 octets: the longest valid name.
        let max = format!("{}.{}", [label.as_str(); 3].join("."), "a".repeat(61));
        let name = Name::from_ascii(&max).unwrap();
        assert_eq!(name.wire_len(), MAX_NAME_LEN);
    }

    #[test]
    fn relations() {
        let name = Name::from_ascii("A.Example.COM").unwrap();
        let zone = Name::from_ascii("example.com").unwrap();
        assert!(name.is_subdomain_of(&zone));
        assert!(zone.is_subdomain_of(&zone));
        assert!(!zone.is_subdomain_of(&name));
        assert!(name.is_subdomain_of(&Name::root()));
        assert!(
            !Name::from_ascii("ample.com")
                .unwrap()
                .is_subdomain_of(&zone)
        );
        assert_eq!(name.parent().unwrap().to_string(), "Example.COM");
        assert_eq!(Name::root().parent(), None);
        assert_eq!(name.to_ascii_lowercase().to_string(), "a.example.com");
        assert_ne!(name, name.to_ascii_lowercase());
        assert!(name.eq_ignore_ascii_case(&name.to_ascii_lowercase()));
    }
}
