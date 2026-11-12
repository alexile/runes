//! The fingerprint value type and the hashing helpers shared by every scheme.

use std::fmt::{self, Write as _};

/// A fingerprint in both of its published forms.
///
/// `raw` is the human-readable string the hash is taken over (`JA3` full
/// string, `JA4_r`, …) and `hash` is the form normally shared and matched
/// (the JA3 MD5, the `JA4` string with truncated SHA-256 sections, …).
/// [`Display`](fmt::Display) prints `hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint {
    /// The hashed form, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub hash: String,
    /// The raw form, e.g. `t13d1516h2_002f,0035,…_0005,000a,…_0403,…`.
    pub raw: String,
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hash)
    }
}

/// Twelve lowercase hex characters standing in for an empty JA4 list.
pub const EMPTY_HASH12: &str = "000000000000";

/// The first 12 lowercase hex characters of the SHA-256 of `s`, or
/// [`EMPTY_HASH12`] when `s` is empty (JA4 marks empty lists this way
/// instead of hashing nothing).
pub fn hash12(s: &str) -> String {
    if s.is_empty() {
        return EMPTY_HASH12.to_owned();
    }
    let digest = rune_sha256::hash_raw(s.as_bytes());
    let mut out = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Joins `values` with `sep`, formatting each with `fmt`.
pub fn join<T>(
    values: impl IntoIterator<Item = T>,
    sep: &str,
    mut fmt: impl FnMut(&mut String, T),
) -> String {
    let mut out = String::new();
    for (i, value) in values.into_iter().enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        fmt(&mut out, value);
    }
    out
}

/// Comma-joined four-digit lowercase hex, the JA4 list format.
pub fn hex_list(values: impl IntoIterator<Item = u16>) -> String {
    join(values, ",", |out, v| {
        let _ = write!(out, "{v:04x}");
    })
}

/// Dash-joined decimal, the JA3 list format.
pub fn dec_list<T: fmt::Display>(values: impl IntoIterator<Item = T>) -> String {
    join(values, "-", |out, v| {
        let _ = write!(out, "{v}");
    })
}

/// A count as two decimal digits, capped at 99.
pub fn count2(n: usize) -> String {
    format!("{:02}", n.min(99))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash12_matches_published_examples() {
        // JA4 technical details, "Cipher hash" and "Extension hash".
        assert_eq!(
            hash12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"),
            "8daaf6152771"
        );
        assert_eq!(
            hash12("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"),
            "6d807ffa2a79"
        );
        assert_eq!(hash12(""), EMPTY_HASH12);
    }

    #[test]
    fn list_formats() {
        assert_eq!(hex_list([0x2f, 0xc02b]), "002f,c02b");
        assert_eq!(hex_list([]), "");
        assert_eq!(dec_list([769u16, 47]), "769-47");
        assert_eq!(count2(7), "07");
        assert_eq!(count2(150), "99");
    }
}
