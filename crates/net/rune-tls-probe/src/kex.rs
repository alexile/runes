//! The server's ephemeral key-exchange parameters from a TLS 1.2 (or
//! older) `ServerKeyExchange`.

use std::fmt;

use rune_tls_hello::{CipherSuite, NamedGroup};

use crate::suites::suite_name;

/// What a TLS 1.2-and-older `ServerKeyExchange` revealed about the
/// server's ephemeral key exchange.
///
/// ```
/// use rune_tls_hello::NamedGroup;
/// use rune_tls_probe::{KeyExchange, KeyExchangeKind};
///
/// // ECDHE: curve type 3 (named_curve), then the group.
/// let body = [3, 0x00, 0x1d, 1, 0x42];
/// assert_eq!(
///     KeyExchange::parse(KeyExchangeKind::Ecdhe, &body),
///     Some(KeyExchange::Ecdhe { group: NamedGroup::X25519 })
/// );
///
/// // DHE: the prime p comes first, as a 16-bit length and big-endian bytes.
/// let mut body = vec![0x00, 0x80, 0xff];
/// body.extend([0u8; 127]);
/// body.extend([0, 1, 2, 0, 1, 7]); // g = 2, Ys
/// assert_eq!(
///     KeyExchange::parse(KeyExchangeKind::Dhe, &body),
///     Some(KeyExchange::Dhe { prime_bits: 1024 })
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyExchange {
    /// Finite-field Diffie-Hellman with a prime of this many bits.
    Dhe {
        /// Size of the prime `p` in bits.
        prime_bits: u32,
    },
    /// Elliptic-curve Diffie-Hellman over a named group.
    Ecdhe {
        /// The curve.
        group: NamedGroup,
    },
}

impl KeyExchange {
    /// Parses the start of a `ServerKeyExchange` body for a suite of this
    /// kind ([RFC 5246 §7.4.3](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.3),
    /// [RFC 8422 §5.4](https://www.rfc-editor.org/rfc/rfc8422#section-5.4)).
    /// `None` when the body is too short, or uses explicit curves.
    #[must_use]
    pub fn parse(kind: KeyExchangeKind, body: &[u8]) -> Option<Self> {
        match kind {
            KeyExchangeKind::Dhe => {
                let len = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
                let prime = body.get(2..2 + len)?;
                let bits = bit_length(prime);
                (bits > 0).then_some(Self::Dhe { prime_bits: bits })
            }
            KeyExchangeKind::Ecdhe => {
                // 3 is named_curve; explicit curves (1, 2) are not reported.
                if *body.first()? != 3 {
                    return None;
                }
                let group = u16::from_be_bytes([*body.get(1)?, *body.get(2)?]);
                Some(Self::Ecdhe {
                    group: NamedGroup(group),
                })
            }
        }
    }
}

impl fmt::Display for KeyExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dhe { prime_bits } => write!(f, "DHE {prime_bits}-bit"),
            Self::Ecdhe { group } => write!(f, "ECDHE {group}"),
        }
    }
}

/// Which ephemeral key exchange a cipher suite uses, as far as the
/// `ServerKeyExchange` layout goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyExchangeKind {
    /// `DHE_RSA`, `DHE_DSS`, `DH_anon`: the message starts with the
    /// Diffie-Hellman parameters.
    Dhe,
    /// `ECDHE_RSA`, `ECDHE_ECDSA`, `ECDH_anon`: the message starts with
    /// the curve parameters.
    Ecdhe,
}

/// The ephemeral key-exchange kind of a pre-TLS 1.3 suite, from its IANA
/// name. PSK variants (whose message starts with an identity hint) and
/// static exchanges give `None`.
#[must_use]
pub fn kind_of(suite: CipherSuite) -> Option<KeyExchangeKind> {
    let name = suite_name(suite)?;
    let kx = name.strip_prefix("TLS_")?.split("_WITH_").next()?;
    if kx.contains("PSK") {
        return None;
    }
    if kx.starts_with("DHE_") || kx.starts_with("DH_anon") {
        Some(KeyExchangeKind::Dhe)
    } else if kx.starts_with("ECDHE_") || kx.starts_with("ECDH_anon") {
        Some(KeyExchangeKind::Ecdhe)
    } else {
        None
    }
}

/// Bits in a big-endian unsigned integer, leading zeros ignored.
fn bit_length(bytes: &[u8]) -> u32 {
    let Some(first) = bytes.iter().position(|&b| b != 0) else {
        return 0;
    };
    let rest = u32::try_from(bytes.len() - first - 1).unwrap_or(u32::MAX / 16);
    let top = bytes.get(first).copied().unwrap_or(0);
    rest.saturating_mul(8) + (8 - top.leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(kind_of(CipherSuite(0x009e)), Some(KeyExchangeKind::Dhe)); // DHE_RSA AES128 GCM
        assert_eq!(kind_of(CipherSuite(0x0034)), Some(KeyExchangeKind::Dhe)); // DH_anon
        assert_eq!(kind_of(CipherSuite(0xc02f)), Some(KeyExchangeKind::Ecdhe));
        assert_eq!(kind_of(CipherSuite(0xc018)), Some(KeyExchangeKind::Ecdhe)); // ECDH_anon
        assert_eq!(kind_of(CipherSuite(0x002f)), None); // RSA
        assert_eq!(kind_of(CipherSuite(0xc00e)), None); // ECDH_RSA, static
        assert_eq!(kind_of(CipherSuite(0x00aa)), None); // DHE_PSK
        assert_eq!(kind_of(CipherSuite(0x1301)), None);
    }

    #[test]
    fn bits() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[0, 1]), 1);
        assert_eq!(bit_length(&[0x80, 0]), 16);
        assert_eq!(bit_length(&[0, 0x7f, 0]), 15);
    }

    #[test]
    fn short_bodies() {
        assert_eq!(KeyExchange::parse(KeyExchangeKind::Dhe, &[]), None);
        assert_eq!(KeyExchange::parse(KeyExchangeKind::Dhe, &[0, 4, 1]), None);
        assert_eq!(KeyExchange::parse(KeyExchangeKind::Dhe, &[0, 1, 0]), None);
        assert_eq!(KeyExchange::parse(KeyExchangeKind::Ecdhe, &[3, 0]), None);
        assert_eq!(
            KeyExchange::parse(KeyExchangeKind::Ecdhe, &[1, 0, 23]),
            None
        );
        assert_eq!(
            KeyExchange::Ecdhe {
                group: NamedGroup::SECP256R1
            }
            .to_string(),
            "ECDHE secp256r1"
        );
    }
}
