//! The crate's error type.

use std::fmt;

/// The protocol layer an [`Error`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// Ethernet II / IEEE 802.3 frame header.
    Ethernet,
    /// IEEE 802.1Q / 802.1ad VLAN tag.
    Vlan,
    /// ARP packet.
    Arp,
    /// IPv4 header.
    Ipv4,
    /// IPv6 fixed header.
    Ipv6,
    /// IPv6 extension header.
    Ipv6Extension,
    /// TCP header or option.
    Tcp,
    /// UDP header.
    Udp,
    /// ICMP (for IPv4) message.
    Icmpv4,
    /// `ICMPv6` message.
    Icmpv6,
}

impl Layer {
    /// A short human-readable name for the layer.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Vlan => "802.1Q",
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Ipv6Extension => "IPv6 extension header",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmpv4 => "ICMP",
            Self::Icmpv6 => "ICMPv6",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Everything that can go wrong when parsing or building a packet.
///
/// Parsers never panic: a short buffer is reported as
/// [`Error::Truncated`], a header that contradicts itself as
/// [`Error::Malformed`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The buffer ended before the header (or the length it declares) did.
    #[error("{layer} truncated: need {needed} bytes, have {available}")]
    Truncated {
        /// Layer being parsed.
        layer: Layer,
        /// Bytes the layer needs, counted from its first byte.
        needed: usize,
        /// Bytes that were available.
        available: usize,
    },
    /// A field holds a value that makes the header invalid.
    #[error("malformed {layer}: {reason}")]
    Malformed {
        /// Layer being parsed or built.
        layer: Layer,
        /// What is wrong.
        reason: &'static str,
    },
    /// A builder was asked to produce a field that does not fit.
    #[error("{layer} too large: {len} bytes, at most {max}")]
    TooLarge {
        /// Layer being built.
        layer: Layer,
        /// Requested length in bytes.
        len: usize,
        /// Largest length the field can hold.
        max: usize,
    },
}

impl Error {
    /// The layer the error refers to.
    #[must_use]
    pub const fn layer(&self) -> Layer {
        match self {
            Self::Truncated { layer, .. }
            | Self::Malformed { layer, .. }
            | Self::TooLarge { layer, .. } => *layer,
        }
    }

    /// Whether the input simply ended too early (as with a capture
    /// snap length), rather than being invalid.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }

    pub(crate) const fn truncated(layer: Layer, needed: usize, available: usize) -> Self {
        Self::Truncated {
            layer,
            needed,
            available,
        }
    }

    pub(crate) const fn malformed(layer: Layer, reason: &'static str) -> Self {
        Self::Malformed { layer, reason }
    }
}

/// Borrow the first `N` bytes of `data` as a fixed-size header.
pub fn fixed<const N: usize>(data: &[u8], layer: Layer) -> Result<&[u8; N], Error> {
    data.first_chunk::<N>()
        .ok_or_else(|| Error::truncated(layer, N, data.len()))
}

/// Split `data` at `at`, or report that `layer` needs `at` bytes.
pub fn split(data: &[u8], at: usize, layer: Layer) -> Result<(&[u8], &[u8]), Error> {
    data.split_at_checked(at)
        .ok_or_else(|| Error::truncated(layer, at, data.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_accessors() {
        let err = Error::truncated(Layer::Tcp, 20, 3);
        assert_eq!(err.to_string(), "TCP truncated: need 20 bytes, have 3");
        assert!(err.is_truncated());
        assert_eq!(err.layer(), Layer::Tcp);
        let err = Error::malformed(Layer::Ipv4, "bad version");
        assert_eq!(err.to_string(), "malformed IPv4: bad version");
        assert!(!err.is_truncated());
    }

    #[test]
    fn helpers_bound_check() {
        assert!(fixed::<4>(&[1, 2, 3], Layer::Udp).is_err());
        assert_eq!(fixed::<2>(&[1, 2, 3], Layer::Udp), Ok(&[1, 2]));
        assert!(split(&[1], 2, Layer::Udp).unwrap_err().is_truncated());
    }
}
