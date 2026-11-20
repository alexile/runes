//! CIDR (IPv4/IPv6) parsing, membership testing and range math, with no
//! dependencies beyond std.
//!
//! ```
//! use rune_cidr::{aggregate, Cidr};
//!
//! let net: Cidr = "10.0.0.0/24".parse().unwrap();
//! assert!(net.contains("10.0.0.42".parse().unwrap()));
//! assert!(!net.contains("10.0.1.1".parse().unwrap()));
//!
//! // A bare address (no `/prefix`) is treated as a full-length match.
//! let exact: Cidr = "10.0.0.5".parse().unwrap();
//! assert!(exact.contains("10.0.0.5".parse().unwrap()));
//!
//! // Range math: counting, bounded expansion, splitting and aggregation.
//! assert_eq!(net.address_count(), 256);
//! assert_eq!(net.host_count(), 254);
//! let first: Vec<_> = net.expand(2).map(|ip| ip.to_string()).collect();
//! assert_eq!(first, ["10.0.0.1", "10.0.0.2"]);
//! let quarters: Vec<_> = net.split(26).unwrap().map(|c| c.to_string()).collect();
//! assert_eq!(quarters, ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"]);
//! let merged = aggregate(&["10.0.0.0/25".parse().unwrap(), "10.0.0.128/25".parse().unwrap()]);
//! assert_eq!(merged, [net]);
//! ```
//!
//! Addresses follow [RFC 4632] (IPv4 CIDR) and [RFC 4291] (IPv6 addressing).
//! Every operation is total: none panics, and the iterators are lazy, so even
//! `::/0` can be walked or split without allocating.
//!
//! [RFC 4632]: https://www.rfc-editor.org/rfc/rfc4632
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;
use core::iter::FusedIterator;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

/// A parsed IPv4 or IPv6 CIDR range.
///
/// The stored address is kept as given, host bits included (`10.0.0.5/24`
/// stays `10.0.0.5/24`); [`Cidr::trunc`] clears them. Every range operation
/// works on the network the prefix describes, so host bits never change a
/// result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cidr {
    /// An IPv4 network address and prefix length.
    V4(u32, u8),
    /// An IPv6 network address and prefix length.
    V6(u128, u8),
}

/// A CIDR string that failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrParseError(String);

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for CidrParseError {}

/// A prefix length that is out of range for the requested operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLenError {
    prefix_len: u8,
    min: u8,
    max: u8,
}

impl PrefixLenError {
    /// The prefix length that was requested.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The smallest prefix length the operation accepts.
    #[must_use]
    pub const fn min(&self) -> u8 {
        self.min
    }

    /// The largest prefix length the operation accepts.
    #[must_use]
    pub const fn max(&self) -> u8 {
        self.max
    }
}

impl fmt::Display for PrefixLenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prefix length /{} is outside /{}../{}",
            self.prefix_len, self.min, self.max
        )
    }
}

impl core::error::Error for PrefixLenError {}

/// Bit width of an address family: 32 or 128.
const V4_BITS: u8 = 32;
const V6_BITS: u8 = 128;

/// The network mask for `prefix` in a family of `bits` bits, right-aligned
/// in a `u128`.
fn mask(bits: u8, prefix: u8) -> u128 {
    let ones = u128::MAX
        .checked_shl(u32::from(V6_BITS - prefix))
        .unwrap_or(0);
    ones >> (V6_BITS - bits)
}

/// The highest address of a family of `bits` bits.
const fn family_max(bits: u8) -> u128 {
    u128::MAX >> (V6_BITS - bits)
}

/// A `u128` with the low `n` bits set (`n <= 128`).
fn low_ones(n: u8) -> u128 {
    u128::MAX.checked_shr(u32::from(V6_BITS - n)).unwrap_or(0)
}

/// Floor of log2(`n`) for `n > 0`.
fn ilog2(n: u128) -> u8 {
    // `leading_zeros` is at most 127 for a non-zero value, so this fits.
    u8::try_from(127 - n.leading_zeros().min(127)).unwrap_or(0)
}

fn to_ip(bits: u8, value: u128) -> IpAddr {
    if bits == V4_BITS {
        IpAddr::V4(Ipv4Addr::from(u32::try_from(value).unwrap_or(u32::MAX)))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

fn ip_parts(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(v4) => (V4_BITS, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (V6_BITS, u128::from(v6)),
    }
}

impl Cidr {
    /// Parse `"10.0.0.0/24"`, `"2001:db8::/32"`, or a bare address
    /// (`"10.0.0.5"`), which is treated as `/32`/`/128`. The prefix must be
    /// plain digits with no sign or leading zeros (`/024` is rejected), and
    /// IPv4 octets with leading zeros are rejected too.
    ///
    /// # Errors
    ///
    /// When the address or prefix is malformed, or the prefix is too long.
    pub fn parse(s: &str) -> Result<Self, CidrParseError> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| CidrParseError(format!("{} is not a valid IP address", Quoted(s))))?;
        let max_prefix = if addr.is_ipv4() { V4_BITS } else { V6_BITS };
        let prefix = match prefix_str {
            Some(prefix_str) => {
                let prefix = parse_prefix(prefix_str).ok_or_else(|| {
                    CidrParseError(format!("{} has a malformed prefix", Quoted(s)))
                })?;
                if prefix > max_prefix {
                    return Err(CidrParseError(format!(
                        "{} has prefix /{prefix}, but {addr} only has {max_prefix} bits",
                        Quoted(s)
                    )));
                }
                prefix
            }
            None => max_prefix,
        };
        Ok(match addr {
            IpAddr::V4(v4) => Self::V4(u32::from(v4), prefix),
            IpAddr::V6(v6) => Self::V6(u128::from(v6), prefix),
        })
    }

    /// Build a range from an address and a prefix length. Host bits are kept
    /// as given; see [`Cidr::trunc`].
    ///
    /// # Errors
    ///
    /// When `prefix_len` exceeds the address family's width (32 or 128).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        let (bits, value) = ip_parts(addr);
        if prefix_len > bits {
            return Err(PrefixLenError {
                prefix_len,
                min: 0,
                max: bits,
            });
        }
        Ok(Self::from_parts(bits, value, prefix_len))
    }

    /// `(family bits, address, prefix length)`. A hand-built value with a
    /// prefix past the family width is read as full length.
    fn parts(self) -> (u8, u128, u8) {
        match self {
            Self::V4(addr, prefix) => (V4_BITS, u128::from(addr), prefix.min(V4_BITS)),
            Self::V6(addr, prefix) => (V6_BITS, addr, prefix.min(V6_BITS)),
        }
    }

    /// Inverse of [`Cidr::parts`]; `value` must fit in `bits`.
    fn from_parts(bits: u8, value: u128, prefix: u8) -> Self {
        if bits == V4_BITS {
            Self::V4(u32::try_from(value).unwrap_or(u32::MAX), prefix)
        } else {
            Self::V6(value, prefix)
        }
    }

    /// First and last address of the range, as integers.
    fn bounds(self) -> (u8, u128, u128) {
        let (bits, value, prefix) = self.parts();
        let m = mask(bits, prefix);
        let first = value & m;
        (bits, first, first | (family_max(bits) & !m))
    }

    /// Whether this is an IPv4 range.
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, Self::V4(..))
    }

    /// Whether this is an IPv6 range.
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(..))
    }

    /// The address as stored, host bits included.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        let (bits, value, _) = self.parts();
        to_ip(bits, value)
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.parts().2
    }

    /// The family's maximum prefix length: 32 for IPv4, 128 for IPv6.
    #[must_use]
    pub fn max_prefix_len(&self) -> u8 {
        self.parts().0
    }

    /// The network (first) address of the range.
    #[must_use]
    pub fn network(&self) -> IpAddr {
        let (bits, first, _) = self.bounds();
        to_ip(bits, first)
    }

    /// The last address of the range (the IPv4 broadcast address).
    #[must_use]
    pub fn last(&self) -> IpAddr {
        let (bits, _, last) = self.bounds();
        to_ip(bits, last)
    }

    /// The network mask, for example `255.255.255.0` for a `/24`.
    #[must_use]
    pub fn netmask(&self) -> IpAddr {
        let (bits, _, prefix) = self.parts();
        to_ip(bits, mask(bits, prefix))
    }

    /// The host mask, for example `0.0.0.255` for a `/24`.
    #[must_use]
    pub fn hostmask(&self) -> IpAddr {
        let (bits, _, prefix) = self.parts();
        to_ip(bits, family_max(bits) & !mask(bits, prefix))
    }

    /// The same range with the host bits cleared: `10.0.0.5/24` becomes
    /// `10.0.0.0/24`.
    #[must_use]
    pub fn trunc(&self) -> Self {
        let (bits, first, _) = self.bounds();
        Self::from_parts(bits, first, self.prefix_len())
    }

    /// Number of addresses in the range, saturating at [`u128::MAX`] (only
    /// `::/0`, which holds 2^128 addresses, saturates).
    #[must_use]
    pub fn address_count(&self) -> u128 {
        let (bits, _, prefix) = self.parts();
        1u128
            .checked_shl(u32::from(bits - prefix))
            .unwrap_or(u128::MAX)
    }

    /// Number of addresses [`Cidr::hosts`] yields: IPv4 ranges wider than
    /// `/31` exclude the network and broadcast addresses; `/31`, `/32` and
    /// every IPv6 range count all of them.
    #[must_use]
    pub fn host_count(&self) -> u128 {
        let total = self.address_count();
        match self {
            Self::V4(_, prefix) if *prefix < 31 => total - 2,
            _ => total,
        }
    }

    /// Every address in the range, network and broadcast included.
    #[must_use]
    pub fn addresses(&self) -> Addresses {
        let (bits, first, last) = self.bounds();
        Addresses {
            bits,
            front: first,
            back: last,
            done: false,
        }
    }

    /// The usable host addresses: like [`Cidr::addresses`], but IPv4 ranges
    /// wider than `/31` skip the network and broadcast addresses
    /// ([RFC 3021] keeps both for `/31`).
    ///
    /// [RFC 3021]: https://www.rfc-editor.org/rfc/rfc3021
    #[must_use]
    pub fn hosts(&self) -> Addresses {
        let mut it = self.addresses();
        if matches!(self, Self::V4(_, prefix) if *prefix < 31) {
            it.front += 1;
            it.back -= 1;
        }
        it
    }

    /// At most `cap` usable hosts, in order. The cap bounds the work done on
    /// wide ranges such as a `/8` or any IPv6 prefix.
    pub fn expand(&self, cap: usize) -> core::iter::Take<Addresses> {
        self.hosts().take(cap)
    }

    /// Whether `ip` falls within this range. Mismatched address families
    /// never match.
    ///
    /// An IPv4-mapped IPv6 address such as `::ffff:10.0.0.1` is IPv6 here;
    /// call [`Ipv6Addr::to_canonical`] on it first to match IPv4 ranges.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4(addr, prefix), IpAddr::V4(v4)) => {
                let m = u32::MAX
                    .checked_shl(u32::from(V4_BITS - prefix.min(V4_BITS)))
                    .unwrap_or(0);
                (addr ^ u32::from(v4)) & m == 0
            }
            (Self::V6(addr, prefix), IpAddr::V6(v6)) => {
                (addr ^ u128::from(v6)) & mask(V6_BITS, prefix.min(V6_BITS)) == 0
            }
            _ => false,
        }
    }

    /// Whether `other` lies entirely within this range.
    #[must_use]
    pub fn contains_cidr(&self, other: &Self) -> bool {
        let (bits, first, last) = self.bounds();
        let (o_bits, o_first, o_last) = other.bounds();
        bits == o_bits && first <= o_first && o_last <= last
    }

    /// Whether the two ranges share at least one address. Since CIDR ranges
    /// nest, that means one contains the other.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.contains_cidr(other) || other.contains_cidr(self)
    }

    /// The enclosing range one bit shorter (`10.0.1.0/24` gives
    /// `10.0.0.0/23`), or `None` for a `/0`.
    #[must_use]
    pub fn supernet(&self) -> Option<Self> {
        let (bits, value, prefix) = self.parts();
        let prefix = prefix.checked_sub(1)?;
        Some(Self::from_parts(bits, value & mask(bits, prefix), prefix))
    }

    /// The two halves one bit longer (`10.0.0.0/23` gives `10.0.0.0/24` and
    /// `10.0.1.0/24`), or `None` for a full-length range.
    #[must_use]
    pub fn subnets(&self) -> Option<(Self, Self)> {
        let mut halves = self.split(self.prefix_len().checked_add(1)?).ok()?;
        Some((halves.next()?, halves.next()?))
    }

    /// The subnets of length `new_prefix_len` that tile this range, lazily
    /// and in order. Bound them with [`Iterator::take`] for wide splits.
    ///
    /// # Errors
    ///
    /// When `new_prefix_len` is shorter than this range's prefix or longer
    /// than the family allows.
    pub fn split(&self, new_prefix_len: u8) -> Result<Subnets, PrefixLenError> {
        let (bits, first, last) = self.bounds();
        let prefix = self.prefix_len();
        if new_prefix_len < prefix || new_prefix_len > bits {
            return Err(PrefixLenError {
                prefix_len: new_prefix_len,
                min: prefix,
                max: bits,
            });
        }
        let host_bits = bits - new_prefix_len;
        Ok(Subnets {
            bits,
            prefix: new_prefix_len,
            front: first,
            back: last & !low_ones(host_bits),
            done: false,
        })
    }
}

/// A prefix length: plain ASCII digits, no sign, no leading zeros.
fn parse_prefix(s: &str) -> Option<u8> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 3 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    s.parse().ok()
}

/// Input echoed in an error: quoted, and cut short so a huge string does
/// not end up copied into the message.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX: usize = 64;
        let s = self.0;
        if s.len() <= MAX {
            return write!(f, "{s:?}");
        }
        let mut end = MAX;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        write!(f, "{:?}...", &s[..end])
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.prefix_len())
    }
}

impl From<IpAddr> for Cidr {
    /// A full-length range holding exactly `ip`.
    fn from(ip: IpAddr) -> Self {
        let (bits, value) = ip_parts(ip);
        Self::from_parts(bits, value, bits)
    }
}

/// Lazy iterator over the addresses of a [`Cidr`], from
/// [`Cidr::addresses`], [`Cidr::hosts`] or [`Cidr::expand`].
#[derive(Debug, Clone)]
pub struct Addresses {
    bits: u8,
    front: u128,
    back: u128,
    done: bool,
}

impl Addresses {
    const fn remaining(&self) -> Option<u128> {
        if self.done || self.front > self.back {
            Some(0)
        } else {
            (self.back - self.front).checked_add(1)
        }
    }
}

impl Iterator for Addresses {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        if self.done || self.front > self.back {
            return None;
        }
        let ip = to_ip(self.bits, self.front);
        if self.front == self.back {
            self.done = true;
        } else {
            self.front += 1;
        }
        Some(ip)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.remaining().map(usize::try_from) {
            Some(Ok(n)) => (n, Some(n)),
            _ => (usize::MAX, None),
        }
    }
}

impl DoubleEndedIterator for Addresses {
    fn next_back(&mut self) -> Option<IpAddr> {
        if self.done || self.front > self.back {
            return None;
        }
        let ip = to_ip(self.bits, self.back);
        if self.front == self.back {
            self.done = true;
        } else {
            self.back -= 1;
        }
        Some(ip)
    }
}

impl FusedIterator for Addresses {}

/// Lazy iterator over equal-sized subnets, from [`Cidr::split`].
#[derive(Debug, Clone)]
pub struct Subnets {
    bits: u8,
    prefix: u8,
    front: u128,
    back: u128,
    done: bool,
}

impl Subnets {
    fn step(&self) -> u128 {
        1u128 << (self.bits - self.prefix).min(127)
    }

    const fn remaining(&self) -> Option<u128> {
        if self.done {
            return Some(0);
        }
        let host_bits = self.bits - self.prefix;
        if host_bits == V6_BITS {
            return Some(1);
        }
        ((self.back - self.front) >> host_bits).checked_add(1)
    }
}

impl Iterator for Subnets {
    type Item = Cidr;

    fn next(&mut self) -> Option<Cidr> {
        if self.done {
            return None;
        }
        let net = Cidr::from_parts(self.bits, self.front, self.prefix);
        if self.front == self.back {
            self.done = true;
        } else {
            self.front += self.step();
        }
        Some(net)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.remaining().map(usize::try_from) {
            Some(Ok(n)) => (n, Some(n)),
            _ => (usize::MAX, None),
        }
    }
}

impl DoubleEndedIterator for Subnets {
    fn next_back(&mut self) -> Option<Cidr> {
        if self.done {
            return None;
        }
        let net = Cidr::from_parts(self.bits, self.back, self.prefix);
        if self.front == self.back {
            self.done = true;
        } else {
            self.back -= self.step();
        }
        Some(net)
    }
}

impl FusedIterator for Subnets {}

/// Whether `ip` matches any entry in `cidrs`.
#[must_use]
pub fn contains_any(ip: IpAddr, cidrs: &[Cidr]) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

/// The addresses of `ips` that fall within at least one of `ranges`, in
/// their original order.
pub fn filter<'a, I>(ips: I, ranges: &'a [Cidr]) -> impl Iterator<Item = IpAddr> + 'a
where
    I: IntoIterator<Item = IpAddr>,
    I::IntoIter: 'a,
{
    ips.into_iter().filter(move |ip| contains_any(*ip, ranges))
}

/// The smallest set of ranges covering exactly the addresses of `nets`:
/// contained ranges are dropped and adjacent ones merged. The result is
/// truncated (no host bits), sorted, with IPv4 before IPv6.
#[must_use]
pub fn aggregate(nets: &[Cidr]) -> Vec<Cidr> {
    let mut out = Vec::new();
    for bits in [V4_BITS, V6_BITS] {
        let mut ranges: Vec<(u128, u128)> = nets
            .iter()
            .map(|n| n.bounds())
            .filter(|(b, _, _)| *b == bits)
            .map(|(_, first, last)| (first, last))
            .collect();
        ranges.sort_unstable();
        // Merge in place: `ranges[..len]` holds the merged runs so far.
        let mut len: usize = 0;
        for i in 0..ranges.len() {
            let (first, last) = ranges[i];
            if let Some(prev) = len.checked_sub(1).map(|j| &mut ranges[j])
                && prev.1.checked_add(1).is_none_or(|next| first <= next)
            {
                prev.1 = prev.1.max(last);
                continue;
            }
            ranges[len] = (first, last);
            len += 1;
        }
        for &(first, last) in &ranges[..len] {
            push_range(&mut out, bits, first, last);
        }
    }
    out
}

/// Append the minimal CIDR cover of `first..=last` to `out`.
fn push_range(out: &mut Vec<Cidr>, bits: u8, mut first: u128, last: u128) {
    loop {
        // Largest block aligned at `first` that does not run past `last`.
        let align = u8::try_from(first.trailing_zeros())
            .unwrap_or(V6_BITS)
            .min(bits);
        let span = last - first;
        let fit = if span == u128::MAX {
            V6_BITS
        } else {
            ilog2(span + 1)
        };
        let host_bits = align.min(fit);
        out.push(Cidr::from_parts(bits, first, bits - host_bits));
        let block_last = first | low_ones(host_bits);
        match block_last.checked_add(1) {
            Some(next) if block_last < last => first = next,
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn strs<T: ToString>(items: impl IntoIterator<Item = T>) -> Vec<String> {
        items.into_iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn parses_bare_ipv4_as_slash_32() {
        assert_eq!(Cidr::parse("10.0.0.5").unwrap(), Cidr::V4(0x0a00_0005, 32));
    }

    #[test]
    fn parses_cidr_ipv4() {
        assert_eq!(
            Cidr::parse("10.0.0.0/24").unwrap(),
            Cidr::V4(0x0a00_0000, 24)
        );
    }

    #[test]
    fn parses_bare_ipv6_as_slash_128() {
        let Cidr::V6(_, prefix) = Cidr::parse("::1").unwrap() else {
            panic!("expected V6");
        };
        assert_eq!(prefix, 128);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/24/8").is_err());
    }

    #[test]
    fn rejects_prefix_wider_than_the_address_family_allows() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("::1/129").is_err());
    }

    #[test]
    fn rejects_sloppy_prefixes() {
        for s in [
            "10.0.0.0/+24",
            "10.0.0.0/024",
            "10.0.0.0/00",
            "10.0.0.0/",
            "10.0.0.0/-0",
            "::/+0",
            "::/0128",
            "10.0.0.0/ 24",
        ] {
            assert!(Cidr::parse(s).is_err(), "{s} should be rejected");
        }
        assert_eq!(c("10.0.0.0/0").prefix_len(), 0);
        assert_eq!(c("::/0").prefix_len(), 0);
    }

    #[test]
    fn rejects_octal_looking_and_odd_addresses() {
        for s in [
            "010.0.0.1/8",
            "10.0.0.01",
            "0x0a.0.0.1",
            "10.1",
            "fe80::1%eth0/64",
            " 10.0.0.0/8",
        ] {
            assert!(Cidr::parse(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_stays_ipv6() {
        let n = c("::ffff:10.0.0.0/104");
        assert!(n.is_ipv6());
        assert!(n.contains(ip("::ffff:10.1.2.3")));
        assert!(!n.contains(ip("10.1.2.3")));
        assert!(!c("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn error_does_not_echo_huge_input() {
        let long = "1".repeat(100_000);
        let err = Cidr::parse(&long).unwrap_err().to_string();
        assert!(err.len() < 200, "error is {} bytes", err.len());
        let err = Cidr::parse(&format!("10.0.0.0/{long}"))
            .unwrap_err()
            .to_string();
        assert!(err.len() < 200, "error is {} bytes", err.len());
    }

    #[test]
    fn out_of_range_prefix_in_hand_built_values_does_not_panic() {
        for n in [
            Cidr::V4(0x0a00_0001, 40),
            Cidr::V4(0, 255),
            Cidr::V6(1, 129),
            Cidr::V6(0, 255),
        ] {
            let full = Cidr::from(n.addr());
            assert_eq!(n.prefix_len(), n.max_prefix_len());
            assert_eq!(n.address_count(), 1);
            assert_eq!(n.host_count(), 1);
            assert_eq!(n.network(), n.addr());
            assert_eq!(n.last(), n.addr());
            assert_eq!(n.netmask(), full.netmask());
            assert_eq!(n.hostmask(), full.hostmask());
            assert_eq!(n.trunc(), full);
            assert!(n.contains(n.addr()));
            assert!(n.contains_cidr(&full) && n.overlaps(&full));
            assert_eq!(n.addresses().count(), 1);
            assert_eq!(n.hosts().count(), 1);
            assert_eq!(n.split(n.max_prefix_len()).unwrap().count(), 1);
            assert!(n.split(0).is_err());
            assert_eq!(n.subnets(), None);
            assert!(n.supernet().is_some());
            assert_eq!(aggregate(&[n]), [full]);
            assert_eq!(n.to_string(), full.to_string());
        }
    }

    #[test]
    fn cidr_membership_respects_the_prefix_boundary() {
        let net = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(net.contains("10.0.0.42".parse().unwrap()));
        assert!(!net.contains("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn slash_zero_matches_every_address_in_the_family() {
        let net = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(net.contains("8.8.8.8".parse().unwrap()));
        assert!(net.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn slash_max_requires_an_exact_match() {
        let net = Cidr::parse("10.0.0.5/32").unwrap();
        assert!(net.contains("10.0.0.5".parse().unwrap()));
        assert!(!net.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn mismatched_address_families_never_match() {
        let net = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(!net.contains("::1".parse().unwrap()));
    }

    #[test]
    fn contains_any_skips_nothing_and_matches_across_the_list() {
        let cidrs = vec![
            Cidr::parse("192.168.0.0/16").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap(),
        ];
        assert!(contains_any("10.1.2.3".parse().unwrap(), &cidrs));
        assert!(!contains_any("8.8.8.8".parse().unwrap(), &cidrs));
    }

    #[test]
    fn from_str_matches_parse() {
        let a: Cidr = "10.0.0.0/24".parse().unwrap();
        let b = Cidr::parse("10.0.0.0/24").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn new_checks_the_prefix_and_from_ip_is_full_length() {
        assert_eq!(Cidr::new(ip("10.0.0.0"), 8).unwrap(), c("10.0.0.0/8"));
        let err = Cidr::new(ip("10.0.0.0"), 33).unwrap_err();
        assert_eq!((err.prefix_len(), err.min(), err.max()), (33, 0, 32));
        assert!(Cidr::new(ip("::"), 128).is_ok());
        assert!(Cidr::new(ip("::"), 129).is_err());
        assert_eq!(Cidr::from(ip("2001:db8::1")), c("2001:db8::1/128"));
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "10.0.0.5/24",
            "0.0.0.0/0",
            "2001:db8::/32",
            "::/0",
            "::1/128",
        ] {
            assert_eq!(c(s).to_string(), s);
            assert_eq!(c(&c(s).to_string()), c(s));
        }
        assert_eq!(c("10.0.0.5").to_string(), "10.0.0.5/32");
    }

    #[test]
    fn accessors_known_answers() {
        let n = c("192.168.1.77/22");
        assert!(n.is_ipv4() && !n.is_ipv6());
        assert_eq!(n.addr(), ip("192.168.1.77"));
        assert_eq!(n.prefix_len(), 22);
        assert_eq!(n.max_prefix_len(), 32);
        assert_eq!(n.network(), ip("192.168.0.0"));
        assert_eq!(n.last(), ip("192.168.3.255"));
        assert_eq!(n.netmask(), ip("255.255.252.0"));
        assert_eq!(n.hostmask(), ip("0.0.3.255"));
        assert_eq!(n.trunc(), c("192.168.0.0/22"));

        let v6 = c("2001:db8:abcd::1/48");
        assert!(v6.is_ipv6());
        assert_eq!(v6.max_prefix_len(), 128);
        assert_eq!(v6.network(), ip("2001:db8:abcd::"));
        assert_eq!(v6.last(), ip("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"));
        assert_eq!(v6.netmask(), ip("ffff:ffff:ffff::"));
        assert_eq!(v6.trunc(), c("2001:db8:abcd::/48"));
    }

    #[test]
    fn boundary_prefixes() {
        let all4 = c("1.2.3.4/0");
        assert_eq!(all4.network(), ip("0.0.0.0"));
        assert_eq!(all4.last(), ip("255.255.255.255"));
        assert_eq!(all4.netmask(), ip("0.0.0.0"));
        assert_eq!(all4.address_count(), 1 << 32);
        assert_eq!(all4.host_count(), (1 << 32) - 2);

        let one4 = c("1.2.3.4/32");
        assert_eq!(one4.network(), ip("1.2.3.4"));
        assert_eq!(one4.last(), ip("1.2.3.4"));
        assert_eq!(one4.netmask(), ip("255.255.255.255"));
        assert_eq!(one4.address_count(), 1);
        assert_eq!(one4.host_count(), 1);
        assert_eq!(strs(one4.hosts()), ["1.2.3.4"]);

        let all6 = c("::/0");
        assert_eq!(all6.last(), ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert_eq!(all6.address_count(), u128::MAX);
        assert_eq!(all6.host_count(), u128::MAX);
        assert!(all6.contains(ip("::")));
        assert!(all6.contains(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert_eq!(all6.supernet(), None);

        let one6 = c("2001:db8::7/128");
        assert_eq!(one6.address_count(), 1);
        assert_eq!(strs(one6.hosts()), ["2001:db8::7"]);
        assert_eq!(one6.subnets(), None);
        assert_eq!(strs(one6.split(128).unwrap()), ["2001:db8::7/128"]);
    }

    #[test]
    fn counts_known_answers() {
        assert_eq!(c("10.0.0.0/24").address_count(), 256);
        assert_eq!(c("10.0.0.0/24").host_count(), 254);
        assert_eq!(c("10.0.0.0/30").host_count(), 2);
        assert_eq!(c("10.0.0.0/31").host_count(), 2);
        assert_eq!(c("2001:db8::/120").address_count(), 256);
        assert_eq!(c("2001:db8::/120").host_count(), 256);
        assert_eq!(c("2001:db8::/64").address_count(), 1 << 64);
        assert_eq!(c("8000::/1").address_count(), 1 << 127);
    }

    #[test]
    fn hosts_and_addresses() {
        assert_eq!(strs(c("192.0.2.0/30").hosts()), ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(
            strs(c("192.0.2.0/30").addresses()),
            ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
        assert_eq!(strs(c("192.0.2.0/31").hosts()), ["192.0.2.0", "192.0.2.1"]);
        assert_eq!(
            strs(c("2001:db8::/126").hosts()),
            ["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"]
        );
        assert_eq!(
            strs(c("192.0.2.0/30").hosts().rev()),
            ["192.0.2.2", "192.0.2.1"]
        );
        assert_eq!(c("192.0.2.0/24").hosts().len_hint(), 254);
        assert_eq!(c("255.255.255.255/32").addresses().count(), 1);
        assert_eq!(
            c("::/0").addresses().next_back(),
            Some(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
        );
    }

    trait LenHint {
        fn len_hint(&self) -> usize;
    }

    impl<I: Iterator> LenHint for I {
        fn len_hint(&self) -> usize {
            self.size_hint().0
        }
    }

    #[test]
    fn expand_is_capped() {
        let ten = strs(c("10.0.0.0/8").expand(3));
        assert_eq!(ten, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        assert_eq!(c("10.0.0.0/24").expand(1000).count(), 254);
        assert_eq!(c("::/0").expand(2).count(), 2);
        assert_eq!(c("10.0.0.0/8").expand(0).count(), 0);
    }

    #[test]
    fn split_known_answers() {
        assert_eq!(
            strs(c("192.168.0.0/24").split(26).unwrap()),
            [
                "192.168.0.0/26",
                "192.168.0.64/26",
                "192.168.0.128/26",
                "192.168.0.192/26"
            ]
        );
        assert_eq!(strs(c("10.0.0.0/8").split(8).unwrap()), ["10.0.0.0/8"]);
        assert_eq!(
            strs(c("2001:db8::/32").split(34).unwrap()),
            [
                "2001:db8::/34",
                "2001:db8:4000::/34",
                "2001:db8:8000::/34",
                "2001:db8:c000::/34"
            ]
        );
        assert_eq!(
            strs(c("2001:db8::/32").split(34).unwrap().rev())
                .first()
                .map(String::as_str),
            Some("2001:db8:c000::/34")
        );
        assert_eq!(c("0.0.0.0/0").split(32).unwrap().len_hint(), 1 << 32);
        assert_eq!(
            c("0.0.0.0/0").split(32).unwrap().next_back(),
            Some(c("255.255.255.255/32"))
        );
        assert_eq!(c("::/0").split(0).unwrap().count(), 1);
        assert_eq!(c("::/0").split(128).unwrap().take(2).count(), 2);
        assert_eq!(
            c("::/0").split(1).unwrap().collect::<Vec<_>>(),
            [c("::/1"), c("8000::/1")]
        );
        // Host bits do not leak into the subnets.
        assert_eq!(
            strs(c("10.0.0.77/30").split(31).unwrap()),
            ["10.0.0.76/31", "10.0.0.78/31"]
        );
    }

    #[test]
    fn split_rejects_out_of_range_prefixes() {
        let err = c("192.168.0.0/24").split(20).unwrap_err();
        assert_eq!((err.prefix_len(), err.min(), err.max()), (20, 24, 32));
        assert!(c("192.168.0.0/24").split(33).is_err());
        assert!(c("::/64").split(129).is_err());
    }

    #[test]
    fn supernet_and_subnets() {
        assert_eq!(c("10.0.1.0/24").supernet(), Some(c("10.0.0.0/23")));
        assert_eq!(c("0.0.0.0/1").supernet(), Some(c("0.0.0.0/0")));
        assert_eq!(c("0.0.0.0/0").supernet(), None);
        assert_eq!(
            c("10.0.0.0/23").subnets(),
            Some((c("10.0.0.0/24"), c("10.0.1.0/24")))
        );
        assert_eq!(c("10.0.0.1/32").subnets(), None);
        assert_eq!(c("::/0").subnets(), Some((c("::/1"), c("8000::/1"))));
        assert_eq!(c("2001:db8::/127").supernet(), Some(c("2001:db8::/126")));
    }

    #[test]
    fn overlaps_and_contains_cidr() {
        assert!(c("10.0.0.0/8").overlaps(&c("10.1.0.0/16")));
        assert!(c("10.1.0.0/16").overlaps(&c("10.0.0.0/8")));
        assert!(!c("10.0.0.0/8").overlaps(&c("11.0.0.0/8")));
        assert!(c("10.0.0.0/8").contains_cidr(&c("10.1.0.0/16")));
        assert!(!c("10.1.0.0/16").contains_cidr(&c("10.0.0.0/8")));
        assert!(c("0.0.0.0/0").contains_cidr(&c("1.2.3.4/32")));
        assert!(!c("0.0.0.0/0").overlaps(&c("::/0")));
        assert!(c("2001:db8::/32").overlaps(&c("2001:db8:1::/48")));
        assert!(!c("2001:db8::/32").overlaps(&c("2001:db9::/32")));
    }

    #[test]
    fn filter_keeps_in_range_addresses_in_order() {
        let ranges = [c("10.0.0.0/16"), c("2001:db8::/32")];
        let ips = [
            ip("10.0.0.5"),
            ip("11.0.0.5"),
            ip("2001:db8::1"),
            ip("10.0.1.9"),
            ip("::1"),
        ];
        assert_eq!(
            strs(filter(ips, &ranges)),
            ["10.0.0.5", "2001:db8::1", "10.0.1.9"]
        );
        assert_eq!(filter(ips, &[]).count(), 0);
    }

    #[test]
    fn aggregate_known_answers() {
        let agg = |xs: &[&str]| strs(aggregate(&xs.iter().map(|s| c(s)).collect::<Vec<_>>()));
        assert_eq!(
            agg(&["192.168.0.0/24", "192.168.1.0/24"]),
            ["192.168.0.0/23"]
        );
        assert_eq!(
            agg(&["10.0.0.0/8", "10.1.0.0/16", "10.2.3.4"]),
            ["10.0.0.0/8"]
        );
        assert_eq!(
            agg(&["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/32"]
        );
        assert_eq!(
            agg(&[
                "2001:db8::/33",
                "2001:db8:8000::/33",
                "10.0.0.0/25",
                "10.0.0.128/25"
            ]),
            ["10.0.0.0/24", "2001:db8::/32"]
        );
        assert_eq!(agg(&["0.0.0.0/1", "128.0.0.0/1"]), ["0.0.0.0/0"]);
        assert_eq!(agg(&["::/1", "8000::/1", "::1"]), ["::/0"]);
        assert_eq!(
            agg(&["255.255.255.255", "255.255.255.254"]),
            ["255.255.255.254/31"]
        );
        assert_eq!(agg(&["10.0.0.5/24"]), ["10.0.0.0/24"]);
        assert_eq!(
            agg(&["10.0.0.0/24", "10.0.2.0/24"]),
            ["10.0.0.0/24", "10.0.2.0/24"]
        );
        assert_eq!(aggregate(&[]), Vec::<Cidr>::new());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_cidr() -> impl Strategy<Value = Cidr> {
        prop_oneof![
            (any::<u32>(), 0u8..=32).prop_map(|(a, p)| Cidr::V4(a, p)),
            (any::<u128>(), 0u8..=128).prop_map(|(a, p)| Cidr::V6(a, p)),
        ]
    }

    /// Small IPv4 ranges inside 10.0.0.0/20, so aggregation can be checked
    /// address by address.
    fn small_v4() -> impl Strategy<Value = Cidr> {
        (0u32..4096, 22u8..=32).prop_map(|(a, p)| Cidr::V4(0x0a00_0000 | a, p))
    }

    proptest! {
        #[test]
        fn parse_never_panics(s in "\\PC{0,48}") {
            let _ = Cidr::parse(&s);
        }

        #[test]
        fn contains_agrees_with_bounds(n in any_cidr(), a in any::<u128>()) {
            let addr = if n.is_ipv4() {
                IpAddr::V4(Ipv4Addr::from(u32::try_from(a >> 96).unwrap()))
            } else {
                IpAddr::V6(Ipv6Addr::from(a))
            };
            let (_, first, last) = n.bounds();
            let (_, v) = ip_parts(addr);
            prop_assert_eq!(n.contains(addr), first <= v && v <= last);
            prop_assert!(n.contains(n.network()) && n.contains(n.last()));
        }

        #[test]
        fn display_round_trips(n in any_cidr()) {
            prop_assert_eq!(Cidr::parse(&n.to_string()), Ok(n));
        }

        #[test]
        fn network_and_last_bound_the_range(n in any_cidr()) {
            prop_assert!(n.contains(n.network()));
            prop_assert!(n.contains(n.last()));
            prop_assert!(n.contains(n.addr()));
            prop_assert!(n.trunc().contains_cidr(&n) && n.contains_cidr(&n.trunc()));
        }

        #[test]
        fn supernet_contains_and_subnets_tile(n in any_cidr()) {
            if let Some(s) = n.supernet() {
                prop_assert!(s.contains_cidr(&n));
                prop_assert_eq!(s.prefix_len() + 1, n.prefix_len());
            }
            if let Some((a, b)) = n.subnets() {
                prop_assert!(n.contains_cidr(&a) && n.contains_cidr(&b));
                prop_assert!(!a.overlaps(&b));
                prop_assert_eq!(aggregate(&[a, b]), vec![n.trunc()]);
            }
        }

        #[test]
        fn split_is_contained_and_sized(n in any_cidr(), extra in 0u8..=6) {
            let target = n.prefix_len().saturating_add(extra).min(n.max_prefix_len());
            let parts: Vec<_> = n.split(target).unwrap().collect();
            prop_assert_eq!(parts.len(), 1usize << (target - n.prefix_len()));
            prop_assert!(parts.iter().all(|p| n.contains_cidr(p)));
            prop_assert_eq!(aggregate(&parts), vec![n.trunc()]);
        }

        #[test]
        fn aggregate_covers_exactly_the_inputs(nets in proptest::collection::vec(small_v4(), 0..8)) {
            let agg = aggregate(&nets);
            for a in 0u32..4096 {
                let addr = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | a));
                prop_assert_eq!(contains_any(addr, &nets), contains_any(addr, &agg));
            }
            for (i, x) in agg.iter().enumerate() {
                prop_assert_eq!(*x, x.trunc());
                for y in &agg[i + 1..] {
                    prop_assert!(!x.overlaps(y));
                    prop_assert!(x < y);
                }
            }
            prop_assert_eq!(aggregate(&agg), agg);
        }

        #[test]
        fn hosts_matches_host_count(a in any::<u32>(), p in 22u8..=32) {
            let n = Cidr::V4(a, p);
            let hosts: Vec<_> = n.hosts().collect();
            prop_assert_eq!(u128::try_from(hosts.len()).unwrap(), n.host_count());
            prop_assert_eq!(n.hosts().size_hint().0, hosts.len());
            prop_assert!(hosts.iter().all(|h| n.contains(*h)));
        }
    }
}
