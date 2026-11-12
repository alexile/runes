//! A longest-prefix-match table over [`Cidr`] keys.
//!
//! Prefixes are stored in one hash map per prefix length, keyed by the
//! network address. A lookup probes only the lengths that are present, from
//! the longest down, so it costs at most 33 (IPv4) or 129 (IPv6) hash
//! probes and in practice around two dozen for a full BGP table. Memory is
//! proportional to the number of prefixes, unlike an uncompressed bit trie.

use std::collections::HashMap;
use std::net::IpAddr;

use rune_cidr::Cidr;

/// Split a range into (family bits, network as integer, prefix length),
/// with the host bits cleared.
pub fn cidr_parts(cidr: Cidr) -> (u8, u128, u8) {
    match cidr.trunc() {
        Cidr::V4(addr, len) => (32, u128::from(addr), len),
        Cidr::V6(addr, len) => (128, addr, len),
    }
}

/// (family bits, address as integer).
pub fn ip_parts(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(v4) => (32, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (128, u128::from(v6)),
    }
}

/// The range with family `bits`, network `value` and length `len`.
pub fn make_cidr(bits: u8, value: u128, len: u8) -> Cidr {
    if bits == 32 {
        Cidr::V4(u32::try_from(value).unwrap_or(u32::MAX), len)
    } else {
        Cidr::V6(value, len)
    }
}

/// Network mask for a `len`-bit prefix in a family of `bits` bits.
fn mask(bits: u8, len: u8) -> u128 {
    let ones = u128::MAX.checked_shl(u32::from(128 - len)).unwrap_or(0);
    ones >> (128 - bits)
}

/// One address family's prefixes, one map per prefix length.
#[derive(Debug, Clone)]
struct Family<V> {
    bits: u8,
    by_len: Vec<HashMap<u128, V>>,
    /// Lengths with at least one prefix, longest first.
    present: Vec<u8>,
}

impl<V> Family<V> {
    fn new(bits: u8) -> Self {
        Self {
            bits,
            by_len: (0..=bits).map(|_| HashMap::new()).collect(),
            present: Vec::new(),
        }
    }

    fn entry(&mut self, value: u128, len: u8, default: impl FnOnce() -> V) -> &mut V {
        let idx = usize::from(len);
        if let Err(pos) = self.present.binary_search_by(|l| len.cmp(l)) {
            self.present.insert(pos, len);
        }
        // `len <= bits`, so `by_len` has the slot; the fallback is unreachable
        // and only keeps the code panic-free.
        if idx >= self.by_len.len() {
            self.by_len.resize_with(idx + 1, HashMap::new);
        }
        self.by_len[idx].entry(value).or_insert_with(default)
    }

    fn get(&self, value: u128, len: u8) -> Option<&V> {
        self.by_len.get(usize::from(len))?.get(&value)
    }

    fn longest(&self, addr: u128) -> Option<(Cidr, &V)> {
        self.present.iter().find_map(|&len| {
            let net = addr & mask(self.bits, len);
            self.get(net, len)
                .map(|v| (make_cidr(self.bits, net, len), v))
        })
    }

    fn all(&self, addr: u128) -> impl Iterator<Item = (Cidr, &V)> {
        self.present.iter().rev().filter_map(move |&len| {
            let net = addr & mask(self.bits, len);
            self.get(net, len)
                .map(|v| (make_cidr(self.bits, net, len), v))
        })
    }

    fn len(&self) -> usize {
        self.by_len.iter().map(HashMap::len).sum()
    }

    fn iter(&self) -> impl Iterator<Item = (Cidr, &V)> {
        self.by_len.iter().enumerate().flat_map(move |(len, map)| {
            let len = u8::try_from(len).unwrap_or(u8::MAX);
            map.iter()
                .map(move |(&net, v)| (make_cidr(self.bits, net, len), v))
        })
    }
}

/// A map from CIDR prefixes to values with longest-prefix-match lookup.
#[derive(Debug, Clone)]
pub struct PrefixTable<V> {
    v4: Family<V>,
    v6: Family<V>,
}

impl<V> Default for PrefixTable<V> {
    fn default() -> Self {
        Self {
            v4: Family::new(32),
            v6: Family::new(128),
        }
    }
}

impl<V> PrefixTable<V> {
    const fn family(&self, bits: u8) -> &Family<V> {
        if bits == 32 { &self.v4 } else { &self.v6 }
    }

    /// The value stored for `prefix` (host bits ignored), inserting
    /// `default()` first if there is none.
    pub fn entry(&mut self, prefix: Cidr, default: impl FnOnce() -> V) -> &mut V {
        let (bits, value, len) = cidr_parts(prefix);
        let family = if bits == 32 {
            &mut self.v4
        } else {
            &mut self.v6
        };
        family.entry(value, len, default)
    }

    /// The most specific prefix containing `ip`, with its value.
    pub fn longest_match(&self, ip: IpAddr) -> Option<(Cidr, &V)> {
        let (bits, addr) = ip_parts(ip);
        self.family(bits).longest(addr)
    }

    /// Every prefix containing `ip`, least specific first.
    pub fn matches(&self, ip: IpAddr) -> impl Iterator<Item = (Cidr, &V)> {
        let (bits, addr) = ip_parts(ip);
        self.family(bits).all(addr)
    }

    /// Number of distinct prefixes.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Every prefix and value, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (Cidr, &V)> {
        self.v4.iter().chain(self.v6.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    #[test]
    fn longest_match_prefers_the_most_specific_prefix() {
        let mut t = PrefixTable::default();
        *t.entry(c("10.0.0.0/8"), || 0) = 8;
        *t.entry(c("10.1.0.0/16"), || 0) = 16;
        *t.entry(c("::/0"), || 0) = 1;
        let ip = "10.1.2.3".parse().unwrap();
        assert_eq!(t.longest_match(ip), Some((c("10.1.0.0/16"), &16)));
        let all: Vec<_> = t.matches(ip).map(|(p, _)| p).collect();
        assert_eq!(all, [c("10.0.0.0/8"), c("10.1.0.0/16")]);
        assert_eq!(
            t.longest_match("10.2.0.0".parse().unwrap()),
            Some((c("10.0.0.0/8"), &8))
        );
        assert_eq!(t.longest_match("11.0.0.0".parse().unwrap()), None);
        assert_eq!(
            t.longest_match("2001:db8::1".parse().unwrap()),
            Some((c("::/0"), &1))
        );
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn host_bits_are_ignored() {
        let mut t = PrefixTable::default();
        *t.entry(c("192.0.2.77/24"), || 0) = 1;
        assert_eq!(
            t.longest_match("192.0.2.1".parse().unwrap()),
            Some((c("192.0.2.0/24"), &1))
        );
    }
}
