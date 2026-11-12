//! Port lists: parsing, formatting and the top-ports table.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// Commonly open TCP ports, most frequently open first.
///
/// The order follows public port-frequency surveys (nmap's
/// `nmap-services` open-frequency ranking); `top-N` in a port list takes
/// the first `N` entries.
pub const TOP_PORTS: [u16; 100] = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

/// An ordered set of TCP ports (1–65535), without duplicates.
///
/// Ports keep the order in which they were first added, so `top-20`
/// scans the most likely ports first. Parse one from a list such as
/// `22,80,443,8000-8100,top-20`:
///
/// - `N` — a single port;
/// - `A-B` — an inclusive range; `A-` runs to 65535 and `-B` starts at 1;
/// - `-` or `all` — every port;
/// - `top-N` — the first `N` of [`TOP_PORTS`].
///
/// Items are separated by commas; whitespace around items is ignored.
/// Port 0 is rejected.
///
/// ```
/// use rune_port_scan::PortSet;
///
/// let ports: PortSet = "443, 80, 8000-8002, 80, top-3".parse()?;
/// assert_eq!(ports.as_slice(), [443, 80, 8000, 8001, 8002, 23]);
/// assert_eq!(ports.to_string(), "443,80,8000-8002,23");
/// # Ok::<(), rune_port_scan::Error>(())
/// ```
#[derive(Clone)]
pub struct PortSet {
    ports: Vec<u16>,
    seen: Box<[u64]>,
}

impl PortSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            seen: vec![0; 1024].into_boxed_slice(),
        }
    }

    /// Parses a port list (see the type docs for the syntax).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPorts`] for an empty list, an empty item, a port
    /// outside 1–65535, a reversed range or an oversized `top-N`.
    pub fn parse(list: &str) -> Result<Self> {
        let mut set = Self::new();
        for item in list.split(',') {
            set.parse_item(item.trim())?;
        }
        Ok(set)
    }

    /// The first `n` of [`TOP_PORTS`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPorts`] if `n` is 0 or larger than the table.
    pub fn top(n: usize) -> Result<Self> {
        let mut set = Self::new();
        set.add_top(n, "top")?;
        Ok(set)
    }

    /// Every port, 1–65535.
    #[must_use]
    pub fn all() -> Self {
        Self::from_iter(1..=u16::MAX)
    }

    /// Adds `port` if it is not already present. Port 0 is ignored.
    /// Returns whether it was added.
    pub fn insert(&mut self, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        let (word, bit) = (usize::from(port / 64), port % 64);
        let Some(slot) = self.seen.get_mut(word) else {
            return false;
        };
        if *slot & (1 << bit) != 0 {
            return false;
        }
        *slot |= 1 << bit;
        self.ports.push(port);
        true
    }

    /// Whether `port` is in the set.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        let (word, bit) = (usize::from(port / 64), port % 64);
        port != 0 && self.seen.get(word).is_some_and(|w| w & (1 << bit) != 0)
    }

    /// The ports, in insertion order.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.ports
    }

    /// Iterates over the ports in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u16> + '_ {
        self.ports.iter().copied()
    }

    /// Number of ports.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ports.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }

    fn parse_item(&mut self, item: &str) -> Result<()> {
        if item.is_empty() {
            return Err(Error::invalid(item, "empty item"));
        }
        if item == "-" || item.eq_ignore_ascii_case("all") {
            self.extend(1..=u16::MAX);
            return Ok(());
        }
        if let Some(n) = strip_prefix_ignore_case(item, "top-") {
            let n = n
                .parse::<usize>()
                .map_err(|_| Error::invalid(item, "top-N needs a number"))?;
            return self.add_top(n, item);
        }
        match item.split_once('-') {
            None => {
                let port = parse_port(item, item)?;
                self.insert(port);
            }
            Some((start, end)) => {
                let start = if start.trim().is_empty() {
                    1
                } else {
                    parse_port(start.trim(), item)?
                };
                let end = if end.trim().is_empty() {
                    u16::MAX
                } else {
                    parse_port(end.trim(), item)?
                };
                if start > end {
                    return Err(Error::invalid(item, "range start is after its end"));
                }
                self.extend(start..=end);
            }
        }
        Ok(())
    }

    fn add_top(&mut self, n: usize, item: &str) -> Result<()> {
        if n == 0 {
            return Err(Error::invalid(item, "top-N needs N of at least 1"));
        }
        let Some(ports) = TOP_PORTS.get(..n) else {
            return Err(Error::invalid(
                item,
                "top-N is limited to the 100-entry table",
            ));
        };
        self.extend(ports.iter().copied());
        Ok(())
    }
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

fn parse_port(text: &str, item: &str) -> Result<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::invalid(item, "not a port number"));
    }
    match text.parse::<u16>() {
        Ok(0) => Err(Error::invalid(item, "port 0 is not scannable")),
        Ok(port) => Ok(port),
        Err(_) => Err(Error::invalid(item, "port is above 65535")),
    }
}

impl Default for PortSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Two sets are equal when they hold the same ports in the same order.
impl PartialEq for PortSet {
    fn eq(&self, other: &Self) -> bool {
        self.ports == other.ports
    }
}

impl Eq for PortSet {}

impl Extend<u16> for PortSet {
    fn extend<I: IntoIterator<Item = u16>>(&mut self, iter: I) {
        for port in iter {
            self.insert(port);
        }
    }
}

impl FromIterator<u16> for PortSet {
    fn from_iter<I: IntoIterator<Item = u16>>(iter: I) -> Self {
        let mut set = Self::new();
        set.extend(iter);
        set
    }
}

impl<'a> IntoIterator for &'a PortSet {
    type Item = u16;
    type IntoIter = std::iter::Copied<std::slice::Iter<'a, u16>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ports.iter().copied()
    }
}

impl FromStr for PortSet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Debug for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PortSet").field(&self.to_string()).finish()
    }
}

/// The canonical list form: insertion order, with ascending consecutive
/// runs written as ranges. It parses back to an equal set.
impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut ports = self.ports.iter().copied().peekable();
        while let Some(start) = ports.next() {
            let mut end = start;
            while let Some(&next) = ports.peek() {
                if end.checked_add(1) != Some(next) {
                    break;
                }
                end = next;
                ports.next();
            }
            if !first {
                f.write_str(",")?;
            }
            first = false;
            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PortSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PortSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_singles_ranges_and_dedups() {
        let ports = PortSet::parse("80, 443,8000-8003,80,8002").unwrap();
        assert_eq!(ports.as_slice(), [80, 443, 8000, 8001, 8002, 8003]);
        assert!(ports.contains(8001) && !ports.contains(8004) && !ports.contains(0));
    }

    #[test]
    fn open_ended_ranges_and_all() {
        assert_eq!(PortSet::parse("65530-").unwrap().len(), 6);
        assert_eq!(PortSet::parse("-3").unwrap().as_slice(), [1, 2, 3]);
        assert_eq!(PortSet::parse("-").unwrap().len(), 65535);
        assert_eq!(PortSet::parse("ALL").unwrap(), PortSet::all());
    }

    #[test]
    fn top_ports() {
        assert_eq!(PortSet::parse("top-3").unwrap().as_slice(), [80, 23, 443]);
        assert_eq!(PortSet::top(100).unwrap().len(), 100);
        assert!(PortSet::top(101).is_err());
        assert!(PortSet::top(0).is_err());
        let mut sorted = TOP_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TOP_PORTS.len());
        assert!(!TOP_PORTS.contains(&0));
    }

    #[test]
    fn rejects_bad_items() {
        for bad in [
            "", "80,", "0", "65536", "80-79", "http", "+80", "top-", "top-x", "1-2-3", "top-101",
        ] {
            assert!(
                matches!(PortSet::parse(bad), Err(Error::InvalidPorts { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn displays_ranges_in_order() {
        let ports = PortSet::parse("9,1-3,4,10,8").unwrap();
        assert_eq!(ports.to_string(), "9,1-4,10,8");
        assert_eq!(PortSet::all().to_string(), "1-65535");
        assert_eq!(PortSet::new().to_string(), "");
        assert_eq!(
            format!("{:?}", PortSet::parse("1-2").unwrap()),
            "PortSet(\"1-2\")"
        );
    }

    #[test]
    fn default_set_accepts_inserts() {
        let mut ports = PortSet::default();
        assert!(ports.is_empty());
        assert!(ports.insert(22));
        assert!(!ports.insert(22));
        assert!(!ports.insert(0));
        assert_eq!(ports.as_slice(), [22]);
    }
}
