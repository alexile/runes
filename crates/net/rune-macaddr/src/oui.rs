//! OUI / MA-L / MA-M / MA-S prefixes, registry records and the vendor
//! lookup table.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use crate::Error;
use crate::mac::{Eui64, MacAddr, hex_u64};
use crate::parse::{RegistryFormat, parse_registry};

/// Mask of the 48 bits an EUI-48 occupies in a `u64`.
const MAC_MASK: u64 = 0xffff_ffff_ffff;

/// A prefix of the 48-bit address space: an IEEE assignment block
/// (MA-L/OUI `/24`, MA-M `/28`, MA-S and IAB `/36`) or any other
/// `/1`–`/48` range.
///
/// The text form is the Wireshark `manuf` one: `00:1B:63` for a `/24`, and
/// all six octets with a length otherwise (`70:B3:D5:12:30:00/36`).
/// [`FromStr`] also takes hyphen or bare-hex notation, with the length
/// either explicit (`/36`) or implied by the digit count (`70B3D5123` is
/// nine hex digits, so a `/36`), as in the IEEE CSV files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OuiPrefix {
    /// Prefix bits in the low 48 bits, host bits cleared.
    value: u64,
    /// Prefix length in bits, `1..=48`.
    len: u8,
}

/// The mask of a `/len` prefix in the low 48 bits.
const fn mask(len: u8) -> u64 {
    if len == 0 {
        0
    } else {
        (u64::MAX << (48 - len as u32)) & MAC_MASK
    }
}

impl OuiPrefix {
    /// A prefix from the top `len` bits of a 48-bit `value` (the low 48 bits
    /// of the integer; host bits are cleared).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrefix`] unless `1 <= len <= 48` and `value` fits in
    /// 48 bits.
    pub const fn from_u64(value: u64, len: u8) -> Result<Self, Error> {
        if len == 0 || len > 48 {
            return Err(Error::InvalidPrefix("length must be between 1 and 48"));
        }
        if value & !MAC_MASK != 0 {
            return Err(Error::InvalidPrefix("value is wider than 48 bits"));
        }
        Ok(Self {
            value: value & mask(len),
            len,
        })
    }

    /// A prefix from compile-time constants: `len` is clamped to `1..=48`
    /// and `value` masked to it.
    pub(crate) const fn from_const(value: u64, len: u8) -> Self {
        let len = if len == 0 {
            1
        } else if len > 48 {
            48
        } else {
            len
        };
        Self {
            value: value & mask(len),
            len,
        }
    }

    /// The `/24` MA-L (OUI) prefix with these three octets.
    #[must_use]
    pub const fn oui(octets: [u8; 3]) -> Self {
        let value =
            ((octets[0] as u64) << 40) | ((octets[1] as u64) << 32) | ((octets[2] as u64) << 24);
        Self { value, len: 24 }
    }

    /// Parses an assignment as plain hex digits (`001B63`, `70B3D51`,
    /// `70B3D5123`): each digit is four bits of prefix, so 6, 7 and 9
    /// digits give a `/24`, `/28` and `/36`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrefix`] for an empty, non-hex or over-long string.
    pub fn from_hex_digits(digits: &str) -> Result<Self, Error> {
        let bytes = digits.as_bytes();
        if bytes.is_empty() || bytes.len() > 12 {
            return Err(Error::InvalidPrefix("expected 1 to 12 hex digits"));
        }
        let value = hex_u64(bytes).ok_or(Error::InvalidPrefix("invalid hex digit"))?;
        // At most 12 digits: the shift is at most 44 and the length at most 48.
        let bits = u8::try_from(bytes.len() * 4).map_err(|_| Error::InvalidPrefix("too long"))?;
        Self::from_u64(value << (48 - bits), bits)
    }

    /// Prefix length in bits, `1..=48`.
    #[must_use]
    pub const fn bits(&self) -> u8 {
        self.len
    }

    /// The first address of the prefix.
    #[must_use]
    pub fn network(&self) -> MacAddr {
        MacAddr::from_u64(self.value).unwrap_or_default()
    }

    /// The prefix bits in the low 48 bits of an integer.
    #[must_use]
    pub const fn to_u64(&self) -> u64 {
        self.value
    }

    /// Whether `mac` falls inside the prefix.
    #[must_use]
    pub fn contains(&self, mac: &MacAddr) -> bool {
        mac.to_u64() & mask(self.len) == self.value
    }

    /// Whether the top 48 bits of `eui` fall inside the prefix.
    #[must_use]
    pub const fn contains_eui64(&self, eui: &Eui64) -> bool {
        (eui.to_u64() >> 16) & mask(self.len) == self.value
    }
}

impl fmt::Display for OuiPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.value.to_be_bytes();
        if self.len == 24 {
            write!(f, "{:02X}:{:02X}:{:02X}", o[2], o[3], o[4])
        } else {
            write!(
                f,
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}/{}",
                o[2], o[3], o[4], o[5], o[6], o[7], self.len
            )
        }
    }
}

impl FromStr for OuiPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (body, len) = match s.split_once('/') {
            Some((body, len)) => {
                if len.is_empty() || len.len() > 2 || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::InvalidPrefix("invalid length"));
                }
                let len: u8 = len
                    .parse()
                    .map_err(|_| Error::InvalidPrefix("invalid length"))?;
                (body, Some(len))
            }
            None => (s, None),
        };
        let sep = body.bytes().find(|b| matches!(b, b':' | b'-' | b'.'));
        let digits: String = match sep {
            Some(sep @ (b':' | b'-')) => {
                let mut out = String::with_capacity(12);
                for group in body.split(char::from(sep)) {
                    match group.len() {
                        2 => out.push_str(group),
                        1 => {
                            out.push('0');
                            out.push_str(group);
                        }
                        _ => {
                            return Err(Error::InvalidPrefix(
                                "each octet must have one or two hex digits",
                            ));
                        }
                    }
                }
                out
            }
            Some(_) => return Err(Error::InvalidPrefix("unsupported separator")),
            None => body.to_owned(),
        };
        let prefix = Self::from_hex_digits(&digits)?;
        len.map_or(Ok(prefix), |len| Self::from_u64(prefix.value, len))
    }
}

/// The IEEE Registration Authority registry an assignment comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Registry {
    /// MAC Address Block Large (MA-L, the classic OUI): a `/24`.
    MaL,
    /// MAC Address Block Medium (MA-M): a `/28`.
    MaM,
    /// MAC Address Block Small (MA-S, formerly OUI-36): a `/36`.
    MaS,
    /// Individual Address Block (IAB, retired): a `/36`.
    Iab,
    /// Company ID (CID): a `/24` for locally administered addresses.
    Cid,
}

impl Registry {
    /// The registry's name as the IEEE CSV files spell it (`MA-L`, …).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MaL => "MA-L",
            Self::MaM => "MA-M",
            Self::MaS => "MA-S",
            Self::Iab => "IAB",
            Self::Cid => "CID",
        }
    }
}

impl fmt::Display for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Registry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.trim().to_ascii_uppercase().as_str() {
            "MA-L" | "OUI" => Ok(Self::MaL),
            "MA-M" => Ok(Self::MaM),
            "MA-S" | "OUI-36" | "OUI36" => Ok(Self::MaS),
            "IAB" => Ok(Self::Iab),
            "CID" => Ok(Self::Cid),
            _ => Err(Error::InvalidPrefix("unknown registry name")),
        }
    }
}

/// One assignment: a prefix and the organization it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct OuiRecord {
    /// The assigned prefix.
    pub prefix: OuiPrefix,
    /// The registry, when the source says (the IEEE CSV files do).
    pub registry: Option<Registry>,
    /// Organization name as registered.
    pub organization: String,
    /// Short name, when the source has one (Wireshark `manuf`).
    pub short_name: Option<String>,
    /// Postal address, when the source has one (IEEE CSV and text files).
    pub address: Option<String>,
}

impl OuiRecord {
    /// A record with just a prefix and an organization name.
    #[must_use]
    pub fn new(prefix: OuiPrefix, organization: impl Into<String>) -> Self {
        Self {
            prefix,
            registry: None,
            organization: organization.into(),
            short_name: None,
            address: None,
        }
    }

    /// Sets the registry.
    #[must_use]
    pub const fn with_registry(mut self, registry: Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Sets the short name.
    #[must_use]
    pub fn with_short_name(mut self, short_name: impl Into<String>) -> Self {
        self.short_name = Some(short_name.into());
        self
    }

    /// Sets the postal address.
    #[must_use]
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }
}

/// A vendor lookup table: prefix → [`OuiRecord`], answered by longest
/// prefix match, so an MA-S `/36` inside an MA-L `/24` wins.
///
/// The table ships empty: load the IEEE registry files (or a Wireshark
/// `manuf` file) yourself — see the crate docs for why no vendor data is
/// embedded.
#[derive(Debug, Clone, Default)]
pub struct OuiDb {
    by_prefix: HashMap<(u8, u64), OuiRecord>,
    /// Distinct prefix lengths present, longest first.
    lens: Vec<u8>,
}

impl OuiDb {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of prefixes in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_prefix.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_prefix.is_empty()
    }

    /// Adds a record, returning the one it replaces for the same prefix.
    pub fn insert(&mut self, record: OuiRecord) -> Option<OuiRecord> {
        let p = record.prefix;
        if let Err(at) = self.lens.binary_search_by(|l| p.len.cmp(l)) {
            self.lens.insert(at, p.len);
        }
        self.by_prefix.insert((p.len, p.value), record)
    }

    /// Adds every record from a parser, stopping at the first error.
    /// Returns the number of records added.
    pub fn try_extend<I>(&mut self, records: I) -> Result<usize, Error>
    where
        I: IntoIterator<Item = Result<OuiRecord, Error>>,
    {
        let mut n = 0;
        for record in records {
            self.insert(record?);
            n += 1;
        }
        Ok(n)
    }

    /// Detects the format of `text` (IEEE CSV, IEEE text or Wireshark
    /// `manuf`), parses it and adds every record. Returns the number of
    /// records added; on error, records before the bad line stay loaded.
    pub fn load(&mut self, text: &str) -> Result<usize, Error> {
        self.try_extend(parse_registry(text, RegistryFormat::detect(text)))
    }

    /// The record of exactly this prefix.
    #[must_use]
    pub fn get(&self, prefix: &OuiPrefix) -> Option<&OuiRecord> {
        self.by_prefix.get(&(prefix.len, prefix.value))
    }

    /// The record of the longest prefix containing a 48-bit value.
    fn longest(&self, value: u64) -> Option<&OuiRecord> {
        self.lens
            .iter()
            .find_map(|&len| self.by_prefix.get(&(len, value & mask(len))))
    }

    /// The assignment covering `mac`, by longest prefix match.
    ///
    /// A group address with no entry of its own falls back to the same
    /// address with the I/G bit cleared: the owner of an OUI also owns the
    /// group addresses under it (`01:00:5e:…` belongs to `00:00:5E`, IANA).
    #[must_use]
    pub fn lookup(&self, mac: &MacAddr) -> Option<&OuiRecord> {
        self.longest(mac.to_u64()).or_else(|| {
            mac.is_multicast()
                .then(|| self.longest(mac.with_multicast(false).to_u64()))
                .flatten()
        })
    }

    /// The assignment covering an EUI-64, matched on its top 48 bits, with
    /// the same group-address fallback as [`lookup`](Self::lookup).
    #[must_use]
    pub fn lookup_eui64(&self, eui: &Eui64) -> Option<&OuiRecord> {
        let top = |e: &Eui64| e.to_u64() >> 16;
        self.longest(top(eui)).or_else(|| {
            eui.is_multicast()
                .then(|| self.longest(top(&eui.with_multicast(false))))
                .flatten()
        })
    }

    /// The organization owning `mac`, if known.
    #[must_use]
    pub fn vendor(&self, mac: &MacAddr) -> Option<&str> {
        self.lookup(mac).map(|r| r.organization.as_str())
    }

    /// Every record, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &OuiRecord> {
        self.by_prefix.values()
    }
}

impl Extend<OuiRecord> for OuiDb {
    fn extend<T: IntoIterator<Item = OuiRecord>>(&mut self, iter: T) {
        for record in iter {
            self.insert(record);
        }
    }
}

impl FromIterator<OuiRecord> for OuiDb {
    fn from_iter<T: IntoIterator<Item = OuiRecord>>(iter: T) -> Self {
        let mut db = Self::new();
        db.extend(iter);
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_text_forms() {
        let p: OuiPrefix = "00:1B:63".parse().unwrap();
        assert_eq!(p, OuiPrefix::oui([0x00, 0x1b, 0x63]));
        assert_eq!(p.to_string(), "00:1B:63");
        assert_eq!("00-1b-63".parse::<OuiPrefix>(), Ok(p));
        assert_eq!("001B63".parse::<OuiPrefix>(), Ok(p));
        assert_eq!("0:1b:63".parse::<OuiPrefix>(), Ok(p));
        let s: OuiPrefix = "70:B3:D5:12:30:00/36".parse().unwrap();
        assert_eq!(s.bits(), 36);
        assert_eq!(s.to_string(), "70:B3:D5:12:30:00/36");
        assert_eq!(OuiPrefix::from_hex_digits("70B3D5123"), Ok(s));
        assert_eq!(OuiPrefix::from_hex_digits("70B3D51").unwrap().bits(), 28);
        // Host bits are cleared.
        assert_eq!("70:B3:D5:12:3F:FF/36".parse::<OuiPrefix>(), Ok(s));
        for bad in [
            "",
            "/24",
            "00:1B:63/0",
            "00:1B:63/49",
            "00:1B:63/x",
            "001.B63",
            "0011223344556",
            "00:1B:633",
        ] {
            assert!(bad.parse::<OuiPrefix>().is_err(), "{bad}");
        }
        assert!(s.contains(&mac("70:b3:d5:12:3a:bc")));
        assert!(!s.contains(&mac("70:b3:d5:12:4a:bc")));
        assert_eq!(s.network(), mac("70:b3:d5:12:30:00"));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut db = OuiDb::new();
        db.insert(
            OuiRecord::new("70:B3:D5".parse().unwrap(), "IEEE Registration Authority")
                .with_registry(Registry::MaL),
        );
        db.insert(
            OuiRecord::new("70B3D5123".parse().unwrap(), "Small Co").with_registry(Registry::MaS),
        );
        db.insert(OuiRecord::new(
            "00:00:5E".parse().unwrap(),
            "ICANN, IANA Department",
        ));
        assert_eq!(db.len(), 3);
        assert_eq!(db.vendor(&mac("70:b3:d5:12:3f:00")), Some("Small Co"));
        assert_eq!(
            db.vendor(&mac("70:b3:d5:99:00:00")),
            Some("IEEE Registration Authority")
        );
        assert_eq!(
            db.vendor(&mac("01:00:5e:00:00:fb")),
            Some("ICANN, IANA Department")
        );
        assert_eq!(db.vendor(&mac("00:11:22:33:44:55")), None);
        let eui: Eui64 = "70:b3:d5:12:3f:00:00:01".parse().unwrap();
        assert_eq!(
            db.lookup_eui64(&eui).map(|r| r.registry),
            Some(Some(Registry::MaS))
        );
        let replaced = db.insert(OuiRecord::new("00:00:5E".parse().unwrap(), "IANA"));
        assert_eq!(
            replaced.map(|r| r.organization),
            Some("ICANN, IANA Department".into())
        );
        assert_eq!(db.len(), 3);
    }

    #[test]
    fn registry_names() {
        for r in [
            Registry::MaL,
            Registry::MaM,
            Registry::MaS,
            Registry::Iab,
            Registry::Cid,
        ] {
            assert_eq!(r.as_str().parse::<Registry>(), Ok(r));
        }
        assert!("MA-X".parse::<Registry>().is_err());
    }
}
