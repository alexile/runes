//! Protocol-defined address ranges, from published standards (not from the
//! IEEE vendor registry).

use crate::mac::MacAddr;
use crate::oui::OuiPrefix;

/// A range of addresses whose meaning a protocol standard defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct WellKnown {
    /// The range.
    pub prefix: OuiPrefix,
    /// What the addresses are used for.
    pub name: &'static str,
    /// The defining document.
    pub reference: &'static str,
}

/// Builds a table entry; the inputs are compile-time constants.
const fn entry(value: u64, len: u8, name: &'static str, reference: &'static str) -> WellKnown {
    WellKnown {
        prefix: OuiPrefix::from_const(value, len),
        name,
        reference,
    }
}

/// The built-in table, in no particular order.
pub static WELL_KNOWN: &[WellKnown] = &[
    entry(0xffff_ffff_ffff, 48, "Broadcast", "IEEE 802"),
    entry(
        0x0180_c200_0000,
        44,
        "IEEE 802.1 reserved group address",
        "IEEE 802.1Q, Table 8-1",
    ),
    entry(
        0x0180_c200_0000,
        48,
        "Nearest Customer Bridge (STP/RSTP/MSTP BPDUs)",
        "IEEE 802.1Q",
    ),
    entry(
        0x0180_c200_0001,
        48,
        "MAC Control (PAUSE)",
        "IEEE 802.3, Annex 31B",
    ),
    entry(
        0x0180_c200_0002,
        48,
        "Slow Protocols (LACP, Marker, OAM)",
        "IEEE 802.3, Annex 43B",
    ),
    entry(
        0x0180_c200_0003,
        48,
        "Nearest non-TPMR Bridge (802.1X PAE)",
        "IEEE 802.1X",
    ),
    entry(
        0x0180_c200_000e,
        48,
        "Nearest Bridge (LLDP, PTP peer delay)",
        "IEEE 802.1AB",
    ),
    entry(
        0x0180_c200_0020,
        44,
        "GARP/MRP application address",
        "IEEE 802.1Q",
    ),
    entry(
        0x011b_1900_0000,
        48,
        "PTP over Ethernet (forwardable)",
        "IEEE 1588, Annex F",
    ),
    entry(0x0000_5e00_0000, 24, "IANA unicast", "RFC 7042"),
    entry(0x0000_5e00_0100, 40, "VRRP IPv4 virtual router", "RFC 5798"),
    entry(0x0000_5e00_0200, 40, "VRRP IPv6 virtual router", "RFC 5798"),
    entry(0x0100_5e00_0000, 24, "IANA multicast", "RFC 7042"),
    entry(0x0100_5e00_0000, 25, "IPv4 multicast", "RFC 1112"),
    entry(0x0100_5e80_0000, 28, "MPLS multicast", "RFC 7213"),
    entry(0x3333_0000_0000, 16, "IPv6 multicast", "RFC 2464"),
];

/// The most specific built-in [`WellKnown`] range containing `mac`.
///
/// ```
/// use rune_macaddr::{MacAddr, well_known};
///
/// let mdns: MacAddr = "01:00:5e:00:00:fb".parse()?;
/// assert_eq!(well_known(&mdns).map(|w| w.name), Some("IPv4 multicast"));
/// # Ok::<(), rune_macaddr::Error>(())
/// ```
#[must_use]
pub fn well_known(mac: &MacAddr) -> Option<&'static WellKnown> {
    WELL_KNOWN
        .iter()
        .filter(|w| w.prefix.contains(mac))
        .max_by_key(|w| w.prefix.bits())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Option<&'static str> {
        well_known(&s.parse().unwrap()).map(|w| w.name)
    }

    #[test]
    fn every_entry_is_reachable() {
        for w in WELL_KNOWN {
            let hit = well_known(&w.prefix.network()).unwrap();
            assert!(hit.prefix.bits() >= w.prefix.bits(), "{}", w.name);
        }
    }

    #[test]
    fn most_specific_wins() {
        assert_eq!(name("ff:ff:ff:ff:ff:ff"), Some("Broadcast"));
        assert_eq!(
            name("01:80:c2:00:00:0e"),
            Some("Nearest Bridge (LLDP, PTP peer delay)")
        );
        assert_eq!(
            name("01:80:c2:00:00:05"),
            Some("IEEE 802.1 reserved group address")
        );
        assert_eq!(name("01:00:5e:00:00:fb"), Some("IPv4 multicast"));
        assert_eq!(name("01:00:5e:80:00:01"), Some("MPLS multicast"));
        assert_eq!(name("01:00:5e:90:00:01"), Some("IANA multicast"));
        assert_eq!(name("33:33:00:00:00:01"), Some("IPv6 multicast"));
        assert_eq!(name("00:00:5e:00:01:07"), Some("VRRP IPv4 virtual router"));
        assert_eq!(name("00:1b:63:84:45:e6"), None);
    }
}
