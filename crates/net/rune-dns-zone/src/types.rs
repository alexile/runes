//! Record type mnemonics beyond the ones `rune-dns-wire` names.

use rune_dns_wire::RecordType;

/// Mnemonics this crate knows in addition to [`RecordType::mnemonic`].
const EXTRA: &[(u16, &str)] = &[
    (14, "MINFO"),
    (17, "RP"),
    (18, "AFSDB"),
    (29, "LOC"),
    (36, "KX"),
    (37, "CERT"),
    (39, "DNAME"),
    (53, "SMIMEA"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (61, "OPENPGPKEY"),
    (63, "ZONEMD"),
    (99, "SPF"),
    (256, "URI"),
];

/// Parses a record type: a mnemonic (case-insensitive) or `TYPE<n>`.
///
/// Knows every mnemonic [`RecordType`] does, plus `MINFO`, `RP`, `AFSDB`,
/// `LOC`, `KX`, `CERT`, `DNAME`, `SMIMEA`, `CDS`, `CDNSKEY`, `OPENPGPKEY`,
/// `ZONEMD`, `SPF` and `URI`.
///
/// ```
/// use rune_dns_wire::RecordType;
/// use rune_dns_zone::parse_record_type;
///
/// assert_eq!(parse_record_type("afsdb"), Some(RecordType(18)));
/// assert_eq!(parse_record_type("MX"), Some(RecordType::MX));
/// assert_eq!(parse_record_type("TYPE65280"), Some(RecordType(65_280)));
/// assert_eq!(parse_record_type("BOGUS"), None);
/// ```
#[must_use]
pub fn parse_record_type(text: &str) -> Option<RecordType> {
    EXTRA
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(text))
        .map(|&(code, _)| RecordType(code))
        .or_else(|| text.parse().ok())
}

/// The mnemonic of a record type, or `TYPE<n>` for one without a name; the
/// inverse of [`parse_record_type`].
///
/// ```
/// use rune_dns_wire::RecordType;
/// use rune_dns_zone::record_type_name;
///
/// assert_eq!(record_type_name(RecordType(29)), "LOC");
/// assert_eq!(record_type_name(RecordType::AAAA), "AAAA");
/// assert_eq!(record_type_name(RecordType(65_280)), "TYPE65280");
/// ```
#[must_use]
pub fn record_type_name(rtype: RecordType) -> String {
    EXTRA
        .iter()
        .find(|&&(code, _)| code == rtype.0)
        .map_or_else(|| rtype.to_string(), |&(_, name)| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for code in 0..=1024u16 {
            let rtype = RecordType(code);
            assert_eq!(parse_record_type(&record_type_name(rtype)), Some(rtype));
        }
    }
}
