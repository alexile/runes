//! Parsers for the registry files vendor data is distributed in.

use std::iter::{Enumerate, Peekable};
use std::str::Lines;

use crate::Error;
use crate::mac::hex_u64;
use crate::oui::{OuiPrefix, OuiRecord};

/// The file formats [`parse_registry`] understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryFormat {
    /// IEEE RA CSV (`oui.csv`, `mam.csv`, `oui36.csv`, `iab.csv`,
    /// `cid.csv`): `Registry,Assignment,Organization Name,Organization Address`.
    IeeeCsv,
    /// IEEE RA text (`oui.txt`, `mam.txt`, `oui36.txt`, `iab.txt`): a
    /// `(hex)` line, a `(base 16)` line and indented address lines per
    /// assignment.
    IeeeTxt,
    /// Wireshark `manuf`: `prefix<TAB>short name[<TAB>long name]`, with
    /// `#` comments.
    Manuf,
}

impl RegistryFormat {
    /// Guesses the format from the content: a CSV header or an IEEE
    /// `(hex)` line, else Wireshark `manuf`.
    #[must_use]
    pub fn detect(text: &str) -> Self {
        let first = text
            .trim_start_matches('\u{feff}')
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .unwrap_or_default();
        if first.to_ascii_lowercase().starts_with("registry,") {
            Self::IeeeCsv
        } else if text
            .lines()
            .take(64)
            .any(|l| l.contains("(hex)") || l.contains("(base 16)"))
        {
            Self::IeeeTxt
        } else {
            Self::Manuf
        }
    }
}

/// Iterator over the records of a registry file; see [`parse_registry`].
#[derive(Debug, Clone)]
pub struct Records<'a> {
    lines: Peekable<Enumerate<Lines<'a>>>,
    format: RegistryFormat,
    /// IEEE text files: the OUI of the last `(hex)` line.
    prev_hex: Option<[u8; 3]>,
}

/// Parses `text` in `format`, yielding one record per assignment.
///
/// Blank lines, comments and the CSV header are skipped; a malformed line
/// yields [`Error::Parse`] with its 1-based number and iteration continues
/// with the next line.
#[must_use]
pub fn parse_registry(text: &str, format: RegistryFormat) -> Records<'_> {
    Records {
        lines: text
            .trim_start_matches('\u{feff}')
            .lines()
            .enumerate()
            .peekable(),
        format,
        prev_hex: None,
    }
}

/// Parses an IEEE RA CSV file (`oui.csv`, `mam.csv`, `oui36.csv`, …).
#[must_use]
pub fn parse_ieee_csv(text: &str) -> Records<'_> {
    parse_registry(text, RegistryFormat::IeeeCsv)
}

/// Parses an IEEE RA text file (`oui.txt`, `mam.txt`, `oui36.txt`, …).
#[must_use]
pub fn parse_ieee_txt(text: &str) -> Records<'_> {
    parse_registry(text, RegistryFormat::IeeeTxt)
}

/// Parses a Wireshark `manuf` file.
#[must_use]
pub fn parse_manuf(text: &str) -> Records<'_> {
    parse_registry(text, RegistryFormat::Manuf)
}

impl Iterator for Records<'_> {
    type Item = Result<OuiRecord, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (i, raw) = self.lines.next()?;
            let line = raw.trim_end_matches('\r');
            let parsed = match self.format {
                RegistryFormat::IeeeCsv => csv_line(line),
                RegistryFormat::IeeeTxt => self.txt_line(line),
                RegistryFormat::Manuf => manuf_line(line),
            };
            match parsed {
                Ok(None) => {}
                Ok(Some(record)) => return Some(Ok(record)),
                Err(reason) => {
                    return Some(Err(Error::Parse {
                        line: i + 1,
                        reason: reason.to_owned(),
                    }));
                }
            }
        }
    }
}

/// Trims and drops an empty string.
fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// Splits one CSV line (RFC 4180 quoting, no embedded newlines).
fn csv_fields(line: &str) -> Result<Vec<String>, &'static str> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    let mut at_start = true;
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
        } else if c == '"' && at_start {
            quoted = true;
            at_start = false;
        } else if c == ',' {
            fields.push(std::mem::take(&mut field));
            at_start = true;
        } else {
            field.push(c);
            at_start = false;
        }
    }
    if quoted {
        return Err("unterminated quoted field");
    }
    fields.push(field);
    Ok(fields)
}

/// One line of an IEEE CSV file.
fn csv_line(line: &str) -> Result<Option<OuiRecord>, &'static str> {
    if line.trim().is_empty() || line.to_ascii_lowercase().starts_with("registry,") {
        return Ok(None);
    }
    let fields = csv_fields(line)?;
    let [registry, assignment, organization, rest @ ..] = fields.as_slice() else {
        return Err("expected at least three fields");
    };
    let prefix = OuiPrefix::from_hex_digits(assignment.trim()).map_err(|_| "invalid assignment")?;
    let organization = non_empty(organization).ok_or("missing organization name")?;
    Ok(Some(OuiRecord {
        prefix,
        registry: registry.parse().ok(),
        organization,
        short_name: None,
        address: rest.first().and_then(|a| non_empty(a)),
    }))
}

/// Text after a marker such as `(hex)`, trimmed.
fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.find(marker).map(|at| line[at + marker.len()..].trim())
}

/// Parses `XX-XX-XX` into three octets.
fn hyphen_oui(token: &str) -> Option<[u8; 3]> {
    let mut out = [0u8; 3];
    let mut parts = token.split('-');
    for slot in &mut out {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::try_from(hex_u64(part.as_bytes())?).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The prefix of a `(base 16)` line under OUI `oui`: either the OUI itself
/// (`001B63`) or a range of the remaining 24 bits (`E00000-EFFFFF`).
fn base16_prefix(oui: [u8; 3], token: &str) -> Result<OuiPrefix, &'static str> {
    let base = OuiPrefix::oui(oui).to_u64();
    let six = |s: &str| {
        (s.len() == 6)
            .then(|| hex_u64(s.as_bytes()))
            .flatten()
            .ok_or("invalid base-16 assignment")
    };
    match token.split_once('-') {
        None => {
            if six(token)? << 24 != base {
                return Err("base-16 assignment does not match the hex line");
            }
            Ok(OuiPrefix::oui(oui))
        }
        Some((start, end)) => {
            let (start, end) = (six(start)?, six(end)?);
            let span = start ^ end;
            if end < start || start & span != 0 || end != start | span || span & (span + 1) != 0 {
                return Err("range is not an aligned power-of-two block");
            }
            // `span` is 2^k - 1 with k <= 24, so the length is 24..=48.
            let len = 48 - span.count_ones();
            let len = u8::try_from(len).map_err(|_| "invalid range")?;
            OuiPrefix::from_u64(base | start, len).map_err(|_| "invalid range")
        }
    }
}

impl Records<'_> {
    /// One line of an IEEE text file; consumes the address lines that
    /// follow a `(base 16)` line.
    fn txt_line(&mut self, line: &str) -> Result<Option<OuiRecord>, &'static str> {
        if after(line, "(hex)").is_some() {
            let token = line.split_whitespace().next().unwrap_or_default();
            self.prev_hex = Some(hyphen_oui(token).ok_or("invalid (hex) line")?);
            return Ok(None);
        }
        let Some(name) = after(line, "(base 16)") else {
            return Ok(None); // headers, blank lines
        };
        let token = line.split_whitespace().next().unwrap_or_default();
        // The OUI of a range comes from the `(hex)` line just above it,
        // which an MA-L entry repeats; take it from there when present.
        let prev_hex = self.prev_hex.take();
        let oui = match prev_hex {
            Some(oui) => oui,
            None if !token.contains('-') => {
                let v = (token.len() == 6)
                    .then(|| hex_u64(token.as_bytes()))
                    .flatten()
                    .ok_or("invalid base-16 assignment")?;
                let b = v.to_be_bytes();
                [b[5], b[6], b[7]]
            }
            None => return Err("range without a preceding (hex) line"),
        };
        let prefix = base16_prefix(oui, token)?;
        let organization = non_empty(name).ok_or("missing organization name")?;
        let mut address = Vec::new();
        while let Some((_, next)) = self.lines.peek() {
            let next = next.trim_end_matches('\r');
            if next.trim().is_empty() || !next.starts_with([' ', '\t']) {
                break;
            }
            address.push(next.trim());
            self.lines.next();
        }
        Ok(Some(OuiRecord {
            prefix,
            registry: None,
            organization,
            short_name: None,
            address: (!address.is_empty()).then(|| address.join(", ")),
        }))
    }
}

/// One line of a Wireshark `manuf` file.
fn manuf_line(line: &str) -> Result<Option<OuiRecord>, &'static str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (prefix, rest) = line
        .split_once(|c: char| c.is_ascii_whitespace())
        .ok_or("missing vendor name")?;
    let prefix: OuiPrefix = prefix.parse().map_err(|_| "invalid prefix")?;
    // Old files: `short # long`; current files: `short<TAB>long`.
    let (short, long) = match rest.split_once('#') {
        Some((short, long)) => (short, Some(long)),
        None => match rest.trim().split_once('\t') {
            Some((short, long)) => (short, Some(long)),
            None => (rest, None),
        },
    };
    let short = non_empty(short).ok_or("missing vendor name")?;
    let long = long.and_then(non_empty);
    Ok(Some(OuiRecord {
        prefix,
        registry: None,
        organization: long.unwrap_or_else(|| short.clone()),
        short_name: Some(short),
        address: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MacAddr, OuiDb, Registry};

    const CSV: &str = "\u{feff}Registry,Assignment,Organization Name,Organization Address\r\n\
        MA-L,001B63,Apple,1 Infinite Loop Cupertino CA US 95014 \r\n\
        MA-L,00005E,\"ICANN, IANA Department\",\"12025 Waterfront Drive, Suite 300 Los Angeles CA US 90094\"\r\n\
        MA-M,70B3D51,\"Example \"\"Quoted\"\" Ltd\",\r\n\
        MA-S,70B3D5123,Small Co,\r\n";

    const TXT: &str = "OUI/MA-L\t\t\t\t\t\t\tOrganization\n\
        company_id\t\t\t\t\t\tOrganization\n\
        \t\t\t\t\t\t\t\tAddress\n\
        \n\
        00-1B-63   (hex)\t\tApple, Inc.\n\
        001B63     (base 16)\t\tApple, Inc.\n\
        \t\t\t\t1 Infinite Loop\n\
        \t\t\t\tCupertino  CA  95014\n\
        \t\t\t\tUS\n\
        \n\
        70-B3-D5   (hex)\t\tSmall Co\n\
        123000-123FFF     (base 16)\t\tSmall Co\n\
        \t\t\t\tSomewhere\n\
        \n\
        C8-8E-D1   (hex)\t\tMedium Co\n\
        E00000-EFFFFF     (base 16)\t\tMedium Co\n\
        \n\
        08-00-27   (hex)\t\tPCS Systemtechnik GmbH\n\
        080027     (base 16)\t\tPCS Systemtechnik GmbH\n";

    const MANUF: &str = "# Wireshark manuf\n\
        00:00:0C\tCisco\tCisco Systems, Inc\n\
        00:1B:63\tApple\n\
        08:00:27\tPcsCompu               # PCS Computer Systems GmbH\n\
        70:B3:D5:12:30:00/36\tSmallCo\tSmall Co\n\
        01-80-C2-00-00-00/48\tSpanning-tree-(for-bridges)_00\n";

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    #[test]
    fn csv() {
        let records: Vec<_> = parse_ieee_csv(CSV).collect::<Result<_, _>>().unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].organization, "Apple");
        assert_eq!(
            records[0].address.as_deref(),
            Some("1 Infinite Loop Cupertino CA US 95014")
        );
        assert_eq!(records[1].organization, "ICANN, IANA Department");
        assert_eq!(records[2].organization, "Example \"Quoted\" Ltd");
        assert_eq!(records[2].prefix.bits(), 28);
        assert_eq!(records[2].registry, Some(Registry::MaM));
        assert_eq!(records[2].address, None);
        assert_eq!(records[3].prefix.to_string(), "70:B3:D5:12:30:00/36");
        assert_eq!(RegistryFormat::detect(CSV), RegistryFormat::IeeeCsv);
    }

    #[test]
    fn csv_errors_carry_line_numbers() {
        let text = "Registry,Assignment,Organization Name,Organization Address\nMA-L,XYZ,Bad,\nMA-L,\"001B63,Open\nMA-L,001B63,,\nMA-L,001B63\nMA-L,001B63,Ok,\n";
        let results: Vec<_> = parse_ieee_csv(text).collect();
        let lines: Vec<_> = results
            .iter()
            .filter_map(|r| match r {
                Err(Error::Parse { line, .. }) => Some(*line),
                _ => None,
            })
            .collect();
        assert_eq!(lines, [2, 3, 4, 5]);
        assert!(results.last().unwrap().is_ok());
    }

    #[test]
    fn txt() {
        let records: Vec<_> = parse_ieee_txt(TXT).collect::<Result<_, _>>().unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].prefix, OuiPrefix::oui([0x00, 0x1b, 0x63]));
        assert_eq!(records[0].organization, "Apple, Inc.");
        assert_eq!(
            records[0].address.as_deref(),
            Some("1 Infinite Loop, Cupertino  CA  95014, US")
        );
        assert_eq!(records[1].prefix.to_string(), "70:B3:D5:12:30:00/36");
        assert_eq!(records[2].prefix.to_string(), "C8:8E:D1:E0:00:00/28");
        assert_eq!(records[3].address, None);
        assert_eq!(RegistryFormat::detect(TXT), RegistryFormat::IeeeTxt);
    }

    #[test]
    fn txt_errors() {
        for bad in [
            "00-1B-63   (hex)\t\tX\n001B64     (base 16)\t\tX\n",
            "70-B3-D5   (hex)\t\tX\n123000-123FFE     (base 16)\t\tX\n",
            "70-B3-D5   (hex)\t\tX\n123400-123BFF     (base 16)\t\tX\n",
            "123000-123FFF     (base 16)\t\tX\n",
            "00-1B-63   (hex)\t\tX\n001B63     (base 16)\n",
        ] {
            assert!(
                matches!(parse_ieee_txt(bad).next(), Some(Err(Error::Parse { .. }))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn manuf() {
        let records: Vec<_> = parse_manuf(MANUF).collect::<Result<_, _>>().unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].organization, "Cisco Systems, Inc");
        assert_eq!(records[0].short_name.as_deref(), Some("Cisco"));
        assert_eq!(records[1].organization, "Apple");
        assert_eq!(records[2].organization, "PCS Computer Systems GmbH");
        assert_eq!(records[2].short_name.as_deref(), Some("PcsCompu"));
        assert_eq!(records[4].prefix.bits(), 48);
        assert_eq!(RegistryFormat::detect(MANUF), RegistryFormat::Manuf);
        assert!(parse_manuf("zz:zz:zz\tX\n").next().unwrap().is_err());
        assert!(parse_manuf("00:00:0C\n").next().unwrap().is_err());
    }

    #[test]
    fn load_and_lookup_known_prefixes() {
        let mut db = OuiDb::new();
        assert_eq!(db.load(CSV), Ok(4));
        assert_eq!(db.load(TXT), Ok(4));
        assert_eq!(db.load(MANUF), Ok(5));
        assert_eq!(
            db.vendor(&mac("00:00:0c:12:34:56")),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(
            db.vendor(&mac("08:00:27:aa:bb:cc")),
            Some("PCS Computer Systems GmbH")
        );
        assert_eq!(db.vendor(&mac("70:b3:d5:12:3f:ff")), Some("Small Co"));
        assert_eq!(
            db.vendor(&mac("70:b3:d5:1f:00:00")),
            Some("Example \"Quoted\" Ltd")
        );
        assert_eq!(db.vendor(&mac("c8:8e:d1:e1:23:45")), Some("Medium Co"));
        assert_eq!(db.vendor(&mac("c8:8e:d1:d1:23:45")), None);
        assert_eq!(
            db.vendor(&mac("01:80:c2:00:00:00")),
            Some("Spanning-tree-(for-bridges)_00")
        );
        assert_eq!(
            db.vendor(&mac("01:00:5e:7f:ff:fa")),
            Some("ICANN, IANA Department")
        );
    }
}
