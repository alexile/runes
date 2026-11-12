//! RDATA presentation format: zone-file text to [`RData`] and back.

use std::net::{Ipv4Addr, Ipv6Addr};

use rune_dns_wire::{
    Caa, Dnskey, Ds, Message, Mx, Name, RData, Record, RecordType, Rrsig, Soa, Srv, Tlsa,
};

use crate::Error;
use crate::lexer::{Token, unescape};
use crate::types::{parse_record_type, record_type_name};

/// `LOC` (RFC 1876).
const LOC: RecordType = RecordType(29);

/// Parses a TTL: decimal seconds, or BIND-style units (`1w2d3h4m5s`,
/// case-insensitive).
pub fn parse_ttl(text: &str) -> Option<u32> {
    if !text.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse().ok();
    }
    let mut total: u64 = 0;
    let mut number: Option<u64> = None;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            let value = number.unwrap_or(0) * 10 + u64::from(byte - b'0');
            if value > u64::from(u32::MAX) {
                return None;
            }
            number = Some(value);
            continue;
        }
        let unit = match byte.to_ascii_lowercase() {
            b'w' => 604_800,
            b'd' => 86_400,
            b'h' => 3_600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        total += number.take()? * unit;
        if total > u64::from(u32::MAX) {
            return None;
        }
    }
    if number.is_some() {
        return None;
    }
    u32::try_from(total).ok()
}

/// Whether a name in text form is absolute: it ends in an unescaped dot.
fn is_absolute(text: &str) -> bool {
    let Some(body) = text.strip_suffix('.') else {
        return false;
    };
    body.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 0
}

/// Resolves a name as written in a zone file: `@` is the origin, a name
/// without a trailing dot is relative to it.
pub fn name_from_text(text: &str, origin: Option<&Name>, line: usize) -> Result<Name, Error> {
    if text == "@" {
        return origin.cloned().ok_or(Error::NoOrigin { line });
    }
    let name = Name::from_ascii(text).map_err(|source| Error::Wire { line, source })?;
    if is_absolute(text) {
        return Ok(name);
    }
    let origin = origin.ok_or(Error::NoOrigin { line })?;
    Name::from_labels(name.labels().chain(origin.labels()))
        .map_err(|source| Error::Wire { line, source })
}

/// A name with its trailing dot, as RDATA in a zone file needs it.
pub fn absolute(name: &Name) -> String {
    if name.is_root() {
        ".".to_owned()
    } else {
        format!("{name}.")
    }
}

/// A cursor over the RDATA tokens of one record.
struct Fields<'a> {
    tokens: &'a [Token],
    pos: usize,
    line: usize,
    origin: Option<&'a Name>,
}

impl<'a> Fields<'a> {
    const fn syntax(&self, reason: &'static str) -> Error {
        Error::Syntax {
            line: self.line,
            reason,
        }
    }

    const fn is_done(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn next(&mut self) -> Result<&'a Token, Error> {
        let token = self
            .tokens
            .get(self.pos)
            .ok_or_else(|| self.syntax("missing RDATA field"))?;
        self.pos += 1;
        Ok(token)
    }

    fn word(&mut self) -> Result<&'a str, Error> {
        Ok(self.next()?.text.as_str())
    }

    fn peek_word(&self) -> Option<&'a str> {
        self.tokens.get(self.pos).map(|token| token.text.as_str())
    }

    fn number<T: core::str::FromStr>(&mut self, reason: &'static str) -> Result<T, Error> {
        let word = self.word()?;
        if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
            return Err(self.syntax(reason));
        }
        word.parse().map_err(|_| self.syntax(reason))
    }

    fn u8(&mut self) -> Result<u8, Error> {
        self.number("expected a number from 0 to 255")
    }

    fn u16(&mut self) -> Result<u16, Error> {
        self.number("expected a number from 0 to 65535")
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.number("expected a number from 0 to 4294967295")
    }

    fn ttl(&mut self) -> Result<u32, Error> {
        let word = self.word()?;
        parse_ttl(word).ok_or_else(|| self.syntax("invalid time value"))
    }

    fn name(&mut self) -> Result<Name, Error> {
        let word = self.word()?;
        name_from_text(word, self.origin, self.line)
    }

    fn rtype(&mut self) -> Result<RecordType, Error> {
        let word = self.word()?;
        parse_record_type(word).ok_or_else(|| Error::UnknownType {
            line: self.line,
            text: word.to_owned(),
        })
    }

    /// Any-length text: one token, escapes decoded.
    fn text(&mut self) -> Result<Vec<u8>, Error> {
        let word = self.word()?;
        unescape(word).ok_or_else(|| self.syntax("bad escape"))
    }

    /// A `<character-string>`: at most 255 octets.
    fn char_string(&mut self) -> Result<Vec<u8>, Error> {
        let bytes = self.text()?;
        if bytes.len() > 255 {
            return Err(self.syntax("character string longer than 255 octets"));
        }
        Ok(bytes)
    }

    /// The remaining tokens, concatenated (hex and base64 may be split by
    /// spaces).
    fn rest(&mut self) -> String {
        let rest = self.tokens.get(self.pos..).unwrap_or_default();
        self.pos = self.tokens.len();
        rest.iter().map(|token| token.text.as_str()).collect()
    }

    fn hex_rest(&mut self) -> Result<Vec<u8>, Error> {
        let text = self.rest();
        if text == "-" {
            return Ok(Vec::new());
        }
        if text.starts_with("0x") || text.starts_with("0X") {
            return Err(self.syntax("invalid hex"));
        }
        rune_hex::decode(&text).map_err(|_| self.syntax("invalid hex"))
    }

    fn base64_rest(&mut self) -> Result<Vec<u8>, Error> {
        let text = self.rest();
        if text.contains(['-', '_']) {
            return Err(self.syntax("invalid base64"));
        }
        rune_base64::decode(&text).map_err(|_| self.syntax("invalid base64"))
    }

    /// RRSIG times: `YYYYMMDDHHmmSS` or seconds since the epoch.
    fn time(&mut self) -> Result<u32, Error> {
        let word = self.word()?;
        let bad = || self.syntax("invalid signature time");
        if !word.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        if word.len() != 14 {
            return word.parse().map_err(|_| bad());
        }
        let field = |range: core::ops::Range<usize>| -> Result<i64, Error> {
            word.get(range)
                .and_then(|digits| digits.parse().ok())
                .ok_or_else(bad)
        };
        let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
        let (hour, minute, second) = (field(8..10)?, field(10..12)?, field(12..14)?);
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(bad());
        }
        let seconds =
            days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
        // RFC 4034 §3.1.5: the value is modulo 2^32.
        Ok(u32::try_from(seconds.rem_euclid(1 << 32)).unwrap_or_default())
    }

    const fn done(&self) -> Result<(), Error> {
        if self.is_done() {
            Ok(())
        } else {
            Err(self.syntax("too many RDATA fields"))
        }
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The types `rune-dns-wire` decodes into typed variants.
const fn is_typed(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::A
            | RecordType::AAAA
            | RecordType::NS
            | RecordType::CNAME
            | RecordType::PTR
            | RecordType::MX
            | RecordType::TXT
            | RecordType::SOA
            | RecordType::SRV
            | RecordType::CAA
            | RecordType::TLSA
            | RecordType::DS
            | RecordType::DNSKEY
            | RecordType::RRSIG
    )
}

/// Parses the RDATA tokens of a record of type `rtype`.
pub fn parse_rdata(
    rtype: RecordType,
    tokens: &[Token],
    line: usize,
    origin: Option<&Name>,
) -> Result<RData, Error> {
    let mut f = Fields {
        tokens,
        pos: 0,
        line,
        origin,
    };
    if tokens
        .first()
        .is_some_and(|token| !token.quoted && token.text == "\\#")
    {
        return generic(rtype, &mut f);
    }
    let data = match rtype {
        RecordType::A => RData::A(
            f.word()?
                .parse::<Ipv4Addr>()
                .map_err(|_| f.syntax("invalid IPv4 address"))?,
        ),
        RecordType::AAAA => RData::Aaaa(
            f.word()?
                .parse::<Ipv6Addr>()
                .map_err(|_| f.syntax("invalid IPv6 address"))?,
        ),
        RecordType::NS => RData::Ns(f.name()?),
        RecordType::CNAME => RData::Cname(f.name()?),
        RecordType::PTR => RData::Ptr(f.name()?),
        RecordType::MX => RData::Mx(Mx {
            preference: f.u16()?,
            exchange: f.name()?,
        }),
        RecordType::TXT => {
            let mut strings = Vec::new();
            while !f.is_done() {
                strings.push(f.char_string()?);
            }
            RData::Txt(strings)
        }
        RecordType::SOA => RData::Soa(Soa {
            mname: f.name()?,
            rname: f.name()?,
            serial: f.u32()?,
            refresh: f.ttl()?,
            retry: f.ttl()?,
            expire: f.ttl()?,
            minimum: f.ttl()?,
        }),
        RecordType::SRV => RData::Srv(Srv {
            priority: f.u16()?,
            weight: f.u16()?,
            port: f.u16()?,
            target: f.name()?,
        }),
        RecordType::CAA => {
            let flags = f.u8()?;
            let tag = f.word()?;
            if !(1..=15).contains(&tag.len()) || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(f.syntax("CAA tag is not 1 to 15 letters and digits"));
            }
            RData::Caa(Caa {
                flags,
                tag: tag.to_owned(),
                value: f.text()?,
            })
        }
        RecordType::TLSA => RData::Tlsa(Tlsa {
            usage: f.u8()?,
            selector: f.u8()?,
            matching_type: f.u8()?,
            data: f.hex_rest()?,
        }),
        RecordType::DS => RData::Ds(Ds {
            key_tag: f.u16()?,
            algorithm: f.u8()?,
            digest_type: f.u8()?,
            digest: f.hex_rest()?,
        }),
        RecordType::DNSKEY => RData::Dnskey(Dnskey {
            flags: f.u16()?,
            protocol: f.u8()?,
            algorithm: f.u8()?,
            public_key: f.base64_rest()?,
        }),
        RecordType::RRSIG => RData::Rrsig(Rrsig {
            type_covered: f.rtype()?,
            algorithm: f.u8()?,
            labels: f.u8()?,
            original_ttl: f.u32()?,
            expiration: f.time()?,
            inception: f.time()?,
            key_tag: f.u16()?,
            signer_name: f.name()?,
            signature: f.base64_rest()?,
        }),
        LOC => RData::Unknown {
            rtype,
            data: loc_parse(&mut f)?,
        },
        RecordType::OPT => return Err(f.syntax("OPT is not a zone record")),
        _ => {
            let schema = schema(rtype).ok_or(Error::UnsupportedType { line, rtype })?;
            RData::Unknown {
                rtype,
                data: schema_parse(schema, &mut f)?,
            }
        }
    };
    f.done()?;
    Ok(data)
}

/// The RFC 3597 `\# <length> <hex>` form.
fn generic(rtype: RecordType, f: &mut Fields<'_>) -> Result<RData, Error> {
    f.next()?; // `\#`
    let len: u16 = f.u16()?;
    let data = if f.is_done() {
        Vec::new()
    } else {
        f.hex_rest()?
    };
    if data.len() != usize::from(len) {
        return Err(f.syntax("\\# length does not match the data"));
    }
    if rtype == RecordType::OPT {
        return Err(f.syntax("OPT is not a zone record"));
    }
    if !is_typed(rtype) {
        return Ok(RData::Unknown { rtype, data });
    }
    // Let the wire decoder lay out a type it models: encode the bytes as
    // opaque RDATA, then decode the message back.
    let line = f.line;
    let wire = |source| Error::Wire { line, source };
    let message = Message::default().with_answer(Record::new(
        Name::root(),
        0,
        RData::Unknown { rtype, data },
    ));
    let bytes = message.encode().map_err(wire)?;
    Message::decode(&bytes)
        .map_err(wire)?
        .answers
        .into_iter()
        .next()
        .map(|record| record.data)
        .ok_or_else(|| f.syntax("generic RDATA did not decode"))
}

/// The presentation format of `data`, as written after the type in a zone
/// file. Names are absolute (with their trailing dot); RDATA of a type
/// without a presentation format here uses the RFC 3597 `\#` form.
///
/// ```
/// use rune_dns_wire::{Mx, RData, RecordType};
/// use rune_dns_zone::rdata_to_text;
///
/// let mx = RData::Mx(Mx { preference: 10, exchange: "mail.example".parse()? });
/// assert_eq!(rdata_to_text(&mx), "10 mail.example.");
///
/// let unknown = RData::Unknown { rtype: RecordType(65_280), data: vec![0xab] };
/// assert_eq!(rdata_to_text(&unknown), "\\# 1 AB");
/// # Ok::<(), rune_dns_wire::Error>(())
/// ```
#[must_use]
pub fn rdata_to_text(data: &RData) -> String {
    match data {
        RData::Ns(name) | RData::Cname(name) | RData::Ptr(name) => absolute(name),
        RData::Mx(mx) => format!("{} {}", mx.preference, absolute(&mx.exchange)),
        RData::Soa(soa) => format!(
            "{} {} {} {} {} {} {}",
            absolute(&soa.mname),
            absolute(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::Srv(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            absolute(&srv.target)
        ),
        RData::Rrsig(sig) => format!(
            "{} {} {} {} {} {} {} {} {}",
            record_type_name(sig.type_covered),
            sig.algorithm,
            sig.labels,
            sig.original_ttl,
            sig.expiration,
            sig.inception,
            sig.key_tag,
            absolute(&sig.signer_name),
            rune_base64::encode(&sig.signature)
        )
        .trim_end()
        .to_owned(),
        RData::Unknown { rtype, data } => {
            let text = if *rtype == LOC {
                loc_text(data)
            } else {
                schema(*rtype).and_then(|schema| schema_text(schema, data))
            };
            text.unwrap_or_else(|| generic_text(data))
        }
        other => other.to_string().trim_end().to_owned(),
    }
}

fn generic_text(data: &[u8]) -> String {
    if data.is_empty() {
        "\\# 0".to_owned()
    } else {
        format!("\\# {} {}", data.len(), rune_hex::encode_upper(data))
    }
}

/// Writes `bytes` as a quoted string with `\"`, `\\` and `\DDD` escapes.
fn quoted(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                out.push('\\');
                out.push(char::from(b'0' + byte / 100));
                out.push(char::from(b'0' + byte / 10 % 10));
                out.push(char::from(b'0' + byte % 10));
            }
        }
    }
    out.push('"');
    out
}

/// A field of a type described by a [`schema`].
#[derive(Debug, Clone, Copy)]
enum Field {
    U8,
    U16,
    U32,
    /// An uncompressed domain name.
    Name,
    /// One `<character-string>`.
    Str,
    /// Zero or more `<character-string>`s, to the end.
    Strs,
    /// Raw text to the end (URI target), written quoted.
    Text,
    /// Hex to the end.
    Hex,
    /// Base64 to the end.
    Base64,
    /// NSEC3 salt: a length octet, hex or `-` in text.
    Salt,
    /// NSEC3 next hashed owner: a length octet, base32hex in text.
    Hash,
    /// NSEC/NSEC3 type bitmap, to the end.
    Bitmap,
    /// CERT type: a 16-bit value with RFC 4398 mnemonics.
    CertType,
}

/// Layouts of the types kept as opaque RDATA that have a presentation
/// format here.
const fn schema(rtype: RecordType) -> Option<&'static [Field]> {
    use Field::{Base64, Bitmap, CertType, Hash, Hex, Name, Salt, Str, Strs, Text, U8, U16, U32};
    Some(match rtype.0 {
        13 => &[Str, Str],                        // HINFO
        14 | 17 => &[Name, Name],                 // MINFO, RP
        18 | 36 => &[U16, Name],                  // AFSDB, KX
        35 => &[U16, U16, Str, Str, Str, Name],   // NAPTR
        37 => &[CertType, U16, U8, Base64],       // CERT
        39 => &[Name],                            // DNAME
        44 => &[U8, U8, Hex],                     // SSHFP
        47 => &[Name, Bitmap],                    // NSEC
        50 => &[U8, U8, U16, Salt, Hash, Bitmap], // NSEC3
        51 => &[U8, U8, U16, Salt],               // NSEC3PARAM
        53 => &[U8, U8, U8, Hex],                 // SMIMEA
        59 => &[U16, U8, U8, Hex],                // CDS
        60 => &[U16, U8, U8, Base64],             // CDNSKEY
        61 => &[Base64],                          // OPENPGPKEY
        63 => &[U32, U8, U8, Hex],                // ZONEMD
        99 => &[Strs],                            // SPF
        256 => &[U16, U16, Text],                 // URI
        _ => return None,
    })
}

/// RFC 4398 §2.1 certificate type mnemonics.
const CERT_TYPES: &[(u16, &str)] = &[
    (1, "PKIX"),
    (2, "SPKI"),
    (3, "PGP"),
    (4, "IPKIX"),
    (5, "ISPKI"),
    (6, "IPGP"),
    (7, "ACPKIX"),
    (8, "IACPKIX"),
    (253, "URI"),
    (254, "OID"),
];

fn schema_parse(schema: &[Field], f: &mut Fields<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for field in schema {
        match field {
            Field::U8 => out.push(f.u8()?),
            Field::U16 => out.extend_from_slice(&f.u16()?.to_be_bytes()),
            Field::U32 => out.extend_from_slice(&f.u32()?.to_be_bytes()),
            Field::Name => out.extend_from_slice(f.name()?.as_wire()),
            Field::Str => push_string(&mut out, &f.char_string()?),
            Field::Strs => {
                while !f.is_done() {
                    push_string(&mut out, &f.char_string()?);
                }
            }
            Field::Text => out.extend_from_slice(&f.text()?),
            Field::Hex => out.extend_from_slice(&f.hex_rest()?),
            Field::Base64 => out.extend_from_slice(&f.base64_rest()?),
            Field::Salt => {
                let word = f.word()?;
                let salt = if word == "-" {
                    Vec::new()
                } else {
                    rune_hex::decode(word)
                        .ok()
                        .filter(|_| !word.starts_with("0x") && !word.starts_with("0X"))
                        .ok_or_else(|| f.syntax("invalid NSEC3 salt"))?
                };
                push_string_checked(&mut out, &salt, f, "NSEC3 salt longer than 255 octets")?;
            }
            Field::Hash => {
                let word = f.word()?;
                if word.is_empty() || word.contains('=') {
                    return Err(f.syntax("invalid NSEC3 hash"));
                }
                let hash =
                    rune_base32::decode_hex(word).map_err(|_| f.syntax("invalid NSEC3 hash"))?;
                if hash.is_empty()
                    || rune_base32::encode_hex(&hash).trim_end_matches('=').len() != word.len()
                {
                    return Err(f.syntax("invalid NSEC3 hash"));
                }
                push_string_checked(&mut out, &hash, f, "NSEC3 hash longer than 255 octets")?;
            }
            Field::Bitmap => {
                let mut types = Vec::new();
                while !f.is_done() {
                    types.push(f.rtype()?.0);
                }
                out.extend_from_slice(&bitmap(types));
            }
            Field::CertType => {
                let word = f.peek_word().unwrap_or_default();
                let code = CERT_TYPES
                    .iter()
                    .find(|(_, name)| name.eq_ignore_ascii_case(word))
                    .map(|&(code, _)| code);
                let code = match code {
                    Some(code) => {
                        f.next()?;
                        code
                    }
                    None => f.u16()?,
                };
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
    }
    Ok(out)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "callers check that the string is at most 255 octets"
)]
fn push_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn push_string_checked(
    out: &mut Vec<u8>,
    bytes: &[u8],
    f: &Fields<'_>,
    reason: &'static str,
) -> Result<(), Error> {
    if bytes.len() > 255 {
        return Err(f.syntax(reason));
    }
    push_string(out, bytes);
    Ok(())
}

/// Encodes a type bitmap (RFC 4034 §4.1.2).
fn bitmap(mut types: Vec<u16>) -> Vec<u8> {
    types.sort_unstable();
    types.dedup();
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(&first) = types.get(index) {
        let [window, _] = first.to_be_bytes();
        let mut bits = [0u8; 32];
        while let Some(&rtype) = types.get(index) {
            let [high, low] = rtype.to_be_bytes();
            if high != window {
                break;
            }
            if let Some(byte) = bits.get_mut(usize::from(low / 8)) {
                *byte |= 0x80 >> (low % 8);
            }
            index += 1;
        }
        let len = bits.iter().rposition(|&b| b != 0).map_or(0, |at| at + 1);
        out.push(window);
        out.push(u8::try_from(len).unwrap_or(32));
        out.extend_from_slice(bits.get(..len).unwrap_or_default());
    }
    out
}

/// A cursor over opaque RDATA, for the text writers.
struct Bytes<'a> {
    rest: &'a [u8],
}

impl<'a> Bytes<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(len)?;
        self.rest = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)?.try_into().ok().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)?.try_into().ok().map(u32::from_be_bytes)
    }

    fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.rest)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    /// An uncompressed name; compression pointers are not followed.
    fn name(&mut self) -> Option<Name> {
        let mut labels = Vec::new();
        loop {
            let len = self.u8()?;
            if len == 0 {
                break;
            }
            if len & 0xC0 != 0 {
                return None;
            }
            labels.push(self.take(usize::from(len))?);
        }
        Name::from_labels(labels).ok()
    }
}

fn schema_text(schema: &[Field], data: &[u8]) -> Option<String> {
    let mut bytes = Bytes { rest: data };
    let mut parts = Vec::new();
    for field in schema {
        let part = match field {
            Field::U8 => bytes.u8()?.to_string(),
            Field::U16 => bytes.u16()?.to_string(),
            Field::U32 => bytes.u32()?.to_string(),
            Field::Name => absolute(&bytes.name()?),
            Field::Str => quoted(bytes.string()?),
            Field::Strs => {
                let mut strings = Vec::new();
                while !bytes.rest.is_empty() {
                    strings.push(quoted(bytes.string()?));
                }
                strings.join(" ")
            }
            Field::Text => quoted(bytes.rest()),
            Field::Hex => {
                let rest = bytes.rest();
                if rest.is_empty() {
                    "-".to_owned()
                } else {
                    rune_hex::encode_upper(rest)
                }
            }
            Field::Base64 => rune_base64::encode(bytes.rest()),
            Field::Salt => {
                let salt = bytes.string()?;
                if salt.is_empty() {
                    "-".to_owned()
                } else {
                    rune_hex::encode_upper(salt)
                }
            }
            Field::Hash => {
                let hash = bytes.string()?;
                if hash.is_empty() {
                    return None;
                }
                rune_base32::encode_hex(hash)
                    .trim_end_matches('=')
                    .to_owned()
            }
            Field::Bitmap => bitmap_text(bytes.rest())?,
            Field::CertType => {
                let code = bytes.u16()?;
                CERT_TYPES
                    .iter()
                    .find(|&&(known, _)| known == code)
                    .map_or_else(|| code.to_string(), |&(_, name)| name.to_owned())
            }
        };
        parts.push(part);
    }
    if !bytes.rest.is_empty() {
        return None;
    }
    Some(parts.join(" ").trim_end().to_owned())
}

/// Decodes a type bitmap in canonical form (ascending windows, no trailing
/// zero octets), or `None`, so the text re-encodes to the same bytes.
fn bitmap_text(data: &[u8]) -> Option<String> {
    let mut bytes = Bytes { rest: data };
    let mut names = Vec::new();
    let mut last_window: Option<u8> = None;
    while !bytes.rest.is_empty() {
        let window = bytes.u8()?;
        let len = bytes.u8()?;
        if last_window.is_some_and(|last| window <= last) || !(1..=32).contains(&len) {
            return None;
        }
        last_window = Some(window);
        let bits = bytes.take(usize::from(len))?;
        if bits.last() == Some(&0) {
            return None;
        }
        for (index, &byte) in bits.iter().enumerate() {
            for bit in 0..8u8 {
                if byte & (0x80 >> bit) != 0 {
                    let low = u8::try_from(index).ok()? * 8 + bit;
                    names.push(record_type_name(RecordType(u16::from_be_bytes([
                        window, low,
                    ]))));
                }
            }
        }
    }
    Some(names.join(" "))
}

/// `2^31`: the equator and the prime meridian in `LOC` coordinates.
const LOC_ZERO: i64 = 1 << 31;
/// `LOC` altitudes are offset by 100 000 m, in centimetres.
const LOC_ALTITUDE_BASE: i64 = 10_000_000;

/// Parses `LOC` text (RFC 1876 §3) into its 16 octets.
fn loc_parse(f: &mut Fields<'_>) -> Result<Vec<u8>, Error> {
    let latitude = loc_coordinate(f, ("N", "S"), 90)?;
    let longitude = loc_coordinate(f, ("E", "W"), 180)?;
    let altitude = metres(f.word()?, true).ok_or_else(|| f.syntax("invalid LOC altitude"))?;
    let altitude = u32::try_from(altitude + LOC_ALTITUDE_BASE)
        .map_err(|_| f.syntax("LOC altitude out of range"))?;
    let mut precision = [0x12, 0x16, 0x13]; // 1 m, 10 000 m, 10 m
    for slot in &mut precision {
        if f.is_done() {
            break;
        }
        let centimetres = metres(f.word()?, false)
            .and_then(|cm| u64::try_from(cm).ok())
            .ok_or_else(|| f.syntax("invalid LOC size or precision"))?;
        *slot = loc_precision(centimetres).ok_or_else(|| f.syntax("LOC size out of range"))?;
    }
    let mut out = vec![0, precision[0], precision[1], precision[2]];
    out.extend_from_slice(&latitude.to_be_bytes());
    out.extend_from_slice(&longitude.to_be_bytes());
    out.extend_from_slice(&altitude.to_be_bytes());
    Ok(out)
}

/// `d [m [s.sss]] H` as thousandths of an arc second around `2^31`.
fn loc_coordinate(
    f: &mut Fields<'_>,
    (positive, negative): (&str, &str),
    max_degrees: i64,
) -> Result<u32, Error> {
    let bad = |f: &Fields<'_>| f.syntax("invalid LOC coordinate");
    let is_hemisphere =
        |word: &str| word.eq_ignore_ascii_case(positive) || word.eq_ignore_ascii_case(negative);
    let degrees: i64 = f.number("invalid LOC coordinate")?;
    if degrees > max_degrees {
        return Err(bad(f));
    }
    let mut minutes = 0;
    let mut millis = 0;
    let mut word = f.word()?;
    if !is_hemisphere(word) {
        minutes = word
            .parse::<i64>()
            .ok()
            .filter(|m| (0..60).contains(m) && word.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| bad(f))?;
        word = f.word()?;
        if !is_hemisphere(word) {
            millis = decimal(word, 3)
                .filter(|&(negative, value)| !negative && value < 60_000)
                .map(|(_, value)| value)
                .ok_or_else(|| bad(f))?;
            word = f.word()?;
        }
    }
    if !is_hemisphere(word) {
        return Err(bad(f));
    }
    let total = degrees * 3_600_000 + minutes * 60_000 + millis;
    if total > max_degrees * 3_600_000 {
        return Err(bad(f));
    }
    let signed = if word.eq_ignore_ascii_case(negative) {
        LOC_ZERO - total
    } else {
        LOC_ZERO + total
    };
    u32::try_from(signed).map_err(|_| bad(f))
}

/// `12.34m` (the `m` optional) in centimetres.
fn metres(word: &str, signed: bool) -> Option<i64> {
    let word = word
        .strip_suffix('m')
        .or_else(|| word.strip_suffix('M'))
        .unwrap_or(word);
    let (negative, value) = decimal(word, 2)?;
    if negative && !signed {
        return None;
    }
    Some(if negative { -value } else { value })
}

/// A decimal with at most `places` fractional digits, scaled by
/// `10^places`.
fn decimal(word: &str, places: u32) -> Option<(bool, i64)> {
    let (negative, word) = word
        .strip_prefix('-')
        .map_or((false, word), |rest| (true, rest));
    let (whole, fraction) = word.split_once('.').unwrap_or((word, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || whole.len() > 12 || !digits(whole) || !digits(fraction) {
        return None;
    }
    let places_len = usize::try_from(places).ok()?;
    if fraction.len() > places_len || (word.contains('.') && fraction.is_empty()) {
        return None;
    }
    let mut value: i64 = whole.parse().ok()?;
    for index in 0..places_len {
        let digit = fraction
            .as_bytes()
            .get(index)
            .map_or(0, |&b| i64::from(b - b'0'));
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some((negative, value))
}

/// Encodes centimetres as `LOC` mantissa and exponent, or `None` if they do
/// not fit or would be rounded.
fn loc_precision(mut centimetres: u64) -> Option<u8> {
    let mut exponent = 0u8;
    while centimetres >= 10 {
        if !centimetres.is_multiple_of(10) {
            return None;
        }
        centimetres /= 10;
        exponent += 1;
    }
    if exponent > 9 {
        return None;
    }
    u8::try_from(centimetres)
        .ok()
        .map(|mantissa| mantissa << 4 | exponent)
}

fn loc_precision_text(byte: u8) -> Option<String> {
    let (mantissa, exponent) = (byte >> 4, byte & 0xF);
    if mantissa > 9 || exponent > 9 || (mantissa == 0 && exponent != 0) {
        return None;
    }
    Some(centimetres_text(
        i64::from(mantissa) * 10_i64.pow(u32::from(exponent)),
    ))
}

fn centimetres_text(centimetres: i64) -> String {
    let sign = if centimetres < 0 { "-" } else { "" };
    let abs = centimetres.unsigned_abs();
    if abs.is_multiple_of(100) {
        format!("{sign}{}m", abs / 100)
    } else {
        format!("{sign}{}.{:02}m", abs / 100, abs % 100)
    }
}

/// `LOC` RDATA as text, or `None` for a version or value this crate would
/// not parse back to the same octets.
fn loc_text(data: &[u8]) -> Option<String> {
    let mut bytes = Bytes { rest: data };
    let version = bytes.u8()?;
    let precision = [bytes.u8()?, bytes.u8()?, bytes.u8()?];
    let latitude = bytes.u32()?;
    let longitude = bytes.u32()?;
    let altitude = bytes.u32()?;
    if version != 0 || !bytes.rest.is_empty() {
        return None;
    }
    let coordinate = |value: u32, (positive, negative): (&str, &str), max: i64| {
        let offset = i64::from(value) - LOC_ZERO;
        let total = offset.abs();
        if total > max * 3_600_000 {
            return None;
        }
        let hemisphere = if offset < 0 { negative } else { positive };
        Some(format!(
            "{} {} {}.{:03} {hemisphere}",
            total / 3_600_000,
            total % 3_600_000 / 60_000,
            total % 60_000 / 1000,
            total % 1000
        ))
    };
    // Precision values must survive re-encoding.
    let sizes = precision
        .iter()
        .map(|&byte| {
            let text = loc_precision_text(byte)?;
            let cm = metres(&text, false).and_then(|cm| u64::try_from(cm).ok())?;
            (loc_precision(cm)? == byte).then_some(text)
        })
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{} {} {} {}",
        coordinate(latitude, ("N", "S"), 90)?,
        coordinate(longitude, ("E", "W"), 180)?,
        centimetres_text(i64::from(altitude) - LOC_ALTITUDE_BASE),
        sizes.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(text: &str) -> Vec<Token> {
        crate::lexer::entries(text)
            .unwrap()
            .into_iter()
            .next()
            .map(|entry| entry.tokens)
            .unwrap_or_default()
    }

    fn parse(rtype: RecordType, text: &str) -> Result<RData, Error> {
        let origin = Name::from_ascii("example.com").unwrap();
        parse_rdata(rtype, &tokens(text), 1, Some(&origin))
    }

    #[test]
    fn ttl_units() {
        assert_eq!(parse_ttl("3600"), Some(3600));
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("1W2d"), Some(777_600));
        assert_eq!(parse_ttl("4294967295"), Some(u32::MAX));
        for bad in ["", "h", "1h30", "1x", "4294967296", "99999999999w", "-1"] {
            assert_eq!(parse_ttl(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn names() {
        let origin = Name::from_ascii("example.com").unwrap();
        let resolve = |text| name_from_text(text, Some(&origin), 1).unwrap().to_string();
        assert_eq!(resolve("@"), "example.com");
        assert_eq!(resolve("www"), "www.example.com");
        assert_eq!(resolve("www.other."), "www.other");
        assert_eq!(resolve("a\\."), "a\\..example.com");
        assert_eq!(resolve("a\\\\."), "a\\\\");
        assert_eq!(resolve("."), ".");
        assert_eq!(
            name_from_text("www", None, 7),
            Err(Error::NoOrigin { line: 7 })
        );
    }

    #[test]
    fn rrsig_times() {
        let data = parse(
            RecordType::RRSIG,
            "A 13 2 300 20260101000000 19700101000001 1234 example.com. AAAA",
        )
        .unwrap();
        let RData::Rrsig(sig) = data else {
            unreachable!()
        };
        assert_eq!(sig.expiration, 1_767_225_600);
        assert_eq!(sig.inception, 1);
        assert_eq!(sig.signature, [0, 0, 0]);
        // Past 2106 the value wraps modulo 2^32.
        let data = parse(
            RecordType::RRSIG,
            "A 13 2 300 21060207062816 1 1 example.com. AAAA",
        )
        .unwrap();
        let RData::Rrsig(sig) = data else {
            unreachable!()
        };
        assert_eq!(sig.expiration, 0);
    }

    #[test]
    fn generic_form() {
        assert_eq!(
            parse(RecordType::A, "\\# 4 C0000201").unwrap(),
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            parse(RecordType(65_280), "\\# 3 0a 0b0c").unwrap(),
            RData::Unknown {
                rtype: RecordType(65_280),
                data: vec![10, 11, 12],
            }
        );
        assert_eq!(
            parse(RecordType(65_280), "\\# 0").unwrap(),
            RData::Unknown {
                rtype: RecordType(65_280),
                data: vec![],
            }
        );
        assert!(parse(RecordType(65_280), "\\# 2 0a").is_err());
        assert!(parse(RecordType::A, "\\# 3 0a0b0c").is_err());
        assert!(matches!(
            parse(RecordType(65_280), "abc"),
            Err(Error::UnsupportedType { .. })
        ));
    }

    #[test]
    fn schema_types_round_trip() {
        let cases = [
            (13, "\"Casio fx-700G\" \"Windows XP\""),
            (17, "robin.example.com. robinwood.example.com."),
            (18, "1 asfdbbox.example.com."),
            (
                35,
                "2 3 \"P\" \"E2U+sip\" \"!^.*$!sip:customer-service@example.com!\" .",
            ),
            (37, "PKIX 0 0 AAECAw=="),
            (37, "300 1 5 AAEC"),
            (39, "target.example.net."),
            (44, "1 2 0123456789ABCDEF"),
            (
                47,
                "host.example.com. A NS SOA MX RRSIG NSEC DNSKEY TYPE1234",
            ),
            (
                50,
                "1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG",
            ),
            (50, "1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR"),
            (51, "1 0 10 -"),
            (59, "2371 13 2 1F987CC6583E92DF0890718C42"),
            (61, "AQID"),
            (63, "2018031500 1 1 FEBE3D4CE2EC2FFA4BA9"),
            (99, "\"v=spf1 -all\" \"x\""),
            (256, "10 1 \"ftp://ftp1.example.com/public\""),
            (29, "53 20 56.558 N 1 38 33.526 W 0m 1m 10000m 10m"),
            (29, "42 21 54.000 N 71 6 18.000 W -24m 30m 10000m 10m"),
            (29, "0 0 0.000 N 0 0 0.000 E 0.10m 0m 0m 0m"),
        ];
        for (code, text) in cases {
            let rtype = RecordType(code);
            let data = parse(rtype, text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert!(matches!(data, RData::Unknown { .. }), "{text}");
            assert_eq!(rdata_to_text(&data), text, "{code}");
        }
    }

    #[test]
    fn loc_shorthand() {
        let short = parse(LOC, "52 N 4 E 0").unwrap();
        let text = rdata_to_text(&short);
        assert_eq!(text, "52 0 0.000 N 4 0 0.000 E 0m 1m 10000m 10m");
        assert_eq!(parse(LOC, &text).unwrap(), short);
        for bad in [
            "91 N 0 E 0",
            "0 60 N 0 E 0",
            "0 0 60 N 0 E 0",
            "0 N 0 E 0 15m",
            "0 X 0 E 0",
            // Regression: degrees overflowed
            // i64 before the range check.
            "6666666666466667 N 4 60 E 0",
        ] {
            assert!(parse(LOC, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn non_canonical_opaque_data_falls_back_to_generic() {
        // A compression pointer in an RP name, and a bitmap with a trailing
        // zero octet: neither has a text form that re-encodes the same.
        let rp = RData::Unknown {
            rtype: RecordType(17),
            data: vec![0xC0, 0x0C, 0],
        };
        assert_eq!(rdata_to_text(&rp), "\\# 3 C00C00");
        let nsec = RData::Unknown {
            rtype: RecordType::NSEC,
            data: vec![0, 0, 2, 0x40, 0],
        };
        assert_eq!(rdata_to_text(&nsec), "\\# 5 0000024000");
    }

    #[test]
    fn typed_rdata() {
        let cases = [
            (RecordType::MX, "10 mail", "10 mail.example.com."),
            (
                RecordType::SOA,
                "ns hostmaster 1 1h 15m 1w 300",
                "ns.example.com. hostmaster.example.com. 1 3600 900 604800 300",
            ),
            (RecordType::SRV, "0 5 5060 sip", "0 5 5060 sip.example.com."),
            (
                RecordType::CAA,
                "0 issue \"ca.example\"",
                "0 issue \"ca.example\"",
            ),
            (RecordType::CAA, "128 tbs Unknown", "128 tbs \"Unknown\""),
            (RecordType::TLSA, "3 1 1 ab cd", "3 1 1 ABCD"),
            (RecordType::DS, "1 8 2 -", "1 8 2 -"),
            (RecordType::DNSKEY, "256 3 8 AQID BA==", "256 3 8 AQIDBA=="),
            (RecordType::TXT, "a \"b c\" \\065", "\"a\" \"b c\" \"A\""),
            (RecordType::TXT, "", ""),
        ];
        for (rtype, input, output) in cases {
            let data = parse(rtype, input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(rdata_to_text(&data), output);
        }
        for (rtype, bad) in [
            (RecordType::A, "1.2.3"),
            (RecordType::A, "1.2.3.4 5"),
            (RecordType::MX, "x mail"),
            (RecordType::MX, "+1 mail"),
            (RecordType::CAA, "0 is-sue x"),
            (RecordType::TXT, &format!("\"{}\"", "x".repeat(256))),
            (RecordType::DNSKEY, "256 3 8 ab-_"),
            (RecordType::TLSA, "3 1 1 0xabcd"),
            (RecordType::OPT, "\\# 0"),
        ] {
            assert!(parse(rtype, bad).is_err(), "{rtype} {bad}");
        }
    }
}
