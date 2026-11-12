//! Numeric DNS parameters: record types, classes, opcodes and response
//! codes, as open newtypes so unassigned values round-trip.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// Declares a numeric newtype with named constants and a mnemonic table.
macro_rules! code {
    (
        $(#[$meta:meta])*
        $name:ident($int:ty), unknown = $prefix:literal;
        $( $(#[$cmeta:meta])* $const:ident = $value:literal => $text:literal, )*
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub $int);

        impl $name {
            $( $(#[$cmeta])* pub const $const: Self = Self($value); )*

            /// The registered mnemonic, or `None` for a value this crate
            /// does not name.
            #[must_use]
            pub const fn mnemonic(self) -> Option<&'static str> {
                match self.0 {
                    $( $value => Some($text), )*
                    _ => None,
                }
            }
        }

        impl From<$int> for $name {
            fn from(value: $int) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $int {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.mnemonic() {
                    Some(text) => f.write_str(text),
                    None => write!(f, concat!($prefix, "{}"), self.0),
                }
            }
        }

        impl FromStr for $name {
            type Err = Error;

            /// Parses a mnemonic (case-insensitive) or the generic
            #[doc = concat!("`", $prefix, "<number>`")]
            /// form.
            fn from_str(text: &str) -> Result<Self, Error> {
                $(
                    if text.eq_ignore_ascii_case($text) {
                        return Ok(Self::$const);
                    }
                )*
                let prefix_len = $prefix.len();
                text.get(..prefix_len)
                    .filter(|prefix| prefix.eq_ignore_ascii_case($prefix))
                    .and_then(|_| text.get(prefix_len..))
                    .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|digits| digits.parse::<$int>().ok())
                    .map(Self)
                    .ok_or(Error::UnknownMnemonic { kind: stringify!($name) })
            }
        }
    };
}

code! {
    /// A resource record `TYPE` or question `QTYPE`
    /// ([IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)).
    RecordType(u16), unknown = "TYPE";
    /// IPv4 address (RFC 1035).
    A = 1 => "A",
    /// Authoritative name server (RFC 1035).
    NS = 2 => "NS",
    /// Canonical name (RFC 1035).
    CNAME = 5 => "CNAME",
    /// Start of authority (RFC 1035).
    SOA = 6 => "SOA",
    /// Domain name pointer (RFC 1035).
    PTR = 12 => "PTR",
    /// Host information (RFC 8482).
    HINFO = 13 => "HINFO",
    /// Mail exchange (RFC 1035).
    MX = 15 => "MX",
    /// Text strings (RFC 1035).
    TXT = 16 => "TXT",
    /// IPv6 address (RFC 3596).
    AAAA = 28 => "AAAA",
    /// Service locator (RFC 2782).
    SRV = 33 => "SRV",
    /// Naming authority pointer (RFC 3403).
    NAPTR = 35 => "NAPTR",
    /// EDNS(0) pseudo-record (RFC 6891).
    OPT = 41 => "OPT",
    /// Delegation signer (RFC 4034).
    DS = 43 => "DS",
    /// SSH key fingerprint (RFC 4255).
    SSHFP = 44 => "SSHFP",
    /// DNSSEC signature (RFC 4034).
    RRSIG = 46 => "RRSIG",
    /// Next secure (RFC 4034).
    NSEC = 47 => "NSEC",
    /// DNSSEC public key (RFC 4034).
    DNSKEY = 48 => "DNSKEY",
    /// Hashed next secure (RFC 5155).
    NSEC3 = 50 => "NSEC3",
    /// NSEC3 parameters (RFC 5155).
    NSEC3PARAM = 51 => "NSEC3PARAM",
    /// TLS certificate association (RFC 6698).
    TLSA = 52 => "TLSA",
    /// Service binding (RFC 9460).
    SVCB = 64 => "SVCB",
    /// HTTPS service binding (RFC 9460).
    HTTPS = 65 => "HTTPS",
    /// Incremental zone transfer (RFC 1995).
    IXFR = 251 => "IXFR",
    /// Zone transfer (RFC 1035).
    AXFR = 252 => "AXFR",
    /// Any type (RFC 1035, RFC 8482).
    ANY = 255 => "ANY",
    /// Certification authority authorization (RFC 8659).
    CAA = 257 => "CAA",
}

code! {
    /// A record `CLASS` or question `QCLASS` (RFC 1035 §3.2.4).
    Class(u16), unknown = "CLASS";
    /// The Internet.
    IN = 1 => "IN",
    /// Chaos.
    CH = 3 => "CH",
    /// Hesiod.
    HS = 4 => "HS",
    /// No class (RFC 2136).
    NONE = 254 => "NONE",
    /// Any class.
    ANY = 255 => "ANY",
}

code! {
    /// A header `OPCODE` (RFC 1035 §4.1.1). Only values up to 15 fit the
    /// wire field.
    Opcode(u8), unknown = "OPCODE";
    /// Standard query.
    QUERY = 0 => "QUERY",
    /// Inverse query (obsolete).
    IQUERY = 1 => "IQUERY",
    /// Server status.
    STATUS = 2 => "STATUS",
    /// Zone change notification (RFC 1996).
    NOTIFY = 4 => "NOTIFY",
    /// Dynamic update (RFC 2136).
    UPDATE = 5 => "UPDATE",
    /// DNS stateful operations (RFC 8490).
    DSO = 6 => "DSO",
}

code! {
    /// A response code. Values up to 15 fit the header; with EDNS(0) the
    /// `OPT` record carries 8 more bits, for 12 in all (RFC 6891 §6.1.3).
    Rcode(u16), unknown = "RCODE";
    /// No error.
    NOERROR = 0 => "NOERROR",
    /// The server could not interpret the query.
    FORMERR = 1 => "FORMERR",
    /// The server failed.
    SERVFAIL = 2 => "SERVFAIL",
    /// The name does not exist.
    NXDOMAIN = 3 => "NXDOMAIN",
    /// Not implemented.
    NOTIMP = 4 => "NOTIMP",
    /// Refused by policy.
    REFUSED = 5 => "REFUSED",
    /// A name exists that should not (RFC 2136).
    YXDOMAIN = 6 => "YXDOMAIN",
    /// An `RRset` exists that should not (RFC 2136).
    YXRRSET = 7 => "YXRRSET",
    /// An `RRset` that should exist does not (RFC 2136).
    NXRRSET = 8 => "NXRRSET",
    /// Not authoritative (RFC 2136).
    NOTAUTH = 9 => "NOTAUTH",
    /// Name not in zone (RFC 2136).
    NOTZONE = 10 => "NOTZONE",
    /// Unsupported EDNS version (RFC 6891).
    BADVERS = 16 => "BADVERS",
    /// Bad or missing server cookie (RFC 7873).
    BADCOOKIE = 23 => "BADCOOKIE",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse() {
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordType(65_280).to_string(), "TYPE65280");
        assert_eq!("aaaa".parse::<RecordType>().unwrap(), RecordType::AAAA);
        assert_eq!(
            "TYPE65280".parse::<RecordType>().unwrap(),
            RecordType(65_280)
        );
        assert_eq!("type1".parse::<RecordType>().unwrap(), RecordType::A);
        assert!("TYPE".parse::<RecordType>().is_err());
        assert!("TYPE+1".parse::<RecordType>().is_err());
        assert!("TYPE70000".parse::<RecordType>().is_err());
        assert!("bogus".parse::<RecordType>().is_err());
        assert_eq!(Class::IN.to_string(), "IN");
        assert_eq!(Class(9).to_string(), "CLASS9");
        assert_eq!(Rcode::NXDOMAIN.to_string(), "NXDOMAIN");
        assert_eq!(Opcode(15).to_string(), "OPCODE15");
        assert_eq!(u16::from(RecordType::CAA), 257);
    }
}
