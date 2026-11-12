//! UTS #46 processing (`ToASCII` and `ToUnicode`) with an optional IDNA2008
//! restriction.

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

use crate::{Error, data};

/// Which ASCII code points [`to_ascii`] and [`to_unicode`] reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AsciiRules {
    /// UTS #46 `UseSTD3ASCIIRules=true`: only letters, digits and hyphens
    /// (LDH). This rejects `_`, so names such as `_dmarc.example.com` fail.
    #[default]
    Std3,
    /// The WHATWG URL Standard's forbidden domain code points: rejects
    /// controls, space and `%#/:<>?@[\]^|`, but allows `_` and the rest.
    Url,
    /// UTS #46 `UseSTD3ASCIIRules=false`: no ASCII is rejected.
    None,
}

impl AsciiRules {
    const fn deny_list(self) -> AsciiDenyList {
        match self {
            Self::Std3 => AsciiDenyList::STD3,
            Self::Url => AsciiDenyList::URL,
            Self::None => AsciiDenyList::EMPTY,
        }
    }
}

/// Settings for [`to_ascii`] and [`to_unicode`].
///
/// Processing is always nontransitional (UTS #46 revision 31 and later):
/// `ß`, `ς`, ZWJ and ZWNJ are kept, not mapped away. `CheckBidi` and
/// `CheckJoiners` are always on.
///
/// The default is the lookup profile: STD3 rules, no hyphen check, DNS
/// lengths verified. [`Options::registration`] is the stricter profile for
/// names being registered or issued.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Which ASCII code points are rejected.
    pub ascii_rules: AsciiRules,
    /// UTS #46 `CheckHyphens`: reject labels that start or end with `-`,
    /// or have `--` in the third and fourth positions (other than `xn--`).
    pub check_hyphens: bool,
    /// UTS #46 `VerifyDnsLength` for [`to_ascii`]: labels of 1 to 63
    /// octets, at most 253 octets in total. A trailing root dot is allowed.
    pub verify_dns_length: bool,
    /// Reject code points that UTS #46 accepts but IDNA2008 (RFC 5892)
    /// does not: symbols and punctuation (`NV8`) and the few `XV8` code
    /// points.
    pub idna2008: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self::lookup()
    }
}

impl Options {
    /// The lookup profile, also [`Options::default`]: STD3 rules, no hyphen
    /// check, DNS lengths verified, UTS #46 repertoire.
    #[must_use]
    pub const fn lookup() -> Self {
        Self {
            ascii_rules: AsciiRules::Std3,
            check_hyphens: false,
            verify_dns_length: true,
            idna2008: false,
        }
    }

    /// The registration profile: [`Options::lookup`] plus `CheckHyphens`
    /// and the IDNA2008 repertoire.
    #[must_use]
    pub const fn registration() -> Self {
        Self {
            check_hyphens: true,
            idna2008: true,
            ..Self::lookup()
        }
    }

    /// Sets [`Options::ascii_rules`].
    #[must_use]
    pub const fn with_ascii_rules(mut self, ascii_rules: AsciiRules) -> Self {
        self.ascii_rules = ascii_rules;
        self
    }

    /// Sets [`Options::check_hyphens`].
    #[must_use]
    pub const fn with_check_hyphens(mut self, check_hyphens: bool) -> Self {
        self.check_hyphens = check_hyphens;
        self
    }

    /// Sets [`Options::verify_dns_length`].
    #[must_use]
    pub const fn with_verify_dns_length(mut self, verify_dns_length: bool) -> Self {
        self.verify_dns_length = verify_dns_length;
        self
    }

    /// Sets [`Options::idna2008`].
    #[must_use]
    pub const fn with_idna2008(mut self, idna2008: bool) -> Self {
        self.idna2008 = idna2008;
        self
    }

    const fn hyphens(&self) -> Hyphens {
        if self.check_hyphens {
            Hyphens::Check
        } else {
            Hyphens::Allow
        }
    }
}

/// Whether `c` is valid under UTS #46 but not under IDNA2008.
fn is_idna2008_excluded(c: char) -> bool {
    crate::in_ranges(data::IDNA2008_EXCLUDED, c)
}

fn check_idna2008(unicode: &str) -> Result<(), Error> {
    unicode
        .chars()
        .find(|&c| c != '.' && is_idna2008_excluded(c))
        .map_or(Ok(()), |c| Err(Error::NotIdna2008(c)))
}

fn verify_dns_length(ascii: &str) -> Result<(), Error> {
    let body = ascii.strip_suffix('.').unwrap_or(ascii);
    for (index, label) in body.split('.').enumerate() {
        if label.is_empty() {
            return Err(Error::EmptyLabel { index });
        }
        if label.len() > 63 {
            return Err(Error::LabelTooLong {
                index,
                len: label.len(),
            });
        }
    }
    if body.len() > 253 {
        return Err(Error::DomainTooLong { len: body.len() });
    }
    Ok(())
}

/// Converts a domain name to its ASCII form: UTS #46
/// [ToASCII](https://www.unicode.org/reports/tr46/#ToASCII).
///
/// The input is mapped (case folded, compatibility characters replaced,
/// ideographic full stops turned into `.`), normalized to NFC, validated
/// label by label, and every non-ASCII label is Punycode-encoded with the
/// `xn--` prefix. Existing `xn--` labels are decoded and validated too.
///
/// ```
/// use rune_idna::{Options, to_ascii};
///
/// assert_eq!(to_ascii("Bücher.Example", &Options::default())?, "xn--bcher-kva.example");
/// assert_eq!(to_ascii("例え。テスト", &Options::default())?, "xn--r8jz45g.xn--zckzah");
/// assert!(to_ascii("a_b.example", &Options::default()).is_err());
/// # Ok::<(), rune_idna::Error>(())
/// ```
///
/// # Errors
///
/// - [`Error::Uts46`] if UTS #46 processing fails.
/// - [`Error::NotIdna2008`] if [`Options::idna2008`] is set and the name
///   uses a code point outside IDNA2008.
/// - [`Error::EmptyLabel`], [`Error::LabelTooLong`] or
///   [`Error::DomainTooLong`] if [`Options::verify_dns_length`] is set and
///   the ASCII form breaks the DNS limits.
pub fn to_ascii(domain: &str, options: &Options) -> Result<String, Error> {
    let uts46 = Uts46::new();
    let ascii = uts46
        .to_ascii(
            domain.as_bytes(),
            options.ascii_rules.deny_list(),
            options.hyphens(),
            DnsLength::Ignore,
        )
        .map_err(|_| Error::Uts46)?;
    if options.idna2008 && ascii.split('.').any(|l| l.starts_with("xn--")) {
        let (unicode, result) = uts46.to_unicode(
            ascii.as_bytes(),
            options.ascii_rules.deny_list(),
            options.hyphens(),
        );
        result.map_err(|_| Error::Uts46)?;
        check_idna2008(&unicode)?;
    } else if options.idna2008 {
        check_idna2008(&ascii)?;
    }
    if options.verify_dns_length {
        verify_dns_length(&ascii)?;
    }
    Ok(ascii.into_owned())
}

/// Converts a domain name to its Unicode form: UTS #46
/// [ToUnicode](https://www.unicode.org/reports/tr46/#ToUnicode).
///
/// The input is mapped and normalized like [`to_ascii`], and `xn--` labels
/// are decoded. DNS lengths are not checked
/// ([`Options::verify_dns_length`] applies to [`to_ascii`] only).
///
/// ```
/// use rune_idna::{Options, to_unicode};
///
/// assert_eq!(to_unicode("xn--bcher-kva.example", &Options::default())?, "bücher.example");
/// assert_eq!(to_unicode("BÜCHER.example", &Options::default())?, "bücher.example");
/// # Ok::<(), rune_idna::Error>(())
/// ```
///
/// # Errors
///
/// - [`Error::Uts46`] if UTS #46 processing fails, for example on an `xn--`
///   label that is not valid Punycode or decodes to a disallowed label.
/// - [`Error::NotIdna2008`] if [`Options::idna2008`] is set and the name
///   uses a code point outside IDNA2008.
pub fn to_unicode(domain: &str, options: &Options) -> Result<String, Error> {
    let (unicode, result) = Uts46::new().to_unicode(
        domain.as_bytes(),
        options.ascii_rules.deny_list(),
        options.hyphens(),
    );
    result.map_err(|_| Error::Uts46)?;
    if options.idna2008 {
        check_idna2008(&unicode)?;
    }
    Ok(unicode.into_owned())
}

/// Whether two domain names name the same DNS node.
///
/// Both names go through [`to_ascii`] with `options` and are compared
/// ignoring a trailing root dot, so `BÜCHER.example.`,
/// `bücher.example` and `xn--bcher-kva.example` are all the same. A name
/// that fails processing is not equal to anything.
///
/// ```
/// use rune_idna::{Options, same_domain};
///
/// let options = Options::default();
/// assert!(same_domain("BÜCHER.example.", "xn--bcher-kva.example", &options));
/// assert!(!same_domain("bucher.example", "bücher.example", &options));
/// ```
#[must_use]
pub fn same_domain(a: &str, b: &str, options: &Options) -> bool {
    match (to_ascii(a, options), to_ascii(b, options)) {
        (Ok(a), Ok(b)) => a.strip_suffix('.').unwrap_or(&a) == b.strip_suffix('.').unwrap_or(&b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii(domain: &str) -> Result<String, Error> {
        to_ascii(domain, &Options::default())
    }

    #[test]
    fn to_ascii_known_answers() {
        let cases = [
            ("example.com", "example.com"),
            ("EXAMPLE.com.", "example.com."),
            ("bücher.example", "xn--bcher-kva.example"),
            ("faß.de", "xn--fa-hia.de"),
            ("βόλος.com", "xn--nxasmm1c.com"),
            ("ශ්‍රී.com", "xn--10cl1a0b660p.com"),
            ("نامه‌ای.com", "xn--mgba3gch31f060k.com"),
            ("日本語。ＪＰ", "xn--wgv71a119e.jp"),
            ("☕.us", "xn--53h.us"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("ＡＢＣ．ｃｏｍ", "abc.com"),
            ("ⓐbc.com", "abc.com"),
        ];
        for (input, expected) in cases {
            assert_eq!(ascii(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn to_unicode_known_answers() {
        let o = Options::default();
        assert_eq!(to_unicode("xn--nxasmm1c.com", &o).unwrap(), "βόλος.com");
        assert_eq!(to_unicode("xn--fa-hia.de", &o).unwrap(), "faß.de");
        assert_eq!(
            to_unicode("XN--BCHER-KVA.example", &o).unwrap(),
            "bücher.example"
        );
        assert_eq!(to_unicode("example.com", &o).unwrap(), "example.com");
    }

    #[test]
    fn invalid_names() {
        for input in [
            "a b.com",
            "a_b.com",
            "xn--a.com", // decodes to nothing valid
            "xn--bcher-kva\u{0}.com",
            "\u{200d}.com",  // ZWJ without a virama (CheckJoiners)
            "a\u{05d0}.com", // LTR then RTL in one label (CheckBidi)
            "\u{0301}a.com", // label starts with a combining mark
        ] {
            assert_eq!(ascii(input), Err(Error::Uts46), "{input:?}");
        }
        assert_eq!(
            to_unicode("xn--zz-zzzz.com", &Options::default()),
            Err(Error::Uts46)
        );
    }

    #[test]
    fn ascii_rules() {
        let url = Options::default().with_ascii_rules(AsciiRules::Url);
        assert_eq!(to_ascii("_dmarc.example", &url).unwrap(), "_dmarc.example");
        assert!(to_ascii("a/b.example", &url).is_err());
        let none = Options::default().with_ascii_rules(AsciiRules::None);
        assert_eq!(to_ascii("a/b.example", &none).unwrap(), "a/b.example");
    }

    #[test]
    fn hyphens() {
        let check = Options::default().with_check_hyphens(true);
        assert!(ascii("-a.com").is_ok());
        assert!(ascii("ab--c.com").is_ok());
        assert_eq!(to_ascii("-a.com", &check), Err(Error::Uts46));
        assert_eq!(to_ascii("a-.com", &check), Err(Error::Uts46));
        assert_eq!(to_ascii("ab--c.com", &check), Err(Error::Uts46));
        assert!(to_ascii("xn--bcher-kva.com", &check).is_ok());
    }

    #[test]
    fn dns_length() {
        let label = "a".repeat(63);
        assert!(ascii(&format!("{label}.com")).is_ok());
        assert_eq!(
            ascii(&format!("{label}a.com")),
            Err(Error::LabelTooLong { index: 0, len: 64 })
        );
        assert_eq!(ascii(""), Err(Error::EmptyLabel { index: 0 }));
        assert_eq!(ascii("a..b"), Err(Error::EmptyLabel { index: 1 }));
        assert_eq!(ascii("."), Err(Error::EmptyLabel { index: 0 }));
        let long = [label.as_str(); 4].join(".");
        assert_eq!(long.len(), 255);
        assert_eq!(ascii(&long), Err(Error::DomainTooLong { len: 255 }));
        // The trailing root dot does not count.
        let fits = format!("{}.{}", [label.as_str(); 3].join("."), "a".repeat(61));
        assert_eq!(fits.len(), 253);
        assert!(ascii(&format!("{fits}.")).is_ok());

        let off = Options::default().with_verify_dns_length(false);
        assert_eq!(to_ascii("a..b", &off).unwrap(), "a..b");
        assert_eq!(to_ascii("", &off).unwrap(), "");
    }

    #[test]
    fn idna2008_repertoire() {
        let strict = Options::default().with_idna2008(true);
        // U+2615 HOT BEVERAGE is NV8: UTS #46 valid, IDNA2008 DISALLOWED.
        assert!(ascii("☕.us").is_ok());
        assert_eq!(to_ascii("☕.us", &strict), Err(Error::NotIdna2008('☕')));
        assert_eq!(
            to_ascii("xn--53h.us", &strict),
            Err(Error::NotIdna2008('☕'))
        );
        assert_eq!(
            to_unicode("xn--53h.us", &strict),
            Err(Error::NotIdna2008('☕'))
        );
        assert_eq!(to_ascii("bücher.de", &strict).unwrap(), "xn--bcher-kva.de");
        // `_` is NV8 too, when the ASCII rules let it through.
        let url_strict = strict.with_ascii_rules(AsciiRules::Url);
        assert_eq!(
            to_ascii("_a.com", &url_strict),
            Err(Error::NotIdna2008('_'))
        );
        assert!(is_idna2008_excluded('☕'));
        assert!(!is_idna2008_excluded('a'));
        assert!(!is_idna2008_excluded('ü'));
    }

    #[test]
    fn registration_profile() {
        let reg = Options::registration();
        assert!(reg.check_hyphens && reg.idna2008 && reg.verify_dns_length);
        assert_eq!(reg.ascii_rules, AsciiRules::Std3);
        assert_eq!(Options::default(), Options::lookup());
    }

    #[test]
    fn same_domain_compares_ascii_forms() {
        let o = Options::default();
        assert!(same_domain("Example.COM", "example.com.", &o));
        assert!(same_domain("日本語.jp", "xn--wgv71a119e.jp", &o));
        assert!(!same_domain("a.com", "b.com", &o));
        assert!(!same_domain("a b.com", "a b.com", &o));
    }
}
