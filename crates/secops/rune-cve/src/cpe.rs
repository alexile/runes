//! CPE names: parsing the CPE 2.3 formatted string and CPE 2.2 URI
//! bindings, and name matching.
//!
//! Specifications: [NISTIR 7695](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)
//! (CPE 2.3 Naming) and [NISTIR 7696](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf)
//! (CPE 2.3 Name Matching).

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// Longest CPE name accepted, in bytes. Real names are well under 300;
/// the limit bounds the cost of wildcard matching on hostile input.
pub const MAX_CPE_LEN: usize = 4096;

/// The eleven attributes of a CPE name, in binding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Attribute {
    /// `a` (application), `o` (operating system) or `h` (hardware).
    Part,
    /// The vendor, e.g. `apache`.
    Vendor,
    /// The product, e.g. `log4j`.
    Product,
    /// The version, e.g. `2.14.1`.
    Version,
    /// The update or service pack, e.g. `sp1`, `rc1`.
    Update,
    /// The legacy edition attribute.
    Edition,
    /// The language tag, e.g. `en-us`.
    Language,
    /// The software edition, e.g. `enterprise`.
    SwEdition,
    /// The target software environment, e.g. `node.js`, `wordpress`.
    TargetSw,
    /// The target hardware, e.g. `x64`.
    TargetHw,
    /// Any other qualifier.
    Other,
}

impl Attribute {
    /// Every attribute, in binding order.
    pub const ALL: [Self; 11] = [
        Self::Part,
        Self::Vendor,
        Self::Product,
        Self::Version,
        Self::Update,
        Self::Edition,
        Self::Language,
        Self::SwEdition,
        Self::TargetSw,
        Self::TargetHw,
        Self::Other,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// The `part` of a CPE name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Part {
    /// `a`: an application.
    Application,
    /// `o`: an operating system.
    OperatingSystem,
    /// `h`: a hardware device.
    Hardware,
}

impl Part {
    /// The one-letter code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "a",
            Self::OperatingSystem => "o",
            Self::Hardware => "h",
        }
    }
}

/// One character of an attribute value pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Tok {
    /// A literal character.
    Char(char),
    /// Unquoted `?`: exactly one character.
    One,
    /// Unquoted `*`: any number of characters.
    Many,
}

/// A concrete attribute value, possibly with wildcards.
///
/// Values are stored unescaped and ASCII-lowercased (CPE matching is
/// case-insensitive).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Value {
    /// The literal characters, when the value has no wildcard.
    literal: Option<Box<str>>,
    /// The whole pattern, when it has a wildcard.
    pattern: Box<[Tok]>,
}

impl Value {
    fn from_toks(toks: Vec<Tok>) -> Self {
        let literal = toks
            .iter()
            .map(|t| match t {
                Tok::Char(c) => Some(*c),
                _ => None,
            })
            .collect::<Option<String>>()
            .map(String::into_boxed_str);
        if literal.is_some() {
            Self {
                literal,
                pattern: Box::new([]),
            }
        } else {
            Self {
                literal: None,
                pattern: toks.into_boxed_slice(),
            }
        }
    }

    fn literal_str(text: &str) -> Self {
        Self {
            literal: Some(text.to_ascii_lowercase().into_boxed_str()),
            pattern: Box::new([]),
        }
    }

    /// The value, unescaped, when it has no wildcard.
    #[must_use]
    pub fn as_literal(&self) -> Option<&str> {
        self.literal.as_deref()
    }

    /// Whether the value contains an unquoted `*` or `?`.
    #[must_use]
    pub const fn has_wildcard(&self) -> bool {
        self.literal.is_none()
    }

    /// Whether this value, as a pattern, matches the literal `target`.
    fn matches_literal(&self, target: &str) -> bool {
        self.literal.as_deref().map_or_else(
            || glob(&self.pattern, &target.chars().collect::<Vec<_>>()),
            |lit| lit == target,
        )
    }

    fn write_fs(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(lit) = &self.literal {
            if &**lit == "-" {
                return f.write_str("\\-");
            }
            for c in lit.chars() {
                write_fs_char(f, c)?;
            }
            return Ok(());
        }
        for t in &*self.pattern {
            match *t {
                Tok::Char(c) => write_fs_char(f, c)?,
                Tok::One => f.write_str("?")?,
                Tok::Many => f.write_str("*")?,
            }
        }
        Ok(())
    }
}

fn write_fs_char(f: &mut fmt::Formatter<'_>, c: char) -> fmt::Result {
    use fmt::Write;
    if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        f.write_char('\\')?;
    }
    f.write_char(c)
}

/// `?` matches one character, `*` any run; iterative with backtracking to
/// the last `*`, O(pattern × text) at worst.
fn glob(pattern: &[Tok], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(Tok::Char(c)) if *c == text[t] => {
                p += 1;
                t += 1;
            }
            Some(Tok::One) => {
                p += 1;
                t += 1;
            }
            Some(Tok::Many) => {
                star = Some((p, t));
                p += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p.min(pattern.len())..]
        .iter()
        .all(|tok| *tok == Tok::Many)
}

/// The value of one attribute of a CPE name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Component {
    /// `*` (ANY): any value, including none.
    #[default]
    Any,
    /// `-` (NA): the attribute does not apply.
    Na,
    /// A value, possibly with wildcards.
    Value(Value),
}

impl Component {
    /// A literal value, taken as is (no escape processing, no wildcards).
    /// ASCII letters are lowercased.
    #[must_use]
    pub fn literal(text: &str) -> Self {
        Self::Value(Value::literal_str(text))
    }

    /// The value when it is a literal without wildcards.
    #[must_use]
    pub fn as_literal(&self) -> Option<&str> {
        match self {
            Self::Value(v) => v.as_literal(),
            _ => None,
        }
    }

    /// Whether `self`, as a source pattern, is a superset of or equal to
    /// `target` (NISTIR 7696 §6.2: SUPERSET or EQUAL).
    fn matches(&self, target: &Self) -> bool {
        match (self, target) {
            (Self::Any, _) | (Self::Na, Self::Na) => true,
            (Self::Na, _) | (Self::Value(_), Self::Any | Self::Na) => false,
            // Wildcards in a target are undefined in 7696; only an
            // identical pattern matches.
            (Self::Value(s), Self::Value(t)) => t
                .as_literal()
                .map_or_else(|| s == t, |lit| s.matches_literal(lit)),
        }
    }
}

impl fmt::Display for Component {
    /// The formatted-string form: `*`, `-`, or the escaped value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Na => f.write_str("-"),
            Self::Value(v) => v.write_fs(f),
        }
    }
}

/// A CPE name: eleven attributes, each [`Any`](Component::Any),
/// [`Na`](Component::Na) or a value.
///
/// [`FromStr`] accepts both bindings:
///
/// - the CPE 2.3 formatted string, `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`,
///   with `\` quoting and unquoted `*`/`?` wildcards. Trailing attributes
///   may be left out and are then ANY (`cpe:2.3:a:apache:log4j:2.14.1`);
/// - the CPE 2.2 URI, `cpe:/a:apache:http_server:2.4.41`, with
///   percent-encoding, `%01`/`%02` wildcards and a packed `~` edition.
///
/// [`Display`](fmt::Display) writes the formatted string with all eleven
/// attributes; it parses back to an equal name. Values are ASCII-lowercased
/// on parse, because CPE comparison is case-insensitive. Serialized as the
/// formatted string.
///
/// # Examples
///
/// ```
/// use rune_cve::{Attribute, Cpe, Part};
///
/// let criteria: Cpe = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*".parse()?;
/// let installed: Cpe = "cpe:/a:apache:log4j:2.14.1".parse()?;
/// assert!(criteria.matches(&installed));
/// assert!(!installed.matches(&criteria));
/// assert_eq!(installed.get(Attribute::Version).as_literal(), Some("2.14.1"));
///
/// let built = Cpe::new(Part::Application, "Apache", "log4j").with_version("2.14.1");
/// assert_eq!(built, installed);
/// assert_eq!(built.to_string(), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
/// # Ok::<(), rune_cve::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cpe {
    attrs: [Component; 11],
}

impl Cpe {
    /// A name for `vendor`'s `product`; every other attribute is ANY.
    /// Values are literal (see [`Component::literal`]).
    #[must_use]
    pub fn new(part: Part, vendor: &str, product: &str) -> Self {
        let mut attrs: [Component; 11] = Default::default();
        attrs[Attribute::Part.index()] = Component::literal(part.as_str());
        attrs[Attribute::Vendor.index()] = Component::literal(vendor);
        attrs[Attribute::Product.index()] = Component::literal(product);
        Self { attrs }
    }

    /// The name with the literal `version`.
    #[must_use]
    pub fn with_version(self, version: &str) -> Self {
        self.with(Attribute::Version, Component::literal(version))
    }

    /// The name with `attribute` set to `value`.
    #[must_use]
    pub fn with(mut self, attribute: Attribute, value: Component) -> Self {
        self.attrs[attribute.index()] = value;
        self
    }

    /// The value of `attribute`.
    #[must_use]
    pub const fn get(&self, attribute: Attribute) -> &Component {
        &self.attrs[attribute.index()]
    }

    /// The part, if it is one of `a`, `o`, `h` (not ANY).
    #[must_use]
    pub fn part(&self) -> Option<Part> {
        match self.get(Attribute::Part).as_literal()? {
            "a" => Some(Part::Application),
            "o" => Some(Part::OperatingSystem),
            "h" => Some(Part::Hardware),
            _ => None,
        }
    }

    /// The vendor, when it is a literal.
    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        self.get(Attribute::Vendor).as_literal()
    }

    /// The product, when it is a literal.
    #[must_use]
    pub fn product(&self) -> Option<&str> {
        self.get(Attribute::Product).as_literal()
    }

    /// The version, when it is a literal.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.get(Attribute::Version).as_literal()
    }

    /// Whether this name, used as a pattern (the *source* in NISTIR 7696),
    /// matches `target`: every attribute of `self` is a superset of or
    /// equal to the target's.
    ///
    /// ANY matches anything, NA only NA, and a value with wildcards any
    /// literal it matches. A value never matches a target's ANY: a
    /// criterion for version `2.14.1` does not match "log4j, version
    /// unknown".
    #[must_use]
    pub fn matches(&self, target: &Self) -> bool {
        self.attrs
            .iter()
            .zip(&target.attrs)
            .all(|(s, t)| s.matches(t))
    }

    /// [`matches`](Self::matches), ignoring the version attribute.
    pub(crate) fn matches_except_version(&self, target: &Self) -> bool {
        self.attrs
            .iter()
            .zip(&target.attrs)
            .enumerate()
            .all(|(i, (s, t))| i == Attribute::Version.index() || s.matches(t))
    }

    fn parse_fs(input: &str, body: &str) -> Result<Self, Error> {
        let mut attrs: [Component; 11] = Default::default();
        let mut count = 0;
        let mut toks = Vec::new();
        let mut raw_len = 0;
        let mut chars = body.chars();
        let mut finish = |toks: &mut Vec<Tok>, raw_len: &mut usize| -> Result<(), Error> {
            let slot = attrs
                .get_mut(count)
                .ok_or_else(|| Error::cpe(input, "more than 11 attributes"))?;
            *slot = component_from_toks(core::mem::take(toks), *raw_len)
                .ok_or_else(|| Error::cpe(input, "empty attribute"))?;
            count += 1;
            *raw_len = 0;
            Ok(())
        };
        loop {
            match chars.next() {
                None => {
                    finish(&mut toks, &mut raw_len)?;
                    break;
                }
                Some(':') => finish(&mut toks, &mut raw_len)?,
                Some('\\') => {
                    let c = chars
                        .next()
                        .ok_or_else(|| Error::cpe(input, "trailing backslash"))?;
                    toks.push(Tok::Char(c.to_ascii_lowercase()));
                    raw_len += 2;
                }
                Some('*') => {
                    toks.push(Tok::Many);
                    raw_len += 1;
                }
                Some('?') => {
                    toks.push(Tok::One);
                    raw_len += 1;
                }
                Some(c) => {
                    toks.push(Tok::Char(c.to_ascii_lowercase()));
                    raw_len += 1;
                }
            }
        }
        Self::checked(input, attrs)
    }

    fn parse_uri(input: &str, body: &str) -> Result<Self, Error> {
        let fields: Vec<&str> = body.split(':').collect();
        if fields.len() > 7 {
            return Err(Error::cpe(input, "more than 7 URI components"));
        }
        let mut attrs: [Component; 11] = Default::default();
        for (i, field) in fields.iter().enumerate() {
            if i == Attribute::Edition.index() && field.starts_with('~') {
                // Packed: ~edition~sw_edition~target_sw~target_hw~other
                let packed: Vec<&str> = field[1..].split('~').collect();
                if packed.len() != 5 {
                    return Err(Error::cpe(input, "packed edition needs 5 fields"));
                }
                for (j, p) in packed.iter().enumerate() {
                    let index = [5, 7, 8, 9, 10][j];
                    attrs[index] = uri_component(input, p)?;
                }
            } else {
                attrs[i] = uri_component(input, field)?;
            }
        }
        Self::checked(input, attrs)
    }

    fn checked(input: &str, attrs: [Component; 11]) -> Result<Self, Error> {
        match &attrs[Attribute::Part.index()] {
            Component::Any => {}
            c if matches!(c.as_literal(), Some("a" | "o" | "h")) => {}
            _ => return Err(Error::cpe(input, "part must be a, o, h or *")),
        }
        Ok(Self { attrs })
    }
}

/// A formatted-string attribute from its tokens. A lone unquoted `*` is
/// ANY and a lone unquoted `-` (one raw byte) is NA; `\-` is a literal
/// hyphen. Empty is invalid.
fn component_from_toks(toks: Vec<Tok>, raw_len: usize) -> Option<Component> {
    match toks.as_slice() {
        [] => None,
        [Tok::Many] => Some(Component::Any),
        [Tok::Char('-')] if raw_len == 1 => Some(Component::Na),
        _ => Some(Component::Value(Value::from_toks(toks))),
    }
}

fn uri_component(input: &str, field: &str) -> Result<Component, Error> {
    match field {
        "" | "*" => return Ok(Component::Any),
        "-" => return Ok(Component::Na),
        _ => {}
    }
    let bytes = field.as_bytes();
    let mut toks = Vec::new();
    let mut lit = Vec::new();
    let flush = |lit: &mut Vec<u8>, toks: &mut Vec<Tok>| -> Result<(), Error> {
        let s = core::str::from_utf8(lit)
            .map_err(|_| Error::cpe(input, "percent-encoding is not UTF-8"))?;
        toks.extend(s.chars().map(|c| Tok::Char(c.to_ascii_lowercase())));
        lit.clear();
        Ok(())
    };
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = field
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| Error::cpe(input, "bad percent-encoding"))?;
            match hex {
                0x01 => {
                    flush(&mut lit, &mut toks)?;
                    toks.push(Tok::One);
                }
                0x02 => {
                    flush(&mut lit, &mut toks)?;
                    toks.push(Tok::Many);
                }
                b => lit.push(b),
            }
            i += 3;
        } else {
            lit.push(bytes[i]);
            i += 1;
        }
    }
    flush(&mut lit, &mut toks)?;
    Ok(Component::Value(Value::from_toks(toks)))
}

impl FromStr for Cpe {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_CPE_LEN {
            return Err(Error::cpe(s, "longer than 4096 bytes"));
        }
        let t = s.trim();
        let prefix = |p: &str| {
            t.get(..p.len())
                .filter(|head| head.eq_ignore_ascii_case(p))
                .map(|_| &t[p.len()..])
        };
        match (prefix("cpe:2.3:"), prefix("cpe:/")) {
            (Some(body), _) => Self::parse_fs(s, body),
            (None, Some(body)) => Self::parse_uri(s, body),
            (None, None) => Err(Error::cpe(s, "expected cpe:2.3: or cpe:/")),
        }
    }
}

impl fmt::Display for Cpe {
    /// The CPE 2.3 formatted string with all eleven attributes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cpe:2.3")?;
        for a in &self.attrs {
            write!(f, ":{a}")?;
        }
        Ok(())
    }
}

impl serde::Serialize for Cpe {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Cpe {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpe(s: &str) -> Cpe {
        s.parse().unwrap()
    }

    #[test]
    fn parses_formatted_strings() {
        let c = cpe(r"cpe:2.3:a:microsoft:visual_c\+\+:2019:-:*:*:*:*:x64:*");
        assert_eq!(c.part(), Some(Part::Application));
        assert_eq!(c.vendor(), Some("microsoft"));
        assert_eq!(c.product(), Some("visual_c++"));
        assert_eq!(c.version(), Some("2019"));
        assert_eq!(c.get(Attribute::Update), &Component::Na);
        assert_eq!(c.get(Attribute::Edition), &Component::Any);
        assert_eq!(c.get(Attribute::TargetHw).as_literal(), Some("x64"));
        assert_eq!(
            c.to_string(),
            r"cpe:2.3:a:microsoft:visual_c\+\+:2019:-:*:*:*:*:x64:*"
        );
    }

    #[test]
    fn escapes_and_case() {
        let c = cpe(r"CPE:2.3:A:Vendor:Pro\:duct:1.0\-beta:*:*:*:*:*:*:*");
        assert_eq!(c.product(), Some("pro:duct"));
        assert_eq!(c.version(), Some("1.0-beta"));
        // A quoted lone hyphen is a value, not NA.
        let h = cpe(r"cpe:2.3:a:v:p:\-:*:*:*:*:*:*:*");
        assert_eq!(h.version(), Some("-"));
        assert_eq!(h.to_string(), r"cpe:2.3:a:v:p:\-:*:*:*:*:*:*:*");
        assert_eq!(cpe(&h.to_string()), h);
        // A quoted asterisk is a literal.
        let s = cpe(r"cpe:2.3:a:v:p:\*:*:*:*:*:*:*:*");
        assert_eq!(s.version(), Some("*"));
    }

    #[test]
    fn short_forms_pad_with_any() {
        assert_eq!(
            cpe("cpe:2.3:a:apache:log4j:2.14.1"),
            cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn parses_uris() {
        let u = cpe("cpe:/a:apache:http_server:2.4.41");
        assert_eq!(u, cpe("cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"));
        let packed = cpe("cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~");
        assert_eq!(
            packed.get(Attribute::SwEdition).as_literal(),
            Some("online")
        );
        assert_eq!(
            packed.get(Attribute::TargetSw).as_literal(),
            Some("win2003")
        );
        assert_eq!(packed.get(Attribute::TargetHw).as_literal(), Some("x64"));
        assert_eq!(packed.get(Attribute::Edition), &Component::Any);
        let enc = cpe("cpe:/a:foo%21bar:p%02:1.0:-");
        assert_eq!(enc.vendor(), Some("foo!bar"));
        assert!(enc.get(Attribute::Product).as_literal().is_none());
        assert_eq!(enc.get(Attribute::Update), &Component::Na);
        assert_eq!(cpe("cpe:/o:linux:linux_kernel").version(), None);
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "cpe:2.3",
            "cpe:2.2:a:v:p",
            "cpe:2.3:x:v:p:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*:*",
            "cpe:2.3:a::p",
            "cpe:2.3:a:v:p\\",
            "cpe:/a:v:p:1:2:3:4:5",
            "cpe:/a:v:p:%zz",
            "cpe:/a:v:p:%ff",
            "cpe:/a:v:p:1::~a~b",
            "cpe:/q:v:p",
            "a:v:p",
        ] {
            assert!(s.parse::<Cpe>().is_err(), "{s}");
        }
        let long = format!("cpe:2.3:a:v:{}", "p".repeat(MAX_CPE_LEN));
        assert!(long.parse::<Cpe>().is_err());
    }

    #[test]
    fn name_matching() {
        let target = cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");
        assert!(cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*").matches(&target));
        assert!(cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").matches(&target));
        assert!(cpe("cpe:2.3:*:*:*:*:*:*:*:*:*:*:*").matches(&target));
        assert!(!cpe("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*").matches(&target));
        assert!(!cpe("cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*").matches(&target));
        assert!(!cpe("cpe:2.3:o:apache:log4j:*:*:*:*:*:*:*:*").matches(&target));
        // A value is a subset of ANY: no match.
        let unknown = cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
        assert!(!target.matches(&unknown));
        // NA matches only NA.
        let na = cpe("cpe:2.3:a:apache:log4j:2.14.1:-:*:*:*:*:*:*");
        assert!(!na.matches(&target));
        assert!(na.matches(&cpe("cpe:2.3:a:apache:log4j:2.14.1:-:*:*:*:*:*:*")));
        assert!(target.matches(&na));
    }

    #[test]
    fn wildcards() {
        let t = |v: &str| cpe(&format!("cpe:2.3:a:v:p:{v}:*:*:*:*:*:*:*"));
        let p = cpe("cpe:2.3:a:v:p:2.14.*:*:*:*:*:*:*:*");
        assert!(p.matches(&t("2.14.1")));
        assert!(p.matches(&t("2.14.")));
        assert!(!p.matches(&t("2.15.0")));
        let q = cpe("cpe:2.3:a:v:p:1.?:*:*:*:*:*:*:*");
        assert!(q.matches(&t("1.5")));
        assert!(!q.matches(&t("1.")));
        assert!(!q.matches(&t("1.55")));
        let lead = cpe("cpe:2.3:a:v:p:*beta:*:*:*:*:*:*:*");
        assert!(lead.matches(&t("1.0beta")));
        assert!(lead.matches(&t("beta")));
        assert!(!lead.matches(&t("beta1")));
        // A wildcard target only matches the same pattern.
        assert!(p.matches(&p.clone()));
        assert!(!q.matches(&p));
        assert_eq!(p.to_string(), "cpe:2.3:a:v:p:2.14.*:*:*:*:*:*:*:*");
        assert_eq!(cpe(&p.to_string()), p);
    }

    #[test]
    fn glob_backtracks() {
        let toks = |s: &str| {
            s.chars()
                .map(|c| match c {
                    '*' => Tok::Many,
                    '?' => Tok::One,
                    c => Tok::Char(c),
                })
                .collect::<Vec<_>>()
        };
        let chars = |s: &str| s.chars().collect::<Vec<_>>();
        assert!(glob(&toks("*a*b"), &chars("xxaxxbxb")));
        assert!(!glob(&toks("*a*b"), &chars("xxaxxbxc")));
        assert!(glob(&toks("**"), &chars("")));
        assert!(!glob(&toks("?"), &chars("")));
        assert!(glob(&toks("a?c*"), &chars("abcdef")));
    }

    #[test]
    fn serde_as_string() {
        let c: Cpe = serde_json::from_str("\"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*\"").unwrap();
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            "\"cpe:2.3:a:v:p:1:*:*:*:*:*:*:*\""
        );
    }
}
