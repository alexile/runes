//! The master-file parser (RFC 1035 §5): directives and resource records.

use rune_dns_wire::{Class, Name, Record};

use crate::Error;
use crate::lexer::{Entry, entries};
use crate::present::{name_from_text, parse_rdata, parse_ttl};
use crate::types::parse_record_type;
use crate::zone::Zone;

/// Options for [`parse`] and [`parse_with_includes`].
///
/// ```
/// use rune_dns_wire::Class;
/// use rune_dns_zone::{ParseOptions, parse};
///
/// let options = ParseOptions::default()
///     .with_origin("example.com".parse()?)
///     .with_default_ttl(300)
///     .with_default_class(Class::IN)
///     .with_max_records(10);
/// let zone = parse("www A 192.0.2.1", &options)?;
/// assert_eq!(zone.records[0].name.to_string(), "www.example.com");
/// assert_eq!(zone.records[0].ttl, 300);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseOptions {
    /// Origin before the first `$ORIGIN`; `None` makes relative names an
    /// error until one appears.
    pub origin: Option<Name>,
    /// TTL for records without one when neither `$TTL` nor an earlier
    /// record gives one.
    pub default_ttl: Option<u32>,
    /// Class for records before the first one that states a class.
    pub default_class: Class,
    /// How deeply `$INCLUDE`s may nest (default 8).
    pub max_include_depth: usize,
    /// Most `$INCLUDE`s to read in all, counting repeats (default 1024).
    /// The depth limit alone does not stop a few files that each include
    /// the next many times.
    pub max_includes: usize,
    /// Most records to accept (default 10 000 000).
    pub max_records: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            origin: None,
            default_ttl: None,
            default_class: Class::IN,
            max_include_depth: 8,
            max_includes: 1024,
            max_records: 10_000_000,
        }
    }
}

impl ParseOptions {
    /// Sets the initial origin.
    #[must_use]
    pub fn with_origin(mut self, origin: Name) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Sets the fallback TTL.
    #[must_use]
    pub const fn with_default_ttl(mut self, ttl: u32) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    /// Sets the initial class.
    #[must_use]
    pub const fn with_default_class(mut self, class: Class) -> Self {
        self.default_class = class;
        self
    }

    /// Sets the `$INCLUDE` nesting limit; `0` rejects every `$INCLUDE`.
    #[must_use]
    pub const fn with_max_include_depth(mut self, depth: usize) -> Self {
        self.max_include_depth = depth;
        self
    }

    /// Sets the total `$INCLUDE` limit; `0` rejects every `$INCLUDE`.
    #[must_use]
    pub const fn with_max_includes(mut self, max: usize) -> Self {
        self.max_includes = max;
        self
    }

    /// Sets the record limit.
    #[must_use]
    pub const fn with_max_records(mut self, max: usize) -> Self {
        self.max_records = max;
        self
    }
}

/// Parses a zone file. `$INCLUDE` is an error; use [`parse_with_includes`]
/// to follow it.
///
/// # Errors
///
/// Any [`Error`] describing the first problem, with its line number.
pub fn parse(text: &str, options: &ParseOptions) -> Result<Zone, Error> {
    let mut state = State::new(options);
    state.run(text, 0, &mut None)?;
    Ok(Zone::new(state.records))
}

/// Parses a zone file, reading each `$INCLUDE <path> [<origin>]` with
/// `loader`.
///
/// `loader` returns the file's text or a reason it cannot. The
/// included file starts with the given origin (or the current one), and the
/// origin is restored after it, as RFC 1035 §5.1 requires.
///
/// ```
/// use rune_dns_zone::{ParseOptions, parse_with_includes};
///
/// let main = "$ORIGIN example.com.\n$TTL 60\n$INCLUDE hosts.inc lan\nwww A 192.0.2.1\n";
/// let zone = parse_with_includes(main, &ParseOptions::default(), |path| match path {
///     "hosts.inc" => Ok("printer A 10.0.0.9\n".to_owned()),
///     _ => Err("not found".to_owned()),
/// })?;
/// assert_eq!(zone.records[0].name.to_string(), "printer.lan.example.com");
/// assert_eq!(zone.records[1].name.to_string(), "www.example.com");
/// # Ok::<(), rune_dns_zone::Error>(())
/// ```
///
/// # Errors
///
/// As [`parse`], plus [`Error::Include`] when `loader` fails,
/// [`Error::IncludeDepth`] past [`ParseOptions::max_include_depth`],
/// [`Error::TooManyIncludes`] past [`ParseOptions::max_includes`], and
/// [`Error::InInclude`] wrapping an error inside an included file.
pub fn parse_with_includes<F>(
    text: &str,
    options: &ParseOptions,
    mut loader: F,
) -> Result<Zone, Error>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut state = State::new(options);
    let mut loader: Loader<'_> = Some(&mut loader);
    state.run(text, 0, &mut loader)?;
    Ok(Zone::new(state.records))
}

type Loader<'l> = Option<&'l mut dyn FnMut(&str) -> Result<String, String>>;

/// Parser state carried from entry to entry (and into includes).
struct State<'o> {
    options: &'o ParseOptions,
    origin: Option<Name>,
    /// The `$TTL` value.
    default_ttl: Option<u32>,
    /// The last TTL written on a record.
    last_ttl: Option<u32>,
    class: Class,
    owner: Option<Name>,
    records: Vec<Record>,
    /// `$INCLUDE`s read so far.
    includes: usize,
}

impl<'o> State<'o> {
    fn new(options: &'o ParseOptions) -> Self {
        Self {
            options,
            origin: options.origin.clone(),
            default_ttl: None,
            last_ttl: None,
            class: options.default_class,
            owner: None,
            records: Vec::new(),
            includes: 0,
        }
    }

    fn run(&mut self, text: &str, depth: usize, loader: &mut Loader<'_>) -> Result<(), Error> {
        for entry in entries(text)? {
            let is_directive = !entry.blank_owner
                && entry
                    .tokens
                    .first()
                    .is_some_and(|token| !token.quoted && token.text.starts_with('$'));
            if is_directive {
                self.directive(&entry, depth, loader)?;
            } else {
                self.record(&entry)?;
            }
        }
        Ok(())
    }

    fn directive(
        &mut self,
        entry: &Entry,
        depth: usize,
        loader: &mut Loader<'_>,
    ) -> Result<(), Error> {
        let line = entry.line;
        let Some((name, args)) = entry.tokens.split_first() else {
            return Ok(());
        };
        let args: Vec<&str> = args.iter().map(|token| token.text.as_str()).collect();
        let syntax = |reason| Error::Syntax { line, reason };
        match name.text.to_ascii_uppercase().as_str() {
            "$ORIGIN" => {
                let [origin] = args[..] else {
                    return Err(syntax("$ORIGIN takes one name"));
                };
                self.origin = Some(name_from_text(origin, self.origin.as_ref(), line)?);
            }
            "$TTL" => {
                let [ttl] = args[..] else {
                    return Err(syntax("$TTL takes one TTL"));
                };
                self.default_ttl = Some(parse_ttl(ttl).ok_or_else(|| syntax("invalid TTL"))?);
            }
            "$INCLUDE" => {
                let (path, origin) = match args[..] {
                    [path] => (path, None),
                    [path, origin] => (path, Some(origin)),
                    _ => return Err(syntax("$INCLUDE takes a path and an optional origin")),
                };
                if depth >= self.options.max_include_depth {
                    return Err(Error::IncludeDepth { line });
                }
                if self.includes >= self.options.max_includes {
                    return Err(Error::TooManyIncludes {
                        line,
                        max: self.options.max_includes,
                    });
                }
                self.includes += 1;
                let include_error = |reason: String| Error::Include {
                    line,
                    path: path.to_owned(),
                    reason,
                };
                let Some(load) = loader.as_mut() else {
                    return Err(include_error("no include loader configured".to_owned()));
                };
                let text = load(path).map_err(include_error)?;
                let saved = self.origin.clone();
                if let Some(origin) = origin {
                    self.origin = Some(name_from_text(origin, saved.as_ref(), line)?);
                }
                let result = self.run(&text, depth + 1, loader);
                self.origin = saved;
                result.map_err(|source| Error::InInclude {
                    path: path.to_owned(),
                    source: Box::new(source),
                })?;
            }
            _ => {
                return Err(Error::UnsupportedDirective {
                    line,
                    directive: name.text.clone(),
                });
            }
        }
        Ok(())
    }

    fn record(&mut self, entry: &Entry) -> Result<(), Error> {
        let line = entry.line;
        let mut tokens = &entry.tokens[..];
        let owner = if entry.blank_owner {
            self.owner.clone().ok_or(Error::NoOwner { line })?
        } else {
            let Some((first, rest)) = tokens.split_first() else {
                return Ok(());
            };
            if first.quoted {
                return Err(Error::Syntax {
                    line,
                    reason: "owner name is quoted",
                });
            }
            tokens = rest;
            name_from_text(&first.text, self.origin.as_ref(), line)?
        };

        // `[<TTL>] [<class>]` or `[<class>] [<TTL>]`, then the type.
        let mut ttl = None;
        let mut class = None;
        while let Some((token, rest)) = tokens.split_first() {
            if token.quoted {
                break;
            }
            if let (None, Some(value)) = (ttl, parse_ttl(&token.text)) {
                ttl = Some(value);
                tokens = rest;
                continue;
            }
            if let (None, Ok(value)) = (class, token.text.parse::<Class>()) {
                class = Some(value);
                tokens = rest;
                continue;
            }
            break;
        }
        let (rtype, rdata) = tokens.split_first().ok_or(Error::Syntax {
            line,
            reason: "missing record type",
        })?;
        let rtype = Some(rtype)
            .filter(|token| !token.quoted)
            .and_then(|token| parse_record_type(&token.text))
            .ok_or_else(|| Error::UnknownType {
                line,
                text: rtype.text.clone(),
            })?;

        let ttl = match ttl {
            Some(ttl) => {
                self.last_ttl = Some(ttl);
                ttl
            }
            None => self
                .default_ttl
                .or(self.last_ttl)
                .or(self.options.default_ttl)
                .ok_or(Error::NoTtl { line })?,
        };
        let class = class.unwrap_or(self.class);
        let data = parse_rdata(rtype, rdata, line, self.origin.as_ref())?;

        if self.records.len() >= self.options.max_records {
            return Err(Error::TooManyRecords {
                max: self.options.max_records,
            });
        }
        self.class = class;
        self.owner = Some(owner.clone());
        self.records
            .push(Record::new(owner, ttl, data).with_class(class));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rune_dns_wire::{RData, RecordType};

    use super::*;

    fn parse_ok(text: &str) -> Zone {
        parse(text, &ParseOptions::default()).unwrap()
    }

    #[test]
    fn ttl_and_class_in_either_order() {
        let zone = parse_ok(
            "$ORIGIN example.com.\n\
             a 60 IN A 192.0.2.1\n\
             b CH 70 A 192.0.2.2\n\
             c A 192.0.2.3\n\
             $TTL 1d\n\
             d A 192.0.2.4\n\
             e 5 A 192.0.2.5\n\
             f A 192.0.2.6\n",
        );
        let summary: Vec<_> = zone
            .records
            .iter()
            .map(|r| (r.name.to_string(), r.ttl, r.class))
            .collect();
        assert_eq!(
            summary,
            [
                ("a.example.com".to_owned(), 60, Class::IN),
                ("b.example.com".to_owned(), 70, Class::CH),
                ("c.example.com".to_owned(), 70, Class::CH),
                ("d.example.com".to_owned(), 86_400, Class::CH),
                ("e.example.com".to_owned(), 5, Class::CH),
                ("f.example.com".to_owned(), 86_400, Class::CH),
            ]
        );
    }

    #[test]
    fn owner_that_looks_like_a_number() {
        let zone = parse_ok("$ORIGIN 2.0.192.in-addr.arpa.\n$TTL 60\n1 PTR host.example.\n");
        assert_eq!(zone.records[0].name.to_string(), "1.2.0.192.in-addr.arpa");
        assert_eq!(zone.records[0].rtype(), RecordType::PTR);
    }

    #[test]
    fn origin_is_relative_to_the_previous_one() {
        let zone = parse_ok("$ORIGIN com.\n$ORIGIN example\n$TTL 1\n@ A 192.0.2.1\n");
        assert_eq!(zone.records[0].name.to_string(), "example.com");
    }

    #[test]
    fn errors_carry_line_numbers() {
        let cases: [(&str, Error); 8] = [
            ("\n\nwww A 1.2.3.4", Error::NoOrigin { line: 3 }),
            ("$ORIGIN x.\n www 1 A 1.2.3.4", Error::NoOwner { line: 2 }),
            ("a. A 1.2.3.4", Error::NoTtl { line: 1 }),
            (
                "a. 1 BOGUS x",
                Error::UnknownType {
                    line: 1,
                    text: "BOGUS".into(),
                },
            ),
            (
                "$GENERATE 1-2 a A 1.2.3.$",
                Error::UnsupportedDirective {
                    line: 1,
                    directive: "$GENERATE".into(),
                },
            ),
            (
                "$INCLUDE other",
                Error::Include {
                    line: 1,
                    path: "other".into(),
                    reason: "no include loader configured".into(),
                },
            ),
            (
                "a. 1 A",
                Error::Syntax {
                    line: 1,
                    reason: "missing RDATA field",
                },
            ),
            (
                "a. 1",
                Error::Syntax {
                    line: 1,
                    reason: "missing record type",
                },
            ),
        ];
        for (text, error) in cases {
            assert_eq!(
                parse(text, &ParseOptions::default()),
                Err(error),
                "{text:?}"
            );
        }
    }

    #[test]
    fn include_fan_out_is_bounded() {
        // Each file includes the next ten times, stopping just inside the
        // depth limit: 10^8 loads unless the total is capped.
        let mut loads = 0usize;
        let files = |path: &str| {
            loads += 1;
            if loads > 100_000 {
                return Err("loader called too often".to_owned());
            }
            let level: usize = path.parse().map_err(|_| "bad path".to_owned())?;
            if level >= 7 {
                return Ok(String::new());
            }
            Ok(format!("$INCLUDE {}\n", level + 1).repeat(10))
        };
        let error = parse_with_includes("$INCLUDE 0", &ParseOptions::default(), files).unwrap_err();
        let mut inner = &error;
        while let Error::InInclude { source, .. } = inner {
            inner = source;
        }
        assert!(
            matches!(inner, Error::TooManyIncludes { max: 1024, .. }),
            "{error}"
        );
    }

    #[test]
    fn includes_nest_and_restore_origin() {
        let files = |path: &str| match path {
            "a" => Ok("x A 10.0.0.1\n$INCLUDE b\ny A 10.0.0.2\n".to_owned()),
            "b" => Ok("$ORIGIN deep.\nz A 10.0.0.3\n".to_owned()),
            "loop" => Ok("$INCLUDE loop\n".to_owned()),
            "bad" => Ok("q A nope\n".to_owned()),
            _ => Err("missing".to_owned()),
        };
        let options = ParseOptions::default().with_default_ttl(1);
        let zone = parse_with_includes(
            "$ORIGIN example.\n$INCLUDE a sub\nw A 10.0.0.4\n",
            &options,
            files,
        )
        .unwrap();
        let names: Vec<_> = zone.records.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(
            names,
            [
                "x.sub.example",
                "z.deep",
                // `$ORIGIN` inside `b` lasts until the end of `a`'s include.
                "y.sub.example",
                "w.example",
            ]
        );

        let looped = parse_with_includes("$INCLUDE loop", &options, files).unwrap_err();
        let mut depth = 0;
        let mut error = &looped;
        while let Error::InInclude { source, .. } = error {
            depth += 1;
            error = source;
        }
        assert_eq!(depth, 8);
        assert_eq!(error, &Error::IncludeDepth { line: 1 });

        let bad = parse_with_includes("$ORIGIN e.\n$INCLUDE bad", &options, files).unwrap_err();
        assert_eq!(
            bad,
            Error::InInclude {
                path: "bad".into(),
                source: Box::new(Error::Syntax {
                    line: 1,
                    reason: "invalid IPv4 address"
                }),
            }
        );
    }

    #[test]
    fn record_limit() {
        let options = ParseOptions::default()
            .with_default_ttl(1)
            .with_max_records(1);
        let error = parse("a. A 1.1.1.1\nb. A 1.1.1.1\n", &options).unwrap_err();
        assert_eq!(error, Error::TooManyRecords { max: 1 });
    }

    #[test]
    fn quoted_semicolons_are_not_comments() {
        let zone = parse_ok("cmd.example. 300 IN TXT \"; ls\" ; real comment\n");
        assert_eq!(zone.records[0].data, RData::Txt(vec![b"; ls".to_vec()]));
        let zone = parse_ok("a.example. 1 A 192.0.2.1");
        assert_eq!(zone.records[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    }
}
