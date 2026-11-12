//! Shared machinery for metric value enums and vector string parsing.

use crate::{Error, Version};

/// Defines a metric value enum with its abbreviations.
///
/// `$name { Variant = "A" (level), ... }` generates the enum, `ALL`,
/// `abbrev`, `parse` and `Display`. Variants are listed in specification
/// order.
macro_rules! metric_enum {
    (
        $(#[$meta:meta])*
        $name:ident: $metric:literal {
            $( $(#[$vmeta:meta])* $variant:ident = $abbr:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every value, in specification order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The value's abbreviation in a vector string (case sensitive).
            #[must_use]
            pub const fn abbrev(self) -> &'static str {
                match self {
                    $( Self::$variant => $abbr, )+
                }
            }

            /// The value with this abbreviation, matched case sensitively
            /// as the specifications require.
            pub fn parse(value: &str) -> Result<Self, $crate::Error> {
                match value {
                    $( $abbr => Ok(Self::$variant), )+
                    _ => Err($crate::Error::InvalidValue {
                        metric: $metric,
                        value: value.to_owned(),
                    }),
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.abbrev())
            }
        }
    };
}

pub(crate) use metric_enum;

/// Parses an optional metric value: `X` (Not Defined) is `None`.
pub fn optional<T>(
    value: &str,
    parse: impl FnOnce(&str) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    if value == "X" {
        Ok(None)
    } else {
        parse(value).map(Some)
    }
}

/// One `NAME:VALUE` part of a vector string, or why it is malformed.
pub type MetricPart<'a> = Result<(&'a str, &'a str), Error>;

/// Splits a vector string into its version and its `NAME:VALUE` parts.
///
/// The prefix is `CVSS:<version>`, then each metric follows a `/`. Empty
/// parts (`//`, a trailing `/`) and parts without a `:` are malformed.
pub fn split(text: &str) -> Result<(Version, impl Iterator<Item = MetricPart<'_>>), Error> {
    let Some(rest) = text.strip_prefix("CVSS:") else {
        return Err(Error::MissingPrefix);
    };
    let (version, metrics) = rest.split_once('/').unwrap_or((rest, ""));
    let version = match version {
        "3.0" => Version::V3_0,
        "3.1" => Version::V3_1,
        "4.0" => Version::V4_0,
        other => return Err(Error::UnsupportedVersion(other.to_owned())),
    };
    // `"".split('/')` yields one empty part; a vector with no metrics after
    // the prefix has none, and is then missing its base metrics.
    let parts = metrics.split('/').filter(move |_| !metrics.is_empty());
    Ok((
        version,
        parts.map(|part| match part.split_once(':') {
            Some((name, value)) if !name.is_empty() && !value.is_empty() => Ok((name, value)),
            _ => Err(Error::MalformedMetric(part.to_owned())),
        }),
    ))
}
