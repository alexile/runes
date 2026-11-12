//! Converting between a finding's [`Location`] and a
//! SARIF [`Location`](model::Location).
//!
//! Every kind becomes a `physicalLocation` whose `artifactLocation.uri`
//! says what it is:
//!
//! | Finding location | `artifactLocation.uri` | `region` |
//! | --- | --- | --- |
//! | `File` | the path, percent-encoded where a URI needs it | lines, columns, `byteOffset`/`byteLength`, `snippet` |
//! | `Url` | the URL, plus `#parameter` when there is one | none |
//! | `Network` | `tcp://host:port` | none |
//! | `ClusterObject` | `k8s://namespace/kind/name` | none |
//! | `Artifact` | the path | none; the offset is `address.absoluteAddress` |
//!
//! Reading infers the kind back from the URI scheme (`http`, `https`, `ws`
//! and `wss` are URLs, `tcp` is a network endpoint, `k8s` a cluster object,
//! anything else a file). When that inference would not give the original
//! location back (a URL that already has a fragment, a path that looks like
//! a URL, an artifact without an offset, a line number of 0, ...), the
//! writer also stores the finding's location as JSON in the SARIF
//! location's property bag under [`LOCATION_PROPERTY`], and the reader
//! prefers it. Round trips are therefore lossless, and ordinary locations
//! carry no extra property.

use rune_finding::Location;

use crate::model;

/// Property of a SARIF location that holds the original finding location
/// (rune-finding JSON shape) when the URI alone cannot reproduce it.
pub const LOCATION_PROPERTY: &str = "rune-finding/location";

/// The SARIF location for a finding location, with the
/// [`LOCATION_PROPERTY`] hint added when it is needed for a lossless read.
#[must_use]
pub fn to_sarif(location: &Location) -> model::Location {
    let mut sarif = to_sarif_plain(location);
    if infer(&sarif).as_ref() != Some(location)
        && let Ok(value) = serde_json::to_value(location)
    {
        sarif.properties.insert(LOCATION_PROPERTY, value);
    }
    sarif
}

/// The SARIF location for a finding location, without the
/// [`LOCATION_PROPERTY`] hint.
#[must_use]
pub fn to_sarif_plain(location: &Location) -> model::Location {
    let physical = match location {
        Location::File {
            path,
            start_line,
            end_line,
            start_column,
            end_column,
            start_byte,
            end_byte,
            snippet,
        } => {
            let positive = |value: &Option<u32>| value.filter(|value| *value >= 1);
            let region = model::Region {
                start_line: positive(start_line),
                start_column: positive(start_column),
                end_line: positive(end_line),
                end_column: positive(end_column),
                byte_offset: *start_byte,
                byte_length: start_byte
                    .zip(*end_byte)
                    .and_then(|(start, end)| end.checked_sub(start)),
                snippet: snippet.as_ref().map(model::ArtifactContent::text),
                ..model::Region::default()
            };
            model::PhysicalLocation {
                artifact_location: Some(model::ArtifactLocation::uri(encode_path(path))),
                region: (!region.is_empty()).then_some(region),
                ..model::PhysicalLocation::default()
            }
        }
        Location::Url { url, parameter } => {
            let mut uri = encode(url, is_uri_char);
            if let Some(parameter) = parameter {
                uri.push('#');
                uri.push_str(&encode(parameter, is_fragment_char));
            }
            physical_uri(uri)
        }
        Location::Network { host, port } => {
            let host = encode(host, is_host_char);
            if host.contains(':') {
                physical_uri(format!("tcp://[{host}]:{port}"))
            } else {
                physical_uri(format!("tcp://{host}:{port}"))
            }
        }
        Location::ClusterObject {
            namespace,
            kind,
            name,
        } => physical_uri(format!(
            "k8s://{}/{}/{}",
            encode(namespace, is_segment_char),
            encode(kind, is_segment_char),
            encode(name, is_segment_char),
        )),
        Location::Artifact { path, offset } => model::PhysicalLocation {
            artifact_location: Some(model::ArtifactLocation::uri(encode_path(path))),
            address: offset.map(|offset| model::Address {
                absolute_address: Some(offset),
                ..model::Address::default()
            }),
            ..model::PhysicalLocation::default()
        },
        // `Location` is non-exhaustive: a kind added later is kept whole in
        // the hint, under an opaque URI.
        _ => physical_uri(format!("rune-finding:{}", location.kind())),
    };
    model::Location {
        physical_location: Some(physical),
        ..model::Location::default()
    }
}

/// The finding location for a SARIF location: the [`LOCATION_PROPERTY`]
/// hint when present and valid, else inferred from the physical location.
/// `None` when the location has neither a hint nor an artifact URI.
#[must_use]
pub fn from_sarif(location: &model::Location) -> Option<Location> {
    location
        .properties
        .get(LOCATION_PROPERTY)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .or_else(|| infer(location))
}

fn physical_uri(uri: String) -> model::PhysicalLocation {
    model::PhysicalLocation {
        artifact_location: Some(model::ArtifactLocation::uri(uri)),
        ..model::PhysicalLocation::default()
    }
}

/// The location the URI and region describe, ignoring any hint.
fn infer(location: &model::Location) -> Option<Location> {
    let physical = location.physical_location.as_ref()?;
    let uri = physical.artifact_location.as_ref()?.uri.as_deref()?;
    let scheme = scheme(uri).map(str::to_ascii_lowercase);
    let inferred = match scheme.as_deref() {
        Some("http" | "https" | "ws" | "wss") => Some(match uri.split_once('#') {
            Some((url, fragment)) => Location::Url {
                url: url.to_owned(),
                parameter: Some(decode(fragment)),
            },
            None => Location::url(uri),
        }),
        Some("tcp") => network(uri),
        Some("k8s") => cluster_object(uri),
        _ => None,
    };
    if inferred.is_some() {
        return inferred;
    }

    let path = match scheme.as_deref() {
        Some("file") => file_uri_path(uri),
        _ => decode(uri),
    };
    if let Some(address) = &physical.address
        && physical.region.is_none()
    {
        return Some(Location::artifact(path, address.absolute_address));
    }
    let region = physical.region.clone().unwrap_or_default();
    Some(Location::File {
        path,
        start_line: region.start_line,
        end_line: region.end_line,
        start_column: region.start_column,
        end_column: region.end_column,
        start_byte: region.byte_offset,
        end_byte: region
            .byte_offset
            .zip(region.byte_length)
            .and_then(|(offset, length)| offset.checked_add(length)),
        snippet: region.snippet.and_then(|snippet| snippet.text),
    })
}

/// `tcp://host:port` or `tcp://[v6:host]:port`.
fn network(uri: &str) -> Option<Location> {
    let rest = uri.get("tcp://".len()..)?;
    let (host, port) = rest.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    Some(Location::network(decode(host), port.parse().ok()?))
}

/// `k8s://namespace/kind/name`.
fn cluster_object(uri: &str) -> Option<Location> {
    let rest = uri.get("k8s://".len()..)?;
    let mut parts = rest.split('/');
    let (namespace, kind, name) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(Location::cluster_object(
        decode(namespace),
        decode(kind),
        decode(name),
    ))
}

/// The path of a `file:` URI: `file:///src/a.py` is `/src/a.py`,
/// `file:a.py` is `a.py`.
fn file_uri_path(uri: &str) -> String {
    let rest = uri.get("file:".len()..).unwrap_or_default();
    match rest.strip_prefix("//") {
        // An empty authority: `file:///abs/path`.
        Some(after) if after.starts_with('/') => decode(after),
        // A host (`file://server/share`) stays, as a UNC-style path, and
        // `file:a.py` has no authority at all.
        _ => decode(rest),
    }
}

/// The RFC 3986 scheme of `uri`, if it has one.
fn scheme(uri: &str) -> Option<&str> {
    let (scheme, _) = uri.split_once(':')?;
    let mut bytes = scheme.bytes();
    let first = bytes.next()?;
    (first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    .then_some(scheme)
}

/// Percent-encode a file path so that it is a relative URI reference that
/// reads back as the same path: `/` stays, `%`, `?`, `#`, spaces and
/// non-ASCII are encoded, and a `:` that would make the first segment look
/// like a scheme is encoded too.
fn encode_path(path: &str) -> String {
    let encoded = encode(path, is_path_char);
    // `C:/x` or `a:b/c` would read as a scheme: escape the colons of the
    // first segment (RFC 3986 §4.2).
    match encoded.split_once('/') {
        Some((first, rest)) if first.contains(':') => {
            format!("{}/{rest}", first.replace(':', "%3A"))
        }
        None if encoded.contains(':') => encoded.replace(':', "%3A"),
        _ => encoded,
    }
}

/// Percent-encode every byte of `text` that `keep` rejects.
fn encode(text: &str, keep: fn(u8) -> bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if keep(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    out
}

/// Decode `%XX` escapes. Malformed escapes stay as they are; bytes that do
/// not form UTF-8 are replaced.
fn decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).and_then(|b| hex_value(*b)),
                bytes.get(index + 2).and_then(|b| hex_value(*b)),
            )
        {
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned())
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 `unreserved` and `sub-delims`.
const fn is_plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

/// A path segment character other than `:` and `@` delimiters we escape.
const fn is_segment_char(byte: u8) -> bool {
    is_plain(byte) || byte == b'@'
}

const fn is_path_char(byte: u8) -> bool {
    is_plain(byte) || matches!(byte, b':' | b'@' | b'/')
}

const fn is_host_char(byte: u8) -> bool {
    is_plain(byte) || byte == b':'
}

const fn is_fragment_char(byte: u8) -> bool {
    is_plain(byte) || matches!(byte, b':' | b'@' | b'/' | b'?')
}

/// Any character that may appear somewhere in a URI, `%` included: only
/// spaces, controls, non-ASCII and the characters ``"<>\^`{|}`` are
/// encoded.
const fn is_uri_char(byte: u8) -> bool {
    is_plain(byte) || matches!(byte, b':' | b'@' | b'/' | b'?' | b'#' | b'[' | b']' | b'%')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(location: &model::Location) -> &str {
        location
            .physical_location
            .as_ref()
            .and_then(|physical| physical.artifact_location.as_ref())
            .and_then(|artifact| artifact.uri.as_deref())
            .unwrap()
    }

    fn round_trip(location: &Location) -> model::Location {
        let sarif = to_sarif(location);
        assert_eq!(from_sarif(&sarif).as_ref(), Some(location), "{sarif:?}");
        sarif
    }

    #[test]
    fn ordinary_locations_need_no_hint() {
        let cases = [
            (
                Location::url("https://shop.test/search?q=x").with_parameter("q"),
                "https://shop.test/search?q=x#q",
            ),
            (Location::url("https://shop.test/"), "https://shop.test/"),
            (
                Location::network("example.test", 443),
                "tcp://example.test:443",
            ),
            (Location::network("::1", 8443), "tcp://[::1]:8443"),
            (
                Location::cluster_object("prod", "Ingress", "web"),
                "k8s://prod/Ingress/web",
            ),
            (Location::file("src/app.py"), "src/app.py"),
            (
                Location::file("dir with space/ü.rs"),
                "dir%20with%20space/%C3%BC.rs",
            ),
            (Location::file("C:\\x.rs"), "C%3A%5Cx.rs"),
            (Location::file("100%#?.txt"), "100%25%23%3F.txt"),
            (Location::artifact("bin/app", Some(4096)), "bin/app"),
        ];
        for (location, expected) in cases {
            let sarif = round_trip(&location);
            assert_eq!(uri(&sarif), expected);
            assert!(sarif.properties.is_empty(), "{location:?}");
        }
    }

    #[test]
    fn file_regions() {
        let location = Location::file("src/db.py")
            .with_lines(42, 44)
            .with_columns(5, 61)
            .with_bytes(1200, 1256)
            .with_snippet("cursor.execute(q)");
        let sarif = round_trip(&location);
        assert!(sarif.properties.is_empty());
        let region = sarif.physical_location.unwrap().region.unwrap();
        assert_eq!(
            (
                region.start_line,
                region.end_line,
                region.start_column,
                region.end_column
            ),
            (Some(42), Some(44), Some(5), Some(61))
        );
        assert_eq!(
            (region.byte_offset, region.byte_length),
            (Some(1200), Some(56))
        );
        assert_eq!(
            region.snippet.unwrap().text.as_deref(),
            Some("cursor.execute(q)")
        );
    }

    #[test]
    fn ambiguous_locations_carry_a_hint() {
        let cases = [
            Location::url("https://shop.test/page#section"),
            Location::url("https://shop.test/a b"),
            Location::file("https://not-a-url.test/x"),
            Location::file("tcp://x:1"),
            Location::file("a.rs").with_lines(0, 0),
            Location::file("a.rs").with_bytes(9, 3),
            Location::artifact("bin/app", None),
            Location::cluster_object("n", "k", "a/b"),
            Location::network("bad host", 1),
        ];
        for location in cases {
            let sarif = round_trip(&location);
            // Ambiguity is case by case: some of these are lossless anyway.
            let _ = sarif;
        }
        let hinted = to_sarif(&Location::url("https://shop.test/page#section"));
        assert!(hinted.properties.get(LOCATION_PROPERTY).is_some());
        assert!(
            to_sarif_plain(&Location::url("https://shop.test/page#section"))
                .properties
                .is_empty()
        );
    }

    #[test]
    fn reads_other_tools_uris() {
        let read = |uri: &str| {
            from_sarif(&model::Location {
                physical_location: Some(physical_uri(uri.to_owned())),
                ..model::Location::default()
            })
        };
        assert_eq!(
            read("file:///src/app.py"),
            Some(Location::file("/src/app.py"))
        );
        assert_eq!(read("file:app.py"), Some(Location::file("app.py")));
        assert_eq!(
            read("file://server/share/a"),
            Some(Location::file("//server/share/a"))
        );
        assert_eq!(
            read("HTTP://x.test/#p"),
            Some(Location::url("HTTP://x.test/").with_parameter("p"))
        );
        assert_eq!(read("tcp://x"), Some(Location::file("tcp://x")));
        assert_eq!(read("k8s://a/b"), Some(Location::file("k8s://a/b")));
        assert_eq!(read("bad%zz%4"), Some(Location::file("bad%zz%4")));
        assert_eq!(read("%FF"), Some(Location::file("\u{FFFD}")));
        assert_eq!(from_sarif(&model::Location::default()), None);
    }

    #[test]
    fn invalid_hint_falls_back_to_the_uri() {
        let mut sarif = to_sarif(&Location::file("a.rs"));
        sarif
            .properties
            .insert(LOCATION_PROPERTY, serde_json::json!({"bogus": 1}));
        assert_eq!(from_sarif(&sarif), Some(Location::file("a.rs")));
    }
}
