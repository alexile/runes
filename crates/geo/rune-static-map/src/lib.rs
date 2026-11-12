//! Build the query-parameter string for a generic static-map-image request
//! from a center point, zoom, image size, markers, and an optional polyline
//! overlay.
//!
//! This is a URL/params builder only — it makes no network calls and is not
//! tied to any one specific map provider's exact API. The parameter names
//! (`center`, `zoom`, `size`, `markers`, `path`) are the generic shape shared
//! by most static-map-image endpoints; adapting the output to a particular
//! provider's exact naming is left to the caller.
//!
//! # Features
//!
//! - [`StaticMapRequest`] — a fluent builder for center, zoom, size,
//!   markers, and an already-encoded polyline overlay.
//! - [`StaticMapRequest::build_query_string`] — assembles a URL-encoded
//!   `key=value&...` query string from the builder's state.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_static_map::StaticMapRequest;
//!
//! let query = StaticMapRequest::new((60.1699, 24.9384), 12, (600, 400))
//!     .add_marker(60.1699, 24.9384, "red")
//!     .with_polyline("_p~iF~ps|U_ulLnnqC")
//!     .build_query_string();
//!
//! assert!(query.contains("center=60.1699%2C24.9384"));
//! assert!(query.contains("zoom=12"));
//! assert!(query.contains("size=600x400"));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-static-map --center 60.1699,24.9384 --zoom 12 --size 600x400 --marker 60.1699,24.9384,red
//! ```

use std::fmt::Write as _;

/// A single marker: a coordinate plus a provider-agnostic label or color
/// string (e.g. `"red"`, `"#FF0000"`, `"A"`).
#[derive(Debug, Clone, PartialEq)]
struct Marker {
    lat: f64,
    lon: f64,
    label_or_color: String,
}

/// Builds the query-parameter string for a static-map-image request.
///
/// Construct with [`StaticMapRequest::new`], add markers and/or a polyline
/// via the fluent `add_marker`/`with_polyline` methods, then call
/// [`StaticMapRequest::build_query_string`] to get the finished, URL-encoded
/// parameter string.
#[derive(Debug, Clone, PartialEq)]
pub struct StaticMapRequest {
    center: (f64, f64),
    zoom: u8,
    size: (u32, u32),
    markers: Vec<Marker>,
    polyline: Option<String>,
}

impl StaticMapRequest {
    /// Starts a new request for a map centered at `(lat, lon)`, at the given
    /// `zoom` level, rendered at `(width, height)` pixels.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_static_map::StaticMapRequest;
    ///
    /// let req = StaticMapRequest::new((60.1699, 24.9384), 12, (600, 400));
    /// ```
    #[must_use]
    pub const fn new(center: (f64, f64), zoom: u8, size: (u32, u32)) -> Self {
        Self {
            center,
            zoom,
            size,
            markers: Vec::new(),
            polyline: None,
        }
    }

    /// Adds a marker at `(lat, lon)` with a provider-agnostic label or color
    /// string. Can be called multiple times; markers are emitted in the
    /// `markers` parameter in the order they were added.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_static_map::StaticMapRequest;
    ///
    /// let req = StaticMapRequest::new((0.0, 0.0), 10, (300, 300))
    ///     .add_marker(1.0, 2.0, "red")
    ///     .add_marker(3.0, 4.0, "blue");
    /// ```
    #[must_use]
    pub fn add_marker(mut self, lat: f64, lon: f64, label_or_color: &str) -> Self {
        self.markers.push(Marker {
            lat,
            lon,
            label_or_color: label_or_color.to_string(),
        });
        self
    }

    /// Attaches an already-encoded polyline as the `path` overlay. This
    /// crate does not encode polylines itself — pass the output of a
    /// dedicated polyline encoder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_static_map::StaticMapRequest;
    ///
    /// let req = StaticMapRequest::new((0.0, 0.0), 10, (300, 300))
    ///     .with_polyline("_p~iF~ps|U_ulLnnqC");
    /// ```
    #[must_use]
    pub fn with_polyline(mut self, encoded: &str) -> Self {
        self.polyline = Some(encoded.to_string());
        self
    }

    /// Builds the finished, URL-encoded `key=value&...` query string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_static_map::StaticMapRequest;
    ///
    /// let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100)).build_query_string();
    /// assert_eq!(query, "center=0%2C0&zoom=5&size=100x100");
    /// ```
    #[must_use]
    pub fn build_query_string(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!(
            "center={}",
            percent_encode(&format_coord(self.center))
        ));
        parts.push(format!("zoom={}", self.zoom));
        parts.push(format!(
            "size={}",
            percent_encode(&format!("{}x{}", self.size.0, self.size.1))
        ));

        if !self.markers.is_empty() {
            let joined = self
                .markers
                .iter()
                .map(|m| {
                    format!(
                        "{},{},{}",
                        format_num(m.lat),
                        format_num(m.lon),
                        m.label_or_color
                    )
                })
                .collect::<Vec<_>>()
                .join("|");
            parts.push(format!("markers={}", percent_encode(&joined)));
        }

        if let Some(polyline) = &self.polyline {
            parts.push(format!("path={}", percent_encode(polyline)));
        }

        parts.join("&")
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
#[allow(clippy::float_cmp, reason = "exact comparison is intended here")]
fn format_num(n: f64) -> String {
    if n == n.trunc() {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

fn format_coord(coord: (f64, f64)) -> String {
    format!("{},{}", format_num(coord.0), format_num(coord.1))
}

/// Percent-encodes a string per RFC 3986: only unreserved characters
/// (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`) pass through unchanged;
/// everything else is encoded as `%XX` uppercase hex.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                let _ = write!(out, "{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_string_with_no_markers_or_polyline() {
        let query = StaticMapRequest::new((60.0, 24.0), 12, (600, 400)).build_query_string();
        assert_eq!(query, "center=60%2C24&zoom=12&size=600x400");
    }

    #[test]
    fn center_uses_full_precision_for_non_integer_coordinates() {
        let query = StaticMapRequest::new((60.1699, 24.9384), 12, (600, 400)).build_query_string();
        assert!(query.contains("center=60.1699%2C24.9384"), "{query}");
    }

    #[test]
    fn single_marker_is_included() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100))
            .add_marker(1.0, 2.0, "red")
            .build_query_string();
        assert!(query.contains("markers=1%2C2%2Cred"), "{query}");
    }

    #[test]
    fn multiple_markers_are_pipe_joined_and_encoded() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100))
            .add_marker(1.0, 2.0, "red")
            .add_marker(3.0, 4.0, "blue")
            .build_query_string();
        assert!(
            query.contains("markers=1%2C2%2Cred%7C3%2C4%2Cblue"),
            "{query}"
        );
    }

    #[test]
    fn hash_in_color_hex_code_is_percent_encoded() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100))
            .add_marker(1.0, 2.0, "#FF00FF")
            .build_query_string();
        assert!(query.contains("markers=1%2C2%2C%23FF00FF"), "{query}");
        assert!(
            !query.contains('#'),
            "raw # must not survive encoding: {query}"
        );
    }

    #[test]
    fn space_in_label_is_percent_encoded() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100))
            .add_marker(1.0, 2.0, "New York")
            .build_query_string();
        assert!(query.contains("New%20York"), "{query}");
        assert!(
            !query.contains(' '),
            "raw space must not survive encoding: {query}"
        );
    }

    #[test]
    fn polyline_is_attached_as_percent_encoded_path_param() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100))
            .with_polyline("_p~iF~ps|U_ulLnnqC")
            .build_query_string();
        assert!(query.contains("path="), "{query}");
        assert!(
            !query.contains("path=_p~iF~ps|U"),
            "pipe must be encoded: {query}"
        );
        assert!(query.contains("path=_p~iF~ps%7CU_ulLnnqC"), "{query}");
    }

    #[test]
    fn no_polyline_means_no_path_param() {
        let query = StaticMapRequest::new((0.0, 0.0), 5, (100, 100)).build_query_string();
        assert!(!query.contains("path="));
    }

    #[test]
    fn percent_encode_leaves_unreserved_characters_untouched() {
        assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
    }

    #[test]
    fn percent_encode_escapes_reserved_and_unicode_bytes() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("#"), "%23");
        assert_eq!(percent_encode(","), "%2C");
    }
}
