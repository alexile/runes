//! Heuristic column/field-type detector for arbitrary CSV/JSON.
//!
//! Partner data dumps rarely come with a schema. `rune-schema-sniff` looks at a
//! column's name and its sampled values together and guesses what kind of field
//! it is — an identifier, a timestamp, a coordinate, a flag, a plain number, or
//! free text — along with a confidence score, so a human (or a downstream
//! pipeline) can decide what to trust without hand-inspecting every column.
//!
//! # Features
//!
//! - [`sniff_csv`] — guess one [`FieldGuess`] per CSV column from its header and
//!   sampled row values.
//! - [`sniff_json`] — same idea for a slice of JSON objects: the union of observed
//!   keys becomes the column set.
//!
//! Name and value evidence are combined: a column named `lat` whose values sit in
//! `-90.0..=90.0` scores higher than either signal alone would, while a purely
//! numeric column with no matching name (e.g. a temperature reading) is left as
//! [`FieldType::Numeric`] rather than mistaken for a coordinate — small numbers are
//! common and only reliably mean "coordinate" when the name says so.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_schema_sniff::{sniff_csv, FieldType};
//!
//! let headers = vec!["id".to_string(), "lat".to_string(), "lon".to_string()];
//! let rows = vec![
//!     vec!["u1".to_string(), "60.17".to_string(), "24.94".to_string()],
//!     vec!["u2".to_string(), "60.20".to_string(), "24.90".to_string()],
//! ];
//!
//! let guesses = sniff_csv(&headers, &rows);
//! assert_eq!(guesses[0].guessed_type, FieldType::Id);
//! assert_eq!(guesses[1].guessed_type, FieldType::Latitude);
//! assert_eq!(guesses[2].guessed_type, FieldType::Longitude);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-schema-sniff data.csv
//! rune-schema-sniff data.json
//! ```

use std::collections::HashMap;
use std::fmt;

/// The type a column is guessed to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Looks like a date/time value, by name or by falling in a plausible Unix-epoch range.
    Timestamp,
    /// Looks like an identifier column.
    Id,
    /// A plain number with no more specific signal.
    Numeric,
    /// A latitude coordinate.
    Latitude,
    /// A longitude coordinate.
    Longitude,
    /// A true/false flag.
    Boolean,
    /// Free text — the default when nothing more specific matches.
    Text,
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Timestamp => "timestamp",
            Self::Id => "id",
            Self::Numeric => "numeric",
            Self::Latitude => "latitude",
            Self::Longitude => "longitude",
            Self::Boolean => "boolean",
            Self::Text => "text",
        };
        f.write_str(label)
    }
}

/// One column's guessed type and how confident the guess is.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldGuess {
    /// The column/field name.
    pub name: String,
    /// The guessed type.
    pub guessed_type: FieldType,
    /// Confidence in the guess, in `0.0..=1.0`.
    pub confidence: f64,
}

/// Guesses a [`FieldType`] for each CSV column, given its header and every sampled
/// row's cell for that column.
///
/// Rows shorter than `headers` simply contribute fewer samples for the missing
/// trailing columns; this never panics on ragged input.
///
/// # Example
///
/// ```rust
/// use rune_schema_sniff::{sniff_csv, FieldType};
///
/// let headers = vec!["event_time".to_string(), "note".to_string()];
/// let rows = vec![vec!["1700000000000".to_string(), "ok".to_string()]];
///
/// let guesses = sniff_csv(&headers, &rows);
/// assert_eq!(guesses[0].guessed_type, FieldType::Timestamp);
/// assert_eq!(guesses[1].guessed_type, FieldType::Text);
/// ```
#[must_use]
pub fn sniff_csv(headers: &[String], rows: &[Vec<String>]) -> Vec<FieldGuess> {
    headers
        .iter()
        .enumerate()
        .map(|(col_idx, name)| {
            let values: Vec<&str> = rows
                .iter()
                .filter_map(|row| row.get(col_idx))
                .map(String::as_str)
                .collect();
            let (guessed_type, confidence) = analyze(name, &values);
            FieldGuess {
                name: name.clone(),
                guessed_type,
                confidence,
            }
        })
        .collect()
}

/// Guesses a [`FieldType`] for each key found across a slice of JSON objects.
///
/// Non-object rows are skipped. The column order follows first appearance across
/// `rows`. `null`, array, and object values are skipped when sampling (they carry
/// no scalar type signal); a column with no scalar samples at all falls back to
/// [`FieldType::Text`] with low confidence.
///
/// # Example
///
/// ```rust
/// use rune_schema_sniff::{sniff_json, FieldType};
/// use serde_json::json;
///
/// let rows = vec![
///     json!({ "id": "u1", "lat": 60.17, "lon": 24.94 }),
///     json!({ "id": "u2", "lat": 60.20, "lon": 24.90 }),
/// ];
///
/// let guesses = sniff_json(&rows);
/// assert_eq!(guesses[0].guessed_type, FieldType::Id);
/// assert_eq!(guesses[1].guessed_type, FieldType::Latitude);
/// assert_eq!(guesses[2].guessed_type, FieldType::Longitude);
/// ```
#[must_use]
pub fn sniff_json(rows: &[serde_json::Value]) -> Vec<FieldGuess> {
    let mut order: Vec<String> = Vec::new();
    let mut values: HashMap<String, Vec<String>> = HashMap::new();

    for row in rows {
        let serde_json::Value::Object(map) = row else {
            continue;
        };
        for (key, val) in map {
            let bucket = values.entry(key.clone()).or_insert_with(|| {
                order.push(key.clone());
                Vec::new()
            });
            if let Some(s) = json_value_to_string(val) {
                bucket.push(s);
            }
        }
    }

    order
        .into_iter()
        .map(|name| {
            let vals = values.remove(&name).unwrap_or_default();
            let val_refs: Vec<&str> = vals.iter().map(String::as_str).collect();
            let (guessed_type, confidence) = analyze(&name, &val_refs);
            FieldGuess {
                name,
                guessed_type,
                confidence,
            }
        })
        .collect()
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

fn name_hint(name: &str) -> Option<(FieldType, f64)> {
    let lower = name.to_lowercase();
    if lower.contains("timestamp")
        || lower.contains("time")
        || lower.contains("date")
        || lower.contains("ts")
    {
        Some((FieldType::Timestamp, 0.5))
    } else if lower.contains("uuid") || lower.contains("id") {
        Some((FieldType::Id, 0.5))
    } else if lower.contains("latitude") || lower.contains("lat") {
        Some((FieldType::Latitude, 0.5))
    } else if lower.contains("longitude") || lower.contains("lng") || lower.contains("lon") {
        Some((FieldType::Longitude, 0.5))
    } else {
        None
    }
}

fn try_parse_all_f64(values: &[&str]) -> Option<Vec<f64>> {
    let mut nums = Vec::with_capacity(values.len());
    for v in values {
        nums.push(v.trim().parse::<f64>().ok()?);
    }
    Some(nums)
}

fn is_all_boolean(values: &[&str]) -> bool {
    values.iter().all(|v| {
        let lower = v.trim().to_lowercase();
        lower == "true" || lower == "false"
    })
}

fn plausible_epoch(v: f64) -> bool {
    const SEC_MIN: f64 = 946_684_800.0; // 2000-01-01T00:00:00Z
    const SEC_MAX: f64 = 4_102_444_800.0; // 2100-01-01T00:00:00Z
    (SEC_MIN..=SEC_MAX).contains(&v) || (SEC_MIN * 1000.0..=SEC_MAX * 1000.0).contains(&v)
}

/// Combines name and value evidence into one `(FieldType, confidence)` guess.
///
/// Coordinate types are only ever guessed when the name hints at them and the
/// values fall in the matching range — a small numeric value alone (a percentage,
/// a temperature, a count) is not reliable evidence of a coordinate by itself.
fn analyze(name: &str, values: &[&str]) -> (FieldType, f64) {
    if values.is_empty() {
        return (FieldType::Text, 0.2);
    }

    let name_guess = name_hint(name);

    if let Some(nums) = try_parse_all_f64(values) {
        if let Some((FieldType::Id, name_conf)) = name_guess {
            return (FieldType::Id, f64::mul_add(name_conf, 0.5, 0.4).min(1.0));
        }

        let in_lat_range = nums.iter().all(|&v| (-90.0..=90.0).contains(&v));
        let in_lon_range = nums.iter().all(|&v| (-180.0..=180.0).contains(&v));
        let in_epoch_range = nums.iter().all(|&v| plausible_epoch(v));

        return match name_guess {
            Some((FieldType::Latitude, name_conf)) if in_lat_range => (
                FieldType::Latitude,
                f64::mul_add(name_conf, 0.5, 0.7).min(1.0),
            ),
            Some((FieldType::Longitude, name_conf)) if in_lon_range => (
                FieldType::Longitude,
                f64::mul_add(name_conf, 0.5, 0.65).min(1.0),
            ),
            Some((FieldType::Timestamp, name_conf)) if in_epoch_range => (
                FieldType::Timestamp,
                f64::mul_add(name_conf, 0.5, 0.7).min(1.0),
            ),
            _ if in_epoch_range => (FieldType::Timestamp, 0.65),
            _ => (FieldType::Numeric, 0.6),
        };
    }

    if is_all_boolean(values) {
        return (FieldType::Boolean, 0.85);
    }

    match name_guess {
        Some((t, c)) => (t, c),
        None => (FieldType::Text, 0.3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn id_column_from_string_values() {
        let headers = vec!["id".to_string()];
        let rows = vec![vec!["u1".to_string()], vec!["u2".to_string()]];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Id);
        assert!(guesses[0].confidence > 0.3);
    }

    #[test]
    fn lat_lon_pair_guessed_with_high_confidence() {
        let headers = vec!["lat".to_string(), "lon".to_string()];
        let rows = vec![
            vec!["60.17".to_string(), "24.94".to_string()],
            vec!["60.20".to_string(), "24.90".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Latitude);
        assert!(guesses[0].confidence > 0.8);
        assert_eq!(guesses[1].guessed_type, FieldType::Longitude);
        assert!(guesses[1].confidence > 0.8);
    }

    #[test]
    fn numeric_non_coordinate_column_is_numeric_not_latitude() {
        let headers = vec!["temperature_c".to_string()];
        let rows = vec![
            vec!["15.0".to_string()],
            vec!["22.5".to_string()],
            vec!["30.0".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Numeric);
    }

    #[test]
    fn epoch_millis_column_is_timestamp() {
        let headers = vec!["event_time".to_string()];
        let rows = vec![
            vec!["1700000000000".to_string()],
            vec!["1700000005000".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Timestamp);
    }

    #[test]
    fn epoch_seconds_without_matching_name_is_still_timestamp() {
        let headers = vec!["x".to_string()];
        let rows = vec![
            vec!["1700000000".to_string()],
            vec!["1700000500".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Timestamp);
    }

    #[test]
    fn boolean_looking_column() {
        let headers = vec!["active".to_string()];
        let rows = vec![
            vec!["true".to_string()],
            vec!["False".to_string()],
            vec!["TRUE".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Boolean);
        assert!(guesses[0].confidence > 0.5);
    }

    #[test]
    fn plain_text_column_defaults_to_text() {
        let headers = vec!["description".to_string()];
        let rows = vec![
            vec!["hello world".to_string()],
            vec!["another note".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Text);
    }

    #[test]
    fn json_entry_point_matches_csv_entry_point() {
        let headers = vec!["id".to_string(), "lat".to_string(), "lon".to_string()];
        let rows = vec![
            vec!["u1".to_string(), "60.17".to_string(), "24.94".to_string()],
            vec!["u2".to_string(), "60.20".to_string(), "24.90".to_string()],
        ];
        let csv_guesses = sniff_csv(&headers, &rows);

        let json_rows = vec![
            json!({ "id": "u1", "lat": 60.17, "lon": 24.94 }),
            json!({ "id": "u2", "lat": 60.20, "lon": 24.90 }),
        ];
        let json_guesses = sniff_json(&json_rows);

        assert_eq!(csv_guesses.len(), json_guesses.len());
        for (csv_guess, json_guess) in csv_guesses.iter().zip(json_guesses.iter()) {
            assert_eq!(csv_guess.name, json_guess.name);
            assert_eq!(csv_guess.guessed_type, json_guess.guessed_type);
        }
    }

    #[test]
    fn json_column_order_follows_first_appearance() {
        let rows = vec![json!({ "b": 1, "a": 2 }), json!({ "b": 3, "a": 4, "c": 5 })];
        let guesses = sniff_json(&rows);
        let names: Vec<&str> = guesses.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["b", "a", "c"]);
    }

    #[test]
    fn empty_column_falls_back_to_low_confidence_text() {
        let headers = vec!["mystery".to_string()];
        let rows: Vec<Vec<String>> = vec![];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses[0].guessed_type, FieldType::Text);
        assert!(guesses[0].confidence < 0.3);
    }

    #[test]
    fn ragged_rows_do_not_panic() {
        let headers = vec!["a".to_string(), "b".to_string()];
        let rows = vec![
            vec!["1".to_string()],
            vec!["2".to_string(), "x".to_string()],
        ];
        let guesses = sniff_csv(&headers, &rows);
        assert_eq!(guesses.len(), 2);
    }
}
