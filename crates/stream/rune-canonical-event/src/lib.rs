//! A typed event envelope shared across streaming/ingest pipelines.
//!
//! Different sources — sensors, logs, telemetry, message queues — rarely agree on
//! field names or shapes. `CanonicalEvent` gives every ingest path one normalized
//! target to produce, and every downstream consumer (rules, aggregation, replay,
//! broadcast) one shape to read: `source_id`, `ts`, `seq`, `kind`, `payload`, an
//! optional `geo` position, and a free-form `meta` map.
//!
//! # Features
//!
//! - [`CanonicalEvent`] — the envelope: serializable, deserializable, and directly
//!   constructible when every field is already known.
//! - [`CanonicalEventBuilder`] — a builder that validates as it goes and reports the
//!   first violated invariant.
//! - [`CanonicalEvent::validate`] — the same invariants, runnable against an event
//!   that arrived over the wire (e.g. deserialized directly from JSON).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_canonical_event::CanonicalEvent;
//! use serde_json::json;
//!
//! let event = CanonicalEvent::builder("sensor-42", 1_700_000_000_000, 1, "temperature")
//!     .payload(json!({ "celsius": 21.5 }))
//!     .meta("unit", "pump-3")
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(event.source_id, "sensor-42");
//! assert_eq!(event.meta.get("unit").map(String::as_str), Some("pump-3"));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-canonical-event events.ndjson
//! cat events.ndjson | rune-canonical-event -
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// A geographic position attached to an event.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Geo {
    /// Latitude in degrees, must fall within `-90.0..=90.0`.
    pub lat: f64,
    /// Longitude in degrees, must fall within `-180.0..=180.0`.
    pub lon: f64,
}

/// The canonical event envelope.
///
/// Every field except `geo` is required. `payload` is an arbitrary JSON value so
/// the envelope stays domain-agnostic — a temperature reading, a GPS fix, and a
/// log line all fit through the same shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEvent {
    /// Identifier of the producing source (device id, sensor id, service name, ...).
    pub source_id: String,
    /// Event timestamp, milliseconds since the Unix epoch.
    pub ts: i64,
    /// Monotonically increasing per-source sequence number, used for reordering and dedup.
    pub seq: u64,
    /// Event type/kind, e.g. `"temperature"`, `"position"`, `"heartbeat"`.
    pub kind: String,
    /// Domain-specific payload.
    pub payload: serde_json::Value,
    /// Optional geographic position.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub geo: Option<Geo>,
    /// Free-form string metadata, e.g. tenant id, firmware version, ingest adapter name.
    #[serde(default)]
    pub meta: HashMap<String, String>,
}

/// An invariant violated by an event's fields.
#[derive(Debug, Clone, PartialEq)]
pub enum EventError {
    /// `source_id` was empty.
    EmptySourceId,
    /// `kind` was empty.
    EmptyKind,
    /// `ts` was negative.
    NegativeTimestamp(i64),
    /// `geo.lat` was outside `-90.0..=90.0`.
    LatitudeOutOfRange(f64),
    /// `geo.lon` was outside `-180.0..=180.0`.
    LongitudeOutOfRange(f64),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySourceId => write!(f, "source_id must not be empty"),
            Self::EmptyKind => write!(f, "kind must not be empty"),
            Self::NegativeTimestamp(ts) => write!(f, "ts must not be negative, got {ts}"),
            Self::LatitudeOutOfRange(lat) => {
                write!(f, "geo.lat must be within -90.0..=90.0, got {lat}")
            }
            Self::LongitudeOutOfRange(lon) => {
                write!(f, "geo.lon must be within -180.0..=180.0, got {lon}")
            }
        }
    }
}

impl std::error::Error for EventError {}

impl CanonicalEvent {
    /// Starts a [`CanonicalEventBuilder`] with the four required fields.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_canonical_event::CanonicalEvent;
    ///
    /// let event = CanonicalEvent::builder("gw-1", 0, 0, "heartbeat").build().unwrap();
    /// assert_eq!(event.kind, "heartbeat");
    /// ```
    pub fn builder(
        source_id: impl Into<String>,
        ts: i64,
        seq: u64,
        kind: impl Into<String>,
    ) -> CanonicalEventBuilder {
        CanonicalEventBuilder {
            source_id: source_id.into(),
            ts,
            seq,
            kind: kind.into(),
            payload: serde_json::Value::Null,
            geo: None,
            meta: HashMap::new(),
        }
    }

    /// Checks the same invariants the builder enforces, for events constructed by
    /// other means (e.g. `serde_json::from_str` directly into `CanonicalEvent`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_canonical_event::{CanonicalEvent, EventError};
    ///
    /// let bad: CanonicalEvent = serde_json::from_str(
    ///     r#"{"source_id":"","ts":0,"seq":0,"kind":"x","payload":null}"#
    /// ).unwrap();
    /// assert_eq!(bad.validate(), Err(EventError::EmptySourceId));
    /// ```
    pub fn validate(&self) -> Result<(), EventError> {
        if self.source_id.is_empty() {
            return Err(EventError::EmptySourceId);
        }
        if self.kind.is_empty() {
            return Err(EventError::EmptyKind);
        }
        if self.ts < 0 {
            return Err(EventError::NegativeTimestamp(self.ts));
        }
        if let Some(geo) = self.geo {
            if !(-90.0..=90.0).contains(&geo.lat) {
                return Err(EventError::LatitudeOutOfRange(geo.lat));
            }
            if !(-180.0..=180.0).contains(&geo.lon) {
                return Err(EventError::LongitudeOutOfRange(geo.lon));
            }
        }
        Ok(())
    }
}

/// Builder for [`CanonicalEvent`], returned by [`CanonicalEvent::builder`].
pub struct CanonicalEventBuilder {
    source_id: String,
    ts: i64,
    seq: u64,
    kind: String,
    payload: serde_json::Value,
    geo: Option<Geo>,
    meta: HashMap<String, String>,
}

impl CanonicalEventBuilder {
    /// Sets the payload. Defaults to `Value::Null` if never called.
    #[must_use]
    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    /// Attaches a geographic position.
    #[must_use]
    pub const fn geo(mut self, lat: f64, lon: f64) -> Self {
        self.geo = Some(Geo { lat, lon });
        self
    }

    /// Inserts one metadata key/value pair. May be called multiple times.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.meta.insert(key.into(), value.into());
        self
    }

    /// Validates the accumulated fields and produces a [`CanonicalEvent`].
    ///
    /// # Errors
    ///
    /// Returns the first [`EventError`] found; see [`CanonicalEvent::validate`] for the
    /// checked invariants.
    pub fn build(self) -> Result<CanonicalEvent, EventError> {
        let event = CanonicalEvent {
            source_id: self.source_id,
            ts: self.ts,
            seq: self.seq,
            kind: self.kind,
            payload: self.payload,
            geo: self.geo,
            meta: self.meta,
        };
        event.validate()?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_minimal_event() {
        let event = CanonicalEvent::builder("src-1", 100, 0, "ping")
            .build()
            .unwrap();
        assert_eq!(event.source_id, "src-1");
        assert_eq!(event.ts, 100);
        assert_eq!(event.seq, 0);
        assert_eq!(event.kind, "ping");
        assert_eq!(event.payload, serde_json::Value::Null);
        assert!(event.geo.is_none());
        assert!(event.meta.is_empty());
    }

    #[test]
    fn builds_full_event() {
        let event = CanonicalEvent::builder("src-1", 100, 7, "position")
            .payload(json!({ "speed": 12.3 }))
            .geo(60.17, 24.94)
            .meta("tenant", "acme")
            .meta("fw", "1.2.0")
            .build()
            .unwrap();

        assert_eq!(event.payload, json!({ "speed": 12.3 }));
        assert_eq!(
            event.geo,
            Some(Geo {
                lat: 60.17,
                lon: 24.94
            })
        );
        assert_eq!(event.meta.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(event.meta.get("fw").map(String::as_str), Some("1.2.0"));
    }

    #[test]
    fn rejects_empty_source_id() {
        let err = CanonicalEvent::builder("", 0, 0, "x").build().unwrap_err();
        assert_eq!(err, EventError::EmptySourceId);
    }

    #[test]
    fn rejects_empty_kind() {
        let err = CanonicalEvent::builder("src", 0, 0, "")
            .build()
            .unwrap_err();
        assert_eq!(err, EventError::EmptyKind);
    }

    #[test]
    fn rejects_negative_timestamp() {
        let err = CanonicalEvent::builder("src", -1, 0, "x")
            .build()
            .unwrap_err();
        assert_eq!(err, EventError::NegativeTimestamp(-1));
    }

    #[test]
    fn rejects_out_of_range_latitude() {
        let err = CanonicalEvent::builder("src", 0, 0, "x")
            .geo(91.0, 0.0)
            .build()
            .unwrap_err();
        assert_eq!(err, EventError::LatitudeOutOfRange(91.0));
    }

    #[test]
    fn rejects_out_of_range_longitude() {
        let err = CanonicalEvent::builder("src", 0, 0, "x")
            .geo(0.0, 200.0)
            .build()
            .unwrap_err();
        assert_eq!(err, EventError::LongitudeOutOfRange(200.0));
    }

    #[test]
    fn accepts_boundary_coordinates() {
        let event = CanonicalEvent::builder("src", 0, 0, "x")
            .geo(90.0, -180.0)
            .build()
            .unwrap();
        assert_eq!(
            event.geo,
            Some(Geo {
                lat: 90.0,
                lon: -180.0
            })
        );
    }

    #[test]
    fn round_trips_through_json() {
        let event = CanonicalEvent::builder("src-1", 42, 3, "temperature")
            .payload(json!({ "c": 21.5 }))
            .geo(1.0, 2.0)
            .meta("k", "v")
            .build()
            .unwrap();

        let json = serde_json::to_string(&event).unwrap();
        let parsed: CanonicalEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn deserialized_event_without_geo_or_meta_is_valid() {
        let event: CanonicalEvent =
            serde_json::from_str(r#"{"source_id":"s","ts":0,"seq":0,"kind":"k","payload":null}"#)
                .unwrap();
        assert!(event.validate().is_ok());
        assert!(event.geo.is_none());
        assert!(event.meta.is_empty());
    }
}
