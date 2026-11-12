//! Encode point, line, and polygon features as Mapbox Vector Tile (MVT v2)
//! protobuf bytes.
//!
//! This is a self-contained protobuf encoder: there is no dependency on a
//! general-purpose protobuf crate. It implements exactly the wire format the
//! MVT spec needs — varints, zigzag-encoded deltas, and length-delimited
//! fields — plus the MVT-specific pieces on top: command/parameter-encoded
//! geometries and a per-layer key/value tag dictionary that feature
//! properties are interned into and referenced by index.
//!
//! # Features
//!
//! - [`Layer`] — a named layer with a tile extent, built up feature by
//!   feature via [`Layer::add_point_feature`], [`Layer::add_line_feature`],
//!   and [`Layer::add_polygon_feature`]. Keys and values are interned
//!   automatically as features are added.
//! - [`Tile`] — a collection of layers; [`Tile::encode`] produces the final
//!   raw protobuf bytes for the tile.
//! - [`Value`] — the property-value type: string, float, double, signed or
//!   unsigned integer, or bool.
//! - [`decode`] — a validating decoder for untrusted tile bytes, returning
//!   [`DecodedTile`] / [`DecodedLayer`] / [`DecodedFeature`].
//!
//! The wire format is the [Mapbox Vector Tile specification 2.1]. The
//! encoder emits only spec-valid geometry: consecutive duplicate vertices
//! are dropped (a `LineTo` may not be zero-length, §4.3.3.2), and features
//! whose geometry degenerates (a line with fewer than two distinct
//! vertices, a polygon with no ring of non-zero area) are not added. Ring
//! winding order (§4.3.4.4) and unique layer names (§4.1) are the caller's
//! responsibility.
//!
//! [Mapbox Vector Tile specification 2.1]: https://github.com/mapbox/vector-tile-spec/tree/master/2.1
//!
//! Coordinates passed to the feature builders are tile-local integers in
//! `0..extent`, per the MVT contract — projecting real-world coordinates
//! into that grid is the caller's job.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_mvt::{Layer, Tile, Value};
//!
//! let mut layer = Layer::new("poi");
//! layer.add_point_feature(100, 200, &[("name", Value::String("cafe".into()))]);
//! layer.add_line_feature(&[(0, 0), (100, 0), (100, 100)], &[]);
//! layer.add_polygon_feature(
//!     &[vec![(0, 0), (100, 0), (100, 100), (0, 100)]],
//!     &[("kind", Value::String("building".into()))],
//! );
//!
//! let mut tile = Tile::new();
//! tile.add_layer(layer);
//! let bytes = tile.encode();
//! assert!(!bytes.is_empty());
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-mvt --layer poi --extent 4096 --output tile.mvt 100,200 300,400
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decode;
mod varint;

pub use decode::{DecodedFeature, DecodedLayer, DecodedTile, GeometryType, MvtError, decode};
use varint::{
    encode_varint, write_fixed32_field, write_fixed64_field, write_length_delimited, write_tag,
    write_varint_field, zigzag_encode, zigzag_encode_i64,
};

const LAYER_VERSION: u64 = 2;

/// A feature property value.
///
/// Maps onto the MVT `Value` message's `string_value`, `float_value`,
/// `double_value`, `sint_value` (for [`Value::Int`], zigzag-encoded),
/// `uint_value` and `bool_value` variants. The decoder also reads
/// `int_value` into [`Value::Int`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// A UTF-8 string value.
    String(String),
    /// A 32-bit floating point value.
    Float(f32),
    /// A 64-bit floating point value.
    Double(f64),
    /// A signed 64-bit integer value.
    Int(i64),
    /// An unsigned 64-bit integer value.
    UInt(u64),
    /// A boolean value.
    Bool(bool),
}

impl Value {
    /// Whether two values encode to the same bytes. Unlike `==`, doubles
    /// compare by bit pattern, so `0.0` and `-0.0` stay distinct and one NaN
    /// matches another with the same bits.
    fn same_encoding(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Double(a), Self::Double(b)) => a.to_bits() == b.to_bits(),
            (Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
            _ => self == other,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::String(s) => write_length_delimited(1, s.as_bytes(), &mut buf),
            Self::Float(f) => write_fixed32_field(2, *f, &mut buf),
            Self::Double(d) => write_fixed64_field(3, *d, &mut buf),
            Self::UInt(u) => write_varint_field(5, *u, &mut buf),
            Self::Int(i) => {
                write_tag(6, 0, &mut buf);
                encode_varint(zigzag_encode_i64(*i), &mut buf);
            }
            Self::Bool(b) => write_varint_field(7, u64::from(*b), &mut buf),
        }
        buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeomType {
    Point = 1,
    LineString = 2,
    Polygon = 3,
}

struct Feature {
    geom_type: GeomType,
    geometry: Vec<u32>,
    tags: Vec<u32>,
}

impl Feature {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if !self.tags.is_empty() {
            let mut packed = Vec::new();
            for &t in &self.tags {
                encode_varint(u64::from(t), &mut packed);
            }
            write_length_delimited(2, &packed, &mut buf);
        }
        write_varint_field(3, self.geom_type as u64, &mut buf);
        if !self.geometry.is_empty() {
            let mut packed = Vec::new();
            for &g in &self.geometry {
                encode_varint(u64::from(g), &mut packed);
            }
            write_length_delimited(4, &packed, &mut buf);
        }
        buf
    }
}

const fn command_integer(id: u32, count: u32) -> u32 {
    (id & 0x7) | (count << 3)
}

fn encode_point_geometry(x: i32, y: i32) -> Vec<u32> {
    vec![command_integer(1, 1), zigzag_encode(x), zigzag_encode(y)]
}

/// Drops consecutive duplicate vertices: a zero-length `LineTo` is invalid
/// (MVT 2.1 §4.3.3.2).
fn dedup_vertices(points: &[(i32, i32)]) -> Vec<(i32, i32)> {
    let mut out = points.to_vec();
    out.dedup();
    out
}

/// Twice the signed area of a ring (surveyor's formula, §4.3.4.4), exact.
fn doubled_area(ring: &[(i32, i32)]) -> i128 {
    ring.iter()
        .zip(ring.iter().cycle().skip(1))
        .map(|(&(x0, y0), &(x1, y1))| {
            i128::from(x0) * i128::from(y1) - i128::from(x1) * i128::from(y0)
        })
        .sum()
}

/// The vertices a ring is encoded with: consecutive duplicates and an
/// explicit closing vertex dropped. `None` for a ring that cannot be
/// encoded: fewer than three distinct vertices or zero area.
fn normalize_ring(ring: &[(i32, i32)]) -> Option<Vec<(i32, i32)>> {
    let mut pts = dedup_vertices(ring);
    if pts.len() > 1 && pts.first() == pts.last() {
        pts.pop();
    }
    (pts.len() >= 3 && doubled_area(&pts) != 0).then_some(pts)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
// Deltas between consecutive vertices use wrapping arithmetic: MVT decoders
// accumulate them in 32-bit integers, so a wrapped delta still decodes to the
// exact vertex, and no pair of `i32` coordinates can overflow the encoder.
fn encode_line_geometry(points: &[(i32, i32)]) -> Vec<u32> {
    let mut geom = Vec::new();
    let points = dedup_vertices(points);
    // A LineString needs a LineTo with a count of at least one (§4.3.4.3).
    if points.len() < 2 {
        return geom;
    }
    let (mut cx, mut cy) = (0i32, 0i32);
    let (x0, y0) = points[0];
    geom.push(command_integer(1, 1));
    geom.push(zigzag_encode(x0.wrapping_sub(cx)));
    geom.push(zigzag_encode(y0.wrapping_sub(cy)));
    cx = x0;
    cy = y0;
    if points.len() > 1 {
        geom.push(command_integer(2, (points.len() - 1) as u32));
        for &(x, y) in &points[1..] {
            geom.push(zigzag_encode(x.wrapping_sub(cx)));
            geom.push(zigzag_encode(y.wrapping_sub(cy)));
            cx = x;
            cy = y;
        }
    }
    geom
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
fn encode_polygon_geometry(rings: &[Vec<(i32, i32)>]) -> Vec<u32> {
    let mut geom = Vec::new();
    let (mut cx, mut cy) = (0i32, 0i32);
    for ring in rings {
        let Some(pts) = normalize_ring(ring) else {
            continue;
        };
        let (x0, y0) = pts[0];
        geom.push(command_integer(1, 1));
        geom.push(zigzag_encode(x0.wrapping_sub(cx)));
        geom.push(zigzag_encode(y0.wrapping_sub(cy)));
        cx = x0;
        cy = y0;
        geom.push(command_integer(2, (pts.len() - 1) as u32));
        for &(x, y) in &pts[1..] {
            geom.push(zigzag_encode(x.wrapping_sub(cx)));
            geom.push(zigzag_encode(y.wrapping_sub(cy)));
            cx = x;
            cy = y;
        }
        // ClosePath does not move the cursor (MVT 2.1, section 4.3.3.3): the
        // next ring's MoveTo is relative to this ring's last vertex.
        geom.push(command_integer(7, 1));
    }
    geom
}

/// A single named layer within a [`Tile`].
///
/// Feature properties passed to the `add_*_feature` methods are interned
/// into per-layer `keys`/`values` arrays as they are added, and each
/// feature stores only the indices into those arrays — this is the MVT tag
/// dictionary scheme, and it's what lets many features share the same key
/// or value without repeating the bytes.
pub struct Layer {
    name: String,
    extent: u32,
    keys: Vec<String>,
    values: Vec<Value>,
    features: Vec<Feature>,
}

impl Layer {
    /// Creates an empty layer with the default extent of 4096.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::Layer;
    ///
    /// let layer = Layer::new("roads");
    /// ```
    pub fn new(name: impl Into<String>) -> Self {
        Self::with_extent(name, 4096)
    }

    /// Creates an empty layer with a custom extent.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::Layer;
    ///
    /// let layer = Layer::with_extent("roads", 8192);
    /// ```
    pub fn with_extent(name: impl Into<String>, extent: u32) -> Self {
        Self {
            name: name.into(),
            extent,
            keys: Vec::new(),
            values: Vec::new(),
            features: Vec::new(),
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn intern_key(&mut self, key: &str) -> u32 {
        if let Some(pos) = self.keys.iter().position(|k| k == key) {
            pos as u32
        } else {
            self.keys.push(key.to_string());
            (self.keys.len() - 1) as u32
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn intern_value(&mut self, value: &Value) -> u32 {
        if let Some(pos) = self.values.iter().position(|v| v.same_encoding(value)) {
            pos as u32
        } else {
            self.values.push(value.clone());
            (self.values.len() - 1) as u32
        }
    }

    fn intern_tags(&mut self, tags: &[(&str, Value)]) -> Vec<u32> {
        let mut out = Vec::with_capacity(tags.len() * 2);
        for (key, value) in tags {
            out.push(self.intern_key(key));
            out.push(self.intern_value(value));
        }
        out
    }

    /// Adds a single-point feature at tile-local coordinates `(x, y)`.
    ///
    /// Always returns `true` (a point is never degenerate); the return value
    /// matches the other `add_*_feature` methods.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::{Layer, Value};
    ///
    /// let mut layer = Layer::new("poi");
    /// layer.add_point_feature(10, 20, &[("name", Value::String("cafe".into()))]);
    /// ```
    pub fn add_point_feature(&mut self, x: i32, y: i32, tags: &[(&str, Value)]) -> bool {
        self.push_feature(GeomType::Point, encode_point_geometry(x, y), tags)
    }

    /// Adds a feature unless its geometry is empty, interning tags only
    /// for features that are kept.
    fn push_feature(
        &mut self,
        geom_type: GeomType,
        geometry: Vec<u32>,
        tags: &[(&str, Value)],
    ) -> bool {
        if geometry.is_empty() {
            return false;
        }
        let tags = self.intern_tags(tags);
        self.features.push(Feature {
            geom_type,
            geometry,
            tags,
        });
        true
    }

    /// Adds a line feature through the given tile-local points, in order.
    ///
    /// Consecutive duplicate points are dropped. Returns `false`, and adds
    /// nothing, if fewer than two distinct points remain.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::Layer;
    ///
    /// let mut layer = Layer::new("roads");
    /// layer.add_line_feature(&[(0, 0), (100, 0), (100, 100)], &[]);
    /// ```
    pub fn add_line_feature(&mut self, points: &[(i32, i32)], tags: &[(&str, Value)]) -> bool {
        self.push_feature(GeomType::LineString, encode_line_geometry(points), tags)
    }

    /// Adds a polygon feature from one or more rings of tile-local points.
    ///
    /// Each ring should list its vertices in order; a duplicated closing
    /// point (last point equal to the first) is tolerated and dropped, since
    /// MVT geometries close rings implicitly via the `ClosePath` command.
    /// Consecutive duplicate vertices are dropped, and rings with fewer than
    /// 3 distinct vertices or zero area are skipped. Returns `false`, and
    /// adds nothing, if no ring remains. Winding order is not changed: per
    /// MVT 2.1 §4.3.4.4 exterior rings must have positive area in tile
    /// coordinates (clockwise with y pointing down) and holes negative.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::{Layer, Value};
    ///
    /// let mut layer = Layer::new("buildings");
    /// layer.add_polygon_feature(
    ///     &[vec![(0, 0), (100, 0), (100, 100), (0, 100)]],
    ///     &[("kind", Value::String("building".into()))],
    /// );
    /// ```
    pub fn add_polygon_feature(
        &mut self,
        rings: &[Vec<(i32, i32)>],
        tags: &[(&str, Value)],
    ) -> bool {
        self.push_feature(GeomType::Polygon, encode_polygon_geometry(rings), tags)
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_length_delimited(1, self.name.as_bytes(), &mut buf);
        for feature in &self.features {
            write_length_delimited(2, &feature.encode(), &mut buf);
        }
        for key in &self.keys {
            write_length_delimited(3, key.as_bytes(), &mut buf);
        }
        for value in &self.values {
            write_length_delimited(4, &value.encode(), &mut buf);
        }
        write_varint_field(5, u64::from(self.extent), &mut buf);
        write_varint_field(15, LAYER_VERSION, &mut buf);
        buf
    }
}

/// A Mapbox Vector Tile: a collection of [`Layer`]s.
#[derive(Default)]
pub struct Tile {
    layers: Vec<Layer>,
}

impl Tile {
    /// Creates an empty tile.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::Tile;
    ///
    /// let tile = Tile::new();
    /// assert!(tile.encode().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a layer to the tile.
    pub fn add_layer(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Encodes the tile into raw MVT protobuf bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_mvt::{Layer, Tile};
    ///
    /// let mut tile = Tile::new();
    /// tile.add_layer(Layer::new("empty"));
    /// let bytes = tile.encode();
    /// assert!(!bytes.is_empty());
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for layer in &self.layers {
            write_length_delimited(3, &layer.encode(), &mut buf);
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::{decode_varint, iter_fields, zigzag_decode, zigzag_decode_i64};

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn decode_packed_varints(bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let (v, n) = decode_varint(&bytes[pos..]);
            out.push(v as u32);
            pos += n;
        }
        out
    }

    fn replay_geometry(ints: &[u32]) -> Vec<Vec<(i32, i32)>> {
        let mut paths: Vec<Vec<(i32, i32)>> = Vec::new();
        let (mut cx, mut cy) = (0i32, 0i32);
        let mut i = 0;
        while i < ints.len() {
            let cmd_int = ints[i];
            i += 1;
            let id = cmd_int & 0x7;
            let count = cmd_int >> 3;
            match id {
                1 => {
                    let mut path = Vec::new();
                    for _ in 0..count {
                        cx = cx.wrapping_add(zigzag_decode(ints[i]));
                        cy = cy.wrapping_add(zigzag_decode(ints[i + 1]));
                        i += 2;
                        path.push((cx, cy));
                    }
                    paths.push(path);
                }
                2 => {
                    let path = paths.last_mut().expect("LineTo without a preceding MoveTo");
                    for _ in 0..count {
                        cx = cx.wrapping_add(zigzag_decode(ints[i]));
                        cy = cy.wrapping_add(zigzag_decode(ints[i + 1]));
                        i += 2;
                        path.push((cx, cy));
                    }
                }
                // ClosePath leaves the cursor where it is (spec 4.3.3.3).
                7 => {}
                other => panic!("unknown geometry command id {other}"),
            }
        }
        paths
    }

    fn decode_value(bytes: &[u8]) -> Value {
        for f in iter_fields(bytes) {
            match f.number {
                1 => return Value::String(String::from_utf8(f.bytes.to_vec()).unwrap()),
                3 => {
                    let arr: [u8; 8] = f.bytes.try_into().unwrap();
                    return Value::Double(f64::from_le_bytes(arr));
                }
                6 => return Value::Int(zigzag_decode_i64(f.varint)),
                7 => return Value::Bool(f.varint != 0),
                _ => {}
            }
        }
        panic!("no recognized value field in {bytes:?}");
    }

    struct DecodedFeature {
        tags: Vec<u32>,
        geom_type: u32,
        geometry: Vec<u32>,
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn decode_feature(bytes: &[u8]) -> DecodedFeature {
        let mut tags = Vec::new();
        let mut geom_type = 0u32;
        let mut geometry = Vec::new();
        for f in iter_fields(bytes) {
            match f.number {
                2 => tags = decode_packed_varints(f.bytes),
                3 => geom_type = f.varint as u32,
                4 => geometry = decode_packed_varints(f.bytes),
                _ => {}
            }
        }
        DecodedFeature {
            tags,
            geom_type,
            geometry,
        }
    }

    struct DecodedLayer {
        name: String,
        extent: u32,
        version: u32,
        keys: Vec<String>,
        values: Vec<Value>,
        features: Vec<DecodedFeature>,
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn decode_layer(bytes: &[u8]) -> DecodedLayer {
        let mut name = String::new();
        let mut extent = 0u32;
        let mut version = 0u32;
        let mut keys = Vec::new();
        let mut values = Vec::new();
        let mut features = Vec::new();
        for f in iter_fields(bytes) {
            match f.number {
                1 => name = String::from_utf8(f.bytes.to_vec()).unwrap(),
                2 => features.push(decode_feature(f.bytes)),
                3 => keys.push(String::from_utf8(f.bytes.to_vec()).unwrap()),
                4 => values.push(decode_value(f.bytes)),
                5 => extent = f.varint as u32,
                15 => version = f.varint as u32,
                _ => {}
            }
        }
        DecodedLayer {
            name,
            extent,
            version,
            keys,
            values,
            features,
        }
    }

    fn decode_tile_layers(bytes: &[u8]) -> Vec<DecodedLayer> {
        iter_fields(bytes)
            .into_iter()
            .filter(|f| f.number == 3)
            .map(|f| decode_layer(f.bytes))
            .collect()
    }

    #[test]
    fn point_feature_round_trips_geometry_and_tags() {
        let mut layer = Layer::new("poi");
        layer.add_point_feature(10, 20, &[("name", Value::String("cafe".into()))]);

        let mut tile = Tile::new();
        tile.add_layer(layer);
        let bytes = tile.encode();

        let layers = decode_tile_layers(&bytes);
        assert_eq!(layers.len(), 1);
        let layer = &layers[0];
        assert_eq!(layer.name, "poi");
        assert_eq!(layer.extent, 4096);
        assert_eq!(layer.version, 2);

        assert_eq!(layer.features.len(), 1);
        let feature = &layer.features[0];
        assert_eq!(feature.geom_type, 1);

        let paths = replay_geometry(&feature.geometry);
        assert_eq!(paths, vec![vec![(10, 20)]]);

        assert_eq!(feature.tags, vec![0, 0]);
        assert_eq!(layer.keys[0], "name");
        assert_eq!(layer.values[0], Value::String("cafe".into()));
    }

    #[test]
    fn line_feature_round_trips_geometry() {
        let mut layer = Layer::new("roads");
        layer.add_line_feature(&[(0, 0), (100, 0), (100, 100)], &[]);

        let bytes = layer.encode();
        let decoded = decode_layer(&bytes);
        let feature = &decoded.features[0];
        assert_eq!(feature.geom_type, 2);

        let paths = replay_geometry(&feature.geometry);
        assert_eq!(paths, vec![vec![(0, 0), (100, 0), (100, 100)]]);
    }

    #[test]
    fn polygon_feature_closes_ring_and_drops_duplicate_closing_point() {
        let mut layer = Layer::new("buildings");
        layer.add_polygon_feature(
            &[vec![(0, 0), (100, 0), (100, 100), (0, 100), (0, 0)]],
            &[("kind", Value::String("building".into()))],
        );

        let bytes = layer.encode();
        let decoded = decode_layer(&bytes);
        let feature = &decoded.features[0];
        assert_eq!(feature.geom_type, 3);

        let paths = replay_geometry(&feature.geometry);
        assert_eq!(paths, vec![vec![(0, 0), (100, 0), (100, 100), (0, 100)]]);
    }

    // Regression: a polygon whose rings were all degenerate, or a
    // line with fewer than two points, was encoded with an empty (or
    // MoveTo-only) geometry, which MVT 2.1 §4.3.4 forbids. Such features
    // are now not added, and their tags are not interned.
    #[test]
    fn degenerate_features_are_not_added() {
        let mut layer = Layer::new("buildings");
        let tags = [("k", Value::Bool(true))];
        assert!(!layer.add_polygon_feature(&[vec![(0, 0), (1, 1)]], &tags));
        assert!(!layer.add_polygon_feature(&[], &tags));
        assert!(!layer.add_line_feature(&[], &tags));
        assert!(!layer.add_line_feature(&[(5, 5)], &tags));
        assert!(!layer.add_line_feature(&[(5, 5), (5, 5)], &tags));
        assert!(layer.features.is_empty());
        assert!(layer.keys.is_empty() && layer.values.is_empty());
        assert!(layer.add_point_feature(0, 0, &[]));
        assert_eq!(decode_layer(&layer.encode()).features.len(), 1);
    }

    // Regression: consecutive duplicate vertices were encoded as
    // zero-length LineTo pairs, which MVT 2.1 §4.3.3.2 forbids.
    #[test]
    fn duplicate_vertices_are_dropped() {
        let mut layer = Layer::new("l");
        assert!(layer.add_line_feature(&[(0, 0), (0, 0), (3, 4), (3, 4), (6, 0)], &[]));
        assert!(layer.add_polygon_feature(
            &[vec![
                (0, 0),
                (0, 0),
                (10, 0),
                (10, 10),
                (10, 10),
                (0, 10),
                (0, 0)
            ]],
            &[]
        ));
        let decoded = decode_layer(&layer.encode());
        assert_eq!(
            replay_geometry(&decoded.features[0].geometry),
            [vec![(0, 0), (3, 4), (6, 0)]]
        );
        assert_eq!(
            replay_geometry(&decoded.features[1].geometry),
            [vec![(0, 0), (10, 0), (10, 10), (0, 10)]]
        );
        for feature in &decoded.features {
            for path in replay_geometry(&feature.geometry) {
                assert!(path.windows(2).all(|p| p[0] != p[1]), "zero-length LineTo");
            }
        }
    }

    // Regression: a ring of three or more collinear vertices has zero
    // area, so it is neither an exterior nor an interior ring (§4.3.4.4).
    #[test]
    fn zero_area_rings_are_skipped() {
        let mut layer = Layer::new("l");
        assert!(!layer.add_polygon_feature(&[vec![(0, 0), (5, 5), (10, 10)]], &[]));
        let square = vec![(0, 0), (10, 0), (10, 10), (0, 10)];
        assert!(layer.add_polygon_feature(&[vec![(0, 0), (1, 0), (2, 0)], square.clone()], &[]));
        let decoded = decode_layer(&layer.encode());
        assert_eq!(replay_geometry(&decoded.features[0].geometry), [square]);
    }

    #[test]
    fn doubled_area_is_exact_at_the_extremes() {
        let ring = [
            (i32::MIN, i32::MIN),
            (i32::MAX, i32::MIN),
            (i32::MAX, i32::MAX),
        ];
        assert!(doubled_area(&ring) > 0);
        assert_eq!(doubled_area(&[(0, 0), (4, 0), (4, 4), (0, 4)]), 32);
    }

    /// MVT 2.1 §4.3.5 example geometries, encoded by this crate.
    #[test]
    fn spec_geometry_examples_encode() {
        assert_eq!(encode_point_geometry(25, 17), [9, 50, 34]);
        assert_eq!(
            encode_line_geometry(&[(2, 2), (2, 10), (10, 10)]),
            [9, 4, 4, 18, 0, 16, 16, 0]
        );
        assert_eq!(
            encode_polygon_geometry(&[vec![(3, 6), (8, 12), (20, 34), (3, 6)]]),
            [9, 6, 12, 18, 10, 12, 24, 44, 15]
        );
        assert_eq!(
            encode_polygon_geometry(&[
                vec![(0, 0), (10, 0), (10, 10), (0, 10), (0, 0)],
                vec![(11, 11), (20, 11), (20, 20), (11, 20), (11, 11)],
                vec![(13, 13), (13, 17), (17, 17), (17, 13), (13, 13)],
            ]),
            [
                9, 0, 0, 26, 20, 0, 0, 20, 19, 0, 15, 9, 22, 2, 26, 18, 0, 0, 18, 17, 0, 15, 9, 4,
                13, 26, 0, 8, 8, 0, 0, 7, 15
            ]
        );
    }

    #[test]
    fn tag_dictionary_interns_shared_keys_and_values() {
        let mut layer = Layer::new("poi");
        layer.add_point_feature(0, 0, &[("kind", Value::String("cafe".into()))]);
        layer.add_point_feature(1, 1, &[("kind", Value::String("cafe".into()))]);
        layer.add_point_feature(2, 2, &[("kind", Value::String("bar".into()))]);

        assert_eq!(layer.keys.len(), 1, "one shared key");
        assert_eq!(layer.values.len(), 2, "two distinct values");

        let bytes = layer.encode();
        let decoded = decode_layer(&bytes);
        assert_eq!(decoded.features[0].tags, vec![0, 0]);
        assert_eq!(decoded.features[1].tags, vec![0, 0]);
        assert_eq!(decoded.features[2].tags, vec![0, 1]);
    }

    #[test]
    fn value_variants_round_trip() {
        let mut layer = Layer::new("l");
        layer.add_point_feature(
            0,
            0,
            &[
                ("s", Value::String("hi".into())),
                ("d", Value::Double(1.5)),
                ("i", Value::Int(-42)),
                ("b", Value::Bool(true)),
            ],
        );

        let bytes = layer.encode();
        let decoded = decode_layer(&bytes);
        assert_eq!(decoded.values[0], Value::String("hi".into()));
        assert_eq!(decoded.values[1], Value::Double(1.5));
        assert_eq!(decoded.values[2], Value::Int(-42));
        assert_eq!(decoded.values[3], Value::Bool(true));
    }

    #[test]
    fn empty_tile_encodes_to_empty_bytes() {
        let tile = Tile::new();
        assert_eq!(tile.encode(), [] as [u8; 0]);
    }

    #[test]
    fn multiple_layers_are_each_length_delimited() {
        let mut tile = Tile::new();
        tile.add_layer(Layer::new("a"));
        tile.add_layer(Layer::new("b"));
        let bytes = tile.encode();
        let layers = decode_tile_layers(&bytes);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].name, "a");
        assert_eq!(layers[1].name, "b");
    }

    #[test]
    fn custom_extent_is_preserved() {
        let layer = Layer::with_extent("l", 8192);
        let bytes = layer.encode();
        let decoded = decode_layer(&bytes);
        assert_eq!(decoded.extent, 8192);
    }

    // Regression: the vertex delta `x - cx` overflowed for
    // coordinates at opposite ends of the i32 range.
    #[test]
    fn extreme_coordinates_encode_with_wrapping_deltas() {
        let line = [(i32::MAX, i32::MIN), (i32::MIN, i32::MAX), (0, 0)];
        let mut layer = Layer::new("edges");
        layer.add_line_feature(&line, &[]);
        layer.add_polygon_feature(&[line.to_vec()], &[]);
        let decoded = decode_layer(&layer.encode());
        for feature in &decoded.features {
            assert_eq!(replay_geometry(&feature.geometry), vec![line.to_vec()]);
        }
    }

    // Regression: interning compared values with `==`, so
    // `-0.0` reused the `0.0` entry and lost its sign, and NaNs never matched.
    #[test]
    fn doubles_are_interned_by_bit_pattern() {
        let mut layer = Layer::new("signs");
        layer.add_point_feature(0, 0, &[("v", Value::Double(0.0))]);
        layer.add_point_feature(0, 0, &[("v", Value::Double(-0.0))]);
        layer.add_point_feature(0, 0, &[("v", Value::Double(f64::NAN))]);
        layer.add_point_feature(0, 0, &[("v", Value::Double(f64::NAN))]);
        let decoded = decode_layer(&layer.encode());
        assert_eq!(decoded.values.len(), 3);
        let Value::Double(negative_zero) = decoded.values[decoded.features[1].tags[1] as usize]
        else {
            panic!("expected a double");
        };
        assert!(negative_zero == 0.0 && negative_zero.is_sign_negative());
        assert_eq!(decoded.features[2].tags, decoded.features[3].tags);
    }

    // Regression: after ClosePath the encoder reset its
    // cursor to the ring's first vertex, but ClosePath does not move the
    // cursor, so every ring after the first (holes) decoded shifted.
    #[test]
    fn polygon_with_hole_decodes_per_spec() {
        let outer = vec![(0, 0), (100, 0), (100, 100), (0, 100)];
        let hole = vec![(25, 25), (25, 75), (75, 75), (75, 25)];
        let mut layer = Layer::new("donut");
        layer.add_polygon_feature(&[outer.clone(), hole.clone()], &[]);
        let decoded = decode_layer(&layer.encode());
        assert_eq!(
            replay_geometry(&decoded.features[0].geometry),
            vec![outer, hole]
        );
    }
}
