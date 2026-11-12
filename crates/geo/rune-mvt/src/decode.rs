//! Decoder for untrusted Mapbox Vector Tile bytes.
//!
//! Every length, index and count is checked against the input, so a
//! malformed tile returns an [`MvtError`] instead of panicking, and memory
//! use stays linear in the input size: feature properties are kept as
//! indices into the layer's key/value tables, never copied per feature.

use crate::Value;

/// Error returned by [`decode`] for bytes that are not a valid MVT tile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MvtError {
    /// The input ends in the middle of a field.
    #[error("unexpected end of input")]
    Truncated,
    /// The protobuf encoding is invalid (bad varint, wire type, UTF-8, …).
    #[error("malformed protobuf: {reason}")]
    Malformed {
        /// What is wrong.
        reason: &'static str,
    },
    /// A layer has no `name` field (MVT 2.1 §4.1).
    #[error("layer has no name")]
    MissingName,
    /// A layer's `version` is not 1 or 2.
    #[error("unsupported layer version {version}")]
    UnsupportedVersion {
        /// The version found.
        version: u64,
    },
    /// A `Value` message does not hold exactly one known value field.
    #[error("invalid value: {reason}")]
    InvalidValue {
        /// What is wrong.
        reason: &'static str,
    },
    /// A feature's tags are odd in number or index past the key/value table.
    #[error("invalid feature tags: {reason}")]
    InvalidTags {
        /// What is wrong.
        reason: &'static str,
    },
    /// A feature's geometry commands violate MVT 2.1 §4.3.
    #[error("invalid geometry: {reason}")]
    InvalidGeometry {
        /// What is wrong.
        reason: &'static str,
    },
}

/// The geometry type of a decoded feature (MVT 2.1 §4.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GeometryType {
    /// `UNKNOWN` (0) or a type number this crate does not know.
    Unknown,
    /// `POINT` (1): one path of one vertex per point.
    Point,
    /// `LINESTRING` (2): one path per line.
    LineString,
    /// `POLYGON` (3): one path per ring, without the closing vertex.
    Polygon,
}

/// A decoded tile.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct DecodedTile {
    /// Layers in tile order.
    pub layers: Vec<DecodedLayer>,
}

/// A decoded layer.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DecodedLayer {
    /// Layer name.
    pub name: String,
    /// Layer version (1 if absent).
    pub version: u32,
    /// Tile extent (4096 if absent).
    pub extent: u32,
    /// The key table features index into.
    pub keys: Vec<String>,
    /// The value table features index into.
    pub values: Vec<Value>,
    /// Features in layer order.
    pub features: Vec<DecodedFeature>,
}

impl DecodedLayer {
    /// The properties of `feature` (which must come from this layer), as
    /// `(key, value)` pairs in tag order.
    ///
    /// Indices were validated by [`decode`], so every pair resolves.
    pub fn properties<'a>(
        &'a self,
        feature: &'a DecodedFeature,
    ) -> impl Iterator<Item = (&'a str, &'a Value)> + 'a {
        feature.tags.iter().filter_map(|&(key, value)| {
            Some((
                self.keys.get(usize::try_from(key).ok()?)?.as_str(),
                self.values.get(usize::try_from(value).ok()?)?,
            ))
        })
    }
}

/// A decoded feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodedFeature {
    /// Feature id, if present.
    pub id: Option<u64>,
    /// Geometry type.
    pub geometry_type: GeometryType,
    /// `(key index, value index)` pairs into the layer's tables.
    pub tags: Vec<(u32, u32)>,
    /// Absolute tile coordinates: one path per `MoveTo` vertex, extended by
    /// the `LineTo`s that follow it. Polygon rings omit the implicit closing
    /// vertex.
    pub geometry: Vec<Vec<(i32, i32)>>,
}

/// Decodes MVT 2.x tile bytes.
///
/// Unknown fields are skipped, as protobuf requires. Fields may be packed or
/// unpacked. Geometry is validated against the command rules of MVT 2.1
/// §4.3.4 for points, lines and polygons; polygon winding and duplicate
/// layer names are not checked.
///
/// # Errors
///
/// Returns [`MvtError`] for malformed protobuf, a layer without a name, an
/// unsupported version, an invalid value, out-of-range tags, or invalid
/// geometry commands.
///
/// # Example
///
/// ```rust
/// use rune_mvt::{GeometryType, Layer, Tile, Value, decode};
///
/// let mut layer = Layer::new("poi");
/// layer.add_point_feature(25, 17, &[("name", Value::String("cafe".into()))]);
/// let mut tile = Tile::new();
/// tile.add_layer(layer);
///
/// let decoded = decode(&tile.encode())?;
/// let layer = &decoded.layers[0];
/// let feature = &layer.features[0];
/// assert_eq!(feature.geometry_type, GeometryType::Point);
/// assert_eq!(feature.geometry, [[(25, 17)]]);
/// let props: Vec<_> = layer.properties(feature).collect();
/// assert_eq!(props, [("name", &Value::String("cafe".into()))]);
/// # Ok::<(), rune_mvt::MvtError>(())
/// ```
pub fn decode(bytes: &[u8]) -> Result<DecodedTile, MvtError> {
    let mut reader = Reader::new(bytes);
    let mut layers = Vec::new();
    while let Some((number, field)) = reader.field()? {
        if number == 3 {
            layers.push(decode_layer(field.bytes()?)?);
        }
    }
    Ok(DecodedTile { layers })
}

fn decode_layer(bytes: &[u8]) -> Result<DecodedLayer, MvtError> {
    let mut reader = Reader::new(bytes);
    let (mut name, mut version, mut extent) = (None, 1u64, 4096u64);
    let (mut keys, mut values, mut raw_features) = (Vec::new(), Vec::new(), Vec::new());
    while let Some((number, field)) = reader.field()? {
        match number {
            1 => name = Some(utf8(field.bytes()?)?),
            2 => raw_features.push(field.bytes()?),
            3 => keys.push(utf8(field.bytes()?)?),
            4 => values.push(decode_value(field.bytes()?)?),
            5 => extent = field.varint()?,
            15 => version = field.varint()?,
            _ => {}
        }
    }
    let name = name.ok_or(MvtError::MissingName)?;
    if !(1..=2).contains(&version) {
        return Err(MvtError::UnsupportedVersion { version });
    }
    let extent = u32::try_from(extent).map_err(|_| MvtError::Malformed {
        reason: "extent does not fit in u32",
    })?;
    let features = raw_features
        .into_iter()
        .map(|bytes| decode_feature(bytes, keys.len(), values.len()))
        .collect::<Result<_, _>>()?;
    Ok(DecodedLayer {
        name,
        // Checked to be 1 or 2 above.
        version: u32::from(version == 2) + 1,
        extent,
        keys,
        values,
        features,
    })
}

fn decode_value(bytes: &[u8]) -> Result<Value, MvtError> {
    let mut reader = Reader::new(bytes);
    let mut value = None;
    while let Some((number, field)) = reader.field()? {
        let decoded = match (number, field) {
            (1, Field::Bytes(s)) => Value::String(utf8(s)?),
            (2, Field::Fixed32(f)) => Value::Float(f32::from_le_bytes(f)),
            (3, Field::Fixed64(d)) => Value::Double(f64::from_le_bytes(d)),
            (4, Field::Varint(v)) => Value::Int(i64::from_ne_bytes(v.to_ne_bytes())),
            (5, Field::Varint(v)) => Value::UInt(v),
            (6, Field::Varint(v)) => Value::Int(crate::varint::zigzag_decode_i64(v)),
            (7, Field::Varint(v)) => Value::Bool(v != 0),
            (1..=7, _) => {
                return Err(MvtError::InvalidValue {
                    reason: "value field has the wrong wire type",
                });
            }
            _ => continue,
        };
        if value.replace(decoded).is_some() {
            return Err(MvtError::InvalidValue {
                reason: "more than one value field",
            });
        }
    }
    value.ok_or(MvtError::InvalidValue {
        reason: "no value field",
    })
}

fn decode_feature(
    bytes: &[u8],
    key_count: usize,
    value_count: usize,
) -> Result<DecodedFeature, MvtError> {
    let mut reader = Reader::new(bytes);
    let (mut id, mut kind) = (None, 0u64);
    let (mut tags, mut commands) = (Vec::new(), Vec::new());
    while let Some((number, field)) = reader.field()? {
        match number {
            1 => id = Some(field.varint()?),
            2 => field.repeated_u32(&mut tags)?,
            3 => kind = field.varint()?,
            4 => field.repeated_u32(&mut commands)?,
            _ => {}
        }
    }
    if tags.len() % 2 != 0 {
        return Err(MvtError::InvalidTags {
            reason: "odd number of tag indices",
        });
    }
    let in_range = |index: u32, len: usize| usize::try_from(index).is_ok_and(|i| i < len);
    let tags = tags
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[key, value]| {
            if !in_range(key, key_count) {
                return Err(MvtError::InvalidTags {
                    reason: "key index out of range",
                });
            }
            if !in_range(value, value_count) {
                return Err(MvtError::InvalidTags {
                    reason: "value index out of range",
                });
            }
            Ok((key, value))
        })
        .collect::<Result<_, _>>()?;
    let geometry_type = match kind {
        1 => GeometryType::Point,
        2 => GeometryType::LineString,
        3 => GeometryType::Polygon,
        _ => GeometryType::Unknown,
    };
    let geometry = decode_geometry(geometry_type, &commands)?;
    Ok(DecodedFeature {
        id,
        geometry_type,
        tags,
        geometry,
    })
}

const MOVE_TO: u32 = 1;
const LINE_TO: u32 = 2;
const CLOSE_PATH: u32 = 7;

/// Replays geometry commands into absolute paths, enforcing the per-type
/// command sequences of MVT 2.1 §4.3.4.
fn decode_geometry(
    geometry_type: GeometryType,
    commands: &[u32],
) -> Result<Vec<Vec<(i32, i32)>>, MvtError> {
    let invalid = |reason| MvtError::InvalidGeometry { reason };
    let mut paths: Vec<Vec<(i32, i32)>> = Vec::new();
    let mut cursor = (0i32, 0i32);
    let mut ints = commands.iter().copied();
    // What the previous command was, to check the per-type sequences.
    let mut previous = None;
    while let Some(command) = ints.next() {
        let (id, count) = (command & 7, command >> 3);
        if !matches!(id, MOVE_TO | LINE_TO | CLOSE_PATH) {
            return Err(invalid("unknown command id"));
        }
        let allowed = match geometry_type {
            GeometryType::Unknown => true,
            GeometryType::Point => id == MOVE_TO && previous.is_none(),
            GeometryType::LineString => match id {
                MOVE_TO => matches!(previous, None | Some(LINE_TO)),
                LINE_TO => previous == Some(MOVE_TO),
                _ => false,
            },
            GeometryType::Polygon => match id {
                MOVE_TO => matches!(previous, None | Some(CLOSE_PATH)),
                LINE_TO => previous == Some(MOVE_TO),
                _ => previous == Some(LINE_TO),
            },
        };
        if !allowed {
            return Err(invalid("command out of sequence for the geometry type"));
        }
        let minimum = match (geometry_type, id) {
            (GeometryType::Polygon, LINE_TO) => 2,
            (GeometryType::Unknown, _) => 0,
            _ => 1,
        };
        let exact_one = matches!(
            (geometry_type, id),
            (GeometryType::LineString | GeometryType::Polygon, MOVE_TO) | (_, CLOSE_PATH)
        );
        if count < minimum || (exact_one && count != 1) {
            return Err(invalid("bad command count"));
        }
        previous = Some(id);
        if id == CLOSE_PATH {
            // ClosePath does not move the cursor (§4.3.3.3).
            continue;
        }
        for _ in 0..count {
            let (Some(dx), Some(dy)) = (ints.next(), ints.next()) else {
                return Err(invalid("command is missing parameters"));
            };
            cursor = (
                cursor.0.wrapping_add(crate::varint::zigzag_decode(dx)),
                cursor.1.wrapping_add(crate::varint::zigzag_decode(dy)),
            );
            if id == MOVE_TO {
                paths.push(vec![cursor]);
            } else {
                paths
                    .last_mut()
                    .ok_or_else(|| invalid("LineTo before MoveTo"))?
                    .push(cursor);
            }
        }
    }
    let complete = match (geometry_type, previous) {
        (GeometryType::Unknown, _) => true,
        (_, None) => false,
        (GeometryType::Point, _) => true,
        (GeometryType::LineString, last) => last == Some(LINE_TO),
        (GeometryType::Polygon, last) => last == Some(CLOSE_PATH),
    };
    if !complete {
        return Err(invalid("geometry is empty or ends mid-sequence"));
    }
    Ok(paths)
}

fn utf8(bytes: &[u8]) -> Result<String, MvtError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| MvtError::Malformed {
        reason: "string is not UTF-8",
    })
}

/// One protobuf field.
#[derive(Debug, Clone, Copy)]
enum Field<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
    Fixed32([u8; 4]),
}

impl<'a> Field<'a> {
    const fn bytes(self) -> Result<&'a [u8], MvtError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(MvtError::Malformed {
                reason: "expected a length-delimited field",
            }),
        }
    }

    const fn varint(self) -> Result<u64, MvtError> {
        match self {
            Self::Varint(value) => Ok(value),
            _ => Err(MvtError::Malformed {
                reason: "expected a varint field",
            }),
        }
    }

    /// Appends a packed or unpacked repeated `uint32` field.
    fn repeated_u32(self, out: &mut Vec<u32>) -> Result<(), MvtError> {
        let to_u32 = |value: u64| {
            u32::try_from(value).map_err(|_| MvtError::Malformed {
                reason: "uint32 value out of range",
            })
        };
        match self {
            Self::Varint(value) => out.push(to_u32(value)?),
            Self::Bytes(packed) => {
                let mut reader = Reader::new(packed);
                while !reader.buf.is_empty() {
                    out.push(to_u32(reader.varint()?)?);
                }
            }
            _ => {
                return Err(MvtError::Malformed {
                    reason: "expected a repeated uint32 field",
                });
            }
        }
        Ok(())
    }
}

/// A bounds-checked protobuf reader.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn varint(&mut self) -> Result<u64, MvtError> {
        let mut value = 0u64;
        for index in 0..10 {
            let (&byte, rest) = self.buf.split_first().ok_or(MvtError::Truncated)?;
            self.buf = rest;
            let bits = u64::from(byte & 0x7f);
            // The tenth byte may only carry the top bit of a u64.
            if index == 9 && bits > 1 {
                break;
            }
            value |= bits << (7 * index);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(MvtError::Malformed {
            reason: "varint longer than 64 bits",
        })
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], MvtError> {
        let (bytes, rest) = self
            .buf
            .split_first_chunk::<N>()
            .ok_or(MvtError::Truncated)?;
        self.buf = rest;
        Ok(*bytes)
    }

    fn field(&mut self) -> Result<Option<(u64, Field<'a>)>, MvtError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number = key >> 3;
        if number == 0 {
            return Err(MvtError::Malformed {
                reason: "field number 0",
            });
        }
        let field = match key & 7 {
            0 => Field::Varint(self.varint()?),
            1 => Field::Fixed64(self.take::<8>()?),
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| MvtError::Truncated)?;
                if len > self.buf.len() {
                    return Err(MvtError::Truncated);
                }
                let (bytes, rest) = self.buf.split_at(len);
                self.buf = rest;
                Field::Bytes(bytes)
            }
            5 => Field::Fixed32(self.take::<4>()?),
            _ => {
                return Err(MvtError::Malformed {
                    reason: "unsupported wire type",
                });
            }
        };
        Ok(Some((number, field)))
    }
}
