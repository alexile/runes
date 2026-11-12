//! Decoder known-answer and rejection tests.
//!
//! The geometry vectors are the worked examples of the Mapbox Vector Tile
//! specification 2.1, §4.3.5.

use rune_mvt::{GeometryType, MvtError, Value, decode};

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(value.to_le_bytes()[0] | 0x80);
        value >>= 7;
    }
    out.push(value.to_le_bytes()[0]);
}

fn key(number: u64, wire_type: u64, out: &mut Vec<u8>) {
    varint(number << 3 | wire_type, out);
}

fn bytes_field(number: u64, payload: &[u8], out: &mut Vec<u8>) {
    key(number, 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn varint_field(number: u64, value: u64, out: &mut Vec<u8>) {
    key(number, 0, out);
    varint(value, out);
}

fn packed(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for &v in values {
        varint(u64::from(v), &mut out);
    }
    out
}

fn feature(kind: u64, tags: &[u32], geometry: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    if !tags.is_empty() {
        bytes_field(2, &packed(tags), &mut out);
    }
    varint_field(3, kind, &mut out);
    bytes_field(4, &packed(geometry), &mut out);
    out
}

/// A one-layer tile named "l" holding `features`, with optional raw extra
/// layer fields appended.
fn tile(features: &[Vec<u8>], extra: &[u8]) -> Vec<u8> {
    let mut layer = Vec::new();
    bytes_field(1, b"l", &mut layer);
    for f in features {
        bytes_field(2, f, &mut layer);
    }
    layer.extend_from_slice(extra);
    varint_field(15, 2, &mut layer);
    let mut out = Vec::new();
    bytes_field(3, &layer, &mut out);
    out
}

fn geometry_of(kind: u64, commands: &[u32]) -> Result<Vec<Vec<(i32, i32)>>, MvtError> {
    let decoded = decode(&tile(&[feature(kind, &[], commands)], &[]))?;
    Ok(decoded.layers[0].features[0].geometry.clone())
}

#[test]
fn spec_4_3_5_1_point() {
    assert_eq!(geometry_of(1, &[9, 50, 34]).unwrap(), [[(25, 17)]]);
}

#[test]
fn spec_4_3_5_2_multipoint() {
    assert_eq!(
        geometry_of(1, &[17, 10, 14, 3, 9]).unwrap(),
        [[(5, 7)], [(3, 2)]]
    );
}

#[test]
fn spec_4_3_5_3_linestring() {
    assert_eq!(
        geometry_of(2, &[9, 4, 4, 18, 0, 16, 16, 0]).unwrap(),
        [[(2, 2), (2, 10), (10, 10)]]
    );
}

#[test]
fn spec_4_3_5_4_multilinestring() {
    assert_eq!(
        geometry_of(2, &[9, 4, 4, 18, 0, 16, 16, 0, 9, 17, 17, 10, 4, 8]).unwrap(),
        [vec![(2, 2), (2, 10), (10, 10)], vec![(1, 1), (3, 5)]]
    );
}

#[test]
fn spec_4_3_5_5_polygon() {
    assert_eq!(
        geometry_of(3, &[9, 6, 12, 18, 10, 12, 24, 44, 15]).unwrap(),
        [[(3, 6), (8, 12), (20, 34)]]
    );
}

#[test]
fn spec_4_3_5_6_multipolygon() {
    let commands = [
        9, 0, 0, 26, 20, 0, 0, 20, 19, 0, 15, 9, 22, 2, 26, 18, 0, 0, 18, 17, 0, 15, 9, 4, 13, 26,
        0, 8, 8, 0, 0, 7, 15,
    ];
    assert_eq!(
        geometry_of(3, &commands).unwrap(),
        [
            [(0, 0), (10, 0), (10, 10), (0, 10)],
            [(11, 11), (20, 11), (20, 20), (11, 20)],
            [(13, 13), (13, 17), (17, 17), (17, 13)],
        ]
    );
}

#[test]
fn all_value_fields_and_defaults() {
    let mut extra = Vec::new();
    bytes_field(3, b"k", &mut extra);
    let values: [&[u8]; 7] = [
        &[0x0a, 0x02, b'h', b'i'],             // string_value
        &[0x15, 0x00, 0x00, 0xc0, 0x3f],       // float_value 1.5
        &[0x19, 0, 0, 0, 0, 0, 0, 0xf8, 0x3f], // double_value 1.5
        &[
            0x20, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ], // int_value -2
        &[
            0x28, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ], // uint_value 2^63
        &[0x30, 0x03],                         // sint_value -2
        &[0x38, 0x01],                         // bool_value
    ];
    for v in values {
        bytes_field(4, v, &mut extra);
    }
    let mut f = feature(1, &[0, 0, 0, 6], &[9, 2, 2]);
    varint_field(1, 42, &mut f);
    let decoded = decode(&tile(&[f], &extra)).unwrap();
    let layer = &decoded.layers[0];
    assert_eq!(layer.version, 2);
    assert_eq!(layer.extent, 4096, "default extent");
    assert_eq!(
        layer.values,
        [
            Value::String("hi".into()),
            Value::Float(1.5),
            Value::Double(1.5),
            Value::Int(-2),
            Value::UInt(1 << 63),
            Value::Int(-2),
            Value::Bool(true),
        ]
    );
    let feature = &layer.features[0];
    assert_eq!(feature.id, Some(42));
    assert_eq!(feature.geometry_type, GeometryType::Point);
    let props: Vec<_> = layer.properties(feature).collect();
    assert_eq!(
        props,
        [
            ("k", &Value::String("hi".into())),
            ("k", &Value::Bool(true))
        ]
    );
}

#[test]
fn unknown_fields_and_unpacked_repeats_are_accepted() {
    let mut f = Vec::new();
    varint_field(3, 2, &mut f);
    for command in [9, 4, 4, 18, 0, 16, 16, 0] {
        varint_field(4, command, &mut f); // unpacked geometry
    }
    varint_field(99, 7, &mut f); // unknown varint field
    key(98, 5, &mut f); // unknown fixed32 field
    f.extend_from_slice(&[1, 2, 3, 4]);
    let mut extra = Vec::new();
    bytes_field(50, b"ignored", &mut extra);
    let mut bytes = tile(&[f], &extra);
    key(4096, 1, &mut bytes); // unknown tile-level fixed64 extension
    bytes.extend_from_slice(&[0; 8]);
    let decoded = decode(&bytes).unwrap();
    assert_eq!(
        decoded.layers[0].features[0].geometry,
        [[(2, 2), (2, 10), (10, 10)]]
    );
}

#[test]
fn version_one_and_missing_version() {
    let mut layer = Vec::new();
    bytes_field(1, b"v1", &mut layer);
    let mut bytes = Vec::new();
    bytes_field(3, &layer, &mut bytes);
    assert_eq!(decode(&bytes).unwrap().layers[0].version, 1);
}

#[test]
fn empty_input_is_an_empty_tile() {
    assert_eq!(decode(&[]).unwrap().layers, []);
}

#[test]
fn invalid_geometry_is_rejected() {
    let cases: &[(u64, &[u32])] = &[
        (1, &[]),                            // empty point
        (1, &[9, 2]),                        // missing parameter
        (1, &[9, 2, 2, 9, 2, 2]),            // two MoveTo commands for a point
        (1, &[10, 2, 2]),                    // LineTo in a point
        (2, &[9, 2, 2]),                     // MoveTo without LineTo
        (2, &[17, 2, 2, 4, 4, 10, 2, 2]),    // MoveTo count 2 in a line
        (2, &[9, 2, 2, 2]),                  // LineTo count 0
        (2, &[9, 2, 2, 10, 2, 2, 15]),       // ClosePath in a line
        (3, &[9, 0, 0, 10, 2, 0, 15]),       // ring LineTo count 1
        (3, &[9, 0, 0, 18, 2, 0, 0, 2]),     // ring without ClosePath
        (3, &[9, 0, 0, 18, 2, 0, 0, 2, 23]), // ClosePath count 2
        (3, &[15]),                          // ClosePath first
        (1, &[12, 0, 0]),                    // unknown command id 4
        (0, &[10, 2, 2]),                    // LineTo before MoveTo, unknown type
    ];
    for (kind, commands) in cases {
        assert!(
            matches!(
                geometry_of(*kind, commands),
                Err(MvtError::InvalidGeometry { .. })
            ),
            "{kind} {commands:?}"
        );
    }
}

#[test]
fn invalid_tags_are_rejected() {
    let mut extra = Vec::new();
    bytes_field(3, b"k", &mut extra);
    bytes_field(4, &[0x38, 0x01], &mut extra);
    for tags in [&[0][..], &[0, 1], &[1, 0], &[0, 0, 0]] {
        let err = decode(&tile(&[feature(1, tags, &[9, 0, 0])], &extra)).unwrap_err();
        assert!(matches!(err, MvtError::InvalidTags { .. }), "{tags:?}");
    }
}

#[test]
fn invalid_layers_and_values_are_rejected() {
    // No name.
    let mut layer = Vec::new();
    varint_field(15, 2, &mut layer);
    let mut bytes = Vec::new();
    bytes_field(3, &layer, &mut bytes);
    assert_eq!(decode(&bytes).unwrap_err(), MvtError::MissingName);

    // Version 3.
    let mut layer = Vec::new();
    bytes_field(1, b"x", &mut layer);
    varint_field(15, 3, &mut layer);
    let mut bytes = Vec::new();
    bytes_field(3, &layer, &mut bytes);
    assert_eq!(
        decode(&bytes).unwrap_err(),
        MvtError::UnsupportedVersion { version: 3 }
    );

    // Values with zero, two, or mistyped fields.
    for value in [
        &[][..],
        &[0x38, 0x01, 0x38, 0x00],
        &[0x38 | 2, 0x00],
        &[0x1d, 0, 0, 0, 0],
    ] {
        let mut extra = Vec::new();
        bytes_field(4, value, &mut extra);
        assert!(
            matches!(
                decode(&tile(&[], &extra)).unwrap_err(),
                MvtError::InvalidValue { .. }
            ),
            "{value:?}"
        );
    }

    // Non-UTF-8 name.
    let mut layer = Vec::new();
    bytes_field(1, &[0xff], &mut layer);
    let mut bytes = Vec::new();
    bytes_field(3, &layer, &mut bytes);
    assert!(matches!(
        decode(&bytes).unwrap_err(),
        MvtError::Malformed { .. }
    ));
}

#[test]
fn malformed_protobuf_is_rejected() {
    let good = tile(&[feature(1, &[], &[9, 2, 2])], &[]);
    // Every strict prefix of a valid tile fails cleanly.
    for len in 1..good.len() {
        assert!(decode(&good[..len]).is_err(), "prefix {len}");
    }
    // Overlong varint, group wire type, field number 0, huge length.
    for bytes in [
        &[
            0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ][..],
        &[0x0b],
        &[0x02, 0x00],
        &[0x1a, 0xff, 0xff, 0xff, 0xff, 0x0f],
    ] {
        assert!(decode(bytes).is_err(), "{bytes:?}");
    }
    // Geometry parameter that does not fit in u32.
    let mut f = Vec::new();
    varint_field(3, 1, &mut f);
    varint_field(4, 1 << 32, &mut f);
    assert!(matches!(
        decode(&tile(&[f], &[])).unwrap_err(),
        MvtError::Malformed { .. }
    ));
}

#[test]
fn tag_references_do_not_amplify_memory() {
    // A 64 KiB key referenced 50 000 times: properties borrow, never copy.
    let mut extra = Vec::new();
    bytes_field(3, &vec![b'k'; 1 << 16], &mut extra);
    bytes_field(4, &[0x38, 0x01], &mut extra);
    let tags: Vec<u32> = std::iter::repeat_n([0, 0], 50_000).flatten().collect();
    let decoded = decode(&tile(&[feature(1, &tags, &[9, 0, 0])], &extra)).unwrap();
    let layer = &decoded.layers[0];
    assert_eq!(layer.properties(&layer.features[0]).count(), 50_000);
}
