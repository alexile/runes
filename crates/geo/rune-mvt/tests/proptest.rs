//! Encode/decode round-trip and decoder robustness properties.

use proptest::prelude::*;
use rune_mvt::{GeometryType, Layer, Tile, Value, decode};

type Point = (i32, i32);

#[derive(Debug, Clone)]
enum Geometry {
    Point(Point),
    Line(Vec<Point>),
    Polygon(Vec<Vec<Point>>),
}

#[derive(Debug, Clone)]
struct FeatureSpec {
    geometry: Geometry,
    tags: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
struct LayerSpec {
    name: String,
    extent: u32,
    features: Vec<FeatureSpec>,
}

fn coord() -> impl Strategy<Value = i32> {
    // Mostly small (so duplicates and collinear rings occur), sometimes extreme.
    prop_oneof![4 => -4..8i32, 1 => any::<i32>()]
}

fn point() -> impl Strategy<Value = Point> {
    (coord(), coord())
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        ".{0,6}".prop_map(Value::String),
        any::<f32>().prop_map(Value::Float),
        any::<f64>().prop_map(Value::Double),
        any::<i64>().prop_map(Value::Int),
        any::<u64>().prop_map(Value::UInt),
        any::<bool>().prop_map(Value::Bool),
    ]
}

fn feature() -> impl Strategy<Value = FeatureSpec> {
    let geometry = prop_oneof![
        point().prop_map(Geometry::Point),
        prop::collection::vec(point(), 0..8).prop_map(Geometry::Line),
        prop::collection::vec(prop::collection::vec(point(), 0..7), 0..4)
            .prop_map(Geometry::Polygon),
    ];
    let tags = prop::collection::vec(("[a-c]{0,2}", value()), 0..4);
    (geometry, tags).prop_map(|(geometry, tags)| FeatureSpec { geometry, tags })
}

fn layer() -> impl Strategy<Value = LayerSpec> {
    (
        ".{0,8}",
        any::<u32>(),
        prop::collection::vec(feature(), 0..6),
    )
        .prop_map(|(name, extent, features)| LayerSpec {
            name,
            extent,
            features,
        })
}

/// The model of what the encoder keeps: duplicates dropped, closing vertex
/// dropped, degenerate rings / lines dropped.
fn expected(geometry: &Geometry) -> (GeometryType, Vec<Vec<Point>>) {
    let dedup = |points: &[Point]| {
        let mut v = points.to_vec();
        v.dedup();
        v
    };
    match geometry {
        Geometry::Point(p) => (GeometryType::Point, vec![vec![*p]]),
        Geometry::Line(points) => {
            let points = dedup(points);
            let paths = if points.len() >= 2 {
                vec![points]
            } else {
                vec![]
            };
            (GeometryType::LineString, paths)
        }
        Geometry::Polygon(rings) => {
            let rings = rings
                .iter()
                .filter_map(|ring| {
                    let mut ring = dedup(ring);
                    if ring.len() > 1 && ring.first() == ring.last() {
                        ring.pop();
                    }
                    let area: i128 = ring
                        .iter()
                        .zip(ring.iter().cycle().skip(1))
                        .map(|(a, b)| {
                            i128::from(a.0) * i128::from(b.1) - i128::from(b.0) * i128::from(a.1)
                        })
                        .sum();
                    (ring.len() >= 3 && area != 0).then_some(ring)
                })
                .collect();
            (GeometryType::Polygon, rings)
        }
    }
}

fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Double(x), Value::Double(y)) => x.to_bits() == y.to_bits(),
        (Value::Float(x), Value::Float(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn decode_inverts_encode(specs in prop::collection::vec(layer(), 0..4)) {
        let mut tile = Tile::new();
        for spec in &specs {
            let mut layer = Layer::with_extent(spec.name.clone(), spec.extent);
            for feature in &spec.features {
                let tags: Vec<(&str, Value)> =
                    feature.tags.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
                let added = match &feature.geometry {
                    Geometry::Point((x, y)) => layer.add_point_feature(*x, *y, &tags),
                    Geometry::Line(points) => layer.add_line_feature(points, &tags),
                    Geometry::Polygon(rings) => layer.add_polygon_feature(rings, &tags),
                };
                prop_assert_eq!(added, !expected(&feature.geometry).1.is_empty());
            }
            tile.add_layer(layer);
        }
        let decoded = decode(&tile.encode()).unwrap();
        prop_assert_eq!(decoded.layers.len(), specs.len());
        for (layer, spec) in decoded.layers.iter().zip(&specs) {
            prop_assert_eq!(&layer.name, &spec.name);
            prop_assert_eq!(layer.extent, spec.extent);
            prop_assert_eq!(layer.version, 2);
            let kept: Vec<_> = spec
                .features
                .iter()
                .filter(|f| !expected(&f.geometry).1.is_empty())
                .collect();
            prop_assert_eq!(layer.features.len(), kept.len());
            for (feature, spec) in layer.features.iter().zip(kept) {
                let (kind, paths) = expected(&spec.geometry);
                prop_assert_eq!(feature.geometry_type, kind);
                prop_assert_eq!(&feature.geometry, &paths);
                prop_assert_eq!(feature.id, None);
                let props: Vec<_> = layer.properties(feature).collect();
                prop_assert_eq!(props.len(), spec.tags.len());
                for ((k, v), (ek, ev)) in props.into_iter().zip(&spec.tags) {
                    prop_assert_eq!(k, ek.as_str());
                    prop_assert!(same_value(v, ev), "{:?} != {:?}", v, ev);
                }
            }
        }
    }

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn decode_never_panics_on_mutated_tiles(
        spec in layer(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let mut layer = Layer::with_extent(spec.name.clone(), spec.extent);
        for feature in &spec.features {
            let tags: Vec<(&str, Value)> =
                feature.tags.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            match &feature.geometry {
                Geometry::Point((x, y)) => layer.add_point_feature(*x, *y, &tags),
                Geometry::Line(points) => layer.add_line_feature(points, &tags),
                Geometry::Polygon(rings) => layer.add_polygon_feature(rings, &tags),
            };
        }
        let mut tile = Tile::new();
        tile.add_layer(layer);
        let mut bytes = tile.encode();
        for (index, byte) in flips {
            let i = index.index(bytes.len());
            bytes[i] ^= byte;
        }
        if let Ok(decoded) = decode(&bytes) {
            for layer in &decoded.layers {
                for feature in &layer.features {
                    prop_assert_eq!(layer.properties(feature).count(), feature.tags.len());
                }
            }
        }
    }
}
