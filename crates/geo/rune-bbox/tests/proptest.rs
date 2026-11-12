//! Known values and set-algebra properties: union is the smallest enclosing
//! box, intersection is the largest common box, point containment agrees with
//! both, and `merge_overlapping` yields disjoint boxes covering the input.

use proptest::prelude::*;
use rune_bbox::{BBox, contains, contains_point, intersection, merge_overlapping, overlaps, union};

const fn bb(min_lat: f64, min_lon: f64, max_lat: f64, max_lon: f64) -> BBox {
    BBox {
        min_lat,
        min_lon,
        max_lat,
        max_lon,
    }
}

/// Valid boxes on a coarse integer grid, so overlaps, shared edges and
/// identical boxes all come up often.
fn bbox() -> impl Strategy<Value = BBox> {
    (-20i8..20, -20i8..20, 0i8..10, 0i8..10).prop_map(|(lat, lon, h, w)| {
        bb(
            f64::from(lat),
            f64::from(lon),
            f64::from(lat) + f64::from(h),
            f64::from(lon) + f64::from(w),
        )
    })
}

fn point() -> impl Strategy<Value = (f64, f64)> {
    (-25.0..35.0f64, -25.0..35.0f64)
}

#[test]
fn known_values() {
    let a = bb(0.0, 0.0, 2.0, 2.0);
    let b = bb(1.0, 1.0, 3.0, 3.0);
    assert_eq!(union(&a, &b), bb(0.0, 0.0, 3.0, 3.0));
    assert_eq!(intersection(&a, &b), Some(bb(1.0, 1.0, 2.0, 2.0)));

    // Boxes sharing only an edge or a corner touch: the intersection is
    // degenerate but present, because boundaries are inclusive.
    let right = bb(0.0, 2.0, 2.0, 4.0);
    assert_eq!(intersection(&a, &right), Some(bb(0.0, 2.0, 2.0, 2.0)));
    let corner = bb(2.0, 2.0, 3.0, 3.0);
    assert_eq!(intersection(&a, &corner), Some(bb(2.0, 2.0, 2.0, 2.0)));
    assert!(overlaps(&a, &corner));
    assert!(!overlaps(&a, &bb(2.000_001, 0.0, 3.0, 1.0)));

    // Crossing boxes: a horizontal and a vertical bar.
    let h = bb(1.0, -5.0, 2.0, 5.0);
    let v = bb(-5.0, 1.0, 5.0, 2.0);
    assert_eq!(intersection(&h, &v), Some(bb(1.0, 1.0, 2.0, 2.0)));
    assert!(!contains(&h, &v) && !contains(&v, &h));

    // Two separate clusters stay separate; the order of the output follows
    // the first box of each cluster.
    let merged = merge_overlapping(&[
        bb(0.0, 0.0, 1.0, 1.0),
        bb(10.0, 10.0, 11.0, 11.0),
        bb(0.5, 0.5, 2.0, 2.0),
        bb(10.5, 10.5, 12.0, 12.0),
    ]);
    assert_eq!(
        merged,
        vec![bb(0.0, 0.0, 2.0, 2.0), bb(10.0, 10.0, 12.0, 12.0)]
    );

    // A union created during merging can swallow a box seen earlier in the pass.
    let merged = merge_overlapping(&[
        bb(0.0, 0.0, 1.0, 1.0),
        bb(5.0, 5.0, 6.0, 6.0),
        bb(0.5, 0.5, 5.5, 5.5),
    ]);
    assert_eq!(merged, vec![bb(0.0, 0.0, 6.0, 6.0)]);
    assert_eq!(merge_overlapping(&[]), Vec::new());
}

proptest! {
    #[test]
    fn union_is_smallest_enclosing_box(a in bbox(), b in bbox(), c in bbox()) {
        let u = union(&a, &b);
        prop_assert_eq!(u, union(&b, &a));
        prop_assert_eq!(union(&a, &a), a);
        prop_assert_eq!(union(&u, &c), union(&a, &union(&b, &c)));
        prop_assert!(contains(&u, &a) && contains(&u, &b));
        // Any box containing both contains the union.
        if contains(&c, &a) && contains(&c, &b) {
            prop_assert!(contains(&c, &u));
        }
    }

    #[test]
    fn intersection_is_largest_common_box(a in bbox(), b in bbox()) {
        let i = intersection(&a, &b);
        prop_assert_eq!(i, intersection(&b, &a));
        prop_assert_eq!(intersection(&a, &a), Some(a));
        prop_assert_eq!(overlaps(&a, &b), i.is_some());
        prop_assert_eq!(overlaps(&a, &b), overlaps(&b, &a));
        if let Some(i) = i {
            prop_assert!(i.min_lat <= i.max_lat && i.min_lon <= i.max_lon);
            prop_assert!(contains(&a, &i) && contains(&b, &i));
        }
        if contains(&a, &b) {
            prop_assert_eq!(i, Some(b));
            prop_assert_eq!(union(&a, &b), a);
        }
    }

    #[test]
    fn point_membership_agrees_with_set_ops(a in bbox(), b in bbox(), (lat, lon) in point()) {
        let in_a = contains_point(&a, lat, lon);
        let in_b = contains_point(&b, lat, lon);
        let in_i = intersection(&a, &b).is_some_and(|i| contains_point(&i, lat, lon));
        prop_assert_eq!(in_i, in_a && in_b);
        if in_a || in_b {
            prop_assert!(contains_point(&union(&a, &b), lat, lon));
        }
    }

    #[test]
    fn corners_are_inside(a in bbox()) {
        for (lat, lon) in [
            (a.min_lat, a.min_lon),
            (a.min_lat, a.max_lon),
            (a.max_lat, a.min_lon),
            (a.max_lat, a.max_lon),
        ] {
            prop_assert!(contains_point(&a, lat, lon));
        }
    }

    #[test]
    fn merge_yields_disjoint_cover(boxes in prop::collection::vec(bbox(), 0..24)) {
        let merged = merge_overlapping(&boxes);
        prop_assert!(merged.len() <= boxes.len());
        prop_assert_eq!(merged.is_empty(), boxes.is_empty());
        // No two output boxes overlap.
        for (i, x) in merged.iter().enumerate() {
            for y in &merged[i + 1..] {
                prop_assert!(!overlaps(x, y), "{:?} overlaps {:?}", x, y);
            }
        }
        // Every input box lies inside exactly one output box.
        for b in &boxes {
            let homes = merged.iter().filter(|m| contains(m, b)).count();
            prop_assert_eq!(homes, 1, "{:?}", b);
        }
        // Each output box is exactly the union of the inputs it contains.
        for m in &merged {
            let members = boxes.iter().filter(|b| contains(m, b));
            let rebuilt = members.copied().reduce(|x, y| union(&x, &y));
            prop_assert_eq!(rebuilt, Some(*m));
        }
        // Merging again changes nothing.
        prop_assert_eq!(merge_overlapping(&merged), merged);
    }

    #[test]
    fn merge_result_does_not_depend_on_input_order(
        boxes in prop::collection::vec(bbox(), 0..16),
        seed in any::<prop::sample::Index>(),
    ) {
        let mut rotated = boxes.clone();
        if !rotated.is_empty() {
            let k = seed.index(rotated.len());
            rotated.rotate_left(k);
        }
        let key = |b: &BBox| (b.min_lat.to_bits(), b.min_lon.to_bits(), b.max_lat.to_bits(), b.max_lon.to_bits());
        let mut x = merge_overlapping(&boxes);
        let mut y = merge_overlapping(&rotated);
        x.sort_by_key(key);
        y.sort_by_key(key);
        prop_assert_eq!(x, y);
    }
}
