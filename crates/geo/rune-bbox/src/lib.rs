//! Bounding-box math over latitude/longitude boxes: union, intersection,
//! containment, and fixed-point merging of overlapping boxes.
//!
//! # Features
//!
//! - [`union`] / [`intersection`] — combine two boxes.
//! - [`contains`] / [`contains_point`] / [`overlaps`] — containment queries.
//! - [`merge_overlapping`] — collapse a set of boxes into their connected-component
//!   unions, following chains of overlap (A overlaps B, B overlaps C ⇒ A, B, C merge
//!   into one box even if A and C never directly touch).
//!
//! All coordinates use `(lat, lon)` in degrees. Boundaries are treated as inclusive
//! everywhere: a point or box edge exactly on another box's edge counts as inside /
//! overlapping.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_bbox::{BBox, union, contains_point};
//!
//! let a = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.0, max_lon: 1.0 };
//! let b = BBox { min_lat: 0.5, min_lon: 0.5, max_lat: 1.5, max_lon: 1.5 };
//!
//! let u = union(&a, &b);
//! assert_eq!(u, BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.5, max_lon: 1.5 });
//! assert!(contains_point(&u, 0.75, 0.75));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-bbox union 0,0,1,1 0.5,0.5,1.5,1.5
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// A latitude/longitude bounding box. `min_*` must be `<= max_*`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BBox {
    /// Southern edge, in degrees.
    pub min_lat: f64,
    /// Western edge, in degrees.
    pub min_lon: f64,
    /// Northern edge, in degrees.
    pub max_lat: f64,
    /// Eastern edge, in degrees.
    pub max_lon: f64,
}

/// The smallest box containing both `a` and `b`.
///
/// # Example
///
/// ```rust
/// use rune_bbox::{BBox, union};
///
/// let a = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.0, max_lon: 1.0 };
/// let b = BBox { min_lat: 2.0, min_lon: 2.0, max_lat: 3.0, max_lon: 3.0 };
/// let u = union(&a, &b);
/// assert_eq!(u, BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 3.0, max_lon: 3.0 });
/// ```
#[must_use]
pub const fn union(a: &BBox, b: &BBox) -> BBox {
    BBox {
        min_lat: a.min_lat.min(b.min_lat),
        min_lon: a.min_lon.min(b.min_lon),
        max_lat: a.max_lat.max(b.max_lat),
        max_lon: a.max_lon.max(b.max_lon),
    }
}

/// The overlapping region of `a` and `b`, or `None` if they don't overlap.
///
/// # Example
///
/// ```rust
/// use rune_bbox::{BBox, intersection};
///
/// let a = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 2.0, max_lon: 2.0 };
/// let b = BBox { min_lat: 1.0, min_lon: 1.0, max_lat: 3.0, max_lon: 3.0 };
/// let i = intersection(&a, &b).unwrap();
/// assert_eq!(i, BBox { min_lat: 1.0, min_lon: 1.0, max_lat: 2.0, max_lon: 2.0 });
/// ```
#[must_use]
pub fn intersection(a: &BBox, b: &BBox) -> Option<BBox> {
    let min_lat = a.min_lat.max(b.min_lat);
    let min_lon = a.min_lon.max(b.min_lon);
    let max_lat = a.max_lat.min(b.max_lat);
    let max_lon = a.max_lon.min(b.max_lon);
    if min_lat > max_lat || min_lon > max_lon {
        None
    } else {
        Some(BBox {
            min_lat,
            min_lon,
            max_lat,
            max_lon,
        })
    }
}

/// Whether `outer` fully contains `inner` (boundary-inclusive).
#[must_use]
pub fn contains(outer: &BBox, inner: &BBox) -> bool {
    outer.min_lat <= inner.min_lat
        && outer.min_lon <= inner.min_lon
        && outer.max_lat >= inner.max_lat
        && outer.max_lon >= inner.max_lon
}

/// Whether `(lat, lon)` falls within `b` (boundary-inclusive).
///
/// # Example
///
/// ```rust
/// use rune_bbox::{BBox, contains_point};
///
/// let b = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.0, max_lon: 1.0 };
/// assert!(contains_point(&b, 1.0, 1.0)); // boundary is inclusive
/// assert!(!contains_point(&b, 1.1, 0.5));
/// ```
#[must_use]
pub fn contains_point(b: &BBox, lat: f64, lon: f64) -> bool {
    lat >= b.min_lat && lat <= b.max_lat && lon >= b.min_lon && lon <= b.max_lon
}

/// Whether `a` and `b` overlap or touch (boundary-inclusive).
#[must_use]
pub fn overlaps(a: &BBox, b: &BBox) -> bool {
    intersection(a, b).is_some()
}

/// Repeatedly unions overlapping boxes until no two boxes in the result overlap,
/// following chains of overlap transitively (connected-component merge).
///
/// # Example
///
/// ```rust
/// use rune_bbox::{BBox, merge_overlapping};
///
/// let a = BBox { min_lat: 0.0, min_lon: 0.0, max_lat: 1.0, max_lon: 1.0 };
/// let b = BBox { min_lat: 0.9, min_lon: 0.9, max_lat: 2.0, max_lon: 2.0 };
/// let c = BBox { min_lat: 1.9, min_lon: 1.9, max_lat: 3.0, max_lon: 3.0 };
///
/// let merged = merge_overlapping(&[a, b, c]);
/// assert_eq!(merged.len(), 1); // a-b overlap, b-c overlap, so all three merge
/// ```
#[must_use]
pub fn merge_overlapping(boxes: &[BBox]) -> Vec<BBox> {
    let mut current: Vec<BBox> = boxes.to_vec();

    loop {
        let mut merged: Vec<BBox> = Vec::with_capacity(current.len());
        let mut consumed = vec![false; current.len()];
        let mut any_merge = false;

        for i in 0..current.len() {
            if consumed[i] {
                continue;
            }
            let mut acc = current[i];
            consumed[i] = true;
            for j in (i + 1)..current.len() {
                if !consumed[j] && overlaps(&acc, &current[j]) {
                    acc = union(&acc, &current[j]);
                    consumed[j] = true;
                    any_merge = true;
                }
            }
            merged.push(acc);
        }

        current = merged;
        if !any_merge {
            return current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bb(min_lat: f64, min_lon: f64, max_lat: f64, max_lon: f64) -> BBox {
        BBox {
            min_lat,
            min_lon,
            max_lat,
            max_lon,
        }
    }

    #[test]
    fn union_covers_both_corners() {
        let a = bb(0.0, 0.0, 1.0, 1.0);
        let b = bb(2.0, -1.0, 3.0, 0.5);
        let u = union(&a, &b);
        assert!(contains_point(&u, 0.0, 0.0));
        assert!(contains_point(&u, 1.0, 1.0));
        assert!(contains_point(&u, 2.0, -1.0));
        assert!(contains_point(&u, 3.0, 0.5));
    }

    #[test]
    fn intersection_of_overlapping_boxes() {
        let a = bb(0.0, 0.0, 2.0, 2.0);
        let b = bb(1.0, 1.0, 3.0, 3.0);
        assert_eq!(intersection(&a, &b), Some(bb(1.0, 1.0, 2.0, 2.0)));
    }

    #[test]
    fn intersection_of_disjoint_boxes_is_none() {
        let a = bb(0.0, 0.0, 1.0, 1.0);
        let b = bb(5.0, 5.0, 6.0, 6.0);
        assert_eq!(intersection(&a, &b), None);
    }

    #[test]
    fn contains_inside_and_outside() {
        let outer = bb(0.0, 0.0, 10.0, 10.0);
        let inner = bb(1.0, 1.0, 2.0, 2.0);
        let not_inner = bb(1.0, 1.0, 11.0, 2.0);
        assert!(contains(&outer, &inner));
        assert!(!contains(&outer, &not_inner));
    }

    #[test]
    fn contains_point_boundary_is_inclusive() {
        let b = bb(0.0, 0.0, 1.0, 1.0);
        assert!(contains_point(&b, 0.0, 0.0));
        assert!(contains_point(&b, 1.0, 1.0));
        assert!(!contains_point(&b, 1.0001, 0.5));
    }

    #[test]
    fn merge_overlapping_chain_collapses_to_one() {
        let a = bb(0.0, 0.0, 1.0, 1.0);
        let b = bb(0.9, 0.9, 2.0, 2.0);
        let c = bb(1.9, 1.9, 3.0, 3.0);
        let merged = merge_overlapping(&[a, b, c]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], bb(0.0, 0.0, 3.0, 3.0));
    }

    #[test]
    fn merge_overlapping_disjoint_boxes_unchanged_count() {
        let a = bb(0.0, 0.0, 1.0, 1.0);
        let b = bb(10.0, 10.0, 11.0, 11.0);
        let merged = merge_overlapping(&[a, b]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn overlaps_matches_intersection() {
        let a = bb(0.0, 0.0, 1.0, 1.0);
        let b = bb(0.5, 0.5, 1.5, 1.5);
        let c = bb(5.0, 5.0, 6.0, 6.0);
        assert!(overlaps(&a, &b));
        assert!(!overlaps(&a, &c));
    }
}
