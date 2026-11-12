//! A from-scratch, dependency-free 2D R-tree spatial index.
//!
//! Stores `(f64, f64)` points with an associated generic payload `T` and
//! supports incremental insertion, axis-aligned bounding-box range queries,
//! and exact k-nearest-neighbor queries. Internally it is a Guttman-style
//! R-tree: leaf nodes hold up to `max_entries` points, internal nodes hold
//! up to `max_entries` children, and an overflowing node is split into two
//! using a quadratic-cost (but cheap in practice, since `max_entries` is
//! small) seed-picking heuristic that minimizes wasted bounding-box area.
//!
//! Deletion is intentionally not implemented — this index is built once (or
//! incrementally grown) and queried, which covers the common case without
//! the substantially more complex underflow/reinsertion machinery a full
//! R-tree needs to support removal.
//!
//! # Features
//!
//! - [`RTree::insert`] — incremental insertion with automatic node splitting.
//! - [`RTree::range`] — all points whose location falls inside a query
//!   [`BBox`].
//! - [`RTree::nearest`] — exact k-nearest-neighbor search using
//!   branch-and-bound pruning over subtree bounding boxes.
//! - Generic payload `T` — attach an id, a struct, anything `Sized`.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_rtree::{RTree, BBox};
//!
//! let mut tree = RTree::new();
//! tree.insert((0.0, 0.0), "origin");
//! tree.insert((1.0, 1.0), "near");
//! tree.insert((10.0, 10.0), "far");
//!
//! let in_range = tree.range(BBox::new(-0.5, -0.5, 2.0, 2.0));
//! assert_eq!(in_range.len(), 2);
//!
//! let nearest = tree.nearest((0.1, 0.1), 1);
//! assert_eq!(nearest[0].1, &"origin");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-rtree points.csv --query-x 1.0 --query-y 1.0 --k 3
//! rune-rtree points.csv --range 0.0 0.0 5.0 5.0
//! ```

/// An axis-aligned bounding box.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BBox {
    /// Minimum x coordinate.
    pub min_x: f64,
    /// Minimum y coordinate.
    pub min_y: f64,
    /// Maximum x coordinate.
    pub max_x: f64,
    /// Maximum y coordinate.
    pub max_y: f64,
}

impl BBox {
    /// Builds a bounding box from two opposite corners, in any order.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::BBox;
    ///
    /// let b = BBox::new(5.0, 5.0, 0.0, 0.0);
    /// assert_eq!(b.min_x, 0.0);
    /// assert_eq!(b.max_x, 5.0);
    /// ```
    #[must_use]
    pub const fn new(x1: f64, y1: f64, x2: f64, y2: f64) -> Self {
        Self {
            min_x: x1.min(x2),
            min_y: y1.min(y2),
            max_x: x1.max(x2),
            max_y: y1.max(y2),
        }
    }

    /// A degenerate, zero-area bounding box covering a single point.
    #[must_use]
    pub const fn point(p: (f64, f64)) -> Self {
        Self {
            min_x: p.0,
            min_y: p.1,
            max_x: p.0,
            max_y: p.1,
        }
    }

    /// The smallest bounding box that contains both `self` and `other`.
    #[must_use]
    pub const fn union(&self, other: &Self) -> Self {
        Self {
            min_x: self.min_x.min(other.min_x),
            min_y: self.min_y.min(other.min_y),
            max_x: self.max_x.max(other.max_x),
            max_y: self.max_y.max(other.max_y),
        }
    }

    /// The box's area. Zero for a degenerate point box or a flat line.
    #[must_use]
    pub fn area(&self) -> f64 {
        (self.max_x - self.min_x) * (self.max_y - self.min_y)
    }

    /// Whether `self` and `other` overlap, including touching edges.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::BBox;
    ///
    /// let a = BBox::new(0.0, 0.0, 2.0, 2.0);
    /// let b = BBox::new(1.0, 1.0, 3.0, 3.0);
    /// let c = BBox::new(5.0, 5.0, 6.0, 6.0);
    /// assert!(a.intersects(&b));
    /// assert!(!a.intersects(&c));
    /// ```
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.min_x <= other.max_x
            && self.max_x >= other.min_x
            && self.min_y <= other.max_y
            && self.max_y >= other.min_y
    }

    /// Whether the point `p` falls within `self`, edges inclusive.
    #[must_use]
    pub fn contains_point(&self, p: (f64, f64)) -> bool {
        p.0 >= self.min_x && p.0 <= self.max_x && p.1 >= self.min_y && p.1 <= self.max_y
    }
}

struct LeafEntry<T> {
    bbox: BBox,
    point: (f64, f64),
    data: T,
}

struct Child<T> {
    bbox: BBox,
    node: Box<Node<T>>,
}

enum NodeKind<T> {
    Leaf(Vec<LeafEntry<T>>),
    Internal(Vec<Child<T>>),
}

struct Node<T> {
    bbox: BBox,
    kind: NodeKind<T>,
}

impl<T> Node<T> {
    const fn empty_leaf() -> Self {
        Self {
            bbox: BBox::point((0.0, 0.0)),
            kind: NodeKind::Leaf(Vec::new()),
        }
    }

    fn insert(
        &mut self,
        entry: LeafEntry<T>,
        max_entries: usize,
        min_entries: usize,
    ) -> Option<Self> {
        match &mut self.kind {
            NodeKind::Leaf(entries) => {
                entries.push(entry);
                self.bbox = bbox_union_all(entries, |e| e.bbox);
                if entries.len() > max_entries {
                    let all = std::mem::take(entries);
                    let (group_a, group_b) = split(all, |e| e.bbox, min_entries);
                    self.bbox = bbox_union_all(&group_a, |e| e.bbox);
                    *entries = group_a;
                    let sibling_bbox = bbox_union_all(&group_b, |e| e.bbox);
                    Some(Self {
                        bbox: sibling_bbox,
                        kind: NodeKind::Leaf(group_b),
                    })
                } else {
                    None
                }
            }
            NodeKind::Internal(children) => {
                let idx = choose_subtree(children, entry.bbox);
                let split_result = children[idx].node.insert(entry, max_entries, min_entries);
                children[idx].bbox = children[idx].node.bbox;
                if let Some(sibling) = split_result {
                    children.push(Child {
                        bbox: sibling.bbox,
                        node: Box::new(sibling),
                    });
                }
                self.bbox = bbox_union_all(children, |c| c.bbox);
                if children.len() > max_entries {
                    let all = std::mem::take(children);
                    let (group_a, group_b) = split(all, |c| c.bbox, min_entries);
                    self.bbox = bbox_union_all(&group_a, |c| c.bbox);
                    *children = group_a;
                    let sibling_bbox = bbox_union_all(&group_b, |c| c.bbox);
                    Some(Self {
                        bbox: sibling_bbox,
                        kind: NodeKind::Internal(group_b),
                    })
                } else {
                    None
                }
            }
        }
    }
}

fn bbox_union_all<X>(items: &[X], bbox_of: impl Fn(&X) -> BBox) -> BBox {
    let mut iter = items.iter();
    iter.next().map_or_else(
        || BBox::point((0.0, 0.0)),
        |first| iter.fold(bbox_of(first), |acc, x| acc.union(&bbox_of(x))),
    )
}

fn choose_subtree<T>(children: &[Child<T>], bbox: BBox) -> usize {
    children
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let enlargement = c.bbox.union(&bbox).area() - c.bbox.area();
            (i, enlargement, c.bbox.area())
        })
        .min_by(|a, b| a.1.total_cmp(&b.1).then(a.2.total_cmp(&b.2)))
        // Internal nodes always have children, so the fallback is never used.
        .map_or(0, |(i, _, _)| i)
}

/// Splits `entries` into two non-empty groups using a quadratic seed-picking
/// heuristic (Guttman's quadratic split): the pair whose combined bounding
/// box wastes the most area over the two individual boxes seeds each group,
/// then remaining entries are assigned one at a time to whichever group's
/// area grows least, forcing the rest into a group once it would otherwise
/// drop below `min_entries`.
fn split<X>(entries: Vec<X>, bbox_of: impl Fn(&X) -> BBox, min_entries: usize) -> (Vec<X>, Vec<X>) {
    let n = entries.len();
    let bboxes: Vec<BBox> = entries.iter().map(&bbox_of).collect();

    let mut best = (0usize, 1usize, f64::MIN);
    for i in 0..n {
        for j in (i + 1)..n {
            let combined = bboxes[i].union(&bboxes[j]);
            let waste = combined.area() - bboxes[i].area() - bboxes[j].area();
            if waste > best.2 {
                best = (i, j, waste);
            }
        }
    }
    let (seed_a, seed_b, _) = best;

    let mut bbox_a = bboxes[seed_a];
    let mut bbox_b = bboxes[seed_b];
    let mut group_a = Vec::with_capacity(n);
    let mut group_b = Vec::with_capacity(n);
    let mut remaining: Vec<(BBox, X)> = Vec::with_capacity(n.saturating_sub(2));
    for (i, x) in entries.into_iter().enumerate() {
        if i == seed_a {
            group_a.push(x);
        } else if i == seed_b {
            group_b.push(x);
        } else {
            remaining.push((bboxes[i], x));
        }
    }

    while !remaining.is_empty() {
        let need_a = min_entries.saturating_sub(group_a.len());
        let need_b = min_entries.saturating_sub(group_b.len());

        if need_a >= remaining.len() {
            for (b, x) in remaining {
                bbox_a = bbox_a.union(&b);
                group_a.push(x);
            }
            break;
        }
        if need_b >= remaining.len() {
            for (b, x) in remaining {
                bbox_b = bbox_b.union(&b);
                group_b.push(x);
            }
            break;
        }

        let mut pick_pos = 0;
        let mut best_diff = f64::MIN;
        let mut goes_to_a = true;
        for (pos, (b, _)) in remaining.iter().enumerate() {
            let enlarge_a = bbox_a.union(b).area() - bbox_a.area();
            let enlarge_b = bbox_b.union(b).area() - bbox_b.area();
            let diff = (enlarge_a - enlarge_b).abs();
            if diff > best_diff {
                best_diff = diff;
                pick_pos = pos;
                goes_to_a = match enlarge_a.total_cmp(&enlarge_b) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Equal => bbox_a.area() <= bbox_b.area(),
                    std::cmp::Ordering::Greater => false,
                };
            }
        }

        let (b, x) = remaining.remove(pick_pos);
        if goes_to_a {
            bbox_a = bbox_a.union(&b);
            group_a.push(x);
        } else {
            bbox_b = bbox_b.union(&b);
            group_b.push(x);
        }
    }

    (group_a, group_b)
}

fn count_node<T>(node: &Node<T>) -> usize {
    match &node.kind {
        NodeKind::Leaf(entries) => entries.len(),
        NodeKind::Internal(children) => children.iter().map(|c| count_node(&c.node)).sum(),
    }
}

fn range_node<'a, T>(node: &'a Node<T>, region: &BBox, out: &mut Vec<(f64, f64, &'a T)>) {
    if !node.bbox.intersects(region) {
        return;
    }
    match &node.kind {
        NodeKind::Leaf(entries) => {
            for e in entries {
                if region.contains_point(e.point) {
                    out.push((e.point.0, e.point.1, &e.data));
                }
            }
        }
        NodeKind::Internal(children) => {
            for c in children {
                range_node(&c.node, region, out);
            }
        }
    }
}

fn euclidean(a: (f64, f64), b: (f64, f64)) -> f64 {
    let dx = a.0 - b.0;
    let dy = a.1 - b.1;
    dx.hypot(dy)
}

fn mindist_to_bbox(point: (f64, f64), b: BBox) -> f64 {
    let dx = if point.0 < b.min_x {
        b.min_x - point.0
    } else if point.0 > b.max_x {
        point.0 - b.max_x
    } else {
        0.0
    };
    let dy = if point.1 < b.min_y {
        b.min_y - point.1
    } else if point.1 > b.max_y {
        point.1 - b.max_y
    } else {
        0.0
    };
    dx.hypot(dy)
}

fn insert_sorted<'a, T>(
    best: &mut Vec<(f64, (f64, f64), &'a T)>,
    k: usize,
    d: f64,
    p: (f64, f64),
    data: &'a T,
) {
    if best.len() < k {
        let pos = best.partition_point(|x| x.0 <= d);
        best.insert(pos, (d, p, data));
    } else if !best.is_empty() && d < best[best.len() - 1].0 {
        best.pop();
        let pos = best.partition_point(|x| x.0 <= d);
        best.insert(pos, (d, p, data));
    }
}

fn nearest_node<'a, T>(
    node: &'a Node<T>,
    point: (f64, f64),
    k: usize,
    best: &mut Vec<(f64, (f64, f64), &'a T)>,
) {
    match &node.kind {
        NodeKind::Leaf(entries) => {
            for e in entries {
                let d = euclidean(point, e.point);
                insert_sorted(best, k, d, e.point, &e.data);
            }
        }
        NodeKind::Internal(children) => {
            let mut ordered: Vec<&Child<T>> = children.iter().collect();
            ordered.sort_by(|a, b| {
                mindist_to_bbox(point, a.bbox).total_cmp(&mindist_to_bbox(point, b.bbox))
            });
            for c in ordered {
                if best.len() == k {
                    let worst = best[best.len() - 1].0;
                    if mindist_to_bbox(point, c.bbox) > worst {
                        continue;
                    }
                }
                nearest_node(&c.node, point, k, best);
            }
        }
    }
}

/// A 2D R-tree spatial index mapping `(f64, f64)` points to a payload `T`.
///
/// Construct with [`RTree::new`] (or [`RTree::with_max_entries`] to tune the
/// node fanout), then [`RTree::insert`] points one at a time and query with
/// [`RTree::range`] or [`RTree::nearest`].
pub struct RTree<T> {
    root: Node<T>,
    max_entries: usize,
    min_entries: usize,
}

impl<T> Default for RTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RTree<T> {
    /// Creates an empty R-tree with a default node fanout of 8 entries.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::RTree;
    ///
    /// let tree: RTree<usize> = RTree::new();
    /// assert!(tree.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_entries(8)
    }

    /// Creates an empty R-tree with a custom maximum entries per node.
    ///
    /// Larger values mean shallower trees with more linear scanning per
    /// node; smaller values mean deeper trees with more pointer-chasing.
    /// `8` is a reasonable default for most workloads.
    ///
    /// # Panics
    ///
    /// Panics if `max_entries < 4`, since a split needs room for two groups
    /// of at least two entries each.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        assert!(max_entries >= 4, "max_entries must be at least 4");
        let min_entries = (max_entries / 3).max(2);
        Self {
            root: Node::empty_leaf(),
            max_entries,
            min_entries,
        }
    }

    /// Number of points stored in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        count_node(&self.root)
    }

    /// Whether the index holds no points.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts `point` with associated `data` into the index.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::RTree;
    ///
    /// let mut tree = RTree::new();
    /// tree.insert((1.0, 2.0), 42usize);
    /// assert_eq!(tree.len(), 1);
    /// ```
    pub fn insert(&mut self, point: (f64, f64), data: T) {
        let entry = LeafEntry {
            bbox: BBox::point(point),
            point,
            data,
        };
        if let Some(sibling) = self.root.insert(entry, self.max_entries, self.min_entries) {
            let old_root = std::mem::replace(&mut self.root, Node::empty_leaf());
            let new_bbox = old_root.bbox.union(&sibling.bbox);
            self.root = Node {
                bbox: new_bbox,
                kind: NodeKind::Internal(vec![
                    Child {
                        bbox: old_root.bbox,
                        node: Box::new(old_root),
                    },
                    Child {
                        bbox: sibling.bbox,
                        node: Box::new(sibling),
                    },
                ]),
            };
        }
    }

    /// Returns every stored point that falls within `region`, as
    /// `(x, y, &data)` tuples. Order is unspecified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::{RTree, BBox};
    ///
    /// let mut tree = RTree::new();
    /// tree.insert((0.0, 0.0), "a");
    /// tree.insert((5.0, 5.0), "b");
    /// tree.insert((100.0, 100.0), "c");
    ///
    /// let hits = tree.range(BBox::new(-1.0, -1.0, 6.0, 6.0));
    /// assert_eq!(hits.len(), 2);
    /// ```
    #[must_use]
    pub fn range(&self, region: BBox) -> Vec<(f64, f64, &T)> {
        let mut out = Vec::new();
        range_node(&self.root, &region, &mut out);
        out
    }

    /// Returns the `k` stored points nearest to `point`, closest first, as
    /// `((x, y), &data, distance)` tuples. Uses branch-and-bound pruning
    /// over subtree bounding boxes, so it is exact, not approximate.
    ///
    /// Returns fewer than `k` results if the tree holds fewer than `k`
    /// points.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_rtree::RTree;
    ///
    /// let mut tree = RTree::new();
    /// tree.insert((0.0, 0.0), "origin");
    /// tree.insert((3.0, 4.0), "five-away");
    /// tree.insert((10.0, 0.0), "far");
    ///
    /// let nearest = tree.nearest((0.0, 0.0), 2);
    /// assert_eq!(nearest.len(), 2);
    /// assert_eq!(nearest[0].1, &"origin");
    /// assert_eq!(nearest[1].1, &"five-away");
    /// assert!((nearest[1].2 - 5.0).abs() < 1e-9);
    /// ```
    #[must_use]
    pub fn nearest(&self, point: (f64, f64), k: usize) -> Vec<((f64, f64), &T, f64)> {
        if k == 0 {
            return Vec::new();
        }
        let mut best = Vec::with_capacity(k);
        nearest_node(&self.root, point, k, &mut best);
        best.into_iter().map(|(d, p, t)| (p, t, d)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_no_results() {
        let tree: RTree<usize> = RTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.range(BBox::new(-100.0, -100.0, 100.0, 100.0)).len(), 0);
        assert_eq!(tree.nearest((0.0, 0.0), 5).len(), 0);
    }

    #[test]
    fn insert_and_len() {
        let mut tree = RTree::new();
        for i in 0..20 {
            tree.insert((f64::from(i), f64::from(i)), i);
        }
        assert_eq!(tree.len(), 20);
    }

    #[test]
    fn range_returns_only_points_inside_box() {
        let mut tree = RTree::new();
        tree.insert((0.0, 0.0), "a");
        tree.insert((1.0, 1.0), "b");
        tree.insert((5.0, 5.0), "c");
        tree.insert((-5.0, -5.0), "d");

        let hits = tree.range(BBox::new(-0.5, -0.5, 2.0, 2.0));
        let mut labels: Vec<&str> = hits.iter().map(|&(_, _, v)| *v).collect();
        labels.sort_unstable();
        assert_eq!(labels, vec!["a", "b"]);
    }

    #[test]
    fn range_covering_everything_returns_all_points() {
        let mut tree = RTree::new();
        for i in 0..50 {
            tree.insert((f64::from(i), f64::from(-i)), i);
        }
        let hits = tree.range(BBox::new(-1000.0, -1000.0, 1000.0, 1000.0));
        assert_eq!(hits.len(), 50);
    }

    #[test]
    fn range_with_no_matches_is_empty() {
        let mut tree = RTree::new();
        tree.insert((0.0, 0.0), 1);
        tree.insert((1.0, 1.0), 2);
        let hits = tree.range(BBox::new(50.0, 50.0, 60.0, 60.0));
        assert_eq!(hits, [] as [(f64, f64, &i32); 0]);
    }

    #[test]
    fn nearest_returns_closest_point_first() {
        let mut tree = RTree::new();
        tree.insert((0.0, 0.0), "origin");
        tree.insert((3.0, 4.0), "five");
        tree.insert((10.0, 0.0), "ten");
        tree.insert((-1.0, -1.0), "near");

        let hits = tree.nearest((0.0, 0.0), 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, &"origin");
        assert_eq!(hits[0].2, 0.0);
    }

    #[test]
    fn nearest_k_results_are_sorted_by_distance() {
        let mut tree = RTree::new();
        let pts = [(0.0, 0.0), (1.0, 0.0), (2.0, 0.0), (3.0, 0.0), (10.0, 10.0)];
        for (i, &p) in pts.iter().enumerate() {
            tree.insert(p, i);
        }

        let hits = tree.nearest((0.0, 0.0), 3);
        assert_eq!(hits.len(), 3);
        for w in hits.windows(2) {
            assert!(w[0].2 <= w[1].2, "results must be sorted ascending");
        }
        let ids: Vec<usize> = hits.iter().map(|&(_, &d, _)| d).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn nearest_with_k_larger_than_len_returns_all() {
        let mut tree = RTree::new();
        tree.insert((0.0, 0.0), 1);
        tree.insert((1.0, 1.0), 2);
        let hits = tree.nearest((0.0, 0.0), 100);
        assert_eq!(hits.len(), 2);
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn nearest_matches_brute_force_on_many_points() {
        let mut tree = RTree::new();
        let mut pts = Vec::new();
        let mut seed = 12345u64;
        for i in 0..200 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let x = ((seed >> 33) as f64 % 1000.0) - 500.0;
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let y = ((seed >> 33) as f64 % 1000.0) - 500.0;
            pts.push((x, y));
            tree.insert((x, y), i);
        }

        let query = (0.0, 0.0);
        let tree_hits = tree.nearest(query, 5);

        let mut brute: Vec<(f64, usize)> = pts
            .iter()
            .enumerate()
            .map(|(i, &p)| (euclidean(query, p), i))
            .collect();
        brute.sort_by(|a, b| a.0.total_cmp(&b.0));

        let tree_dists: Vec<f64> = tree_hits.iter().map(|&(_, _, d)| d).collect();
        let brute_dists: Vec<f64> = brute[..5].iter().map(|&(d, _)| d).collect();

        for (a, b) in tree_dists.iter().zip(brute_dists.iter()) {
            assert!((a - b).abs() < 1e-9, "tree={a} brute={b}");
        }
    }

    #[test]
    fn bbox_union_and_intersects() {
        let a = BBox::new(0.0, 0.0, 2.0, 2.0);
        let b = BBox::new(1.0, 1.0, 3.0, 3.0);
        let u = a.union(&b);
        assert_eq!(u, BBox::new(0.0, 0.0, 3.0, 3.0));
        assert!(a.intersects(&b));

        let c = BBox::new(10.0, 10.0, 11.0, 11.0);
        assert!(!a.intersects(&c));
    }

    #[test]
    fn bbox_contains_point() {
        let b = BBox::new(0.0, 0.0, 10.0, 10.0);
        assert!(b.contains_point((5.0, 5.0)));
        assert!(b.contains_point((0.0, 0.0)));
        assert!(!b.contains_point((10.1, 5.0)));
    }

    #[test]
    #[should_panic(expected = "max_entries must be at least 4")]
    fn with_max_entries_rejects_too_small() {
        let _: RTree<usize> = RTree::with_max_entries(2);
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn splitting_triggers_and_tree_stays_correct() {
        let mut tree: RTree<usize> = RTree::with_max_entries(4);
        for i in 0..100 {
            tree.insert((i as f64, (i * 2) as f64), i);
        }
        assert_eq!(tree.len(), 100);
        let hits = tree.range(BBox::new(0.0, 0.0, 9.0, 18.0));
        assert_eq!(hits.len(), 10);
    }
}
