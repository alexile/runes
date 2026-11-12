//! SimHash and MinHash locality-sensitive signatures, shingling, and an
//! online near-duplicate clusterer.
//!
//! Built for collapsing soft-404s and templated pages in content
//! discovery, baselining responses for anomaly scanning, and deduplicating
//! findings. Everything is sans-I/O: text or feature hashes in, signatures
//! and cluster ids out.
//!
//! | Piece | API |
//! | --- | --- |
//! | Tokenise + shingle (words or chars, optional HTML stripping) | [`shingles`], [`ShingleOptions`], [`strip_html`] |
//! | 64-bit SimHash ([Charikar 2002](https://doi.org/10.1145/509907.509965)), Hamming similarity | [`SimHash`], [`SimHasher`] |
//! | MinHash ([Broder 1997](https://doi.org/10.1109/SEQUEN.1997.666900)), Jaccard estimate | [`MinHasher`], [`MinHashSignature`], [`jaccard`] |
//! | Online leader clustering, optional LSH banding | [`Clusterer`], [`ClusterOptions`] |
//!
//! SimHash is the cheap choice (8 bytes per item, one XOR + popcount per
//! comparison) and suits whole responses. MinHash costs more but its
//! similarity is a calibrated Jaccard estimate, which makes thresholds
//! easier to reason about on short texts.
//!
//! Fingerprints are stable across platforms and releases: the crate uses
//! its own fixed feature hash ([`hash_feature`]), never `std`'s seeded one.
//!
//! # Example
//!
//! ```
//! use rune_simhash::{ClusterOptions, Clusterer, ShingleOptions, SimHash};
//!
//! let opts = ShingleOptions::default().with_strip_html(true);
//! let not_found = |path: &str| format!(
//!     "<h1>Not Found</h1><p>The requested URL {path} was not found on this server. \
//!      Additionally, a 404 Not Found error was encountered while trying to use an \
//!      ErrorDocument to handle the request. Please contact the administrator.</p>"
//! );
//! let a = SimHash::from_text(&not_found("/admin"), &opts)?;
//! let b = SimHash::from_text(&not_found("/backup.tar.gz"), &opts)?;
//! let c = SimHash::from_text("<h1>Dashboard</h1><p>Welcome back. You have 3 unread messages.</p>", &opts)?;
//! assert!(a.hamming(b) < a.hamming(c));
//!
//! let mut clusters = Clusterer::new(ClusterOptions::default())?;
//! let ids: Vec<usize> = [a, b, c].into_iter().map(|s| clusters.assign(s).cluster).collect();
//! assert_eq!(ids, [0, 0, 1]);
//! # Ok::<(), rune_simhash::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::doc_markdown,
    reason = "SimHash and MinHash are algorithm names, not code identifiers"
)]

mod cluster;
mod error;
mod hash;
mod minhash;
mod shingle;
mod simhash;

pub use cluster::{Assignment, Cluster, ClusterOptions, Clusterer, Signature};
pub use error::Error;
pub use hash::hash_feature;
pub use minhash::{MinHashSignature, MinHasher, jaccard};
pub use shingle::{ShingleOptions, TokenKind, shingles, strip_html};
pub use simhash::{SimHash, SimHasher};
