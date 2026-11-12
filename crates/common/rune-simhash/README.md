# rune-simhash

> SimHash and MinHash locality-sensitive signatures with shingling and an online near-duplicate clusterer

[![crates.io](https://img.shields.io/crates/v/rune-simhash)](https://crates.io/crates/rune-simhash)
[![docs.rs](https://img.shields.io/docsrs/rune-simhash)](https://docs.rs/rune-simhash)
[![license](https://img.shields.io/crates/l/rune-simhash)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Locality-sensitive hashing for near-duplicate text: collapse soft-404s and
templated pages during content discovery, baseline responses for anomaly
scanning, deduplicate findings. Sans-I/O: text or feature hashes in,
signatures and cluster ids out.

| Piece | API |
| --- | --- |
| Word or character shingles, optional HTML stripping | `shingles`, `ShingleOptions`, `strip_html` |
| 64-bit SimHash ([Charikar 2002](https://doi.org/10.1145/509907.509965)), weighted features, Hamming similarity | `SimHash`, `SimHasher` |
| MinHash ([Broder 1997](https://doi.org/10.1109/SEQUEN.1997.666900)), Jaccard estimate, exact `jaccard` | `MinHasher`, `MinHashSignature` |
| Online leader clustering, optional LSH banding | `Clusterer`, `ClusterOptions` |

Fingerprints are stable across platforms and releases: features are hashed
with a fixed FNV-1a + SplitMix64 function (`hash_feature`), never `std`'s
randomly seeded hasher, so they can be stored and compared later.

## Installation

```toml
[dependencies]
rune-simhash = "0.1"
```

Enable the `serde` feature to serialize `SimHash` and `MinHashSignature`.
The command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-simhash --features cli
```

## Usage

### Library

```rust
use rune_simhash::{ClusterOptions, Clusterer, MinHasher, ShingleOptions, SimHash};

fn main() -> Result<(), rune_simhash::Error> {
    let opts = ShingleOptions::default().with_strip_html(true);
    let page = |path: &str| format!(
        "<h1>Not Found</h1><p>The requested URL {path} was not found on this server. \
         Additionally, a 404 Not Found error was encountered while trying to use an \
         ErrorDocument to handle the request. Please contact the administrator.</p>"
    );

    // SimHash: 8 bytes per response, compared with XOR + popcount.
    let mut clusters = Clusterer::new(ClusterOptions::default())?; // threshold 0.8
    for path in ["/admin", "/.git/config", "/backup.zip"] {
        let fp = SimHash::from_text(&page(path), &opts)?;
        let a = clusters.assign(fp);
        println!("{path}: cluster {} ({fp})", a.cluster);
    }
    assert_eq!(clusters.clusters().len(), 1);

    // MinHash: a calibrated Jaccard estimate, with LSH banding for scale.
    let hasher = MinHasher::new(128, 0)?;
    let a = hasher.signature_text(&page("/a"), &opts)?;
    let b = hasher.signature_text(&page("/b"), &opts)?;
    assert!(a.jaccard(&b)? > 0.7);
    Ok(())
}
```

### Choosing a threshold

SimHash similarity is `1 − hamming/64`. Unrelated texts differ in 32 ± 4
bits. Changing a fraction `f` of a document's shingles moves about
`64·acos(1 − f)/π` bits: 2 % ≈ 4 bits, 10 % ≈ 9 bits. The default 0.8
(distance ≤ 12) keeps unrelated texts more than 4.5 standard deviations
away; use 0.95 (distance ≤ 3, Manku et al.) for long documents where only
true near-copies should merge. Very short texts (a dozen words) carry too
few shingles for SimHash; use MinHash or `TokenKind::Chars` there.

`ClusterOptions::bands` switches from an exhaustive scan to LSH buckets.
For SimHash, `b` bands always find pairs within distance `b − 1`; for
MinHash, `b` bands of `r` rows find a pair of Jaccard `J` with probability
`1 − (1 − J^r)^b`.

### Performance

`cargo run --release -p rune-simhash --example bench_10k` signs and
clusters 10 000 short HTML documents (half soft-404 variants of 20
templates, half unique). On a recent x86-64 laptop:

| Step | Time |
| --- | --- |
| SimHash, shingle + sign | ~85 ms |
| SimHash, exhaustive clustering | ~30 ms |
| SimHash, 4-band clustering | ~3 ms |
| MinHash (128), shingle + sign | ~110 ms |
| MinHash, 32-band clustering | ~20 ms |

### CLI

```bash
rune-simhash --html --threshold 0.8 responses/*.html
# 0	089c796d0897ce60	responses/a.html
# 0	88b87c7d88f7ee78	responses/b.html
# 1	666e6653f7f0b0ae	responses/c.html
```

Each line is the cluster id, the fingerprint and the path.

## License

MIT
