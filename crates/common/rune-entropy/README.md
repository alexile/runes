# rune-entropy

> Shannon entropy, `ent`-style randomness statistics and sliding-window
> profiles for files and byte streams.

[![crates.io](https://img.shields.io/crates/v/rune-entropy)](https://crates.io/crates/rune-entropy)
[![docs.rs](https://img.shields.io/docsrs/rune-entropy)](https://docs.rs/rune-entropy)
[![license](https://img.shields.io/crates/l/rune-entropy)](LICENSE)

Entropy measures how unpredictable bytes are, from `0.0` bits per byte (one
value repeated) to `8.0` (every byte value equally likely). High scores point
at compression, encryption or packing; low scores at padding and repetitive
data. This crate gives you:

- **One-call entropy** for slices and files, plus a coarse class label.
- **Streaming analysis** with fixed memory: feed chunks, read a running
  entropy at any point. Gigabyte files never get loaded into memory.
- **More than Shannon:** min-entropy, chi-square against uniform (with a
  p-value), arithmetic mean, serial correlation and the Monte Carlo π
  estimate from the classic `ent` tool, and direct access to the byte
  histogram.
- **Sliding-window profiles** and a **region detector** that returns the byte
  ranges of packed or encrypted content.
- **A cautious verdict** (text / repetitive / binary / high-entropy /
  random-like) that says how confident it is and admits when the sample is
  too small.
- `no_std` + `alloc` core, no required dependencies.

## Installation

```toml
[dependencies]
rune-entropy = "0.4"
```

The command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-entropy --features cli
```

| Feature | Default | What it does |
|---------|---------|--------------|
| `std`   | yes     | File and `Read` helpers, `io::Write` for `Analyzer` |
| `libm`  | no      | Float math for `no_std` builds (`default-features = false, features = ["libm"]`) |
| `cli`   | no      | The `rune-entropy` binary |

## Library

### Entropy of a slice or file

```rust
use rune_entropy::{classify, entropy, file_entropy};
use std::path::Path;

let score = entropy(b"hello world");
println!("{score:.4} bits/byte ({})", classify(score));

// Streams the file in 64 KiB chunks.
let score = file_entropy(Path::new("suspicious.bin"))?;
```

### Streaming, with every statistic

```rust
use rune_entropy::Analyzer;

let mut analyzer = Analyzer::new();
for chunk in [&b"first chunk "[..], b"second chunk"] {
    analyzer.update(chunk);
    println!("running entropy: {:.3}", analyzer.shannon());
}

let report = analyzer.analysis();
println!("chi-square {:?}, serial correlation {:?}", report.chi_square, report.serial_correlation);
println!("{}", report.assess()); // e.g. "text (low confidence)"
```

`analyze(&bytes)`, `analyze_reader(reader)` and `analyze_file(path)` are
shortcuts; `Analyzer` also implements `std::io::Write`, so `io::copy` works.

### Finding packed or encrypted regions

```rust
use rune_entropy::{high_entropy_regions, RegionOptions};

let data = std::fs::read("firmware.bin")?;
let options = RegionOptions { threshold: 7.2, ..RegionOptions::default() };
for region in high_entropy_regions(&data, &options)? {
    println!(
        "{:#010x}..{:#010x}  {} bytes  mean {:.3}",
        region.start, region.end, region.len(), region.mean_entropy
    );
}
```

For files too large to load, build the profile from a stream and filter it
with any condition:

```rust
use rune_entropy::{profile_file, regions_where};
use std::path::Path;

let profile = profile_file(Path::new("disk.img"), 4096, 1024)?;
let zero_fill = regions_where(&profile, |e| e < 0.5, 64 * 1024);
```

## Reading the numbers

| Shannon (bits/byte) | `EntropyClass`     | Typical content |
|---------------------|--------------------|-----------------|
| 0.0 – 3.0           | `Low`              | padding, zero fill, sparse tables |
| 3.0 – 5.5           | `TextOrStructured` | prose (~4.0–4.7), source code, JSON/XML |
| 5.5 – 7.0           | `BinaryOrEncoded`  | machine code (~5.5–6.5), base64 (≤ 6.0) |
| 7.0 – 8.0           | `High`             | compressed, encrypted, random, packed |

Some caveats:

- **Short inputs score low.** 256 perfectly random bytes average about 7.17,
  1 KiB about 7.81. `random_entropy_baseline(n)` tells you what to expect, so
  you can pick thresholds that fit your window size.
- **Shannon entropy can't tell compression from encryption.** The chi-square
  test often can: on a few kilobytes or more, compressed data usually fails it
  (p < 0.001) while ciphertext passes. `Analysis::assess` uses this, together
  with serial correlation, to choose between `HighEntropy` and `RandomLike`.
  Small compressed chunks can still pass as random.
- **Text means ASCII.** UTF-8 text in non-Latin scripts reads as binary.

## CLI

```bash
rune-entropy suspicious.bin                # summary for one file
rune-entropy *.bin                         # one line per file
rune-entropy --stats sample.bin            # every statistic, like `ent`
rune-entropy --block-size 4096 fw.bin      # non-overlapping blocks
rune-entropy --window 1024 --step 256 fw.bin   # sliding-window profile
rune-entropy --regions fw.bin              # high-entropy byte ranges only
rune-entropy --regions -t 7.5 --min-len 8192 fw.bin
rune-entropy --json --regions fw.bin       # machine-readable output
cat data.bin | rune-entropy -              # stdin
```

```
$ rune-entropy --stats archive.gz
file:           archive.gz
size:           26389 bytes
entropy:        7.9905 / 8.0  [####################]  high
verdict:        high-entropy (high confidence)
min-entropy:    7.5177
chi-square:     349.17 (p = 0.0001; random data: ~255, p well above 0.001)
mean:           125.6596 (random: 127.5)
serial corr.:   0.015243 (random: 0.0)
monte carlo pi: 3.166894 (error 0.81%)
distinct bytes: 256
printable:      38.6%
```

```
$ rune-entropy --regions image.bin
file:           image.bin
size:           6000000 bytes
entropy:        1.9759 / 8.0  [#####...............]  low
verdict:        repetitive (high confidence)
regions:
  0x002dc700..0x003d0900      999936 bytes  mean 7.8094  max 7.8663
```

Unreadable files are reported on stderr and the rest are still processed; the
exit code is 1 if any file failed.

## Migrating from 0.3

- `EntropyClass` has new variants and thresholds that match real data better
  (English text scores 4–4.7, which 0.3 called "structured"):
  `Plaintext` → `Low` (< 3.0), `Structured` → `TextOrStructured` (3.0–5.5),
  `CompressedOrCode` → `BinaryOrEncoded` (5.5–7.0),
  `EncryptedOrRandom` → `High` (≥ 7.0). Display strings changed with them.
- `file_block_entropy` with a zero block size now returns an
  `InvalidInput` error instead of panicking. `file_entropy` and
  `file_block_entropy` now stream instead of reading the whole file.
- The CLI prints a verdict line and the new class labels, and keeps going
  after an unreadable file (exit code 1 at the end).
- `entropy`, `block_entropy` and `classify` keep their signatures.

## License

MIT
