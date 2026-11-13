//! Versioned, checksummed snapshot format.
//!
//! Layout (all integers little-endian):
//!
//! | Field              | Size        | Notes                                    |
//! | ------------------ | ----------- | ---------------------------------------- |
//! | magic              | 8           | `RVSTORE\0`                              |
//! | version            | 4           | `1`                                      |
//! | metric             | 1           | 0 cosine, 1 dot, 2 Euclidean             |
//! | index              | 1           | 0 flat, 1 HNSW                           |
//! | reserved           | 2           | zero                                     |
//! | dimension          | 4           | 0 while unset                            |
//! | HNSW params        | 20          | `m`, `ef_construction`, `ef_search` (u32), `seed` (u64); zero for flat |
//! | record count       | 8           |                                          |
//! | records            | …           | see below                                |
//! | CRC-32             | 4           | IEEE, over every preceding byte          |
//!
//! Each record is `id_len: u32`, `id` (UTF-8), `dimension` × `f32`,
//! `content_len: u32`, `content` (UTF-8), `meta_len: u32`, `meta` (a JSON
//! object). HNSW graphs are not stored: loading re-inserts the records with
//! the saved parameters and seed, which rebuilds the same graph and means a
//! hostile file can never smuggle in a malformed one.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::{HnswParams, IndexKind, Options, Record, StoreError, VectorIndex};

const MAGIC: &[u8; 8] = b"RVSTORE\0";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 8 + 4 + 1 + 1 + 2 + 4 + 20 + 8;
const CRC_LEN: usize = 4;
/// Hard upper bounds on HNSW parameters read from a file, whatever the
/// [`LoadLimits`] say.
const MAX_M: u32 = 1024;
const MAX_EF: u32 = 1 << 20;

/// Size limits enforced while loading a snapshot, so a corrupt or hostile
/// file cannot exhaust memory.
///
/// Every limit is checked *before* the corresponding allocation. The defaults
/// suit large single-process stores; tighten them for untrusted input.
///
/// An HNSW snapshot is rebuilt on load with the `m` and `ef_construction`
/// stored in the file, and large values make the rebuild far slower (a 40 KB
/// file with `m = 1024` used to take seconds). [`LoadLimits::max_m`] and
/// [`LoadLimits::max_ef_construction`] cap them; the defaults sit well above
/// any sensible build setting. Load time still grows with the number of
/// records, so keep [`LoadLimits::max_bytes`] tight for untrusted files.
///
/// # Example
///
/// ```
/// use rune_vectorstore::LoadLimits;
///
/// let limits = LoadLimits::default()
///     .with_max_bytes(64 << 20)
///     .with_max_records(100_000);
/// assert_eq!(limits.max_records, 100_000);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoadLimits {
    /// Largest snapshot accepted, in bytes. Default 1 GiB.
    pub max_bytes: u64,
    /// Most records accepted. Default 10 million.
    pub max_records: u64,
    /// Largest vector dimension accepted. Default 65 536.
    pub max_dimension: u32,
    /// Largest single id, content or metadata field, in bytes. Default 64 MiB.
    pub max_field_bytes: u32,
    /// Largest HNSW `m` accepted. Default 128.
    pub max_m: u32,
    /// Largest HNSW `ef_construction` accepted. Default 4096.
    pub max_ef_construction: u32,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1 << 30,
            max_records: 10_000_000,
            max_dimension: 65_536,
            max_field_bytes: 64 << 20,
            max_m: 128,
            max_ef_construction: 4096,
        }
    }
}

impl LoadLimits {
    /// Set [`LoadLimits::max_bytes`].
    #[must_use]
    pub const fn with_max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = n;
        self
    }

    /// Set [`LoadLimits::max_records`].
    #[must_use]
    pub const fn with_max_records(mut self, n: u64) -> Self {
        self.max_records = n;
        self
    }

    /// Set [`LoadLimits::max_dimension`].
    #[must_use]
    pub const fn with_max_dimension(mut self, n: u32) -> Self {
        self.max_dimension = n;
        self
    }

    /// Set [`LoadLimits::max_field_bytes`].
    #[must_use]
    pub const fn with_max_field_bytes(mut self, n: u32) -> Self {
        self.max_field_bytes = n;
        self
    }

    /// Set [`LoadLimits::max_m`]. Values above 1024 are still rejected.
    ///
    /// ```
    /// use rune_vectorstore::LoadLimits;
    ///
    /// assert_eq!(LoadLimits::default().with_max_m(256).max_m, 256);
    /// ```
    #[must_use]
    pub const fn with_max_m(mut self, n: u32) -> Self {
        self.max_m = n;
        self
    }

    /// Set [`LoadLimits::max_ef_construction`]. Values above 2^20 are still
    /// rejected.
    ///
    /// ```
    /// use rune_vectorstore::LoadLimits;
    ///
    /// let limits = LoadLimits::default().with_max_ef_construction(8192);
    /// assert_eq!(limits.max_ef_construction, 8192);
    /// ```
    #[must_use]
    pub const fn with_max_ef_construction(mut self, n: u32) -> Self {
        self.max_ef_construction = n;
        self
    }
}

fn invalid(msg: impl Into<String>) -> StoreError {
    StoreError::InvalidSnapshot(msg.into())
}

fn to_u32(n: usize, what: &str) -> Result<u32, StoreError> {
    u32::try_from(n).map_err(|_| invalid(format!("{what} does not fit the format ({n})")))
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<(), StoreError> {
    out.extend_from_slice(&to_u32(bytes.len(), what)?.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Serialise `index` into the snapshot format.
pub fn encode(index: &dyn VectorIndex) -> Result<Vec<u8>, StoreError> {
    let kind = index.kind().unwrap_or_default();
    let dim = index.dimension().unwrap_or(0);
    let mut out = Vec::with_capacity(HEADER_LEN + index.len() * (dim * 4 + 64) + CRC_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(index.metric().tag());
    let params = match kind {
        IndexKind::Flat => {
            out.push(0);
            None
        }
        IndexKind::Hnsw(p) => {
            out.push(1);
            Some(p)
        }
    };
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&to_u32(dim, "dimension")?.to_le_bytes());
    match params {
        Some(p) => {
            out.extend_from_slice(&to_u32(p.m, "m")?.to_le_bytes());
            out.extend_from_slice(&to_u32(p.ef_construction, "ef_construction")?.to_le_bytes());
            out.extend_from_slice(&to_u32(p.ef_search, "ef_search")?.to_le_bytes());
            out.extend_from_slice(&p.seed.to_le_bytes());
        }
        None => out.extend_from_slice(&[0; 20]),
    }
    out.extend_from_slice(&(index.len() as u64).to_le_bytes());
    for r in index.records() {
        put_bytes(&mut out, r.id.as_bytes(), "id length")?;
        for x in &r.vector {
            out.extend_from_slice(&x.to_le_bytes());
        }
        put_bytes(&mut out, r.content.as_bytes(), "content length")?;
        let meta = serde_json::to_vec(&r.metadata)
            .map_err(|e| invalid(format!("metadata of {:?}: {e}", r.id)))?;
        put_bytes(&mut out, &meta, "metadata length")?;
    }
    let crc = rune_crc32::checksum(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

/// Bounds-checked little-endian reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| invalid("truncated"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let mut a = [0; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn field(&mut self, limits: &LoadLimits, what: &'static str) -> Result<&'a [u8], StoreError> {
        let len = self.u32()?;
        if len > limits.max_field_bytes {
            return Err(StoreError::LimitExceeded {
                what,
                limit: u64::from(limits.max_field_bytes),
                actual: u64::from(len),
            });
        }
        self.take(len as usize)
    }

    fn string(&mut self, limits: &LoadLimits, what: &'static str) -> Result<String, StoreError> {
        let bytes = self.field(limits, what)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| invalid(format!("{what} is not UTF-8")))
    }
}

/// Parse a snapshot and rebuild its index.
pub fn decode(bytes: &[u8], limits: &LoadLimits) -> Result<Box<dyn VectorIndex>, StoreError> {
    let size = bytes.len() as u64;
    if size > limits.max_bytes {
        return Err(StoreError::LimitExceeded {
            what: "snapshot size in bytes",
            limit: limits.max_bytes,
            actual: size,
        });
    }
    if bytes.len() < HEADER_LEN + CRC_LEN {
        return Err(invalid("too short to be a snapshot"));
    }
    if &bytes[..8] != MAGIC {
        return Err(invalid("not a vector-store snapshot (bad magic)"));
    }
    let (body, crc) = bytes.split_at(bytes.len() - CRC_LEN);
    let mut r = Reader { buf: body, pos: 8 };
    let version = r.u32()?;
    if version != VERSION {
        return Err(invalid(format!(
            "format version {version} is not supported (expected {VERSION})"
        )));
    }
    let mut stored = [0; CRC_LEN];
    stored.copy_from_slice(crc);
    if rune_crc32::checksum(body) != u32::from_le_bytes(stored) {
        return Err(invalid("checksum mismatch"));
    }

    let metric = crate::Metric::from_tag(r.u8()?).ok_or_else(|| invalid("unknown metric"))?;
    let index_tag = r.u8()?;
    if r.array::<2>()? != [0, 0] {
        return Err(invalid("reserved header bytes are not zero"));
    }
    let dim = r.u32()?;
    if dim > limits.max_dimension {
        return Err(StoreError::LimitExceeded {
            what: "vector dimension",
            limit: u64::from(limits.max_dimension),
            actual: u64::from(dim),
        });
    }
    let (m, efc, efs, seed) = (r.u32()?, r.u32()?, r.u32()?, r.u64()?);
    let kind = match index_tag {
        0 => IndexKind::Flat,
        1 => {
            if m > MAX_M || efc > MAX_EF || efs > MAX_EF {
                return Err(invalid("HNSW parameters out of range"));
            }
            for (what, limit, actual) in [
                ("HNSW m", limits.max_m, m),
                ("HNSW ef_construction", limits.max_ef_construction, efc),
            ] {
                if actual > limit {
                    return Err(StoreError::LimitExceeded {
                        what,
                        limit: u64::from(limit),
                        actual: u64::from(actual),
                    });
                }
            }
            IndexKind::Hnsw(
                HnswParams::default()
                    .with_m(m as usize)
                    .with_ef_construction(efc as usize)
                    .with_ef_search(efs as usize)
                    .with_seed(seed),
            )
        }
        _ => return Err(invalid("unknown index kind")),
    };
    let count = r.u64()?;
    if count > limits.max_records {
        return Err(StoreError::LimitExceeded {
            what: "record count",
            limit: limits.max_records,
            actual: count,
        });
    }
    if dim == 0 && count > 0 {
        return Err(invalid("records present but no dimension set"));
    }
    let dim = dim as usize;
    // Each record takes at least its three length prefixes and its vector.
    let min_record = 12 + dim * 4;
    let fits = r.remaining() / min_record;
    if count > fits as u64 {
        return Err(invalid("record count exceeds the data present"));
    }
    let mut records = Vec::with_capacity(usize::try_from(count).map_or(fits, |c| c.min(fits)));
    for _ in 0..count {
        let id = r.string(limits, "id length")?;
        let vector = r
            .take(dim * 4)?
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes(*c))
            .collect();
        let content = r.string(limits, "content length")?;
        let meta = r.field(limits, "metadata length")?;
        let metadata = match serde_json::from_slice::<Value>(meta) {
            Ok(Value::Object(map)) => map.into_iter().collect(),
            Ok(_) => return Err(invalid(format!("metadata of {id:?} is not an object"))),
            Err(e) => return Err(invalid(format!("metadata of {id:?}: {e}"))),
        };
        records.push(Record {
            id,
            vector,
            content,
            metadata,
        });
    }
    if r.remaining() != 0 {
        return Err(invalid("trailing bytes after the last record"));
    }

    let mut options = Options::default().with_metric(metric).with_index(kind);
    if dim > 0 {
        options = options.with_dimension(dim);
    }
    let mut index = options.build_index();
    index
        .upsert(records)
        .map_err(|e| invalid(format!("bad record: {e}")))?;
    Ok(index)
}

/// Read at most `limits.max_bytes` from `path`.
pub fn read_limited(path: &Path, limits: &LoadLimits) -> Result<Vec<u8>, StoreError> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    let too_big = |actual| StoreError::LimitExceeded {
        what: "snapshot size in bytes",
        limit: limits.max_bytes,
        actual,
    };
    if len > limits.max_bytes {
        return Err(too_big(len));
    }
    let mut buf = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    // The file may grow between the size check and the read.
    file.take(limits.max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > limits.max_bytes {
        return Err(too_big(buf.len() as u64));
    }
    Ok(buf)
}

/// Write `bytes` to `path` atomically: a temporary file in the same
/// directory is written, flushed to disk and renamed over `path`, so readers
/// see either the old file or the complete new one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .ok_or_else(|| invalid(format!("{} has no file name", path.display())))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        // Make the rename itself durable.
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(result?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlatIndex, HnswIndex, Metric, Query};

    fn sample() -> FlatIndex {
        let mut idx = FlatIndex::new(Metric::Euclidean);
        idx.upsert(vec![
            Record::new("a", vec![1.0, 2.0])
                .with_content("alpha")
                .with_meta("n", 1)
                .with_meta("tags", serde_json::json!(["x", "y"])),
            Record::new("b", vec![-3.0, 0.5]),
        ])
        .unwrap();
        idx
    }

    #[test]
    fn round_trip_flat_and_hnsw() {
        let flat = sample();
        let bytes = encode(&flat).unwrap();
        let back = decode(&bytes, &LoadLimits::default()).unwrap();
        assert_eq!(back.kind(), Some(IndexKind::Flat));
        assert_eq!(back.metric(), Metric::Euclidean);
        assert_eq!(back.get("a"), flat.get("a"));
        assert_eq!(back.get("b"), flat.get("b"));

        let params = HnswParams::default().with_m(8).with_seed(42);
        let mut h = HnswIndex::with_dimension(Metric::Cosine, params, 2);
        h.upsert(flat.records().cloned().collect()).unwrap();
        let back = decode(&encode(&h).unwrap(), &LoadLimits::default()).unwrap();
        assert_eq!(back.kind(), Some(IndexKind::Hnsw(params)));
        assert_eq!(back.len(), 2);
        let q = Query::new(vec![1.0, 2.0], 1);
        assert_eq!(back.query(&q).unwrap()[0].record.id, "a");
    }

    #[test]
    fn empty_index_round_trips() {
        let empty = FlatIndex::new(Metric::Cosine);
        let back = decode(&encode(&empty).unwrap(), &LoadLimits::default()).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.dimension(), None);
        let fixed = FlatIndex::with_dimension(Metric::Cosine, 7);
        let back = decode(&encode(&fixed).unwrap(), &LoadLimits::default()).unwrap();
        assert_eq!(back.dimension(), Some(7));
    }

    fn reseal(bytes: &mut Vec<u8>) {
        bytes.truncate(bytes.len() - CRC_LEN);
        let crc = rune_crc32::checksum(bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn rejects_corruption() {
        let good = encode(&sample()).unwrap();
        let lim = LoadLimits::default();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x41;
            assert!(decode(&bad, &lim).is_err(), "flip at {i} accepted");
        }
        for n in 0..good.len() {
            assert!(
                decode(&good[..n], &lim).is_err(),
                "truncation to {n} accepted"
            );
        }
        let mut v2 = good.clone();
        v2[8] = 2;
        reseal(&mut v2);
        assert!(
            matches!(decode(&v2, &lim), Err(StoreError::InvalidSnapshot(m)) if m.contains("version"))
        );
        let mut trailing = good.clone();
        trailing.insert(good.len() - CRC_LEN, 0);
        reseal(&mut trailing);
        assert!(decode(&trailing, &lim).is_err());
    }

    #[test]
    fn rejects_nan_vectors_and_duplicate_ids_in_files() {
        let mut bytes = encode(&sample()).unwrap();
        // First record: id_len (4) + "a" (1), then the first f32.
        let at = HEADER_LEN + 5;
        bytes[at..at + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        reseal(&mut bytes);
        assert!(decode(&bytes, &LoadLimits::default()).is_err());

        let mut idx = FlatIndex::new(Metric::Cosine);
        idx.upsert(vec![
            Record::new("a", vec![1.0]),
            Record::new("b", vec![1.0]),
        ])
        .unwrap();
        let mut bytes = encode(&idx).unwrap();
        let pos = bytes.iter().rposition(|&b| b == b'b').unwrap();
        bytes[pos] = b'a';
        reseal(&mut bytes);
        assert!(decode(&bytes, &LoadLimits::default()).is_err());
    }

    /// A small HNSW snapshot with the given build parameters: `n` records of
    /// dimension 2, empty content and `{}` metadata.
    fn hnsw_snapshot(m: u32, efc: u32, n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&[2, 1, 0, 0]);
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&m.to_le_bytes());
        out.extend_from_slice(&efc.to_le_bytes());
        out.extend_from_slice(&64u32.to_le_bytes());
        out.extend_from_slice(&7u64.to_le_bytes());
        out.extend_from_slice(&u64::from(n).to_le_bytes());
        for i in 0..n {
            let id = format!("{i:x}");
            out.extend_from_slice(&u32::try_from(id.len()).unwrap().to_le_bytes());
            out.extend_from_slice(id.as_bytes());
            #[allow(clippy::cast_precision_loss)]
            let x = i as f32;
            out.extend_from_slice(&x.sin().to_le_bytes());
            out.extend_from_slice(&x.cos().to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&2u32.to_le_bytes());
            out.extend_from_slice(b"{}");
        }
        let crc = rune_crc32::checksum(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    #[test]
    fn hostile_hnsw_parameters_are_rejected_before_the_rebuild() {
        // About 38 KB; with these parameters the rebuild used to take seconds.
        let hostile = hnsw_snapshot(MAX_M, MAX_EF, 1_500);
        assert!(hostile.len() < 40_000);
        let start = std::time::Instant::now();
        let Err(err) = decode(&hostile, &LoadLimits::default()) else {
            panic!("hostile snapshot loaded");
        };
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert!(
            matches!(
                err,
                StoreError::LimitExceeded {
                    what: "HNSW m",
                    limit: 128,
                    actual: 1024
                }
            ),
            "{err:?}"
        );

        let wide_ef = hnsw_snapshot(16, MAX_EF, 1);
        assert!(matches!(
            decode(&wide_ef, &LoadLimits::default()),
            Err(StoreError::LimitExceeded {
                what: "HNSW ef_construction",
                ..
            })
        ));
        // Raising the limits lets them through.
        let lim = LoadLimits::default()
            .with_max_m(MAX_M)
            .with_max_ef_construction(MAX_EF);
        assert_eq!(decode(&wide_ef, &lim).unwrap().len(), 1);
        // Parameters at the default caps still load.
        assert_eq!(
            decode(&hnsw_snapshot(128, 4096, 3), &LoadLimits::default())
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn hostile_headers_hit_limits_before_allocating() {
        let good = encode(&sample()).unwrap();
        // Claim a billion records.
        let mut huge = good.clone();
        huge[HEADER_LEN - 8..HEADER_LEN].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        reseal(&mut huge);
        assert!(matches!(
            decode(&huge, &LoadLimits::default()),
            Err(StoreError::LimitExceeded {
                what: "record count",
                ..
            })
        ));
        assert!(matches!(
            decode(&huge, &LoadLimits::default().with_max_records(u64::MAX)),
            Err(StoreError::InvalidSnapshot(_))
        ));
        // Claim a huge dimension.
        let mut wide = good.clone();
        wide[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut wide);
        assert!(matches!(
            decode(&wide, &LoadLimits::default()),
            Err(StoreError::LimitExceeded {
                what: "vector dimension",
                ..
            })
        ));
        // Claim a 4 GiB id.
        let mut long = good.clone();
        long[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut long);
        assert!(matches!(
            decode(&long, &LoadLimits::default()),
            Err(StoreError::LimitExceeded {
                what: "id length",
                ..
            })
        ));
        assert!(decode(&long, &LoadLimits::default().with_max_field_bytes(u32::MAX)).is_err());
        // Whole-file cap.
        assert!(matches!(
            decode(&good, &LoadLimits::default().with_max_bytes(10)),
            Err(StoreError::LimitExceeded { .. })
        ));
        // Absurd HNSW parameters.
        let mut h = HnswIndex::new(Metric::Cosine, HnswParams::default());
        h.upsert(vec![Record::new("a", vec![1.0])]).unwrap();
        let mut bad = encode(&h).unwrap();
        bad[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut bad);
        assert!(decode(&bad, &LoadLimits::default()).is_err());
    }
}
