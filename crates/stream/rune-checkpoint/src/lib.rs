//! Resumable-cursor/offset persistence for restartable stream consumers.
//!
//! A long-running stream consumer needs to remember, per source, how far it got —
//! so a restart resumes instead of replaying from the beginning (or worse, from
//! nowhere). `CheckpointStore` persists a flat `source_id -> offset` map to a single
//! JSON file on disk, writing atomically so a crash mid-write can never leave the
//! store corrupted or half-updated.
//!
//! # Features
//!
//! - [`CheckpointStore::save`] — atomically persist one source's offset (write to a
//!   temp file, then rename over the target).
//! - [`CheckpointStore::load`] — read back a single source's last saved offset.
//! - [`CheckpointStore::load_all`] — read the entire map at once.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_checkpoint::CheckpointStore;
//! use std::env::temp_dir;
//!
//! let path = temp_dir().join("rune-checkpoint-doctest-quickstart.json");
//! let store = CheckpointStore::new(&path);
//!
//! store.save("sensor-1", 1024).unwrap();
//! assert_eq!(store.load("sensor-1").unwrap(), Some(1024));
//! assert_eq!(store.load("sensor-2").unwrap(), None);
//!
//! # std::fs::remove_file(&path).ok();
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-checkpoint --store state.json save sensor-1 1024
//! rune-checkpoint --store state.json load sensor-1
//! rune-checkpoint --store state.json list
//! ```

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A JSON-file-backed store mapping source ids to their last saved offset.
///
/// Each [`save`](CheckpointStore::save) call rewrites the whole file atomically:
/// the new contents are written to a sibling `.tmp` file, then renamed over the
/// target, so a reader (or a crash) never observes a partially written file.
pub struct CheckpointStore {
    path: PathBuf,
}

impl CheckpointStore {
    /// Creates a store backed by the JSON file at `path`. The file is not created
    /// until the first [`save`](CheckpointStore::save) call.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_checkpoint::CheckpointStore;
    ///
    /// let store = CheckpointStore::new("checkpoints.json");
    /// ```
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Persists `offset` for `source_id`, overwriting any previously saved offset
    /// for the same source. Other sources already in the store are preserved.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the existing store can't be read (other than not
    /// existing), or if the temp file can't be written or renamed into place.
    pub fn save(&self, source_id: &str, offset: u64) -> io::Result<()> {
        let mut entries = self.load_all()?;
        entries.insert(source_id.to_string(), offset);
        self.write_all(&entries)
    }

    /// Returns the last saved offset for `source_id`, or `None` if it has never
    /// been saved (or the store file doesn't exist yet).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the store file exists but can't be read or
    /// parsed.
    pub fn load(&self, source_id: &str) -> io::Result<Option<u64>> {
        Ok(self.load_all()?.get(source_id).copied())
    }

    /// Returns every saved `source_id -> offset` entry. Returns an empty map if
    /// the store file doesn't exist yet.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the store file exists but can't be read or
    /// parsed as JSON.
    pub fn load_all(&self) -> io::Result<HashMap<String, u64>> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => {
                let entries: HashMap<String, u64> = serde_json::from_str(&contents)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                Ok(entries)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(err) => Err(err),
        }
    }

    fn write_all(&self, entries: &HashMap<String, u64>) -> io::Result<()> {
        let serialized = serde_json::to_string_pretty(entries)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let tmp_path = tmp_path_for(&self.path);
        fs::write(&tmp_path, serialized)?;
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempStore {
        store: CheckpointStore,
        path: PathBuf,
    }

    impl TempStore {
        fn new(test_name: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "rune-checkpoint-test-{test_name}-{}-{n}.json",
                std::process::id()
            ));
            Self {
                store: CheckpointStore::new(&path),
                path,
            }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            fs::remove_file(&self.path).ok();
            fs::remove_file(tmp_path_for(&self.path)).ok();
        }
    }

    #[test]
    fn save_then_load_round_trip() {
        let t = TempStore::new("round_trip");
        t.store.save("source-a", 42).unwrap();
        assert_eq!(t.store.load("source-a").unwrap(), Some(42));
    }

    #[test]
    fn load_from_nonexistent_store_is_none() {
        let t = TempStore::new("nonexistent");
        assert_eq!(t.store.load("anything").unwrap(), None);
    }

    #[test]
    fn load_all_from_nonexistent_store_is_empty() {
        let t = TempStore::new("nonexistent_all");
        assert!(t.store.load_all().unwrap().is_empty());
    }

    #[test]
    fn saving_twice_overwrites() {
        let t = TempStore::new("overwrite");
        t.store.save("source-a", 1).unwrap();
        t.store.save("source-a", 2).unwrap();
        assert_eq!(t.store.load("source-a").unwrap(), Some(2));
    }

    #[test]
    fn multiple_sources_coexist() {
        let t = TempStore::new("multi");
        t.store.save("source-a", 10).unwrap();
        t.store.save("source-b", 20).unwrap();

        assert_eq!(t.store.load("source-a").unwrap(), Some(10));
        assert_eq!(t.store.load("source-b").unwrap(), Some(20));
    }

    #[test]
    fn load_all_reflects_every_saved_entry() {
        let t = TempStore::new("load_all");
        t.store.save("source-a", 1).unwrap();
        t.store.save("source-b", 2).unwrap();
        t.store.save("source-c", 3).unwrap();

        let all = t.store.load_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all.get("source-a"), Some(&1));
        assert_eq!(all.get("source-b"), Some(&2));
        assert_eq!(all.get("source-c"), Some(&3));
    }

    #[test]
    fn saving_one_source_preserves_others() {
        let t = TempStore::new("preserve");
        t.store.save("source-a", 1).unwrap();
        t.store.save("source-b", 2).unwrap();
        t.store.save("source-a", 99).unwrap();

        assert_eq!(t.store.load("source-a").unwrap(), Some(99));
        assert_eq!(t.store.load("source-b").unwrap(), Some(2));
    }

    #[test]
    fn no_tmp_file_left_behind_after_save() {
        let t = TempStore::new("no_tmp_leftover");
        t.store.save("source-a", 1).unwrap();
        assert!(!tmp_path_for(&t.path).exists());
    }
}
