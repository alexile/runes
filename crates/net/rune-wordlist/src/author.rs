//! Building and signing packs.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::pack::{MANIFEST_FILE, SIGNATURE_FILE};
use crate::reader::hash_reader;
use crate::{
    Error, ListEntry, ListKind, Manifest, SecretKey, Version, validate_name, validate_path,
};

/// Builds a pack from list files already in a directory: hashes each one,
/// writes `pack.toml` and signs it into `pack.toml.sig`.
///
/// ```no_run
/// use rune_wordlist::{ListKind, PackBuilder, SecretKey, Version};
///
/// let key = SecretKey::from_hex(&std::fs::read_to_string("signing.key")?)?;
/// let manifest = PackBuilder::new("web-discovery", Version::new(1, 4, 0))?
///     .description("Paths and parameters for content discovery")
///     .list("dirs", "lists/dirs.txt", ListKind::Wordlist)?
///     .list("xss", "payloads/xss.txt", ListKind::Payload)?
///     .write("packs/web-discovery", &key)?;
/// assert_eq!(manifest.lists.len(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct PackBuilder {
    name: String,
    version: Version,
    description: Option<String>,
    lists: Vec<(String, String, ListKind)>,
}

impl PackBuilder {
    /// A builder for pack `name` at `version`.
    pub fn new(name: impl Into<String>, version: Version) -> Result<Self, Error> {
        let name = name.into();
        validate_name(&name)?;
        Ok(Self {
            name,
            version,
            description: None,
            lists: Vec::new(),
        })
    }

    /// Sets the pack description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Adds a list file, `path` relative to the pack directory.
    pub fn list(
        mut self,
        name: impl Into<String>,
        path: impl Into<String>,
        kind: ListKind,
    ) -> Result<Self, Error> {
        let (name, path) = (name.into(), path.into());
        validate_name(&name)?;
        validate_path(&path)?;
        if self.lists.iter().any(|(n, _, _)| *n == name) {
            return Err(Error::DuplicateList(name));
        }
        self.lists.push((name, path, kind));
        Ok(self)
    }

    /// Hashes the lists under `dir`, counts their lines, and writes the
    /// signed manifest there. Returns the manifest that was written.
    pub fn write(self, dir: impl AsRef<Path>, key: &SecretKey) -> Result<Manifest, Error> {
        let dir = dir.as_ref();
        let mut manifest = Manifest::new(self.name, self.version, key.public_key().id())?;
        manifest.description = self.description;
        for (name, path, kind) in self.lists {
            let probe = ListEntry::new(name, path, [0; 32], 0);
            let file_path = probe.file_in(dir);
            let file = File::open(&file_path).map_err(|e| Error::io(&file_path, e))?;
            let mut lines = 0u64;
            let mut last = b'\n';
            let counting = CountLines {
                inner: file,
                lines: &mut lines,
                last: &mut last,
            };
            let (sha256, size) = hash_reader(counting).map_err(|e| Error::io(&file_path, e))?;
            if last != b'\n' {
                lines += 1;
            }
            let ListEntry { name, path, .. } = probe;
            manifest.lists.push(
                ListEntry::new(name, path, sha256, size)
                    .with_kind(kind)
                    .with_entries(lines),
            );
        }
        let text = manifest.to_toml()?;
        let sig = key.sign(text.as_bytes());
        write_atomic(&dir.join(MANIFEST_FILE), text.as_bytes())?;
        write_atomic(&dir.join(SIGNATURE_FILE), format!("{sig}\n").as_bytes())?;
        Ok(manifest)
    }
}

/// Counts physical lines (newline bytes) as data passes through.
struct CountLines<'a, R> {
    inner: R,
    lines: &'a mut u64,
    last: &'a mut u8,
}

impl<R: Read> Read for CountLines<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(&last) = buf[..n].last() {
            *self.lines += buf[..n]
                .iter()
                .fold(0, |acc, &b| acc + u64::from(b == b'\n'));
            *self.last = last;
        }
        Ok(n)
    }
}

/// Writes `data` to a temporary sibling, syncs it and renames it over `path`.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut f = File::create(&tmp).map_err(|e| Error::io(&tmp, e))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| Error::io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}
