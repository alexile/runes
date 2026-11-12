//! Opening and verifying packs on disk.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::reader::verify_reader;
use crate::{Error, Keyring, ListEntry, ListReader, Manifest, ReadOptions, Signature};

/// File name of the manifest inside a pack directory.
pub const MANIFEST_FILE: &str = "pack.toml";
/// File name of the manifest's detached signature.
pub const SIGNATURE_FILE: &str = "pack.toml.sig";

/// When list contents are checked against the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Verify {
    /// Hash every list when the pack is opened (one streaming pass each, so
    /// constant memory), and again while reading. A tampered list is
    /// rejected before any of its lines is used.
    #[default]
    Eager,
    /// Only hash while reading: a tampered list is reported at its end.
    /// Opening is instant, which suits large packs read once.
    Lazy,
}

/// Settings for [`Pack::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// When list contents are checked. Default [`Verify::Eager`].
    pub verify: Verify,
    /// How lists are read.
    pub read: ReadOptions,
    /// Largest accepted manifest in bytes. Default 1 MiB.
    pub max_manifest_len: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            verify: Verify::Eager,
            read: ReadOptions::default(),
            max_manifest_len: 1024 * 1024,
        }
    }
}

impl Options {
    /// Sets [`verify`](Self::verify).
    #[must_use]
    pub const fn with_verify(mut self, verify: Verify) -> Self {
        self.verify = verify;
        self
    }

    /// Sets [`read`](Self::read).
    #[must_use]
    pub const fn with_read(mut self, read: ReadOptions) -> Self {
        self.read = read;
        self
    }

    /// Sets [`max_manifest_len`](Self::max_manifest_len).
    #[must_use]
    pub const fn with_max_manifest_len(mut self, max: u64) -> Self {
        self.max_manifest_len = max;
        self
    }
}

/// Checks raw manifest bytes against their signature file and a keyring,
/// then parses them. This is the sans-I/O core of [`Pack::open`].
///
/// The signature is checked before the manifest is parsed, so the parser
/// only ever sees authenticated bytes: the signature must verify with one of
/// the keyring's keys, and the manifest's `key-id` must name that key.
///
/// ```
/// use rune_wordlist::{KeyId, Keyring, Manifest, SecretKey, Version, verify_manifest};
///
/// let key = SecretKey::from_seed(&[42; 32]);
/// let manifest = Manifest::new("demo", Version::new(1, 0, 0), key.public_key().id())?;
/// let bytes = manifest.to_toml()?;
/// let sig = key.sign(bytes.as_bytes()).to_string();
///
/// let keyring = Keyring::new().with_key(key.public_key());
/// assert_eq!(verify_manifest(bytes.as_bytes(), &sig, &keyring)?, manifest);
///
/// let forged = bytes.replace("1.0.0", "9.0.0");
/// assert!(verify_manifest(forged.as_bytes(), &sig, &keyring).is_err());
/// # Ok::<(), rune_wordlist::Error>(())
/// ```
pub fn verify_manifest(
    manifest: &[u8],
    signature: &str,
    keyring: &Keyring,
) -> Result<Manifest, Error> {
    let signature = Signature::parse(signature)?;
    let signer = keyring.signer_of(manifest, &signature)?;
    let parsed = Manifest::parse(manifest)?;
    if parsed.key_id != signer {
        return Err(Error::UnknownKey(parsed.key_id.to_string()));
    }
    Ok(parsed)
}

/// A signed pack opened from a directory: `pack.toml`, `pack.toml.sig` and
/// the list files it names.
#[derive(Debug, Clone)]
pub struct Pack {
    root: PathBuf,
    manifest: Manifest,
    options: Options,
}

impl Pack {
    /// Opens the pack in `dir`: reads the manifest and signature, verifies
    /// the signature with `keyring`, and (with [`Verify::Eager`]) hashes
    /// every list.
    pub fn open(
        dir: impl AsRef<Path>,
        keyring: &Keyring,
        options: &Options,
    ) -> Result<Self, Error> {
        let root = dir.as_ref().to_path_buf();
        let manifest_path = root.join(MANIFEST_FILE);
        let manifest_bytes =
            read_limited(&manifest_path, options.max_manifest_len).and_then(|b| {
                b.ok_or(Error::ManifestTooLarge {
                    max: options.max_manifest_len,
                })
            })?;
        let sig_path = root.join(SIGNATURE_FILE);
        let sig = read_limited(&sig_path, 4096)?
            .ok_or_else(|| Error::SignatureFormat("signature file is too large".to_owned()))?;
        let sig = String::from_utf8(sig)
            .map_err(|_| Error::SignatureFormat("signature file is not UTF-8".to_owned()))?;
        let manifest = verify_manifest(&manifest_bytes, &sig, keyring)?;
        let pack = Self {
            root,
            manifest,
            options: options.clone(),
        };
        if options.verify == Verify::Eager {
            pack.verify_all()?;
        }
        Ok(pack)
    }

    /// The verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The pack directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Opens a list for streaming. The reader checks the contents against
    /// the manifest as it goes, whatever the [`Verify`] mode, so a file
    /// swapped after the pack was opened is still caught.
    pub fn list(&self, name: &str) -> Result<ListReader<File>, Error> {
        let entry = self.entry(name)?;
        let path = entry.file_in(&self.root);
        let file = File::open(&path).map_err(|e| Error::io(path, e))?;
        Ok(ListReader::new(file, entry, &self.options.read))
    }

    /// Hashes one list and checks it against the manifest.
    pub fn verify_list(&self, name: &str) -> Result<(), Error> {
        let entry = self.entry(name)?;
        let path = entry.file_in(&self.root);
        let file = File::open(&path).map_err(|e| Error::io(path, e))?;
        verify_reader(file, entry)
    }

    /// Hashes every list and checks it against the manifest.
    pub fn verify_all(&self) -> Result<(), Error> {
        self.manifest
            .lists
            .iter()
            .try_for_each(|l| self.verify_list(&l.name))
    }

    fn entry(&self, name: &str) -> Result<&ListEntry, Error> {
        self.manifest
            .list(name)
            .ok_or_else(|| Error::NoSuchList(name.to_owned()))
    }
}

/// Reads at most `max` bytes; `None` if the file is larger.
pub fn read_limited(path: &Path, max: u64) -> Result<Option<Vec<u8>>, Error> {
    let file = File::open(path).map_err(|e| Error::io(path, e))?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(path, e))?;
    Ok((buf.len() as u64 <= max).then_some(buf))
}
