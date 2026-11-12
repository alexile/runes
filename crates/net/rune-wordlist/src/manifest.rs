//! The pack manifest (`pack.toml`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, KeyId, Version, hex};

/// The manifest format this crate reads and writes.
pub const FORMAT: u32 = 1;

/// What a list holds. Informational: every list is read the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ListKind {
    /// Words for discovery and enumeration (paths, parameters, subdomains).
    #[default]
    Wordlist,
    /// Attack payloads for fuzzing.
    Payload,
}

/// One list in a pack: a newline-separated file named by a relative path,
/// pinned by its SHA-256 and size.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListEntry {
    /// Name used to open the list, `[a-z0-9._-]`.
    pub name: String,
    /// Path of the file, relative to the pack directory, `/`-separated.
    pub path: String,
    /// What the list holds.
    pub kind: ListKind,
    /// SHA-256 of the file's bytes.
    pub sha256: [u8; 32],
    /// Size of the file in bytes.
    pub size: u64,
    /// Number of lines, if the author recorded it.
    pub entries: Option<u64>,
    /// Free-form description.
    pub description: Option<String>,
}

impl ListEntry {
    /// An entry; `sha256` and `size` come from the file's contents.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        sha256: [u8; 32],
        size: u64,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            kind: ListKind::Wordlist,
            sha256,
            size,
            entries: None,
            description: None,
        }
    }

    /// Sets the kind.
    #[must_use]
    pub const fn with_kind(mut self, kind: ListKind) -> Self {
        self.kind = kind;
        self
    }

    /// Records the number of lines.
    #[must_use]
    pub const fn with_entries(mut self, entries: u64) -> Self {
        self.entries = Some(entries);
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// The file's location under `root`. The path was validated when the
    /// manifest was parsed, so it never leaves `root`.
    #[must_use]
    pub fn file_in(&self, root: &Path) -> PathBuf {
        self.path
            .split('/')
            .fold(root.to_path_buf(), |p, c| p.join(c))
    }
}

/// A pack manifest: identity, version, signing key and the pinned lists.
///
/// ```toml
/// format = 1
/// name = "web-discovery"
/// version = "1.4.0"
/// key-id = "8a1c0f2d4e6b7a90"
///
/// [[lists]]
/// name = "dirs"
/// path = "lists/dirs.txt"
/// kind = "wordlist"
/// sha256 = "…64 hex digits…"
/// size = 1048576
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    /// Pack name, `[a-z0-9._-]`; also its directory name in a [`Store`](crate::Store).
    pub name: String,
    /// Pack version.
    pub version: Version,
    /// Id of the key that signs the manifest.
    pub key_id: KeyId,
    /// Free-form description.
    pub description: Option<String>,
    /// The lists, in manifest order.
    pub lists: Vec<ListEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawManifest {
    format: u32,
    name: String,
    version: String,
    key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default)]
    lists: Vec<RawList>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawList {
    name: String,
    path: String,
    #[serde(default)]
    kind: ListKind,
    sha256: String,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl Manifest {
    /// An empty manifest.
    pub fn new(name: impl Into<String>, version: Version, key_id: KeyId) -> Result<Self, Error> {
        let name = name.into();
        validate_name(&name)?;
        Ok(Self {
            name,
            version,
            key_id,
            description: None,
            lists: Vec::new(),
        })
    }

    /// Parses and validates manifest bytes. Call this only on bytes whose
    /// signature has been checked; [`Pack::open`](crate::Pack::open) does both.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|e| Error::Manifest(e.to_string()))?;
        let raw: RawManifest =
            toml::from_str(text).map_err(|e| Error::Manifest(e.message().to_owned()))?;
        if raw.format != FORMAT {
            return Err(Error::UnsupportedFormat(raw.format));
        }
        validate_name(&raw.name)?;
        let mut seen = HashSet::new();
        let mut lists = Vec::with_capacity(raw.lists.len());
        for l in raw.lists {
            validate_name(&l.name)?;
            validate_path(&l.path)?;
            if !seen.insert(l.name.clone()) {
                return Err(Error::DuplicateList(l.name));
            }
            lists.push(ListEntry {
                sha256: hex::decode(&l.sha256, "sha256")?,
                name: l.name,
                path: l.path,
                kind: l.kind,
                size: l.size,
                entries: l.entries,
                description: l.description,
            });
        }
        Ok(Self {
            version: raw.version.parse()?,
            key_id: KeyId::from_hex(&raw.key_id)?,
            name: raw.name,
            description: raw.description,
            lists,
        })
    }

    /// Writes the manifest as TOML, the bytes that get signed. Fails if a
    /// name or path is invalid or two lists share a name, so whatever this
    /// writes, [`parse`](Self::parse) reads back.
    pub fn to_toml(&self) -> Result<String, Error> {
        validate_name(&self.name)?;
        let mut seen = HashSet::new();
        for l in &self.lists {
            validate_name(&l.name)?;
            validate_path(&l.path)?;
            if !seen.insert(&l.name) {
                return Err(Error::DuplicateList(l.name.clone()));
            }
        }
        let raw = RawManifest {
            format: FORMAT,
            name: self.name.clone(),
            version: self.version.to_string(),
            key_id: self.key_id.to_string(),
            description: self.description.clone(),
            lists: self
                .lists
                .iter()
                .map(|l| RawList {
                    name: l.name.clone(),
                    path: l.path.clone(),
                    kind: l.kind,
                    sha256: hex::encode(&l.sha256),
                    size: l.size,
                    entries: l.entries,
                    description: l.description.clone(),
                })
                .collect(),
        };
        toml::to_string(&raw).map_err(|e| Error::Manifest(e.to_string()))
    }

    /// The list with this name.
    #[must_use]
    pub fn list(&self, name: &str) -> Option<&ListEntry> {
        self.lists.iter().find(|l| l.name == name)
    }
}

/// Checks a pack or list name: 1-64 characters from `[a-z0-9._-]`, starting
/// with a letter or digit (so it is always a safe directory name).
pub fn validate_name(name: &str) -> Result<(), Error> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidName(name.to_owned()))
    }
}

/// Checks a list path: relative, `/`-separated, no empty, `.` or `..`
/// components, and no characters that change meaning across platforms.
pub fn validate_path(path: &str) -> Result<(), Error> {
    let ok = !path.is_empty()
        && path.len() <= 1024
        && path.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && !c
                    .bytes()
                    .any(|b| b.is_ascii_control() || matches!(b, b'\\' | b':'))
        });
    if ok {
        Ok(())
    } else {
        Err(Error::UnsafePath(path.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        let mut m = Manifest::new("web", Version::new(1, 2, 3), KeyId([0xab; 8])).unwrap();
        m.description = Some("Web \"discovery\" lists".into());
        m.lists.push(
            ListEntry::new("dirs", "lists/dirs.txt", [1; 32], 42)
                .with_entries(7)
                .with_description("Directories"),
        );
        m.lists
            .push(ListEntry::new("xss", "xss.txt", [2; 32], 0).with_kind(ListKind::Payload));
        m
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let text = m.to_toml().unwrap();
        assert!(text.starts_with("format = 1\n"), "{text}");
        assert_eq!(Manifest::parse(text.as_bytes()).unwrap(), m);
    }

    #[test]
    fn rejects_bad_manifests() {
        let good = sample().to_toml().unwrap();
        let cases = [
            (good.replace("format = 1", "format = 2"), "format"),
            (good.replace("lists/dirs.txt", "../dirs.txt"), "path"),
            (good.replace("lists/dirs.txt", "/etc/passwd"), "path"),
            (good.replace("lists/dirs.txt", "C:\\\\x"), "path"),
            (good.replace("name = \"xss\"", "name = \"dirs\""), "dup"),
            (good.replace("name = \"web\"", "name = \"Web\""), "name"),
            (good.replace("1.2.3", "1.2"), "version"),
            (format!("{good}\nextra = 1\n"), "unknown field"),
        ];
        for (text, what) in cases {
            assert!(Manifest::parse(text.as_bytes()).is_err(), "{what}: {text}");
        }
        assert!(Manifest::parse(b"\xff").is_err());
    }

    #[test]
    fn names_and_paths() {
        for ok in ["a", "web-content", "v1.2_x", "0day"] {
            validate_name(ok).unwrap();
        }
        for bad in ["", "-a", ".a", "A", "a b", "a/b", &"a".repeat(65)] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
        for ok in ["a.txt", "lists/a.txt", "a/b/c..txt"] {
            validate_path(ok).unwrap();
        }
        for bad in [
            "", "/a", "a/", "a//b", "./a", "a/../b", "..", "a\\b", "c:x", "a\nb",
        ] {
            assert!(validate_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn file_in_joins_components() {
        let e = ListEntry::new("d", "lists/d.txt", [0; 32], 0);
        assert_eq!(e.file_in(Path::new("/p")), Path::new("/p/lists/d.txt"));
    }
}
