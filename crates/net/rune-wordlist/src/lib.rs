//! Versioned, Ed25519-signed wordlist and payload packs, loaded with
//! streaming, tamper-checked iteration and rollback-safe updates.
//!
//! A **pack** is a directory holding list files (one entry per line), a
//! TOML manifest `pack.toml` that pins each file's SHA-256 and size, and
//! `pack.toml.sig`, a detached [Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
//! signature over the manifest. Loading a pack:
//!
//! 1. checks the signature against a [`Keyring`] of trusted public keys
//!    *before* parsing the manifest ([`verify_manifest`]);
//! 2. optionally hashes every list up front ([`Verify::Eager`], the default);
//! 3. streams lists line by line through a [`ListReader`] that hashes as it
//!    reads and fails on any byte that differs from the manifest, using one
//!    fixed-size buffer however large the list is.
//!
//! A [`Store`] keeps installed packs by version; [`Store::install`] is the
//! update command (verify, refuse rollbacks, stage, swap atomically).
//! [`PackBuilder`] hashes list files and signs the manifest for authors.
//!
//! # Example
//!
//! ```
//! use rune_wordlist::{Keyring, ListKind, Options, Pack, PackBuilder, SecretKey, Version};
//!
//! let dir = tempfile::tempdir()?;
//! std::fs::write(dir.path().join("dirs.txt"), "admin\nbackup\n.git\n")?;
//!
//! // The author signs the pack...
//! let key = SecretKey::from_seed(&[7; 32]);
//! PackBuilder::new("web", Version::new(1, 0, 0))?
//!     .list("dirs", "dirs.txt", ListKind::Wordlist)?
//!     .write(dir.path(), &key)?;
//!
//! // ...and the consumer only trusts the author's public key.
//! let keyring = Keyring::new().with_key(key.public_key());
//! let pack = Pack::open(dir.path(), &keyring, &Options::default())?;
//! let words = pack.list("dirs")?.lines().collect::<Result<Vec<_>, _>>()?;
//! assert_eq!(words, ["admin", "backup", ".git"]);
//!
//! // Any change to a list is caught.
//! std::fs::write(dir.path().join("dirs.txt"), "admin\nbackdoor\n.git\n")?;
//! assert!(Pack::open(dir.path(), &keyring, &Options::default()).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod author;
mod error;
mod hex;
mod manifest;
mod pack;
mod reader;
mod sign;
mod store;
mod version;

pub use author::PackBuilder;
pub use error::{Error, Result};
pub use manifest::{FORMAT, ListEntry, ListKind, Manifest, validate_name, validate_path};
pub use pack::{MANIFEST_FILE, Options, Pack, SIGNATURE_FILE, Verify, verify_manifest};
pub use reader::{Lines, ListReader, ReadOptions, hash_reader, sha256, verify_reader};
pub use sign::{KeyId, Keyring, PublicKey, SIGNING_CONTEXT, SecretKey, Signature};
pub use store::{InstallOptions, Store, UpdateOutcome, plan_update};
pub use version::Version;
