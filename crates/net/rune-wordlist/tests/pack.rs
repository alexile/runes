//! End-to-end tests over signed packs on disk: the committed sample pack,
//! tampering of every part, lazy verification and store updates.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::fs;
use std::path::{Path, PathBuf};

use rune_wordlist::{
    Error, InstallOptions, Keyring, ListKind, Options, Pack, PackBuilder, PublicKey, ReadOptions,
    SecretKey, Store, UpdateOutcome, Verify, Version,
};

/// Public key of the seed `[0x42; 32]` that signed `tests/fixtures/sample-pack`.
const SAMPLE_PUBKEY: &str = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-pack")
}

fn sample_keyring() -> Keyring {
    Keyring::new().with_key(PublicKey::from_hex(SAMPLE_PUBKEY).unwrap())
}

/// Copies a directory tree (the fixture) somewhere it can be tampered with.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn tampered_copy() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("pack");
    copy_tree(&fixture(), &dir);
    (tmp, dir)
}

#[test]
fn sample_key_matches_its_seed() {
    let key = SecretKey::from_seed(&[0x42; 32]);
    assert_eq!(key.public_key().to_hex(), SAMPLE_PUBKEY);
}

#[test]
fn loads_signed_sample_pack() {
    let pack = Pack::open(fixture(), &sample_keyring(), &Options::default()).unwrap();
    let m = pack.manifest();
    assert_eq!(m.name, "sample");
    assert_eq!(m.version, Version::new(1, 0, 0));
    assert_eq!(m.lists.len(), 3);
    assert_eq!(m.list("xss").unwrap().kind, ListKind::Payload);

    let dirs: Vec<String> = pack
        .list("dirs")
        .unwrap()
        .lines()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(dirs.len(), 6);
    assert_eq!(dirs[0], "admin");
    assert_eq!(
        u64::try_from(dirs.len()).ok(),
        m.list("dirs").unwrap().entries
    );

    // CRLF payloads come back without the line ending; '#' is data by default.
    let xss: Vec<String> = pack
        .list("xss")
        .unwrap()
        .lines()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(xss[0], "<script>alert(1)</script>");
    assert!(xss[2].starts_with('#'));

    let opts = Options::default().with_read(ReadOptions::default().with_skip_comments(true));
    let pack = Pack::open(fixture(), &sample_keyring(), &opts).unwrap();
    assert_eq!(pack.list("dirs").unwrap().count(), 5);
    assert!(matches!(pack.list("nope"), Err(Error::NoSuchList(_))));
}

#[test]
fn rejects_tampered_list() {
    let (_tmp, dir) = tampered_copy();
    fs::write(dir.join("lists/dirs.txt"), "admin\nbackdoor\n").unwrap();
    let err = Pack::open(&dir, &sample_keyring(), &Options::default()).unwrap_err();
    assert!(
        matches!(err, Error::Tampered { ref list, .. } if list == "dirs"),
        "{err}"
    );

    // Same-size change: only the hash catches it.
    let original = fs::read(fixture().join("lists/params.txt")).unwrap();
    let mut flipped = original;
    flipped[0] ^= 0x20;
    fs::write(
        dir.join("lists/dirs.txt"),
        fs::read(fixture().join("lists/dirs.txt")).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("lists/params.txt"), &flipped).unwrap();
    let err = Pack::open(&dir, &sample_keyring(), &Options::default()).unwrap_err();
    assert!(
        matches!(err, Error::Tampered { ref list, .. } if list == "params"),
        "{err}"
    );
}

#[test]
fn lazy_mode_reports_tampering_at_end_of_list() {
    let (_tmp, dir) = tampered_copy();
    fs::write(
        dir.join("lists/params.txt"),
        "id\nredirect\nnext\ncallbacX\n",
    )
    .unwrap();
    let lazy = Options::default().with_verify(Verify::Lazy);
    let pack = Pack::open(&dir, &sample_keyring(), &lazy).unwrap();
    let items: Vec<_> = pack.list("params").unwrap().collect();
    assert_eq!(items.len(), 5);
    assert!(items[..4].iter().all(Result::is_ok));
    assert!(matches!(items[4], Err(Error::Tampered { .. })));
    // Untouched lists still read cleanly in lazy mode.
    assert!(pack.list("dirs").unwrap().all(|r| r.is_ok()));
}

#[test]
fn list_swapped_after_open_is_caught() {
    let (_tmp, dir) = tampered_copy();
    let pack = Pack::open(&dir, &sample_keyring(), &Options::default()).unwrap();
    fs::write(dir.join("lists/dirs.txt"), "evil\n").unwrap();
    let r: Result<Vec<_>, _> = pack.list("dirs").unwrap().collect();
    assert!(matches!(r, Err(Error::Tampered { .. })));
}

#[test]
fn rejects_tampered_manifest_and_signature() {
    type Edit = fn(&str) -> String;
    let edits: [(&str, Edit); 4] = [
        ("version bump", |m| m.replace("1.0.0", "9.0.0")),
        ("hash swap", |m| m.replace("5a9fe33b", "5a9fe33c")),
        ("whitespace", |m| format!("{m}\n")),
        ("path change", |m| {
            m.replace("lists/dirs.txt", "lists/params.txt")
        }),
    ];
    for (what, edit) in edits {
        let (_tmp, dir) = tampered_copy();
        let m = fs::read_to_string(dir.join("pack.toml")).unwrap();
        fs::write(dir.join("pack.toml"), edit(&m)).unwrap();
        let err = Pack::open(&dir, &sample_keyring(), &Options::default()).unwrap_err();
        assert!(matches!(err, Error::BadSignature), "{what}: {err}");
    }

    let (_tmp, dir) = tampered_copy();
    fs::write(
        dir.join("pack.toml.sig"),
        format!("ed25519:{}\n", "00".repeat(64)),
    )
    .unwrap();
    assert!(matches!(
        Pack::open(&dir, &sample_keyring(), &Options::default()),
        Err(Error::BadSignature)
    ));
    fs::write(dir.join("pack.toml.sig"), "garbage").unwrap();
    assert!(matches!(
        Pack::open(&dir, &sample_keyring(), &Options::default()),
        Err(Error::SignatureFormat(_))
    ));
    fs::remove_file(dir.join("pack.toml.sig")).unwrap();
    assert!(matches!(
        Pack::open(&dir, &sample_keyring(), &Options::default()),
        Err(Error::Io { .. })
    ));
}

#[test]
fn rejects_untrusted_and_resigned_packs() {
    // Nobody trusted: fails.
    assert!(matches!(
        Pack::open(fixture(), &Keyring::new(), &Options::default()),
        Err(Error::BadSignature)
    ));
    // An attacker re-signs a modified pack with their own key: still fails
    // against the real keyring.
    let (_tmp, dir) = tampered_copy();
    fs::write(dir.join("lists/dirs.txt"), "evil\n").unwrap();
    let attacker = SecretKey::from_seed(&[0x66; 32]);
    PackBuilder::new("sample", Version::new(1, 0, 1))
        .unwrap()
        .list("dirs", "lists/dirs.txt", ListKind::Wordlist)
        .unwrap()
        .write(&dir, &attacker)
        .unwrap();
    assert!(matches!(
        Pack::open(&dir, &sample_keyring(), &Options::default()),
        Err(Error::BadSignature)
    ));
    // A manifest whose key-id lies about the (trusted) signer is refused.
    let trusted = SecretKey::from_seed(&[0x42; 32]);
    let ring = sample_keyring().with_key(attacker.public_key());
    let manifest = fs::read_to_string(dir.join("pack.toml")).unwrap();
    fs::write(
        dir.join("pack.toml.sig"),
        trusted.sign(manifest.as_bytes()).to_string(),
    )
    .unwrap();
    assert!(matches!(
        Pack::open(&dir, &ring, &Options::default()),
        Err(Error::UnknownKey(_))
    ));
}

#[test]
fn oversized_manifest_is_refused() {
    let opts = Options::default().with_max_manifest_len(16);
    assert!(matches!(
        Pack::open(fixture(), &sample_keyring(), &opts),
        Err(Error::ManifestTooLarge { max: 16 })
    ));
}

fn build_version(dir: &Path, key: &SecretKey, version: Version, words: &str) {
    fs::create_dir_all(dir.join("lists")).unwrap();
    fs::write(dir.join("lists/words.txt"), words).unwrap();
    PackBuilder::new("words", version)
        .unwrap()
        .list("words", "lists/words.txt", ListKind::Wordlist)
        .unwrap()
        .write(dir, key)
        .unwrap();
}

#[test]
fn store_installs_upgrades_and_refuses_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed(&[9; 32]);
    let ring = Keyring::new().with_key(key.public_key());
    let (v1, v2) = (Version::new(1, 0, 0), Version::new(1, 1, 0));
    let src1 = tmp.path().join("src1");
    let src2 = tmp.path().join("src2");
    build_version(&src1, &key, v1, "a\nb\n");
    build_version(&src2, &key, v2, "a\nb\nc\n");
    // Stray files in the source are not copied.
    fs::write(src2.join("README"), "not in the manifest").unwrap();

    let store = Store::new(tmp.path().join("store"));
    let opts = InstallOptions::default();
    assert_eq!(store.installed("words").unwrap(), None);
    assert!(matches!(
        store.open("words", &ring, &Options::default()),
        Err(Error::NotInstalled(_))
    ));

    assert_eq!(
        store.install(&src1, &ring, &opts).unwrap(),
        UpdateOutcome::Installed { version: v1 }
    );
    assert_eq!(
        store.install(&src2, &ring, &opts).unwrap(),
        UpdateOutcome::Upgraded { from: v1, to: v2 }
    );
    assert!(!store.root().join("words/1.1.0/README").exists());
    let pack = store.open("words", &ring, &Options::default()).unwrap();
    assert_eq!(pack.list("words").unwrap().count(), 3);

    // Rollback to an old, validly signed version is refused...
    assert!(matches!(
        store.install(&src1, &ring, &opts),
        Err(Error::NotNewer { .. })
    ));
    assert_eq!(store.installed("words").unwrap(), Some(v2));
    // ...unless explicitly allowed.
    let force = InstallOptions::default().with_allow_downgrade(true);
    assert_eq!(
        store.install(&src1, &ring, &force).unwrap(),
        UpdateOutcome::Replaced { from: v2, to: v1 }
    );
    assert_eq!(store.installed("words").unwrap(), Some(v1));
    // Reinstalling the same version replaces it in place.
    assert!(store.install(&src1, &ring, &force).is_ok());

    assert_eq!(store.prune("words").unwrap(), [v2]);
    assert!(!store.root().join("words/1.1.0").exists());
}

#[test]
fn store_rejects_tampered_update_and_keeps_current() {
    let tmp = tempfile::tempdir().unwrap();
    let key = SecretKey::from_seed(&[9; 32]);
    let ring = Keyring::new().with_key(key.public_key());
    let src1 = tmp.path().join("src1");
    let src2 = tmp.path().join("src2");
    build_version(&src1, &key, Version::new(1, 0, 0), "a\n");
    build_version(&src2, &key, Version::new(2, 0, 0), "a\nb\n");
    fs::write(src2.join("lists/words.txt"), "a\nX\n").unwrap();

    let store = Store::new(tmp.path().join("store"));
    store
        .install(&src1, &ring, &InstallOptions::default())
        .unwrap();
    assert!(matches!(
        store.install(&src2, &ring, &InstallOptions::default()),
        Err(Error::Tampered { .. })
    ));
    assert_eq!(
        store.installed("words").unwrap(),
        Some(Version::new(1, 0, 0))
    );
    assert!(!store.root().join("words/2.0.0").exists());

    // Tampering with the installed copy is caught when it is opened.
    fs::write(store.root().join("words/1.0.0/lists/words.txt"), "z\n").unwrap();
    assert!(store.open("words", &ring, &Options::default()).is_err());
}
