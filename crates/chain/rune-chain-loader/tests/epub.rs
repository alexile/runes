//! EPUB loader. Fixtures are zipped in memory by the tests.

#![cfg(feature = "epub")]
#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::io::{Cursor, Write};

use proptest::prelude::*;
use rune_chain_loader::epub::{self, EpubLoader};
use rune_chain_loader::{DirectoryLoader, Jail, Limits, LoadError};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const CONTAINER: &str = r#"<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>"#;

fn opf(manifest: &str, spine: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="id">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>The  Book &amp; More</dc:title>
    <dc:creator>Jane Roe</dc:creator>
    <dc:creator>John Doe</dc:creator>
  </metadata>
  <manifest>{manifest}</manifest>
  <spine>{spine}</spine>
</package>"#
    )
}

fn xhtml(title: &str, body: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\">\
         <head><title>{title}</title><style>p{{}}</style></head><body>{body}</body></html>"
    )
}

/// Zip `entries` (name, data, deflated?) into an archive.
fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data, deflate) in entries {
        let method = if *deflate {
            CompressionMethod::Deflated
        } else {
            CompressionMethod::Stored
        };
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .large_file(data.len() > u32::MAX as usize);
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// An EPUB with the standard container and the given package and extra
/// entries.
fn epub_with(package: &str, extra: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut entries: Vec<(&str, &[u8], bool)> = vec![
        ("mimetype", b"application/epub+zip", false),
        ("META-INF/container.xml", CONTAINER.as_bytes(), true),
        ("OEBPS/content.opf", package.as_bytes(), true),
    ];
    entries.extend_from_slice(extra);
    zip(&entries)
}

fn sample() -> Vec<u8> {
    let manifest = r#"
      <item id="c1" href="text/ch%201.xhtml" media-type="application/xhtml+xml"/>
      <item id="cover" href="images/cover.jpg" media-type="image/jpeg"/>
      <item id="blank" href="text/blank.xhtml" media-type="application/xhtml+xml"/>
      <item id="c2" href="text/../text/ch2.xhtml#start" media-type="application/xhtml+xml"/>"#;
    let spine = r#"<itemref idref="c1"/><itemref idref="cover"/><itemref idref="blank"/>
                   <itemref idref="missing"/><itemref idref="c2" linear="no"/>"#;
    let ch1 = xhtml("One", "<h1>Chapter 1</h1><p>It was a &amp; dark night.</p>");
    let ch2 = xhtml("", "<p>The end.</p><script>x()</script>");
    let blank = xhtml("Blank", "<p> </p>");
    epub_with(
        &opf(manifest, spine),
        &[
            ("OEBPS/text/ch 1.xhtml", ch1.as_bytes(), true),
            ("OEBPS/text/ch2.xhtml", ch2.as_bytes(), true),
            ("OEBPS/text/blank.xhtml", blank.as_bytes(), true),
            ("OEBPS/images/cover.jpg", &[0xff, 0xd8, 0xff], false),
        ],
    )
}

#[test]
fn chapters_in_spine_order_with_metadata() {
    let docs = epub::load_bytes(&sample(), "book.epub").unwrap();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].content, "Chapter 1\nIt was a & dark night.");
    assert_eq!(docs[1].content, "The end.");
    assert_eq!(docs[0].metadata["chapter"], "1");
    assert_eq!(docs[1].metadata["chapter"], "5");
    assert_eq!(docs[0].metadata["chapter_title"], "One");
    assert!(!docs[1].metadata.contains_key("chapter_title"));
    assert_eq!(docs[0].metadata["entry"], "OEBPS/text/ch 1.xhtml");
    assert_eq!(docs[1].metadata["entry"], "OEBPS/text/ch2.xhtml");
    for doc in &docs {
        assert_eq!(doc.metadata["chapter_count"], "5");
        assert_eq!(doc.metadata["title"], "The Book & More");
        assert_eq!(doc.metadata["author"], "Jane Roe, John Doe");
        assert_eq!(doc.metadata["source"], "book.epub");
        assert_eq!(doc.metadata["content_sha256"], doc.content_sha256());
    }
}

#[test]
fn file_reader_and_bytes_agree() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.epub"), sample()).unwrap();
    let loader = EpubLoader::new().jail(Jail::new(dir.path()).unwrap());
    let from_file = loader.load_file("b.epub").unwrap();
    let from_bytes = loader.load_bytes(&sample(), "b.epub").unwrap();
    let from_reader = loader.load_reader(&sample()[..], "b.epub").unwrap();
    assert_eq!(from_bytes, from_reader);
    assert_eq!(from_file.len(), 2);
    assert_eq!(from_file[1].content, from_bytes[1].content);
}

#[test]
fn malformed_inputs_are_errors() {
    let not_zip = epub::load_bytes(b"PK\x03\x04 nope", "x").unwrap_err();
    assert!(
        matches!(not_zip, LoadError::Malformed { .. }),
        "{not_zip:?}"
    );
    let no_container = zip(&[("mimetype", b"application/epub+zip", false)]);
    assert!(matches!(
        epub::load_bytes(&no_container, "x"),
        Err(LoadError::Malformed { .. })
    ));
    let bad_xml = epub_with("<package><manifest><item id=", &[]);
    assert!(matches!(
        epub::load_bytes(&bad_xml, "x"),
        Err(LoadError::Malformed { .. })
    ));
    let latin1 = epub_with(
        &opf(
            r#"<item id="c" href="c.xhtml" media-type="application/xhtml+xml"/>"#,
            r#"<itemref idref="c"/>"#,
        ),
        &[("OEBPS/c.xhtml", b"<p>caf\xe9</p>", true)],
    );
    assert!(matches!(
        epub::load_bytes(&latin1, "x"),
        Err(LoadError::InvalidUtf8 { .. })
    ));
}

#[test]
fn truncated_and_corrupted_archives_never_panic() {
    let full = sample();
    for len in (0..full.len()).step_by(7) {
        assert!(epub::load_bytes(&full[..len], "x").is_err());
    }
    for i in (0..full.len()).step_by(3) {
        let mut bad = full.clone();
        bad[i] ^= 0xa5;
        let _ = epub::load_bytes(&bad, "x");
    }
}

#[test]
fn zip_bomb_entry_is_refused_by_ratio() {
    let bomb = vec![b' '; 8 << 20];
    let body = xhtml("Bomb", &format!("<p>boom</p>{}", " ".repeat(10)));
    let manifest = r#"<item id="c" href="c.xhtml" media-type="application/xhtml+xml"/>"#;
    let mut chapter = body.into_bytes();
    chapter.extend_from_slice(&bomb);
    let bytes = epub_with(
        &opf(manifest, r#"<itemref idref="c"/>"#),
        &[("OEBPS/c.xhtml", &chapter, true)],
    );
    assert!(bytes.len() < 64 * 1024, "{}", bytes.len());
    let err = epub::load_bytes(&bytes, "x").unwrap_err();
    assert!(
        matches!(&err, LoadError::CompressionRatio { entry, limit: 100 } if entry == "OEBPS/c.xhtml"),
        "{err:?}"
    );
    assert!(err.is_per_file());

    // With the ratio check off, the decompression budget still stops it.
    let limits = Limits::default()
        .with_max_compression_ratio(u64::MAX)
        .with_max_decompressed_bytes(1 << 20);
    let err = EpubLoader::new()
        .limits(limits)
        .load_bytes(&bytes, "x")
        .unwrap_err();
    assert!(
        matches!(err, LoadError::DecompressedTooLarge { limit } if limit == 1 << 20),
        "{err:?}"
    );

    // Trusted input can lift both.
    let docs = EpubLoader::new()
        .limits(Limits::default().with_max_compression_ratio(u64::MAX))
        .load_bytes(&bytes, "x")
        .unwrap();
    assert_eq!(docs[0].content, "boom");
}

#[test]
fn entry_and_chapter_caps() {
    let filler: Vec<(String, Vec<u8>)> = (0..20).map(|i| (format!("f/{i}"), vec![b'x'])).collect();
    let extra: Vec<(&str, &[u8], bool)> = filler
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice(), false))
        .collect();
    let bytes = epub_with(&opf("", ""), &extra);
    let limits = Limits::default().with_max_archive_entries(10);
    assert!(matches!(
        EpubLoader::new().limits(limits).load_bytes(&bytes, "x"),
        Err(LoadError::TooManyEntries { limit: 10 })
    ));

    let limits = Limits::default().with_max_pages(4);
    assert!(matches!(
        EpubLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::TooManyPages { limit: 4 })
    ));
    let limits = Limits::default().with_max_total_bytes(20);
    assert!(matches!(
        EpubLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::OutputTooLarge { limit: 20 })
    ));
    let limits = Limits::default().with_max_file_bytes(64);
    assert!(matches!(
        EpubLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::TooLarge { limit: 64, .. })
    ));
}

#[test]
fn links_cannot_escape_the_archive() {
    for href in [
        "../../etc/passwd",
        "../../../x.xhtml",
        "/etc/passwd",
        "a/%2e%2e/%2e%2e/%2e%2e/x",
    ] {
        let manifest =
            format!(r#"<item id="c" href="{href}" media-type="application/xhtml+xml"/>"#);
        let bytes = epub_with(&opf(&manifest, r#"<itemref idref="c"/>"#), &[]);
        let err = epub::load_bytes(&bytes, "x").unwrap_err();
        assert!(
            matches!(err, LoadError::OutsideRoot { .. }),
            "{href}: {err:?}"
        );
    }
    // External links are ignored.
    let manifest =
        r#"<item id="c" href="https://example.com/x.xhtml" media-type="application/xhtml+xml"/>"#;
    let bytes = epub_with(&opf(manifest, r#"<itemref idref="c"/>"#), &[]);
    assert_eq!(epub::load_bytes(&bytes, "x").unwrap(), Vec::new());
}

#[test]
fn unsafe_entry_names_are_never_read() {
    // The package resolves `x.xhtml` to `OEBPS/x.xhtml`; entries whose raw
    // names would normalise to it via `..`, absolute paths or backslashes
    // must not be picked up.
    let manifest = r#"<item id="c" href="x.xhtml" media-type="application/xhtml+xml"/>"#;
    let page = xhtml("", "<p>evil</p>");
    for name in [
        "OEBPS/a/../x.xhtml",
        "/OEBPS/x.xhtml",
        "OEBPS\\x.xhtml",
        "C:/OEBPS/x.xhtml",
    ] {
        let bytes = epub_with(
            &opf(manifest, r#"<itemref idref="c"/>"#),
            &[(name, page.as_bytes(), true)],
        );
        let docs = epub::load_bytes(&bytes, "x").unwrap();
        assert!(docs.is_empty(), "{name}");
    }
}

#[test]
fn duplicate_entry_names_are_refused() {
    let page = xhtml("", "<p>a</p>");
    let bytes = epub_with(
        &opf("", ""),
        &[
            ("OEBPS/x.xhtml", page.as_bytes(), true),
            ("OEBPS/./x.xhtml", page.as_bytes(), true),
        ],
    );
    let err = epub::load_bytes(&bytes, "x").unwrap_err();
    assert!(
        matches!(err, LoadError::Malformed { ref message, .. } if message.contains("duplicate")),
        "{err:?}"
    );
}

fn encryption_xml(algorithm: &str, uri: &str) -> String {
    format!(
        r#"<encryption xmlns="urn:oasis:names:tc:opendocument:xmlns:container"
            xmlns:enc="http://www.w3.org/2001/04/xmlenc#">
          <enc:EncryptedData>
            <enc:EncryptionMethod Algorithm="{algorithm}"/>
            <enc:CipherData><enc:CipherReference URI="{uri}"/></enc:CipherData>
          </enc:EncryptedData>
        </encryption>"#
    )
}

#[test]
fn drm_chapters_are_refused_but_obfuscated_fonts_are_fine() {
    let manifest = r#"<item id="c" href="c.xhtml" media-type="application/xhtml+xml"/>"#;
    let page = xhtml("", "<p>text</p>");
    let package = opf(manifest, r#"<itemref idref="c"/>"#);
    let drm = encryption_xml(
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
        "OEBPS/c.xhtml",
    );
    let bytes = epub_with(
        &package,
        &[
            ("OEBPS/c.xhtml", page.as_bytes(), true),
            ("META-INF/encryption.xml", drm.as_bytes(), true),
        ],
    );
    assert!(matches!(
        epub::load_bytes(&bytes, "x"),
        Err(LoadError::Encrypted { .. })
    ));

    let fonts = encryption_xml("http://www.idpf.org/2008/embedding", "OEBPS/font.otf");
    let bytes = epub_with(
        &package,
        &[
            ("OEBPS/c.xhtml", page.as_bytes(), true),
            ("META-INF/encryption.xml", fonts.as_bytes(), true),
        ],
    );
    assert_eq!(epub::load_bytes(&bytes, "x").unwrap()[0].content, "text");
}

#[test]
fn zip_encrypted_entries_are_refused() {
    let manifest = r#"<item id="c" href="c.xhtml" media-type="application/xhtml+xml"/>"#;
    let page = xhtml("", "<p>text</p>");
    let mut bytes = epub_with(
        &opf(manifest, r#"<itemref idref="c"/>"#),
        &[("OEBPS/c.xhtml", page.as_bytes(), false)],
    );
    // Set the "encrypted" flag on the chapter's local and central headers.
    let name = b"OEBPS/c.xhtml";
    let mut i = 0;
    while let Some(p) = bytes[i..].windows(name.len()).position(|w| w == name) {
        let at = i + p;
        if bytes[..at].len() >= 30 && bytes[at - 30..at - 26] == *b"PK\x03\x04" {
            bytes[at - 30 + 6] |= 1;
        }
        if bytes[..at].len() >= 46 && bytes[at - 46..at - 42] == *b"PK\x01\x02" {
            bytes[at - 46 + 8] |= 1;
        }
        i = at + 1;
    }
    let err = epub::load_bytes(&bytes, "x").unwrap_err();
    assert!(matches!(err, LoadError::Encrypted { .. }), "{err:?}");
}

#[test]
fn timeout_is_enforced() {
    let limits = Limits::default().with_max_duration(std::time::Duration::ZERO);
    assert!(matches!(
        EpubLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::TimedOut { .. })
    ));
}

#[test]
fn directory_walk_loads_epubs_chapter_by_chapter() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("books")).unwrap();
    std::fs::write(dir.path().join("books/b.epub"), sample()).unwrap();
    std::fs::write(dir.path().join("bad.epub"), b"PK\x03\x04\xff\xff").unwrap();
    let docs = DirectoryLoader::new(dir.path()).load().unwrap();
    assert_eq!(docs.len(), 2);
    assert!(
        docs.iter()
            .all(|d| d.metadata["relative_path"] == "books/b.epub")
    );
    assert!(docs[0].metadata["source"].ends_with("b.epub"));
    let errors = DirectoryLoader::new(dir.path())
        .documents()
        .unwrap()
        .filter(Result::is_err)
        .count();
    assert_eq!(errors, 1);
    let off = DirectoryLoader::new(dir.path()).epub(false).load().unwrap();
    assert_eq!(off, Vec::new());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bytes_never_panic(input in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = epub::load_bytes(&input, "x");
    }

    #[test]
    fn arbitrary_package_xml_never_panics(package in "[<>a-z=\" /&;#0-9]{0,200}") {
        let _ = epub::load_bytes(&epub_with(&package, &[]), "x");
    }
}
