//! PDF loader. Fixtures are built byte by byte in the tests.

#![cfg(feature = "pdf")]
#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::Duration;

use proptest::prelude::*;
use rune_chain_loader::pdf::{self, PdfLoader};
use rune_chain_loader::{DirectoryLoader, Jail, Limits, LoadError};

/// Assemble a PDF from object bodies (numbered from 1) with a valid xref.
fn build(objects: &[Vec<u8>], trailer_extra: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        writeln!(out, "{} 0 obj", i + 1).unwrap();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for offset in offsets {
        writeln!(table, "{offset:010} 00000 n ").unwrap();
    }
    out.extend_from_slice(table.as_bytes());
    write!(
        out,
        "trailer\n<< /Size {} /Root 1 0 R {trailer_extra} >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    )
    .unwrap();
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} {dict} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn content(text: &str) -> Vec<u8> {
    format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET").into_bytes()
}

const FONT: &[u8] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

/// A PDF with one page per content stream; objects 1-5 are the catalog,
/// page tree, font, info dictionary and a spare object (`extra`).
fn pdf_full(contents: &[Vec<u8>], compress: bool, font: &[u8], extra: Vec<u8>) -> Vec<u8> {
    let n = contents.len();
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 6 + 2 * i)).collect();
    let mut objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes(),
        font.to_vec(),
        b"<< /Title (Field Notes) /Author (Ada  Lovelace) >>".to_vec(),
        extra,
    ];
    for (i, data) in contents.iter().enumerate() {
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
                7 + 2 * i
            )
            .into_bytes(),
        );
        objects.push(if compress {
            stream("/Filter /FlateDecode", &deflate(data))
        } else {
            stream("", data)
        });
    }
    build(&objects, "/Info 4 0 R")
}

fn pdf_with(contents: &[Vec<u8>], compress: bool) -> Vec<u8> {
    pdf_full(contents, compress, FONT, b"null".to_vec())
}

fn sample() -> Vec<u8> {
    pdf_with(
        &[content("Hello page one"), Vec::new(), content("Page three")],
        true,
    )
}

#[test]
fn pages_become_documents_with_metadata() {
    let docs = pdf::load_bytes(&sample(), "notes.pdf").unwrap();
    assert_eq!(docs.len(), 2, "the empty page is skipped");
    assert_eq!(docs[0].content, "Hello page one");
    assert_eq!(docs[1].content, "Page three");
    assert_eq!(docs[0].metadata["page"], "1");
    assert_eq!(docs[1].metadata["page"], "3");
    for doc in &docs {
        assert_eq!(doc.metadata["page_count"], "3");
        assert_eq!(doc.metadata["title"], "Field Notes");
        assert_eq!(doc.metadata["author"], "Ada Lovelace");
        assert_eq!(doc.metadata["source"], "notes.pdf");
        assert_eq!(doc.metadata["content_sha256"], doc.content_sha256());
    }
}

#[test]
fn tj_arrays_and_line_operators() {
    let data = b"BT /F1 12 Tf [(Hel) -20 (lo) -300 (world)] TJ T* (next) Tj \
                 0 -14 Td (third) ' ET"
        .to_vec();
    let docs = pdf::load_bytes(&pdf_with(&[data], false), "x").unwrap();
    assert_eq!(docs[0].content, "Hello world\nnext\nthird");
}

#[test]
fn file_reader_and_bytes_agree() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pdf"), sample()).unwrap();
    let loader = PdfLoader::new().jail(Jail::new(dir.path()).unwrap());
    let from_file = loader.load_file("a.pdf").unwrap();
    let from_bytes = loader.load_bytes(&sample(), "a.pdf").unwrap();
    let from_reader = loader.load_reader(&sample()[..], "a.pdf").unwrap();
    assert_eq!(from_bytes, from_reader);
    assert_eq!(from_file.len(), 2);
    assert_eq!(from_file[0].content, from_bytes[0].content);
    assert!(matches!(
        loader.load_file("../a.pdf"),
        Err(LoadError::OutsideRoot { .. } | LoadError::Io { .. })
    ));
}

#[test]
fn garbage_and_empty_input_are_malformed() {
    for input in [&b""[..], b"not a pdf", b"%PDF-1.7\n", &[0xff; 64]] {
        let err = pdf::load_bytes(input, "x").unwrap_err();
        assert!(
            matches!(err, LoadError::Malformed { .. }),
            "{input:?}: {err:?}"
        );
        assert!(err.is_per_file());
    }
}

#[test]
fn truncated_and_corrupted_files_never_panic() {
    let full = sample();
    for len in (0..full.len()).step_by(5) {
        let _ = pdf::load_bytes(&full[..len], "x");
    }
    for i in (0..full.len()).step_by(3) {
        let mut bad = full.clone();
        bad[i] ^= 0x5a;
        let _ = pdf::load_bytes(&bad, "x");
    }
}

#[test]
fn file_size_and_page_caps() {
    let bytes = sample();
    let small = Limits::default().with_max_file_bytes(100);
    assert!(matches!(
        PdfLoader::new().limits(small).load_bytes(&bytes, "x"),
        Err(LoadError::TooLarge { limit: 100, .. })
    ));
    let two = Limits::default().with_max_pages(2);
    assert!(matches!(
        PdfLoader::new().limits(two).load_bytes(&bytes, "x"),
        Err(LoadError::TooManyPages { limit: 2 })
    ));
    let three = Limits::default().with_max_pages(3);
    assert_eq!(
        PdfLoader::new()
            .limits(three)
            .load_bytes(&bytes, "x")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn extracted_text_cap() {
    let limits = Limits::default().with_max_total_bytes(20);
    assert!(matches!(
        PdfLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::OutputTooLarge { limit: 20 })
    ));
    let limits = Limits::default().with_max_total_bytes(24);
    assert!(
        PdfLoader::new()
            .limits(limits)
            .load_bytes(&sample(), "x")
            .is_ok()
    );
}

#[test]
fn page_content_bomb_hits_the_budget() {
    // 4 MiB of operators that deflate to a few KB.
    let mut data = content("bomb");
    data.extend(std::iter::repeat_n(b' ', 4 << 20));
    let bytes = pdf_with(&[data], true);
    assert!(bytes.len() < 64 * 1024);
    let limits = Limits::default().with_max_decompressed_bytes(1 << 20);
    let err = PdfLoader::new()
        .limits(limits)
        .load_bytes(&bytes, "x")
        .unwrap_err();
    assert!(
        matches!(err, LoadError::DecompressedTooLarge { limit } if limit == 1 << 20),
        "{err:?}"
    );
    assert!(PdfLoader::new().load_bytes(&bytes, "x").is_ok());
}

#[test]
fn shared_font_maps_are_charged_once() {
    // Two pages share one font with a 600 KB ToUnicode map; a 1 MiB budget
    // only works if the map is inflated and charged once.
    let mut cmap = b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
                     /CMapName /Test def\n/CMapType 2 def\n\
                     1 begincodespacerange\n<00> <FF>\nendcodespacerange\n\
                     1 beginbfchar\n<41> <0042>\nendbfchar\n"
        .to_vec();
    cmap.extend(std::iter::repeat_n(b' ', 600_000));
    cmap.extend_from_slice(b"\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    let font = b"<< /Type /Font /Subtype /Type1 /ToUnicode 5 0 R >>";
    let bytes = pdf_full(
        &[content("AA"), content("A")],
        true,
        font,
        stream("/Filter /FlateDecode", &deflate(&cmap)),
    );
    let limits = Limits::default().with_max_decompressed_bytes(1 << 20);
    let docs = PdfLoader::new()
        .limits(limits)
        .load_bytes(&bytes, "x")
        .unwrap();
    assert_eq!(docs[0].content, "BB");
    assert_eq!(docs[1].content, "B");
}

#[test]
fn object_stream_bomb_is_refused_while_parsing() {
    let mut bomb = b"5 0 ".to_vec();
    bomb.extend(std::iter::repeat_n(b'0', 8 << 20));
    let objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [] /Count 0 >>".to_vec(),
        stream(
            "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
            &deflate(&bomb),
        ),
    ];
    let bytes = build(&objects, "");
    let limits = Limits::default().with_max_decompressed_bytes(2 << 20);
    let err = PdfLoader::new()
        .limits(limits)
        .load_bytes(&bytes, "x")
        .unwrap_err();
    assert!(
        matches!(err, LoadError::DecompressedTooLarge { .. }),
        "{err:?}"
    );
}

#[test]
fn timeout_is_enforced() {
    let limits = Limits::default().with_max_duration(Duration::ZERO);
    assert!(matches!(
        PdfLoader::new().limits(limits).load_bytes(&sample(), "x"),
        Err(LoadError::TimedOut { .. })
    ));
}

#[test]
fn encrypted_pdfs_are_refused() {
    let mut objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>".to_vec(),
        stream("", &content("secret")),
    ];
    let o = "<".to_string() + &"28BF4E5E4E758A41".repeat(4) + ">";
    let u = "<".to_string() + &"64E1C1A1F0D4E4A9".repeat(4) + ">";
    objects.push(format!("<< /Filter /Standard /V 1 /R 2 /O {o} /U {u} /P -44 >>").into_bytes());
    let bytes = build(
        &objects,
        "/Encrypt 5 0 R /ID [<00112233445566778899AABBCCDDEEFF> <00112233445566778899AABBCCDDEEFF>]",
    );
    let err = pdf::load_bytes(&bytes, "x").unwrap_err();
    assert!(matches!(err, LoadError::Encrypted { .. }), "{err:?}");
    assert!(err.is_per_file());
    assert_eq!(err.to_string(), "document is encrypted");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.pdf");
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        pdf::load_file(&path),
        Err(LoadError::Encrypted { path: Some(p) }) if p == path
    ));
}

#[test]
fn directory_walk_loads_pdfs_page_by_page() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.pdf"), sample()).unwrap();
    std::fs::write(dir.path().join("broken.pdf"), b"%PDF-1.4 \xff\xfe").unwrap();
    std::fs::write(dir.path().join("b.txt"), "plain").unwrap();
    let mut docs = DirectoryLoader::new(dir.path()).load().unwrap();
    docs.sort_by(|a, b| a.content.cmp(&b.content));
    assert_eq!(docs.len(), 3);
    assert_eq!(docs[0].content, "Hello page one");
    assert_eq!(docs[0].metadata["relative_path"], "a.pdf");
    assert_eq!(docs[0].metadata["page"], "1");
    assert!(docs[0].metadata["source"].ends_with("a.pdf"));
    assert_eq!(docs[2].content, "plain");

    let errors: Vec<_> = DirectoryLoader::new(dir.path())
        .documents()
        .unwrap()
        .filter_map(Result::err)
        .collect();
    assert_eq!(errors.len(), 1);
    assert!(
        matches!(&errors[0], LoadError::Malformed { path: Some(p), .. } if p.ends_with("broken.pdf"))
    );

    let off = DirectoryLoader::new(dir.path()).pdf(false).load().unwrap();
    assert_eq!(off.len(), 1, "PDFs read as text are skipped as not UTF-8");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bytes_never_panic(mut input in prop::collection::vec(any::<u8>(), 0..512), header in any::<bool>()) {
        if header {
            input.splice(0..0, b"%PDF-1.4\n".iter().copied());
        }
        let _ = pdf::load_bytes(&input, "x");
    }
}
