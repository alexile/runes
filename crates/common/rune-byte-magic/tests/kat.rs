//! Known-answer table for every supported signature.
//!
//! Each sample is the start of a real file of that type, as laid down by the
//! format's specification. The table checks the full header, every
//! truncation of it, and that trailing data never changes the answer.

use rune_byte_magic::{FileType, SAMPLE_LEN, identify};

/// `(type, header bytes, source)`.
const KAT: &[(FileType, &[u8], &str)] = &[
    (
        FileType::Elf,
        b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00",
        "ELF gABI: e_ident, ET_DYN, EM_X86_64",
    ),
    (
        FileType::Pe,
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
        "PE/COFF: MS-DOS stub header",
    ),
    (
        FileType::MachO,
        b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00",
        "mach-o/loader.h: MH_CIGAM_64 (arm64)",
    ),
    (
        FileType::MachO,
        b"\xce\xfa\xed\xfe\x07\x00\x00\x00",
        "mach-o/loader.h: MH_CIGAM (i386)",
    ),
    (
        FileType::MachO,
        b"\xfe\xed\xfa\xce\x00\x00\x00\x12",
        "mach-o/loader.h: MH_MAGIC (ppc)",
    ),
    (
        FileType::MachO,
        b"\xfe\xed\xfa\xcf\x01\x00\x00\x12",
        "mach-o/loader.h: MH_MAGIC_64 (ppc64)",
    ),
    (
        FileType::MachOFat,
        b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07",
        "mach-o/fat.h: FAT_MAGIC, 2 archs",
    ),
    (
        FileType::MachOFat,
        b"\xca\xfe\xba\xbf\x00\x00\x00\x02\x01\x00\x00\x07",
        "mach-o/fat.h: FAT_MAGIC_64, 2 archs",
    ),
    (
        FileType::Dex,
        b"dex\n035\x00",
        "Dalvik dex-format: DEX_FILE_MAGIC v035",
    ),
    (
        FileType::Wasm,
        b"\x00asm\x01\x00\x00\x00",
        "WebAssembly core spec 5.5.16: magic + version 1",
    ),
    (
        FileType::JavaClass,
        b"\xca\xfe\xba\xbe\x00\x00\x00\x34",
        "JVMS 4.1: class file, Java 8 (52.0)",
    ),
    (
        FileType::JavaClass,
        b"\xca\xfe\xba\xbe\x00\x00\x00\x45",
        "JVMS 4.1: class file, Java 25 (69.0)",
    ),
    (
        FileType::Zip,
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
        "APPNOTE 4.3.7: local file header",
    ),
    (
        FileType::Zip,
        b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00",
        "APPNOTE 4.3.16: empty archive (EOCD)",
    ),
    (
        FileType::Gzip,
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",
        "RFC 1952 2.3.1: ID1 ID2 CM=deflate",
    ),
    (
        FileType::Bzip2,
        b"BZh91AY&SY",
        "bzip2: stream header, 900k blocks, block magic",
    ),
    (
        FileType::Xz,
        b"\xfd7zXZ\x00\x00\x04",
        "XZ file format 2.1.1.1: header magic",
    ),
    (
        FileType::Zstd,
        b"\x28\xb5\x2f\xfd\x24\x00",
        "RFC 8878 3.1.1: zstd frame magic",
    ),
    (
        FileType::Lz4,
        b"\x04\x22\x4d\x18\x64\x40\xa7",
        "LZ4 frame format: magic 0x184D2204",
    ),
    (FileType::Rar, b"Rar!\x1a\x07\x00", "RAR 4.x marker block"),
    (FileType::Rar, b"Rar!\x1a\x07\x01\x00", "RAR 5.0 signature"),
    (
        FileType::SevenZip,
        b"7z\xbc\xaf\x27\x1c\x00\x04",
        "7z format: signature header",
    ),
    (
        FileType::Pdf,
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
        "ISO 32000-1 7.5.2: file header",
    ),
    (
        FileType::Ole2,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00",
        "MS-CFB 2.2: header signature",
    ),
    (
        FileType::Png,
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR",
        "PNG spec 5.2: signature + IHDR",
    ),
    (
        FileType::Jpeg,
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
        "JFIF: SOI + APP0",
    ),
    (
        FileType::Jpeg,
        b"\xff\xd8\xff\xe1\x00\x18Exif\x00\x00",
        "Exif: SOI + APP1",
    ),
    (FileType::Gif, b"GIF87a\x01\x00\x01\x00", "GIF87a header"),
    (FileType::Gif, b"GIF89a\x01\x00\x01\x00", "GIF89a header"),
    (
        FileType::Bmp,
        b"BM\x3a\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00",
        "BITMAPFILEHEADER",
    ),
    (
        FileType::Tiff,
        b"II*\x00\x08\x00\x00\x00",
        "TIFF 6.0: little-endian header",
    ),
    (
        FileType::Tiff,
        b"MM\x00*\x00\x00\x00\x08",
        "TIFF 6.0: big-endian header",
    ),
    (
        FileType::Ico,
        b"\x00\x00\x01\x00\x01\x00\x10\x10",
        "ICONDIR: type 1, one image",
    ),
    (
        FileType::Webp,
        b"RIFF\x24\x00\x00\x00WEBPVP8 ",
        "RIFF container, WEBP form",
    ),
    (
        FileType::Mp3,
        b"ID3\x04\x00\x00\x00\x00\x00\x00",
        "ID3v2.4 header",
    ),
    (
        FileType::Mp3,
        b"ID3\x03\x00\x00\x00\x00\x00\x00",
        "ID3v2.3 header",
    ),
    (
        FileType::Ogg,
        b"OggS\x00\x02\x00\x00",
        "RFC 3533 6: capture pattern",
    ),
    (
        FileType::Mp4,
        b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00",
        "ISO/IEC 14496-12 4.3: ftyp box",
    ),
    (
        FileType::Mp4,
        b"\x00\x00\x00\x14ftypqt  ",
        "QuickTime ftyp box",
    ),
    (
        FileType::Sqlite,
        b"SQLite format 3\x00\x10\x00\x01\x01",
        "SQLite file format 1.3: header string",
    ),
    (FileType::Script, b"#!/bin/sh\necho hi\n", "POSIX shebang"),
    (
        FileType::Text,
        b"[package]\nname = \"x\"\n",
        "plain ASCII text",
    ),
    (
        FileType::Text,
        "gr\u{fc}\u{df} dich \u{1F600}\n".as_bytes(),
        "UTF-8 text",
    ),
];

/// A POSIX ustar header: member name, then "ustar\0" "00" at offset 257.
fn tar_header() -> Vec<u8> {
    let mut header = vec![0u8; 512];
    header[..9].copy_from_slice(b"hello.txt");
    header[100..108].copy_from_slice(b"0000644\0");
    header[257..265].copy_from_slice(b"ustar\x0000");
    header
}

#[test]
fn every_signature_is_identified() {
    for (expected, header, source) in KAT {
        assert_eq!(identify(header), *expected, "{source}");
    }
    assert_eq!(identify(&tar_header()), FileType::Tar, "POSIX.1-1988 ustar");
}

#[test]
fn trailing_data_does_not_change_the_answer() {
    let suffixes: [&[u8]; 4] = [b"", b"\x00\x00\x00\x00", b"\xff\xfe", &[0x41; 600]];
    for (expected, header, source) in KAT {
        if *expected == FileType::Text {
            continue; // a binary suffix legitimately turns text into Unknown
        }
        for suffix in suffixes {
            let mut bytes = header.to_vec();
            bytes.extend_from_slice(suffix);
            assert_eq!(
                identify(&bytes),
                *expected,
                "{source} + {} bytes",
                suffix.len()
            );
        }
    }
    let mut tar = tar_header();
    tar.extend_from_slice(&[0xab; 4096]);
    assert_eq!(identify(&tar), FileType::Tar);
}

#[test]
fn every_truncation_is_handled() {
    let tar = tar_header();
    let samples = KAT.iter().map(|(_, header, _)| *header).chain([&tar[..]]);
    for header in samples {
        for len in 0..=header.len() {
            let file_type = identify(&header[..len]);
            assert_ne!(file_type.name(), "");
        }
    }
}

#[test]
fn every_variant_has_metadata_and_one_category() {
    let mut all: Vec<FileType> = KAT.iter().map(|(t, _, _)| *t).collect();
    all.extend([FileType::Tar, FileType::Unknown]);
    for file_type in all {
        assert_ne!(file_type.name(), "");
        assert!(file_type.mime_type().contains('/'));
        assert_ne!(file_type.extension(), "");
        let categories = [
            file_type.is_executable(),
            file_type.is_archive(),
            file_type.is_document(),
            file_type.is_image(),
        ];
        assert!(
            categories.iter().filter(|&&c| c).count() <= 1,
            "{file_type:?}"
        );
    }
}

#[test]
fn sample_len_bounds_inspection() {
    let mut bytes = vec![b'a'; SAMPLE_LEN];
    assert_eq!(identify(&bytes), FileType::Text);
    bytes.extend_from_slice(&[0, 1, 2, 3]);
    assert_eq!(identify(&bytes), FileType::Text);
}
