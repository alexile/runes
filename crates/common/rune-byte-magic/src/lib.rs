//! Identify file types from magic bytes — pure Rust, no libmagic dependency.
//!
//! Inspects the first bytes of a file or byte slice and returns a [`FileType`]
//! describing the format. All detection is purely byte-pattern-based: no
//! external C libraries, no system calls, no `file` binary required.
//!
//! Only the first [`SAMPLE_LEN`] (512) bytes are ever inspected; that is
//! enough for every detection including POSIX TAR (which hides its magic at
//! offset 257). Pass fewer bytes if that is all you have — every check
//! handles short and truncated slices, and [`identify`] never panics on any
//! input.
//!
//! Signatures follow the format specifications (PNG, `GIF89a`, PDF, ZIP
//! APPNOTE, ELF, PE/COFF, Mach-O, WebAssembly, Java class file, bzip2, XZ,
//! Zstandard RFC 8878, LZ4 frame, `ID3v2`, RIFF/WebP, ISO BMFF, SQLite) and
//! are checked against a known-answer table in `tests/kat.rs`.
//!
//! # Features
//!
//! - [`identify`] — detect file type from any byte slice
//! - [`FileType`] — enum covering executables, archives, documents, images, scripts, and more
//! - [`FileType::mime_type`] — standard MIME type string
//! - [`FileType::extension`] — canonical file extension
//! - [`FileType::name`] — human-readable format name
//! - [`FileType::is_executable`] — `true` for ELF, PE, Mach-O, DEX, WASM, Java class
//! - [`FileType::is_archive`] — `true` for ZIP, GZIP, Bzip2, XZ, Zstd, RAR, 7-Zip, TAR
//! - [`FileType::is_document`] — `true` for PDF and OLE2 compound documents
//! - [`FileType::is_image`] — `true` for PNG, JPEG, GIF, BMP, TIFF, ICO, WebP
//!
//! # Quick Start
//!
//! ```rust
//! use rune_byte_magic::{identify, FileType};
//!
//! assert_eq!(identify(b"\x7fELF\x02\x01\x01\x00"), FileType::Elf);
//! assert_eq!(identify(b"MZ\x90\x00"), FileType::Pe);
//! assert_eq!(identify(b"%PDF-1.7"), FileType::Pdf);
//! assert_eq!(identify(b"#! /bin/bash\n"), FileType::Script);
//! assert_eq!(identify(b"hello, world\n"), FileType::Text);
//! assert_eq!(identify(b"\x00\x01\x02\x03"), FileType::Unknown);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-byte-magic file.bin
//! rune-byte-magic file1.bin file2.bin
//! cat file.bin | rune-byte-magic -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

/// The detected type of a file or byte sequence.
///
/// Returned by [`identify`]. Use [`FileType::mime_type`], [`FileType::extension`],
/// and the `is_*` predicate methods to classify files without matching every
/// variant individually.
///
/// # Examples
///
/// ```rust
/// use rune_byte_magic::FileType;
///
/// let ft = FileType::Elf;
/// assert!(ft.is_executable());
/// assert_eq!(ft.mime_type(), "application/x-elf");
/// assert_eq!(ft.extension(), "elf");
/// assert_eq!(ft.name(), "ELF binary");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileType {
    // --- Executables ---
    /// ELF binary (Linux, BSD, embedded systems)
    Elf,
    /// Portable Executable (Windows `.exe`, `.dll`, `.sys`)
    Pe,
    /// Mach-O binary (macOS, iOS — 32 or 64-bit)
    MachO,
    /// Mach-O fat/universal binary (multiple architectures in one file, 32- or
    /// 64-bit fat header)
    MachOFat,
    /// Dalvik Executable (Android `.dex`)
    Dex,
    /// WebAssembly module
    Wasm,
    /// Java bytecode `.class` file
    JavaClass,

    // --- Archives and compressed streams ---
    /// ZIP archive (also `.jar`, `.apk`, `.docx`, `.xlsx`, `.epub`), including
    /// empty and spanned archives
    Zip,
    /// gzip compressed stream
    Gzip,
    /// bzip2 compressed stream
    Bzip2,
    /// XZ compressed stream
    Xz,
    /// Zstandard compressed stream
    Zstd,
    /// LZ4 frame format
    Lz4,
    /// RAR archive
    Rar,
    /// 7-Zip archive
    SevenZip,
    /// POSIX TAR archive (detected via `ustar` magic at offset 257)
    Tar,

    // --- Documents ---
    /// PDF document
    Pdf,
    /// OLE2 compound document (legacy Word, Excel, `PowerPoint`)
    Ole2,

    // --- Images ---
    /// PNG image
    Png,
    /// JPEG image
    Jpeg,
    /// GIF image
    Gif,
    /// BMP image
    Bmp,
    /// TIFF image
    Tiff,
    /// Windows ICO icon
    Ico,
    /// WebP image
    Webp,

    // --- Audio / video ---
    /// MP3 audio (ID3-tagged)
    Mp3,
    /// Ogg container (Vorbis, Opus, Theora)
    Ogg,
    /// MPEG-4 container (`.mp4`, `.m4a`, `.mov`)
    Mp4,

    // --- Database ---
    /// SQLite database
    Sqlite,

    // --- Script ---
    /// Script with a `#!` shebang line
    Script,

    // --- Catch-all ---
    /// Printable text: valid UTF-8 (a sequence cut off at the end of the
    /// sample is allowed) with no binary control bytes
    Text,
    /// Unrecognised binary data
    Unknown,
}

/// Number of leading bytes [`identify`] inspects; later bytes never change
/// the result.
pub const SAMPLE_LEN: usize = 512;

impl FileType {
    /// Standard MIME type for this file type.
    ///
    /// Types without an official IANA registration use an `application/x-*`
    /// vendor or experimental type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert_eq!(FileType::Pdf.mime_type(), "application/pdf");
    /// assert_eq!(FileType::Zip.mime_type(), "application/zip");
    /// assert_eq!(FileType::Elf.mime_type(), "application/x-elf");
    /// assert_eq!(FileType::Unknown.mime_type(), "application/octet-stream");
    /// ```
    #[must_use]
    pub const fn mime_type(self) -> &'static str {
        match self {
            Self::Elf => "application/x-elf",
            Self::Pe => "application/x-dosexec",
            Self::MachO | Self::MachOFat => "application/x-mach-binary",
            Self::Dex => "application/x-dex",
            Self::Wasm => "application/wasm",
            Self::JavaClass => "application/java-vm",
            Self::Zip => "application/zip",
            Self::Gzip => "application/gzip",
            Self::Bzip2 => "application/x-bzip2",
            Self::Xz => "application/x-xz",
            Self::Zstd => "application/zstd",
            Self::Lz4 => "application/x-lz4",
            Self::Rar => "application/vnd.rar",
            Self::SevenZip => "application/x-7z-compressed",
            Self::Tar => "application/x-tar",
            Self::Pdf => "application/pdf",
            Self::Ole2 => "application/x-ole-storage",
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Bmp => "image/bmp",
            Self::Tiff => "image/tiff",
            Self::Ico => "image/x-icon",
            Self::Webp => "image/webp",
            Self::Mp3 => "audio/mpeg",
            Self::Ogg => "audio/ogg",
            Self::Mp4 => "video/mp4",
            Self::Sqlite => "application/x-sqlite3",
            Self::Script => "text/x-shellscript",
            Self::Text => "text/plain",
            Self::Unknown => "application/octet-stream",
        }
    }

    /// Canonical file extension for this type, without the leading dot.
    ///
    /// For types that map to multiple extensions (e.g. `.exe` / `.dll` for PE),
    /// the most common single extension is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert_eq!(FileType::Pe.extension(), "exe");
    /// assert_eq!(FileType::Gzip.extension(), "gz");
    /// assert_eq!(FileType::Jpeg.extension(), "jpg");
    /// ```
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::Pe => "exe",
            Self::MachO | Self::MachOFat => "dylib",
            Self::Dex => "dex",
            Self::Wasm => "wasm",
            Self::JavaClass => "class",
            Self::Zip => "zip",
            Self::Gzip => "gz",
            Self::Bzip2 => "bz2",
            Self::Xz => "xz",
            Self::Zstd => "zst",
            Self::Lz4 => "lz4",
            Self::Rar => "rar",
            Self::SevenZip => "7z",
            Self::Tar => "tar",
            Self::Pdf => "pdf",
            Self::Ole2 => "doc",
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::Tiff => "tiff",
            Self::Ico => "ico",
            Self::Webp => "webp",
            Self::Mp3 => "mp3",
            Self::Ogg => "ogg",
            Self::Mp4 => "mp4",
            Self::Sqlite => "db",
            Self::Script => "sh",
            Self::Text => "txt",
            Self::Unknown => "bin",
        }
    }

    /// Human-readable format name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert_eq!(FileType::Elf.name(), "ELF binary");
    /// assert_eq!(FileType::Ole2.name(), "OLE2 compound document");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Elf => "ELF binary",
            Self::Pe => "PE/COFF executable",
            Self::MachO => "Mach-O binary",
            Self::MachOFat => "Mach-O fat binary",
            Self::Dex => "Dalvik executable",
            Self::Wasm => "WebAssembly module",
            Self::JavaClass => "Java class file",
            Self::Zip => "ZIP archive",
            Self::Gzip => "gzip compressed",
            Self::Bzip2 => "bzip2 compressed",
            Self::Xz => "XZ compressed",
            Self::Zstd => "Zstandard compressed",
            Self::Lz4 => "LZ4 frame",
            Self::Rar => "RAR archive",
            Self::SevenZip => "7-Zip archive",
            Self::Tar => "POSIX TAR archive",
            Self::Pdf => "PDF document",
            Self::Ole2 => "OLE2 compound document",
            Self::Png => "PNG image",
            Self::Jpeg => "JPEG image",
            Self::Gif => "GIF image",
            Self::Bmp => "BMP image",
            Self::Tiff => "TIFF image",
            Self::Ico => "Windows ICO icon",
            Self::Webp => "WebP image",
            Self::Mp3 => "MP3 audio",
            Self::Ogg => "Ogg container",
            Self::Mp4 => "MPEG-4 container",
            Self::Sqlite => "SQLite database",
            Self::Script => "shell script",
            Self::Text => "plain text",
            Self::Unknown => "unknown binary",
        }
    }

    /// Returns `true` for executable binary formats.
    ///
    /// Covers ELF, PE, Mach-O, Mach-O fat, DEX, WASM, and Java class files.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert!(FileType::Elf.is_executable());
    /// assert!(FileType::Pe.is_executable());
    /// assert!(FileType::Wasm.is_executable());
    /// assert!(!FileType::Zip.is_executable());
    /// assert!(!FileType::Pdf.is_executable());
    /// ```
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(
            self,
            Self::Elf
                | Self::Pe
                | Self::MachO
                | Self::MachOFat
                | Self::Dex
                | Self::Wasm
                | Self::JavaClass
        )
    }

    /// Returns `true` for compressed archives and compressed streams.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert!(FileType::Zip.is_archive());
    /// assert!(FileType::Gzip.is_archive());
    /// assert!(FileType::Tar.is_archive());
    /// assert!(!FileType::Pdf.is_archive());
    /// ```
    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(
            self,
            Self::Zip
                | Self::Gzip
                | Self::Bzip2
                | Self::Xz
                | Self::Zstd
                | Self::Lz4
                | Self::Rar
                | Self::SevenZip
                | Self::Tar
        )
    }

    /// Returns `true` for document formats (PDF and OLE2 compound documents).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert!(FileType::Pdf.is_document());
    /// assert!(FileType::Ole2.is_document());
    /// assert!(!FileType::Png.is_document());
    /// ```
    #[must_use]
    pub const fn is_document(self) -> bool {
        matches!(self, Self::Pdf | Self::Ole2)
    }

    /// Returns `true` for raster and vector image formats.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_byte_magic::FileType;
    ///
    /// assert!(FileType::Png.is_image());
    /// assert!(FileType::Jpeg.is_image());
    /// assert!(FileType::Webp.is_image());
    /// assert!(!FileType::Mp3.is_image());
    /// ```
    #[must_use]
    pub const fn is_image(self) -> bool {
        matches!(
            self,
            Self::Png | Self::Jpeg | Self::Gif | Self::Bmp | Self::Tiff | Self::Ico | Self::Webp
        )
    }
}

/// Identifies the file type from the first bytes of a file.
///
/// Pass any byte slice — only the first [`SAMPLE_LEN`] (512) bytes are read,
/// which is sufficient for all detections including POSIX TAR (which stores
/// its magic at offset 257). Short slices are handled gracefully; no check
/// will panic on an undersized input.
///
/// Detection order runs longest magic signature first to avoid false positives
/// from prefixes shared between formats. Short two- and three-byte magics
/// (`BM`, `BZh`, `ID3`) also check the byte(s) the format fixes after them,
/// so ordinary text such as `"BMW"` is not misread as an image.
///
/// # Examples
///
/// ```rust
/// use rune_byte_magic::{identify, FileType};
///
/// assert_eq!(identify(b"\x7fELF\x02\x01\x01\x00"), FileType::Elf);
/// assert_eq!(identify(b"MZ\x90\x00"), FileType::Pe);
/// assert_eq!(identify(b"%PDF-1.7"), FileType::Pdf);
/// assert_eq!(identify(b"PK\x03\x04"), FileType::Zip);
/// assert_eq!(identify(b"\x89PNG\r\n\x1a\n"), FileType::Png);
/// assert_eq!(identify(b"#! /bin/bash\n"), FileType::Script);
/// assert_eq!(identify(b"hello, world\n"), FileType::Text);
/// assert_eq!(identify(b"\x00\x01\x02\x03"), FileType::Unknown);
/// ```
#[must_use]
pub fn identify(bytes: &[u8]) -> FileType {
    let bytes = &bytes[..bytes.len().min(SAMPLE_LEN)];
    if bytes.is_empty() {
        return FileType::Unknown;
    }

    // 16-byte signatures
    if bytes.starts_with(b"SQLite format 3\x00") {
        return FileType::Sqlite;
    }

    // 8-byte signatures
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return FileType::Png;
    }
    if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return FileType::Ole2;
    }

    // 6-byte signatures
    if bytes.starts_with(b"\x37\x7a\xbc\xaf\x27\x1c") {
        return FileType::SevenZip;
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return FileType::Rar;
    }
    if bytes.starts_with(b"\xfd7zXZ\x00") {
        return FileType::Xz;
    }

    // 5-byte signatures
    if bytes.starts_with(b"%PDF-") {
        return FileType::Pdf;
    }

    // 4-byte signatures
    if bytes.starts_with(b"\x7fELF") {
        return FileType::Elf;
    }
    if bytes.starts_with(b"dex\n") {
        return FileType::Dex;
    }
    if bytes.starts_with(b"\x00asm") {
        return FileType::Wasm;
    }
    // Local file header, empty archive (end of central directory) and
    // spanned-archive marker (PKWARE APPNOTE 4.3.6, 4.3.16, 8.5.3).
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return FileType::Zip;
    }
    if bytes.starts_with(b"OggS") {
        return FileType::Ogg;
    }
    if bytes.starts_with(b"\x28\xb5\x2f\xfd") {
        return FileType::Zstd;
    }
    if bytes.starts_with(b"\x04\x22\x4d\x18") {
        return FileType::Lz4;
    }
    if bytes.starts_with(b"\x00\x00\x01\x00") {
        return FileType::Ico;
    }
    if bytes.starts_with(b"II*\x00") || bytes.starts_with(b"MM\x00*") {
        return FileType::Tiff;
    }

    // CAFEBABE: Java class file vs Mach-O fat/universal binary.
    // Java class stores the minor version (u16 BE) and major version (u16 BE)
    // at bytes 4–7; Mach-O fat stores the architecture count (u32 BE) there.
    if bytes.starts_with(b"\xca\xfe\xba\xbf") {
        // FAT_MAGIC_64 has no Java counterpart.
        return FileType::MachOFat;
    }
    if bytes.starts_with(b"\xca\xfe\xba\xbe") {
        return if is_java_class(bytes) {
            FileType::JavaClass
        } else {
            FileType::MachOFat
        };
    }

    // Mach-O: four variants (32/64-bit × big/little-endian)
    if bytes.starts_with(b"\xce\xfa\xed\xfe")
        || bytes.starts_with(b"\xcf\xfa\xed\xfe")
        || bytes.starts_with(b"\xfe\xed\xfa\xce")
        || bytes.starts_with(b"\xfe\xed\xfa\xcf")
    {
        return FileType::MachO;
    }

    // GIF87a and GIF89a
    if bytes.len() >= 6
        && bytes.starts_with(b"GIF8")
        && (bytes[4] == b'7' || bytes[4] == b'9')
        && bytes[5] == b'a'
    {
        return FileType::Gif;
    }

    // POSIX TAR: "ustar" at offset 257. Checked before the short magics
    // because a tar header starts with an arbitrary member file name.
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return FileType::Tar;
    }

    // 3-byte signatures. bzip2 is "BZh" followed by the block size '1'–'9'.
    if bytes.starts_with(b"BZh") && bytes.get(3).is_none_or(|b| (b'1'..=b'9').contains(b)) {
        return FileType::Bzip2;
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return FileType::Jpeg;
    }

    // 2-byte signatures
    if bytes.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if bytes.starts_with(b"\x1f\x8b") {
        return FileType::Gzip;
    }
    // BMP: "BM", u32 file size, then two reserved u16s that must be zero.
    if bytes.starts_with(b"BM") && bytes.get(6..10).is_none_or(|reserved| reserved == [0; 4]) {
        return FileType::Bmp;
    }
    if bytes.starts_with(b"#!") {
        return FileType::Script;
    }

    // WebP: RIFF....WEBP (magic at offsets 0 and 8)
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return FileType::Webp;
    }

    // MP4 / MPEG-4: "ftyp" box at offset 4
    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        return FileType::Mp4;
    }

    // ID3-tagged MP3 (must come after more specific signatures to avoid false positives
    // from MPEG sync words appearing in binary data). ID3v2 major versions are 2–4.
    if bytes.starts_with(b"ID3") && bytes.get(3).is_none_or(|v| (2..=4).contains(v)) {
        return FileType::Mp3;
    }

    if is_likely_text(bytes) {
        return FileType::Text;
    }

    FileType::Unknown
}

/// Differentiates Java class files from Mach-O fat binaries.
///
/// Both begin with `\xca\xfe\xba\xbe`. Bytes 4–7 are `minor:u16,
/// major:u16` in a class file and `nfat_arch:u32` in a fat header, all
/// big-endian. Every class file has major ≥ 45 (JDK 1.0.2), so read as one
/// u32 the field is ≥ 45 — far more architectures than any fat binary
/// holds. This is the same split `file(1)` uses, and it keeps working for
/// future Java releases and preview (`minor = 0xFFFF`) class files.
fn is_java_class(bytes: &[u8]) -> bool {
    bytes
        .get(4..8)
        .and_then(|field| <[u8; 4]>::try_from(field).ok())
        .is_some_and(|field| u32::from_be_bytes(field) >= 45)
}

/// Returns `true` if the sample looks like human-readable text.
///
/// The sample must be valid UTF-8, except that a multi-byte sequence cut off
/// at the very end is allowed (the caller may have truncated the file). It
/// may contain printable characters and the whitespace control codes tab,
/// LF, VT, FF, CR and ESC; NUL, other C0 controls and DEL mean binary.
fn is_likely_text(sample: &[u8]) -> bool {
    let valid = match core::str::from_utf8(sample) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => {
            // Only an incomplete sequence at the end: keep the valid prefix.
            core::str::from_utf8(&sample[..error.valid_up_to()]).unwrap_or_default()
        }
        Err(_) => return false,
    };
    valid.bytes().all(
        |b| matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0x1b | 0x20..=0x7e | 0x80..=0xff),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_detected() {
        assert_eq!(identify(b"\x7fELF\x02\x01\x01\x00"), FileType::Elf);
    }

    #[test]
    fn pe_detected() {
        assert_eq!(identify(b"MZ\x90\x00\x03\x00"), FileType::Pe);
    }

    #[test]
    fn macho_little_endian_64_detected() {
        assert_eq!(
            identify(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"),
            FileType::MachO
        );
    }

    #[test]
    fn macho_fat_detected() {
        // \xca\xfe\xba\xbe with architecture count 2 (big-endian) — not a Java major version
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"),
            FileType::MachOFat
        );
    }

    #[test]
    fn java_class_detected() {
        // \xca\xfe\xba\xbe + minor=0 + major=55 (Java 11)
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x37"),
            FileType::JavaClass
        );
    }

    #[test]
    fn dex_detected() {
        assert_eq!(identify(b"dex\n035\x00"), FileType::Dex);
    }

    #[test]
    fn wasm_detected() {
        assert_eq!(identify(b"\x00asm\x01\x00\x00\x00"), FileType::Wasm);
    }

    #[test]
    fn zip_detected() {
        assert_eq!(identify(b"PK\x03\x04"), FileType::Zip);
    }

    #[test]
    fn gzip_detected() {
        assert_eq!(identify(b"\x1f\x8b\x08\x00"), FileType::Gzip);
    }

    #[test]
    fn bzip2_detected() {
        assert_eq!(identify(b"BZh9"), FileType::Bzip2);
    }

    #[test]
    fn xz_detected() {
        assert_eq!(identify(b"\xfd7zXZ\x00"), FileType::Xz);
    }

    #[test]
    fn zstd_detected() {
        assert_eq!(identify(b"\x28\xb5\x2f\xfd\x04\x00"), FileType::Zstd);
    }

    #[test]
    fn lz4_detected() {
        assert_eq!(identify(b"\x04\x22\x4d\x18\x60\x40"), FileType::Lz4);
    }

    #[test]
    fn rar_detected() {
        assert_eq!(identify(b"Rar!\x1a\x07\x00"), FileType::Rar);
    }

    #[test]
    fn sevenzip_detected() {
        assert_eq!(identify(b"\x37\x7a\xbc\xaf\x27\x1c"), FileType::SevenZip);
    }

    #[test]
    fn pdf_detected() {
        assert_eq!(identify(b"%PDF-1.7\n"), FileType::Pdf);
    }

    #[test]
    fn ole2_detected() {
        assert_eq!(
            identify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00"),
            FileType::Ole2
        );
    }

    #[test]
    fn png_detected() {
        assert_eq!(identify(b"\x89PNG\r\n\x1a\n"), FileType::Png);
    }

    #[test]
    fn jpeg_detected() {
        assert_eq!(identify(b"\xff\xd8\xff\xe0"), FileType::Jpeg);
    }

    #[test]
    fn gif_detected() {
        assert_eq!(identify(b"GIF89a\x01\x00"), FileType::Gif);
        assert_eq!(identify(b"GIF87a\x01\x00"), FileType::Gif);
    }

    #[test]
    fn bmp_detected() {
        assert_eq!(identify(b"BM\x36\x00\x00\x00"), FileType::Bmp);
    }

    #[test]
    fn tiff_little_endian_detected() {
        assert_eq!(identify(b"II*\x00"), FileType::Tiff);
    }

    #[test]
    fn tiff_big_endian_detected() {
        assert_eq!(identify(b"MM\x00*"), FileType::Tiff);
    }

    #[test]
    fn ico_detected() {
        assert_eq!(identify(b"\x00\x00\x01\x00\x01\x00"), FileType::Ico);
    }

    #[test]
    fn webp_detected() {
        let mut bytes = b"RIFF\x24\x00\x00\x00WEBP".to_vec();
        bytes.extend_from_slice(b"VP8 ");
        assert_eq!(identify(&bytes), FileType::Webp);
    }

    #[test]
    fn mp3_id3_detected() {
        assert_eq!(identify(b"ID3\x03\x00\x00"), FileType::Mp3);
    }

    #[test]
    fn ogg_detected() {
        assert_eq!(identify(b"OggS\x00\x02"), FileType::Ogg);
    }

    #[test]
    fn mp4_detected() {
        assert_eq!(identify(b"\x00\x00\x00\x18ftypmp41"), FileType::Mp4);
    }

    #[test]
    fn sqlite_detected() {
        assert_eq!(identify(b"SQLite format 3\x00"), FileType::Sqlite);
    }

    #[test]
    fn script_detected() {
        assert_eq!(identify(b"#!/bin/bash\necho hi"), FileType::Script);
        assert_eq!(identify(b"#!/usr/bin/env python3\n"), FileType::Script);
    }

    #[test]
    fn text_detected() {
        assert_eq!(identify(b"hello, world\n"), FileType::Text);
        assert_eq!(identify(b"[package]\nname = \"foo\"\n"), FileType::Text);
    }

    #[test]
    fn unknown_for_binary_data() {
        assert_eq!(identify(b"\x00\x01\x02\x03\x04\x05"), FileType::Unknown);
    }

    #[test]
    fn empty_input_is_unknown() {
        assert_eq!(identify(b""), FileType::Unknown);
    }

    #[test]
    fn tar_detected() {
        let mut buf = vec![0u8; 512];
        buf[257..262].copy_from_slice(b"ustar");
        assert_eq!(identify(&buf), FileType::Tar);
    }

    // Regression: any byte >= 0x80 counted as text, so arbitrary
    // high-bit binary (and invalid UTF-8) was reported as `Text`.
    #[test]
    fn regression_invalid_utf8_is_not_text() {
        assert_eq!(identify(b"\xff\xfe\xfd\xfc"), FileType::Unknown);
        assert_eq!(identify(b"abc\x80def"), FileType::Unknown);
        assert_eq!(identify(b"\xc3("), FileType::Unknown);
        assert_eq!(
            identify("caf\u{e9} na\u{ef}ve \u{1F600}\n".as_bytes()),
            FileType::Text
        );
    }

    #[test]
    fn utf8_cut_at_the_end_is_still_text() {
        let text = "na\u{ef}ve \u{1F600}".as_bytes();
        for cut in 1..=3 {
            assert_eq!(
                identify(&text[..text.len() - cut]),
                FileType::Text,
                "cut {cut}"
            );
        }
        // The same at the 512-byte sample boundary.
        let mut long = "a".repeat(SAMPLE_LEN - 1).into_bytes();
        long.extend_from_slice("\u{1F600}".as_bytes());
        assert_eq!(identify(&long), FileType::Text);
    }

    #[test]
    fn del_and_c0_controls_are_binary() {
        assert_eq!(identify(b"abc\x7f"), FileType::Unknown);
        assert_eq!(identify(b"abc\x01"), FileType::Unknown);
    }

    // Regression: Java class detection stopped at major 70 (Java 26),
    // so class files from Java 27+ and preview class files (minor 0xFFFF)
    // were reported as Mach-O fat binaries.
    #[test]
    fn regression_future_and_preview_java_class() {
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x47"),
            FileType::JavaClass
        );
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x64"),
            FileType::JavaClass
        );
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\xff\xff\x00\x41"),
            FileType::JavaClass
        );
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x03\x00\x2d"),
            FileType::JavaClass
        );
        assert_eq!(
            identify(b"\xca\xfe\xba\xbe\x00\x00\x00\x14"),
            FileType::MachOFat
        );
    }

    // Regression: the 64-bit fat header magic (FAT_MAGIC_64) was not
    // recognised.
    #[test]
    fn regression_fat_magic_64() {
        assert_eq!(
            identify(b"\xca\xfe\xba\xbf\x00\x00\x00\x02"),
            FileType::MachOFat
        );
    }

    // Regression: text starting with "BM", "BZh" or "ID3" was reported
    // as BMP, bzip2 or MP3.
    #[test]
    fn regression_short_magic_false_positives() {
        assert_eq!(identify(b"BMW owners club\n"), FileType::Text);
        assert_eq!(identify(b"BZh, said the bee\n"), FileType::Text);
        assert_eq!(identify(b"ID3 tags explained\n"), FileType::Text);
        // Truncated real headers still match.
        assert_eq!(identify(b"BM"), FileType::Bmp);
        assert_eq!(identify(b"BZh"), FileType::Bzip2);
        assert_eq!(identify(b"ID3"), FileType::Mp3);
    }

    // Regression: a tar archive whose first member name starts with a
    // short magic ("BM…", "MZ…", "#!…") was reported as that type.
    #[test]
    fn regression_tar_member_name_is_not_magic() {
        for name in [&b"BM"[..], b"MZ", b"#!run", b"BZh9", b"ID3\x03"] {
            let mut buf = vec![0u8; 512];
            buf[..name.len()].copy_from_slice(name);
            buf[257..262].copy_from_slice(b"ustar");
            assert_eq!(identify(&buf), FileType::Tar, "{name:?}");
        }
    }

    #[test]
    fn empty_and_spanned_zip() {
        assert_eq!(identify(b"PK\x05\x06\x00\x00"), FileType::Zip);
        assert_eq!(identify(b"PK\x07\x08PK\x03\x04"), FileType::Zip);
    }

    #[test]
    fn only_the_sample_is_inspected() {
        let mut bytes = b"hello".repeat(200);
        assert_eq!(identify(&bytes), FileType::Text);
        bytes.push(0);
        assert_eq!(identify(&bytes), FileType::Text);
    }

    #[test]
    fn is_executable_covers_all_variants() {
        assert!(FileType::Elf.is_executable());
        assert!(FileType::Pe.is_executable());
        assert!(FileType::MachO.is_executable());
        assert!(FileType::MachOFat.is_executable());
        assert!(FileType::Dex.is_executable());
        assert!(FileType::Wasm.is_executable());
        assert!(FileType::JavaClass.is_executable());
        assert!(!FileType::Zip.is_executable());
    }

    #[test]
    fn is_archive_covers_all_variants() {
        for ft in [
            FileType::Zip,
            FileType::Gzip,
            FileType::Bzip2,
            FileType::Xz,
            FileType::Zstd,
            FileType::Lz4,
            FileType::Rar,
            FileType::SevenZip,
            FileType::Tar,
        ] {
            assert!(ft.is_archive(), "{ft:?} should be an archive");
        }
        assert!(!FileType::Pdf.is_archive());
    }

    #[test]
    fn mime_and_extension_are_non_empty() {
        for ft in [
            FileType::Elf,
            FileType::Pe,
            FileType::Pdf,
            FileType::Png,
            FileType::Unknown,
        ] {
            assert_ne!(ft.mime_type(), "");
            assert_ne!(ft.extension(), "");
            assert_ne!(ft.name(), "");
        }
    }
}
