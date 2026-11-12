//! Lightweight PE (Portable Executable) parser for Windows binaries.
//!
//! Parses `.exe`, `.dll`, and `.sys` files to extract headers, section table,
//! import and export tables, and Windows security hardening flags — without any
//! external C libraries or unsafe code.
//!
//! # Features
//!
//! - [`parse`] — parse a PE binary from a byte slice, returns [`Pe`]
//! - [`Pe`] — header, sections, imports, exports, security flags
//! - [`PeHeader`] — machine type, characteristics, PE32 vs PE32+, linker version
//! - [`SecurityFlags`] — ASLR, DEP/NX, CFG, `SafeSEH`, Force Integrity, High Entropy VA
//! - [`Section`] — name, virtual address, raw size, characteristics
//! - [`Import`] — DLL name and imported function names/ordinals
//! - [`Export`] — exported function names and ordinals
//!
//! # Quick Start
//!
//! [`parse`] works on any byte slice. This example builds a minimal 64-bit
//! console executable in memory: a DOS header pointing at the `PE\0\0`
//! signature, the COFF header, a PE32+ optional header and one `.text`
//! section header.
//!
//! ```rust
//! use rune_pe::{PeMagic, parse};
//!
//! fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
//!     buf[off..off + bytes.len()].copy_from_slice(bytes);
//! }
//!
//! const PE_OFFSET: usize = 0x40;
//! const OPT_HEADER_SIZE: usize = 240; // PE32+ with 16 data directories
//! let coff = PE_OFFSET + 4;
//! let opt = coff + 20;
//! let text = opt + OPT_HEADER_SIZE;
//!
//! let mut exe = vec![0u8; text + 40];
//! put(&mut exe, 0, b"MZ");
//! put(&mut exe, 0x3c, &(PE_OFFSET as u32).to_le_bytes()); // e_lfanew
//! put(&mut exe, PE_OFFSET, b"PE\0\0");
//!
//! put(&mut exe, coff, &0x8664u16.to_le_bytes()); // Machine: AMD64
//! put(&mut exe, coff + 2, &1u16.to_le_bytes()); // NumberOfSections
//! put(&mut exe, coff + 16, &(OPT_HEADER_SIZE as u16).to_le_bytes());
//! put(&mut exe, coff + 18, &0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
//!
//! put(&mut exe, opt, &0x20bu16.to_le_bytes()); // Magic: PE32+
//! put(&mut exe, opt + 16, &0x1000u32.to_le_bytes()); // AddressOfEntryPoint
//! put(&mut exe, opt + 24, &0x1_4000_0000u64.to_le_bytes()); // ImageBase
//! put(&mut exe, opt + 68, &3u16.to_le_bytes()); // Subsystem: Windows CUI
//! put(&mut exe, opt + 70, &0x0160u16.to_le_bytes()); // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
//!
//! put(&mut exe, text, b".text");
//! put(&mut exe, text + 12, &0x1000u32.to_le_bytes()); // VirtualAddress
//! put(&mut exe, text + 36, &0x6000_0020u32.to_le_bytes()); // CODE | EXECUTE | READ
//!
//! let pe = parse(&exe).unwrap();
//! assert_eq!(pe.header.machine.to_string(), "x86-64");
//! assert_eq!(pe.header.magic, PeMagic::Pe64);
//! assert!(pe.header.is_exe() && !pe.header.is_dll());
//! assert_eq!(pe.header.image_base, 0x1_4000_0000);
//! assert_eq!(pe.header.entry_point, 0x1000);
//!
//! // ASLR (with high-entropy VA) and DEP are on; CFG is not.
//! assert!(pe.security.aslr && pe.security.high_entropy_va && pe.security.dep);
//! assert!(!pe.security.cfg);
//! assert_eq!(pe.security.score(), 2);
//!
//! assert_eq!(pe.sections[0].name, ".text");
//! assert!(pe.sections[0].is_executable() && !pe.sections[0].is_writable());
//! assert!(pe.imports.is_empty() && pe.exports.is_empty());
//! ```
//!
//! On a real binary:
//!
//! ```rust,no_run
//! use rune_pe::parse;
//! use std::fs;
//!
//! let bytes = fs::read("notepad.exe").unwrap();
//! let pe = parse(&bytes).unwrap();
//! println!("machine: {}", pe.header.machine);
//! println!("ASLR: {}", pe.security.aslr);
//! println!("DEP:  {}", pe.security.dep);
//! println!("CFG:  {}", pe.security.cfg);
//! for imp in &pe.imports {
//!     println!("  {} -> {} functions", imp.dll, imp.functions.len());
//! }
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-pe notepad.exe
//! rune-pe --json malware.dll
//! rune-pe --imports suspicious.exe
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use core::fmt;

/// Errors produced by the PE parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// File too short.
    TooShort,
    /// Missing MZ signature at offset 0.
    BadMzMagic,
    /// PE offset (at 0x3C) points outside the file.
    BadPeOffset,
    /// Missing `PE\0\0` signature at the PE offset.
    BadPeSignature,
    /// Optional header magic is not PE32 (0x10b) or PE32+ (0x20b).
    UnknownMagic(u16),
    /// A required offset or size exceeds the file length.
    OutOfBounds,
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "file too short for PE headers"),
            Self::BadMzMagic => write!(f, "not a PE file (no MZ signature)"),
            Self::BadPeOffset => write!(f, "PE offset out of bounds"),
            Self::BadPeSignature => write!(f, "PE signature not found"),
            Self::UnknownMagic(m) => write!(f, "unknown optional header magic: 0x{m:04x}"),
            Self::OutOfBounds => write!(f, "PE structure references out-of-bounds data"),
        }
    }
}

/// PE bitness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeMagic {
    /// PE32 (32-bit).
    Pe32,
    /// PE32+ (64-bit).
    Pe64,
}

impl fmt::Display for PeMagic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pe32 => write!(f, "PE32"),
            Self::Pe64 => write!(f, "PE32+"),
        }
    }
}

/// CPU architecture from the COFF machine field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine(pub u16);

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0x014c => "i386",
            0x0200 => "IA64",
            0x8664 => "x86-64",
            0xaa64 => "ARM64",
            0x01c0 => "ARM",
            0x01c4 => "ARMv7",
            0x01f0 => "PowerPC",
            _ => return write!(f, "0x{:04x}", self.0),
        };
        write!(f, "{name}")
    }
}

/// Core PE header fields.
#[derive(Debug, Clone)]
pub struct PeHeader {
    /// Target machine type.
    pub machine: Machine,
    /// Optional header format (PE32 or PE32+).
    pub magic: PeMagic,
    /// COFF characteristics flags.
    pub characteristics: u16,
    /// DLL characteristics flags (security-relevant).
    pub dll_characteristics: u16,
    /// Number of entries in the section table.
    pub number_of_sections: u16,
    /// Timestamp from COFF header (seconds since epoch).
    pub timestamp: u32,
    /// Preferred load address of the image.
    pub image_base: u64,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Size of the image in memory, in bytes.
    pub size_of_image: u32,
    /// Major version of the linker that produced the image.
    pub linker_major: u8,
    /// Minor version of the linker that produced the image.
    pub linker_minor: u8,
    /// Windows subsystem required to run the image.
    pub subsystem: u16,
}

impl PeHeader {
    /// Whether the image is a DLL.
    #[must_use]
    pub const fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }
    /// Whether the image is an executable (not a DLL).
    #[must_use]
    pub const fn is_exe(&self) -> bool {
        self.characteristics & 0x0002 != 0
    }
}

/// Windows PE security hardening flags.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_pe::parse;
/// use std::fs;
///
/// let bytes = fs::read("notepad.exe").unwrap();
/// let pe = parse(&bytes).unwrap();
/// let s = &pe.security;
/// println!("ASLR={} DEP={} CFG={} score={}/5", s.aslr, s.dep, s.cfg, s.score());
/// ```
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent, documented switch"
)]
#[derive(Debug, Clone, Default)]
pub struct SecurityFlags {
    /// ASLR (Address Space Layout Randomization): `DLL_CHARACTERISTICS & 0x0040`.
    pub aslr: bool,
    /// High-entropy ASLR (64-bit ASLR): `DLL_CHARACTERISTICS & 0x0020`.
    pub high_entropy_va: bool,
    /// DEP / NX (Data Execution Prevention): `DLL_CHARACTERISTICS & 0x0100`.
    pub dep: bool,
    /// Structured Exception Handling disabled: `DLL_CHARACTERISTICS & 0x0400`.
    pub no_seh: bool,
    /// Control Flow Guard: `DLL_CHARACTERISTICS & 0x4000`.
    pub cfg: bool,
    /// Force Integrity (require signed): `DLL_CHARACTERISTICS & 0x0080`.
    pub force_integrity: bool,
    /// Authenticode signed (Security Directory entry present and non-empty).
    pub signed: bool,
}

impl SecurityFlags {
    /// Score from 0–5 counting ASLR, DEP, CFG, no-SEH, Force Integrity.
    #[must_use]
    pub fn score(&self) -> u8 {
        [
            self.aslr,
            self.dep,
            self.cfg,
            self.no_seh,
            self.force_integrity,
        ]
        .into_iter()
        .map(u8::from)
        .sum()
    }
}

/// A PE section header.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name, e.g. `.text`.
    pub name: String,
    /// RVA of the section when loaded.
    pub virtual_address: u32,
    /// Size of the section when loaded.
    pub virtual_size: u32,
    /// File offset of the section data.
    pub raw_offset: u32,
    /// Size of the section data in the file.
    pub raw_size: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl Section {
    /// Section is executable (`IMAGE_SCN_MEM_EXECUTE = 0x20000000`).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
    /// Section is writable (`IMAGE_SCN_MEM_WRITE = 0x80000000`).
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
    /// Section contains code (`IMAGE_SCN_CNT_CODE = 0x00000020`).
    #[must_use]
    pub const fn contains_code(&self) -> bool {
        self.characteristics & 0x0000_0020 != 0
    }
}

/// Imported functions from a single DLL.
#[derive(Debug, Clone)]
pub struct Import {
    /// Name of the imported DLL.
    pub dll: String,
    /// Functions imported from the DLL.
    pub functions: Vec<ImportFunction>,
}

/// A single imported function.
#[derive(Debug, Clone)]
pub struct ImportFunction {
    /// Function name, if imported by name.
    pub name: Option<String>,
    /// Ordinal, if imported by ordinal.
    pub ordinal: Option<u16>,
    /// Index hint into the DLL export name table.
    pub hint: Option<u16>,
}

impl ImportFunction {
    /// Display name or ordinal.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.ordinal
                .map_or_else(|| "?".to_string(), |ord| format!("#{ord}"))
        })
    }
}

/// An exported function.
#[derive(Debug, Clone)]
pub struct Export {
    /// Exported name, if any.
    pub name: Option<String>,
    /// Export ordinal.
    pub ordinal: u16,
    /// RVA of the exported function.
    pub rva: u32,
}

/// A parsed PE binary.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_pe::parse;
/// use std::fs;
///
/// let bytes = fs::read("notepad.exe").unwrap();
/// let pe = parse(&bytes).unwrap();
///
/// for imp in &pe.imports {
///     for func in &imp.functions {
///         println!("{} -> {}", imp.dll, func.display_name());
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Pe {
    /// Parsed COFF and optional header fields.
    pub header: PeHeader,
    /// Section table.
    pub sections: Vec<Section>,
    /// Imported DLLs and functions.
    pub imports: Vec<Import>,
    /// Exported functions.
    pub exports: Vec<Export>,
    /// Hardening features detected in the image.
    pub security: SecurityFlags,
}

/// Returns `true` if the byte slice starts with the MZ signature.
///
/// # Examples
///
/// ```rust
/// use rune_pe::is_pe;
///
/// assert!(is_pe(b"MZ\x90\x00remaining"));
/// assert!(!is_pe(b"\x7fELF"));
/// ```
#[must_use]
pub const fn is_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z'
}

/// Parse a PE binary from a byte slice.
///
/// # Errors
///
/// Returns [`PeError`] if the bytes are not a valid PE file.
///
/// # Untrusted input
///
/// The input may be hostile. Tables that run past the end of the file are
/// cut short instead of failing the parse, data directories are read only
/// within `NumberOfRvaAndSizes` and the optional header, and the work done
/// is bounded: at most 4096 imported DLLs, 65536 imported functions in
/// total, 65536 exports, and names of up to 4096 bytes (longer or
/// unterminated names are reported as empty).
///
/// # Examples
///
/// ```rust
/// use rune_pe::{parse, PeError};
///
/// // Too short returns TooShort
/// assert_eq!(parse(b"MZ").unwrap_err(), PeError::TooShort);
/// // Right length but bad magic returns BadMzMagic
/// assert_eq!(parse(&vec![0u8; 64]).unwrap_err(), PeError::BadMzMagic);
/// ```
pub fn parse(bytes: &[u8]) -> Result<Pe, PeError> {
    if bytes.len() < 64 {
        return Err(PeError::TooShort);
    }
    if bytes[0] != b'M' || bytes[1] != b'Z' {
        return Err(PeError::BadMzMagic);
    }

    let read16 = |off: usize| -> Result<u16, PeError> {
        read_le_u16(bytes, off).ok_or(PeError::OutOfBounds)
    };
    let read32 = |off: usize| -> Result<u32, PeError> {
        read_le_u32(bytes, off).ok_or(PeError::OutOfBounds)
    };
    let read64 = |off: usize| -> Result<u64, PeError> {
        read_le_u64(bytes, off).ok_or(PeError::OutOfBounds)
    };

    // `e_lfanew` comes from the file: compute its end with checked arithmetic
    // so a value near `u32::MAX` cannot overflow `usize` on 32-bit targets.
    let pe_offset = usize::try_from(read32(0x3c)?).map_err(|_| PeError::BadPeOffset)?;
    let signature = pe_offset
        .checked_add(4)
        .and_then(|end| bytes.get(pe_offset..end))
        .ok_or(PeError::BadPeOffset)?;
    if signature != b"PE\0\0" {
        return Err(PeError::BadPeSignature);
    }

    // ── COFF header (20 bytes after PE\0\0) ───────────────────────────────
    let coff = pe_offset + 4;
    let machine = read16(coff)?;
    let number_of_sections = read16(coff + 2)?;
    let timestamp = read32(coff + 4)?;
    let size_of_optional_header = read16(coff + 16)? as usize;
    let characteristics = read16(coff + 18)?;

    // ── Optional header ───────────────────────────────────────────────────
    let opt = coff + 20;
    let opt_end = opt
        .checked_add(size_of_optional_header)
        .filter(|&end| end <= bytes.len())
        .ok_or(PeError::OutOfBounds)?;

    let magic_val = read16(opt)?;
    let magic = match magic_val {
        0x10b => PeMagic::Pe32,
        0x20b => PeMagic::Pe64,
        v => return Err(PeError::UnknownMagic(v)),
    };

    let linker_major = bytes.get(opt + 2).copied().ok_or(PeError::OutOfBounds)?;
    let linker_minor = bytes.get(opt + 3).copied().ok_or(PeError::OutOfBounds)?;
    let entry_point = read32(opt + 16)?;
    let (image_base, rva_count_off) = if magic == PeMagic::Pe32 {
        (u64::from(read32(opt + 28)?), opt + 92)
    } else {
        (read64(opt + 24)?, opt + 108)
    };
    let subsystem = read16(opt + 68)?;
    let dll_characteristics = read16(opt + 70)?;
    let size_of_image = read32(opt + 56)?;

    // ── Data directories ──────────────────────────────────────────────────
    // A directory exists only if it is within `NumberOfRvaAndSizes` and
    // inside `SizeOfOptionalHeader`; bytes past either belong to something
    // else (usually the section table) and must not be read as directories.
    let data_dirs = DataDirectories {
        bytes,
        start: rva_count_off + 4,
        end: opt_end,
        count: if rva_count_off + 4 <= opt_end {
            read32(rva_count_off).map_or(0, |n| n as usize)
        } else {
            0
        },
    };

    // ── Security directory (Authenticode) ─────────────────────────────────
    // Its "RVA" is really a file offset; any non-empty entry counts as signed.
    let (sec_offset, sec_size) = data_dirs.get(DIR_SECURITY);
    let signed = sec_offset != 0 && sec_size != 0;

    let header = PeHeader {
        machine: Machine(machine),
        magic,
        characteristics,
        dll_characteristics,
        number_of_sections,
        timestamp,
        image_base,
        entry_point,
        size_of_image,
        linker_major,
        linker_minor,
        subsystem,
    };

    let security = SecurityFlags {
        high_entropy_va: dll_characteristics & 0x0020 != 0,
        aslr: dll_characteristics & 0x0040 != 0,
        force_integrity: dll_characteristics & 0x0080 != 0,
        dep: dll_characteristics & 0x0100 != 0,
        no_seh: dll_characteristics & 0x0400 != 0,
        cfg: dll_characteristics & 0x4000 != 0,
        signed,
    };

    // ── Section table ─────────────────────────────────────────────────────
    let section_table_off = opt_end;
    let mut sections = Vec::with_capacity(number_of_sections as usize);

    for i in 0..usize::from(number_of_sections) {
        let base = section_table_off + i * 40;
        if base + 40 > bytes.len() {
            break;
        }
        let raw_name = &bytes[base..base + 8];
        let name = raw_name
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let name = String::from_utf8_lossy(&name).into_owned();
        let virtual_size = read32(base + 8)?;
        let virtual_address = read32(base + 12)?;
        let raw_size = read32(base + 16)?;
        let raw_offset = read32(base + 20)?;
        let section_characteristics = read32(base + 36)?;

        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics: section_characteristics,
        });
    }

    // ── Import table ──────────────────────────────────────────────────────
    let (import_dir_rva, _) = data_dirs.get(DIR_IMPORT);
    let imports = parse_imports(bytes, import_dir_rva, &sections, magic);

    // ── Export table ──────────────────────────────────────────────────────
    let (export_dir_rva, _) = data_dirs.get(DIR_EXPORT);
    let exports = parse_exports(bytes, export_dir_rva, &sections);

    Ok(Pe {
        header,
        sections,
        imports,
        exports,
        security,
    })
}

/// Index of the export table in the data directory array.
const DIR_EXPORT: usize = 0;
/// Index of the import table in the data directory array.
const DIR_IMPORT: usize = 1;
/// Index of the security (Authenticode certificate) table.
const DIR_SECURITY: usize = 4;

/// Longest DLL, import or export name the parser keeps, in bytes. Real
/// names are far shorter (MSVC truncates decorated names at 4096); a longer
/// or unterminated string is treated as missing. Without a cap, thousands of
/// entries pointing at one huge string would cost memory quadratic in the
/// file size.
const MAX_NAME_LEN: usize = 4096;

/// Most import descriptors (DLLs) read from one import table.
const MAX_IMPORT_DLLS: usize = 4096;

/// Most imported functions read across all DLLs. Each descriptor may point
/// its thunk list anywhere in the file, so without a shared budget a crafted
/// file costs time and memory quadratic in its size.
const MAX_IMPORT_FUNCTIONS: usize = 65_536;

/// Most exports read. Export ordinals are 16-bit, so no image can have more.
const MAX_EXPORTS: usize = 65_536;

/// The data directory array of the optional header.
struct DataDirectories<'a> {
    bytes: &'a [u8],
    /// File offset of directory 0.
    start: usize,
    /// End of the optional header: no directory extends past it.
    end: usize,
    /// `NumberOfRvaAndSizes` as stored in the file.
    count: usize,
}

impl DataDirectories<'_> {
    /// `(rva, size)` of directory `index`, or `(0, 0)` when the header does
    /// not contain it.
    fn get(&self, index: usize) -> (u32, u32) {
        let off = self.start + index * 8;
        if index >= self.count || off + 8 > self.end {
            return (0, 0);
        }
        (
            read_le_u32(self.bytes, off).unwrap_or(0),
            read_le_u32(self.bytes, off + 4).unwrap_or(0),
        )
    }
}

/// Read a little-endian `u16` at `off`, or `None` past the end of `bytes`.
fn read_le_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..)?
        .first_chunk::<2>()
        .map(|b| u16::from_le_bytes(*b))
}

/// Read a little-endian `u32` at `off`, or `None` past the end of `bytes`.
fn read_le_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..)?
        .first_chunk::<4>()
        .map(|b| u32::from_le_bytes(*b))
}

/// Read a little-endian `u64` at `off`, or `None` past the end of `bytes`.
fn read_le_u64(bytes: &[u8], off: usize) -> Option<u64> {
    bytes
        .get(off..)?
        .first_chunk::<8>()
        .map(|b| u64::from_le_bytes(*b))
}

/// Maps an RVA to a file offset through the section table. Section fields
/// come from the file, so the arithmetic is done in `u64` and cannot overflow.
fn rva_to_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    let rva = u64::from(rva);
    sections
        .iter()
        .find(|s| {
            let start = u64::from(s.virtual_address);
            rva >= start && rva < start + u64::from(s.virtual_size.max(s.raw_size))
        })
        .and_then(|s| {
            usize::try_from(rva - u64::from(s.virtual_address) + u64::from(s.raw_offset)).ok()
        })
}

/// The NUL-terminated UTF-8 string at `off`, or `""` if it is out of bounds,
/// unterminated within [`MAX_NAME_LEN`] bytes, or not UTF-8.
fn read_cstr(bytes: &[u8], off: usize) -> String {
    bytes
        .get(off..)
        .map(|s| &s[..s.len().min(MAX_NAME_LEN + 1)])
        .and_then(|s| s.iter().position(|&b| b == 0).map(|e| &s[..e]))
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_string()
}

#[allow(
    clippy::similar_names,
    reason = "names mirror the PE specification fields"
)]
fn parse_imports(bytes: &[u8], dir_rva: u32, sections: &[Section], magic: PeMagic) -> Vec<Import> {
    let mut imports = Vec::new();
    if dir_rva == 0 {
        return imports;
    }
    let Some(mut off) = rva_to_offset(dir_rva, sections) else {
        return imports;
    };
    let mut budget = MAX_IMPORT_FUNCTIONS;

    for _ in 0..MAX_IMPORT_DLLS {
        if off.saturating_add(20) > bytes.len() {
            break;
        }
        let (Some(ilt_rva), Some(name_rva), Some(iat_rva)) = (
            read_le_u32(bytes, off),
            read_le_u32(bytes, off + 12),
            read_le_u32(bytes, off + 16),
        ) else {
            break;
        };

        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        let dll = rva_to_offset(name_rva, sections)
            .map(|o| read_cstr(bytes, o))
            .unwrap_or_default();

        if !dll.is_empty() {
            let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            let functions = rva_to_offset(thunk_rva, sections).map_or_else(Vec::new, |thunk_off| {
                parse_thunks(bytes, thunk_off, sections, magic, &mut budget)
            });
            imports.push(Import { dll, functions });
        }
        off += 20;
    }
    imports
}

/// Reads the thunk list at `off`, taking each entry out of `budget` (the
/// import functions still allowed for the whole file).
fn parse_thunks(
    bytes: &[u8],
    mut off: usize,
    sections: &[Section],
    magic: PeMagic,
    budget: &mut usize,
) -> Vec<ImportFunction> {
    let mut funcs = Vec::new();
    let entry_size = if magic == PeMagic::Pe64 { 8usize } else { 4 };
    let ordinal_flag: u64 = if magic == PeMagic::Pe64 {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    while *budget > 0 {
        if off.saturating_add(entry_size) > bytes.len() {
            break;
        }
        *budget -= 1;
        let thunk = if magic == PeMagic::Pe64 {
            read_le_u64(bytes, off)
        } else {
            read_le_u32(bytes, off).map(u64::from)
        };
        let Some(thunk) = thunk else {
            break;
        };
        if thunk == 0 {
            break;
        }

        let func = if thunk & ordinal_flag != 0 {
            ImportFunction {
                name: None,
                ordinal: Some((thunk & 0xffff) as u16),
                hint: None,
            }
        } else {
            let rva = (thunk & 0x7fff_ffff) as u32;
            if let Some(name_off) = rva_to_offset(rva, sections) {
                let hint = read_le_u16(bytes, name_off);
                let name = read_cstr(bytes, name_off.saturating_add(2));
                ImportFunction {
                    name: Some(name),
                    ordinal: None,
                    hint,
                }
            } else {
                off += entry_size;
                continue;
            }
        };
        funcs.push(func);
        off += entry_size;
    }
    funcs
}

/// Reads the export directory at `dir_rva`: one [`Export`] per non-empty
/// entry of the export address table, in ordinal order, named from the
/// export name table where a name points at it.
#[allow(
    clippy::similar_names,
    reason = "names mirror the PE specification fields"
)]
fn parse_exports(bytes: &[u8], dir_rva: u32, sections: &[Section]) -> Vec<Export> {
    let mut exports = Vec::new();
    if dir_rva == 0 {
        return exports;
    }
    let Some(base) = rva_to_offset(dir_rva, sections) else {
        return exports;
    };
    if base.saturating_add(40) > bytes.len() {
        return exports;
    }

    let read32 = |off: usize| -> u32 { read_le_u32(bytes, off).unwrap_or(0) };

    let ordinal_base = read32(base + 16);
    let num_functions = read32(base + 20) as usize;
    let num_names = read32(base + 24) as usize;
    let Some(eat_off) = rva_to_offset(read32(base + 28), sections) else {
        return exports;
    };

    // The counts come from the file. Ordinals are 16-bit, and every address
    // table entry needs four bytes inside the file, so neither bound lets a
    // count of up to 2^32 drive the loops.
    let eat_len = num_functions
        .min(MAX_EXPORTS)
        .min(bytes.len().saturating_sub(eat_off) / 4);
    let mut names: Vec<Option<String>> = vec![None; eat_len];

    // The name pointer and ordinal tables are optional (an image may export
    // by ordinal only); each name points at one address table index.
    if let (Some(ent_off), Some(eot_off)) = (
        rva_to_offset(read32(base + 32), sections),
        rva_to_offset(read32(base + 36), sections),
    ) {
        for i in 0..num_names.min(MAX_EXPORTS) {
            let (Some(name_rva), Some(index)) = (
                read_le_u32(bytes, ent_off.saturating_add(i * 4)),
                read_le_u16(bytes, eot_off.saturating_add(i * 2)),
            ) else {
                break;
            };
            if let Some(slot @ None) = names.get_mut(usize::from(index)) {
                *slot = Some(
                    rva_to_offset(name_rva, sections)
                        .map(|o| read_cstr(bytes, o))
                        .unwrap_or_default(),
                );
            }
        }
    }

    for (index, name) in names.into_iter().enumerate() {
        let rva = read32(eat_off + index * 4);
        if rva == 0 {
            // An unused slot in a sparse ordinal range.
            continue;
        }
        let Ok(index) = u32::try_from(index) else {
            break;
        };
        exports.push(Export {
            name,
            // Ordinals are 16-bit; saturate rather than wrap on a corrupt base.
            ordinal: u16::try_from(ordinal_base.saturating_add(index)).unwrap_or(u16::MAX),
            rva,
        });
    }
    exports
}

/// Suspicious Win32 API imports commonly used by malware.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_pe::{parse, suspicious_imports};
/// use std::fs;
///
/// let bytes = fs::read("sample.exe").unwrap();
/// let pe = parse(&bytes).unwrap();
/// let hits = suspicious_imports(&pe);
/// for (dll, func) in &hits {
///     println!("suspicious: {dll}!{func}");
/// }
/// ```
#[must_use]
pub fn suspicious_imports(pe: &Pe) -> Vec<(String, String)> {
    const SUSPICIOUS: &[&str] = &[
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "VirtualAllocEx",
        "VirtualAlloc",
        "OpenProcess",
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "keybd_event",
        "InternetOpenA",
        "InternetConnectA",
        "HttpSendRequestA",
        "WinExec",
        "ShellExecute",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateService",
        "OpenSCManager",
        "StartService",
        "RegSetValue",
        "RegCreateKey",
        "RegOpenKey",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    ];

    let mut hits = Vec::new();
    for imp in &pe.imports {
        for func in &imp.functions {
            if let Some(ref name) = func.name
                && SUSPICIOUS.iter().any(|s| name.starts_with(s))
            {
                hits.push((imp.dll.clone(), name.clone()));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short() {
        assert_eq!(parse(b"").unwrap_err(), PeError::TooShort);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0u8; 64];
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadMzMagic);
    }

    #[test]
    fn rejects_no_pe_sig() {
        let mut buf = vec![0u8; 256];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c] = 0x40;
        assert_eq!(parse(&buf).unwrap_err(), PeError::BadPeSignature);
    }

    #[test]
    fn is_pe_detection() {
        assert!(is_pe(b"MZ\x90\x00"));
        assert!(!is_pe(b"\x7fELF"));
        assert!(!is_pe(b""));
    }

    /// A PE32+ image with one section `(virtual_address, size)` mapped at
    /// file offset 0x200, and the given export and import directory RVAs.
    fn pe64(section: (u32, u32), export_rva: u32, import_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        buf[opt + 112..opt + 116].copy_from_slice(&export_rva.to_le_bytes());
        buf[opt + 120..opt + 124].copy_from_slice(&import_rva.to_le_bytes());
        let sec = opt + 240;
        buf[sec..sec + 5].copy_from_slice(b".data");
        buf[sec + 8..sec + 12].copy_from_slice(&section.1.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&section.0.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&section.1.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf
    }

    // Regression: `virtual_address + size` overflowed u32
    // for a section at the top of the address space.
    #[test]
    fn section_at_top_of_address_space_is_not_an_overflow() {
        let pe = parse(&pe64((0xffff_f000, 0x2000), 0, 0xffff_f800)).unwrap();
        assert!(pe.imports.is_empty());
    }

    // Regression: the export loop trusted a name count of up to
    // 2^32 and kept pushing exports long after the tables left the file.
    #[test]
    fn export_counts_are_bounded_by_the_file() {
        let mut buf = pe64((0x1000, 0x200), 0x1000, 0);
        let dir = 0x200;
        for (field, value) in [
            (20, u32::MAX),
            (24, u32::MAX),
            (28, 0x1000),
            (32, 0x1000),
            (36, 0x1000),
        ] {
            buf[dir + field..dir + field + 4].copy_from_slice(&value.to_le_bytes());
        }
        let pe = parse(&buf).unwrap();
        assert!(pe.exports.len() <= buf.len() / 4);
    }

    // Regression: names were read up to the next NUL anywhere in the
    // file, so many entries naming one huge string cost quadratic memory.
    #[test]
    fn names_longer_than_the_cap_are_dropped() {
        let mut bytes = vec![b'A'; MAX_NAME_LEN + 10];
        bytes.push(0);
        assert_eq!(read_cstr(&bytes, 0), "");
        assert_eq!(read_cstr(&bytes, 10).len(), MAX_NAME_LEN);
        assert_eq!(read_cstr(&bytes, bytes.len() + 5), "");
        assert_eq!(
            read_cstr(b"\xff\xfe\0", 0),
            "",
            "non-UTF-8 names are dropped"
        );
    }

    // Regression: every import descriptor re-read its own thunk list
    // with no shared limit, so descriptors sharing one long list cost time
    // and memory quadratic in the file size.
    #[test]
    fn import_functions_share_one_budget() {
        // One section; descriptors at 0x000.., all pointing at a thunk list
        // of ordinal imports at 0x10000 that fills the rest of the file.
        let section = (0x1000u32, 0x9_0000u32);
        let mut buf = pe64(section, 0, 0x1000);
        buf.resize(0x200 + section.1 as usize, 0);
        let data = 0x200;
        let dll_name: u32 = 0x1_0000 - 0x10;
        buf[data + dll_name as usize..data + dll_name as usize + 6].copy_from_slice(b"x.dll\0");
        for d in 0..1000 {
            let off = data + d * 20;
            buf[off..off + 4].copy_from_slice(&(0x1000u32 + 0x1_0000).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&(0x1000 + dll_name).to_le_bytes());
        }
        for t in (data + 0x1_0000..buf.len()).step_by(8) {
            buf[t..t + 8].copy_from_slice(&(0x8000_0000_0000_0001u64).to_le_bytes());
        }
        let pe = parse(&buf).unwrap();
        let total: usize = pe.imports.iter().map(|i| i.functions.len()).sum();
        assert_eq!(total, MAX_IMPORT_FUNCTIONS);
        assert_eq!(pe.imports.len(), 1000);
        assert!(pe.imports[0].functions.len() > 60_000);
    }

    #[test]
    fn export_counts_are_capped_at_the_ordinal_space() {
        let section = (0x1000u32, 0x8_0000u32);
        let mut buf = pe64(section, 0x1000, 0);
        buf.resize(0x200 + section.1 as usize, 0);
        let dir = 0x200;
        for (field, value) in [(20, u32::MAX), (24, 0), (28, 0x1100)] {
            buf[dir + field..dir + field + 4].copy_from_slice(&value.to_le_bytes());
        }
        for e in (dir + 0x100..buf.len()).step_by(4) {
            buf[e..e + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        }
        let pe = parse(&buf).unwrap();
        assert_eq!(pe.exports.len(), MAX_EXPORTS);
        assert!(pe.exports.iter().all(|e| e.name.is_none()));
        assert_eq!(pe.exports[0].ordinal, 0);
        assert_eq!(pe.exports[MAX_EXPORTS - 1].ordinal, u16::MAX);
    }

    #[test]
    fn export_ordinals_saturate_on_a_corrupt_base() {
        let mut buf = pe64((0x1000, 0x200), 0x1000, 0);
        let dir = 0x200;
        for (field, value) in [(16, u32::MAX - 1), (20, 4), (28, 0x1100)] {
            buf[dir + field..dir + field + 4].copy_from_slice(&value.to_le_bytes());
        }
        for e in 0..4 {
            let off = dir + 0x100 + e * 4;
            buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        }
        let ordinals: Vec<_> = parse(&buf)
            .unwrap()
            .exports
            .iter()
            .map(|e| e.ordinal)
            .collect();
        assert_eq!(ordinals, [u16::MAX; 4]);
    }

    #[test]
    fn huge_e_lfanew_is_a_bad_offset() {
        let mut buf = vec![0u8; 64];
        buf[0..2].copy_from_slice(b"MZ");
        for lfanew in [u32::MAX, u32::MAX - 3, 61, 64] {
            buf[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
            assert_eq!(parse(&buf).unwrap_err(), PeError::BadPeOffset, "{lfanew}");
        }
    }

    #[test]
    fn display_impls() {
        let machines = [
            (0x014c, "i386"),
            (0x0200, "IA64"),
            (0x8664, "x86-64"),
            (0xaa64, "ARM64"),
            (0x01c0, "ARM"),
            (0x01c4, "ARMv7"),
            (0x01f0, "PowerPC"),
            (0x1234, "0x1234"),
        ];
        for (m, name) in machines {
            assert_eq!(Machine(m).to_string(), name);
        }
        assert_eq!(PeMagic::Pe32.to_string(), "PE32");
        assert_eq!(PeMagic::Pe64.to_string(), "PE32+");
        for (err, text) in [
            (PeError::TooShort, "file too short for PE headers"),
            (PeError::BadMzMagic, "not a PE file (no MZ signature)"),
            (PeError::BadPeOffset, "PE offset out of bounds"),
            (PeError::BadPeSignature, "PE signature not found"),
            (
                PeError::UnknownMagic(0x107),
                "unknown optional header magic: 0x0107",
            ),
            (
                PeError::OutOfBounds,
                "PE structure references out-of-bounds data",
            ),
        ] {
            assert_eq!(err.to_string(), text);
        }
    }

    #[test]
    fn import_function_display_name() {
        let f = |name: Option<&str>, ordinal| ImportFunction {
            name: name.map(str::to_string),
            ordinal,
            hint: None,
        };
        assert_eq!(f(Some("CreateFileW"), None).display_name(), "CreateFileW");
        assert_eq!(f(None, Some(42)).display_name(), "#42");
        assert_eq!(f(None, None).display_name(), "?");
    }

    #[test]
    fn suspicious_imports_match_by_prefix() {
        let mut pe = parse(&pe64((0x1000, 0x200), 0, 0)).unwrap();
        let named = |n: &str| ImportFunction {
            name: Some(n.to_string()),
            ordinal: None,
            hint: None,
        };
        pe.imports.push(Import {
            dll: "kernel32.dll".into(),
            functions: vec![
                named("VirtualAllocExNuma"),
                named("CreateFileW"),
                ImportFunction {
                    name: None,
                    ordinal: Some(1),
                    hint: None,
                },
                named("IsDebuggerPresent"),
            ],
        });
        let hits: Vec<_> = suspicious_imports(&pe)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(hits, ["VirtualAllocExNuma", "IsDebuggerPresent"]);
    }

    #[test]
    fn security_score_counts_five_flags() {
        let all = SecurityFlags {
            aslr: true,
            high_entropy_va: true,
            dep: true,
            no_seh: true,
            cfg: true,
            force_integrity: true,
            signed: true,
        };
        assert_eq!(all.score(), 5, "high-entropy VA and signing are not scored");
        assert_eq!(SecurityFlags::default().score(), 0);
    }
}
