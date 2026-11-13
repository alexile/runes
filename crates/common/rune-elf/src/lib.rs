//! Lightweight ELF binary parser — pure Rust, no unsafe, no external dependencies.
//!
//! Parses Linux/BSD ELF executables and shared libraries to extract header fields,
//! section and segment tables, dynamic symbol imports, and hardening flags relevant
//! to security analysis.
//!
//! # Features
//!
//! - [`parse`] — parse ELF from a byte slice, returns [`Elf`]
//! - [`Elf`] — top-level struct with header, sections, segments, symbols,
//!   `DT_NEEDED` shared-library names, and the `PT_INTERP` dynamic-linker path
//! - [`ElfHeader`] — machine type, file type, entry point, bitness, endianness
//! - [`SecurityFlags`] — PIE, NX stack, RELRO, stack canary, `FORTIFY_SOURCE`, stripped
//! - [`Section`] — name, type, flags, virtual address, file offset, size
//! - [`Segment`] — program header type, flags, file offset, virtual address, file size
//! - [`DynSym`] — name and address of dynamic symbol (imports/exports)
//!
//! # Quick Start
//!
//! [`parse`] works on any byte slice. This example builds a minimal 64-bit
//! x86-64 position-independent executable in memory: an ELF header, a
//! `PT_INTERP` program header naming the dynamic linker, a `PT_GNU_STACK`
//! header without the execute bit, and the interpreter path itself.
//!
//! ```rust
//! use rune_elf::{ElfClass, ElfType, SegmentType, parse};
//!
//! fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
//!     buf[off..off + bytes.len()].copy_from_slice(bytes);
//! }
//!
//! const EHDR: usize = 64; // ELF64 header size
//! const PHDR: usize = 56; // ELF64 program header size
//! let interp = b"/lib64/ld-linux-x86-64.so.2\0";
//!
//! let mut image = vec![0u8; EHDR + 2 * PHDR];
//! put(&mut image, 0, b"\x7fELF\x02\x01\x01"); // magic, ELFCLASS64, little-endian, v1
//! put(&mut image, 16, &3u16.to_le_bytes()); // e_type: ET_DYN
//! put(&mut image, 18, &62u16.to_le_bytes()); // e_machine: EM_X86_64
//! put(&mut image, 24, &0x1040u64.to_le_bytes()); // e_entry
//! put(&mut image, 32, &(EHDR as u64).to_le_bytes()); // e_phoff
//! put(&mut image, 54, &(PHDR as u16).to_le_bytes()); // e_phentsize
//! put(&mut image, 56, &2u16.to_le_bytes()); // e_phnum
//!
//! let interp_ph = EHDR;
//! put(&mut image, interp_ph, &3u32.to_le_bytes()); // p_type: PT_INTERP
//! put(&mut image, interp_ph + 4, &4u32.to_le_bytes()); // p_flags: R
//! put(&mut image, interp_ph + 8, &((EHDR + 2 * PHDR) as u64).to_le_bytes()); // p_offset
//! put(&mut image, interp_ph + 32, &(interp.len() as u64).to_le_bytes()); // p_filesz
//!
//! let stack_ph = EHDR + PHDR;
//! put(&mut image, stack_ph, &0x6474_e551u32.to_le_bytes()); // p_type: PT_GNU_STACK
//! put(&mut image, stack_ph + 4, &6u32.to_le_bytes()); // p_flags: R | W, no X
//!
//! image.extend_from_slice(interp);
//!
//! let elf = parse(&image).unwrap();
//! assert_eq!(elf.header.class, ElfClass::Elf64);
//! assert_eq!(elf.header.elf_type, ElfType::Shared);
//! assert_eq!(elf.header.machine.to_string(), "x86-64");
//! assert_eq!(elf.header.entry, 0x1040);
//! assert_eq!(elf.segments[0].segment_type, SegmentType::Interp);
//! assert_eq!(elf.interpreter.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
//!
//! // Hardening: PIE and a non-executable stack, but no RELRO or canary.
//! assert!(elf.security.pie);
//! assert!(elf.security.nx_stack);
//! assert!(!elf.security.relro && !elf.security.stack_canary);
//! assert_eq!(elf.security.score(), 2);
//! ```
//!
//! On a real binary:
//!
//! ```rust,no_run
//! use rune_elf::parse;
//! use std::fs;
//!
//! let bytes = fs::read("/bin/ls").unwrap();
//! let elf = parse(&bytes).unwrap();
//! println!("machine:  {}", elf.header.machine);
//! println!("PIE:      {}", elf.security.pie);
//! println!("NX stack: {}", elf.security.nx_stack);
//! println!("RELRO:    {}", elf.security.relro);
//! println!("canary:   {}", elf.security.stack_canary);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-elf /bin/ls
//! rune-elf --json firmware.elf
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use core::fmt;

/// Errors produced by the ELF parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// The file is too short to contain a valid ELF header.
    TooShort,
    /// The ELF magic bytes are wrong.
    BadMagic,
    /// ELF class (bitness) is not 1 (32-bit) or 2 (64-bit).
    UnknownClass(u8),
    /// Data encoding is not 1 (little-endian) or 2 (big-endian).
    UnknownEncoding(u8),
    /// Byte range needed by the parser is outside the file.
    OutOfBounds,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "file too short for ELF header"),
            Self::BadMagic => write!(f, "not an ELF file (bad magic)"),
            Self::UnknownClass(c) => write!(f, "unknown ELF class: {c}"),
            Self::UnknownEncoding(e) => write!(f, "unknown ELF encoding: {e}"),
            Self::OutOfBounds => write!(f, "ELF structure references out-of-bounds data"),
        }
    }
}

/// Bitness of the ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// 32-bit ELF.
    Elf32,
    /// 64-bit ELF.
    Elf64,
}

impl fmt::Display for ElfClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf32 => write!(f, "ELF32"),
            Self::Elf64 => write!(f, "ELF64"),
        }
    }
}

/// Byte order of the ELF file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// Relocatable object file.
    Relocatable,
    /// Executable file (not PIE).
    Executable,
    /// Shared object / position-independent executable.
    Shared,
    /// Core dump.
    Core,
    /// Any other `e_type` value.
    Other(u16),
}

impl fmt::Display for ElfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocatable => write!(f, "REL"),
            Self::Executable => write!(f, "EXEC"),
            Self::Shared => write!(f, "DYN"),
            Self::Core => write!(f, "CORE"),
            Self::Other(v) => write!(f, "0x{v:04x}"),
        }
    }
}

/// CPU architecture from `e_machine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine(pub u16);

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            3 => "x86",
            8 => "MIPS",
            20 => "PowerPC",
            21 => "PowerPC 64",
            40 => "ARM",
            50 => "IA-64",
            62 => "x86-64",
            183 => "AArch64",
            243 => "RISC-V",
            _ => return write!(f, "Machine({})", self.0),
        };
        write!(f, "{name}")
    }
}

/// Core ELF header fields relevant to security analysis.
#[derive(Debug, Clone)]
pub struct ElfHeader {
    /// 32- or 64-bit file class.
    pub class: ElfClass,
    /// Byte order of multi-byte fields.
    pub endian: Endian,
    /// Object file type.
    pub elf_type: ElfType,
    /// Target instruction set.
    pub machine: Machine,
    /// Entry point virtual address.
    pub entry: u64,
    /// ELF OS/ABI byte.
    pub os_abi: u8,
}

/// ELF program header (segment) type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    /// Unused entry (`PT_NULL`).
    Null,
    /// Loadable segment (`PT_LOAD`).
    Load,
    /// Dynamic linking information (`PT_DYNAMIC`).
    Dynamic,
    /// Path of the program interpreter (`PT_INTERP`).
    Interp,
    /// Auxiliary notes (`PT_NOTE`).
    Note,
    /// Exception-handling frame table (`PT_GNU_EH_FRAME`).
    GnuEhFrame,
    /// GNU stack segment — flags indicate whether the stack is executable.
    GnuStack,
    /// GNU RELRO segment — makes a region read-only after dynamic linking.
    GnuRelro,
    /// GNU program properties (`PT_GNU_PROPERTY`).
    GnuProperty,
    /// Any other `p_type` value.
    Other(u32),
}

impl fmt::Display for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Null => "NULL",
            Self::Load => "LOAD",
            Self::Dynamic => "DYNAMIC",
            Self::Interp => "INTERP",
            Self::Note => "NOTE",
            Self::GnuEhFrame => "GNU_EH_FRAME",
            Self::GnuStack => "GNU_STACK",
            Self::GnuRelro => "GNU_RELRO",
            Self::GnuProperty => "GNU_PROPERTY",
            Self::Other(v) => return write!(f, "0x{v:08x}"),
        };
        write!(f, "{name}")
    }
}

/// An ELF program header / segment.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment type (`p_type`).
    pub segment_type: SegmentType,
    /// Segment flags: `PF_X=1`, `PF_W=2`, `PF_R=4`.
    pub flags: u32,
    /// Offset of the segment in the file.
    pub file_offset: u64,
    /// Virtual address of the segment in memory.
    pub virtual_addr: u64,
    /// Size of the segment in the file.
    pub file_size: u64,
    /// Size of the segment in memory.
    pub mem_size: u64,
    /// Required alignment.
    pub align: u64,
}

impl Segment {
    /// Whether the segment is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & 0x1 != 0
    }
    /// Whether the segment is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & 0x2 != 0
    }
    /// Whether the segment is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.flags & 0x4 != 0
    }
}

/// ELF section header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Inactive section header (`SHT_NULL`).
    Null,
    /// Program-defined data (`SHT_PROGBITS`).
    ProgBits,
    /// Static symbol table (`SHT_SYMTAB`).
    SymTab,
    /// String table (`SHT_STRTAB`).
    StrTab,
    /// Relocations with addends (`SHT_RELA`).
    Rela,
    /// Symbol hash table (`SHT_HASH`).
    Hash,
    /// Dynamic linking information (`SHT_DYNAMIC`).
    Dynamic,
    /// Notes (`SHT_NOTE`).
    Note,
    /// Zero-initialised data with no file contents (`SHT_NOBITS`).
    NoBits,
    /// Relocations without addends (`SHT_REL`).
    Rel,
    /// Dynamic symbol table (`SHT_DYNSYM`).
    DynSym,
    /// Array of constructors (`SHT_INIT_ARRAY`).
    InitArray,
    /// Array of destructors (`SHT_FINI_ARRAY`).
    FiniArray,
    /// GNU-style symbol hash table (`SHT_GNU_HASH`).
    GnuHash,
    /// Symbol version table (`SHT_GNU_versym`).
    GnuVersionSym,
    /// Required symbol versions (`SHT_GNU_verneed`).
    GnuVersionNeed,
    /// Defined symbol versions (`SHT_GNU_verdef`).
    GnuVersionDef,
    /// Any other `sh_type` value.
    Other(u32),
}

/// An ELF section.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name from the section header string table.
    pub name: String,
    /// Section type (`sh_type`).
    pub section_type: SectionType,
    /// Section flags (`SHF_WRITE=1`, `SHF_ALLOC=2`, `SHF_EXECINSTR=4`, ...).
    pub flags: u64,
    /// Virtual address of the section in memory.
    pub virtual_addr: u64,
    /// Offset of the section in the file.
    pub file_offset: u64,
    /// Size of the section in bytes.
    pub size: u64,
}

impl Section {
    /// Whether the section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & 0x4 != 0
    }
    /// Whether the section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & 0x1 != 0
    }
}

/// A dynamic symbol (import or export).
#[derive(Debug, Clone)]
pub struct DynSym {
    /// Symbol name from the dynamic string table.
    pub name: String,
    /// Symbol value (usually its address); `0` for imports.
    pub value: u64,
    /// Size of the symbol in bytes.
    pub size: u64,
    /// Symbol binding: `STB_LOCAL=0`, `STB_GLOBAL=1`, `STB_WEAK=2`.
    pub binding: u8,
    /// Symbol type: `STT_NOTYPE=0`, `STT_OBJECT=1`, `STT_FUNC=2`, `STT_SECTION=3`.
    pub sym_type: u8,
}

impl DynSym {
    /// Whether the symbol is a function (`STT_FUNC`).
    #[must_use]
    pub const fn is_function(&self) -> bool {
        self.sym_type == 2
    }
    /// Whether the symbol has global binding (`STB_GLOBAL`).
    #[must_use]
    pub const fn is_global(&self) -> bool {
        self.binding == 1
    }
    /// Whether the symbol is undefined here, i.e. imported from another object.
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        self.value == 0 && self.size == 0
    }
}

/// Security hardening flags extracted from the ELF structure.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_elf::parse;
/// use std::fs;
///
/// let bytes = fs::read("/bin/ls").unwrap();
/// let elf = parse(&bytes).unwrap();
/// let s = &elf.security;
/// assert!(s.nx_stack, "ls should have a non-executable stack");
/// ```
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent, documented switch"
)]
#[derive(Debug, Clone, Default)]
pub struct SecurityFlags {
    /// Position-independent executable: `e_type == ET_DYN` (enables ASLR).
    pub pie: bool,
    /// Non-executable stack: `PT_GNU_STACK` present with `PF_X` clear.
    pub nx_stack: bool,
    /// Read-only relocations after startup: `PT_GNU_RELRO` segment present.
    pub relro: bool,
    /// Stack canary: `__stack_chk_fail` or `__stack_chk_guard` in the
    /// dynamic symbol table.
    pub stack_canary: bool,
    /// `FORTIFY_SOURCE`: at least one `__*_chk` dynamic symbol present.
    pub fortify: bool,
    /// No `.symtab` section (debug symbols stripped).
    pub stripped: bool,
    /// Immediate binding (full RELRO when combined with `relro`):
    /// `DT_BIND_NOW`, `DF_BIND_NOW` in `DT_FLAGS`, or `DF_1_NOW` in
    /// `DT_FLAGS_1`.
    pub bind_now: bool,
}

impl SecurityFlags {
    /// Score from 0–6 counting how many hardening features are enabled.
    #[must_use]
    pub fn score(&self) -> u8 {
        [
            self.pie,
            self.nx_stack,
            self.relro,
            self.stack_canary,
            self.fortify,
            self.bind_now,
        ]
        .into_iter()
        .map(u8::from)
        .sum()
    }
}

/// A parsed ELF binary.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_elf::parse;
/// use std::fs;
///
/// let bytes = fs::read("/bin/ls").unwrap();
/// let elf = parse(&bytes).unwrap();
/// println!("{} ({}) entry=0x{:x}", elf.header.machine, elf.header.elf_type, elf.header.entry);
/// for sym in elf.dynamic_symbols.iter().filter(|s| s.is_undefined()) {
///     println!("  import: {}", sym.name);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Elf {
    /// Parsed ELF header.
    pub header: ElfHeader,
    /// Program headers (segments).
    pub segments: Vec<Segment>,
    /// Section headers.
    pub sections: Vec<Section>,
    /// Dynamic symbols (imports and exports).
    pub dynamic_symbols: Vec<DynSym>,
    /// Paths to shared libraries listed in `DT_NEEDED` entries.
    pub needed_libs: Vec<String>,
    /// The dynamic linker path from the `PT_INTERP` segment, if present.
    /// `None` for a static binary.
    pub interpreter: Option<String>,
    /// Hardening features detected in the binary.
    pub security: SecurityFlags,
}

/// Parse an ELF binary from a byte slice.
///
/// # Errors
///
/// Returns [`ElfError`] if the bytes do not form a valid ELF file or contain
/// out-of-bounds offsets.
///
/// # Untrusted input
///
/// The input may be hostile. Tables that run past the end of the file are
/// cut short, header tables with undersized entries are ignored, the
/// dynamic section stops at `DT_NULL`, the interpreter path must end inside
/// its `PT_INTERP` segment, and names longer than 4096 bytes (or
/// unterminated) are reported as empty. Section, symbol and library names
/// together are at most twice the size of the file; once that is used up,
/// further names are reported as empty too (and those symbols and libraries
/// are left out). Without section headers, `DT_NEEDED`
/// and the binding flags are read from the `PT_DYNAMIC` segment.
///
/// # Examples
///
/// ```rust
/// use rune_elf::{parse, ElfError};
///
/// // Too short
/// assert_eq!(parse(b"not").unwrap_err(), ElfError::TooShort);
/// // Right length, bad magic
/// let mut buf = vec![0u8; 64];
/// assert_eq!(parse(&buf).unwrap_err(), ElfError::BadMagic);
/// ```
#[allow(
    clippy::too_many_lines,
    reason = "a single linear decode of the header layout reads best in one place"
)]
#[allow(
    clippy::similar_names,
    reason = "names mirror the ELF specification fields"
)]
pub fn parse(bytes: &[u8]) -> Result<Elf, ElfError> {
    if bytes.len() < 64 {
        return Err(ElfError::TooShort);
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }

    let class = match bytes[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        c => return Err(ElfError::UnknownClass(c)),
    };
    let endian = match bytes[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        e => return Err(ElfError::UnknownEncoding(e)),
    };

    let read16 = |off: usize| -> Result<u16, ElfError> {
        let s = *bytes
            .get(off..)
            .and_then(<[u8]>::first_chunk::<2>)
            .ok_or(ElfError::OutOfBounds)?;
        Ok(if endian == Endian::Little {
            u16::from_le_bytes(s)
        } else {
            u16::from_be_bytes(s)
        })
    };
    let read32 = |off: usize| -> Result<u32, ElfError> {
        let s = *bytes
            .get(off..)
            .and_then(<[u8]>::first_chunk::<4>)
            .ok_or(ElfError::OutOfBounds)?;
        Ok(if endian == Endian::Little {
            u32::from_le_bytes(s)
        } else {
            u32::from_be_bytes(s)
        })
    };
    let read64 = |off: usize| -> Result<u64, ElfError> {
        let s = *bytes
            .get(off..)
            .and_then(<[u8]>::first_chunk::<8>)
            .ok_or(ElfError::OutOfBounds)?;
        Ok(if endian == Endian::Little {
            u64::from_le_bytes(s)
        } else {
            u64::from_be_bytes(s)
        })
    };
    // A 64-bit file offset or size, rejected if it does not fit in `usize`.
    let read_offset = |off: usize| -> Result<usize, ElfError> {
        usize::try_from(read64(off)?).map_err(|_| ElfError::OutOfBounds)
    };

    let os_abi = bytes[7];

    let (
        e_type,
        e_machine,
        e_entry,
        e_phoff,
        e_shoff,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = if class == ElfClass::Elf64 {
        (
            read16(16)?,
            read16(18)?,
            read64(24)?,
            read_offset(32)?,
            read_offset(40)?,
            read16(54)? as usize,
            read16(56)? as usize,
            read16(58)? as usize,
            read16(60)? as usize,
            read16(62)? as usize,
        )
    } else {
        (
            read16(16)?,
            read16(18)?,
            u64::from(read32(24)?),
            read32(28)? as usize,
            read32(32)? as usize,
            read16(42)? as usize,
            read16(44)? as usize,
            read16(46)? as usize,
            read16(48)? as usize,
            read16(50)? as usize,
        )
    };

    let elf_type = match e_type {
        1 => ElfType::Relocatable,
        2 => ElfType::Executable,
        3 => ElfType::Shared,
        4 => ElfType::Core,
        v => ElfType::Other(v),
    };

    let header = ElfHeader {
        class,
        endian,
        elf_type,
        machine: Machine(e_machine),
        entry: e_entry,
        os_abi,
    };

    // Header table entries smaller than the standard size would make every
    // field read below run into the next entry; such a table is ignored.
    let (sh_min, ph_min) = if class == ElfClass::Elf64 {
        (64, 56)
    } else {
        (40, 32)
    };
    let e_shnum = if e_shentsize >= sh_min { e_shnum } else { 0 };
    let e_phnum = if e_phentsize >= ph_min { e_phnum } else { 0 };

    // ── Section name string table ──────────────────────────────────────────
    // Every offset below comes from the file, so all arithmetic on it is
    // checked: a crafted header must yield an error or a partial result, never
    // an overflow.
    let strtab_offset = (e_shnum > 0)
        .then(|| table_entry(e_shoff, e_shstrndx, e_shentsize, bytes.len()))
        .flatten()
        .and_then(|shstr| {
            if class == ElfClass::Elf64 {
                read_offset(shstr.checked_add(24)?).ok()
            } else {
                read32(shstr.checked_add(16)?).ok().map(|v| v as usize)
            }
        })
        .unwrap_or(0);

    // Section, symbol and library names, capped per name and in total.
    let mut names = Names::new(bytes);

    // ── Sections ──────────────────────────────────────────────────────────
    let mut sections = Vec::new();
    // `(sh_offset, sh_link)` of each section, for resolving string tables.
    let mut raw_sections: Vec<(usize, usize)> = Vec::new();
    let mut symtab_found = false;
    let mut dynsym: Option<(usize, usize, usize)> = None;
    let mut dynamic_section: Option<(usize, usize, usize)> = None;
    let mut dynstr_by_name: Option<usize> = None;

    for i in 0..e_shnum {
        let Some(sh_off) = table_entry(e_shoff, i, e_shentsize, bytes.len()) else {
            break;
        };

        let (sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link) =
            if class == ElfClass::Elf64 {
                (
                    read32(sh_off)? as usize,
                    read32(sh_off + 4)?,
                    read64(sh_off + 8)?,
                    read64(sh_off + 16)?,
                    read_offset(sh_off + 24)?,
                    read_offset(sh_off + 32)?,
                    read32(sh_off + 40)? as usize,
                )
            } else {
                (
                    read32(sh_off)? as usize,
                    read32(sh_off + 4)?,
                    u64::from(read32(sh_off + 8)?),
                    u64::from(read32(sh_off + 12)?),
                    read32(sh_off + 16)? as usize,
                    read32(sh_off + 20)? as usize,
                    read32(sh_off + 24)? as usize,
                )
            };

        let name = if strtab_offset > 0 {
            strtab_offset
                .checked_add(sh_name_idx)
                .map(|start| names.read(start))
                .unwrap_or_default()
        } else {
            String::new()
        };

        let section_type = match sh_type {
            0 => SectionType::Null,
            1 => SectionType::ProgBits,
            2 => {
                symtab_found = true;
                SectionType::SymTab
            }
            3 => SectionType::StrTab,
            4 => SectionType::Rela,
            5 => SectionType::Hash,
            6 => {
                dynamic_section = Some((sh_offset, sh_size, sh_link));
                SectionType::Dynamic
            }
            7 => SectionType::Note,
            8 => SectionType::NoBits,
            9 => SectionType::Rel,
            11 => {
                dynsym = Some((sh_offset, sh_size, sh_link));
                SectionType::DynSym
            }
            14 => SectionType::InitArray,
            15 => SectionType::FiniArray,
            0x6fff_fff6 => SectionType::GnuHash,
            0x6fff_fffd => SectionType::GnuVersionDef,
            0x6fff_fffe => SectionType::GnuVersionNeed,
            0x6fff_ffff => SectionType::GnuVersionSym,
            v => SectionType::Other(v),
        };

        if name == ".dynstr" {
            dynstr_by_name = Some(sh_offset);
        }

        raw_sections.push((sh_offset, sh_link));
        sections.push(Section {
            name,
            section_type,
            flags: sh_flags,
            virtual_addr: sh_addr,
            file_offset: sh_offset as u64,
            size: sh_size as u64,
        });
    }

    // The string table a `.dynsym` or `.dynamic` section links to (its
    // `sh_link`), falling back to the section named `.dynstr`.
    let linked_strtab = |link: usize| -> Option<usize> {
        sections
            .get(link)
            .filter(|s| s.section_type == SectionType::StrTab)
            .and_then(|_| raw_sections.get(link))
            .map(|&(offset, _)| offset)
            .or(dynstr_by_name)
    };

    // ── Program headers / segments ────────────────────────────────────────
    let mut segments = Vec::new();
    let mut gnu_stack_nx = false;
    let mut relro_present = false;
    let mut has_gnu_stack = false;
    let mut interpreter: Option<String> = None;

    for i in 0..e_phnum {
        let Some(ph_off) = table_entry(e_phoff, i, e_phentsize, bytes.len()) else {
            break;
        };

        let (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align) =
            if class == ElfClass::Elf64 {
                (
                    read32(ph_off)?,
                    read32(ph_off + 4)?,
                    read64(ph_off + 8)?,
                    read64(ph_off + 16)?,
                    read64(ph_off + 32)?,
                    read64(ph_off + 40)?,
                    read64(ph_off + 48)?,
                )
            } else {
                (
                    read32(ph_off)?,
                    read32(ph_off + 24)?,
                    u64::from(read32(ph_off + 4)?),
                    u64::from(read32(ph_off + 8)?),
                    u64::from(read32(ph_off + 16)?),
                    u64::from(read32(ph_off + 20)?),
                    u64::from(read32(ph_off + 28)?),
                )
            };

        let segment_type = match p_type {
            0 => SegmentType::Null,
            1 => SegmentType::Load,
            2 => SegmentType::Dynamic,
            3 => {
                // The path must end within the segment, not merely somewhere
                // later in the file.
                let path = file_range(p_offset, p_filesz, bytes.len())
                    .map(|(start, end)| read_cstr(&bytes[..end], start).to_string())
                    .unwrap_or_default();
                interpreter = Some(path);
                SegmentType::Interp
            }
            4 => SegmentType::Note,
            0x6474_e550 => SegmentType::GnuEhFrame,
            0x6474_e551 => {
                has_gnu_stack = true;
                gnu_stack_nx = p_flags & 0x1 == 0;
                SegmentType::GnuStack
            }
            0x6474_e552 => {
                relro_present = true;
                SegmentType::GnuRelro
            }
            0x6474_e553 => SegmentType::GnuProperty,
            v => SegmentType::Other(v),
        };

        segments.push(Segment {
            segment_type,
            flags: p_flags,
            file_offset: p_offset,
            virtual_addr: p_vaddr,
            file_size: p_filesz,
            mem_size: p_memsz,
            align: p_align,
        });
    }

    // ── Dynamic symbols ───────────────────────────────────────────────────
    let sym_entry_size = if class == ElfClass::Elf64 { 24 } else { 16 };
    let mut dynamic_symbols = Vec::new();

    if let Some((dsym_off, dsym_sz, link)) = dynsym
        && let Some(dstr_off) = linked_strtab(link)
    {
        let count = dsym_sz / sym_entry_size;
        for i in 0..count {
            let Some(base) = table_entry(dsym_off, i, sym_entry_size, bytes.len()) else {
                break;
            };

            let (st_name, st_value, st_size, st_info) = if class == ElfClass::Elf64 {
                (
                    read32(base)? as usize,
                    read64(base + 8)?,
                    read64(base + 16)?,
                    bytes[base + 4],
                )
            } else {
                (
                    read32(base)? as usize,
                    u64::from(read32(base + 4)?),
                    u64::from(read32(base + 8)?),
                    bytes[base + 12],
                )
            };

            let name = dstr_off
                .checked_add(st_name)
                .map(|start| names.read(start))
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }

            dynamic_symbols.push(DynSym {
                name,
                value: st_value,
                size: st_size,
                binding: st_info >> 4,
                sym_type: st_info & 0xf,
            });
        }
    }

    // ── Dynamic section: DT_NEEDED and binding flags ──────────────────────
    // From the `SHT_DYNAMIC` section, or from the `PT_DYNAMIC` segment when
    // the section headers are gone (`sstrip`ped binaries).
    let dyn_entry_size = if class == ElfClass::Elf64 { 16 } else { 8 };
    let dynamic_table = dynamic_section
        .map(|(offset, size, link)| (offset, size, linked_strtab(link)))
        .or_else(|| {
            segments
                .iter()
                .find(|s| s.segment_type == SegmentType::Dynamic)
                .and_then(|s| file_range(s.file_offset, s.file_size, bytes.len()))
                .map(|(start, end)| (start, end - start, dynstr_by_name))
        });

    let mut needed_offsets = Vec::new();
    let mut dt_strtab: Option<u64> = None;
    let mut bind_now = false;
    if let Some((dyn_off, dyn_sz, _)) = dynamic_table {
        for i in 0..dyn_sz / dyn_entry_size {
            let Some(base) = table_entry(dyn_off, i, dyn_entry_size, bytes.len()) else {
                break;
            };
            let (d_tag, d_val) = if class == ElfClass::Elf64 {
                (read64(base)?, read64(base + 8)?)
            } else {
                (u64::from(read32(base)?), u64::from(read32(base + 4)?))
            };
            match d_tag {
                DT_NULL => break,
                DT_NEEDED => needed_offsets.push(d_val),
                DT_STRTAB => dt_strtab = Some(d_val),
                DT_BIND_NOW => bind_now = true,
                DT_FLAGS => bind_now |= d_val & DF_BIND_NOW != 0,
                DT_FLAGS_1 => bind_now |= d_val & DF_1_NOW != 0,
                _ => {}
            }
        }
    }

    // The dynamic string table: from the section headers, else `DT_STRTAB`
    // (a virtual address) mapped to a file offset through the `PT_LOAD`s.
    let dynstr = dynamic_table.and_then(|(_, _, strtab)| strtab).or_else(|| {
        let vaddr = dt_strtab?;
        segments
            .iter()
            .filter(|s| s.segment_type == SegmentType::Load)
            .find(|s| vaddr >= s.virtual_addr && vaddr - s.virtual_addr < s.file_size)
            .and_then(|s| usize::try_from(s.file_offset.checked_add(vaddr - s.virtual_addr)?).ok())
    });

    let mut needed_libs = Vec::new();
    if let Some(dstr_off) = dynstr {
        for d_val in needed_offsets {
            let lib = usize::try_from(d_val)
                .ok()
                .and_then(|v| dstr_off.checked_add(v))
                .map(|start| names.read(start))
                .unwrap_or_default();
            if !lib.is_empty() {
                needed_libs.push(lib);
            }
        }
    }

    // ── Security flags ────────────────────────────────────────────────────
    let stack_canary = dynamic_symbols
        .iter()
        .any(|s| s.name == "__stack_chk_fail" || s.name == "__stack_chk_guard");
    let fortify = dynamic_symbols
        .iter()
        .any(|s| s.name.starts_with("__") && s.name.ends_with("_chk"));

    let security = SecurityFlags {
        pie: elf_type == ElfType::Shared,
        nx_stack: has_gnu_stack && gnu_stack_nx,
        relro: relro_present,
        stack_canary,
        fortify,
        stripped: !symtab_found,
        bind_now,
    };

    Ok(Elf {
        header,
        segments,
        sections,
        dynamic_symbols,
        needed_libs,
        interpreter,
        security,
    })
}

/// `DT_NULL`: marks the end of the dynamic section.
const DT_NULL: u64 = 0;
/// `DT_NEEDED`: string table offset of a needed library's name.
const DT_NEEDED: u64 = 1;
/// `DT_STRTAB`: virtual address of the dynamic string table.
const DT_STRTAB: u64 = 5;
/// `DT_BIND_NOW`: resolve all symbols at load time.
const DT_BIND_NOW: u64 = 24;
/// `DT_FLAGS`: `DF_*` flag word.
const DT_FLAGS: u64 = 30;
/// `DF_BIND_NOW` in `DT_FLAGS`.
const DF_BIND_NOW: u64 = 0x8;
/// `DT_FLAGS_1`: `DF_1_*` flag word.
const DT_FLAGS_1: u64 = 0x6fff_fffb;
/// `DF_1_NOW` in `DT_FLAGS_1`.
const DF_1_NOW: u64 = 0x1;

/// Longest section, symbol, library or interpreter name the parser keeps,
/// in bytes; a longer or unterminated string is treated as empty. Without a
/// cap, many entries pointing at one huge string would cost memory
/// quadratic in the file size.
const MAX_NAME_LEN: usize = 4096;

/// The NUL-terminated UTF-8 string at `start`, or `""` if it is out of
/// bounds, unterminated within [`MAX_NAME_LEN`] bytes, or not UTF-8.
fn read_cstr(bytes: &[u8], start: usize) -> &str {
    bytes
        .get(start..)
        .map(|s| &s[..s.len().min(MAX_NAME_LEN + 1)])
        .and_then(|s| s.iter().position(|&b| b == 0).map(|end| &s[..end]))
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
}

/// Copies names out of the file, at most twice the file's size in total.
///
/// Every symbol, section and `DT_NEEDED` entry can point at the same
/// string, so the per-name cap alone still lets a small file expand into
/// hundreds of megabytes of copies. Real files name each entry with its own
/// string (or share suffixes), so they stay far below the budget; past it,
/// names are reported as empty.
struct Names<'a> {
    bytes: &'a [u8],
    left: usize,
}

impl<'a> Names<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            left: bytes.len().saturating_mul(2),
        }
    }

    /// The name at `start`, as [`read_cstr`] reads it, or `""` once the
    /// budget is spent.
    fn read(&mut self, start: usize) -> String {
        let name = read_cstr(self.bytes, start);
        match self.left.checked_sub(name.len()) {
            Some(left) => {
                self.left = left;
                name.to_string()
            }
            None => String::new(),
        }
    }
}

/// `(start, end)` of `size` bytes at `offset`, clamped to a file of `len`
/// bytes, or `None` if `offset` is past the end.
fn file_range(offset: u64, size: u64, len: usize) -> Option<(usize, usize)> {
    let start = usize::try_from(offset).ok().filter(|&s| s <= len)?;
    let end = usize::try_from(offset.saturating_add(size)).map_or(len, |e| e.min(len));
    Some((start, end))
}

/// Offset of entry `index` in a table of `entry_size`-byte entries at
/// `table`, or `None` when the entry does not lie wholly inside a file of
/// `len` bytes (including when the arithmetic would overflow).
fn table_entry(table: usize, index: usize, entry_size: usize, len: usize) -> Option<usize> {
    let start = index.checked_mul(entry_size)?.checked_add(table)?;
    (start.checked_add(entry_size)? <= len).then_some(start)
}

/// Returns `true` if the byte slice starts with the ELF magic bytes.
///
/// # Examples
///
/// ```rust
/// use rune_elf::is_elf;
///
/// assert!(is_elf(b"\x7fELF\x02\x01\x01\x00remaining"));
/// assert!(!is_elf(b"MZ\x90\x00"));
/// ```
#[must_use]
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0..4] == *b"\x7fELF"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(parse(b"").unwrap_err(), ElfError::TooShort);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"MZ\x90\x00");
        assert_eq!(parse(&buf).unwrap_err(), ElfError::BadMagic);
    }

    #[test]
    fn rejects_unknown_class() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 9;
        assert_eq!(parse(&buf).unwrap_err(), ElfError::UnknownClass(9));
    }

    #[test]
    fn is_elf_detection() {
        assert!(is_elf(b"\x7fELF\x02\x01\x01\x00"));
        assert!(!is_elf(b"MZ\x90\x00"));
        assert!(!is_elf(b""));
    }

    #[test]
    fn minimal_64bit_elf_parses() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        buf[24..32].copy_from_slice(&0x4000u64.to_le_bytes()); // entry

        let elf = parse(&buf).unwrap();
        assert_eq!(elf.header.class, ElfClass::Elf64);
        assert_eq!(elf.header.endian, Endian::Little);
        assert_eq!(elf.header.elf_type, ElfType::Executable);
        assert_eq!(elf.header.entry, 0x4000);
        assert_eq!(format!("{}", elf.header.machine), "x86-64");
        assert_eq!(elf.interpreter, None);
    }

    #[test]
    fn a_real_dynamically_linked_binary_reports_its_interpreter_and_needed_libs() {
        let sh = std::path::Path::new("/usr/bin/sh");
        if !sh.is_file() {
            return;
        }
        let bytes = std::fs::read(sh).unwrap();
        let elf = parse(&bytes).unwrap();
        let interp = elf
            .interpreter
            .as_ref()
            .expect("a dynamically-linked binary should have a PT_INTERP segment");
        assert!(
            interp.contains("ld-linux") || interp.contains("ld.so"),
            "expected a real dynamic linker path, got {interp}"
        );
        assert!(
            elf.needed_libs.iter().any(|lib| lib.contains("libc")),
            "expected libc among DT_NEEDED entries, got {:?}",
            elf.needed_libs
        );

        let interp_segment = elf
            .segments
            .iter()
            .find(|s| s.segment_type == SegmentType::Interp)
            .expect("PT_INTERP segment should be present");
        assert!(
            interp_segment.file_offset > 0,
            "PT_INTERP file_offset should be a real, nonzero file position"
        );
    }

    /// A little-endian ELF64 header followed by one 64-byte section header.
    fn elf64_with_section(e_shoff: u64, sh_name: u32, sh_offset: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little-endian
        buf[40..48].copy_from_slice(&e_shoff.to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf[60..62].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
        buf[64..68].copy_from_slice(&sh_name.to_le_bytes());
        buf[64 + 24..64 + 32].copy_from_slice(&sh_offset.to_le_bytes());
        buf
    }

    // Regression: `strtab_offset + sh_name` overflowed when
    // the section name string table sat at a huge offset.
    #[test]
    fn huge_string_table_offset_is_not_an_overflow() {
        let elf = parse(&elf64_with_section(64, u32::MAX, u64::MAX >> 1)).unwrap();
        assert_eq!(elf.sections.len(), 1);
        assert_eq!(elf.sections[0].name, "");
    }

    // Regression: `e_shoff + i * e_shentsize` overflowed for a
    // section header table at the end of the address space.
    #[test]
    fn section_table_past_the_address_space_is_skipped() {
        let elf = parse(&elf64_with_section(u64::MAX >> 1, 0, 0)).unwrap();
        assert!(elf.sections.is_empty());
    }

    // Regression: the GNU section types were mapped to the wrong
    // values (`SHT_GNU_HASH` is 0x6ffffff6, not `SHT_GNU_versym`'s
    // 0x6fffffff), so real `.gnu.hash` sections came out as `Other`.
    #[test]
    fn gnu_section_types() {
        for (sh_type, expected) in [
            (0x6fff_fff6u32, SectionType::GnuHash),
            (0x6fff_fffd, SectionType::GnuVersionDef),
            (0x6fff_fffe, SectionType::GnuVersionNeed),
            (0x6fff_ffff, SectionType::GnuVersionSym),
            (0x6fff_ffef, SectionType::Other(0x6fff_ffef)),
            (0x6fff_fff0, SectionType::Other(0x6fff_fff0)),
        ] {
            let mut buf = elf64_with_section(64, 0, 0);
            buf[68..72].copy_from_slice(&sh_type.to_le_bytes());
            let elf = parse(&buf).unwrap();
            assert_eq!(elf.sections[0].section_type, expected, "0x{sh_type:08x}");
        }
    }

    #[test]
    fn standard_section_types() {
        let types = [
            (0u32, SectionType::Null),
            (1, SectionType::ProgBits),
            (2, SectionType::SymTab),
            (3, SectionType::StrTab),
            (4, SectionType::Rela),
            (5, SectionType::Hash),
            (6, SectionType::Dynamic),
            (7, SectionType::Note),
            (8, SectionType::NoBits),
            (9, SectionType::Rel),
            (11, SectionType::DynSym),
            (14, SectionType::InitArray),
            (15, SectionType::FiniArray),
            (10, SectionType::Other(10)),
        ];
        for (sh_type, expected) in types {
            let mut buf = elf64_with_section(64, 0, 0);
            buf[68..72].copy_from_slice(&sh_type.to_le_bytes());
            let elf = parse(&buf).unwrap();
            assert_eq!(elf.sections[0].section_type, expected);
            assert_eq!(elf.security.stripped, sh_type != 2);
        }
    }

    // Regression: strings were read up to the next NUL anywhere in the
    // file, so many symbols naming one huge string cost quadratic memory.
    #[test]
    fn names_longer_than_the_cap_are_dropped() {
        let mut bytes = vec![b'a'; MAX_NAME_LEN + 10];
        bytes.push(0);
        assert_eq!(read_cstr(&bytes, 0), "");
        assert_eq!(read_cstr(&bytes, 10).len(), MAX_NAME_LEN);
        assert_eq!(read_cstr(&bytes, usize::MAX), "");
        assert_eq!(
            read_cstr(b"\xc3\x28\0", 0),
            "",
            "non-UTF-8 names are dropped"
        );
    }

    #[test]
    fn file_ranges_are_clamped() {
        assert_eq!(file_range(0, 10, 100), Some((0, 10)));
        assert_eq!(file_range(90, 50, 100), Some((90, 100)));
        assert_eq!(file_range(100, 1, 100), Some((100, 100)));
        assert_eq!(file_range(101, 0, 100), None);
        assert_eq!(file_range(u64::MAX, u64::MAX, 100), None);
        assert_eq!(file_range(5, u64::MAX, 100), Some((5, 100)));
    }

    #[test]
    fn table_entries_are_checked() {
        assert_eq!(table_entry(64, 2, 64, 256), Some(192));
        assert_eq!(table_entry(64, 3, 64, 256), None);
        assert_eq!(table_entry(usize::MAX, 0, 1, usize::MAX), None);
        assert_eq!(table_entry(0, usize::MAX, 2, usize::MAX), None);
    }

    #[test]
    fn display_impls() {
        let machines = [
            (3, "x86"),
            (8, "MIPS"),
            (20, "PowerPC"),
            (21, "PowerPC 64"),
            (40, "ARM"),
            (50, "IA-64"),
            (62, "x86-64"),
            (183, "AArch64"),
            (243, "RISC-V"),
            (999, "Machine(999)"),
        ];
        for (m, name) in machines {
            assert_eq!(Machine(m).to_string(), name);
        }
        assert_eq!(ElfClass::Elf32.to_string(), "ELF32");
        assert_eq!(ElfClass::Elf64.to_string(), "ELF64");
        for (t, name) in [
            (ElfType::Relocatable, "REL"),
            (ElfType::Executable, "EXEC"),
            (ElfType::Shared, "DYN"),
            (ElfType::Core, "CORE"),
            (ElfType::Other(0xfe00), "0xfe00"),
        ] {
            assert_eq!(t.to_string(), name);
        }
        for (t, name) in [
            (SegmentType::Null, "NULL"),
            (SegmentType::Load, "LOAD"),
            (SegmentType::Dynamic, "DYNAMIC"),
            (SegmentType::Interp, "INTERP"),
            (SegmentType::Note, "NOTE"),
            (SegmentType::GnuEhFrame, "GNU_EH_FRAME"),
            (SegmentType::GnuStack, "GNU_STACK"),
            (SegmentType::GnuRelro, "GNU_RELRO"),
            (SegmentType::GnuProperty, "GNU_PROPERTY"),
            (SegmentType::Other(0x7000_0001), "0x70000001"),
        ] {
            assert_eq!(t.to_string(), name);
        }
        for (e, text) in [
            (ElfError::TooShort, "file too short for ELF header"),
            (ElfError::BadMagic, "not an ELF file (bad magic)"),
            (ElfError::UnknownClass(7), "unknown ELF class: 7"),
            (ElfError::UnknownEncoding(9), "unknown ELF encoding: 9"),
            (
                ElfError::OutOfBounds,
                "ELF structure references out-of-bounds data",
            ),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }

    #[test]
    fn segment_and_section_permission_helpers() {
        let seg = |flags| Segment {
            segment_type: SegmentType::Load,
            flags,
            file_offset: 0,
            virtual_addr: 0,
            file_size: 0,
            mem_size: 0,
            align: 0,
        };
        assert!(seg(1).is_executable() && !seg(1).is_writable() && !seg(1).is_readable());
        assert!(seg(2).is_writable() && !seg(2).is_executable());
        assert!(seg(4).is_readable() && !seg(4).is_writable());
        let sec = |flags| Section {
            name: String::new(),
            section_type: SectionType::ProgBits,
            flags,
            virtual_addr: 0,
            file_offset: 0,
            size: 0,
        };
        assert!(sec(0x6).is_executable() && !sec(0x6).is_writable());
        assert!(sec(0x3).is_writable() && !sec(0x3).is_executable());
    }

    #[test]
    fn dynamic_symbol_helpers() {
        let sym = |value, size, info: u8| DynSym {
            name: "f".into(),
            value,
            size,
            binding: info >> 4,
            sym_type: info & 0xf,
        };
        let import = sym(0, 0, 0x12);
        assert!(import.is_undefined() && import.is_function() && import.is_global());
        let local_object = sym(0x1000, 8, 0x01);
        assert!(!local_object.is_undefined() && !local_object.is_function());
        assert!(!local_object.is_global());
    }

    #[test]
    fn security_score_counts_six_flags() {
        let all = SecurityFlags {
            pie: true,
            nx_stack: true,
            relro: true,
            stack_canary: true,
            fortify: true,
            stripped: true,
            bind_now: true,
        };
        assert_eq!(all.score(), 6, "stripped is not scored");
        assert_eq!(SecurityFlags::default().score(), 0);
    }
}
