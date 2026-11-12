//! A small ELF image builder for the integration tests: either class, either
//! byte order. Layout: ELF header, program headers, section contents
//! (8-byte aligned), a generated `.shstrtab`, then the section headers.

#![allow(dead_code, reason = "each test binary uses a different subset")]
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    reason = "test-only builder: sizes are small constants and a failure is a test bug"
)]

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_DYNSYM: u32 = 11;

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_STRTAB: u64 = 5;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_FLAGS: u64 = 30;
pub const DT_FLAGS_1: u64 = 0x6fff_fffb;

/// Byte order and class of the image being built.
#[derive(Clone, Copy)]
pub struct Format {
    pub elf64: bool,
    pub big: bool,
}

impl Format {
    pub const LE64: Self = Self {
        elf64: true,
        big: false,
    };
    pub const BE64: Self = Self {
        elf64: true,
        big: true,
    };
    pub const LE32: Self = Self {
        elf64: false,
        big: false,
    };
    pub const BE32: Self = Self {
        elf64: false,
        big: true,
    };
    pub const ALL: [Self; 4] = [Self::LE64, Self::BE64, Self::LE32, Self::BE32];

    pub fn u16(self, v: u16) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    pub fn u32(self, v: u32) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    pub fn u64(self, v: u64) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    /// An address-sized word (`Elf32_Addr`/`Elf64_Addr` and friends).
    pub fn word(self, v: u64) -> Vec<u8> {
        if self.elf64 {
            self.u64(v)
        } else {
            self.u32(u32::try_from(v).unwrap())
        }
    }
    pub fn ehdr_size(self) -> usize {
        if self.elf64 { 64 } else { 52 }
    }
    pub fn phdr_size(self) -> usize {
        if self.elf64 { 56 } else { 32 }
    }
    pub fn shdr_size(self) -> usize {
        if self.elf64 { 64 } else { 40 }
    }
}

/// What a program header covers in the file.
#[derive(Clone)]
pub enum Content {
    /// Nothing (offset and size 0).
    Empty,
    /// The contents of section `index` in [`ElfSpec::sections`].
    Section(usize),
    /// The whole file from offset 0.
    WholeFile,
}

#[derive(Clone)]
pub struct SegSpec {
    pub p_type: u32,
    pub flags: u32,
    pub vaddr: u64,
    pub content: Content,
}

#[derive(Clone)]
pub struct SecSpec {
    pub name: &'static str,
    pub sh_type: u32,
    pub flags: u64,
    pub data: Vec<u8>,
    /// `sh_link`, as an index into [`ElfSpec::sections`] (`None` = 0).
    pub link: Option<usize>,
}

#[derive(Clone)]
pub struct ElfSpec {
    pub format: Format,
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub segments: Vec<SegSpec>,
    pub sections: Vec<SecSpec>,
    /// Write no section headers at all (like `sstrip`).
    pub strip_section_headers: bool,
}

/// Virtual address the builder maps file offset 0 to.
pub const BASE: u64 = 0x1_0000;

impl ElfSpec {
    pub fn new(format: Format, e_type: u16) -> Self {
        Self {
            format,
            e_type,
            machine: if format.elf64 { 62 } else { 3 },
            entry: BASE + 0x100,
            segments: Vec::new(),
            sections: Vec::new(),
            strip_section_headers: false,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let f = self.format;
        let mut out = vec![0u8; f.ehdr_size() + f.phdr_size() * self.segments.len()];

        // Section contents; index 0 of the header table is the null section,
        // so spec section `i` is header `i + 1`.
        let mut placed = Vec::new();
        for s in &self.sections {
            out.resize(out.len().next_multiple_of(8), 0);
            placed.push((out.len(), s.data.len()));
            out.extend_from_slice(&s.data);
        }
        let mut shstrtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for s in &self.sections {
            name_offsets.push(shstrtab.len());
            shstrtab.extend_from_slice(s.name.as_bytes());
            shstrtab.push(0);
        }
        let shstr_name = shstrtab.len();
        shstrtab.extend_from_slice(b".shstrtab\0");
        let shstr_off = out.len();
        out.extend_from_slice(&shstrtab);
        out.resize(out.len().next_multiple_of(8), 0);
        let shoff = out.len();

        let shnum = self.sections.len() + 2;
        if !self.strip_section_headers {
            out.extend(vec![0u8; f.shdr_size()]);
            for (i, s) in self.sections.iter().enumerate() {
                let (off, size) = placed[i];
                let link = s.link.map_or(0, |l| l + 1);
                out.extend(self.shdr(
                    name_offsets[i],
                    s.sh_type,
                    s.flags,
                    BASE + off as u64,
                    off,
                    size,
                    link,
                ));
            }
            out.extend(self.shdr(shstr_name, SHT_STRTAB, 0, 0, shstr_off, shstrtab.len(), 0));
        }

        // Header.
        let mut h = Vec::new();
        h.extend_from_slice(b"\x7fELF");
        h.push(if f.elf64 { 2 } else { 1 });
        h.push(if f.big { 2 } else { 1 });
        h.push(1);
        h.push(0); // ELFOSABI_SYSV
        h.resize(16, 0);
        h.extend(f.u16(self.e_type));
        h.extend(f.u16(self.machine));
        h.extend(f.u32(1));
        h.extend(f.word(self.entry));
        h.extend(f.word(f.ehdr_size() as u64)); // e_phoff
        h.extend(f.word(if self.strip_section_headers {
            0
        } else {
            shoff as u64
        }));
        h.extend(f.u32(0)); // e_flags
        h.extend(f.u16(f.ehdr_size() as u16));
        h.extend(f.u16(f.phdr_size() as u16));
        h.extend(f.u16(self.segments.len() as u16));
        h.extend(f.u16(f.shdr_size() as u16));
        let (shnum, shstrndx) = if self.strip_section_headers {
            (0, 0)
        } else {
            (shnum, shnum - 1)
        };
        h.extend(f.u16(shnum as u16));
        h.extend(f.u16(shstrndx as u16));
        out[..h.len()].copy_from_slice(&h);

        // Program headers.
        let total = out.len();
        for (i, seg) in self.segments.iter().enumerate() {
            let (off, size) = match seg.content {
                Content::Empty => (0, 0),
                Content::Section(s) => placed[s],
                Content::WholeFile => (0, total),
            };
            let vaddr = if matches!(seg.content, Content::Empty) {
                seg.vaddr
            } else {
                BASE + off as u64
            };
            let mut p = Vec::new();
            p.extend(f.u32(seg.p_type));
            if f.elf64 {
                p.extend(f.u32(seg.flags));
                p.extend(f.u64(off as u64));
                p.extend(f.u64(vaddr));
                p.extend(f.u64(vaddr));
                p.extend(f.u64(size as u64));
                p.extend(f.u64(size as u64));
                p.extend(f.u64(if seg.p_type == PT_LOAD { 0x1000 } else { 8 }));
            } else {
                p.extend(f.u32(off as u32));
                p.extend(f.u32(vaddr as u32));
                p.extend(f.u32(vaddr as u32));
                p.extend(f.u32(size as u32));
                p.extend(f.u32(size as u32));
                p.extend(f.u32(seg.flags));
                p.extend(f.u32(if seg.p_type == PT_LOAD { 0x1000 } else { 4 }));
            }
            let at = f.ehdr_size() + i * f.phdr_size();
            out[at..at + p.len()].copy_from_slice(&p);
        }
        out
    }

    #[allow(clippy::too_many_arguments, reason = "mirrors the header fields")]
    fn shdr(
        &self,
        name: usize,
        sh_type: u32,
        flags: u64,
        addr: u64,
        offset: usize,
        size: usize,
        link: usize,
    ) -> Vec<u8> {
        let f = self.format;
        let mut s = Vec::new();
        s.extend(f.u32(name as u32));
        s.extend(f.u32(sh_type));
        s.extend(f.word(flags));
        s.extend(f.word(addr));
        s.extend(f.word(offset as u64));
        s.extend(f.word(size as u64));
        s.extend(f.u32(link as u32));
        s.extend(f.u32(0)); // sh_info
        s.extend(f.word(8)); // sh_addralign
        let entsize = match sh_type {
            SHT_DYNSYM | SHT_SYMTAB => {
                if f.elf64 {
                    24
                } else {
                    16
                }
            }
            SHT_DYNAMIC => {
                if f.elf64 {
                    16
                } else {
                    8
                }
            }
            _ => 0,
        };
        s.extend(f.word(entsize));
        s
    }
}

/// A dynamic symbol for [`dynsym`]: name, value, size, `st_info`.
pub type Sym = (&'static str, u64, u64, u8);

/// `STT_FUNC` with `STB_GLOBAL`.
pub const GLOBAL_FUNC: u8 = 0x12;
/// `STT_OBJECT` with `STB_WEAK`.
pub const WEAK_OBJECT: u8 = 0x21;

/// A string table holding `strings` after the leading NUL, and the offset
/// of each.
pub fn strtab(strings: &[&str]) -> (Vec<u8>, Vec<u64>) {
    let mut data = vec![0u8];
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(data.len() as u64);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    (data, offsets)
}

/// A symbol table (with the leading null symbol) naming into a string
/// table whose offsets are `names`.
pub fn dynsym(f: Format, syms: &[Sym], names: &[u64]) -> Vec<u8> {
    let entry = if f.elf64 { 24 } else { 16 };
    let mut data = vec![0u8; entry];
    for ((_, value, size, info), name) in syms.iter().zip(names) {
        let mut e = Vec::new();
        e.extend(f.u32(*name as u32));
        if f.elf64 {
            e.push(*info);
            e.push(0);
            e.extend(f.u16(u16::from(*value != 0)));
            e.extend(f.u64(*value));
            e.extend(f.u64(*size));
        } else {
            e.extend(f.u32(*value as u32));
            e.extend(f.u32(*size as u32));
            e.push(*info);
            e.push(0);
            e.extend(f.u16(u16::from(*value != 0)));
        }
        data.extend(e);
    }
    data
}

/// A dynamic section from `(tag, value)` pairs, as given (no implicit
/// terminator).
pub fn dynamic(f: Format, entries: &[(u64, u64)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (tag, val) in entries {
        data.extend(f.word(*tag));
        data.extend(f.word(*val));
    }
    data
}

/// What [`dynamic_image`] puts in the image.
pub struct DynOpts {
    pub needed: Vec<&'static str>,
    pub symbols: Vec<Sym>,
    /// Extra dynamic entries before `DT_NULL`.
    pub dyn_extra: Vec<(u64, u64)>,
    pub interp: Option<&'static str>,
    pub gnu_stack_flags: Option<u32>,
    pub relro: bool,
    pub symtab: bool,
}

impl Default for DynOpts {
    fn default() -> Self {
        Self {
            needed: vec!["libc.so.6"],
            symbols: Vec::new(),
            dyn_extra: Vec::new(),
            interp: Some("/lib/ld.so.1"),
            gnu_stack_flags: Some(6),
            relro: false,
            symtab: false,
        }
    }
}

/// A dynamically linked image: `.interp`, `.dynstr`, `.dynsym`,
/// `.dynamic` (and optionally `.symtab`), with matching program headers.
pub fn dynamic_image(format: Format, e_type: u16, opts: &DynOpts) -> ElfSpec {
    let mut strings: Vec<&str> = opts.needed.clone();
    strings.extend(opts.symbols.iter().map(|s| s.0));
    let (dynstr, offsets) = strtab(&strings);
    let (needed_offs, sym_offs) = offsets.split_at(opts.needed.len());

    let mut entries: Vec<(u64, u64)> = needed_offs.iter().map(|&o| (DT_NEEDED, o)).collect();
    entries.extend(opts.dyn_extra.iter().copied());
    entries.push((DT_STRTAB, 0)); // patched once the layout is known
    entries.push((DT_NULL, 0));

    let mut spec = ElfSpec::new(format, e_type);
    let mut sections = Vec::new();
    if let Some(interp) = opts.interp {
        let mut data = interp.as_bytes().to_vec();
        data.push(0);
        sections.push(SecSpec {
            name: ".interp",
            sh_type: SHT_PROGBITS,
            flags: 2,
            data,
            link: None,
        });
    }
    let dynstr_idx = sections.len();
    sections.push(SecSpec {
        name: ".dynstr",
        sh_type: SHT_STRTAB,
        flags: 2,
        data: dynstr,
        link: None,
    });
    sections.push(SecSpec {
        name: ".dynsym",
        sh_type: SHT_DYNSYM,
        flags: 2,
        data: dynsym(format, &opts.symbols, sym_offs),
        link: Some(dynstr_idx),
    });
    let dynamic_idx = sections.len();
    sections.push(SecSpec {
        name: ".dynamic",
        sh_type: SHT_DYNAMIC,
        flags: 3,
        data: dynamic(format, &entries),
        link: Some(dynstr_idx),
    });
    if opts.symtab {
        sections.push(SecSpec {
            name: ".symtab",
            sh_type: SHT_SYMTAB,
            flags: 0,
            data: vec![0u8; if format.elf64 { 24 } else { 16 }],
            link: Some(dynstr_idx),
        });
    }
    spec.sections = sections;

    spec.segments.push(SegSpec {
        p_type: PT_LOAD,
        flags: 5,
        vaddr: 0,
        content: Content::WholeFile,
    });
    if opts.interp.is_some() {
        spec.segments.push(SegSpec {
            p_type: PT_INTERP,
            flags: 4,
            vaddr: 0,
            content: Content::Section(0),
        });
    }
    spec.segments.push(SegSpec {
        p_type: PT_DYNAMIC,
        flags: 6,
        vaddr: 0,
        content: Content::Section(dynamic_idx),
    });
    if let Some(flags) = opts.gnu_stack_flags {
        spec.segments.push(SegSpec {
            p_type: PT_GNU_STACK,
            flags,
            vaddr: 0,
            content: Content::Empty,
        });
    }
    if opts.relro {
        spec.segments.push(SegSpec {
            p_type: PT_GNU_RELRO,
            flags: 4,
            vaddr: 0,
            content: Content::Section(dynamic_idx),
        });
    }

    // Now that the layout is fixed, fill in DT_STRTAB (same size, so no
    // offsets move).
    let dynstr_vaddr = BASE + section_offset(&spec, dynstr_idx) as u64;
    for entry in &mut entries {
        if entry.0 == DT_STRTAB {
            entry.1 = dynstr_vaddr;
        }
    }
    spec.sections[dynamic_idx].data = dynamic(format, &entries);
    spec
}

/// File offset of spec section `index` in the image `spec` builds.
pub fn section_offset(spec: &ElfSpec, index: usize) -> usize {
    let f = spec.format;
    let mut off = f.ehdr_size() + f.phdr_size() * spec.segments.len();
    for (i, s) in spec.sections.iter().enumerate() {
        off = off.next_multiple_of(8);
        if i == index {
            return off;
        }
        off += s.data.len();
    }
    unreachable!("no section {index}")
}

/// Builder-made fixtures committed under `tests/fixtures/`, by file name.
pub fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let hardened = DynOpts {
        needed: vec!["libc.so.6"],
        symbols: vec![
            ("__stack_chk_fail", 0, 0, GLOBAL_FUNC),
            ("__memcpy_chk", 0, 0, GLOBAL_FUNC),
            ("exported", BASE + 0x100, 16, GLOBAL_FUNC),
        ],
        dyn_extra: vec![(DT_FLAGS_1, 0x0800_0001)],
        relro: true,
        ..DynOpts::default()
    };
    let mut sstripped = dynamic_image(
        Format::LE64,
        2,
        &DynOpts {
            dyn_extra: vec![(DT_BIND_NOW, 0)],
            ..DynOpts::default()
        },
    );
    sstripped.strip_section_headers = true;
    vec![
        (
            "builder-elf32-be-hardened",
            dynamic_image(Format::BE32, 3, &hardened).build(),
        ),
        (
            "builder-elf64-be-hardened",
            dynamic_image(Format::BE64, 3, &hardened).build(),
        ),
        ("builder-elf64-sstripped", sstripped.build()),
    ]
}
