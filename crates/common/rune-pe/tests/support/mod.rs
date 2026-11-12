//! A small PE image builder for the integration tests.
//!
//! It writes the committed fixtures in `tests/fixtures/` (see
//! `fixtures.rs`) and lets the property tests mutate valid images. Layout:
//! DOS header with `e_lfanew = 0x40`, `PE\0\0`, COFF header, optional header
//! with `rva_count` data directories, section table, then each section's raw
//! data at a 0x200-aligned file offset.

#![allow(dead_code, reason = "each test binary uses a different subset")]
#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    reason = "test-only builder: sizes are small constants and a failure is a test bug"
)]

pub const FILE_ALIGN: usize = 0x200;

/// `IMAGE_DLLCHARACTERISTICS_*` bits.
pub mod dll {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_SEH: u16 = 0x0400;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

/// `IMAGE_SCN_*` section characteristics.
pub mod scn {
    pub const CODE: u32 = 0x0000_0020;
    pub const INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const EXECUTE: u32 = 0x2000_0000;
    pub const READ: u32 = 0x4000_0000;
    pub const WRITE: u32 = 0x8000_0000;
}

pub struct SectionSpec {
    pub name: &'static [u8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
    pub characteristics: u32,
}

pub struct PeSpec {
    pub pe64: bool,
    pub machine: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub timestamp: u32,
    pub entry_point: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub linker: (u8, u8),
    /// `NumberOfRvaAndSizes`; also how many directories the header holds.
    pub rva_count: u32,
    pub directories: [(u32, u32); 16],
    /// Written to `NumberOfSections`; `None` means `sections.len()`.
    pub number_of_sections: Option<u16>,
    pub sections: Vec<SectionSpec>,
    /// Appended after the last section (e.g. an Authenticode blob).
    pub trailer: Vec<u8>,
}

impl PeSpec {
    pub fn new(pe64: bool) -> Self {
        Self {
            pe64,
            machine: if pe64 { 0x8664 } else { 0x014c },
            characteristics: 0x0002,
            dll_characteristics: 0,
            timestamp: 0x6500_0000,
            entry_point: 0,
            image_base: if pe64 { 0x1_4000_0000 } else { 0x40_0000 },
            subsystem: 3,
            linker: (14, 36),
            rva_count: 16,
            directories: [(0, 0); 16],
            number_of_sections: None,
            sections: Vec::new(),
            trailer: Vec::new(),
        }
    }

    pub fn optional_header_size(&self) -> usize {
        (if self.pe64 { 112 } else { 96 }) + 8 * self.rva_count.min(16) as usize
    }

    /// File offset the trailer will be written at.
    pub fn trailer_offset(&self) -> usize {
        let mut off = self.headers_size();
        for s in &self.sections {
            off += align(s.data.len());
        }
        off
    }

    fn headers_size(&self) -> usize {
        align(0x40 + 4 + 20 + self.optional_header_size() + 40 * self.sections.len())
    }

    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.headers_size()];
        put(&mut buf, 0, b"MZ");
        put(&mut buf, 0x3c, &0x40u32.to_le_bytes());
        put(&mut buf, 0x40, b"PE\0\0");

        let coff = 0x44;
        let opt_size = self.optional_header_size();
        let nsec = self
            .number_of_sections
            .unwrap_or_else(|| u16::try_from(self.sections.len()).unwrap());
        put(&mut buf, coff, &self.machine.to_le_bytes());
        put(&mut buf, coff + 2, &nsec.to_le_bytes());
        put(&mut buf, coff + 4, &self.timestamp.to_le_bytes());
        put(
            &mut buf,
            coff + 16,
            &u16::try_from(opt_size).unwrap().to_le_bytes(),
        );
        put(&mut buf, coff + 18, &self.characteristics.to_le_bytes());

        let opt = coff + 20;
        let size_of_image = self
            .sections
            .iter()
            .map(|s| s.virtual_address + s.virtual_size.max(1).next_multiple_of(0x1000))
            .max()
            .unwrap_or(0x1000);
        put(
            &mut buf,
            opt,
            &(if self.pe64 { 0x20bu16 } else { 0x10b }).to_le_bytes(),
        );
        buf[opt + 2] = self.linker.0;
        buf[opt + 3] = self.linker.1;
        put(&mut buf, opt + 16, &self.entry_point.to_le_bytes());
        if self.pe64 {
            put(&mut buf, opt + 24, &self.image_base.to_le_bytes());
        } else {
            put(
                &mut buf,
                opt + 28,
                &u32::try_from(self.image_base).unwrap().to_le_bytes(),
            );
        }
        put(&mut buf, opt + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
        put(&mut buf, opt + 36, &(FILE_ALIGN as u32).to_le_bytes()); // FileAlignment
        put(&mut buf, opt + 40, &6u16.to_le_bytes()); // MajorOperatingSystemVersion
        put(&mut buf, opt + 48, &6u16.to_le_bytes()); // MajorSubsystemVersion
        put(&mut buf, opt + 56, &size_of_image.to_le_bytes());
        put(
            &mut buf,
            opt + 60,
            &u32::try_from(self.headers_size()).unwrap().to_le_bytes(),
        );
        put(&mut buf, opt + 68, &self.subsystem.to_le_bytes());
        put(&mut buf, opt + 70, &self.dll_characteristics.to_le_bytes());
        let (count_off, dirs_off) = if self.pe64 { (108, 112) } else { (92, 96) };
        put(&mut buf, opt + count_off, &self.rva_count.to_le_bytes());
        for (i, (rva, size)) in self
            .directories
            .iter()
            .take(self.rva_count.min(16) as usize)
            .enumerate()
        {
            put(&mut buf, opt + dirs_off + i * 8, &rva.to_le_bytes());
            put(&mut buf, opt + dirs_off + i * 8 + 4, &size.to_le_bytes());
        }

        let mut table = opt + opt_size;
        let mut raw = self.headers_size();
        for s in &self.sections {
            let raw_size = align(s.data.len());
            put(&mut buf, table, s.name);
            put(&mut buf, table + 8, &s.virtual_size.to_le_bytes());
            put(&mut buf, table + 12, &s.virtual_address.to_le_bytes());
            put(
                &mut buf,
                table + 16,
                &u32::try_from(raw_size).unwrap().to_le_bytes(),
            );
            let raw_ptr = if raw_size == 0 { 0 } else { raw };
            put(
                &mut buf,
                table + 20,
                &u32::try_from(raw_ptr).unwrap().to_le_bytes(),
            );
            put(&mut buf, table + 36, &s.characteristics.to_le_bytes());
            table += 40;
            raw += raw_size;
        }
        for s in &self.sections {
            let start = buf.len();
            buf.extend_from_slice(&s.data);
            buf.resize(start + align(s.data.len()), 0);
        }
        buf.extend_from_slice(&self.trailer);
        buf
    }
}

pub fn align(n: usize) -> usize {
    n.next_multiple_of(FILE_ALIGN)
}

pub fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

/// An import thunk: by `(hint, name)` or by ordinal.
#[derive(Clone, Copy)]
pub enum Thunk {
    Name(u16, &'static str),
    Ordinal(u16),
}

/// Builds an import section placed at `rva`: the descriptor array, then per
/// DLL its lookup table and address table, then hint/name entries and DLL
/// names. Returns the section data and the import directory `(rva, size)`.
pub fn idata(rva: u32, pe64: bool, dlls: &[(&str, &[Thunk])]) -> (Vec<u8>, (u32, u32)) {
    let entry = if pe64 { 8 } else { 4 };
    let descriptors = 20 * (dlls.len() + 1);
    let mut data = vec![0u8; descriptors];
    let at = |data: &Vec<u8>| rva + u32::try_from(data.len()).unwrap();

    // Lookup and address tables first, names patched in afterwards.
    let mut tables = Vec::new();
    for (_, thunks) in dlls {
        let ilt = data.len();
        data.resize(ilt + entry * (thunks.len() + 1), 0);
        let iat = data.len();
        data.resize(iat + entry * (thunks.len() + 1), 0);
        tables.push((ilt, iat));
    }
    for (i, (dll, thunks)) in dlls.iter().enumerate() {
        let (ilt, iat) = tables[i];
        for (j, thunk) in thunks.iter().enumerate() {
            let value: u64 = match *thunk {
                Thunk::Ordinal(ord) => {
                    (if pe64 { 1u64 << 63 } else { 1u64 << 31 }) | u64::from(ord)
                }
                Thunk::Name(hint, name) => {
                    let name_rva = at(&data);
                    data.extend_from_slice(&hint.to_le_bytes());
                    data.extend_from_slice(name.as_bytes());
                    data.push(0);
                    if data.len() % 2 == 1 {
                        data.push(0);
                    }
                    u64::from(name_rva)
                }
            };
            let bytes = value.to_le_bytes();
            put(&mut data, ilt + j * entry, &bytes[..entry]);
            put(&mut data, iat + j * entry, &bytes[..entry]);
        }
        let name_rva = at(&data);
        data.extend_from_slice(dll.as_bytes());
        data.push(0);
        let d = i * 20;
        put(
            &mut data,
            d,
            &(rva + u32::try_from(ilt).unwrap()).to_le_bytes(),
        );
        put(&mut data, d + 12, &name_rva.to_le_bytes());
        put(
            &mut data,
            d + 16,
            &(rva + u32::try_from(iat).unwrap()).to_le_bytes(),
        );
    }
    (data, (rva, u32::try_from(descriptors).unwrap()))
}

/// Builds an export section placed at `rva` for `dll_name`. `functions[i]`
/// is the address table entry for ordinal `ordinal_base + i`: an optional
/// name and the function RVA (`0` leaves the slot unused). Returns the
/// section data and the export directory `(rva, size)`.
pub fn edata(
    rva: u32,
    dll_name: &str,
    ordinal_base: u32,
    functions: &[(Option<&str>, u32)],
) -> (Vec<u8>, (u32, u32)) {
    let mut named: Vec<(&str, u16)> = functions
        .iter()
        .enumerate()
        .filter_map(|(i, (name, _))| name.map(|n| (n, u16::try_from(i).unwrap())))
        .collect();
    named.sort_unstable();

    let mut data = vec![0u8; 40];
    let at = |data: &Vec<u8>| rva + u32::try_from(data.len()).unwrap();
    let eat = at(&data);
    for (_, f) in functions {
        data.extend_from_slice(&f.to_le_bytes());
    }
    let ent = at(&data);
    let ent_off = data.len();
    data.resize(ent_off + 4 * named.len(), 0);
    let eot = at(&data);
    for (_, index) in &named {
        data.extend_from_slice(&index.to_le_bytes());
    }
    for (i, (name, _)) in named.iter().enumerate() {
        let name_rva = at(&data);
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        put(&mut data, ent_off + 4 * i, &name_rva.to_le_bytes());
    }
    let dll_rva = at(&data);
    data.extend_from_slice(dll_name.as_bytes());
    data.push(0);

    put(&mut data, 12, &dll_rva.to_le_bytes());
    put(&mut data, 16, &ordinal_base.to_le_bytes());
    put(
        &mut data,
        20,
        &u32::try_from(functions.len()).unwrap().to_le_bytes(),
    );
    put(
        &mut data,
        24,
        &u32::try_from(named.len()).unwrap().to_le_bytes(),
    );
    put(&mut data, 28, &eat.to_le_bytes());
    put(&mut data, 32, &ent.to_le_bytes());
    put(&mut data, 36, &eot.to_le_bytes());
    let size = u32::try_from(data.len()).unwrap();
    (data, (rva, size))
}

/// A tiny code blob: `xor eax, eax; ret`, padded with `int3`.
pub fn code() -> Vec<u8> {
    let mut c = vec![0x31, 0xc0, 0xc3];
    c.resize(16, 0xcc);
    c
}

/// 64-bit console executable: imports from two DLLs (by name and by
/// ordinal), every hardening bit on, and an Authenticode blob.
pub fn pe64_console_imports() -> Vec<u8> {
    let (rdata, import_dir) = idata(
        0x2000,
        true,
        &[
            (
                "KERNEL32.dll",
                &[
                    Thunk::Name(0x2b7, "GetProcAddress"),
                    Thunk::Name(0x5e1, "VirtualAlloc"),
                    Thunk::Name(0x166, "ExitProcess"),
                ],
            ),
            (
                "USER32.dll",
                &[Thunk::Name(0x285, "MessageBoxA"), Thunk::Ordinal(17)],
            ),
        ],
    );
    let mut pe = PeSpec::new(true);
    pe.characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    pe.dll_characteristics = dll::HIGH_ENTROPY_VA
        | dll::DYNAMIC_BASE
        | dll::FORCE_INTEGRITY
        | dll::NX_COMPAT
        | dll::NO_SEH
        | dll::GUARD_CF
        | dll::TERMINAL_SERVER_AWARE;
    pe.entry_point = 0x1000;
    pe.directories[1] = import_dir;
    pe.sections = vec![
        SectionSpec {
            name: b".text",
            virtual_address: 0x1000,
            virtual_size: 16,
            data: code(),
            characteristics: scn::CODE | scn::EXECUTE | scn::READ,
        },
        SectionSpec {
            name: b".rdata",
            virtual_address: 0x2000,
            virtual_size: u32::try_from(rdata.len()).unwrap(),
            data: rdata,
            characteristics: scn::INITIALIZED_DATA | scn::READ,
        },
    ];
    // WIN_CERTIFICATE header (length, revision 0x0200, PKCS_SIGNED_DATA)
    // with an empty body: enough for the directory to be non-empty.
    let mut cert = Vec::new();
    cert.extend_from_slice(&8u32.to_le_bytes());
    cert.extend_from_slice(&0x0200u16.to_le_bytes());
    cert.extend_from_slice(&0x0002u16.to_le_bytes());
    pe.directories[4] = (u32::try_from(pe.trailer_offset()).unwrap(), 8);
    pe.trailer = cert;
    pe.build()
}

/// 32-bit DLL exporting two names, one ordinal-only function and an unused
/// slot, with ordinal base 5. ASLR, DEP and `NO_SEH` are set.
pub fn pe32_dll_exports() -> Vec<u8> {
    let (edata, export_dir) = edata(
        0x2000,
        "fixture.dll",
        5,
        &[
            (Some("Beta"), 0x1000),
            (None, 0x1004),
            (None, 0),
            (Some("Alpha"), 0x1008),
        ],
    );
    let mut pe = PeSpec::new(false);
    pe.characteristics = 0x2102; // DLL | 32BIT_MACHINE | EXECUTABLE_IMAGE
    pe.dll_characteristics = dll::DYNAMIC_BASE | dll::NX_COMPAT | dll::NO_SEH;
    pe.subsystem = 2;
    pe.entry_point = 0x1000;
    pe.image_base = 0x1000_0000;
    pe.directories[0] = export_dir;
    pe.sections = vec![
        SectionSpec {
            name: b".text",
            virtual_address: 0x1000,
            virtual_size: 16,
            data: code(),
            characteristics: scn::CODE | scn::EXECUTE | scn::READ,
        },
        SectionSpec {
            name: b".edata",
            virtual_address: 0x2000,
            virtual_size: u32::try_from(edata.len()).unwrap(),
            data: edata,
            characteristics: scn::INITIALIZED_DATA | scn::READ,
        },
    ];
    pe.build()
}

/// 32-bit executable laid out like a UPX-packed one: an empty `UPX0`
/// reserving the unpacked image, the stub in `UPX1`, both writable and
/// executable, the bare loader imports, and no hardening at all.
pub fn pe32_upx_packed() -> Vec<u8> {
    let (idata, import_dir) = idata(
        0x13000,
        false,
        &[(
            "KERNEL32.DLL",
            &[
                Thunk::Name(0, "LoadLibraryA"),
                Thunk::Name(0, "GetProcAddress"),
                Thunk::Name(0, "VirtualProtect"),
                Thunk::Name(0, "ExitProcess"),
            ],
        )],
    );
    let mut pe = PeSpec::new(false);
    pe.characteristics = 0x010f; // EXECUTABLE_IMAGE | 32BIT | stripped relocs/lines/syms
    pe.linker = (2, 56);
    pe.entry_point = 0x12000;
    pe.directories[1] = import_dir;
    let rwx = scn::EXECUTE | scn::READ | scn::WRITE;
    pe.sections = vec![
        SectionSpec {
            name: b"UPX0",
            virtual_address: 0x1000,
            virtual_size: 0x11000,
            data: Vec::new(),
            characteristics: scn::UNINITIALIZED_DATA | rwx,
        },
        SectionSpec {
            name: b"UPX1",
            virtual_address: 0x12000,
            virtual_size: 0x1000,
            data: code(),
            characteristics: scn::INITIALIZED_DATA | rwx,
        },
        SectionSpec {
            name: b".rsrc",
            virtual_address: 0x13000,
            virtual_size: u32::try_from(idata.len()).unwrap(),
            data: idata,
            characteristics: scn::INITIALIZED_DATA | scn::READ | scn::WRITE,
        },
    ];
    pe.build()
}

/// Claims 65535 sections but holds one, so the table runs off the file.
pub fn malformed_truncated_sections() -> Vec<u8> {
    let mut pe = PeSpec::new(true);
    pe.number_of_sections = Some(u16::MAX);
    pe.sections = vec![SectionSpec {
        name: b".text",
        virtual_address: 0x1000,
        virtual_size: 16,
        data: code(),
        characteristics: scn::CODE | scn::EXECUTE | scn::READ,
    }];
    let mut bytes = pe.build();
    // Drop the section data and padding: the table ends at the file end.
    bytes.truncate(0x44 + 20 + pe.optional_header_size() + 40);
    bytes
}

/// `e_lfanew` points far past the end of the file.
pub fn malformed_lfanew_past_eof() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    put(&mut bytes, 0, b"MZ");
    put(&mut bytes, 0x3c, &u32::MAX.to_le_bytes());
    bytes
}

/// Hostile tables in one 64-bit image: export counts of `u32::MAX` whose
/// name pointers all aim at one long string, and many import descriptors
/// sharing one thunk list that runs to the end of the file.
pub fn malformed_hostile_tables() -> Vec<u8> {
    const VA: u32 = 0x1000;
    const LEN: usize = 0x1000;
    let mut data = vec![0u8; LEN];
    // 0x000: export directory with absurd counts.
    put(&mut data, 16, &1u32.to_le_bytes()); // ordinal base
    put(&mut data, 20, &u32::MAX.to_le_bytes()); // NumberOfFunctions
    put(&mut data, 24, &u32::MAX.to_le_bytes()); // NumberOfNames
    put(&mut data, 28, &(VA + 0x800).to_le_bytes()); // address table
    put(&mut data, 32, &(VA + 0x800).to_le_bytes()); // name pointers
    put(&mut data, 36, &(VA + 0x800).to_le_bytes()); // ordinals
    // 0x800..: every u32 is VA + 0xc00, used as function RVA, name RVA,
    // ordinal index (0x1c00 / 0) and import thunk at once.
    for off in (0x800..0xc00).step_by(4) {
        put(&mut data, off, &(VA + 0xc00).to_le_bytes());
    }
    // 0xc00..: a name longer than the parser keeps, never terminated
    // before the final byte of the file.
    for b in &mut data[0xc00..LEN - 1] {
        *b = b'A';
    }
    // 0x40..0x7d4: 97 import descriptors, all sharing the thunk list at 0x800
    // (whose names are the long string) and one DLL name.
    put(&mut data, 0x7f0, b"evil.dll\0");
    for d in (0x40..0x7d0).step_by(20) {
        put(&mut data, d, &(VA + 0x800).to_le_bytes()); // lookup table
        put(&mut data, d + 12, &(VA + 0x7f0).to_le_bytes()); // name
    }

    let mut pe = PeSpec::new(true);
    pe.directories[0] = (VA, 40);
    pe.directories[1] = (VA + 0x40, 0x7ac);
    pe.sections = vec![SectionSpec {
        name: b".evil",
        virtual_address: VA,
        virtual_size: u32::try_from(LEN).unwrap(),
        data,
        characteristics: scn::INITIALIZED_DATA | scn::READ,
    }];
    pe.build()
}

/// Every fixture committed under `tests/fixtures/`, by file name.
pub fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("pe64-console-imports.exe", pe64_console_imports()),
        ("pe32-dll-exports.dll", pe32_dll_exports()),
        ("pe32-upx-packed.exe", pe32_upx_packed()),
        (
            "malformed-truncated-sections.exe",
            malformed_truncated_sections(),
        ),
        ("malformed-lfanew-past-eof.exe", malformed_lfanew_past_eof()),
        ("malformed-hostile-tables.exe", malformed_hostile_tables()),
    ]
}
