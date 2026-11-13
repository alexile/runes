//! Inputs built to make the parser slow rather than to crash it.

use std::time::{Duration, Instant};

use rune_pe::parse;

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

fn le32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes()
}

/// A 3.5 MB PE32 image with 65535 section headers, of which only the last
/// one maps anything (RVA = file offset), and full import and export tables
/// whose every name lives in that last section. Each RVA lookup used to
/// scan the whole section table.
fn many_sections_full_tables() -> Vec<u8> {
    const SECTIONS: usize = 65_535;
    const ENTRIES: usize = 65_536;
    let opt = 0x58;
    let table = opt + 224;
    let imp = table + SECTIONS * 40;
    let thunks = imp + 40;
    let name = thunks + ENTRIES * 4 + 4;
    let exp = name + 8;
    let eat = exp + 40;
    let ent = eat + ENTRIES * 4;
    let eot = ent + ENTRIES * 4;
    let mut b = vec![0u8; eot + ENTRIES * 2 + 16];

    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x40u32.to_le_bytes());
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &0x14cu16.to_le_bytes());
    put(&mut b, 0x46, &u16::MAX.to_le_bytes());
    put(&mut b, 0x44 + 16, &224u16.to_le_bytes());
    put(&mut b, opt, &0x10bu16.to_le_bytes());
    put(&mut b, opt + 92, &16u32.to_le_bytes());
    put(&mut b, opt + 96, &le32(exp));
    put(&mut b, opt + 104, &le32(imp));
    for i in 0..SECTIONS - 1 {
        // Empty sections far away from every RVA the tables use.
        put(&mut b, table + i * 40 + 12, &le32(0x8000_0000 + i));
    }
    put(
        &mut b,
        table + (SECTIONS - 1) * 40 + 8,
        &0x7fff_ffffu32.to_le_bytes(),
    );

    put(&mut b, imp, &le32(thunks));
    put(&mut b, imp + 12, &le32(name + 2));
    for i in 0..ENTRIES {
        put(&mut b, thunks + i * 4, &le32(name));
    }
    put(&mut b, name + 2, b"a\0");

    put(&mut b, exp + 20, &le32(ENTRIES));
    put(&mut b, exp + 24, &le32(ENTRIES));
    put(&mut b, exp + 28, &le32(eat));
    put(&mut b, exp + 32, &le32(ent));
    put(&mut b, exp + 36, &le32(eot));
    for i in 0..ENTRIES {
        put(&mut b, eat + i * 4, &1u32.to_le_bytes());
        put(&mut b, ent + i * 4, &le32(name + 2));
        put(
            &mut b,
            eot + i * 2,
            &u16::try_from(i).unwrap_or(0).to_le_bytes(),
        );
    }
    b
}

#[test]
fn rva_lookups_do_not_scan_every_section() {
    let bytes = many_sections_full_tables();
    let start = Instant::now();
    let pe = parse(&bytes).expect("valid image");
    let elapsed = start.elapsed();
    assert_eq!(pe.sections.len(), 65_535);
    assert_eq!(pe.imports.len(), 1);
    assert_eq!(pe.imports[0].functions.len(), 65_536);
    assert_eq!(pe.exports.len(), 65_536);
    assert!(pe.exports.iter().all(|e| e.name.as_deref() == Some("a")));
    // About 4 s in a release build, minutes in a debug one, before the fix;
    // well under a second after it.
    assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
}

/// A PE32 image whose 65536 imports and 65536 exports all name the same
/// 4096-byte string. Copying that string for every entry used to turn a
/// 0.8 MB file into half a gigabyte of names.
fn one_long_name_everywhere() -> Vec<u8> {
    const ENTRIES: usize = 65_536;
    const NAME_LEN: usize = 4096;
    let opt = 0x58;
    let table = opt + 224;
    let imp = table + 40;
    let thunks = imp + 40;
    let dll = thunks + ENTRIES * 4 + 4;
    let name = dll + 8;
    let exp = name + 2 + NAME_LEN + 1;
    let eat = exp + 40;
    let ent = eat + ENTRIES * 4;
    let eot = ent + ENTRIES * 4;
    let mut b = vec![0u8; eot + ENTRIES * 2 + 16];

    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x40u32.to_le_bytes());
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &0x14cu16.to_le_bytes());
    put(&mut b, 0x46, &1u16.to_le_bytes());
    put(&mut b, 0x44 + 16, &224u16.to_le_bytes());
    put(&mut b, opt, &0x10bu16.to_le_bytes());
    put(&mut b, opt + 92, &16u32.to_le_bytes());
    put(&mut b, opt + 96, &le32(exp));
    put(&mut b, opt + 104, &le32(imp));
    // One section mapping RVA = file offset.
    put(&mut b, table + 8, &0x7fff_ffffu32.to_le_bytes());

    put(&mut b, imp, &le32(thunks));
    put(&mut b, imp + 12, &le32(dll));
    put(&mut b, dll, b"a.dll\0");
    for i in 0..ENTRIES {
        put(&mut b, thunks + i * 4, &le32(name));
    }
    b[name + 2..name + 2 + NAME_LEN].fill(b'x');

    put(&mut b, exp + 20, &le32(ENTRIES));
    put(&mut b, exp + 24, &le32(ENTRIES));
    put(&mut b, exp + 28, &le32(eat));
    put(&mut b, exp + 32, &le32(ent));
    put(&mut b, exp + 36, &le32(eot));
    for i in 0..ENTRIES {
        put(&mut b, eat + i * 4, &1u32.to_le_bytes());
        put(&mut b, ent + i * 4, &le32(name + 2));
        put(
            &mut b,
            eot + i * 2,
            &u16::try_from(i).unwrap_or(0).to_le_bytes(),
        );
    }
    b
}

#[test]
fn names_cannot_outgrow_the_file() {
    let bytes = one_long_name_everywhere();
    let pe = parse(&bytes).expect("valid image");
    assert_eq!(pe.imports[0].functions.len(), 65_536);
    assert_eq!(pe.exports.len(), 65_536);
    let names: usize = pe
        .imports
        .iter()
        .flat_map(|i| &i.functions)
        .filter_map(|f| f.name.as_deref())
        .chain(pe.exports.iter().filter_map(|e| e.name.as_deref()))
        .map(str::len)
        .sum();
    // The first entries still get the real name.
    assert_eq!(
        pe.imports[0].functions[0].name.as_deref().map(str::len),
        Some(4096)
    );
    assert!(
        names <= 2 * bytes.len(),
        "{names} name bytes from {} file bytes",
        bytes.len()
    );
}
