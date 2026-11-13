//! Inputs built to make the parser expand a small file into a lot of memory.

use rune_elf::parse;

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

const fn le64(n: usize) -> [u8; 8] {
    (n as u64).to_le_bytes()
}

/// A 1 MB ELF64 shared object without section headers whose `PT_DYNAMIC`
/// segment holds 65536 `DT_NEEDED` entries, all naming the same 4096-byte
/// string. Copying it for each entry used to take 256 MiB.
fn one_long_needed_name_everywhere() -> Vec<u8> {
    const ENTRIES: usize = 65_536;
    const NAME_LEN: usize = 4096;
    let phdrs = 64;
    let strtab = phdrs + 2 * 56;
    let dynamic = strtab + NAME_LEN + 1;
    let dyn_size = (ENTRIES + 2) * 16;
    let mut b = vec![0u8; dynamic + dyn_size];
    let len = b.len();

    put(&mut b, 0, b"\x7fELF\x02\x01\x01");
    put(&mut b, 16, &3u16.to_le_bytes()); // ET_DYN
    put(&mut b, 18, &62u16.to_le_bytes()); // x86-64
    put(&mut b, 32, &le64(phdrs));
    put(&mut b, 54, &56u16.to_le_bytes());
    put(&mut b, 56, &2u16.to_le_bytes());
    // PT_LOAD mapping the whole file at address 0.
    put(&mut b, phdrs, &1u32.to_le_bytes());
    put(&mut b, phdrs + 32, &le64(len));
    // PT_DYNAMIC.
    put(&mut b, phdrs + 56, &2u32.to_le_bytes());
    put(&mut b, phdrs + 56 + 8, &le64(dynamic));
    put(&mut b, phdrs + 56 + 32, &le64(dyn_size));

    b[strtab..strtab + NAME_LEN].fill(b'l');
    put(&mut b, dynamic, &5u64.to_le_bytes()); // DT_STRTAB
    put(&mut b, dynamic + 8, &le64(strtab));
    for i in 0..ENTRIES {
        put(&mut b, dynamic + 16 + i * 16, &1u64.to_le_bytes()); // DT_NEEDED, offset 0
    }
    b
}

#[test]
fn names_cannot_outgrow_the_file() {
    let bytes = one_long_needed_name_everywhere();
    let elf = parse(&bytes).expect("valid image");
    assert_eq!(elf.needed_libs.first().map(String::len), Some(4096));
    let names: usize = elf.needed_libs.iter().map(String::len).sum();
    assert!(
        names <= 2 * bytes.len(),
        "{names} name bytes from {} file bytes",
        bytes.len()
    );
}
