//! Deterministic inputs and their reference digests.
//!
//! The digests were produced by the reference implementations, not by this
//! crate: TLSH by `py-tlsh` 4.x (Trend Micro's C++ library, 128 buckets,
//! 1-byte checksum) and ssdeep by `fuzzy_hash_buf` / `fuzzy_compare` of
//! ssdeep 2.14.1 built from the release tarball. The inputs come from the
//! generators below, mirrored in the generator script.

#![allow(dead_code, reason = "each test binary uses a different subset")]

/// Which generator makes the input.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// Pseudo-random bytes.
    Bytes,
    /// Pseudo-random words.
    Text,
}

/// One input and its reference digests.
#[derive(Debug)]
pub struct Vector {
    pub kind: Kind,
    pub seed: u64,
    pub len: usize,
    /// Byte positions XOR-ed with 0x5A after generation.
    pub edits: &'static [usize],
    /// `None` where the reference returns `TNULL`.
    pub tlsh: Option<&'static str>,
    pub ssdeep: &'static str,
}

const MUL: u64 = 6_364_136_223_846_793_005;
const INC: u64 = 1_442_695_040_888_963_407;

/// Top bytes of a 64-bit LCG (Knuth's MMIX constants).
pub fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(MUL).wrapping_add(INC);
            (x >> 56) as u8
        })
        .collect()
}

const WORDS: [&str; 16] = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
    "kilo", "lima", "mike", "november", "oscar", "papa",
];

/// LCG-chosen words, space separated, a newline every 12 words.
pub fn text(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len + 16);
    let mut k = 0;
    while out.len() < len {
        x = x.wrapping_mul(MUL).wrapping_add(INC);
        out.extend_from_slice(WORDS[(x >> 60) as usize].as_bytes());
        k += 1;
        out.push(if k % 12 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

impl Vector {
    /// The input bytes.
    pub fn input(&self) -> Vec<u8> {
        let mut data = match self.kind {
            Kind::Bytes => lcg_bytes(self.seed, self.len),
            Kind::Text => text(self.seed, self.len),
        };
        for &p in self.edits {
            let i = p % data.len();
            data[i] ^= 0x5A;
        }
        data
    }
}

/// kind, seed, len, xor-0x5A positions, TLSH (py-tlsh 4.x reference), ssdeep (2.14.1 reference)
pub const VECTORS: &[Vector] = &[
    Vector {
        kind: Kind::Bytes,
        seed: 1,
        len: 0,
        edits: &[],
        tlsh: None,
        ssdeep: "3::",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 2,
        len: 1,
        edits: &[],
        tlsh: None,
        ssdeep: "3:h:h",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 3,
        len: 49,
        edits: &[],
        tlsh: None,
        ssdeep: "3:iEleLeC/q1KNAQPgvFe9:iEEh/VNs49",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 4,
        len: 50,
        edits: &[],
        tlsh: Some("T16990047001054F14577DF5DF151540C5DC41C5C514D317F5070053DCD5474404F41303"),
        ssdeep: "3:xtW2oNq569uKavHx8+OP:xMdXCHo",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 5,
        len: 64,
        edits: &[],
        tlsh: Some("T132A0220AC032200020320E003C2B200CEC023888C20B80A080C832C2F023CC8C2A0008"),
        ssdeep: "3:baUnkHXgTbsoYQADc6cqCn:jMXgTbsQAc6c5n",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 6,
        len: 255,
        edits: &[],
        tlsh: Some("T1B1D0958C3B8510D539F591253280E413E55C63143322147176BD0DAFA78CD15C654F58"),
        ssdeep: "6:M8cT7gtunLv+VmAL/ItoZCQWQBsUZ6LRkQKphIIuu:M8cTJSYfVQWQdZ6lohIIuu",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 7,
        len: 256,
        edits: &[],
        tlsh: Some("T11CD02BA659D381E5948619458A0D6C8140D4E88B86815B7D5D80144C41669DE5C076D3"),
        ssdeep: "6:AX3ipFb9MYcEDVGMf8DlWfStThLy/BAFl6u+uEHQrsysjn:AirqYc0Yi8DzZy/aFl6uDEwIn",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 8,
        len: 1000,
        edits: &[],
        tlsh: Some("T1D9117555D235C512D01C5490E586BC625E8512306F2F13BBB99899B696D12BB0DC0148"),
        ssdeep: "24:CMB6IyXFJcNCWTaESjM1z6nRcu/gCNjvgH:y/csgaESm65LNbgH",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 9,
        len: 4096,
        edits: &[],
        tlsh: Some("T192816D1342A0E4AD67041A404898E109F38AE692DE5C85EB77C73B97FD887424D0BF38"),
        ssdeep: "96:egoW8y2oVrUW+kGNAruW/Y8mKH6X2fbT0CNwakiAjzw1HPvKPPGnxsR:eL+rUWdGeCW/Y80MT0uweGpGmR",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 10,
        len: 10_000,
        edits: &[],
        tlsh: Some("T1BD22AF34F6517132A3EA5D752EE28F4CC456528203EB5C5F30867B66C1F871AB5039EB"),
        ssdeep: "192:cNcrw7tfwc6T26N3V4ufPqr/UXuNWRmidDiDVChN3fh60:cCwxIc6N+ufCoeQtisJL",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 11,
        len: 65_536,
        edits: &[],
        tlsh: Some("T13D5302B4886623F207C37F70316F23C0645D4E8A5B66C649A126EE6BC82185CCFEDB4D"),
        ssdeep: "1536:MuER6btTeJXdHHT8db63DJ+lIRTOiU8lJgbpzx9yfaobdbnI:ZJ6J9w6xY7yJEpFMfao5rI",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 12,
        len: 300_000,
        edits: &[],
        tlsh: Some("T1735423EDA0A68FF50FAB0781A3AC54982C5F41538038D61F3C08A357F9D6BA82976177"),
        ssdeep: "6144:fYhAKYwXW9aW+ZS5hf8itmvlCWJbNujYv2+33jTO8JpzlqHvv6d:fYhA9bkW+ZwLs5Ndn9JyvSd",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 13,
        len: 1_048_576,
        edits: &[],
        tlsh: Some("T1D225236DA1812AA7E40A272D8D91354DFE0D9D3067F50446B31F0A8C7BF5D29BF24E2E"),
        ssdeep: "24576:jlV7/6/6zYrv94SJGmAgGIz9bBxGV3uJ/FkSfUQ4:jlVzXQJRAgGIxbBAZSfUf",
    },
    Vector {
        kind: Kind::Text,
        seed: 1,
        len: 0,
        edits: &[],
        tlsh: None,
        ssdeep: "3::",
    },
    Vector {
        kind: Kind::Text,
        seed: 2,
        len: 1,
        edits: &[],
        tlsh: None,
        ssdeep: "3:I:I",
    },
    Vector {
        kind: Kind::Text,
        seed: 3,
        len: 49,
        edits: &[],
        tlsh: None,
        ssdeep: "3:0/uRFJKFWuRFP90HVA:0/u17uz90Hq",
    },
    Vector {
        kind: Kind::Text,
        seed: 4,
        len: 50,
        edits: &[],
        tlsh: Some("T13F9002041579523545A6015A73882A01D30E40344D1511272258537440D40A41A12408"),
        ssdeep: "3:8AJgIWDKuRFEJnARFVVgREw:8AuIjuEnApVgRr",
    },
    Vector {
        kind: Kind::Text,
        seed: 5,
        len: 64,
        edits: &[],
        tlsh: Some("T1D4A0024D3F840156811D87C65F8F55823309808F91BD8D15089F37358CDDDCC254EC84"),
        ssdeep: "3:xt6B616ATVAyfEg:2cA4qyfz",
    },
    Vector {
        kind: Kind::Text,
        seed: 6,
        len: 255,
        edits: &[],
        tlsh: Some("T1E2D0129126C009E2096C49875A0767527148C157872FCB5E18D873260D49C65200FD0A"),
        ssdeep: "6:EwIQARP0N/KpBvm1LwtDLMK94nP0HxIrMIDRH:EwsP0Qh94nP0HOrMINH",
    },
    Vector {
        kind: Kind::Text,
        seed: 7,
        len: 256,
        edits: &[],
        tlsh: Some("T14FD0174426A7A5B11D7C8145238B5BB2738DC42F6B2E8B23BAD673BD49581A0140CE29"),
        ssdeep: "6:8ASfYc+bMKpV9nnBGqpTabXsKmbYWFJ6s:RSwc4pLnBGAazszbfp",
    },
    Vector {
        kind: Kind::Text,
        seed: 8,
        len: 1000,
        edits: &[],
        tlsh: Some("T17E11EC543F6992724EBC05872B8E6752B34DC53F9E1ECB5F198933784CD60E9201DE09"),
        ssdeep: "24:eDeA+Ij05dWDtiAnVSR+tZ9erfYwcxqS2:eDIII/WDtiAnVSZTYbqS2",
    },
    Vector {
        kind: Kind::Text,
        seed: 9,
        len: 4096,
        edits: &[],
        tlsh: Some("T18F8100843BA6AAB10E7C05872B4B5B52738CC13E9F2ECF5F159E33794C954E8201EE19"),
        ssdeep: "48:wv0rTxrZegJiHzU/UydWAzoSu12nrSJyastVGt7IXl:pPx9iTaUytoSZnrmtFWl",
    },
    Vector {
        kind: Kind::Text,
        seed: 10,
        len: 10_000,
        edits: &[],
        tlsh: Some("T18B2223953BA5A6B10E7C05872B4B6B52734DC13F9F1ECF8F259A33764C964E8210EE09"),
        ssdeep: "96:Tbn89Bo6NSb9fSCH5TSzBGf2tZbgp5aQasn+p68+mJppQxMyNUW2AoO:TwezZB5Tf2Qas+Y8+mJppxOKM",
    },
    Vector {
        kind: Kind::Text,
        seed: 11,
        len: 65_536,
        edits: &[],
        tlsh: Some("T1305313453BA6A5B10E7C05872B4B5B62734DC13E9F2ECF9F149A337A4C964E8210FE19"),
        ssdeep: "384:5CMTslGO8wjWNc0LUJ75CELETNFYkcRc/r6Cug7skEFnCdNQmTNOqt5jRx/Z+19j:7Icx4sU",
    },
    Vector {
        kind: Kind::Text,
        seed: 12,
        len: 300_000,
        edits: &[],
        tlsh: Some("T11B5426453BA6A5B10E7C05472B4B6B52734DC13E9F2ECF9F249A337A4C964E8210FE19"),
        ssdeep: "768:ZK1kTACgVmfJv+Imq4IgHUiPbbtUTXG+mF84t:Z+grg0gVUiNYIFFt",
    },
    Vector {
        kind: Kind::Text,
        seed: 13,
        len: 1_048_576,
        edits: &[],
        tlsh: Some("T16C2536453BA6A5B10E7C05872B4B6B52734DC13E9F2ECF9F259A33794C964E8200FE19"),
        ssdeep: "1536:TzOYmONBREw76hjtBIpJ5MiGis5LfidpxxmfhGbMooJZEuV/1el4USftdeT8n:C",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 9,
        len: 4096,
        edits: &[100],
        tlsh: Some("T1BB816D1342A0E4AD67041A404898E109F38AE692DE5C85EB67C73B97FD887414D0BF78"),
        ssdeep: "96:eaoW8y2oVrUW+kGNAruW/Y8mKH6X2fbT0CNwakiAjzw1HPvKPPGnxsR:el+rUWdGeCW/Y80MT0uweGpGmR",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 9,
        len: 4096,
        edits: &[100, 2000, 3500],
        tlsh: Some("T1CC816D1342A0E4AD67041A404898E109F38AE692DE5C85EB67C73B97FD487414D0AF78"),
        ssdeep: "96:eaoW8y2oVrUW+kGNAruW/Y8mKH6oc2fbT0CNwakiAjzw1HPvoPPGnxsR:el+rUWdGeCW/Y8CMT0uweGPGmR",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 11,
        len: 65_536,
        edits: &[777],
        tlsh: Some("T1C15302B4886623F207C37F70316F23C0645D4E8A5B66C649A126EE6BC82185CCFEDB4D"),
        ssdeep: "1536:MuSR6btTeJXdHHT8db63DJ+lIRTOiU8lJgbpzx9yfaobdbnI:nJ6J9w6xY7yJEpFMfao5rI",
    },
    Vector {
        kind: Kind::Bytes,
        seed: 11,
        len: 65_536,
        edits: &[
            0, 997, 1994, 2991, 3988, 4985, 5982, 6979, 7976, 8973, 9970, 10967, 11964, 12961,
            13958, 14955, 15952, 16949, 17946, 18943, 19940, 20937, 21934, 22931, 23928, 24925,
            25922, 26919, 27916, 28913, 29910, 30907, 31904, 32901, 33898, 34895, 35892, 36889,
            37886, 38883, 39880, 40877, 41874, 42871, 43868, 44865, 45862, 46859, 47856, 48853,
            49850, 50847, 51844, 52841, 53838, 54835, 55832, 56829, 57826, 58823, 59820, 60817,
            61814, 62811, 63808, 64805,
        ],
        tlsh: Some("T1C45302B488A623F207C37F70716F33C0645D498A5B678646A126EE6BC82185C8FADA4D"),
        ssdeep: "1536:euMFmvJ7i7XdHBxq/bO1zHyHiRxOmQulDulTzx/yfaGbdz7I:/hW7lcOZCPgDYTFqfaG5XI",
    },
    Vector {
        kind: Kind::Text,
        seed: 9,
        len: 4096,
        edits: &[100],
        tlsh: Some("T19E8100843BA6AAB10E7C05872B4B5B52738CC13E9F2ECF5F159E33794C954E8201EE19"),
        ssdeep: "48:wh0rTxrZegJiHzU/UydWAzoSu12nrSJyastVGt7IXl:TPx9iTaUytoSZnrmtFWl",
    },
    Vector {
        kind: Kind::Text,
        seed: 9,
        len: 4096,
        edits: &[100, 2000, 3500],
        tlsh: Some("T1668101843BA6AAB10E7C05872B4B5B52738CC13E9F2ECF5F159E33794C954E8201EE19"),
        ssdeep: "48:wh0rTxrZegJiHzU/UydW+zoSu12nrSJyastrGt7IXl:TPx9iTaUynoSZnrmtjWl",
    },
    Vector {
        kind: Kind::Text,
        seed: 11,
        len: 65_536,
        edits: &[777],
        tlsh: Some("T13A5313453BA6A5B10E7C05872B4B5B62734DC13E9F2ECF9F149A337A4C964E8210FE19"),
        ssdeep: "384:54MTslGO8wjWNc0LUJ75CELETNFYkcRc/r6Cug7skEFnCdNQmTNOqt5jRx/Z+19j:dIcx4sU",
    },
    Vector {
        kind: Kind::Text,
        seed: 11,
        len: 65_536,
        edits: &[
            0, 997, 1994, 2991, 3988, 4985, 5982, 6979, 7976, 8973, 9970, 10967, 11964, 12961,
            13958, 14955, 15952, 16949, 17946, 18943, 19940, 20937, 21934, 22931, 23928, 24925,
            25922, 26919, 27916, 28913, 29910, 30907, 31904, 32901, 33898, 34895, 35892, 36889,
            37886, 38883, 39880, 40877, 41874, 42871, 43868, 44865, 45862, 46859, 47856, 48853,
            49850, 50847, 51844, 52841, 53838, 54835, 55832, 56829, 57826, 58823, 59820, 60817,
            61814, 62811, 63808, 64805,
        ],
        tlsh: Some("T18C5313453BA6A5B10E7C05872B4B5B62734DC13E9F2ECF9F149A337A4C964E8210FE19"),
        ssdeep: "384:LUMhslGOawj0XcqLWH7DCEVEhZNH6ScRe/N0Cu27sWujngdDQmVnOqt5Dx/Z+P9p:NKeVQcK",
    },
];
/// (i, j, tlsh diff, tlsh diffxlen, ssdeep compare) over VECTORS indices
/// `(i, j, Some((diff, diffxlen)) or None for TNULL, ssdeep score)`.
pub type Pair = (usize, usize, Option<(u32, u32)>, u32);

pub const PAIRS: &[Pair] = &[
    (8, 26, Some((4, 4)), 99),
    (8, 27, Some((6, 6)), 94),
    (26, 27, Some((3, 3)), 97),
    (10, 28, Some((1, 1)), 99),
    (10, 29, Some((13, 13)), 0),
    (28, 29, Some((13, 13)), 0),
    (21, 30, Some((1, 1)), 99),
    (21, 31, Some((2, 2)), 94),
    (30, 31, Some((2, 2)), 96),
    (23, 32, Some((1, 1)), 99),
    (23, 33, Some((1, 1)), 0),
    (32, 33, Some((1, 1)), 0),
    (17, 21, Some((295, 127)), 0),
    (8, 9, Some((373, 253)), 0),
    (20, 21, Some((170, 86)), 0),
    (8, 21, Some((269, 269)), 0),
    (0, 4, None, 0),
    (12, 25, Some((251, 251)), 0),
];
