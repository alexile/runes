//! Server replies shared by the integration tests.

#![allow(dead_code, reason = "each test binary uses a subset")]
#![allow(clippy::unwrap_used, reason = "test code")]

/// The SPNEGO `negTokenInit` Windows Server sends in its `NEGOTIATE`
/// response: NEGOEX, MS-KRB5, KRB5, KRB5-U2U, NTLMSSP and the
/// `not_defined_in_RFC4178@please_ignore` hint.
pub const WINDOWS_SPNEGO: [u8; 120] = [
    0x60, 0x76, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x6c, 0x30, 0x6a, 0xa0, 0x3c,
    0x30, 0x3a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x12, 0x01, 0x02, 0x02, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03,
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28,
    0xa0, 0x26, 0x1b, 0x24, b'n', b'o', b't', b'_', b'd', b'e', b'f', b'i', b'n', b'e', b'd', b'_',
    b'i', b'n', b'_', b'R', b'F', b'C', b'4', b'1', b'7', b'8', b'@', b'p', b'l', b'e', b'a', b's',
    b'e', b'_', b'i', b'g', b'n', b'o', b'r', b'e',
];

/// `2026-11-12T00:00:00Z` as a FILETIME.
pub const FILETIME: u64 = (1_794_441_600 + 11_644_473_600) * 10_000_000;

pub fn netbios(msg: &[u8]) -> Vec<u8> {
    let len = u32::try_from(msg.len()).unwrap();
    let mut out = vec![0];
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(msg);
    out
}

/// An SMB 2/3 `NEGOTIATE` response.
pub fn smb2_response(
    dialect: u16,
    security_mode: u16,
    capabilities: u32,
    guid: [u8; 16],
    blob: &[u8],
    contexts: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"\xfeSMB");
    m.extend_from_slice(&64u16.to_le_bytes());
    m.extend_from_slice(&1u16.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&1u16.to_le_bytes());
    m.extend_from_slice(&1u32.to_le_bytes()); // SMB2_FLAGS_SERVER_TO_REDIR
    m.extend_from_slice(&[0; 4 + 8 + 4 + 4 + 8 + 16]);
    let blob_offset = 128u16;
    let ctx_offset = (128 + blob.len()).next_multiple_of(8);
    m.extend_from_slice(&65u16.to_le_bytes());
    m.extend_from_slice(&security_mode.to_le_bytes());
    m.extend_from_slice(&dialect.to_le_bytes());
    m.extend_from_slice(&u16::try_from(contexts.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&guid);
    m.extend_from_slice(&capabilities.to_le_bytes());
    m.extend_from_slice(&8_388_608u32.to_le_bytes());
    m.extend_from_slice(&8_388_608u32.to_le_bytes());
    m.extend_from_slice(&8_388_608u32.to_le_bytes());
    m.extend_from_slice(&FILETIME.to_le_bytes());
    m.extend_from_slice(&0u64.to_le_bytes());
    m.extend_from_slice(&blob_offset.to_le_bytes());
    m.extend_from_slice(&u16::try_from(blob.len()).unwrap().to_le_bytes());
    let ctx = if contexts.is_empty() { 0 } else { ctx_offset };
    m.extend_from_slice(&u32::try_from(ctx).unwrap().to_le_bytes());
    assert_eq!(m.len(), 128);
    m.extend_from_slice(blob);
    for (kind, data) in contexts {
        while m.len() % 8 != 0 {
            m.push(0);
        }
        m.extend_from_slice(&kind.to_le_bytes());
        m.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        m.extend_from_slice(&[0; 4]);
        m.extend_from_slice(data);
    }
    netbios(&m)
}

/// The response of Windows Server 2022: SMB 3.1.1, signing enabled but
/// not required, AES-128-GCM and AES-GMAC picked.
pub fn windows_2022(security_mode: u16) -> Vec<u8> {
    let mut preauth = vec![1, 0, 32, 0, 1, 0];
    preauth.extend_from_slice(&[0x11; 32]);
    smb2_response(
        0x0311,
        security_mode,
        0x2f,
        *b"\x10\x32\x54\x76\x98\xba\xdc\xfe\x01\x23\x45\x67\x89\xab\xcd\xef",
        &WINDOWS_SPNEGO,
        &[(1, &preauth), (2, &[1, 0, 2, 0]), (8, &[1, 0, 2, 0])],
    )
}

/// An SMB1 `NEGOTIATE` response accepting `NT LM 0.12`.
pub fn smb1_response(security_mode: u8, extended: bool) -> Vec<u8> {
    let mut m = b"\xffSMB\x72".to_vec();
    m.extend_from_slice(&0u32.to_le_bytes());
    m.push(0x98);
    m.extend_from_slice(&0xc853u16.to_le_bytes());
    m.extend_from_slice(&[0; 12]);
    m.extend_from_slice(&[0, 0, 0xff, 0xfe, 0, 0, 0, 0]);
    m.push(17);
    m.extend_from_slice(&0u16.to_le_bytes()); // DialectIndex
    m.push(security_mode);
    m.extend_from_slice(&50u16.to_le_bytes());
    m.extend_from_slice(&1u16.to_le_bytes());
    m.extend_from_slice(&16_644u32.to_le_bytes());
    m.extend_from_slice(&65_536u32.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes());
    let caps: u32 = if extended { 0x8000_f3fd } else { 0x0000_f3fd };
    m.extend_from_slice(&caps.to_le_bytes());
    m.extend_from_slice(&FILETIME.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    let mut bytes = Vec::new();
    if extended {
        m.push(0);
        bytes.extend_from_slice(b"0123456789abcdef");
        bytes.extend_from_slice(&WINDOWS_SPNEGO);
    } else {
        m.push(8);
        bytes.extend_from_slice(&[0xaa; 8]);
        for name in ["WORKGROUP", "FILESRV"] {
            for unit in name.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&[0, 0]);
        }
    }
    m.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_le_bytes());
    m.extend_from_slice(&bytes);
    netbios(&m)
}

/// An RDP Connection Confirm with negotiation data.
pub fn rdp_confirm(kind: u8, flags: u8, value: u32) -> Vec<u8> {
    let mut out = vec![
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, kind, flags, 8, 0,
    ];
    out.extend_from_slice(&value.to_le_bytes());
    out
}
