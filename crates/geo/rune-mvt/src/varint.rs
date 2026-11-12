//! Low-level protobuf wire-format primitives: varint and zigzag encode/decode,
//! and a generic field walker used by this crate's own round-trip tests.

pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
pub fn decode_varint(buf: &[u8]) -> (u64, usize) {
    let mut result = 0u64;
    let mut shift = 0;
    let mut i = 0;
    loop {
        let byte = buf[i];
        result |= u64::from(byte & 0x7F) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, i)
}

#[allow(
    clippy::cast_sign_loss,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub const fn zigzag_encode(n: i32) -> u32 {
    ((n << 1) ^ (n >> 31)) as u32
}

#[allow(
    clippy::cast_possible_wrap,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub const fn zigzag_decode(n: u32) -> i32 {
    ((n >> 1) as i32) ^ -((n & 1) as i32)
}

#[allow(
    clippy::cast_sign_loss,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub const fn zigzag_encode_i64(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

#[allow(
    clippy::cast_possible_wrap,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
pub const fn zigzag_decode_i64(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

pub fn write_tag(field_number: u32, wire_type: u8, out: &mut Vec<u8>) {
    encode_varint((u64::from(field_number) << 3) | u64::from(wire_type), out);
}

pub fn write_length_delimited(field_number: u32, payload: &[u8], out: &mut Vec<u8>) {
    write_tag(field_number, 2, out);
    encode_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

pub fn write_varint_field(field_number: u32, value: u64, out: &mut Vec<u8>) {
    write_tag(field_number, 0, out);
    encode_varint(value, out);
}

pub fn write_fixed32_field(field_number: u32, value: f32, out: &mut Vec<u8>) {
    write_tag(field_number, 5, out);
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_fixed64_field(field_number: u32, value: f64, out: &mut Vec<u8>) {
    write_tag(field_number, 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

/// One decoded protobuf field, used only by this crate's own tests to verify
/// encoder output (there is no independent protobuf library in play here).
#[cfg(test)]
pub struct ProtoField<'a> {
    pub number: u32,
    pub wire_type: u8,
    pub varint: u64,
    pub bytes: &'a [u8],
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
#[cfg(test)]
pub fn iter_fields(buf: &[u8]) -> Vec<ProtoField<'_>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let (tag, n) = decode_varint(&buf[pos..]);
        pos += n;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;
        match wire_type {
            0 => {
                let (v, n) = decode_varint(&buf[pos..]);
                pos += n;
                out.push(ProtoField {
                    number: field_number,
                    wire_type,
                    varint: v,
                    bytes: &buf[pos..pos],
                });
            }
            1 => {
                let bytes = &buf[pos..pos + 8];
                pos += 8;
                out.push(ProtoField {
                    number: field_number,
                    wire_type,
                    varint: 0,
                    bytes,
                });
            }
            2 => {
                let (len, n) = decode_varint(&buf[pos..]);
                pos += n;
                let len = len as usize;
                let bytes = &buf[pos..pos + len];
                pos += len;
                out.push(ProtoField {
                    number: field_number,
                    wire_type,
                    varint: 0,
                    bytes,
                });
            }
            _ => panic!("unsupported wire type {wire_type} in test decoder"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips() {
        for value in [0u64, 1, 127, 128, 300, 16384, u64::from(u32::MAX)] {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            let (decoded, consumed) = decode_varint(&buf);
            assert_eq!(decoded, value);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn varint_matches_known_encoding() {
        // 300 = 0b1_0010_1100 -> low 7 bits 0101100 with continuation, then 0000010
        let mut buf = Vec::new();
        encode_varint(300, &mut buf);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn zigzag_round_trips_positive_and_negative() {
        for n in [-1000, -1, 0, 1, 1000] {
            assert_eq!(zigzag_decode(zigzag_encode(n)), n);
        }
    }

    #[test]
    fn zigzag_matches_known_values() {
        assert_eq!(zigzag_encode(0), 0);
        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_encode(1), 2);
        assert_eq!(zigzag_encode(-2), 3);
    }

    #[test]
    fn zigzag_i64_round_trips_positive_and_negative() {
        for n in [
            i64::MIN + 1,
            -1_000_000_000_000,
            -1,
            0,
            1,
            1_000_000_000_000,
            i64::MAX,
        ] {
            assert_eq!(zigzag_decode_i64(zigzag_encode_i64(n)), n);
        }
    }

    #[test]
    fn zigzag_i64_matches_known_values() {
        assert_eq!(zigzag_encode_i64(0), 0);
        assert_eq!(zigzag_encode_i64(-1), 1);
        assert_eq!(zigzag_encode_i64(1), 2);
        assert_eq!(zigzag_encode_i64(-2), 3);
    }

    #[test]
    fn tag_encoding_matches_field_number_and_wire_type() {
        let mut buf = Vec::new();
        write_tag(3, 2, &mut buf);
        let (tag, _) = decode_varint(&buf);
        assert_eq!(tag >> 3, 3);
        assert_eq!(tag & 0x7, 2);
    }

    #[test]
    fn length_delimited_round_trips_via_iter_fields() {
        let mut buf = Vec::new();
        write_length_delimited(5, b"hello", &mut buf);
        let fields = iter_fields(&buf);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].number, 5);
        assert_eq!(fields[0].wire_type, 2);
        assert_eq!(fields[0].bytes, b"hello");
    }
}
