
> Fast hex encoding and decoding: `no_std`, zero-copy slices, constant-time decoding, tolerant parsing, io streams and serde.

[![crates.io](https://img.shields.io/crates/v/rune-hex)](https://crates.io/crates/rune-hex)
[![docs.rs](https://img.shields.io/docsrs/rune-hex)](https://docs.rs/rune-hex)
[![license](https://img.shields.io/crates/l/rune-hex)](LICENSE)

- Encode to lowercase or uppercase, into a `String`, a caller's buffer, or
  straight into a formatter.
- Decode from a `String`, into a buffer, or into a fixed-size array.
- Errors say what went wrong and where (`invalid hex character 'g' at offset 3`).
- Tolerant decoding (whitespace, `0x`, `:`/`-` separators) when you ask for it.
- A constant-time decoder for keys and other secrets.
- `Read`/`Write` adapters that stream through a fixed 4 KiB buffer.
- `#[serde(with = "rune_hex::serde")]` for byte fields.
- Safe Rust only, `no_std` friendly, no required dependencies.

## Installation

```toml
[dependencies]
rune-hex = "0.3"
```

| Feature | Default | What it adds |
|---|---|---|
| `std` | yes | `rune_hex::io` stream adapters; implies `alloc` |
| `alloc` | via `std` | functions returning `String` / `Vec<u8>` |
| `serde` | no | `rune_hex::serde` helpers |
| `cli` | no | the `rune-hex` binary |

For `no_std`, use `default-features = false` and add `alloc` if you have an
allocator. The slice, array, `display` and `ct` functions need only `core`.

## Usage

### Encode and decode

```rust
use rune_hex::{decode, encode, encode_upper};

assert_eq!(encode(b"\xde\xad\xbe\xef"), "deadbeef");
assert_eq!(encode_upper(b"\xde\xad\xbe\xef"), "DEADBEEF");

assert_eq!(decode("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
assert_eq!(decode("0xDeAdBeEf").unwrap(), b"\xde\xad\xbe\xef"); // either case, optional 0x
```

### Without allocating

```rust
// Into a buffer; returns the written part as &mut str.
let mut buf = [0u8; 64];
let hex = rune_hex::encode_to_slice([0xca, 0xfe], &mut buf).unwrap();
assert_eq!(hex, "cafe");

// Into a fixed-size array: handy for digests and ids.
let digest: [u8; 4] = rune_hex::decode_array("deadbeef").unwrap();

// Into a buffer; returns the written part.
let mut out = [0u8; 16];
let bytes = rune_hex::decode_to_slice("0102", &mut out).unwrap();
assert_eq!(bytes, [1, 2]);

// Straight into a formatter.
assert_eq!(format!("sha256:{}", rune_hex::display(&digest)), "sha256:deadbeef");
assert_eq!(format!("{:X}", rune_hex::display(&digest)), "DEADBEEF");
```

### Errors

```rust
use rune_hex::{decode, HexError};

assert_eq!(decode("abc"), Err(HexError::OddLength));
assert_eq!(decode("0x00fg"), Err(HexError::InvalidByte { byte: b'g', offset: 5 }));
assert_eq!(
    decode("00fg").unwrap_err().to_string(),
    "invalid hex character 'g' at offset 3",
);
```

### Tolerant input

Plain `decode` accepts digits and an optional `0x`, nothing else.
`DecodeOptions` switches on each relaxation explicitly. Whitespace and
separators are allowed only between bytes, never between the two digits of
one byte.

```rust
use rune_hex::DecodeOptions;

let fingerprint = DecodeOptions::new().separator(b':');
assert_eq!(fingerprint.decode("DE:AD:BE:EF").unwrap(), [0xde, 0xad, 0xbe, 0xef]);

let wrapped = DecodeOptions::new().skip_whitespace(true);
assert_eq!(wrapped.decode("dead\nbeef\n").unwrap(), [0xde, 0xad, 0xbe, 0xef]);

// 0x, whitespace, ':' and '-' all at once.
let mac: [u8; 6] = DecodeOptions::lenient().decode_array("00-1a-2b-3c-4d-5e").unwrap();
```

### Secrets: constant-time decoding

`rune_hex::ct` treats every input byte the same way, with no lookup tables and
no branches on the data, and reports only *that* the input was bad, not
where. Timing depends on the length alone. On error the output is zeroed.

```rust
use rune_hex::{ct, HexError};

let key: [u8; 4] = ct::decode_array("00ff10EF").unwrap();
assert_eq!(ct::decode_array::<2>("00zz"), Err(HexError::Invalid));
```

The regular encoder is already table-free and branch-free, so
`encode`/`encode_to_slice` are fine for secrets too. This is careful code,
not a formally verified guarantee: the compiler and CPU have the last word.

### Streams

```rust
use std::io::{Read, Write};
use rune_hex::{DecodeOptions, io::{DecodeReader, EncodeWriter}};

let mut enc = EncodeWriter::new(Vec::new());
enc.write_all(b"streamed").unwrap();
assert_eq!(enc.into_inner(), b"73747265616d6564");

let text = "73 74 72 65\n61 6d 65 64\n";
let mut bytes = Vec::new();
DecodeReader::with_options(text.as_bytes(), DecodeOptions::lenient()).read_to_end(&mut bytes).unwrap();
assert_eq!(bytes, b"streamed");
```

`EncodeReader` and `DecodeWriter` cover the other two directions. Decoding
errors come back as `io::ErrorKind::InvalidData` with the stream offset.

### Serde

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Entry {
    #[serde(with = "rune_hex::serde")]
    digest: [u8; 32],
    #[serde(with = "rune_hex::serde::upper")]
    payload: Vec<u8>,
    #[serde(with = "rune_hex::serde::option", default)]
    salt: Option<Vec<u8>>,
}
```

### CLI

```bash
cargo install rune-hex --features cli
```

```bash
echo -n hello | rune-hex encode            # 68656c6c6f
echo -n hello | rune-hex encode -u -s :    # 68:65:6C:6C:6F
rune-hex encode -w 16 -s ' ' firmware.bin  # 16 bytes per line, space separated

rune-hex decode 0xdeadbeef > out.bin
rune-hex decode -f dump.hex > out.bin      # whitespace and newlines are fine
echo "de:ad:be:ef" | rune-hex decode -s :  # accept extra separators
```

Both commands stream, so input size is not limited by memory. Errors name the
offset: `rune-hex: invalid hex character 'z' at offset 4`.

## Performance

Encoding turns eight bytes at a time into sixteen digits with plain `u64`
arithmetic. Decoding validates and converts eight digits at a time the same
way, then looks for the offending byte only if something was wrong. Both are
safe Rust with no lookup tables.

Throughput on 1 MiB of input, best of several runs, AMD Ryzen 7 7800X3D,
rustc 1.99, `--release`:

| Operation | rune-hex 0.3 | rune-hex 0.2 | hex 0.4.3 |
|---|---:|---:|---:|
| encode to `String` | 1.4 GiB/s | 0.27 GiB/s | 0.35 GiB/s |
| encode into a slice | 1.5 GiB/s | — | 1.5 GiB/s |
| decode to `Vec` | 2.6 GiB/s | 0.45 GiB/s | 0.40 GiB/s |
| decode into a slice | 2.6 GiB/s | — | 0.75 GiB/s |
| `ct` decode into a slice | 2.6 GiB/s | — | — |
| `DecodeOptions::lenient` decode | 0.8 GiB/s | — | — |

Numbers will differ on other machines; the ratios are the useful part.

## Migrating from 0.2

- `HexError` is now `#[non_exhaustive]` and `Copy`. `InvalidChar(char)` became
  `InvalidByte { byte, offset }`: the raw input byte and its position. Error
  messages now include the offset.
- New variants: `Invalid` (from `ct`), `BufferTooSmall`, `WrongLength`.
- `encode`, `encode_upper` and `decode` take `impl AsRef<[u8]>`, so existing
  calls with `&str`, `&String`, `&[u8]` or `&Vec<u8>` keep compiling.
- With `default-features = false`, the `String`/`Vec` functions now need the
  `alloc` feature.
- CLI: `decode` now skips whitespace anywhere between bytes, not just at the
  ends, and streams its output; `encode` gained `--wrap` and `--separator`.

## License

MIT
