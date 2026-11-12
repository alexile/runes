//! A registry of named, chainable byte transforms, in the style of Burp
//! Decoder.
//!
//! A [`Transform`] is one named byte-to-byte operation. It always has a
//! forward direction ([`Transform::encode`]) and, when it is reversible, a
//! backward one ([`Transform::decode`]). Transforms are looked up by id in a
//! [`TransformRegistry`] and composed into a [`TransformChain`].
//!
//! [`TransformRegistry::builtin`] holds more than forty transforms: base64,
//! base32, hex, URL and HTML encodings, JavaScript and `%u` escapes, binary
//! and decimal renderings, gzip/zlib/deflate, ROT13/ROT47/atbash and other
//! byte shuffles, MD5 and the SHA family, case folding and JWT decoding. The
//! codecs come from the existing rune crates (`rune-base64`, `rune-hex`,
//! `rune-url-encode`, `rune-html-encode`, `rune-jwt`, …); this crate only
//! adds the registry, chaining and the operations that have no rune of their
//! own. Parameterised transforms ([`PrefixTransform`], [`SuffixTransform`],
//! [`MatchReplaceTransform`], [`XorTransform`], [`CompressTransform`] with a
//! custom limit, …) are built directly and can be registered or chained like
//! any other.
//!
//! [`smart_decode`] peels layered base64, URL and hex encodings off a value
//! heuristically.
//!
//! Everything is sans-I/O: transforms work on in-memory bytes, and nothing
//! is global. Decompression is bounded (see [`CompressTransform`]).
//!
//! # Example
//!
//! ```
//! use rune_transform::TransformRegistry;
//!
//! let registry = TransformRegistry::builtin();
//!
//! // One transform, both directions.
//! assert_eq!(registry.encode("base64", b"hi")?, b"aGk=");
//! assert_eq!(registry.decode("hex", b"6869")?, b"hi");
//!
//! // A chain runs left to right on encode and right to left on decode.
//! let chain = registry.parse_chain("gzip | base64")?;
//! let packed = chain.encode(b"hello hello hello")?;
//! assert_eq!(chain.decode(&packed)?, b"hello hello hello");
//!
//! // `:decode` turns a step around, so mixed pipelines read naturally.
//! let unpack = registry.parse_chain("base64:decode | gzip:decode")?;
//! assert_eq!(unpack.encode(&packed)?, b"hello hello hello");
//!
//! // Hashes are one-way: chain them with an encoding to print them.
//! let digest = registry.parse_chain("sha256 | hex")?.encode(b"abc")?;
//! assert!(digest.starts_with(b"ba7816bf"));
//! # Ok::<(), rune_transform::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod builtin;
mod chain;
mod compress;
mod error;
mod ops;
mod registry;
mod smart;
mod transform;

pub use chain::TransformChain;
pub use compress::{CompressTransform, CompressionFormat, DEFAULT_MAX_OUTPUT};
pub use error::Error;
pub use ops::{
    MatchReplaceTransform, PrefixTransform, SuffixTransform, UnicodeLowerCaseTransform,
    UnicodeUpperCaseTransform, XorTransform,
};
pub use registry::{Direction, TransformRegistry};
pub use smart::{SMART_DECODE_MAX_DEPTH, SmartDecodeStep, smart_decode};
pub use transform::{Category, Inverse, Transform};
