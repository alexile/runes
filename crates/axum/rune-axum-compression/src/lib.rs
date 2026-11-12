//! Response compression middleware — Tower middleware for Axum.
//!
//! A [`tower::Layer`] that compresses response bodies with the content
//! coding the client prefers, negotiated from `Accept-Encoding` per
//! [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.3).
//! Only responses worth compressing are touched: the `Content-Type` must be
//! on an allowlist (text-like types by default, so images, archives and
//! other already-compressed formats are skipped), and bodies of known size
//! below a threshold are sent as is.
//!
//! The decisions are sans-I/O: [`negotiate`] picks a coding,
//! [`Compression::should_compress`] decides eligibility and [`compress`]
//! encodes a buffer. The layer wires them to a streaming
//! [`CompressionBody`].
//!
//! # Features
//!
//! | Feature | Coding | Default |
//! |---------|--------|---------|
//! | `gzip` | `gzip` ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952)) | yes |
//! | `deflate` | `deflate` ([RFC 1950](https://www.rfc-editor.org/rfc/rfc1950) zlib stream) | yes |
//! | `br` | `br` ([RFC 7932](https://www.rfc-editor.org/rfc/rfc7932)) | no |
//! | `zstd` | `zstd` ([RFC 8878](https://www.rfc-editor.org/rfc/rfc8878)); builds C libzstd | no |
//! | `full` | all of the above | no |
//!
//! The server preference among codings the client weights equally is zstd,
//! br, gzip, deflate (see [`Compression::encodings`]).
//!
//! # Quick Start
//!
//! ```rust
//! use http::{header, HeaderMap, StatusCode};
//! use rune_axum_compression::{Compression, Encoding};
//!
//! let config = Compression::new();
//!
//! // Which coding? Client weights first, then server preference.
//! assert_eq!(config.negotiate("deflate;q=0.5, gzip"), Encoding::Gzip);
//! assert_eq!(config.negotiate("gzip;q=0"), Encoding::Identity);
//!
//! // Is the response worth compressing?
//! let mut headers = HeaderMap::new();
//! headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
//! assert!(config.should_compress(StatusCode::OK, &headers, Some(64 * 1024)));
//! assert!(!config.should_compress(StatusCode::OK, &headers, Some(200))); // too small
//!
//! headers.insert(header::CONTENT_TYPE, "image/png".parse().unwrap());
//! assert!(!config.should_compress(StatusCode::OK, &headers, Some(64 * 1024)));
//! ```
//!
//! # Axum
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_compression::{Compression, CompressionLayer, Encoding, Level};
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(CompressionLayer::new(
//!         Compression::new()
//!             .encodings([Encoding::Gzip])
//!             .level(Level::Fastest)
//!             .min_size(512)
//!             .content_type("application/x-yaml"),
//!     ));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use body::{BoxError, CompressionBody};
pub use codec::{Error, Level, compress};
pub use encoding::{Encoding, negotiate};
pub use layer::{Compression, CompressionLayer, CompressionService, ResponseFuture};

mod body;
mod codec;
mod encoding;
mod layer;
