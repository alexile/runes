//! Parse `robots.txt` ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309))
//! and `sitemap.xml` / sitemap index files
//! ([sitemaps.org](https://www.sitemaps.org/protocol.html)), and decide
//! whether a crawler may fetch a path.
//!
//! - [`Robots`] parses a robots.txt body (never fails, like RFC 9309
//!   requires), selects the groups for a user agent, and answers
//!   "is this path allowed?" with the longest-match rule ([`Robots::verdict`],
//!   [`Robots::is_allowed`]). It also exposes `Crawl-delay` and `Sitemap`
//!   directives, and [`Robots::from_response`] maps a fetch status to the
//!   allow-all / disallow-all fallbacks of RFC 9309 §2.3.1.
//! - [`Sitemap`] parses a `<urlset>`, a `<sitemapindex>` or a plain-text
//!   sitemap, gzipped or not, with size and entry limits ([`Options`]).
//!
//! The crate is sans-I/O: you fetch the bytes, it interprets them.
//!
//! # Example
//!
//! ```
//! use rune_robots::{Robots, Sitemap};
//!
//! let robots = Robots::parse(
//!     "User-agent: *\n\
//!      Disallow: /private/\n\
//!      Allow: /private/press-kit/\n\
//!      \n\
//!      User-agent: BadBot\n\
//!      Disallow: /\n\
//!      \n\
//!      Sitemap: https://example.com/sitemap.xml\n",
//! );
//! assert!(robots.is_allowed("MyCrawler/1.0", "/index.html"));
//! assert!(!robots.is_allowed("MyCrawler/1.0", "/private/notes"));
//! assert!(robots.is_allowed("MyCrawler/1.0", "https://example.com/private/press-kit/logo.png"));
//! assert!(!robots.is_allowed("badbot", "/index.html"));
//! assert_eq!(robots.sitemaps, ["https://example.com/sitemap.xml"]);
//!
//! let sitemap = Sitemap::parse(
//!     br#"<?xml version="1.0" encoding="UTF-8"?>
//!     <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
//!       <url><loc>https://example.com/?a=1&amp;b=2</loc><priority>0.8</priority></url>
//!     </urlset>"#,
//! )?;
//! assert_eq!(sitemap.locations().collect::<Vec<_>>(), ["https://example.com/?a=1&b=2"]);
//! # Ok::<(), rune_robots::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod robots;
mod sitemap;

pub use robots::{
    Group, MAX_ROBOTS_LEN, ROBOTS_PATH, Robots, Rule, RuleKind, Verdict, robots_path,
};
pub use sitemap::{
    ChangeFreq, MAX_SITEMAP_ENTRIES, MAX_SITEMAP_LEN, Options, Sitemap, SitemapRef, UrlEntry,
};

/// Errors from parsing a sitemap. Parsing robots.txt never fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The (decompressed) body is larger than the limit.
    #[error("sitemap is larger than {limit} bytes")]
    TooLarge {
        /// The limit, in bytes.
        limit: usize,
    },
    /// The sitemap has more entries than the limit.
    #[error("sitemap has more than {limit} entries")]
    TooManyEntries {
        /// The limit.
        limit: usize,
    },
    /// The body is not UTF-8.
    #[error("sitemap is not UTF-8 (invalid at byte {offset})")]
    NotUtf8 {
        /// Length of the valid prefix.
        offset: usize,
    },
    /// The gzip stream is corrupt, or gzip support is disabled.
    #[error("cannot decompress gzipped sitemap: {message}")]
    Gzip {
        /// What went wrong.
        message: String,
    },
    /// The XML is malformed.
    #[error("malformed sitemap XML at byte {position}: {message}")]
    Xml {
        /// Byte offset of the error.
        position: u64,
        /// What is wrong.
        message: String,
    },
    /// The root element is neither `<urlset>` nor `<sitemapindex>`.
    #[error("not a sitemap (root element `{root}`)")]
    NotSitemap {
        /// The root element's local name (empty when there is none).
        root: String,
    },
}
