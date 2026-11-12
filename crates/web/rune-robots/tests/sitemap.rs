//! sitemap.xml, sitemap index, text and gzip parsing.

#[cfg(feature = "gzip")]
use std::io::Write;

use rune_robots::{ChangeFreq, Error, Options, Sitemap, SitemapRef, UrlEntry};

const URLSET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>https://www.example.com/</loc>
    <lastmod>2005-01-01</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc><![CDATA[https://www.example.com/catalog?item=12&desc=vacation_hawaii]]></loc>
    <changefreq>Weekly</changefreq>
    <image:image><image:loc>https://www.example.com/image.jpg</image:loc></image:image>
  </url>
  <url>
    <loc>
      https://www.example.com/catalog?item=73&amp;desc=vacation_new_zealand&#x26;x=&#49;
    </loc>
    <priority>7</priority>
    <changefreq>sometimes</changefreq>
  </url>
  <url><lastmod>2004-12-23</lastmod></url>
</urlset>"#;

#[cfg(feature = "gzip")]
#[allow(clippy::unwrap_used, reason = "test helper")]
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn urlset() {
    let sitemap = Sitemap::parse(URLSET.as_bytes()).unwrap();
    let Sitemap::UrlSet(entries) = &sitemap else {
        panic!("expected a urlset");
    };
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].loc, "https://www.example.com/");
    assert_eq!(entries[0].lastmod.as_deref(), Some("2005-01-01"));
    assert_eq!(entries[0].changefreq, Some(ChangeFreq::Monthly));
    assert_eq!(entries[0].priority, Some(0.8));
    assert_eq!(
        entries[1].loc,
        "https://www.example.com/catalog?item=12&desc=vacation_hawaii"
    );
    assert_eq!(entries[1].changefreq, Some(ChangeFreq::Weekly));
    assert_eq!(
        entries[2].loc,
        "https://www.example.com/catalog?item=73&desc=vacation_new_zealand&x=1"
    );
    assert_eq!(entries[2].priority, None);
    assert_eq!(entries[2].changefreq, None);
    assert!(!sitemap.is_index());
    assert_eq!(sitemap.len(), 3);
}

#[test]
fn sitemap_index() {
    let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://www.example.com/sitemap1.xml.gz</loc><lastmod>2004-10-01T18:23:17+00:00</lastmod></sitemap>
  <sitemap><loc>https://www.example.com/sitemap2.xml.gz</loc></sitemap>
</sitemapindex>"#;
    let sitemap = Sitemap::parse(body).unwrap();
    let Sitemap::Index(refs) = &sitemap else {
        panic!("expected an index");
    };
    assert_eq!(refs.len(), 2);
    assert_eq!(
        refs[0].lastmod.as_deref(),
        Some("2004-10-01T18:23:17+00:00")
    );
    assert_eq!(
        sitemap.locations().collect::<Vec<_>>(),
        [
            "https://www.example.com/sitemap1.xml.gz",
            "https://www.example.com/sitemap2.xml.gz"
        ]
    );
    let first: &SitemapRef = &refs[0];
    assert!(first.loc.ends_with("sitemap1.xml.gz"));
}

#[test]
fn prefixed_default_namespace_elements_are_not_entries() {
    // `<url>` under an index, and `<sitemap>` under a urlset, are ignored.
    let sitemap = Sitemap::parse(b"<sitemapindex><url><loc>x</loc></url></sitemapindex>").unwrap();
    assert!(sitemap.is_index() && sitemap.is_empty());
    let sitemap = Sitemap::parse(b"<urlset><sitemap><loc>x</loc></sitemap></urlset>").unwrap();
    assert!(!sitemap.is_index() && sitemap.is_empty());
}

#[test]
fn plain_text_sitemap() {
    let sitemap =
        Sitemap::parse(b"\xEF\xBB\xBFhttps://e.com/a\r\n\r\n  https://e.com/b  \n").unwrap();
    assert_eq!(
        sitemap,
        Sitemap::UrlSet(vec![
            UrlEntry::new("https://e.com/a"),
            UrlEntry::new("https://e.com/b"),
        ])
    );
}

#[cfg(feature = "gzip")]
#[test]
fn gzipped_sitemaps() {
    let plain = Sitemap::parse(URLSET.as_bytes()).unwrap();
    assert_eq!(Sitemap::parse(&gzip(URLSET.as_bytes())).unwrap(), plain);
    // Truncated stream.
    let mut broken = gzip(URLSET.as_bytes());
    broken.truncate(broken.len() / 2);
    assert!(matches!(Sitemap::parse(&broken), Err(Error::Gzip { .. })));
}

#[cfg(feature = "gzip")]
#[test]
fn decompression_is_bounded() {
    let bomb = gzip(&vec![b' '; 1 << 20]);
    let options = Options::default().with_max_len(1024);
    assert_eq!(
        Sitemap::parse_with(&bomb, &options),
        Err(Error::TooLarge { limit: 1024 })
    );
    assert_eq!(
        Sitemap::parse_with(&[b' '; 2048], &options),
        Err(Error::TooLarge { limit: 1024 })
    );
}

#[test]
fn entry_limit() {
    let options = Options::default().with_max_entries(2);
    assert_eq!(
        Sitemap::parse_with(URLSET.as_bytes(), &options),
        Err(Error::TooManyEntries { limit: 2 })
    );
    assert_eq!(
        Sitemap::parse_with(b"a\nb\nc\n", &options),
        Err(Error::TooManyEntries { limit: 2 })
    );
    assert!(Sitemap::parse_with(b"a\nb\n", &options).is_ok());
}
