//! Property tests: matching agrees with a naive reference matcher, parsers
//! never panic, and sitemaps round-trip through XML and gzip.

use std::fmt::Write as _;
#[cfg(feature = "gzip")]
use std::io::Write as _;

use proptest::prelude::*;
use rune_robots::{Robots, Rule, RuleKind, Sitemap};

/// Naive recursive RFC 9309 matcher over plain ASCII.
fn reference(path: &[u8], pattern: &[u8]) -> bool {
    match pattern.split_first() {
        None => true,
        Some((b'$', [])) => path.is_empty(),
        Some((b'*', rest)) => (0..=path.len()).any(|i| reference(&path[i..], rest)),
        Some((&c, rest)) => path.first() == Some(&c) && reference(&path[1..], rest),
    }
}

proptest! {
    #[test]
    fn matcher_agrees_with_reference(path in "/[ab*$/.]{0,12}", pattern in "/[ab*$/.]{0,8}") {
        let rule = Rule::new(RuleKind::Disallow, &pattern);
        prop_assert_eq!(rule.matches(&path), reference(path.as_bytes(), pattern.as_bytes()));
    }

    #[test]
    fn literal_prefix_rules_block(path in "/[a-z/]{0,20}", cut in 0usize..20) {
        let prefix = &path[..cut.min(path.len()).max(1)];
        let robots = Robots::parse(&format!("User-agent: *\nDisallow: {prefix}\n"));
        prop_assert!(!robots.is_allowed("bot", &path) || path == "/robots.txt");
        // A more specific allow overrides it.
        let robots = Robots::parse(&format!("User-agent: *\nDisallow: {prefix}\nAllow: {path}\n"));
        prop_assert!(robots.is_allowed("bot", &path));
    }

    #[test]
    fn robots_never_panics(body in any::<Vec<u8>>(), agent in any::<String>(), path in any::<String>()) {
        let robots = Robots::parse_bytes(&body);
        let _ = robots.verdict(&agent, &path);
        let _ = robots.crawl_delay(&agent);
        prop_assert!(robots.is_allowed(&agent, "/robots.txt"));
    }

    #[test]
    fn sitemap_never_panics(body in any::<Vec<u8>>(), text in any::<String>()) {
        let _ = Sitemap::parse(&body);
        let _ = Sitemap::parse(text.as_bytes());
        let _ = Sitemap::parse(format!("<urlset><url><loc>{text}</loc></url></urlset>").as_bytes());
    }

    #[test]
    fn sitemap_round_trips(locs in prop::collection::vec("https://[a-z]{1,8}\\.com/[a-z0-9&<>\"'/?=]{0,16}", 0..8)) {
        let mut xml = String::from(r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">"#);
        for loc in &locs {
            let escaped = loc.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
                .replace('"', "&quot;").replace('\'', "&apos;");
            write!(xml, "<url><loc>{escaped}</loc></url>").unwrap();
        }
        xml.push_str("</urlset>");
        let parsed = Sitemap::parse(xml.as_bytes()).unwrap();
        prop_assert_eq!(parsed.locations().collect::<Vec<_>>(), locs.iter().map(String::as_str).collect::<Vec<_>>());
        #[cfg(feature = "gzip")]
        {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(xml.as_bytes()).unwrap();
        prop_assert_eq!(Sitemap::parse(&encoder.finish().unwrap()).unwrap(), parsed);
        }
    }
}
