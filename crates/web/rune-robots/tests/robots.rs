//! robots.txt behaviour from RFC 9309 and Google's reference parser.

use std::time::Duration;

use rune_robots::{Robots, Rule, RuleKind};

#[test]
fn rfc9309_example() {
    // RFC 9309 §5.1.
    let robots = Robots::parse(
        "User-Agent: foobot\n\
         Disallow: /\n\
         Allow: /example/page.html\n\
         Allow: /example/allowed.gif\n\
         \n\
         User-Agent: barbot\n\
         User-Agent: bazbot\n\
         Disallow: /example/page.html\n\
         \n\
         User-Agent: quxbot\n\
         \n\
         EOF",
    );
    assert!(robots.is_allowed("foobot", "/example/page.html"));
    assert!(robots.is_allowed("foobot", "/example/allowed.gif"));
    assert!(!robots.is_allowed("foobot", "/example/disallowed.gif"));
    assert!(!robots.is_allowed("barbot", "/example/page.html"));
    assert!(!robots.is_allowed("bazbot", "/example/page.html"));
    assert!(robots.is_allowed("bazbot", "/example/allowed.gif"));
    assert!(robots.is_allowed("quxbot", "/anything"));
    assert!(robots.is_allowed("otherbot", "/example/page.html"));
    assert_eq!(robots.groups.len(), 3);
    assert_eq!(robots.groups[1].user_agents, ["barbot", "bazbot"]);
}

#[test]
fn longest_match_and_allow_wins_ties() {
    let robots = Robots::parse(
        "user-agent: *\n\
         allow: /p\n\
         disallow: /\n\
         allow: /folder\n\
         disallow: /folder\n\
         allow: /page\n\
         disallow: /*.htm\n\
         allow: /$\n\
         disallow: /secret\n",
    );
    assert!(robots.is_allowed("x", "/page"));
    assert!(robots.is_allowed("x", "/folder/page"));
    assert!(!robots.is_allowed("x", "/page.htm"));
    assert!(robots.is_allowed("x", "/"));
    assert!(!robots.is_allowed("x", "/other"));
    let verdict = robots.verdict("x", "/secret/plans");
    assert!(!verdict.allowed);
    let rule = verdict.rule.unwrap();
    assert_eq!(
        (rule.kind, rule.pattern.as_str(), rule.line),
        (RuleKind::Disallow, "/secret", 9)
    );
}

#[test]
fn group_selection_merges_and_falls_back() {
    let robots = Robots::parse(
        "User-agent: googlebot\nDisallow: /a\n\
         User-agent: *\nDisallow: /b\n\
         User-agent: Googlebot/2.1\nDisallow: /c\n",
    );
    // Specific groups merge; the `*` group does not apply to googlebot.
    assert!(!robots.is_allowed("Googlebot", "/a"));
    assert!(robots.is_allowed("Googlebot", "/b"));
    assert!(!robots.is_allowed("GOOGLEBOT/2.1 (+http://www.google.com/bot.html)", "/c"));
    assert!(robots.is_allowed("otherbot", "/a"));
    assert!(!robots.is_allowed("otherbot", "/b"));
    assert_eq!(robots.groups_for("googlebot").count(), 2);
    // No group, no rules.
    assert!(Robots::parse("User-agent: a\nDisallow: /\n").is_allowed("b", "/x"));
}

#[test]
fn rules_outside_groups_and_empty_rules_are_ignored() {
    let robots = Robots::parse("Disallow: /\nUser-agent: *\nDisallow:\nAllow:\n");
    assert!(robots.is_allowed("x", "/anything"));
    assert_eq!(robots.groups[0].rules, []);
}

#[test]
fn robots_txt_is_always_allowed() {
    let robots = Robots::disallow_all();
    assert!(!robots.is_allowed("x", "/"));
    assert!(robots.is_allowed("x", "/robots.txt"));
    assert!(robots.is_allowed("x", "https://example.com/robots.txt"));
}

#[test]
fn lenient_syntax() {
    let robots = Robots::parse_bytes(
        b"\xEF\xBB\xBFuseragent: *\r\ndisalow: /a # comment\rDisallow /b\n  DISALLOW :  /c  \nsite-map: https://e.com/s.xml\nfoo: bar\n",
    );
    for path in ["/a", "/b", "/c"] {
        assert!(!robots.is_allowed("x", path), "{path}");
    }
    assert_eq!(robots.sitemaps, ["https://e.com/s.xml"]);
}

#[test]
fn group_is_not_closed_by_sitemap_or_unknown_lines() {
    let robots = Robots::parse(
        "User-agent: a\nSitemap: https://e.com/s.xml\nUser-agent: b\nunknown: x\nUser-agent: c\nDisallow: /\n",
    );
    assert_eq!(robots.groups.len(), 1);
    assert_eq!(robots.groups[0].user_agents, ["a", "b", "c"]);
}

#[test]
fn percent_encoding_is_normalised() {
    let robots = Robots::parse("User-agent: *\nDisallow: /foo/bär\nDisallow: /%e2%82%ac\n");
    assert!(!robots.is_allowed("x", "/foo/b%C3%A4r"));
    assert!(!robots.is_allowed("x", "/foo/bär"));
    assert!(!robots.is_allowed("x", "/€"));
    assert!(!robots.is_allowed("x", "/%E2%82%AC"));
    assert!(Rule::new(RuleKind::Allow, "/ä").matches("/%c3%a4"));
}

#[test]
fn query_strings_and_urls() {
    let robots = Robots::parse("User-agent: *\nDisallow: /*?session=\nDisallow: /*.pdf$\n");
    assert!(!robots.is_allowed("x", "/page?session=1"));
    assert!(robots.is_allowed("x", "/page?other=1"));
    assert!(!robots.is_allowed("x", "https://example.com/doc.pdf#page=2"));
    assert!(robots.is_allowed("x", "https://example.com/doc.pdf?download"));
}

#[test]
fn crawl_delay() {
    let robots = Robots::parse(
        "User-agent: slow\nCrawl-delay: 2.5\nCrawl-delay: 9\nDisallow: /x\n\
         User-agent: *\nCrawl-delay: nonsense\n\
         User-agent: neg\nCrawl-delay: -1\n",
    );
    assert_eq!(
        robots.crawl_delay("slow"),
        Some(Duration::from_millis(2500))
    );
    assert_eq!(robots.crawl_delay("other"), None);
    assert_eq!(robots.crawl_delay("neg"), None);
}

#[test]
fn status_handling() {
    let body = b"User-agent: *\nDisallow: /x\n";
    assert!(!Robots::from_response(200, body).is_allowed("a", "/x"));
    assert!(Robots::from_response(404, body).is_allowed("a", "/x"));
    assert!(Robots::from_response(301, body).is_allowed("a", "/x"));
    assert!(!Robots::from_response(429, body).is_allowed("a", "/y"));
    assert!(!Robots::from_response(503, body).is_allowed("a", "/y"));
    assert!(!Robots::from_response(0, body).is_allowed("a", "/y"));
}

#[test]
fn content_past_the_limit_is_ignored() {
    let mut body = b"User-agent: *\n".to_vec();
    body.resize(rune_robots::MAX_ROBOTS_LEN, b'\n');
    body.extend_from_slice(b"Disallow: /\n");
    assert!(Robots::parse_bytes(&body).is_allowed("x", "/"));
}

#[test]
fn empty_and_garbage_allow_everything() {
    assert!(Robots::parse("").is_allowed("x", "/"));
    assert!(Robots::parse_bytes(b"\x00\xFF\xFE<html>").is_allowed("x", "/"));
}

#[test]
fn percent_encoded_unreserved_characters_match_their_plain_form() {
    // RFC 9309 §2.2.2: "/foo/bar/%62%61%7A" is matched as "/foo/bar/baz".
    let rule = Rule::new(RuleKind::Disallow, "/foo/bar/%62%61%7A");
    assert_eq!(rule.pattern, "/foo/bar/baz");
    assert!(rule.matches("/foo/bar/baz"));
    let robots = Robots::parse("User-agent: *\nDisallow: /%7Euser/\n");
    assert!(!robots.is_allowed("bot", "/~user/page"));
    let robots = Robots::parse("User-agent: *\nDisallow: /~user/\n");
    assert!(!robots.is_allowed("bot", "/%7euser/page"));
    // Reserved characters stay encoded, so an encoded `*` or `/` is literal.
    let rule = Rule::new(RuleKind::Disallow, "/a%2Ab%2fc");
    assert_eq!(rule.pattern, "/a%2Ab%2Fc");
    assert!(!rule.matches("/axb/c"));
    assert!(rule.matches("/a%2ab%2Fc"));
    // UTF-8 stays encoded too.
    assert_eq!(
        Rule::new(RuleKind::Allow, "/%e3%83%84").pattern,
        "/%E3%83%84"
    );
}
