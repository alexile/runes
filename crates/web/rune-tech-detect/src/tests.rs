//! End-to-end tests over small hand-written fixtures.

use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};

use crate::*;

fn exchange(url: &str, response: HttpResponse) -> HttpExchange {
    HttpExchange::new(ExchangeId(1), "test", HttpRequest::get(url)).with_response(response)
}

fn names(found: &[Detection]) -> Vec<&str> {
    found.iter().map(|d| d.name.as_str()).collect()
}

#[test]
fn builtin_rules_load_and_compile_strictly() {
    let rules = builtin_ruleset();
    assert_eq!(rules.technologies.len(), 18);
    assert_eq!(rules.categories.len(), 11);
    let detector = Detector::strict(&rules).unwrap();
    assert_eq!(detector.len(), 18);
    assert_eq!(Detector::builtin().skipped().len(), 0);
    // Every category id resolves and every implied technology exists.
    for technology in &rules.technologies {
        assert!(
            technology
                .categories
                .iter()
                .all(|id| rules.categories.contains_key(id))
        );
        for implied in &technology.implies {
            assert!(rules.get(&implied.name).is_some(), "{}", implied.name);
        }
    }
}

#[test]
fn wordpress_stack() {
    let page = exchange(
        "https://blog.example.test/",
        HttpResponse::new(200)
            .with_header("Server", "Apache/2.4.58 (Debian)")
            .with_header("X-Powered-By", "PHP/8.2.12")
            .with_header(
                "Link",
                "<https://blog.example.test/wp-json/>; rel=\"https://api.w.org/\"",
            )
            .with_body(
                "<html><head><meta name=\"generator\" content=\"WordPress 6.4.2\" />\
                 <link rel='stylesheet' href='/wp-content/themes/t/style.css' />\
                 <script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>\
                 <script src='https://cdn.example.test/jquery-3.7.1.min.js'></script>\
                 </head></html>",
            ),
    );
    let found = Detector::builtin().detect_exchange(&page);
    assert_eq!(
        names(&found),
        ["Apache HTTP Server", "PHP", "WordPress", "jQuery", "MySQL"]
    );
    let get = |name: &str| found.iter().find(|d| d.name == name).unwrap();
    assert_eq!(get("WordPress").version.as_deref(), Some("6.4.2"));
    assert_eq!(get("PHP").version.as_deref(), Some("8.2.12"));
    assert_eq!(get("Apache HTTP Server").version.as_deref(), Some("2.4.58"));
    assert_eq!(get("jQuery").version.as_deref(), Some("3.7.1"));
    assert_eq!(get("MySQL").confidence, 50);
    assert_eq!(get("WordPress").categories, ["CMS"]);
    let sources: Vec<Source> = get("WordPress").evidence.iter().map(|e| e.source).collect();
    assert_eq!(
        sources,
        [
            Source::Header,
            Source::Meta,
            Source::Html,
            Source::ScriptSrc
        ]
    );
    assert!(
        get("PHP")
            .evidence
            .iter()
            .any(|e| e.source == Source::Implied && e.key.as_deref() == Some("WordPress"))
    );
}

#[test]
fn cookies_and_transitive_implies() {
    let page = Page::new("https://app.example.test/")
        .with_header("Set-Cookie", "laravel_session=x; HttpOnly")
        .with_header("X-Powered-By", "Next.js 14.1.0");
    let found = Detector::builtin().detect(&page);
    assert_eq!(
        names(&found),
        ["Laravel", "Next.js", "Node.js", "PHP", "React"]
    );
}

#[test]
fn confidence_sums_and_caps() {
    let page = Page::new("https://h.test/").with_html("<script src=/js/jquery.js></script>");
    let found = Detector::builtin().detect(&page);
    assert_eq!(found[0].name, "jQuery");
    assert_eq!(found[0].confidence, 50);
    assert_eq!(found[0].version, None);
    let page = page.with_html("<script src=/jquery.js></script><script src=/jquery-1.12.4.js>");
    let found = Detector::builtin().detect(&page);
    assert_eq!(found[0].confidence, 100);
    assert_eq!(found[0].version.as_deref(), Some("1.12.4"));
}

#[test]
fn favicon_requires_and_excludes() {
    let rules = Ruleset::from_wappalyzer_json(&format!(
        r#"{{
          "Panel": {{ "favicon": [{}] }},
          "Plugin": {{ "html": "plugin", "requires": "Panel" }},
          "Legacy": {{ "html": "plugin" }},
          "Modern": {{ "html": "plugin", "excludes": "Legacy" }}
        }}"#,
        rune_favicon_hash::favicon_hash(b"\x00icon")
    ))
    .unwrap();
    let detector = Detector::strict(&rules).unwrap();
    let page = Page::new("u").with_html("plugin");
    assert_eq!(names(&detector.detect(&page)), ["Modern"]);
    let page = page.with_favicon(b"\x00icon");
    let found = detector.detect(&page);
    assert_eq!(names(&found), ["Modern", "Panel", "Plugin"]);
    assert_eq!(found[1].evidence[0].source, Source::Favicon);
}

#[test]
fn lenient_and_strict_compilation() {
    let rules = Ruleset::from_wappalyzer_json(
        r#"{ "JS-only": { "html": ["(?<!x)y", "plain"], "headers": {"X": "(?=a)"} } }"#,
    )
    .unwrap();
    let detector = Detector::new(&rules);
    assert_eq!(detector.skipped().len(), 2);
    assert_eq!(detector.skipped()[0].technology, "JS-only");
    assert_eq!(
        names(&detector.detect(&Page::new("u").with_html("plain"))),
        ["JS-only"]
    );
    let error = Detector::strict(&rules).unwrap_err();
    assert_eq!(error.code(), "invalid_pattern");
}

#[test]
fn url_patterns_and_unknown_categories() {
    let mut rules = Ruleset::new();
    let mut technology = Technology::new("Php page");
    technology.url.push(Pattern::new(r"\.php$"));
    technology.categories.push(99);
    technology
        .implies
        .push(Implied::parse("Outside\\;confidence:40"));
    rules.insert(technology);
    let found = Detector::strict(&rules)
        .unwrap()
        .detect(&Page::new("https://h.test/index.php"));
    assert_eq!(found[0].categories, ["#99"]);
    assert_eq!(found[1].name, "Outside");
    assert_eq!(found[1].confidence, 40);
    assert_eq!(
        Detector::strict(&rules)
            .unwrap()
            .detect(&Page::new("https://h.test/")),
        []
    );
    assert_eq!(Source::ScriptSrc.to_string(), "script_src");
}
