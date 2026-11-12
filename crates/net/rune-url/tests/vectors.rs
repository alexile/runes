//! Table-driven known-answer tests from RFC 3986 and the WHATWG URL
//! Standard's test data (`urltestdata.json`).

use rune_url::{Options, Url, canonicalize, resolve};

/// RFC 3986 §5.4.1 (normal) and §5.4.2 (abnormal) reference resolution
/// against `http://a/b/c/d;p?q`. Where the WHATWG standard deliberately
/// differs, the WHATWG result is used and the RFC one noted.
const RFC3986_RESOLUTION: &[(&str, &str)] = &[
    // §5.4.1
    ("g", "http://a/b/c/g"),
    ("./g", "http://a/b/c/g"),
    ("g/", "http://a/b/c/g/"),
    ("/g", "http://a/g"),
    ("//g", "http://g/"), // RFC: "http://g" (WHATWG adds the empty path's "/")
    ("?y", "http://a/b/c/d;p?y"),
    ("g?y", "http://a/b/c/g?y"),
    ("#s", "http://a/b/c/d;p?q#s"),
    ("g#s", "http://a/b/c/g#s"),
    ("g?y#s", "http://a/b/c/g?y#s"),
    (";x", "http://a/b/c/;x"),
    ("g;x", "http://a/b/c/g;x"),
    ("g;x?y#s", "http://a/b/c/g;x?y#s"),
    ("", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/"),
    ("./", "http://a/b/c/"),
    ("..", "http://a/b/"),
    ("../", "http://a/b/"),
    ("../g", "http://a/b/g"),
    ("../..", "http://a/"),
    ("../../", "http://a/"),
    ("../../g", "http://a/g"),
    // §5.4.2
    ("../../../g", "http://a/g"),
    ("../../../../g", "http://a/g"),
    ("/./g", "http://a/g"),
    ("/../g", "http://a/g"),
    ("g.", "http://a/b/c/g."),
    (".g", "http://a/b/c/.g"),
    ("g..", "http://a/b/c/g.."),
    ("..g", "http://a/b/c/..g"),
    ("./../g", "http://a/b/g"),
    ("./g/.", "http://a/b/c/g/"),
    ("g/./h", "http://a/b/c/g/h"),
    ("g/../h", "http://a/b/c/h"),
    ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
    ("g;x=1/../y", "http://a/b/c/y"),
    ("g?y/./x", "http://a/b/c/g?y/./x"),
    ("g?y/../x", "http://a/b/c/g?y/../x"),
    ("g#s/./x", "http://a/b/c/g#s/./x"),
    ("g#s/../x", "http://a/b/c/g#s/../x"),
    ("http:g", "http://a/b/c/g"), // the "for backward compatibility" reading
];

#[test]
fn rfc3986_reference_resolution() {
    let base = Url::parse("http://a/b/c/d;p?q").unwrap();
    for (reference, expected) in RFC3986_RESOLUTION {
        let got = resolve(&base, reference, &Options::default()).unwrap();
        assert_eq!(got.as_str(), *expected, "reference {reference:?}");
    }
}

/// RFC 3986 §6.2 equivalence examples: every input in a row has the same
/// canonical form.
const RFC3986_EQUIVALENT: &[(&[&str], &str)] = &[
    // §6.1 and §6.2.2
    (
        &[
            "example://a/b/c/%7Bfoo%7D",
            "eXAMPLE://a/./b/../b/%63/%7bfoo%7d",
        ],
        "example://a/b/c/%7Bfoo%7D",
    ),
    // §6.2.2.1 case normalization
    (
        &["HTTP://www.EXAMPLE.com/", "http://www.example.com/"],
        "http://www.example.com/",
    ),
    (&["http://h/%3a", "http://h/%3A"], "http://h/%3A"),
    // §6.2.2.2 percent-encoding normalization
    (
        &[
            "http://h/%7Esmith/",
            "http://h/~smith/",
            "http://h/%7esmith/",
        ],
        "http://h/~smith/",
    ),
    (&["http://h/%41%2D%5F%2e"], "http://h/A-_."),
    // §6.2.2.3 path segment normalization
    (&["http://h/a/b/c/./../../g"], "http://h/a/g"),
    (&["http://h/mid/content=5/../6"], "http://h/mid/6"),
    // §6.2.3 scheme-based normalization
    (
        &[
            "http://example.com",
            "http://example.com/",
            "http://example.com:/",
            "http://example.com:80/",
        ],
        "http://example.com/",
    ),
];

#[test]
fn rfc3986_equivalence() {
    for (inputs, expected) in RFC3986_EQUIVALENT {
        for input in *inputs {
            let got = canonicalize(input, &Options::default()).unwrap();
            assert_eq!(got.as_str(), *expected, "input {input:?}");
        }
    }
}

/// Cases from the WHATWG URL Standard's `urltestdata.json` (input with no
/// base, and the expected `href`), followed by this crate's
/// percent-encoding normalization where it applies.
const WHATWG: &[(&str, &str)] = &[
    ("http://example.com/foo/../bar", "http://example.com/bar"),
    (
        "http://example.com/foo/%2e%2E/bar",
        "http://example.com/bar",
    ),
    ("http://example.com/foo/%2e", "http://example.com/foo/"),
    ("http://example.com/foo/./", "http://example.com/foo/"),
    ("http://example.com////../..", "http://example.com//"),
    (
        "http://example.com/foo/bar//../..",
        "http://example.com/foo/",
    ),
    ("http://example.com/foo\\bar", "http://example.com/foo/bar"),
    ("http://ExAmPlE.CoM", "http://example.com/"),
    ("http://example.com:0080/", "http://example.com/"),
    ("https://example.com:443/", "https://example.com/"),
    ("ws://example.com:80/", "ws://example.com/"),
    ("http://example.com:8080/", "http://example.com:8080/"),
    ("http://0x7f.1/", "http://127.0.0.1/"),
    ("http://0300.0250.0.1/", "http://192.168.0.1/"),
    ("http://4294967295/", "http://255.255.255.255/"),
    ("http://[0:0:0:0:0:0:0:1]/", "http://[::1]/"),
    ("http://[::127.0.0.1]/", "http://[::7f00:1]/"),
    ("http://[2001:DB8::0:1]/", "http://[2001:db8::1]/"),
    ("http://münchen.de/", "http://xn--mnchen-3ya.de/"),
    ("http://EXAMPLE.com/%7Efoo", "http://example.com/~foo"),
    ("http://example.com/a b", "http://example.com/a%20b"),
    ("http://example.com/\u{e9}", "http://example.com/%C3%A9"),
    ("http://example.com/%c3%a9", "http://example.com/%C3%A9"),
    ("http://example.com/?q=a b", "http://example.com/?q=a%20b"),
    ("http://example.com/#a b", "http://example.com/#a%20b"),
    (
        "http://user:pass@example.com/",
        "http://user:pass@example.com/",
    ),
    ("http://:@example.com/", "http://example.com/"),
    ("http://example.com/?", "http://example.com/?"),
    ("http://example.com/#", "http://example.com/#"),
    ("HTTP:example.com", "http://example.com/"),
    ("file:///C:/a/../b", "file:///C:/b"),
    ("non-special://H/a/../b", "non-special://h/b"),
    ("data:text/html,%3Cp%3E", "data:text/html,%3Cp%3E"),
    ("javascript:alert(1)", "javascript:alert(1)"),
];

#[test]
fn whatwg_parsing_and_normalization() {
    for (input, expected) in WHATWG {
        let got = canonicalize(input, &Options::default()).unwrap();
        assert_eq!(got.as_str(), *expected, "input {input:?}");
    }
}

/// WHATWG `urltestdata.json` inputs that are failures.
const WHATWG_FAILURES: &[&str] = &[
    "http://",
    "http://[::1",
    "http://a b/",
    "http://example.com:65536/",
    "http://1.2.3.4.5/",
    "http://0x100000000/",
    "//relative",
    "",
];

#[test]
fn whatwg_failures() {
    for input in WHATWG_FAILURES {
        assert!(
            canonicalize(input, &Options::default()).is_err(),
            "{input:?}"
        );
    }
}
