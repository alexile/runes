//! Known XSS filter-evasion vectors. Stripping must leave nothing that a
//! browser would parse as markup; escaping must leave no `<` at all.

use rune_axum_sanitize::{Mode, Normalization, Sanitizer, sanitize_query, strip_html};

const VECTORS: &[&str] = &[
    "<script>alert(1)</script>",
    "<SCRIPT SRC=//evil/x.js></SCRIPT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>script>alert(1)<</script>/script>",
    "<<<b>b>>",
    "<img src=x onerror=alert(1)",
    "<img src=x onerror=alert(1)//",
    "<img alt=\">\" src=x onerror=alert(1)>",
    "<img alt='>' src=x onerror=alert(1)>",
    "<img src=`x`onerror=alert(1)>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<a href=\"jav&#x09;ascript:alert(1)\">x</a>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><![CDATA[<script>alert(1)</script>]]></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "<math><mi xlink:href=\"data:x,<script>alert(1)</script>\">",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<div style=\"background:url(javascript:alert(1))\">",
    "<style>@import 'x';</style><b>",
    "<!--<script>alert(1)//-->",
    "<!--><script>alert(1)</script>-->",
    "<!---><img src=x onerror=alert(1)>",
    "<!-- --!><img src=x onerror=alert(1)>",
    "<![CDATA[><img src=x onerror=alert(1)>]]>",
    "<?xml-stylesheet href=x?><img src=x onerror=alert(1)>",
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<xmp><img src=x onerror=alert(1)></xmp>",
    "<a/href=javascript:alert(1)>x",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
    "<embed src=javascript:alert(1)>",
    "<form><button formaction=javascript:alert(1)>x",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<scr\0ipt>alert(1)</scr\0ipt>",
    "<\0script>alert(1)</script>",
    "<script\x0c>alert(1)</script>",
    "<\u{0}img src=x onerror=alert(1)>",
    "<img\nsrc=x\nonerror=alert(1)>",
    "<a href=x\u{202E}>x</a>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<</p>script>alert(1)",
    "<a\u{200B}href=x>y</a>",
    "<",
    "</",
    "<!",
    "<!-",
    "<!--",
    "<a",
    "<a b='",
    "<script>",
    "</script",
];

/// Lookalikes NFKC folds into ASCII markup characters.
const LOOKALIKES: &[&str] = &[
    "＜script＞alert(1)＜/script＞",
    "﹤img src=x onerror=alert(1)﹥",
    "＜svg／onload=alert(1)＞",
];

fn has_markup(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(2).any(|pair| {
        pair[0] == b'<' && (pair[1].is_ascii_alphabetic() || matches!(pair[1], b'/' | b'!' | b'?'))
    })
}

#[test]
fn strip_leaves_no_markup() {
    for vector in VECTORS {
        let out = strip_html(vector);
        assert!(!has_markup(&out), "{vector:?} -> {out:?}");
        assert_eq!(strip_html(&out), out, "not idempotent for {vector:?}");
    }
}

#[test]
fn strip_drops_script_bodies() {
    assert_eq!(strip_html("<script>alert(1)</script>"), "");
    assert_eq!(strip_html("<svg><script>alert(1)</script></svg>"), "");
    assert_eq!(
        strip_html("<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>"),
        ""
    );
}

#[test]
fn sanitizer_with_controls_and_invisibles() {
    let sanitizer = Sanitizer::new().strip_invisible(true);
    for vector in VECTORS {
        let out = sanitizer.clean(vector);
        assert!(!has_markup(&out), "{vector:?} -> {out:?}");
        assert!(!out.contains('\0'));
    }
}

#[test]
fn escape_leaves_no_angle_brackets() {
    let sanitizer = Sanitizer::new().mode(Mode::Escape);
    for vector in VECTORS.iter().chain(LOOKALIKES) {
        let out = sanitizer.clean(vector);
        assert!(
            !out.contains(['<', '>', '"', '\'']),
            "{vector:?} -> {out:?}"
        );
    }
}

#[test]
fn nfkc_catches_lookalikes() {
    let sanitizer = Sanitizer::new().normalization(Some(Normalization::Nfkc));
    for vector in LOOKALIKES {
        let out = sanitizer.clean(vector);
        assert!(!has_markup(&out), "{vector:?} -> {out:?}");
    }
    let escape = sanitizer.mode(Mode::Escape);
    assert_eq!(escape.clean("＜b＞"), "&lt;b&gt;");
}

#[test]
fn entities_are_not_decoded() {
    // Entity-encoded markup is text. It stays harmless unless something
    // downstream decodes it and renders the result as HTML.
    assert_eq!(
        strip_html("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    );
    let escape = Sanitizer::new().mode(Mode::Escape);
    assert_eq!(escape.clean("&lt;script&gt;"), "&amp;lt;script&amp;gt;");
}

#[test]
fn query_vectors_are_decoded_before_cleaning() {
    for vector in VECTORS {
        let encoded: String = form_urlencoded::byte_serialize(vector.as_bytes()).collect();
        let out = sanitize_query(&format!("q={encoded}"));
        for (_, value) in form_urlencoded::parse(out.as_bytes()) {
            assert!(!has_markup(&value), "{vector:?} -> {value:?}");
        }
    }
}

/// The tags in ammonia's output. Text `<` is always entity-encoded there, so
/// every literal `<` opens a tag.
#[cfg(feature = "allowlist")]
fn tags(html: &str) -> Vec<String> {
    html.split('<')
        .skip(1)
        .map(|rest| rest.split('>').next().unwrap_or_default().to_lowercase())
        .collect()
}

#[cfg(feature = "allowlist")]
#[test]
fn allowlist_removes_active_content() {
    let sanitizer = Sanitizer::new().mode(Mode::allowlist());
    for vector in VECTORS.iter().chain(LOOKALIKES) {
        let out = sanitizer.clean(vector);
        for tag in tags(&out) {
            let name = tag
                .trim_start_matches('/')
                .split([' ', '/'])
                .next()
                .unwrap_or_default();
            assert!(
                ![
                    "script", "style", "iframe", "svg", "math", "object", "embed", "form",
                    "button", "input", "body"
                ]
                .contains(&name),
                "{vector:?} -> {out:?}"
            );
            let has_handler = tag
                .split_whitespace()
                .skip(1)
                .any(|attribute| attribute.starts_with("on"));
            assert!(
                !has_handler && !tag.contains("javascript:"),
                "{vector:?} -> {out:?}"
            );
        }
    }
    assert_eq!(
        sanitizer.clean("<b>bold</b> <i>it</i>"),
        "<b>bold</b> <i>it</i>"
    );
}
