//! Preload eligibility against the published submission requirements, and
//! membership lookups against caller-supplied lists (no network).

use rune_finding::Location;
use rune_hsts::{
    Error, HttpBehavior, PRELOAD_MIN_MAX_AGE, PreloadEntry, PreloadIssueKind, PreloadList, Site,
    check_preload,
};

const GOOD: &str = "max-age=63072000; includeSubDomains; preload";

fn kinds(site: &Site) -> Vec<PreloadIssueKind> {
    check_preload(site)
        .issues
        .into_iter()
        .map(|i| i.kind)
        .collect()
}

#[test]
fn eligible_site() {
    for http in [
        HttpBehavior::NotListening,
        HttpBehavior::Redirect {
            location: "https://EXAMPLE.com:443/".into(),
        },
    ] {
        let site = Site::new("Example.COM.")
            .with_https_header(GOOD)
            .with_http(http);
        let e = check_preload(&site);
        assert!(e.is_eligible(), "{:?}", e.issues);
        assert_eq!(e.domain, "example.com");
        assert_eq!(e.hsts.map(|h| h.max_age), Some(63_072_000));
    }
}

#[test]
fn exactly_one_year_is_enough() {
    let site = Site::new("example.com").with_https_header(format!(
        "max-age={PRELOAD_MIN_MAX_AGE}; includeSubDomains; preload"
    ));
    assert!(check_preload(&site).is_eligible());
    let site = Site::new("example.com").with_https_header(format!(
        "max-age={}; includeSubDomains; preload",
        PRELOAD_MIN_MAX_AGE - 1
    ));
    assert_eq!(kinds(&site), [PreloadIssueKind::MaxAgeTooLow]);
}

#[test]
fn header_requirements() {
    assert_eq!(
        kinds(&Site::new("example.com")),
        [PreloadIssueKind::MissingHeader]
    );
    assert_eq!(
        kinds(&Site::new("example.com").with_https_header("includeSubDomains; preload")),
        [PreloadIssueKind::InvalidHeader]
    );
    assert_eq!(
        kinds(&Site::new("example.com").with_https_header("max-age=31536000")),
        [
            PreloadIssueKind::MissingIncludeSubdomains,
            PreloadIssueKind::MissingPreload
        ]
    );
    // A valued preload token is not consent.
    assert_eq!(
        kinds(
            &Site::new("example.com")
                .with_https_header("max-age=31536000; includeSubDomains; preload=true")
        ),
        [PreloadIssueKind::MissingPreload]
    );
}

#[test]
fn redirect_requirements() {
    let site = |http| {
        Site::new("example.com")
            .with_https_header(GOOD)
            .with_http(http)
    };
    assert_eq!(
        kinds(&site(HttpBehavior::NoRedirect)),
        [PreloadIssueKind::NoHttpRedirect]
    );
    assert_eq!(
        kinds(&site(HttpBehavior::Redirect {
            location: "http://example.com/login".into()
        })),
        [PreloadIssueKind::RedirectNotHttps]
    );
    assert_eq!(
        kinds(&site(HttpBehavior::Redirect {
            location: "/secure".into()
        })),
        [PreloadIssueKind::RedirectNotHttps]
    );
    assert_eq!(
        kinds(&site(HttpBehavior::Redirect {
            location: "https://www.example.com/".into()
        })),
        [PreloadIssueKind::RedirectToOtherHost]
    );
}

#[test]
fn domain_requirements() {
    let site = |d: &str| Site::new(d).with_https_header(GOOD);
    assert_eq!(kinds(&site("localhost")), [PreloadIssueKind::InvalidDomain]);
    assert_eq!(kinds(&site("10.0.0.1")), [PreloadIssueKind::InvalidDomain]);
    assert_eq!(
        kinds(&site("exa_mple.com")),
        [PreloadIssueKind::InvalidDomain]
    );
}

#[cfg(feature = "psl")]
#[test]
fn registrable_domain_requirement() {
    let site = |d: &str| Site::new(d).with_https_header(GOOD);
    assert!(check_preload(&site("example.co.uk")).is_eligible());
    assert_eq!(
        kinds(&site("www.example.com")),
        [PreloadIssueKind::NotRegistrableDomain]
    );
    assert_eq!(
        kinds(&site("co.uk")),
        [PreloadIssueKind::NotRegistrableDomain]
    );
    let e = check_preload(&site("www.example.com"));
    assert!(e.issues[0].message.contains("example.com"));
}

#[test]
fn every_issue_is_reported_and_mapped() {
    let site = Site::new("example.com")
        .with_https_header("max-age=10")
        .with_http(HttpBehavior::NoRedirect);
    let e = check_preload(&site);
    assert_eq!(e.issues.len(), 4);
    let findings = e.to_findings::<()>(&Location::url("https://example.com/"));
    let ids: Vec<_> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "hsts.preload_max_age_too_low",
            "hsts.preload_missing_include_subdomains",
            "hsts.preload_missing_preload",
            "hsts.preload_no_http_redirect",
        ]
    );
}

#[test]
fn plain_list_membership() {
    let list = PreloadList::parse(
        "# snapshot\n\
         \n\
         example.com include_subdomains\n\
         // other comment style\n\
         www.example.org\n\
         dev includeSubDomains\n\
         Shop.Example.NET.\n",
    )
    .unwrap();
    assert_eq!(list.len(), 4);
    assert!(list.is_preloaded("example.com"));
    assert!(list.is_preloaded("a.b.EXAMPLE.com."));
    assert!(list.is_preloaded("www.example.org"));
    assert!(!list.is_preloaded("example.org"));
    assert!(!list.is_preloaded("api.www.example.org"));
    assert!(list.is_preloaded("anything.dev"));
    assert!(list.is_preloaded("shop.example.net"));
    assert!(!list.is_preloaded("example.net"));
    let m = list.lookup("x.example.com").unwrap();
    assert!(!m.exact);
    assert_eq!(m.entry.name, "example.com");
    assert!(list.lookup("example.com").unwrap().exact);
}

#[test]
fn most_specific_entry_decides() {
    let mut list = PreloadList::new();
    list.insert(PreloadEntry::new("example.com", true));
    list.insert(PreloadEntry::new("a.example.com", false));
    // a.example.com's own entry decides for itself...
    assert_eq!(
        list.lookup("a.example.com").unwrap().entry.name,
        "a.example.com"
    );
    // ...but does not cover its children, so the parent's does.
    assert_eq!(
        list.lookup("b.a.example.com").unwrap().entry.name,
        "example.com"
    );
}

#[test]
fn plain_list_errors() {
    assert!(matches!(
        PreloadList::parse("ok.com\nbad..com\n"),
        Err(Error::InvalidList { line: 2, .. })
    ));
    assert!(matches!(
        PreloadList::parse("ok.com force"),
        Err(Error::InvalidList { line: 1, .. })
    ));
}

#[cfg(feature = "chromium")]
#[test]
fn chromium_json_membership() {
    // Shape of Chromium's net/http/transport_security_state_static.json.
    let json = r#"// Copyright header
// with several comment lines.
{
  "pinsets": [
    { "name": "test", "static_spki_hashes": ["TestSPKI"] }
  ],
  "entries": [
    // Comment inside the array.
    { "name": "example.com", "policy": "custom", "mode": "force-https", "include_subdomains": true },
    { "name": "pinned.example", "policy": "custom", "pins": "test" },
    { "name": "app", "policy": "public-suffix", "mode": "force-https", "include_subdomains": true },
    { "name": "www.example.org", "policy": "bulk-18-weeks", "mode": "force-https" }
  ]
}
"#;
    let list = PreloadList::from_chromium_json(json).unwrap();
    assert_eq!(list.len(), 4);
    assert!(list.is_preloaded("deep.sub.example.com"));
    assert!(list.is_preloaded("my.app"));
    assert!(list.is_preloaded("www.example.org"));
    assert!(!list.is_preloaded("example.org"));
    // Listed for pinning only: matched but not HSTS.
    let m = list.lookup("pinned.example").unwrap();
    assert!(!m.is_hsts());
    assert!(!list.is_preloaded("pinned.example"));

    assert!(matches!(
        PreloadList::from_chromium_json("{ \"entries\": [ { \"nam\": 1 } ] }"),
        Err(Error::InvalidList { .. })
    ));
    assert!(matches!(
        PreloadList::from_chromium_json("{\"entries\": [{\"name\": \"a b\"}]}"),
        Err(Error::InvalidList { .. })
    ));
}
