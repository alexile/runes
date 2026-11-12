//! Every supported resource parsed from a realistic fixture, served as an
//! HTTP response, plus an unknown resource returned raw.

use rune_wellknown::rune_securitytxt::{self, Options, Timestamp};
use rune_wellknown::{
    AssetTarget, ChangePassword, HANDLE_ALL_URLS, Mode, Resource, Response, WellKnown, parse,
};

fn ok(body: &str, media_type: &str) -> Response {
    Response::new(200, body).with_header("Content-Type", media_type)
}

fn get(kind: WellKnown, body: &str, media_type: &str) -> Resource {
    let resource =
        parse(&kind.path(), &ok(body, media_type)).unwrap_or_else(|e| unreachable!("{kind}: {e}"));
    assert_eq!(resource.kind(), Some(kind));
    resource
}

#[test]
fn security_txt() {
    let Resource::SecurityTxt(doc) = get(
        WellKnown::SecurityTxt,
        include_str!("fixtures/security.txt"),
        "text/plain; charset=utf-8",
    ) else {
        unreachable!()
    };
    assert!(doc.is_signed());
    assert_eq!(doc.contacts()[0], "mailto:security@example.com");
    let options = Options::default()
        .with_now(Timestamp::parse("2026-11-11T00:00:00Z").unwrap())
        .with_retrieved_from("https://example.com/.well-known/security.txt");
    assert_eq!(rune_securitytxt::analyze(&doc, &options), []);
}

#[test]
fn mta_sts() {
    let Resource::MtaSts(policy) = get(
        WellKnown::MtaSts,
        include_str!("fixtures/mta-sts.txt"),
        "text/plain",
    ) else {
        unreachable!()
    };
    assert_eq!(policy.mode, Mode::Enforce);
    assert_eq!(policy.max_age, 604_800);
    assert!(policy.matches_mx("mx1.example.net"));
}

#[test]
fn openid_configuration() {
    let Resource::OpenIdConfiguration(config) = get(
        WellKnown::OpenIdConfiguration,
        include_str!("fixtures/openid-configuration.json"),
        "application/json",
    ) else {
        unreachable!()
    };
    assert!(config.issuer_matches("https://accounts.example.com"));
    assert_eq!(config.missing_required(), Vec::<&str>::new());
    assert_eq!(config.insecure_endpoints(), []);
    assert!(config.other.contains_key("device_authorization_endpoint"));
    assert_eq!(
        config.code_challenge_methods_supported.as_deref(),
        Some(&["plain".to_owned(), "S256".to_owned()][..])
    );
}

#[test]
fn asset_links() {
    let Resource::AssetLinks(links) = get(
        WellKnown::AssetLinks,
        include_str!("fixtures/assetlinks.json"),
        "application/json",
    ) else {
        unreachable!()
    };
    assert_eq!(links.statements.len(), 2);
    let apps = links.android_apps(HANDLE_ALL_URLS);
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].0, "com.example.android");
    assert_eq!(apps[0].1.len(), 1);
    assert!(matches!(
        &links.statements[1].target,
        AssetTarget::Web { site } if site == "https://login.example.com"
    ));
}

#[test]
fn apple_app_site_association() {
    let body = include_str!("fixtures/apple-app-site-association");
    let Resource::AppleAppSiteAssociation(aasa) =
        get(WellKnown::AppleAppSiteAssociation, body, "application/json")
    else {
        unreachable!()
    };
    let details = &aasa.applinks.as_ref().unwrap().details;
    assert_eq!(details[0].components.len(), 4);
    assert!(details[0].components[0].exclude);
    assert_eq!(
        details[0].components[0].fragment.as_deref(),
        Some("no_universal_links")
    );
    assert_eq!(aasa.app_ids().len(), 3);
    // The legacy root location parses the same way.
    assert_eq!(
        parse("/apple-app-site-association", &ok(body, "application/json")).unwrap(),
        Resource::AppleAppSiteAssociation(aasa)
    );
}

#[test]
fn change_password() {
    let redirect =
        Response::new(303, "").with_header("location", " https://example.com/me/password ");
    assert_eq!(
        parse("/.well-known/change-password", &redirect).unwrap(),
        Resource::ChangePassword(ChangePassword::Redirect {
            status: 303,
            location: "https://example.com/me/password".to_owned(),
        })
    );
    assert_eq!(
        parse("/.well-known/change-password", &Response::new(404, "")).unwrap(),
        Resource::ChangePassword(ChangePassword::Unsupported { status: 404 })
    );
}

#[test]
fn unknown_resources_are_raw() {
    let body = include_str!("fixtures/nodeinfo");
    for status in [200, 404] {
        let Resource::Unknown(raw) = parse(
            "/.well-known/nodeinfo",
            &Response::new(status, body).with_header("Content-Type", "application/json"),
        )
        .unwrap() else {
            unreachable!()
        };
        assert_eq!(raw.path, "/.well-known/nodeinfo");
        assert_eq!(raw.status, status);
        assert_eq!(raw.media_type.as_deref(), Some("application/json"));
        assert_eq!(raw.body, body.as_bytes());
    }
}
