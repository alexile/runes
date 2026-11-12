//! The fetching helpers over an in-memory `Fetcher` (no network).
#![cfg(feature = "fetch")]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use rune_wellknown::fetch::{FetchError, Fetcher, discover, fetch, mta_sts_origin, url_for};
use rune_wellknown::{ChangePassword, Error, Resource, Response, WellKnown};

#[derive(Debug, thiserror::Error)]
#[error("connection refused")]
struct Refused;

/// Answers from a map of URL to response; records every request.
#[derive(Default)]
struct MapFetcher {
    routes: HashMap<String, Response>,
    seen: Mutex<Vec<String>>,
}

impl MapFetcher {
    fn route(mut self, url: &str, response: Response) -> Self {
        self.routes.insert(url.to_owned(), response);
        self
    }
}

impl Fetcher for MapFetcher {
    type Error = Refused;

    fn get(&self, url: &str) -> impl Future<Output = Result<Response, Refused>> + Send {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(url.to_owned());
        }
        std::future::ready(self.routes.get(url).cloned().ok_or(Refused))
    }
}

#[tokio::test]
async fn discovers_every_resource() {
    let o = "https://example.com";
    let fetcher = MapFetcher::default()
        .route(
            &format!("{o}/.well-known/security.txt"),
            Response::new(200, include_str!("fixtures/security.txt")),
        )
        .route(
            &format!("{o}/.well-known/change-password"),
            Response::new(302, "").with_header("Location", "/account"),
        )
        .route(
            &format!("{o}/.well-known/mta-sts.txt"),
            Response::new(404, "nope"),
        )
        .route(
            &format!("{o}/.well-known/openid-configuration"),
            Response::new(200, include_str!("fixtures/openid-configuration.json")),
        )
        .route(
            &format!("{o}/.well-known/assetlinks.json"),
            Response::new(200, "not json"),
        );
    let found = discover(&fetcher, "https://example.com/", &WellKnown::ALL).await;
    assert_eq!(found.len(), WellKnown::ALL.len());
    let by_kind = |k: WellKnown| found.iter().find(|d| d.kind == k).unwrap();

    assert!(matches!(
        by_kind(WellKnown::SecurityTxt).result,
        Ok(Resource::SecurityTxt(_))
    ));
    assert!(matches!(
        by_kind(WellKnown::ChangePassword).result,
        Ok(Resource::ChangePassword(ChangePassword::Redirect { .. }))
    ));
    assert!(matches!(
        by_kind(WellKnown::MtaSts).result,
        Err(FetchError::Parse(Error::Status { status: 404 }))
    ));
    assert!(matches!(
        by_kind(WellKnown::OpenIdConfiguration).result,
        Ok(Resource::OpenIdConfiguration(_))
    ));
    assert!(matches!(
        by_kind(WellKnown::AssetLinks).result,
        Err(FetchError::Parse(Error::Json { .. }))
    ));
    let aasa = by_kind(WellKnown::AppleAppSiteAssociation);
    assert_eq!(
        aasa.url,
        "https://example.com/.well-known/apple-app-site-association"
    );
    assert!(matches!(aasa.result, Err(FetchError::Transport(Refused))));
    assert_eq!(fetcher.seen.lock().unwrap().len(), 6);
}

#[tokio::test]
async fn fetch_unknown_and_invalid_origins() {
    let fetcher = MapFetcher::default().route(
        "http://127.0.0.1:8080/.well-known/host-meta",
        Response::new(200, "<XRD/>"),
    );
    let r = fetch(&fetcher, "http://127.0.0.1:8080", "/.well-known/host-meta").await;
    assert!(matches!(r, Ok(Resource::Unknown(raw)) if raw.body == b"<XRD/>"));
    for origin in [
        "example.com",
        "ftp://example.com",
        "https://example.com/app",
        "https://u@example.com",
        "https://",
    ] {
        let r = fetch(&fetcher, origin, "/.well-known/security.txt").await;
        assert!(
            matches!(r, Err(FetchError::InvalidOrigin { .. })),
            "{origin}"
        );
    }
    assert_eq!(fetcher.seen.lock().unwrap().len(), 1);
}

#[test]
fn urls() {
    assert_eq!(
        mta_sts_origin("example.com."),
        "https://mta-sts.example.com"
    );
    assert_eq!(
        url_for(&mta_sts_origin("example.com"), "/.well-known/mta-sts.txt").as_deref(),
        Some("https://mta-sts.example.com/.well-known/mta-sts.txt")
    );
    assert_eq!(
        url_for("HTTPS://Example.com:8443", "security.txt").as_deref(),
        Some("HTTPS://Example.com:8443/security.txt")
    );
}
