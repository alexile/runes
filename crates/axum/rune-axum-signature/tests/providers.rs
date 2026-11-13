//! Provider presets: published example vectors, tampering, timestamps,
//! replay and rotation, through both the pure API and the layer.
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use axum::body::{Body, Bytes};
use axum::{Router, routing::post};
use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use rune_axum_signature::{
    HmacConfig, HmacLayer, MemoryReplayStore, Provider, Secret, VerifiedWebhook, VerifyError,
    WebhookLayer, WebhookVerifier,
};
use sha2::Sha256;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

fn hmac256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(*k, HeaderValue::from_str(v).unwrap());
    }
    map
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ---- Standard Webhooks / Svix --------------------------------------------

// Example from the Svix docs (docs.svix.com, "Verifying webhooks manually").
const SVIX_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const SVIX_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const SVIX_TS: i64 = 1_614_265_330;
const SVIX_BODY: &[u8] = br#"{"test": 2432232314}"#;
const SVIX_SIG: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

fn svix_headers(sig: &str) -> HeaderMap {
    headers(&[
        ("webhook-id", SVIX_ID),
        ("webhook-timestamp", &SVIX_TS.to_string()),
        ("webhook-signature", sig),
    ])
}

#[test]
fn standard_webhooks_official_vector() {
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    let hook = v
        .verify_at(&svix_headers(SVIX_SIG), SVIX_BODY, SVIX_TS)
        .unwrap();
    assert_eq!(hook.id(), Some(SVIX_ID));
    assert_eq!(hook.timestamp(), Some(SVIX_TS));
    assert_eq!(hook.provider(), Provider::StandardWebhooks);
    assert_eq!(hook.body().as_ref(), SVIX_BODY);
}

#[test]
fn svix_header_names_are_accepted() {
    let v = WebhookVerifier::svix(SVIX_SECRET).unwrap();
    let h = headers(&[
        ("svix-id", SVIX_ID),
        ("svix-timestamp", &SVIX_TS.to_string()),
        ("svix-signature", SVIX_SIG),
    ]);
    assert!(v.verify_at(&h, SVIX_BODY, SVIX_TS).is_ok());
}

#[test]
fn standard_webhooks_multiple_signatures_and_versions() {
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    let sig = format!("v1a,abcd v1,bm9wZQ== {SVIX_SIG}");
    assert!(v.verify_at(&svix_headers(&sig), SVIX_BODY, SVIX_TS).is_ok());
    // A v1a (asymmetric) entry carrying the right bytes is not accepted as v1.
    let wrong_version = SVIX_SIG.replace("v1,", "v2,");
    assert_eq!(
        v.verify_at(&svix_headers(&wrong_version), SVIX_BODY, SVIX_TS)
            .unwrap_err(),
        VerifyError::SignatureMismatch
    );
}

#[test]
fn standard_webhooks_tampered_body_and_id() {
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    let err = v
        .verify_at(
            &svix_headers(SVIX_SIG),
            &br#"{"test": 2432232315}"#[..],
            SVIX_TS,
        )
        .unwrap_err();
    assert_eq!(err, VerifyError::SignatureMismatch);

    let mut h = svix_headers(SVIX_SIG);
    h.insert("webhook-id", HeaderValue::from_static("msg_other"));
    assert!(v.verify_at(&h, SVIX_BODY, SVIX_TS).is_err());
}

#[test]
fn standard_webhooks_timestamp_tolerance() {
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    let h = svix_headers(SVIX_SIG);
    assert!(v.verify_at(&h, SVIX_BODY, SVIX_TS + 300).is_ok());
    assert!(v.verify_at(&h, SVIX_BODY, SVIX_TS - 300).is_ok());
    assert_eq!(
        v.verify_at(&h, SVIX_BODY, SVIX_TS + 301).unwrap_err(),
        VerifyError::TimestampOutOfTolerance
    );
    assert_eq!(
        v.verify_at(&h, SVIX_BODY, SVIX_TS - 301).unwrap_err(),
        VerifyError::TimestampOutOfTolerance
    );
    let strict = v.tolerance(Duration::from_secs(10));
    assert!(strict.verify_at(&h, SVIX_BODY, SVIX_TS + 11).is_err());
}

#[test]
fn standard_webhooks_rotation() {
    let other = "whsec_dGhpcyBpcyBhIGRpZmZlcmVudCBrZXk=";
    let only_new = WebhookVerifier::standard_webhooks(other).unwrap();
    assert!(
        only_new
            .verify_at(&svix_headers(SVIX_SIG), SVIX_BODY, SVIX_TS)
            .is_err()
    );
    let both = only_new.with_secret(Secret::from_whsec(SVIX_SECRET).unwrap());
    assert!(
        both.verify_at(&svix_headers(SVIX_SIG), SVIX_BODY, SVIX_TS)
            .is_ok()
    );
}

#[test]
fn standard_webhooks_missing_and_bad_headers() {
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    assert_eq!(
        v.verify_at(&HeaderMap::new(), SVIX_BODY, SVIX_TS)
            .unwrap_err(),
        VerifyError::MissingHeader("svix-id".into())
    );
    let mut h = svix_headers(SVIX_SIG);
    h.insert("webhook-timestamp", HeaderValue::from_static("soon"));
    assert_eq!(
        v.verify_at(&h, SVIX_BODY, SVIX_TS).unwrap_err(),
        VerifyError::MalformedHeader("webhook-timestamp".into())
    );
}

#[tokio::test]
async fn standard_webhooks_replay_is_rejected() {
    let ts = now().to_string();
    let body = br#"{"type":"invoice.paid"}"#;
    let mut signed = b"msg_1.".to_vec();
    signed.extend_from_slice(ts.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);
    let key = rune_base64::decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    let sig = format!("v1,{}", rune_base64::encode(&hmac256(&key, &signed)));
    let h = headers(&[
        ("webhook-id", "msg_1"),
        ("webhook-timestamp", &ts),
        ("webhook-signature", &sig),
    ]);

    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    assert!(v.verify_and_record(&h, &body[..]).await.is_ok());
    assert_eq!(
        v.verify_and_record(&h, &body[..]).await.unwrap_err(),
        VerifyError::Replayed
    );
    // Turning it off lets duplicates through (e.g. idempotent handlers).
    let off = v.without_replay_protection();
    assert!(off.verify_and_record(&h, &body[..]).await.is_ok());
}

// ---- Stripe ----------------------------------------------------------------

// Stripe publishes no fixed test vector; stripe-node and stripe-python
// generate headers in their tests the same way as here.
fn stripe_header(secret: &str, t: i64, body: &[u8]) -> String {
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={t},v1={}", hex(&hmac256(secret.as_bytes(), &msg)))
}

#[test]
fn stripe_valid_and_tampered() {
    let v = WebhookVerifier::stripe("whsec_test_secret");
    let body = br#"{"id":"evt_1","object":"event"}"#;
    let h = headers(&[(
        "stripe-signature",
        &stripe_header("whsec_test_secret", 1000, body),
    )]);
    let hook = v.verify_at(&h, &body[..], 1000).unwrap();
    assert_eq!(hook.timestamp(), Some(1000));
    assert_eq!(
        v.verify_at(&h, &b"{}"[..], 1000).unwrap_err(),
        VerifyError::SignatureMismatch
    );
    assert_eq!(
        v.verify_at(&h, &body[..], 1000 + 301).unwrap_err(),
        VerifyError::TimestampOutOfTolerance
    );
}

#[test]
fn stripe_multiple_v1_and_rotation() {
    let body = b"payload";
    let new = stripe_header("whsec_new", 50, body);
    let old = stripe_header("whsec_old", 50, body);
    let old_v1 = old.split(',').nth(1).unwrap();
    // Stripe sends one v1 per active secret during a roll, plus a v0.
    let combined = format!("{new},{old_v1},v0=deadbeef");
    let h = headers(&[("stripe-signature", &combined)]);

    assert!(
        WebhookVerifier::stripe("whsec_old")
            .verify_at(&h, &body[..], 50)
            .is_ok()
    );
    assert!(
        WebhookVerifier::stripe("whsec_new")
            .verify_at(&h, &body[..], 50)
            .is_ok()
    );

    let only_old = headers(&[("stripe-signature", &old)]);
    let v = WebhookVerifier::stripe("whsec_new");
    assert!(v.verify_at(&only_old, &body[..], 50).is_err());
    assert!(
        v.with_secret("whsec_old")
            .verify_at(&only_old, &body[..], 50)
            .is_ok()
    );
}

#[test]
fn stripe_malformed_header() {
    let v = WebhookVerifier::stripe("s");
    for bad in ["v1=00", "t=abc,v1=00", "t=1,t=2,v1=00"] {
        let h = headers(&[("stripe-signature", bad)]);
        assert_eq!(
            v.verify_at(&h, &b""[..], 1).unwrap_err(),
            VerifyError::MalformedHeader("stripe-signature".into()),
            "{bad}"
        );
    }
    let no_v1 = headers(&[("stripe-signature", "t=1,v0=00")]);
    assert_eq!(
        v.verify_at(&no_v1, &b""[..], 1).unwrap_err(),
        VerifyError::SignatureMismatch
    );
}

#[tokio::test]
async fn stripe_replay_is_opt_in() {
    let t = now();
    let h = headers(&[("stripe-signature", &stripe_header("s", t, b"x"))]);
    let default = WebhookVerifier::stripe("s");
    assert!(default.verify_and_record(&h, &b"x"[..]).await.is_ok());
    assert!(default.verify_and_record(&h, &b"x"[..]).await.is_ok());

    let guarded = WebhookVerifier::stripe("s").replay_store(MemoryReplayStore::new(16));
    assert!(guarded.verify_and_record(&h, &b"x"[..]).await.is_ok());
    assert_eq!(
        guarded.verify_and_record(&h, &b"x"[..]).await.unwrap_err(),
        VerifyError::Replayed
    );
}

// ---- GitHub ----------------------------------------------------------------

// Example from GitHub's docs, "Validating webhook deliveries" → "Testing the
// webhook payload validation".
#[test]
fn github_official_vector() {
    let v = WebhookVerifier::github("It's a Secret to Everybody");
    let h = headers(&[
        (
            "x-hub-signature-256",
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
        ),
        ("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958"),
    ]);
    let hook = v.verify_at(&h, &b"Hello, World!"[..], 0).unwrap();
    assert_eq!(hook.id(), Some("72d3162e-cc78-11e3-81ab-4c9367dc0958"));
    assert_eq!(hook.timestamp(), None);
    assert_eq!(
        v.verify_at(&h, &b"Hello, World?"[..], 0).unwrap_err(),
        VerifyError::SignatureMismatch
    );
}

#[test]
fn github_requires_prefix() {
    let v = WebhookVerifier::github("It's a Secret to Everybody");
    let h = headers(&[(
        "x-hub-signature-256",
        "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
    )]);
    assert_eq!(
        v.verify_at(&h, &b"Hello, World!"[..], 0).unwrap_err(),
        VerifyError::MalformedHeader("x-hub-signature-256".into())
    );
}

// ---- Slack -----------------------------------------------------------------

fn slack_headers(secret: &str, ts: i64, body: &[u8]) -> HeaderMap {
    let mut msg = format!("v0:{ts}:").into_bytes();
    msg.extend_from_slice(body);
    headers(&[
        ("x-slack-request-timestamp", &ts.to_string()),
        (
            "x-slack-signature",
            &format!("v0={}", hex(&hmac256(secret.as_bytes(), &msg))),
        ),
    ])
}

#[test]
fn slack_valid_tampered_and_stale() {
    let v = WebhookVerifier::slack("8f742231b10e8888abcd99yyyzzz85a5");
    let body = b"token=xyz&team_id=T1&command=%2Fweather&text=94070";
    let h = slack_headers("8f742231b10e8888abcd99yyyzzz85a5", 1_531_420_618, body);
    assert!(v.verify_at(&h, &body[..], 1_531_420_618).is_ok());
    assert!(v.verify_at(&h, &b"token=xyz"[..], 1_531_420_618).is_err());
    assert_eq!(
        v.verify_at(&h, &body[..], 1_531_420_618 + 600).unwrap_err(),
        VerifyError::TimestampOutOfTolerance
    );
    // Changing the timestamp header breaks the signature.
    let mut moved = h;
    moved.insert(
        "x-slack-request-timestamp",
        HeaderValue::from_static("1531420619"),
    );
    assert_eq!(
        v.verify_at(&moved, &body[..], 1_531_420_618).unwrap_err(),
        VerifyError::SignatureMismatch
    );
}

// ---- Shopify ---------------------------------------------------------------

#[test]
fn shopify_valid_tampered_rotation() {
    let body = br#"{"id":820982911946154508}"#;
    let sig = rune_base64::encode(&hmac256(b"shpss_old", body));
    let h = headers(&[
        ("x-shopify-hmac-sha256", &sig),
        ("x-shopify-webhook-id", "b54557e4"),
    ]);

    let v = WebhookVerifier::shopify("shpss_new");
    assert!(v.verify_at(&h, &body[..], 0).is_err());
    let v = v.with_secret("shpss_old");
    let hook = v.verify_at(&h, &body[..], 0).unwrap();
    assert_eq!(hook.id(), Some("b54557e4"));
    assert!(v.verify_at(&h, &b"{}"[..], 0).is_err());

    let bad = headers(&[("x-shopify-hmac-sha256", "%%%")]);
    assert_eq!(
        v.verify_at(&bad, &body[..], 0).unwrap_err(),
        VerifyError::MalformedHeader("x-shopify-hmac-sha256".into())
    );
}

// ---- Generic + secrets hygiene --------------------------------------------

#[test]
fn generic_mode_with_rotation() {
    let config = HmacConfig::sha256(b"new").header("x-sig").prefix("sha256=");
    let sig = format!("sha256={}", hex(&hmac256(b"old", b"body")));
    let h = headers(&[("x-sig", &sig)]);
    let v = WebhookVerifier::generic(config);
    assert!(v.verify_at(&h, &b"body"[..], 0).is_err());
    assert!(
        v.with_secret(&b"old"[..])
            .verify_at(&h, &b"body"[..], 0)
            .is_ok()
    );
}

#[test]
fn no_secret_in_debug_or_errors() {
    let v = WebhookVerifier::slack("super-secret-value").with_secret("second-secret");
    let dbg = format!("{v:?}");
    assert!(
        !dbg.contains("super-secret") && !dbg.contains("second-secret"),
        "{dbg}"
    );
    let err = v.verify_at(&HeaderMap::new(), &b""[..], 0).unwrap_err();
    assert!(!err.to_string().contains("secret-value"));
    let layer = WebhookLayer::new(v);
    assert!(!format!("{layer:?}").contains("super-secret"));
}

#[test]
fn oversized_body_is_rejected_by_pure_api() {
    let v = WebhookVerifier::github("s").max_body_bytes(4);
    let err = v
        .verify_at(&HeaderMap::new(), &b"12345"[..], 0)
        .unwrap_err();
    assert_eq!(err, VerifyError::BodyTooLarge { limit: 4 });
    assert_eq!(err.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ---- Layer + extractor -----------------------------------------------------

async fn echo(hook: VerifiedWebhook, body: Bytes) -> String {
    assert_eq!(hook.body(), &body);
    format!(
        "{:?}:{}",
        hook.provider(),
        String::from_utf8_lossy(hook.body())
    )
}

fn app(v: WebhookVerifier) -> Router {
    Router::new()
        .route("/hook", post(echo))
        .layer(WebhookLayer::new(v))
}

fn request(h: &HeaderMap, body: impl Into<Body>) -> Request<Body> {
    let mut req = Request::post("/hook").body(body.into()).unwrap();
    req.headers_mut().extend(h.clone());
    req
}

#[tokio::test]
async fn layer_hands_verified_body_to_handler() {
    let t = now();
    let h = headers(&[("stripe-signature", &stripe_header("s", t, b"{\"a\":1}"))]);
    let res = app(WebhookVerifier::stripe("s"))
        .oneshot(request(&h, "{\"a\":1}"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&text[..], b"Stripe:{\"a\":1}");
}

#[tokio::test]
async fn layer_rejections() {
    let t = now();
    let h = headers(&[("stripe-signature", &stripe_header("s", t, b"ok"))]);
    let v = WebhookVerifier::stripe("s").max_body_bytes(8);

    let tampered = app(v.clone()).oneshot(request(&h, "ko")).await.unwrap();
    assert_eq!(tampered.status(), StatusCode::UNAUTHORIZED);

    let missing = app(v.clone())
        .oneshot(request(&HeaderMap::new(), "ok"))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    // Streamed body without Content-Length still hits the cap.
    let stream = Body::from_stream(futures::stream::iter(
        ["0123", "4567", "89"].map(|c| Ok::<_, std::io::Error>(Bytes::from(c))),
    ));
    let big = app(v.clone()).oneshot(request(&h, stream)).await.unwrap();
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let mut declared = request(&h, "0123456789");
    declared
        .headers_mut()
        .insert("content-length", HeaderValue::from_static("10"));
    let big = app(v.clone()).oneshot(declared).await.unwrap();
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let stale = headers(&[("stripe-signature", &stripe_header("s", t - 3600, b"ok"))]);
    let res = app(v).oneshot(request(&stale, "ok")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn layer_blocks_replay() {
    let ts = now().to_string();
    let body = b"{}";
    let mut signed = format!("msg_layer.{ts}.").into_bytes();
    signed.extend_from_slice(body);
    let key = rune_base64::decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    let sig = format!("v1,{}", rune_base64::encode(&hmac256(&key, &signed)));
    let h = headers(&[
        ("webhook-id", "msg_layer"),
        ("webhook-timestamp", &ts),
        ("webhook-signature", &sig),
    ]);
    let router = app(WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap());
    let first = router.clone().oneshot(request(&h, "{}")).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = router.oneshot(request(&h, "{}")).await.unwrap();
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extractor_without_layer_is_500() {
    let router: Router = Router::new().route("/hook", post(|_: VerifiedWebhook| async { "x" }));
    let res = router
        .oneshot(request(&HeaderMap::new(), ""))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// The 0.2 API keeps working.
#[tokio::test]
async fn hmac_layer_compat() {
    let sig = format!("sha256={}", hex(&hmac256(b"github-secret", b"payload")));
    let layer = HmacLayer::new(
        HmacConfig::sha256(b"github-secret")
            .header("x-hub-signature-256")
            .prefix("sha256="),
    );
    let router = Router::new()
        .route("/hook", post(|| async { "ok" }))
        .layer(layer);
    let h = headers(&[("x-hub-signature-256", &sig)]);
    let ok = router
        .clone()
        .oneshot(request(&h, "payload"))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let bad = router.oneshot(request(&h, "tampered")).await.unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
}

// ---- Misconfiguration and retries -------------------------------------------

/// An empty secret (say, an unset environment variable read with
/// `unwrap_or_default`) must not turn into a key anyone can sign with.
#[test]
fn empty_secret_never_verifies() {
    let body = b"{}";
    let forged = hmac256(b"", body);
    let h = headers(&[("x-hub-signature-256", &format!("sha256={}", hex(&forged)))]);
    assert_eq!(
        WebhookVerifier::github("")
            .verify(&h, &body[..])
            .unwrap_err(),
        VerifyError::SignatureMismatch
    );
    assert!(
        WebhookVerifier::github("real")
            .with_secret("")
            .verify(&h, &body[..])
            .is_err()
    );
    let h = headers(&[("x-signature-256", &hex(&forged))]);
    assert!(
        WebhookVerifier::generic(HmacConfig::sha256(b""))
            .verify(&h, &body[..])
            .is_err()
    );
    assert!(!HmacConfig::sha256(b"").verify(body, &hex(&forged)));

    let t = now();
    let h = headers(&[("stripe-signature", &stripe_header("", t, body))]);
    assert!(WebhookVerifier::stripe("").verify(&h, &body[..]).is_err());
    let h = headers(&[("x-shopify-hmac-sha256", &rune_base64::encode(&forged))]);
    assert!(WebhookVerifier::shopify("").verify(&h, &body[..]).is_err());
    assert!(
        WebhookVerifier::slack("")
            .verify(&slack_headers("", t, body), &body[..])
            .is_err()
    );
}

fn svix_signed(id: &str, ts: i64, body: &[u8]) -> HeaderMap {
    let ts = ts.to_string();
    let mut signed = format!("{id}.{ts}.").into_bytes();
    signed.extend_from_slice(body);
    let key = rune_base64::decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
    let sig = format!("v1,{}", rune_base64::encode(&hmac256(&key, &signed)));
    headers(&[
        ("webhook-id", id),
        ("webhook-timestamp", &ts),
        ("webhook-signature", &sig),
    ])
}

/// Standard Webhooks senders resend a failed message with the same id but a
/// fresh timestamp and signature. That is a retry, not a replay: refusing it
/// would drop the event whenever the handler failed the first time.
#[tokio::test]
async fn standard_webhooks_resend_is_not_a_replay() {
    let body = br#"{"type":"invoice.paid"}"#;
    let v = WebhookVerifier::standard_webhooks(SVIX_SECRET).unwrap();
    let first = svix_signed("msg_retry", now() - 10, body);
    assert!(v.verify_and_record(&first, &body[..]).await.is_ok());
    let resend = svix_signed("msg_retry", now(), body);
    assert!(v.verify_and_record(&resend, &body[..]).await.is_ok());
    // The exact same delivery is still a replay.
    assert_eq!(
        v.verify_and_record(&resend, &body[..]).await.unwrap_err(),
        VerifyError::Replayed
    );
}
