//! End-to-end tests: keys are generated at test time (RSA comes from a fixed
//! test-only fixture, since ring cannot generate RSA keys) and the JWKS is
//! served by an in-process server on 127.0.0.1. No internet access.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{FromRef, State},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::get,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use ring::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
        Ed25519KeyPair, KeyPair, RsaKeyPair, RsaPublicKeyComponents,
    },
};
use rune_axum_jwt::{
    Algorithm, Claims, JwksError, JwksOptions, JwksSource, Jwt, JwtConfig, JwtLayer, StaticKeys,
    VerifiedClaims, VerifyKey,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const RSA_DER: &[u8] = include_bytes!("fixtures/rsa2048-test-only.der");
const AUD: &str = "api://test";

fn b64(bytes: &[u8]) -> String {
    rune_base64::encode_url_no_pad(bytes)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A signing key plus its public JWK.
struct TestKey {
    alg: Algorithm,
    kid: String,
    enc: EncodingKey,
    jwk: Value,
}

impl TestKey {
    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(self.alg);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.enc).unwrap()
    }
}

fn rsa(alg: Algorithm, kid: &str) -> TestKey {
    let pair = RsaKeyPair::from_der(RSA_DER).unwrap();
    let parts = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
    TestKey {
        alg,
        kid: kid.into(),
        enc: EncodingKey::from_rsa_der(RSA_DER),
        jwk: json!({"kty": "RSA", "kid": kid, "alg": format!("{alg:?}"), "use": "sig",
                    "n": b64(&parts.n), "e": b64(&parts.e)}),
    }
}

fn ec(alg: Algorithm, kid: &str) -> TestKey {
    let rng = SystemRandom::new();
    let (curve, crv, coord) = match alg {
        Algorithm::ES256 => (&ECDSA_P256_SHA256_FIXED_SIGNING, "P-256", 32),
        _ => (&ECDSA_P384_SHA384_FIXED_SIGNING, "P-384", 48),
    };
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(curve, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(curve, pkcs8.as_ref(), &rng).unwrap();
    let point = pair.public_key().as_ref(); // 0x04 || x || y
    TestKey {
        alg,
        kid: kid.into(),
        enc: EncodingKey::from_ec_der(pkcs8.as_ref()),
        // No `alg`: it is inferred from the curve.
        jwk: json!({"kty": "EC", "kid": kid, "crv": crv,
                    "x": b64(&point[1..=coord]), "y": b64(&point[1 + coord..])}),
    }
}

fn ed(kid: &str) -> TestKey {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    TestKey {
        alg: Algorithm::EdDSA,
        kid: kid.into(),
        enc: EncodingKey::from_ed_der(pkcs8.as_ref()),
        jwk: json!({"kty": "OKP", "kid": kid, "crv": "Ed25519", "alg": "EdDSA",
                    "x": b64(pair.public_key().as_ref())}),
    }
}

fn jwks(keys: &[&TestKey]) -> Value {
    json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()})
}

#[derive(Clone)]
struct Idp {
    base: Arc<Mutex<String>>,
    jwks: Arc<Mutex<Value>>,
    hits: Arc<AtomicUsize>,
}

impl Idp {
    fn base(&self) -> String {
        self.base.lock().unwrap().clone()
    }
    fn jwks_url(&self) -> String {
        format!("{}/jwks", self.base())
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    fn set(&self, keys: Value) {
        *self.jwks.lock().unwrap() = keys;
    }
}

/// Serves a JWKS and an OIDC discovery document on 127.0.0.1.
async fn idp(keys: Value) -> Idp {
    let state = Idp {
        base: Arc::default(),
        jwks: Arc::new(Mutex::new(keys)),
        hits: Arc::default(),
    };
    let app = Router::new()
        .route(
            "/jwks",
            get(|State(s): State<Idp>| async move {
                s.hits.fetch_add(1, Ordering::SeqCst);
                Json(s.jwks.lock().unwrap().clone())
            }),
        )
        .route(
            "/.well-known/openid-configuration",
            get(|State(s): State<Idp>| async move {
                let base = s.base();
                Json(json!({"issuer": base, "jwks_uri": format!("{base}/jwks")}))
            }),
        )
        .route("/big", get(|| async { "x".repeat(10_000) }))
        .route("/redirect", get(|| async { Redirect::temporary("/jwks") }))
        .route(
            "/down",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR.into_response() }),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    *state.base.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    state
}

fn claims() -> Value {
    json!({"sub": "alice", "iss": "https://issuer.test", "aud": AUD,
           "exp": now() + 600, "iat": now()})
}

fn config(source: JwksSource) -> JwtConfig {
    JwtConfig::new(source)
        .issuer("https://issuer.test")
        .audience(&[AUD])
}

fn fast() -> JwksOptions {
    JwksOptions::default().min_refetch_interval(Duration::ZERO)
}

fn app(layer: JwtLayer) -> Router {
    Router::new()
        .route(
            "/me",
            get(|claims: Option<Claims<Value>>| async move {
                claims.map_or_else(|| "anonymous".to_owned(), |Claims(c)| c["sub"].to_string())
            }),
        )
        .layer(layer)
}

/// Sends a request and returns status, `WWW-Authenticate` and body.
async fn call(app: &Router, auth: Option<&str>) -> (StatusCode, Option<String>, String) {
    let mut req = Request::builder().uri("/me");
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, auth);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap().to_owned());
    let body =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    (status, www, body)
}

async fn status(app: &Router, token: &str) -> StatusCode {
    call(app, Some(&format!("Bearer {token}"))).await.0
}

const INVALID: Option<&str> = Some(r#"Bearer error="invalid_token""#);

#[tokio::test]
async fn every_asymmetric_algorithm_verifies() {
    let keys = [
        rsa(Algorithm::RS256, "rs256"),
        rsa(Algorithm::RS384, "rs384"),
        rsa(Algorithm::RS512, "rs512"),
        rsa(Algorithm::PS256, "ps256"),
        rsa(Algorithm::PS384, "ps384"),
        rsa(Algorithm::PS512, "ps512"),
        ec(Algorithm::ES256, "es256"),
        ec(Algorithm::ES384, "es384"),
        ed("eddsa"),
    ];
    let server = idp(jwks(&keys.iter().collect::<Vec<_>>())).await;
    let app = app(JwtLayer::new(config(
        JwksSource::new(&server.jwks_url()).unwrap(),
    )));
    for key in &keys {
        let (code, _, body) = call(&app, Some(&format!("Bearer {}", key.sign(&claims())))).await;
        assert_eq!(code, StatusCode::OK, "{:?}", key.alg);
        assert_eq!(body, "\"alice\"");
    }
    assert_eq!(server.hits(), 1, "keys are cached");
}

#[tokio::test]
async fn algorithm_confusion_is_rejected() {
    let key = rsa(Algorithm::RS256, "rsa");
    let server = idp(jwks(&[&key])).await;
    let app = app(JwtLayer::new(config(
        JwksSource::new(&server.jwks_url()).unwrap(),
    )));
    assert_eq!(status(&app, &key.sign(&claims())).await, StatusCode::OK);

    // HS256 "signed" with the RSA public key material as the HMAC secret.
    let pair = RsaKeyPair::from_der(RSA_DER).unwrap();
    let parts = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
    for secret in [
        pair.public().as_ref().to_vec(),
        b64(&parts.n).into_bytes(),
        serde_json::to_vec(&key.jwk).unwrap(),
    ] {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("rsa".into());
        let forged = encode(&header, &claims(), &EncodingKey::from_secret(&secret)).unwrap();
        assert_eq!(
            call(&app, Some(&format!("Bearer {forged}")))
                .await
                .1
                .as_deref(),
            INVALID
        );
    }

    // Same RSA key, but an algorithm it is not pinned to.
    let other = rsa(Algorithm::PS256, "rsa");
    assert_eq!(
        status(&app, &other.sign(&claims())).await,
        StatusCode::UNAUTHORIZED
    );

    // alg: none, with and without a signature.
    let body = b64(serde_json::to_vec(&claims()).unwrap().as_slice());
    for alg in ["none", "None", "NONE"] {
        let head = b64(format!(r#"{{"alg":"{alg}","kid":"rsa"}}"#).as_bytes());
        for token in [format!("{head}.{body}."), format!("{head}.{body}.c2ln")] {
            assert_eq!(status(&app, &token).await, StatusCode::UNAUTHORIZED);
        }
    }

    // A `crit` header we do not understand.
    let head = b64(br#"{"alg":"RS256","kid":"rsa","crit":["exp"],"exp":1}"#);
    let sig = key.sign(&claims());
    let sig = sig.rsplit('.').next().unwrap();
    assert_eq!(
        status(&app, &format!("{head}.{body}.{sig}")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bad_claims_are_rejected_without_detail() {
    let key = ed("k");
    let server = idp(jwks(&[&key])).await;
    let source = JwksSource::new(&server.jwks_url()).unwrap();
    let app = app(JwtLayer::new(
        config(source).leeway(5).require_claims(["sub"]),
    ));
    let t = now();
    let cases = [
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": t - 60}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": "api://other", "exp": t + 60}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": ["x", "y"], "exp": t + 60}),
        json!({"sub": "a", "iss": "https://issuer.test", "exp": t + 60}),
        json!({"sub": "a", "iss": "https://issuer.test/", "aud": AUD, "exp": t + 60}),
        json!({"sub": "a", "aud": AUD, "exp": t + 60}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": t + 60, "nbf": t + 60}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": t + 600, "iat": t + 120}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": t + 60, "iat": "yesterday"}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": t + 60, "nbf": "99999999999"}),
        json!({"sub": "a", "iss": "https://issuer.test", "aud": AUD, "exp": "99999999999"}),
        json!({"iss": "https://issuer.test", "aud": AUD, "exp": t + 60}),
    ];
    for c in &cases {
        let (code, www, body) = call(&app, Some(&format!("Bearer {}", key.sign(c)))).await;
        assert_eq!(
            (code, www.as_deref()),
            (StatusCode::UNAUTHORIZED, INVALID),
            "{c}"
        );
        assert!(body.is_empty(), "no detail in the body");
    }
    // Leeway covers a just-expired token; aud may be one of several.
    let ok = json!({"sub": "a", "iss": "https://issuer.test", "aud": ["x", AUD], "exp": t - 2});
    assert_eq!(status(&app, &key.sign(&ok)).await, StatusCode::OK);

    // Signature over different claims.
    let good = key.sign(&claims());
    let mut parts: Vec<&str> = good.split('.').collect();
    let other = b64(serde_json::to_vec(&json!({"sub": "mallory"}))
        .unwrap()
        .as_slice());
    parts[1] = &other;
    assert_eq!(
        status(&app, &parts.join(".")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unknown_kid_refreshes_the_cache() {
    let old = ec(Algorithm::ES256, "2025");
    let new = ec(Algorithm::ES256, "2026");
    let server = idp(jwks(&[&old])).await;
    let app = app(JwtLayer::new(config(
        JwksSource::with_options(&server.jwks_url(), fast()).unwrap(),
    )));
    assert_eq!(status(&app, &old.sign(&claims())).await, StatusCode::OK);
    assert_eq!(server.hits(), 1);

    server.set(jwks(&[&old, &new]));
    assert_eq!(status(&app, &new.sign(&claims())).await, StatusCode::OK);
    assert_eq!(server.hits(), 2);
    assert_eq!(status(&app, &old.sign(&claims())).await, StatusCode::OK);
    assert_eq!(server.hits(), 2, "known kid needs no fetch");
}

#[tokio::test]
async fn unknown_kid_refetches_are_throttled() {
    let key = ed("real");
    let server = idp(jwks(&[&key])).await;
    let source = JwksSource::with_options(
        &server.jwks_url(),
        JwksOptions::default().min_refetch_interval(Duration::from_secs(60)),
    )
    .unwrap();
    let app = app(JwtLayer::new(config(source)));
    assert_eq!(status(&app, &key.sign(&claims())).await, StatusCode::OK);

    let mut handles = Vec::new();
    for i in 0..50 {
        let app = app.clone();
        let bogus = TestKey {
            kid: format!("bogus-{i}"),
            ..ed("x")
        };
        handles.push(tokio::spawn(async move {
            status(&app, &bogus.sign(&claims())).await
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(server.hits(), 1, "no fetch storm");
}

#[tokio::test]
async fn refetches_after_the_interval() {
    let key = ed("real");
    let server = idp(jwks(&[&key])).await;
    let source = JwksSource::with_options(
        &server.jwks_url(),
        JwksOptions::default()
            .min_refetch_interval(Duration::from_millis(100))
            .refresh_interval(Duration::from_millis(100)),
    )
    .unwrap();
    let app = app(JwtLayer::new(config(source)));
    assert_eq!(status(&app, &key.sign(&claims())).await, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(status(&app, &key.sign(&claims())).await, StatusCode::OK);
    assert_eq!(server.hits(), 2, "stale cache refreshed");

    // The IdP goes down: stale keys keep working.
    server.set(json!({"keys": "nope"}));
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(status(&app, &key.sign(&claims())).await, StatusCode::OK);
    assert_eq!(server.hits(), 3);
}

#[tokio::test]
async fn oidc_discovery() {
    let key = rsa(Algorithm::RS256, "k");
    let server = idp(jwks(&[&key])).await;
    let issuer = server.base();
    let jwt = JwtConfig::oidc_with(&issuer, fast())
        .await
        .unwrap()
        .audience(&[AUD]);
    let app = app(JwtLayer::new(jwt));
    let mut c = claims();
    c["iss"] = json!(issuer);
    assert_eq!(status(&app, &key.sign(&c)).await, StatusCode::OK);
    c["iss"] = json!("https://issuer.test");
    assert_eq!(status(&app, &key.sign(&c)).await, StatusCode::UNAUTHORIZED);

    // The document's issuer must match exactly.
    let err = JwksSource::discover(&format!("{issuer}/"), fast())
        .await
        .unwrap_err();
    assert!(matches!(err, JwksError::IssuerMismatch { .. }), "{err}");
    assert!(matches!(
        JwksSource::discover("http://idp.example.com", fast()).await,
        Err(JwksError::NotHttps(_))
    ));
}

#[tokio::test]
async fn fetch_limits() {
    let server = idp(json!({"keys": []})).await;
    let base = server.base();
    let capped = JwksSource::with_options(
        &format!("{base}/big"),
        JwksOptions::default().max_response_bytes(1024),
    )
    .unwrap();
    assert_eq!(capped.refresh().await, Err(JwksError::TooLarge(1024)));
    let redirect = JwksSource::new(&format!("{base}/redirect")).unwrap();
    assert_eq!(redirect.refresh().await, Err(JwksError::Status(307)));
    let empty = JwksSource::new(&server.jwks_url()).unwrap();
    assert_eq!(empty.refresh().await, Err(JwksError::NoUsableKeys));

    // Symmetric keys in a remote JWKS are ignored.
    server.set(json!({"keys": [{"kty": "oct", "k": "c2VjcmV0", "alg": "HS256"}]}));
    assert_eq!(empty.refresh().await, Err(JwksError::NoUsableKeys));
}

#[tokio::test]
async fn unavailable_keys_give_503() {
    let server = idp(json!({})).await;
    let source = JwksSource::new(&format!("{}/down", server.base())).unwrap();
    let app = app(JwtLayer::new(config(source)));
    let (code, www, _) = call(&app, Some(&format!("Bearer {}", ed("k").sign(&claims())))).await;
    assert_eq!((code, www), (StatusCode::SERVICE_UNAVAILABLE, None));
}

#[tokio::test]
async fn kid_required_with_several_keys() {
    let a = ec(Algorithm::ES256, "a");
    let b = ec(Algorithm::ES256, "b");
    let jwt = JwtConfig::new(StaticKeys::from_jwks_json(&jwks(&[&a, &b]).to_string()).unwrap())
        .issuer("https://issuer.test")
        .audience(&[AUD]);
    let app = app(JwtLayer::new(jwt));
    assert_eq!(status(&app, &b.sign(&claims())).await, StatusCode::OK);
    let no_kid = encode(&Header::new(Algorithm::ES256), &claims(), &a.enc).unwrap();
    assert_eq!(status(&app, &no_kid).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn header_handling_and_length_cap() {
    let jwt = JwtConfig::hs256(b"secret").max_token_len(200);
    let app = app(JwtLayer::new(jwt));
    assert_eq!(
        call(&app, None).await,
        (
            StatusCode::UNAUTHORIZED,
            Some("Bearer".into()),
            String::new()
        )
    );
    assert_eq!(
        call(&app, Some("Basic dXNlcjpwYXNz")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, Some("Bearer not a token")).await,
        (
            StatusCode::BAD_REQUEST,
            Some(r#"Bearer error="invalid_request""#.into()),
            String::new()
        )
    );
    let long = format!("Bearer {}", "a".repeat(300));
    assert_eq!(call(&app, Some(&long)).await.1.as_deref(), INVALID);
}

#[tokio::test]
async fn scopes_and_roles_per_route() {
    let jwt = JwtConfig::hs256(b"secret").roles_claim("realm_access.roles");
    let key = EncodingKey::from_secret(b"secret");
    let token = |extra: Value| {
        let mut c = json!({"sub": "a", "exp": now() + 60});
        c.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        format!("Bearer {}", encode(&Header::default(), &c, &key).unwrap())
    };
    let app = Router::new()
        .route(
            "/me",
            get(|c: VerifiedClaims| async move { c.scopes().join(",") })
                .layer(JwtLayer::new(jwt.clone()).require_scopes(["read"])),
        )
        .route(
            "/admin",
            get(|| async { "admin" }).layer(JwtLayer::new(jwt.clone()).require_roles(["admin"])),
        )
        .layer(JwtLayer::new(jwt));

    let (code, _, body) = call(&app, Some(&token(json!({"scope": "write read"})))).await;
    assert_eq!((code, body.as_str()), (StatusCode::OK, "read,write"));
    assert_eq!(
        call(&app, Some(&token(json!({"scp": ["read"]})))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, Some(&token(json!({"scope": "write"})))).await,
        (
            StatusCode::FORBIDDEN,
            Some(r#"Bearer error="insufficient_scope", scope="read""#.into()),
            String::new()
        )
    );

    let admin = |roles: Value| async {
        let req = Request::builder()
            .uri("/admin")
            .header(header::AUTHORIZATION, token(roles))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    };
    assert_eq!(
        admin(json!({"realm_access": {"roles": ["user", "admin"]}})).await,
        StatusCode::OK
    );
    assert_eq!(
        admin(json!({"realm_access": {"roles": ["user"]}})).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        admin(json!({"roles": ["admin"]})).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn optional_mode() {
    let app = app(JwtLayer::new(JwtConfig::hs256(b"secret")).optional());
    assert_eq!(
        call(&app, None).await,
        (StatusCode::OK, None, "anonymous".into())
    );
    let good = encode(
        &Header::default(),
        &json!({"sub": "bob", "exp": now() + 60}),
        &EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    assert_eq!(
        call(&app, Some(&format!("Bearer {good}"))).await.2,
        "\"bob\""
    );
    // A bad token is still rejected, not treated as anonymous.
    let bad = encode(
        &Header::default(),
        &json!({"sub": "bob", "exp": now() + 60}),
        &EncodingKey::from_secret(b"other"),
    )
    .unwrap();
    assert_eq!(status(&app, &bad).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stateful_extractor_without_layer() {
    #[derive(Clone)]
    struct AppState {
        jwt: JwtConfig,
    }
    impl FromRef<AppState> for JwtConfig {
        fn from_ref(s: &AppState) -> Self {
            s.jwt.clone()
        }
    }
    #[derive(serde::Deserialize)]
    struct User {
        sub: String,
    }
    let key = VerifyKey::hs512(b"secret").with_kid("v1");
    let app: Router = Router::new()
        .route("/me", get(|Jwt(u): Jwt<User>| async move { u.sub }))
        .with_state(AppState {
            jwt: JwtConfig::new(StaticKeys::new([key])),
        });
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some("v1".into());
    let token = encode(
        &header,
        &json!({"sub": "carol", "exp": now() + 60}),
        &EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    let (code, _, body) = call(&app, Some(&format!("Bearer {token}"))).await;
    assert_eq!((code, body.as_str()), (StatusCode::OK, "carol"));
    let (code, www, _) = call(&app, None).await;
    assert_eq!(
        (code, www.as_deref()),
        (StatusCode::UNAUTHORIZED, Some("Bearer"))
    );
}
