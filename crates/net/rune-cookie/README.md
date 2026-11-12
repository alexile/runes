# rune-cookie

> RFC 6265 cookies: Set-Cookie/Cookie parsing and serialization, cookie dates, and a sans-I/O cookie jar with PSL scoping and SameSite

[![crates.io](https://img.shields.io/crates/v/rune-cookie)](https://crates.io/crates/rune-cookie)
[![docs.rs](https://img.shields.io/docsrs/rune-cookie)](https://docs.rs/rune-cookie)
[![license](https://img.shields.io/crates/l/rune-cookie)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One auditable cookie implementation for clients, proxies and analysers,
following [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) and the parts of
[RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
that browsers enforce. It passes the IETF httpstate conformance corpus the
RFC was validated against.

- **`SetCookie`**: the user-agent parsing algorithm of §5.2 (last valid
  attribute wins, lenient dates, `Max-Age` over `Expires`), plus
  `SameSite` and `Partitioned`. Every raw attribute is kept in wire order
  next to the interpretation, so analysers can see duplicates, typos and
  ignored values. `Display` writes a header back.
- **`parse_cookie_header`** / **`serialize_cookie_header`**: the `Cookie`
  request header. **`is_valid_name`** / **`is_valid_value`**: the strict
  server grammar of §4.1.1.
- **`parse_cookie_date`** / **`format_cookie_date`**: the §5.1.1 date
  algorithm and IMF-fixdate.
- **`CookieJar`**: storage (§5.3) and retrieval (§5.4). Host-only and
  domain cookies, default paths, path ordering, expiry, replacement, LRU
  eviction. `Domain` attributes that are public suffixes (`co.uk`,
  `github.io`) are refused with the Public Suffix List of
  [`rune-psl`](../../common/rune-psl). On by default and switchable in
  `JarOptions`: strict secure cookies, `__Secure-`/`__Host-` prefixes,
  `SameSite` (with a `SiteContext` per request), `SameSite=None` requires
  `Secure`; optional Lax-by-default and a lifetime cap.
- **`domain_match`**, **`path_match`**, **`default_path`**,
  **`is_same_site`** (schemeful, eTLD+1).
- **[`rune-http-model`](../rune-http-model) glue**:
  `CookieJar::store_response`, `store_exchange`, `apply_to_request`, and
  `response_set_cookies` for jar-less analysis.

The jar is sans-I/O and never reads the clock: every call takes the request
URL, a `RequestContext` (HTTP or script API, site context, method) and
`now`.

## Installation

```toml
[dependencies]
rune-cookie = "0.1"
```

Features:

- `serde`: `Serialize`/`Deserialize` for `SetCookie`, `Cookie`,
  `CookiePair` and `SameSite`, to save a jar (`CookieJar::iter`) and
  restore it (`CookieJar::from_cookies`).

## Usage

```rust
use std::time::{Duration, SystemTime};
use rune_cookie::{CookieJar, Error, Rejection, RequestContext, SetCookie, SiteContext};
use url::Url;

let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
let ctx = RequestContext::http();
let mut jar = CookieJar::new();

let login = Url::parse("https://shop.example.co.uk/account/login").unwrap();
jar.store(&login, "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", &ctx, now)?;
jar.store(&login, "pref=dark; Domain=example.co.uk; Path=/; Max-Age=3600", &ctx, now)?;

// `co.uk` is a public suffix: the cookie would leak to every UK site.
assert_eq!(
    jar.store(&login, "track=1; Domain=co.uk", &ctx, now),
    Err(Error::Rejected(Rejection::PublicSuffix { domain: "co.uk".into() })),
);

let cart = Url::parse("https://shop.example.co.uk/cart").unwrap();
assert_eq!(jar.cookie_header(&cart, &ctx, now)?.as_deref(), Some("sid=abc; pref=dark"));

// A cross-site POST does not carry the `SameSite=Lax` session cookie.
let cross = ctx
    .with_site(SiteContext::CrossSiteTopLevelNavigation)
    .with_method("POST");
assert_eq!(jar.cookie_header(&cart, &cross, now)?.as_deref(), Some("pref=dark"));

// Parse without a jar, for analysis.
let cookie = SetCookie::parse("id=1; secure; Max-Age=60; Max-Age=oops; SameSite=bogus")?;
assert!(cookie.secure);
assert_eq!(cookie.max_age, Some(60));
assert_eq!(cookie.same_site, None);
assert_eq!(cookie.attributes.len(), 4);
# Ok::<(), rune_cookie::Error>(())
```

With [`rune-http-model`](../rune-http-model):

```rust
use std::time::SystemTime;
use rune_cookie::{CookieJar, RequestContext};
use rune_http_model::{HttpRequest, HttpResponse};

let (now, ctx) = (SystemTime::now(), RequestContext::http());
let mut jar = CookieJar::new();
let response = HttpResponse::new(302)
    .with_header("Location", "/home")
    .with_header("Set-Cookie", "sid=abc; Path=/");
jar.store_response("https://app.example.com/login", &response, &ctx, now)?;

let mut next = HttpRequest::get("https://app.example.com/home");
jar.apply_to_request(&mut next, &ctx, now)?;
assert_eq!(next.header("Cookie"), Some("sid=abc"));
# Ok::<(), rune_cookie::Error>(())
```

## Conformance

`tests/conformance.rs` runs the [httpstate](https://github.com/abarth/http-state)
corpus: all 214 required parser cases (with RFC 6265 options and with the
default RFC 6265bis options), the 4 optional cases, and the 15 + 55
cookie-date cases from httpstate and Chromium. `tests/proptest.rs` checks
serialization round trips and that nothing panics.

## Limitations

- `Partitioned` (CHIPS) is parsed and stored, but the jar does not key
  cookies by top-level site.
- Only `https` and `wss` count as secure; `http://localhost` does not.

## License

MIT
