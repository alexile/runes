# rune-axum-cors

> CORS middleware for Axum — exact origin allowlists, explicit subdomain wildcards, per-route policies, configs vetted by rune-cors at build time.

[![crates.io](https://img.shields.io/crates/v/rune-axum-cors)](https://crates.io/crates/rune-axum-cors)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-cors)](https://docs.rs/rune-axum-cors)
[![license](https://img.shields.io/crates/l/rune-axum-cors)](LICENSE)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) implementing the server side of the [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol). It answers preflights and adds `Access-Control-*` headers for allowed origins. It is the writing side of [`rune-cors`](../../web/rune-cors), which analyses CORS response headers.

Every policy is **audited before it serves**. `CorsLayer::new` runs the headers the middleware would send for a set of attacker-style probe origins (an unrelated site, `null`, subdomains, plain-`http` variants, unanchored lookalikes such as `evilexample.com` and `example.com.evil.net`) through `rune_cors::run`, and refuses the policy when the analyzer rates it insecure.

| Refused configuration                                       | rune-cors check id               |
| ----------------------------------------------------------- | -------------------------------- |
| `*` with credentials (always)                               | `cors.wildcard_with_credentials` |
| Predicate that reflects any origin                          | `cors.origin_reflection`         |
| `null` origin allowed                                       | `cors.null_origin`               |
| Predicate with a suffix/prefix match that admits lookalikes | `cors.unanchored_allowlist`      |
| `http://` variant of a secure origin allowed                | `cors.insecure_origin`           |
| Predicate that admits arbitrary subdomains                  | `cors.subdomain_origin`          |
| Private Network Access for attacker-controllable origins    | `cors.private_network_access`    |

## Installation

```toml
[dependencies]
rune-axum-cors = "0.1"
```

## Usage

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use http::{HeaderName, Method};
use rune_axum_cors::{Cors, CorsLayer};

let layer = CorsLayer::new(
    Cors::new()
        .site("https://example.com")
        .allow_origins(["https://app.example.com", "https://admin.example.com"])
        .allow_origin("https://*.tenants.example.com") // one label deep, not the apex
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([HeaderName::from_static("content-type")])
        .expose_headers([HeaderName::from_static("x-request-id")])
        .max_age(Duration::from_secs(600)),
)?
// A looser policy for one part of the API, audited on its own.
.route("/public", Cors::new().allow_any_origin())?;

// Weaknesses below the rejection threshold are kept for logging.
for weakness in &layer.report().weaknesses {
    eprintln!("{}: {}", weakness.kind.check_id(), weakness.message);
}

let app: Router = Router::new()
    .route("/api/items", get(handler))
    .route("/public/stats", get(stats))
    .layer(layer);
```

The dangerous configuration fails at build time:

```rust
use rune_axum_cors::{Cors, CorsLayer};

let err = CorsLayer::new(Cors::new().allow_any_origin().allow_credentials(true)).unwrap_err();
// insecure CORS policy: cors.wildcard_with_credentials (low): ...
println!("{err}");
```

### Origins only known at run time

```rust
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use rune_axum_cors::Cors;

let tenants = Arc::new(RwLock::new(HashSet::<String>::new()));
let lookup = Arc::clone(&tenants);
let cors = Cors::new()
    .site("https://example.com")
    .allow_origin_fn(move |origin| lookup.read().is_ok_and(|set| set.contains(origin)))
    .allow_credentials(true);
```

Whatever the predicate accepts is echoed back, so a sloppy predicate is origin reflection. Compare whole origins, never `ends_with`, `starts_with`, `contains` or unanchored regexes. The audit probes the predicate with lookalikes and refuses it when they get through, but probing cannot prove a predicate safe.

## Configuration

| Method                          | Default            | Description                                                                                              |
| ------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------- |
| `.site(origin)`                 | none               | The protected site's origin; the audit judges allowed origins relative to it.                            |
| `.allow_origin(origin)`         | none               | Allow one exact origin (normalised), or a wildcard `scheme://*.host` (one label) / `scheme://**.host` (any depth). `"*"` = any origin, `"null"` = opaque origin. |
| `.allow_origins(iter)`          | none               | Allow several origins or wildcards.                                                                      |
| `.allow_any_origin()`           | off                | `Access-Control-Allow-Origin: *`, for public resources only.                                             |
| `.allow_subdomains(bool)`       | off                | Also allow subdomains (any depth) of the exact origins, same scheme and port. Prefer explicit wildcards. |
| `.allow_origin_fn(f)`           | none               | Predicate for dynamic origins; probed by the audit with attacker-style origins.                          |
| `.allow_credentials(bool)`      | off                | `Access-Control-Allow-Credentials: true`.                                                                |
| `.allow_methods(iter)`          | `GET, HEAD, POST`  | Methods allowed in preflights (`*` only without credentials).                                            |
| `.allow_headers(iter)`          | none               | Request headers allowed in preflights (`*` only without credentials). Never mirrored.                   |
| `.expose_headers(iter)`         | none               | `Access-Control-Expose-Headers`.                                                                         |
| `.max_age(Duration)`            | not sent           | `Access-Control-Max-Age` on preflights, clamped to `MAX_AGE_CAP` (2 hours).                              |
| `.allow_private_network(bool)`  | off                | Answer Private Network Access preflights, for exactly listed origins only.                               |
| `.reject_at(Severity)`          | `Low`              | Audit severity that rejects the policy; never above `High`.                                              |
| `.rejection(Rejection)`         | `Status(403)`      | Refused preflights: a status code, or `OmitHeaders` (`204` without CORS headers).                        |
| `.deny_status(StatusCode)`      | `403`              | Shorthand for `.rejection(Rejection::Status(..))`.                                                       |
| `CorsLayer::route(prefix, cors)`| none               | Per-route override by path prefix; longest prefix wins.                                                  |

## Behaviour

- **Preflight** (`OPTIONS` with `Origin` and `Access-Control-Request-Method`): answered directly with `204 No Content` and the CORS headers when the origin, method, every requested header and any Private Network Access request are allowed; otherwise according to the rejection mode, with no CORS headers. Repeated or malformed preflight headers are refused. Preflights never reach handlers.
- **Actual requests**: passed to the inner service. Allowed origins get `Access-Control-Allow-Origin` (the echoed origin, or `*`), credentials and exposed headers. The layer owns the CORS headers and replaces or removes any the handler or an inner error path set.
- **`Vary: Origin`** is added to every response unless the policy is `*`; preflights also vary on the `Access-Control-Request-*` headers.
- **Per-route policies** match the raw request path on segment boundaries (`/api` covers `/api/x`, not `/apix`), the way Axum routes. A path that would pick a different policy once percent-decoded or with `.`/`..`/`//`/`\` resolved gets no CORS grant. Inside Axum you can also use `get(handler).layer(cors_layer)` per route; `route_layer` does not see preflights.

## Security

The layer is built against the classic CORS mistakes (PortSwigger's CORS research, the OWASP testing guide):

| Mistake | What this crate does |
| --- | --- |
| Reflecting any `Origin` | Only an origin that passed the policy is echoed. Predicates that reflect are refused by the audit. |
| `null` origin allowed | Off unless listed; the audit refuses it (`High` with credentials, cannot be waived). Predicates never see `null`. |
| Suffix/prefix/regex bugs (`evil-example.com`, `example.com.evil.net`) | Exact byte comparison against the canonical origin; wildcards match whole labels only. Lookalike predicates are refused. |
| `*` with credentials | Always refused, whatever `reject_at` says. |
| Missing `Vary: Origin` | Added to every origin-dependent response, including refusals, errors and requests without `Origin`. |
| Preflight cache poisoning | Preflights vary on `Origin` and every `Access-Control-Request-*` header; `Max-Age` is capped at two hours so a tightened policy reaches browsers. |
| All headers allowed with credentials | `*` is a literal with credentials, so credentialed preflights must list headers. Requested headers are never mirrored. |
| Case, port, scheme normalisation | Configured origins are normalised; request origins must be in browser form. `HTTPS://`, `:443`, `http://` variants and other ports match nothing. |
| Trailing dots, empty labels | Refused in configuration, never matched in requests. |
| IDN / punycode | Configure punycode (`xn--`), as browsers send it. Non-ASCII input is an error, so a Unicode lookalike can never slip into the list. |
| Private Network Access | Only granted to exactly listed origins when enabled; never to `*`, wildcards or the predicate. A PNA preflight the policy does not grant is refused. |
| Error paths reflecting without checks | Inner responses (handlers, error handlers, other layers) have their CORS headers stripped and recomputed. Malformed preflights are refused by the layer instead of reaching the router. |

Things the layer cannot do for you: CORS controls what browsers let scripts read, it is not access control. Disallowed origins still reach handlers with simple requests, so state-changing endpoints need CSRF protection. Every host under a wildcard can read your responses, including a forgotten subdomain someone else takes over.

## License

MIT
