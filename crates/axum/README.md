# Axum middleware

Axum and Tower middleware: auth, rate limiting, CSRF, security headers, request limits.

| Crate | Description |
| --- | --- |
| [`rune-axum-apikey`](rune-axum-apikey) | API key extractor and middleware for Axum — validates keys from headers, bearer tokens, or query parameters with constant-time comparison |
| [`rune-axum-audit`](rune-axum-audit) | Structured audit log middleware for Axum — records method, path, status, latency, and client identity |
| [`rune-axum-basicauth`](rune-axum-basicauth) | HTTP Basic authentication extractor and middleware layer for Axum with constant-time credential comparison |
| [`rune-axum-bearer`](rune-axum-bearer) | Bearer token extractor for Axum — typed extraction from Authorization headers |
| [`rune-axum-brute`](rune-axum-brute) | Account lockout middleware for Axum — lock out repeated authentication failures per key, with spoof-resistant client IPs and bounded state |
| [`rune-axum-cache`](rune-axum-cache) | Cache-Control and conditional-request middleware for Axum — sets caching directives and validators, answers 304/412 per RFC 9110 |
| [`rune-axum-compression`](rune-axum-compression) | Response compression middleware for Axum — negotiated gzip, deflate, br and zstd with a content-type allowlist and minimum size |
| [`rune-axum-concurrency`](rune-axum-concurrency) | Concurrency limit middleware for Axum — bounded in-flight requests with 503 load shedding and metrics |
| [`rune-axum-cors`](rune-axum-cors) | CORS middleware for Axum — exact origin allowlists, explicit subdomain wildcards, per-route policies, configs vetted by rune-cors at build time |
| [`rune-axum-csrf`](rune-axum-csrf) | CSRF protection middleware for Axum — signed double-submit cookie or token-free Origin/Fetch-Metadata mode |
| [`rune-axum-health`](rune-axum-health) | Health and readiness probes plus graceful shutdown for Axum — readiness flips on shutdown and in-flight requests drain before exit |
| [`rune-axum-helmet`](rune-axum-helmet) | Security headers middleware for Axum — validated CSP with per-request nonces, HSTS, Permissions-Policy, COOP/COEP/CORP and more |
| [`rune-axum-ipfilter`](rune-axum-ipfilter) | IP allowlist / blocklist middleware for Axum — CIDR filtering with spoof-resistant client IP resolution (socket peer, trusted proxies) |
| [`rune-axum-jwt`](rune-axum-jwt) | JWT bearer auth for Axum 0.8: HMAC, RSA, ECDSA and EdDSA keys, cached JWKS and OIDC discovery, scope/role checks, RFC 6750 errors |
| [`rune-axum-mtls`](rune-axum-mtls) | Mutual-TLS client-certificate extraction for Axum: rustls listener, rune-x509 clientAuth verification, typed extractor |
| [`rune-axum-problem`](rune-axum-problem) | RFC 9457 problem details for Axum — application/problem+json error responses with extensions, plus a layer for bare error statuses |
| [`rune-axum-ratelimit`](rune-axum-ratelimit) | Rate limiter middleware for Axum — fixed-window or GCRA per client, in-memory or Redis store, spoof-resistant client IPs, IETF RateLimit headers |
| [`rune-axum-redirect-https`](rune-axum-redirect-https) | Redirect HTTP requests to HTTPS — Tower middleware for Axum |
| [`rune-axum-requestid`](rune-axum-requestid) | Request-id and W3C traceparent propagation layer for Axum — extensions, response header and tracing span |
| [`rune-axum-sanitize`](rune-axum-sanitize) | Defence-in-depth input sanitization for Axum: tokenizer-based tag stripping, HTML escaping or allowlist cleaning of query, form and JSON string values |
| [`rune-axum-signature`](rune-axum-signature) | Webhook signature verification layer and extractor for Axum: Standard Webhooks/Svix, Stripe, GitHub, Slack, Shopify and generic HMAC |
| [`rune-axum-size`](rune-axum-size) | Request body size limiter — Tower middleware for Axum |
| [`rune-axum-stack`](rune-axum-stack) | All-in-one middleware stack for Axum — security headers, CSRF, limits, timeouts, CORS, request ids, problem details and health probes |
| [`rune-axum-timeout`](rune-axum-timeout) | Request timeout middleware for Axum — per-request deadline with a configurable 504 response, overridable per route |
| [`rune-axum-trace`](rune-axum-trace) | One Axum layer for OpenTelemetry traces (OTLP/gRPC), Prometheus HTTP metrics and redacted access logs |
| [`rune-tower-circuitbreaker`](rune-tower-circuitbreaker) | Circuit-breaker layer for Tower clients — opens on error-rate or slow-call-rate thresholds, probes in half-open, closes on recovery |
| [`rune-tower-retry`](rune-tower-retry) | Retry and hedging layer for Tower clients — backoff with jitter, a retry budget, and request hedging for idempotent calls |

[All groups](../../README.md)
