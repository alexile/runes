# Web

Web security headers and well-known files: CSP, CORS, HSTS, robots, security.txt, tech detection.

| Crate | Description |
| --- | --- |
| [`rune-cookie-sec`](rune-cookie-sec) | Analyze Set-Cookie headers for weak security attributes, reporting rune-finding findings |
| [`rune-cors`](rune-cors) | Analyze CORS response headers for dangerous origin, credential and allowlist combinations, reporting rune-finding findings |
| [`rune-csp`](rune-csp) | Parse, analyze and canonicalize Content-Security-Policy headers, reporting weaknesses as rune-finding findings |
| [`rune-favicon-hash`](rune-favicon-hash) | Shodan-style favicon hash: signed MurmurHash3-32 over the MIME-wrapped base64 of the icon bytes |
| [`rune-hsts`](rune-hsts) | Parse and analyze Strict-Transport-Security headers and check HSTS preload-list eligibility and membership |
| [`rune-payload-encode`](rune-payload-encode) | WAF-evasion payload variants (case, encoding, comment, whitespace, concatenation) as composable rune-transform transforms |
| [`rune-permissions-policy`](rune-permissions-policy) | Parse, analyze and canonicalize Permissions-Policy and legacy Feature-Policy headers, flagging over-permissive grants as rune-finding findings |
| [`rune-referrer-policy`](rune-referrer-policy) | Parse and analyze Referrer-Policy headers and meta values, flagging leak-prone policies as rune-finding findings |
| [`rune-robots`](rune-robots) | Parse robots.txt (RFC 9309) and sitemap.xml / sitemap index files (plain or gzipped), and match paths against robots rules |
| [`rune-securitytxt`](rune-securitytxt) | Parse and validate security.txt files (RFC 9116): fields, expiry, canonical URIs and OpenPGP cleartext signatures |
| [`rune-tech-detect`](rune-tech-detect) | Wappalyzer-style technology fingerprinting engine: header, cookie, HTML, script, meta, URL and favicon-hash rules with versions and confidence |
| [`rune-wellknown`](rune-wellknown) | Discover and parse /.well-known resources (security.txt, change-password, MTA-STS, OpenID configuration, assetlinks, apple-app-site-association) into typed models |

[All groups](../../README.md)
