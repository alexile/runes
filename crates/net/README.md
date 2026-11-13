# Net

Network protocols and parsers: DNS, TLS, HTTP, IP, X.509, service probes, capture formats.

| Crate | Description |
| --- | --- |
| [`rune-asn`](rune-asn) | IP-to-ASN and ASN-to-prefix lookup over BGP/RIR datasets (RouteViews pfx2as, iptoasn, bgpdump, RIR delegated stats) with longest-prefix match |
| [`rune-burp-xml`](rune-burp-xml) | Burp Suite items and issues XML export reader and writer over rune-http-model, base64 request/response to HttpExchange |
| [`rune-cloud-ranges`](rune-cloud-ranges) | Cloud and CDN IP-range datasets (AWS, Google, Azure, Cloudflare, Fastly, Oracle, DigitalOcean) with provider, service and CDN lookup |
| [`rune-cookie`](rune-cookie) | RFC 6265 cookies: Set-Cookie/Cookie parsing and serialization, cookie dates, and a sans-I/O cookie jar with PSL scoping and SameSite |
| [`rune-diff`](rune-diff) | Myers line/word diff with unified output, volatile-field masking and structural HTTP response diff (status, headers, JSON and text bodies) |
| [`rune-dns-records`](rune-dns-records) | Typed parsers and weakness checks for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, CAA, TLSA and DNSSEC records |
| [`rune-dns-resolver`](rune-dns-resolver) | Async DNS stub resolver over rune-dns-wire: UDP with TCP fallback, DoT and DoH, timeouts, retries and typed lookups |
| [`rune-dns-wire`](rune-dns-wire) | Sans-I/O DNS message parser and builder (RFC 1035, EDNS0, name compression) |
| [`rune-dns-zone`](rune-dns-zone) | Sans-I/O DNS zone-file (RFC 1035 master format) parser and writer with AXFR/IXFR reassembly |
| [`rune-egress-proxy`](rune-egress-proxy) | Allowlisted, default-deny HTTP CONNECT egress proxy: host/CIDR allowlists, SSRF guard against non-global addresses, and DNS pinning |
| [`rune-geoip`](rune-geoip) | Pure-Rust MaxMind DB (MMDB) reader for GeoLite2/GeoIP2 and DB-IP databases: search tree, data decoder, typed city/country/ASN records |
| [`rune-graphql`](rune-graphql) | GraphQL SDL and introspection import: type model, bounded query and mutation generation, insertion points and operation validation |
| [`rune-har`](rune-har) | HAR 1.2 (HTTP Archive) reader and writer over rune-http-model, tolerant of Chrome, Firefox and Charles exports |
| [`rune-http-auth`](rune-http-auth) | Client-side HTTP authentication: Basic, Bearer, Digest (RFC 7616) and NTLM/Negotiate message framing over rune-http-model |
| [`rune-http-fingerprint`](rune-http-fingerprint) | Passive HTTP server and stack fingerprint from header order, casing, status-line and error-page quirks |
| [`rune-http-model`](rune-http-model) | Shared HTTP model: requests, responses, byte-exact bodies, headers, timings and exchanges, sans-I/O |
| [`rune-idna`](rune-idna) | Internationalized domain names: Punycode (RFC 3492), UTS #46 / IDNA2008 conversion, and UTS #39 confusable and mixed-script homograph detection |
| [`rune-ip`](rune-ip) | IPv4/IPv6 classification per the IANA special-purpose registries (global, private, bogon, scope) with SSRF-safe mapped-address unwrapping |
| [`rune-ip-intel`](rune-ip-intel) | IP-reputation provider trait with AbuseIPDB, GreyNoise, Shodan InternetDB and Censys adapters, normalized verdicts, caching and rate limits over a caller-supplied transport |
| [`rune-ja`](rune-ja) | JA3/JA3S and JA4/JA4S/JA4H/JA4T TLS, HTTP and TCP client/server fingerprints |
| [`rune-macaddr`](rune-macaddr) | MAC address (EUI-48/EUI-64) parsing, formatting and classification with IEEE OUI vendor lookup over caller-supplied registry data |
| [`rune-matchers`](rune-matchers) | Nuclei-style matcher and extractor DSL over rune-http-model exchanges: word, regex, binary, status, header, JSON and XPath rules |
| [`rune-mime`](rune-mime) | MIME media types: Content-Type parsing and formatting, charset detection, and bounded multipart/form-data and multipart/mixed parsing |
| [`rune-openapi`](rune-openapi) | OpenAPI 3.x and Swagger 2.0 import: normalized endpoints, typed parameters, schemas, example requests and insertion points |
| [`rune-packet`](rune-packet) | Zero-copy, sans-I/O Ethernet/802.1Q/ARP/IPv4/IPv6/TCP/UDP/ICMP parser and builder with checksums |
| [`rune-pcap`](rune-pcap) | Streaming pcap and pcapng reader and writer with link-type aware dissection via rune-packet |
| [`rune-port-scan`](rune-port-scan) | Rate-limited async TCP connect scanner with port-list parsing, banner grabbing and service and OS hints |
| [`rune-postman`](rune-postman) | Postman v2.0/v2.1 collection and environment import into rune-http-model requests, with variable resolution and auth helpers |
| [`rune-probe-ldap`](rune-probe-ldap) | Read-only LDAP probe: rootDSE read, StartTLS offer and opt-in anonymous-bind detection |
| [`rune-probe-mail`](rune-probe-mail) | Read-only SMTP/SMTPS and FTP/FTPS probes: greeting banner, EHLO and FEAT capabilities, STARTTLS and AUTH TLS support |
| [`rune-probe-ms`](rune-probe-ms) | Read-only SMB negotiate (dialect, signing, SMBv1) and RDP security-protocol negotiation probes |
| [`rune-probe-nosql`](rune-probe-nosql) | Read-only Redis, MongoDB, Memcached and Elasticsearch probes for unauthenticated exposure |
| [`rune-probe-sql`](rune-probe-sql) | Read-only MySQL/MariaDB, PostgreSQL and MSSQL (TDS prelogin) handshake and version probes |
| [`rune-probe-ssh`](rune-probe-ssh) | Read-only SSH probe and policy grader: banner, KEXINIT algorithm grading, Terrapin check, version CVE hints and host-key fingerprint |
| [`rune-proxy-protocol`](rune-proxy-protocol) | HAProxy PROXY protocol v1 (text) and v2 (binary, TLVs) sans-I/O decoder and encoder, with an optional tokio adapter |
| [`rune-rdap`](rune-rdap) | RDAP client for domains, IP networks and ASNs with IANA bootstrap (RFC 9224), typed responses, caching and rate limiting |
| [`rune-service-probe`](rune-service-probe) | Read-only service probing framework: a sans-I/O ServiceProbe trait, ServiceInfo model and a bounded tokio runner |
| [`rune-socks`](rune-socks) | SOCKS4/4a/5 sans-I/O codecs (CONNECT, BIND, UDP ASSOCIATE, username/password, GSSAPI framing) with tokio client and server |
| [`rune-sse`](rune-sse) | Incremental sans-I/O Server-Sent Events (text/event-stream) parser |
| [`rune-subdomain-permute`](rune-subdomain-permute) | Pattern-based subdomain permutation (alterx class): deterministic, deduplicated, bounded candidate generation |
| [`rune-tls-hello`](rune-tls-hello) | Sans-I/O TLS record and ClientHello/ServerHello parser and builder (SNI, ALPN, versions, extensions) |
| [`rune-tls-probe`](rune-tls-probe) | Read-only TLS server probe over raw handshakes: SSLv3-TLS 1.3 version and cipher-suite enumeration, weak-suite flags, fallback SCSV, compression, secure renegotiation |
| [`rune-url`](rune-url) | URL canonicalization, dedup keys, same-origin/same-site tests and scope matching for crawlers and scanners |
| [`rune-wildcard-dns`](rune-wildcard-dns) | Wildcard DNS detection and filtering for subdomain enumeration, over a caller-supplied resolver |
| [`rune-wordlist`](rune-wordlist) | Versioned, Ed25519-signed wordlist and payload pack loader with streaming, tamper-checked iteration and safe updates |
| [`rune-ws`](rune-ws) | Sans-I/O WebSocket (RFC 6455) framing, handshake and connection state machine, with optional permessage-deflate and tokio adapter |
| [`rune-wsdl`](rune-wsdl) | WSDL 1.1 / 2.0 import: SOAP 1.1 / 1.2 operations, message parts, inline XSD expanded into sample envelopes, HttpRequests and insertion points |
| [`rune-x509`](rune-x509) | X.509 certificate analysis: typed summaries, weak-crypto flags, chain building and path validation, hostname checks |

[All groups](../../README.md)
