# runes

A collection of small crates.

## Groups

| Group | What's in it |
| --- | --- |
| [Chain (LLM)](crates/chain/README.md) | LLM orchestration: core traits, OpenAI/Anthropic/Ollama providers, prompts, memory, agents, tools, RAG and MCP. |
| [Axum middleware](crates/axum/README.md) | Axum and Tower middleware: auth, rate limiting, CSRF, security headers, request limits. |
| [Net](crates/net/README.md) | Network protocols and parsers: DNS, TLS, HTTP, IP, X.509, service probes, capture formats. |
| [Secops](crates/secops/README.md) | Security findings, CVE/CVSS/EPSS, SARIF, correlation and Linux sandboxing. |
| [Web](crates/web/README.md) | Web security headers and well-known files: CSP, CORS, HSTS, robots, security.txt, tech detection. |
| [Common](crates/common/README.md) | Small utilities: encodings, hashes, ciphers, binary formats, secrets, logging. |
| [ML](crates/ml/README.md) | Unsupervised ML: clustering, dimensionality reduction, graph embeddings, community detection. |
| [Time series](crates/ts/README.md) | Time series: statistics, smoothing, resampling, change points, forecasting. |
| [Geo](crates/geo/README.md) | Geospatial: geohash, polylines, simplification, geofencing, map matching, tracking. |
| [Graph](crates/graph/README.md) | Embedded property graph, Gremlin-style traversal and pattern matching. |
| [Stream](crates/stream/README.md) | Stream processing: backpressure, dedupe, windowing, watermarks, ingest. |

## Minimum supported Rust version

Every crate builds on **Rust 1.88** and later. Raising the MSRV never ships
in a patch release.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT
