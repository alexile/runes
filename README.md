# runes

A collection of small crates.

**Building with LLMs?** Start with [`rune-chain`](crates/chain/rune-chain): one dependency for
providers (OpenAI, Anthropic, Gemini, Ollama), agents with `#[tool]` functions, RAG over
in-memory, Qdrant, pgvector or SQLite stores, typed extraction, streaming, stateful graphs and evals.

```toml
[dependencies]
rune-chain = "0.1"
```

## Groups

| Group | What's in it |
| --- | --- |
| [Chain (LLM)](crates/chain/README.md) | LLM toolkit: one-dependency `rune-chain`, OpenAI/Anthropic/Gemini/Ollama providers, agents, `#[tool]` macros, RAG and vector stores, graphs, evals and MCP. |
| [Axum middleware](crates/axum/README.md) | Axum and Tower middleware: auth, rate limiting, CSRF, security headers, request limits. |
| [Net](crates/net/README.md) | Network protocols and parsers: DNS, TLS, HTTP, IP, X.509, service probes, capture formats. |
| [Secops](crates/secops/README.md) | Security findings, CVE/CVSS/EPSS, SARIF, correlation and Linux sandboxing. |
| [Web](crates/web/README.md) | Web security headers and well-known files: CSP, CORS, HSTS, robots, security.txt, tech detection. |
| [Common](crates/common/README.md) | Small utilities: encodings, hashes, ciphers, binary formats, secrets, logging. |
| [ML](crates/ml/README.md) | ML: metrics, linear models, clustering, dimensionality reduction, graph embeddings, community detection. |
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
