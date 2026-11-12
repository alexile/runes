# Common

Small utilities: encodings, hashes, ciphers, binary formats, secrets, logging.

| Crate | Description |
| --- | --- |
| [`rune-adler32`](rune-adler32) | Compute Adler-32 checksums of byte slices and files (RFC 1950) |
| [`rune-ascii`](rune-ascii) | ASCII table lookup and character conversion — decimal, hex, octal, binary, and char |
| [`rune-atbash`](rune-atbash) | Atbash cipher — reverse-alphabet substitution for Latin letters |
| [`rune-audit-log`](rune-audit-log) | Append-only, hash-chained (optionally HMAC-signed) tamper-evident audit log with pluggable storage |
| [`rune-base`](rune-base) | Encode and decode integers and byte strings in any numeric base with a custom alphabet |
| [`rune-base32`](rune-base32) | Base32 encode/decode — RFC 4648 standard and hex alphabets, pure Rust |
| [`rune-base58`](rune-base58) | Base58 encode/decode — Bitcoin alphabet and Flickr alphabet, with optional Check encoding |
| [`rune-base64`](rune-base64) | Base64 encoder and decoder — standard (RFC 4648) and URL-safe variants |
| [`rune-binary`](rune-binary) | Binary representation encoder and decoder — converts bytes to 01010101 bit strings |
| [`rune-blake3`](rune-blake3) | Compute BLAKE3 hashes of byte slices and files — faster than SHA-256 and cryptographically secure |
| [`rune-byte-magic`](rune-byte-magic) | Identify file types from magic bytes — pure Rust, no libmagic dependency |
| [`rune-caesar`](rune-caesar) | Caesar cipher — shift-based substitution cipher with brute-force decoder |
| [`rune-cidr`](rune-cidr) | CIDR (IPv4/IPv6) parsing, membership and range math (expand, split, aggregate, overlaps) — no dependencies beyond std |
| [`rune-config`](rune-config) | Layered TOML configuration (defaults, files, environment, CLI) with per-key source tracking |
| [`rune-crc32`](rune-crc32) | Compute CRC-32 checksums of byte slices and files (IEEE 802.3 / Ethernet polynomial) |
| [`rune-dirs`](rune-dirs) | Per-app config, cache, data and state directories (XDG, macOS, Windows) from a caller-supplied environment |
| [`rune-elf`](rune-elf) | Lightweight ELF binary parser: header, sections, segments, security flags (PIE, NX, RELRO, stack canary, FORTIFY) |
| [`rune-elf-deps`](rune-elf-deps) | Transitive shared-library dependency closure resolution for ELF binaries — pure-Rust ELF inspection via rune-elf, never executes the binaries it analyzes |
| [`rune-entropy`](rune-entropy) | Shannon entropy calculator for files and byte streams — useful for detecting encrypted, packed, or compressed data |
| [`rune-epoch`](rune-epoch) | Unix timestamp conversions — epoch to human-readable and back |
| [`rune-fnv`](rune-fnv) | FNV-1 and FNV-1a hash functions for byte slices and strings (32 and 64-bit) |
| [`rune-fuzzyhash`](rune-fuzzyhash) | TLSH and ssdeep (CTPH) fuzzy hashes with distance scoring for near-identical files and payloads |
| [`rune-hex`](rune-hex) | Hex encoding and decoding for byte slices and files — lowercase, uppercase, and streaming output |
| [`rune-hexdump`](rune-hexdump) | Hex dump with sidebar — inspect binary files like xxd |
| [`rune-host-match`](rune-host-match) | Hostname pattern matching: exact, *.suffix egress allowlists and RFC 6125 certificate wildcards |
| [`rune-html-encode`](rune-html-encode) | HTML entity encoding and decoding — escape and unescape HTML special characters |
| [`rune-jwt`](rune-jwt) | Decode and inspect JWT claims without verification — tear open any token for debugging and CTF work |
| [`rune-leak`](rune-leak) | Scan source trees and git history for hardcoded secrets with a data-driven ruleset and entropy heuristics, reporting rune-finding findings |
| [`rune-log`](rune-log) | Structured tracing logging layer (text or JSON) with field-level secret and PII redaction, configured from env-style values |
| [`rune-md5`](rune-md5) | Compute MD5 checksums of byte slices and files |
| [`rune-metrics`](rune-metrics) | Metrics registry with counters, gauges and histograms plus a Prometheus / OpenMetrics text exporter, process collector and HTTP middleware |
| [`rune-morse`](rune-morse) | Morse code encoder and decoder — ASCII text to dots and dashes and back |
| [`rune-murmur`](rune-murmur) | MurmurHash3 — pure-Rust implementation of the 32-bit and 128-bit variants |
| [`rune-notify`](rune-notify) | Notification sinks for findings and alerts: Slack, Discord, generic JSON webhook and Jira, over a caller-supplied HTTP transport |
| [`rune-pe`](rune-pe) | Lightweight PE (Windows executable) parser: headers, sections, imports, exports, security flags (ASLR, DEP, CFG, SafeSEH) |
| [`rune-psl`](rune-psl) | Public Suffix List: public suffix and registrable domain (eTLD+1) lookups over an embedded, pinned list |
| [`rune-randomness`](rune-randomness) | NIST SP 800-22 and FIPS 140-2 statistical randomness tests for tokens and bit streams |
| [`rune-redact`](rune-redact) | Redact PII and secrets from text, streams, writers and tracing output with a configurable mask, hash or tokenize policy |
| [`rune-regex-sec`](rune-regex-sec) | Security-focused regex patterns for detecting IPs, CVEs, hashes, secrets, and PII in text |
| [`rune-relay`](rune-relay) | Bidirectional byte relay between two stream halves, plus a ready-made TCP-listener-to-Unix-domain-socket bridge built on it — generic stream plumbing, no protocol awareness |
| [`rune-rlimits`](rune-rlimits) | Typed POSIX resource limits: read and set them for the current process, or apply them to a std::process::Command via pre_exec |
| [`rune-rot13`](rune-rot13) | ROT13 cipher — rotate ASCII letters by 13 positions |
| [`rune-rot47`](rune-rot47) | ROT47 cipher — rotate printable ASCII characters by 47 positions |
| [`rune-secret-ref`](rune-secret-ref) | Secret references (env, file, command) resolved into a redacting SecretValue |
| [`rune-secret-vault`](rune-secret-vault) | Secret providers (env, file, OS keyring, HashiCorp Vault) with TTL caching over rune-secret-ref |
| [`rune-sha1`](rune-sha1) | Compute SHA-1 hashes of byte slices and files |
| [`rune-sha256`](rune-sha256) | Compute SHA-256 hashes of byte slices and files, returning lowercase hex strings |
| [`rune-sha512`](rune-sha512) | Compute SHA-512 hashes of byte slices and files |
| [`rune-simhash`](rune-simhash) | SimHash and MinHash locality-sensitive signatures with shingling and an online near-duplicate clusterer |
| [`rune-strace`](rune-strace) | Syscall tracing for seccomp profiles: ptrace a child to collect the system calls it makes, and parse `strace -f` output |
| [`rune-strings`](rune-strings) | Extract printable strings from binary files — configurable minimum length and encoding |
| [`rune-telemetry`](rune-telemetry) | One-call tracing subscriber and OTLP trace export bootstrap configured from OTEL_* and RUST_LOG environment variables |
| [`rune-tokenize`](rune-tokenize) | Approximate token counting, budget checking, text truncation, and overlapping chunk splitting for LLM context windows |
| [`rune-transform`](rune-transform) | Registry of named, chainable byte transforms (encode, decode, hash, compress) built on the rune codecs |
| [`rune-url-encode`](rune-url-encode) | URL percent-encoding and decoding for byte slices and strings |
| [`rune-which`](rune-which) | Cross-platform executable lookup on PATH or in given directories, honouring PATHEXT |
| [`rune-xor`](rune-xor) | XOR cipher for byte streams and files — repeating-key and single-byte modes with English-scored brute-force |
| [`rune-xxhash`](rune-xxhash) | xxHash (xxh32 / xxh64) — extremely fast non-cryptographic hash, pure Rust |

[All groups](../../README.md)
