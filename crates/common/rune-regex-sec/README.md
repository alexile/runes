# rune-regex-sec

> Security-focused regex patterns: IPs, CVEs, hashes, secrets, and PII detection.

[![crates.io](https://img.shields.io/crates/v/rune-regex-sec)](https://crates.io/crates/rune-regex-sec)
[![docs.rs](https://img.shields.io/docsrs/rune-regex-sec)](https://docs.rs/rune-regex-sec)
[![license](https://img.shields.io/crates/l/rune-regex-sec)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A curated library of compiled regular expressions for finding security-relevant
text: IP addresses, CVE IDs, hash digests, JWT tokens, AWS keys, private key
headers, email addresses, URLs, UUIDs, and long Base64 secrets.

## Installation

```toml
[dependencies]
rune-regex-sec = "0.1"
```

The `rune-regex-sec` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-regex-sec --features cli
```

## Usage

```rust
use rune_regex_sec::{match_ipv4, match_cve, scan};

let text = "Found CVE-2024-1234 at 192.168.1.1";

let ips  = match_ipv4(text);      // ["192.168.1.1"]
let cves = match_cve(text);        // ["CVE-2024-1234"]
let all  = scan(text);             // Vec<Finding> with category + value
```

## CLI

```bash
rune-regex-sec config.env     # scan a file
cat source.py | rune-regex-sec -  # scan stdin
```

## Output

```
config.env  ipv4        10.0.0.1
config.env  aws_key     AKIAIOSFODNN7EXAMPLE
config.env  email       admin@example.com
```

## License

MIT
