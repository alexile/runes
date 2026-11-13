# rune-leak

> Scan source trees and git history for hardcoded secrets, API keys, and credentials.

[![crates.io](https://img.shields.io/crates/v/rune-leak)](https://crates.io/crates/rune-leak)
[![docs.rs](https://img.shields.io/docsrs/rune-leak)](https://docs.rs/rune-leak)
[![license](https://img.shields.io/crates/l/rune-leak)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

One secret-scanning engine for SAST pipelines, CI gates and agents, with two
layers:

- **Ruleset API.** Rules are data (`SecretRule`: id, name, pattern, entropy
  threshold, keywords, severity, CWE). `default_rules()` ships 15 rules (AWS,
  GCP, GitHub, GitLab, Slack, Stripe, SendGrid, npm, PyPI, private keys, JWTs,
  generic `password = "…"` assignments), plus an entropy detector for
  key-like tokens. Add your own rules in code or from TOML. Matches become
  [`rune-finding`](https://crates.io/crates/rune-finding) findings with
  check id `secret.<rule id>`, a file location (line, columns, bytes) and a
  CWE-798 taxonomy reference. Scan a working tree and its **git history**.
- **Simple API.** `scan_text`, `scan_file`, `scan_dir` and `LeakScanner`
  classify `rune-regex-sec` categories by entropy into a `Leak`.
  `scan_dir` skips files over 2 MB (`DEFAULT_MAX_FILE_BYTES`; another cap
  with `LeakScanner::scan_dir_with_max_file_bytes`).

Secrets never reach findings: evidence carries a 4-character prefix and the
length. Inline base64 images (`data:` URIs), UUIDs, URL paths and
subresource-integrity digests are not reported.

## Installation

```toml
[dependencies]
rune-leak = "0.2"
```

Features: `serde` (serialize rules and reports), `toml` (load rules from
TOML), `cli` (the binary):

```bash
cargo install rune-leak --features cli
```

## Usage

### Ruleset API

```rust
use rune_finding::Severity;
use rune_leak::{Ruleset, SecretRule};

let mut rules = Ruleset::builtin();
rules.extend([SecretRule::new("acme_token", "ACME API token", r"acme_[0-9a-f]{32}", Severity::High)
    .with_keywords(["acme_"])])?;

let findings = rules.findings("key = AKIAIOSFODNN7EXAMPLE", "config.env");
assert_eq!(findings[0].check_id, "secret.aws_access_key");
assert_eq!(findings[0].taxonomy[0].id, "CWE-798");
```

`Ruleset::for_each_match` is the allocation-light path: matches borrow the
rule and the text, and only a few scratch buffers are allocated per call.

### Working tree and git history

```rust,no_run
use rune_leak::{run, ScanOptions};

let report = run(&ScanOptions::new(".").with_scan_git_history(true).with_max_commits(500))?;
for finding in &report.findings {
    println!("{} {:?}", finding.check_id, finding.location);
}
```

History scanning drives the local `git` executable's plumbing commands
(`rev-list`, `ls-tree`, `diff-tree`, `cat-file --batch`): no git library, no
network, no hooks, and no repository discovery above the given path. Every
blob is read once, and each secret is reported once with the short hash of
the oldest commit that contains it. `HistoryScanner` is the sans-I/O core if
you walk history yourself (for example with `gix`).

### User rules (TOML)

```toml
[[rules]]
id = "acme_token"
name = "ACME API token"
pattern = 'acme_([0-9a-f]{32})'   # group 1, if any, is the secret
keywords = ["acme_"]              # case-insensitive line pre-filter
entropy_threshold = 3.0           # bits per byte, optional
severity = "high"                 # default "medium"
cwe = 798                         # default 798
```

```rust,ignore
let rules = rune_leak::rules_from_toml(&std::fs::read_to_string("rules.toml")?)?;
let options = rune_leak::ScanOptions::new(".").with_rules([rune_leak::default_rules(), rules].concat());
```

### Simple API

```rust
use rune_leak::{scan_text, Severity};

let code = r#"const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.abc";"#;
let leaks = scan_text(code);
assert_eq!(leaks[0].severity, Severity::Critical);
```

## CLI

```bash
rune-leak src/                              # simple engine
rune-leak --ruleset src/                    # ruleset engine, redacted output
rune-leak --git-history --max-commits 200 . # working tree plus history
rune-leak --rules acme.toml src/            # built-in plus user rules
cat secrets.txt | rune-leak -
rune-leak --min-severity CRITICAL src/      # only critical findings
rune-leak --include-info src/               # include IPs and emails
```

The exit status is 1 when anything at or above `--min-severity` (default
`HIGH`) is found.

## Default rules

| Id | Detects | Severity |
|---|---|---|
| `aws_access_key` | AWS access key id (`AKIA…`, `ASIA…`) | High |
| `aws_secret` | 40-char AWS secret near an `aws` marker | High |
| `gcp_api_key` | Google Cloud API key | High |
| `github_token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens | High |
| `github_fine_grained_pat` | `github_pat_…` | High |
| `gitlab_pat` | `glpat-…` | High |
| `slack_token` | `xox[baprs]-…` | High |
| `slack_webhook` | Slack incoming webhook URL | Medium |
| `stripe_live` | `sk_live_`/`rk_live_` keys | High |
| `sendgrid_api_key` | `SG.….…` | High |
| `npm_token` | `npm_…` | High |
| `pypi_token` | `pypi-AgEIcHlwaS5vcmc…` | High |
| `private_key_block` | `-----BEGIN … PRIVATE KEY-----` | High |
| `jwt` | JSON Web Token | Medium |
| `generic_assignment` | `password`/`secret`/`token`/`api_key` = literal | Medium |
| `high_entropy_string` | key-like token with entropy ≥ 4.3 (detector) | Low |

## Simple API severity levels

| Category | Severity | Notes |
|---|---|---|
| JWT | Critical | Always flagged |
| AWS access key | Critical | Always flagged |
| PEM private key | Critical | Always flagged |
| High-entropy base64 (≥ 4.5 bits) | High | Probable credential |
| Hash digest with entropy ≥ 3.5 | Medium | Possible hardcoded hash |
| Emails, URLs | Low | `--include-info` |
| IPs, UUIDs, CVEs | Info | `--include-info` |

## License

MIT
