# Secops

Security findings, CVE/CVSS/EPSS, SARIF, correlation and Linux sandboxing.

| Crate | Description |
| --- | --- |
| [`rune-aspm-correlate`](rune-aspm-correlate) | ASPM correlation: ingest external SARIF and DAST findings, correlate SAST and DAST into one risk view with provenance |
| [`rune-cve`](rune-cve) | CVE and NVD 2.0 record model with CPE 2.3 parsing and version-range matching |
| [`rune-cvss`](rune-cvss) | CVSS v3.0, v3.1 and v4.0 vector parsing and scoring, exactly as the FIRST specifications and reference calculators define it |
| [`rune-epss`](rune-epss) | EPSS exploit-probability scores and the CISA KEV catalog, parsed from their feeds and joined by CVE id |
| [`rune-finding`](rune-finding) | Shared security finding model: Finding, Severity, Confidence, Location, Evidence and taxonomy references, with a stable fingerprint |
| [`rune-finding-dedupe`](rune-finding-dedupe) | Cross-scan finding deduplication and correlation: merge findings by fingerprint and track stable issue identity over time |
| [`rune-landlock`](rune-landlock) | Landlock LSM filesystem sandboxing: path allowlist rulesets with ABI detection and best-effort fallback on older kernels |
| [`rune-namespaces`](rune-namespaces) | Linux namespace process isolation: spawn children under bubblewrap or unshare(2) with an ordered mount plan and environment allowlist |
| [`rune-pledge`](rune-pledge) | pledge-style capability reduction: map a simple promise profile to Landlock and seccomp on Linux, with a documented best-effort no-op elsewhere |
| [`rune-sandbox-preset`](rune-sandbox-preset) | Reusable sandbox presets (dev-tool, network-tool) that compile to rune-namespaces, rune-seccomp, rune-landlock and rune-egress-proxy |
| [`rune-sarif`](rune-sarif) | SARIF 2.1.0 for security findings: typed log model, writer from rune-finding, reader for CodeQL, Semgrep, Trivy and Gitleaks output, GitHub upload checks |
| [`rune-seccomp`](rune-seccomp) | seccomp-bpf system call filtering: deny-by-default allowlists and denylists with errno, trap, log and kill actions, kernel detection and best-effort fallback |
| [`rune-secops-warden`](rune-secops-warden) | Whitelist-only TOML policy engine for sandboxing AI coding agents (Claude Code and friends) via bubblewrap namespaces and a seccomp-bpf syscall filter — filesystem, network, env vars, commands, and syscalls all deny-by-default |
| [`rune-taxonomy`](rune-taxonomy) | CWE, CAPEC, ATT&CK, OWASP Top 10 and ASVS reference data with typed, validated ids and cross-mappings |

[All groups](../../README.md)
