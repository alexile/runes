# Security policy

Some of these crates sit on security boundaries (auth, CSRF, rate limiting,
JWT and webhook verification, network parsers, secret redaction, sandboxing,
LLM tool execution, MCP), so I take reports seriously.

## Reporting a vulnerability

Please report privately through GitHub: open the **Security** tab of
[alexile/runes](https://github.com/alexile/runes) and click
**Report a vulnerability**. Don't open a public issue, PR or discussion for
a vulnerability.

Useful things to include:

- the affected crate and version (e.g. `rune-foo 0.3.1`)
- what an attacker can do with it (the impact)
- steps to reproduce, or a small proof of concept
- a suggested fix, if you have one

## What happens next

This is a one-person project, so these are best-effort targets:

- I'll acknowledge the report within a few days.
- Once confirmed, I'll work on a fix with you and keep you posted in the
  advisory thread.
- The fix ships as a new release of the affected crate on crates.io.
- I'll publish a GitHub security advisory, and for serious issues also file
  a RustSec advisory. You'll be credited unless you'd rather not be.

There is no bug bounty.

## Supported versions

Crates are versioned independently. Only the latest released version of each
crate gets security fixes. Below 1.0, a fix that needs a breaking change may
come out as a new `0.y` release rather than a patch.

## Scope

In scope: vulnerabilities in the code of the crates in this repo, for example
auth or verification bypass, injection, panics or unbounded memory/CPU use on
untrusted input, secrets leaking through `Debug` output or logs, and sandbox
escapes.

Out of scope:

- bugs in third-party dependencies; please report those upstream, and let me
  know if a runes crate needs to bump its version requirement
- using a crate against its documented security notes
- probe and scanner crates doing what they are meant to do against systems
  you own or are allowed to test
