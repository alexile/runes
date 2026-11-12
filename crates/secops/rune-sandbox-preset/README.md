# rune-sandbox-preset

> Reusable sandbox presets (dev-tool, network-tool) that compile to rune-namespaces, rune-seccomp, rune-landlock and rune-egress-proxy

[![crates.io](https://img.shields.io/crates/v/rune-sandbox-preset)](https://crates.io/crates/rune-sandbox-preset)
[![docs.rs](https://img.shields.io/docsrs/rune-sandbox-preset)](https://docs.rs/rune-sandbox-preset)
[![license](https://img.shields.io/crates/l/rune-sandbox-preset)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## Installation

```toml
[dependencies]
rune-sandbox-preset = "0.1"
```

The `rune-sandbox-preset` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-sandbox-preset --features cli
```

Sane sandbox defaults for programs you don't fully trust, without
`rune-secops-warden`'s TOML policy engine. A `Preset` is one declarative
description — host paths it may see, paths it may not, environment, network,
system call filter — compiled from the same data to every mechanism:

| Mechanism                   | Crate               | From                                            |
| --------------------------- | ------------------- | ----------------------------------------------- |
| namespaces, mounts, env     | `rune-namespaces`   | `Preset::namespace_options`, `Preset::command`  |
| seccomp-bpf                 | `rune-seccomp`      | `Preset::seccomp_program`                       |
| Landlock (defense in depth) | `rune-landlock`     | `Preset::landlock_options`, `landlock_wrapper`  |
| domain-allowlisted egress   | `rune-egress-proxy` | `Network::Proxied`                              |

## Presets

| Preset         | Filesystem                                                                 | Network                          | Working dir |
| -------------- | -------------------------------------------------------------------------- | -------------------------------- | ----------- |
| `dev_tool`     | system dirs read+exec, `/etc/passwd`, `/etc/group`, `/etc/localtime`, project read-write | none                             | project     |
| `network_tool` | as `dev_tool` plus DNS, TLS CA bundle and host identity files, optional work dir read-write | host, or only an egress proxy socket | work dir or `/tmp` |

Both:

- show **nothing** of the host beyond that — no home directory, no
  `/etc/shadow`, no `.ssh`;
- pin `PATH` to system directories and `HOME` to a path that exists in the
  sandbox (`/tmp` by default) instead of inheriting the host's — a writable
  directory early on a developer's `PATH` lets a sandboxed shell shadow
  every command, and a `HOME` that points at nothing makes many runtimes
  abort;
- pass through only `LANG`, `LC_*`, `TERM`, `TZ`, `USER`, `LOGNAME`;
- deny the dangerous system calls (module loading, `ptrace`, keyring,
  `mount`, `io_uring`, ...) with `EPERM`;
- unshare every namespace (user, mount, PID, IPC, UTS, cgroup, and network
  unless the host's network was asked for).

The path lists (`DNS_FILES`, `TLS_PATHS`, `HOST_IDENTITY_FILES`, `SAFE_PATH`)
come from tracing real programs in `rune-secops-warden`, whose `claude_code`
preset is built from them too.

## Usage

### Library

```rust
use rune_namespaces::{Access, Exposure};
use rune_sandbox_preset::{DevToolOptions, MaskKind, dev_tool};

let preset = dev_tool(
    &DevToolOptions::new("/home/me/project")
        .with_read_write("/home/me/.cargo/registry")
        .with_masks([("/home/me/project/.env".into(), MaskKind::File)]),
);
preset.validate().unwrap();

// Inspect it without running anything.
assert_eq!(preset.exposure("/home/me/project/.env"), Exposure::Masked);
assert!(!preset.is_visible("/home/me/.ssh/id_ed25519"));

// Run a program in it (needs bwrap and unprivileged user namespaces).
// let status = preset.command("/usr/bin/cargo", &["test"])?.status()?;
```

Masks over files that do not exist would make `bwrap` create them on the
host through the read-write bind, so `secret_masks(project)` looks for the
usual credential files (`.env*`, `.npmrc`, `.netrc`, `.git-credentials`, ...)
and returns masks only for the ones present.

With `Network::Proxied`, the sandbox has a private network namespace and
only the egress proxy's Unix socket, bound at `/run/rune-egress-proxy.sock`.
Run `rune_egress_proxy::Proxy::serve_unix` on the host socket; the proxy
enforces the host allowlist.

### CLI

```bash
# Offline: run the tests of a project, its .env masked, no network.
rune-sandbox-preset dev-tool --project ~/project -- /usr/bin/make test

# Network, read-write download directory.
rune-sandbox-preset network-tool --work-dir ~/dl -- /usr/bin/curl -O https://example.com/f

# Print the bwrap arguments instead of running.
rune-sandbox-preset --print dev-tool --project ~/project -- /usr/bin/true
```

## License

MIT
